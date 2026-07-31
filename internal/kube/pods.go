// Package kube maintains a view of the pods running on this node, so a caller's
// pod UID can be turned into the namespace and labels that secret bindings select
// on.
//
// It talks to the API server directly over HTTP rather than through client-go.
// The agent needs exactly one thing, a list-watch of pods filtered to its own
// node, and client-go would add tens of megabytes of dependencies to a binary
// whose whole point is to be a small static thing that loads BPF. The tradeoff is
// that reconnect and resync are handled here; see watchOnce.
package kube

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"net/url"
	"os"
	"strings"
	"sync"
	"time"
)

const (
	serviceAccountDir = "/var/run/secrets/kubernetes.io/serviceaccount"
	tokenFile         = serviceAccountDir + "/token"
	caFile            = serviceAccountDir + "/ca.crt"

	// listTimeout bounds the initial synchronous list. The agent refuses to serve
	// until it completes, so this is also how long startup can stall.
	listTimeout = 30 * time.Second

	// watchTimeout is sent to the API server as timeoutSeconds. The server closes
	// the stream at that point and the watch reconnects, which bounds how long a
	// silently dead connection can leave the cache stale.
	watchTimeout = 5 * time.Minute
)

// Pod is the subset of a pod that secret bindings can select on.
type Pod struct {
	UID       string
	Name      string
	Namespace string
	Labels    map[string]string

	// Containers maps a runtime container ID to the container's name in the pod
	// spec. The cgroup path yields the ID; bindings select on the name.
	Containers map[string]string
}

// Config points the watcher at an API server.
type Config struct {
	// Server is the API server base URL. Empty means derive it from the
	// KUBERNETES_SERVICE_HOST and KUBERNETES_SERVICE_PORT environment variables.
	Server string

	// NodeName restricts the watch to pods scheduled on this node. Required: a
	// cluster-wide pod watch on every node is a load the API server should not
	// have to absorb, and the agent can only ever be asked about local callers.
	NodeName string

	// Token is the bearer token. Empty means read the service account token from
	// disk on every request, which is what projected token rotation requires.
	Token string

	// CACertPath overrides the service account CA bundle.
	CACertPath string

	// InsecureSkipVerify disables API server certificate verification. Only for
	// tests; the watcher logs loudly if it is ever set.
	InsecureSkipVerify bool
}

// Watcher keeps a pod cache for one node, indexed by pod UID.
type Watcher struct {
	cfg    Config
	client *http.Client

	mu     sync.RWMutex
	byUID  map[string]Pod
	synced bool

	cancel context.CancelFunc
	done   chan struct{}
}

// InCluster reports whether the process looks like it is running inside a pod
// with a service account mounted. Callers use this to tell "pod identity is
// unavailable because we are not in a cluster" apart from "it is broken".
func InCluster() bool {
	if os.Getenv("KUBERNETES_SERVICE_HOST") == "" {
		return false
	}
	_, err := os.Stat(tokenFile)
	return err == nil
}

// NewWatcher creates a watcher. Call Start to populate it.
func NewWatcher(cfg Config) (*Watcher, error) {
	if cfg.NodeName == "" {
		return nil, errors.New("node name is required; set NODE_NAME from spec.nodeName")
	}

	if cfg.Server == "" {
		host := os.Getenv("KUBERNETES_SERVICE_HOST")
		port := os.Getenv("KUBERNETES_SERVICE_PORT")
		if host == "" {
			return nil, errors.New("KUBERNETES_SERVICE_HOST is not set; not running in a cluster")
		}
		if port == "" {
			port = "443"
		}
		cfg.Server = "https://" + net.JoinHostPort(host, port)
	}

	transport, err := newTransport(cfg)
	if err != nil {
		return nil, err
	}

	return &Watcher{
		cfg:    cfg,
		client: &http.Client{Transport: transport},
		byUID:  make(map[string]Pod),
		done:   make(chan struct{}),
	}, nil
}

func newTransport(cfg Config) (*http.Transport, error) {
	tlsCfg := &tls.Config{MinVersion: tls.VersionTLS12}

	if cfg.InsecureSkipVerify {
		log.Println("[WARN] API server certificate verification is DISABLED; this is for tests only")
		tlsCfg.InsecureSkipVerify = true //nolint:gosec // gated on an explicit test-only option
	} else {
		path := cfg.CACertPath
		if path == "" {
			path = caFile
		}
		pem, err := os.ReadFile(path)
		if err != nil {
			return nil, fmt.Errorf("reading API server CA %s: %w", path, err)
		}
		pool := x509.NewCertPool()
		if !pool.AppendCertsFromPEM(pem) {
			return nil, fmt.Errorf("no certificates found in %s", path)
		}
		tlsCfg.RootCAs = pool
	}

	return &http.Transport{TLSClientConfig: tlsCfg}, nil
}

// Start performs the initial list synchronously and then watches in the
// background. It returns once the cache is populated, so a caller that succeeds
// here can rely on Lookup for pods that already existed.
func (w *Watcher) Start(ctx context.Context) error {
	listCtx, cancelList := context.WithTimeout(ctx, listTimeout)
	defer cancelList()

	resourceVersion, err := w.list(listCtx)
	if err != nil {
		return fmt.Errorf("initial pod list: %w", err)
	}

	w.mu.Lock()
	w.synced = true
	count := len(w.byUID)
	w.mu.Unlock()

	log.Printf("[PODS] Watching %d pod(s) on node %s", count, w.cfg.NodeName)

	watchCtx, cancel := context.WithCancel(ctx)
	w.cancel = cancel

	go func() {
		defer close(w.done)
		w.watchLoop(watchCtx, resourceVersion)
	}()

	return nil
}

// Stop ends the watch and waits for it to finish.
func (w *Watcher) Stop() {
	if w.cancel == nil {
		return
	}
	w.cancel()
	<-w.done
}

// Lookup returns the pod with the given UID.
func (w *Watcher) Lookup(uid string) (Pod, bool) {
	w.mu.RLock()
	defer w.mu.RUnlock()
	p, ok := w.byUID[uid]
	return p, ok
}

// HasSynced reports whether the initial list has completed. A lookup miss before
// the cache is warm means "unknown", not "no such pod", and authorization must
// not treat the two the same.
func (w *Watcher) HasSynced() bool {
	w.mu.RLock()
	defer w.mu.RUnlock()
	return w.synced
}

// Len reports how many pods are cached, for metrics.
func (w *Watcher) Len() int {
	w.mu.RLock()
	defer w.mu.RUnlock()
	return len(w.byUID)
}

// podList is the subset of a PodList the watcher reads.
type podList struct {
	Metadata struct {
		ResourceVersion string `json:"resourceVersion"`
	} `json:"metadata"`
	Items []podObject `json:"items"`
}

type containerStatus struct {
	Name string `json:"name"`
	// ContainerID carries a runtime scheme, for example
	// "containerd://9a8b...". The cgroup path has only the bare ID.
	ContainerID string `json:"containerID"`
}

type podObject struct {
	Metadata struct {
		UID             string            `json:"uid"`
		Name            string            `json:"name"`
		Namespace       string            `json:"namespace"`
		Labels          map[string]string `json:"labels"`
		ResourceVersion string            `json:"resourceVersion"`
	} `json:"metadata"`
	Status struct {
		ContainerStatuses          []containerStatus `json:"containerStatuses"`
		InitContainerStatuses      []containerStatus `json:"initContainerStatuses"`
		EphemeralContainerStatuses []containerStatus `json:"ephemeralContainerStatuses"`
	} `json:"status"`
}

func (p podObject) toPod() Pod {
	pod := Pod{
		UID:       p.Metadata.UID,
		Name:      p.Metadata.Name,
		Namespace: p.Metadata.Namespace,
		Labels:    p.Metadata.Labels,
	}

	// Init and ephemeral containers are included because the shim can wrap any of
	// them, and a caller the agent cannot name is a caller it has to refuse.
	all := make([]containerStatus, 0,
		len(p.Status.ContainerStatuses)+len(p.Status.InitContainerStatuses)+len(p.Status.EphemeralContainerStatuses))
	all = append(all, p.Status.ContainerStatuses...)
	all = append(all, p.Status.InitContainerStatuses...)
	all = append(all, p.Status.EphemeralContainerStatuses...)

	for _, cs := range all {
		id := stripRuntimePrefix(cs.ContainerID)
		if id == "" || cs.Name == "" {
			continue
		}
		if pod.Containers == nil {
			pod.Containers = make(map[string]string, len(all))
		}
		pod.Containers[id] = cs.Name
	}

	return pod
}

// stripRuntimePrefix turns "containerd://9a8b..." into "9a8b...", matching what
// ParsePod reads out of a cgroup path.
func stripRuntimePrefix(id string) string {
	if i := strings.Index(id, "://"); i >= 0 {
		return strings.ToLower(id[i+3:])
	}
	return strings.ToLower(id)
}

type watchEvent struct {
	Type   string    `json:"type"`
	Object podObject `json:"object"`
}

func (w *Watcher) podsURL(watch bool, resourceVersion string) string {
	q := url.Values{}
	q.Set("fieldSelector", "spec.nodeName="+w.cfg.NodeName)

	if watch {
		q.Set("watch", "true")
		q.Set("allowWatchBookmarks", "true")
		q.Set("timeoutSeconds", fmt.Sprint(int(watchTimeout.Seconds())))
		if resourceVersion != "" {
			q.Set("resourceVersion", resourceVersion)
		}
	}

	return strings.TrimSuffix(w.cfg.Server, "/") + "/api/v1/pods?" + q.Encode()
}

func (w *Watcher) bearer() (string, error) {
	if w.cfg.Token != "" {
		return w.cfg.Token, nil
	}
	// Projected service account tokens are rotated in place, so the file is read
	// per request rather than cached. A stale token surfaces as a 401 that no
	// amount of retrying fixes.
	data, err := os.ReadFile(tokenFile)
	if err != nil {
		return "", fmt.Errorf("reading service account token: %w", err)
	}
	return strings.TrimSpace(string(data)), nil
}

func (w *Watcher) do(ctx context.Context, rawURL string) (*http.Response, error) {
	token, err := w.bearer()
	if err != nil {
		return nil, err
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, rawURL, nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("Authorization", "Bearer "+token)
	req.Header.Set("Accept", "application/json")

	resp, err := w.client.Do(req)
	if err != nil {
		return nil, err
	}
	if resp.StatusCode != http.StatusOK {
		// The body is a Status object explaining the rejection. A truncated or
		// unreadable one still leaves the status code, which is the part that
		// decides whether this is retried, so a read failure is not worth
		// propagating over the error it is describing.
		body, readErr := io.ReadAll(io.LimitReader(resp.Body, 2048))
		resp.Body.Close()
		if readErr != nil {
			body = []byte("<body unreadable: " + readErr.Error() + ">")
		}
		return nil, &apiError{Code: resp.StatusCode, Body: strings.TrimSpace(string(body))}
	}
	return resp, nil
}

type apiError struct {
	Code int
	Body string
}

func (e *apiError) Error() string {
	return fmt.Sprintf("API server returned %d: %s", e.Code, e.Body)
}

// list replaces the cache with a fresh snapshot and returns the resource version
// to watch from.
func (w *Watcher) list(ctx context.Context) (string, error) {
	resp, err := w.do(ctx, w.podsURL(false, ""))
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()

	var list podList
	if err := json.NewDecoder(resp.Body).Decode(&list); err != nil {
		return "", fmt.Errorf("decoding pod list: %w", err)
	}

	fresh := make(map[string]Pod, len(list.Items))
	for _, item := range list.Items {
		if item.Metadata.UID == "" {
			continue
		}
		fresh[item.Metadata.UID] = item.toPod()
	}

	w.mu.Lock()
	w.byUID = fresh
	w.mu.Unlock()

	return list.Metadata.ResourceVersion, nil
}

// watchLoop keeps the cache current, re-listing whenever the watch cannot be
// resumed. Every exit from watchOnce is a reason to back off before retrying, so
// a broken API server cannot turn into a hot loop.
func (w *Watcher) watchLoop(ctx context.Context, resourceVersion string) {
	const (
		minBackoff = 1 * time.Second
		maxBackoff = 30 * time.Second
	)
	backoff := minBackoff

	for {
		if ctx.Err() != nil {
			return
		}

		next, err := w.watchOnce(ctx, resourceVersion)
		switch {
		case ctx.Err() != nil:
			return

		case err == nil:
			// A clean end of stream is the server closing an idle watch. Resume
			// from where it left off without backing off.
			resourceVersion = next
			backoff = minBackoff
			continue

		case isExpired(err):
			// The history the watch needs has been compacted away. Only a fresh
			// list can recover, and it must succeed before the cache is trusted
			// again.
			log.Printf("[PODS] Watch expired, re-listing: %v", err)
			resourceVersion = ""

		default:
			log.Printf("[WARN] Pod watch failed, retrying in %s: %v", backoff, err)
		}

		if !sleepCtx(ctx, backoff) {
			return
		}
		if backoff *= 2; backoff > maxBackoff {
			backoff = maxBackoff
		}

		if resourceVersion == "" {
			rv, lerr := w.relist(ctx)
			if lerr != nil {
				log.Printf("[WARN] Pod re-list failed: %v", lerr)
				continue
			}
			resourceVersion = rv
			backoff = minBackoff
		}
	}
}

func (w *Watcher) relist(ctx context.Context) (string, error) {
	listCtx, cancel := context.WithTimeout(ctx, listTimeout)
	defer cancel()
	return w.list(listCtx)
}

// watchOnce streams events until the connection ends. It returns the last
// resource version seen so the next watch can resume from it.
func (w *Watcher) watchOnce(ctx context.Context, resourceVersion string) (string, error) {
	resp, err := w.do(ctx, w.podsURL(true, resourceVersion))
	if err != nil {
		return resourceVersion, err
	}
	defer resp.Body.Close()

	decoder := json.NewDecoder(resp.Body)
	for {
		var ev watchEvent
		if err := decoder.Decode(&ev); err != nil {
			if errors.Is(err, io.EOF) || errors.Is(err, io.ErrUnexpectedEOF) {
				return resourceVersion, nil
			}
			return resourceVersion, fmt.Errorf("decoding watch event: %w", err)
		}

		if rv := ev.Object.Metadata.ResourceVersion; rv != "" {
			resourceVersion = rv
		}

		switch ev.Type {
		case "ADDED", "MODIFIED":
			if ev.Object.Metadata.UID != "" {
				w.put(ev.Object.toPod())
			}
		case "DELETED":
			w.delete(ev.Object.Metadata.UID)
		case "BOOKMARK":
			// Carries only a resource version, already recorded above.
		case "ERROR":
			return resourceVersion, &watchExpired{detail: "server sent an ERROR event"}
		}
	}
}

func (w *Watcher) put(p Pod) {
	w.mu.Lock()
	defer w.mu.Unlock()
	w.byUID[p.UID] = p
}

func (w *Watcher) delete(uid string) {
	if uid == "" {
		return
	}
	w.mu.Lock()
	defer w.mu.Unlock()
	delete(w.byUID, uid)
}

// watchExpired marks the case where the watch cannot be resumed and only a fresh
// list will do.
type watchExpired struct{ detail string }

func (e *watchExpired) Error() string { return e.detail }

func isExpired(err error) bool {
	var we *watchExpired
	if errors.As(err, &we) {
		return true
	}
	var ae *apiError
	if errors.As(err, &ae) {
		return ae.Code == http.StatusGone
	}
	return false
}

// sleepCtx waits for d, reporting false if the context ended first.
func sleepCtx(ctx context.Context, d time.Duration) bool {
	t := time.NewTimer(d)
	defer t.Stop()
	select {
	case <-ctx.Done():
		return false
	case <-t.C:
		return true
	}
}
