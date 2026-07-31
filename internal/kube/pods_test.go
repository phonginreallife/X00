package kube

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"
)

const (
	podUID   = "3f8a1b2c-4d5e-6f70-8192-a3b4c5d6e7f8"
	otherUID = "aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee"
	nodeName = "ip-10-0-1-23.ec2.internal"
)

// fakeAPI is a stand-in for the API server that serves one list and then holds a
// watch open until the test releases it.
type fakeAPI struct {
	t *testing.T

	mu        sync.Mutex
	listCalls int
	lastQuery string

	items []podObject

	// events is drained by the watch handler and written to the stream.
	events chan watchEvent

	// watchStatus, when non-zero, is returned instead of a stream.
	watchStatus int
}

func newFakeAPI(t *testing.T, items ...podObject) *fakeAPI {
	return &fakeAPI{t: t, items: items, events: make(chan watchEvent, 8)}
}

func (f *fakeAPI) handler() http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		f.mu.Lock()
		f.lastQuery = r.URL.RawQuery
		isWatch := r.URL.Query().Get("watch") == "true"
		if !isWatch {
			f.listCalls++
		}
		status := f.watchStatus
		items := f.items
		f.mu.Unlock()

		if !isWatch {
			var list podList
			list.Metadata.ResourceVersion = "100"
			list.Items = items
			w.Header().Set("Content-Type", "application/json")
			if err := json.NewEncoder(w).Encode(list); err != nil {
				f.t.Errorf("encoding list: %v", err)
			}
			return
		}

		if status != 0 {
			w.WriteHeader(status)
			fmt.Fprint(w, `{"kind":"Status","reason":"Expired","code":410}`)
			return
		}

		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		flusher, ok := w.(http.Flusher)
		if !ok {
			f.t.Fatal("test server does not support flushing")
		}
		flusher.Flush()

		enc := json.NewEncoder(w)
		for {
			select {
			case <-r.Context().Done():
				return
			case ev := <-f.events:
				if err := enc.Encode(ev); err != nil {
					return
				}
				flusher.Flush()
			}
		}
	})
}

func pod(uid, name, namespace string, labels map[string]string) podObject {
	var p podObject
	p.Metadata.UID = uid
	p.Metadata.Name = name
	p.Metadata.Namespace = namespace
	p.Metadata.Labels = labels
	p.Metadata.ResourceVersion = "101"
	return p
}

// The cgroup path yields a bare container ID; the API server reports it with a
// runtime scheme. Bindings select on the container's name, so the two spellings
// have to meet somewhere, and this is it.
func TestToPod_MapsContainerIDsToNames(t *testing.T) {
	const id = "9a8b7c6d5e4f3a2b1c0d9e8f7a6b5c4d3e2f1a0b9c8d7e6f5a4b3c2d1e0f9a8b"

	var p podObject
	p.Metadata.UID = podUID
	p.Metadata.Name = "checkout-abc"
	p.Metadata.Namespace = "payments"
	p.Status.ContainerStatuses = []containerStatus{
		{Name: "server", ContainerID: "containerd://" + id},
	}
	p.Status.InitContainerStatuses = []containerStatus{
		{Name: "install-shim", ContainerID: "cri-o://" + "1111111111111111111111111111111111111111111111111111111111111111"},
	}
	// A container that has not started yet has no ID and must not create an entry
	// keyed on the empty string, which would match any caller with no container.
	p.Status.EphemeralContainerStatuses = []containerStatus{
		{Name: "debug", ContainerID: ""},
	}

	pod := p.toPod()

	if got := pod.Containers[id]; got != "server" {
		t.Errorf("Containers[%s] = %q, want server", id, got)
	}
	if len(pod.Containers) != 2 {
		t.Errorf("Containers = %v, want the two containers that have IDs", pod.Containers)
	}
	if _, ok := pod.Containers[""]; ok {
		t.Error("a container with no ID was indexed under the empty string")
	}
}

func TestStripRuntimePrefix(t *testing.T) {
	tests := map[string]string{
		"containerd://ABC123": "abc123",
		"cri-o://abc123":      "abc123",
		"docker://abc123":     "abc123",
		"abc123":              "abc123",
		"":                    "",
	}
	for in, want := range tests {
		if got := stripRuntimePrefix(in); got != want {
			t.Errorf("stripRuntimePrefix(%q) = %q, want %q", in, got, want)
		}
	}
}

func startWatcher(t *testing.T, api *fakeAPI) (*Watcher, *httptest.Server) {
	t.Helper()

	srv := httptest.NewServer(api.handler())
	t.Cleanup(srv.Close)

	w, err := NewWatcher(Config{
		Server:             srv.URL,
		NodeName:           nodeName,
		Token:              "test-token",
		InsecureSkipVerify: true,
	})
	if err != nil {
		t.Fatalf("NewWatcher: %v", err)
	}

	if err := w.Start(context.Background()); err != nil {
		t.Fatalf("Start: %v", err)
	}
	t.Cleanup(w.Stop)

	return w, srv
}

func TestNewWatcher_RequiresNodeName(t *testing.T) {
	if _, err := NewWatcher(Config{Server: "https://example", Token: "t"}); err == nil {
		t.Error("expected an error when NodeName is empty")
	}
}

func TestStart_ListsAndIndexesByUID(t *testing.T) {
	api := newFakeAPI(t,
		pod(podUID, "checkout-abc", "payments", map[string]string{"app": "checkout"}),
		pod(otherUID, "audit-xyz", "security", map[string]string{"app": "audit"}),
	)
	w, _ := startWatcher(t, api)

	if !w.HasSynced() {
		t.Error("HasSynced is false after a successful Start")
	}
	if got := w.Len(); got != 2 {
		t.Errorf("Len = %d, want 2", got)
	}

	got, ok := w.Lookup(podUID)
	if !ok {
		t.Fatalf("Lookup(%s) missed", podUID)
	}
	if got.Namespace != "payments" || got.Name != "checkout-abc" {
		t.Errorf("pod = %+v, want namespace payments name checkout-abc", got)
	}
	if got.Labels["app"] != "checkout" {
		t.Errorf("labels = %v, want app=checkout", got.Labels)
	}
}

// A cluster-wide pod watch would work but is the wrong thing: it puts load on the
// API server proportional to node count squared, and the agent can only ever be
// asked about callers on its own node.
func TestStart_RestrictsTheWatchToThisNode(t *testing.T) {
	api := newFakeAPI(t, pod(podUID, "checkout-abc", "payments", nil))
	_, _ = startWatcher(t, api)

	api.mu.Lock()
	q := api.lastQuery
	api.mu.Unlock()

	want := "spec.nodeName%3D" + nodeName
	if !strings.Contains(q, want) {
		t.Errorf("query = %q, want a fieldSelector containing %q", q, want)
	}
}

func TestLookup_MissForUnknownUID(t *testing.T) {
	api := newFakeAPI(t, pod(podUID, "checkout-abc", "payments", nil))
	w, _ := startWatcher(t, api)

	if _, ok := w.Lookup("no-such-uid"); ok {
		t.Error("Lookup returned a pod for an unknown UID")
	}
}

func TestWatch_AddedAndDeleted(t *testing.T) {
	api := newFakeAPI(t, pod(podUID, "checkout-abc", "payments", nil))
	w, _ := startWatcher(t, api)

	api.events <- watchEvent{Type: "ADDED", Object: pod(otherUID, "audit-xyz", "security", map[string]string{"app": "audit"})}
	waitFor(t, func() bool {
		_, ok := w.Lookup(otherUID)
		return ok
	}, "the added pod to appear in the cache")

	got, _ := w.Lookup(otherUID)
	if got.Namespace != "security" {
		t.Errorf("namespace = %q, want security", got.Namespace)
	}

	api.events <- watchEvent{Type: "DELETED", Object: pod(otherUID, "audit-xyz", "security", nil)}
	waitFor(t, func() bool {
		_, ok := w.Lookup(otherUID)
		return !ok
	}, "the deleted pod to leave the cache")
}

// A pod's labels can change after it starts, and a binding that selects on labels
// has to follow that or it authorizes against a stale view.
func TestWatch_ModifiedUpdatesLabels(t *testing.T) {
	api := newFakeAPI(t, pod(podUID, "checkout-abc", "payments", map[string]string{"app": "checkout"}))
	w, _ := startWatcher(t, api)

	api.events <- watchEvent{
		Type:   "MODIFIED",
		Object: pod(podUID, "checkout-abc", "payments", map[string]string{"app": "checkout", "tier": "prod"}),
	}

	waitFor(t, func() bool {
		p, ok := w.Lookup(podUID)
		return ok && p.Labels["tier"] == "prod"
	}, "the modified labels to reach the cache")
}

// When the API server compacts away the history a watch needs, resuming is
// impossible and only a fresh list recovers. Silently continuing would leave the
// cache permanently stale.
func TestWatch_ExpiredTriggersRelist(t *testing.T) {
	api := newFakeAPI(t, pod(podUID, "checkout-abc", "payments", nil))
	api.mu.Lock()
	api.watchStatus = http.StatusGone
	api.mu.Unlock()

	w, _ := startWatcher(t, api)

	waitFor(t, func() bool {
		api.mu.Lock()
		defer api.mu.Unlock()
		return api.listCalls >= 2
	}, "a re-list after the watch expired")

	if !w.HasSynced() {
		t.Error("HasSynced went false after a re-list")
	}
}

func TestStart_FailsWhenTheAPIServerRejects(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusForbidden)
		fmt.Fprint(w, `{"kind":"Status","reason":"Forbidden","code":403}`)
	}))
	defer srv.Close()

	w, err := NewWatcher(Config{
		Server:             srv.URL,
		NodeName:           nodeName,
		Token:              "test-token",
		InsecureSkipVerify: true,
	})
	if err != nil {
		t.Fatalf("NewWatcher: %v", err)
	}

	err = w.Start(context.Background())
	if err == nil {
		t.Fatal("Start succeeded against an API server that returns 403")
	}
	if w.HasSynced() {
		t.Error("HasSynced is true after a failed Start")
	}
}

func waitFor(t *testing.T, cond func() bool, what string) {
	t.Helper()
	deadline := time.Now().Add(3 * time.Second)
	for time.Now().Before(deadline) {
		if cond() {
			return
		}
		time.Sleep(5 * time.Millisecond)
	}
	t.Fatalf("timed out waiting for %s", what)
}
