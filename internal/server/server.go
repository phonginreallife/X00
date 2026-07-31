// Package server delivers secrets to the kernelseal-exec shim over a unix socket.
//
// The ordering inside handle is the security-relevant part: the caller's PID is
// marked protected in the BPF map *before* the secrets are written back. By the
// time the shim applies the environment and exec's the real binary, reads of
// /proc/<pid>/environ are already refused. Because execve preserves the PID, the
// protection carries over to the application.
package server

import (
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log"
	"net"
	"os"
	"os/user"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"time"

	"github.com/phonginreallife/kernelseal/internal/logging"
	"github.com/phonginreallife/kernelseal/internal/protocol"
	"github.com/phonginreallife/kernelseal/internal/secrets"
)

// handshakeTimeout bounds how long a single shim exchange may take, so a stuck
// or malicious caller cannot hold a connection open indefinitely.
const handshakeTimeout = 10 * time.Second

// Resolver reports which secrets apply to a caller.
type Resolver interface {
	Lookup(binaryName string, caller secrets.Caller) secrets.Match
}

// Identifier reports what the kernel and the API server know about a caller.
// Errors mean the caller could not be identified, which is different from a
// caller that is legitimately not in a pod.
type Identifier interface {
	Identify(pid uint32) (secrets.Caller, error)
}

// Protector manages kernel-side protection for a PID.
type Protector interface {
	ProtectPID(pid uint32) error
	UnprotectPID(pid uint32) error
	TrackPID(pid uint32) error
}

// Config configures the socket server.
type Config struct {
	// SocketPath is the unix socket to listen on.
	SocketPath string

	// SocketMode is the socket's file mode. The default 0660 keeps the socket
	// off-limits to unrelated users, which means the caller must share a group
	// with KernelSeal. See SocketGroup.
	SocketMode os.FileMode

	// SocketGroup optionally sets the socket's owning group, by name or numeric
	// GID. The agent runs as root, so without this a 0660 socket is reachable
	// only by root and any unprivileged caller gets EACCES on connect.
	//
	// In Kubernetes this is normally handled by the pod's fsGroup instead.
	SocketGroup string

	// RequireProtection withholds secrets when the PID could not be marked
	// protected, rather than handing out secrets the kernel will not guard.
	RequireProtection bool

	// IdentifyCallers resolves each caller's cgroup and pod before matching. Off
	// only for policy.podIdentity: disabled, where bindings are selected by the
	// binary name the caller claims and nothing else.
	IdentifyCallers bool

	// RequirePodIdentity refuses any caller the agent cannot attribute to a pod.
	// This is what makes the binary name stop being an authorization input: a
	// process that reaches the socket and names someone else's binary is refused
	// because it is not that pod, whatever it calls itself.
	RequirePodIdentity bool
}

// Server serves secret requests from kernelseal-exec.
type Server struct {
	cfg        Config
	resolver   Resolver
	protector  Protector
	identifier Identifier

	ln     net.Listener
	wg     sync.WaitGroup
	stopCh chan struct{}
	closer sync.Once

	onIssued func(pid uint32, names []string)
	onDenied func(pid uint32, reason string)
}

// New creates a server. Call Listen before Serve.
//
// identifier may be nil only when cfg.IdentifyCallers is false; with it nil and
// identification on, every caller would look unidentifiable and nothing would be
// served.
func New(cfg Config, resolver Resolver, protector Protector, identifier Identifier) *Server {
	if cfg.SocketPath == "" {
		cfg.SocketPath = protocol.DefaultSocketPath
	}
	if cfg.SocketMode == 0 {
		cfg.SocketMode = 0o660
	}
	return &Server{
		cfg:        cfg,
		resolver:   resolver,
		protector:  protector,
		identifier: identifier,
		stopCh:     make(chan struct{}),
	}
}

// SetIssuedCallback registers a hook invoked after secrets are released.
func (s *Server) SetIssuedCallback(cb func(pid uint32, names []string)) {
	s.onIssued = cb
}

// SetDeniedCallback registers a hook invoked when a request is refused.
func (s *Server) SetDeniedCallback(cb func(pid uint32, reason string)) {
	s.onDenied = cb
}

// Listen creates the socket and its parent directory.
func (s *Server) Listen() error {
	dir := filepath.Dir(s.cfg.SocketPath)
	if err := os.MkdirAll(dir, 0o750); err != nil {
		return fmt.Errorf("creating socket directory %s: %w", dir, err)
	}

	gid := -1
	if s.cfg.SocketGroup != "" {
		resolved, err := lookupGID(s.cfg.SocketGroup)
		if err != nil {
			return err
		}
		gid = resolved

		// The socket may be group-readable, but callers still need execute on
		// every parent directory to reach it. Share the directory with the same
		// group so unprivileged shims can connect.
		if err := os.Chown(dir, -1, gid); err != nil {
			return fmt.Errorf("setting group %q on %s: %w", s.cfg.SocketGroup, dir, err)
		}
		if err := os.Chmod(dir, 0o750); err != nil {
			return fmt.Errorf("setting mode on %s: %w", dir, err)
		}
	}

	// A socket left behind by an unclean shutdown would make Listen fail.
	if err := os.Remove(s.cfg.SocketPath); err != nil && !os.IsNotExist(err) {
		return fmt.Errorf("removing stale socket %s: %w", s.cfg.SocketPath, err)
	}

	ln, err := net.Listen("unix", s.cfg.SocketPath)
	if err != nil {
		return fmt.Errorf("listening on %s: %w", s.cfg.SocketPath, err)
	}

	// Set the group before the mode so the socket is never briefly reachable by
	// a wider audience than intended.
	if gid >= 0 {
		if err := os.Chown(s.cfg.SocketPath, -1, gid); err != nil {
			ln.Close()
			return fmt.Errorf("setting group %q on %s: %w", s.cfg.SocketGroup, s.cfg.SocketPath, err)
		}
	}

	if err := os.Chmod(s.cfg.SocketPath, s.cfg.SocketMode); err != nil {
		ln.Close()
		return fmt.Errorf("setting mode on %s: %w", s.cfg.SocketPath, err)
	}

	s.ln = ln

	if gid >= 0 {
		log.Printf("[SOCKET] Listening on %s (mode %#o, group %s/%d)",
			s.cfg.SocketPath, s.cfg.SocketMode, s.cfg.SocketGroup, gid)
	} else {
		log.Printf("[SOCKET] Listening on %s (mode %#o, owned by uid %d)",
			s.cfg.SocketPath, s.cfg.SocketMode, os.Geteuid())

		// A root-owned 0660 socket is reachable only by root, which silently
		// blocks every unprivileged caller. Say so rather than letting them
		// discover it as EACCES on connect.
		if os.Geteuid() == 0 && s.cfg.SocketMode&0o006 == 0 {
			log.Printf("[SOCKET] Note: only root can connect. Pass -socket-group to share it " +
				"with an unprivileged user's group.")
		}
	}

	return nil
}

// lookupGID resolves a group name or numeric GID.
func lookupGID(group string) (int, error) {
	if gid, err := strconv.Atoi(group); err == nil {
		return gid, nil
	}

	grp, err := user.LookupGroup(group)
	if err != nil {
		return 0, fmt.Errorf("resolving socket group %q: %w", group, err)
	}

	gid, err := strconv.Atoi(grp.Gid)
	if err != nil {
		return 0, fmt.Errorf("group %q has non-numeric gid %q", group, grp.Gid)
	}
	return gid, nil
}

// Serve accepts connections until Close is called.
func (s *Server) Serve() {
	s.wg.Add(1)
	go func() {
		defer s.wg.Done()
		for {
			conn, err := s.ln.Accept()
			if err != nil {
				select {
				case <-s.stopCh:
					return
				default:
				}
				if errors.Is(err, net.ErrClosed) {
					return
				}
				log.Printf("[WARN] Accept failed: %v", err)
				continue
			}

			s.wg.Add(1)
			go func() {
				defer s.wg.Done()
				s.handleConn(conn)
			}()
		}
	}()
}

// Close stops accepting, waits for in-flight requests, and removes the socket.
func (s *Server) Close() {
	s.closer.Do(func() {
		close(s.stopCh)
		if s.ln != nil {
			s.ln.Close()
		}
		s.wg.Wait()
		if err := os.Remove(s.cfg.SocketPath); err != nil && !os.IsNotExist(err) {
			log.Printf("[WARN] Failed to remove socket %s: %v", s.cfg.SocketPath, err)
		}
	})
}

func (s *Server) handleConn(conn net.Conn) {
	defer conn.Close()

	if err := conn.SetDeadline(time.Now().Add(handshakeTimeout)); err != nil {
		log.Printf("[WARN] Setting deadline: %v", err)
		return
	}

	unixConn, ok := conn.(*net.UnixConn)
	if !ok {
		log.Printf("[WARN] Rejecting non-unix connection %T", conn)
		return
	}

	cred, err := peerCred(unixConn)
	if err != nil {
		log.Printf("[WARN] Could not identify caller, rejecting: %v", err)
		s.reply(conn, protocol.Response{Error: "peer identification failed"})
		return
	}

	var req protocol.Request
	if err := json.NewDecoder(io.LimitReader(conn, protocol.MaxMessageSize)).Decode(&req); err != nil {
		log.Printf("[WARN] Malformed request from pid=%d: %v", cred.Pid, err)
		s.reply(conn, protocol.Response{Error: "malformed request"})
		return
	}

	s.reply(conn, s.handle(cred, req))
}

func (s *Server) reply(conn net.Conn, resp protocol.Response) {
	if err := json.NewEncoder(conn).Encode(resp); err != nil {
		log.Printf("[WARN] Failed to write response: %v", err)
	}
}

// handle resolves and releases secrets for a verified caller.
func (s *Server) handle(cred *syscall.Ucred, req protocol.Request) protocol.Response {
	pid := uint32(cred.Pid)
	peer := describePeer(cred)

	binaryName := filepath.Base(req.Binary)
	if req.Binary == "" || binaryName == "." || binaryName == "/" {
		s.denied(pid, "empty binary")
		return protocol.Response{Error: "request did not name a binary"}
	}

	caller, identErr := s.identify(pid)
	peer = describeCaller(peer, caller)

	// A caller the agent cannot attribute to a pod is refused outright when the
	// socket is reachable by more than one pod. Falling through to binary matching
	// here is exactly the hole this mode exists to close.
	if s.cfg.RequirePodIdentity {
		switch {
		case identErr != nil:
			s.denied(pid, "caller unidentified")
			log.Printf("[DENY] Refusing pid=%d: policy.podIdentity is required and the caller "+
				"could not be identified: %v (%s)", pid, identErr, peer)
			return protocol.Response{Error: "caller could not be attributed to a pod"}

		case caller.Pod == nil:
			s.denied(pid, "caller not in a pod")
			log.Printf("[DENY] Refusing pid=%d: policy.podIdentity is required and the caller "+
				"is not in a known pod (%s)", pid, peer)
			return protocol.Response{Error: "caller could not be attributed to a pod"}
		}
	} else if identErr != nil {
		// Not fatal here, but it does mean every pod-scoped binding will refuse
		// this caller, so say why once rather than leaving the refusals unexplained.
		logging.Debugf("[SHIM] Could not identify pid=%d: %v", pid, identErr)
	}

	matched := s.resolver.Lookup(binaryName, caller)

	if matched.Empty() {
		// Not an error, and not worth a line at the default level: the shim may
		// front a binary that has no secrets bound to it.
		logging.Debugf("[SHIM] No secrets bound to %q, allowing exec unchanged (%s)", binaryName, peer)
		return protocol.Response{OK: true, Protected: false}
	}

	// Bindings exist for this binary but none of them admit this caller. This is
	// the case the cgroup work exists to catch, so it is refused regardless of
	// enforcement mode: it is an authorization decision, not a protection one.
	if len(matched.Secrets) == 0 && len(matched.Refused) > 0 {
		s.denied(pid, "pod identity refused")
		log.Printf("[DENY] Refusing %q to pid=%d: no binding admits this caller; refused %v (%s)",
			binaryName, pid, matched.Refused, peer)
		return protocol.Response{
			Error: fmt.Sprintf("no secret binding for %q admits this caller", binaryName),
		}
	}

	// The configuration names this binary but the binding cannot serve anyone as
	// written. Serving nothing silently would start the process unprotected, so
	// this is refused the same way an unreadable secret source is.
	if len(matched.Secrets) == 0 && len(matched.Rejected) > 0 {
		s.denied(pid, "binding rejected by policy")
		log.Printf("[DENY] Refusing %q to pid=%d: binding(s) %v are not servable under the "+
			"active policy (%s)", binaryName, pid, matched.Rejected, peer)
		return protocol.Response{
			Error: fmt.Sprintf("secret binding(s) %v for %q are rejected by policy",
				matched.Rejected, binaryName),
		}
	}

	unresolved := matched.Unresolved

	// The configuration binds secrets to this binary, but none of them could be
	// read. Returning the "no secrets bound" response here would start the
	// process with no secrets AND no kernel protection, silently, which is how a
	// single typo in a fileRef turns enforce mode into no enforcement at all.
	if len(matched.Secrets) == 0 {
		if s.cfg.RequireProtection {
			s.denied(pid, "all secrets unresolved")
			log.Printf("[DENY] Refusing to start %q: all %d configured secret(s) failed to resolve %v (%s)",
				binaryName, len(unresolved), unresolved, peer)
			return protocol.Response{
				Error: fmt.Sprintf("all %d configured secret(s) for %q failed to resolve: %v",
					len(unresolved), binaryName, unresolved),
			}
		}

		log.Printf("[WARN] Starting %q unprotected: all %d configured secret(s) failed to resolve %v (%s)",
			binaryName, len(unresolved), unresolved, peer)
		return protocol.Response{
			OK:        true,
			Protected: false,
			Warning: fmt.Sprintf("all %d configured secret(s) failed to resolve: %v",
				len(unresolved), unresolved),
		}
	}

	// Snapshot the caller's identity so PID recycling during the handshake is
	// detectable.
	startBefore, err := processStartTime(pid)
	if err != nil {
		s.denied(pid, "caller vanished")
		log.Printf("[DENY] Caller pid=%d disappeared before protection: %v", pid, err)
		return protocol.Response{Error: "caller no longer exists"}
	}

	protected := true
	if err := s.protector.ProtectPID(pid); err != nil {
		protected = false
		log.Printf("[WARN] Could not protect pid=%d: %v", pid, err)
	}
	if err := s.protector.TrackPID(pid); err != nil {
		log.Printf("[WARN] Could not track pid=%d for exit cleanup: %v", pid, err)
	}

	startAfter, err := processStartTime(pid)
	if err != nil || startAfter != startBefore {
		if uerr := s.protector.UnprotectPID(pid); uerr != nil {
			log.Printf("[WARN] Failed to roll back protection for pid=%d: %v", pid, uerr)
		}
		s.denied(pid, "pid recycled")
		log.Printf("[DENY] pid=%d was recycled during the handshake, withholding secrets", pid)
		return protocol.Response{Error: "caller no longer exists"}
	}

	if !protected && s.cfg.RequireProtection {
		s.denied(pid, "protection unavailable")
		log.Printf("[DENY] Refusing to release secrets to pid=%d: kernel protection unavailable", pid)
		return protocol.Response{
			Error: "kernel protection unavailable and policy requires it",
		}
	}

	env := make(map[string]string, len(matched.Secrets))
	names := make([]string, 0, len(matched.Secrets))
	for _, sec := range matched.Secrets {
		env[sec.Name] = sec.Value
		names = append(names, sec.Name)
	}
	sort.Strings(names)

	if protected {
		log.Printf("[PROTECT] pid=%d marked protected before release (%s)", pid, peer)
	}
	log.Printf("[ISSUE] Released %d secrets to %q %v (%s)", len(names), binaryName, names, peer)

	if s.onIssued != nil {
		s.onIssued(pid, names)
	}

	// A partial delivery is protected and usable, so it is not a denial - but the
	// application is starting without secrets its configuration says it needs,
	// and it will most likely fail somewhere less obvious.
	var warnings []string
	if len(unresolved) > 0 {
		log.Printf("[WARN] %q started with %d unresolved secret(s): %v",
			binaryName, len(unresolved), unresolved)
		warnings = append(warnings, fmt.Sprintf("%d configured secret(s) failed to resolve: %v",
			len(unresolved), unresolved))
	}

	// Another binding for this binary served, so the request is not refused, but
	// one that the operator wrote is contributing nothing. Without this the only
	// evidence is a line logged once at config load, long before the application
	// starts missing values it expects.
	if len(matched.Rejected) > 0 {
		log.Printf("[WARN] %q started without binding(s) %v, which the active policy rejects",
			binaryName, matched.Rejected)
		warnings = append(warnings, fmt.Sprintf("binding(s) %v are rejected by policy",
			matched.Rejected))
	}

	return protocol.Response{
		OK:        true,
		Env:       env,
		Protected: protected,
		Warning:   strings.Join(warnings, "; "),
	}
}

// identify resolves a caller's cgroup and pod, or returns an empty Caller when
// identification is switched off.
func (s *Server) identify(pid uint32) (secrets.Caller, error) {
	if !s.cfg.IdentifyCallers {
		return secrets.Caller{}, nil
	}
	if s.identifier == nil {
		return secrets.Caller{}, errors.New("caller identification is enabled but no identifier is configured")
	}
	return s.identifier.Identify(pid)
}

func (s *Server) denied(pid uint32, reason string) {
	if s.onDenied != nil {
		s.onDenied(pid, reason)
	}
}
