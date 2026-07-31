package integration

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/phonginreallife/kernelseal/internal/cgroup"
	"github.com/phonginreallife/kernelseal/internal/identity"
	"github.com/phonginreallife/kernelseal/internal/secrets"
	"github.com/phonginreallife/kernelseal/internal/server"
)

// These tests exercise authorization against the running kernel rather than a
// fixture: the shim's cgroup is read from the real procfs and matched against a
// real cgroupPath selector. They need no privileges and no BPF, so unlike the LSM
// tests they run everywhere, which matters because this is the path that decides
// whether one workload can obtain another's secrets.
//
// The pod-based selectors cannot be covered here, since attributing a cgroup to a
// pod needs an API server. See internal/cgroup for the path shapes and
// internal/secrets for the matching rules.

// startAuthzServer brings up a server with real cgroup identification.
func startAuthzServer(t *testing.T, bindings []secrets.Binding, requirePodIdentity bool) string {
	t.Helper()

	dir, err := os.MkdirTemp("/tmp", "ks-authz-*")
	if err != nil {
		t.Fatalf("creating socket dir: %v", err)
	}
	t.Cleanup(func() { os.RemoveAll(dir) })

	registry := secrets.NewRegistry()
	registry.Replace(bindings)

	socketPath := filepath.Join(dir, "s.sock")

	// A nil pod lookup: this host has no API server, so callers resolve to a
	// cgroup and no pod, which is exactly what a cgroupPath selector needs.
	ident := identity.New(cgroup.NewResolver("", ""), nil)

	srv := server.New(server.Config{
		SocketPath:         socketPath,
		SocketMode:         0o666,
		RequireProtection:  false,
		IdentifyCallers:    true,
		RequirePodIdentity: requirePodIdentity,
	}, registry, &stubProtector{}, ident)

	if err := srv.Listen(); err != nil {
		t.Fatalf("Listen: %v", err)
	}
	srv.Serve()
	t.Cleanup(srv.Close)

	return socketPath
}

// requireCgroups skips when the host has no unified cgroup hierarchy to read.
func requireCgroups(t *testing.T) {
	t.Helper()

	if _, err := os.Stat(cgroup.DefaultRoot); err != nil {
		t.Skipf("no cgroup hierarchy at %s: %v", cgroup.DefaultRoot, err)
	}
}

// ownCgroup returns this process's unified cgroup path, which the shim will share
// because it is started as a child.
//
// Skips when that path is the root cgroup, which cannot scope a binding to
// anything and is rejected as a selector.
func ownCgroup(t *testing.T) string {
	t.Helper()
	requireCgroups(t)

	// #nosec G115 - a PID is always positive and fits in uint32
	id, err := cgroup.NewResolver("", "").Resolve(uint32(os.Getpid()))
	if err != nil {
		t.Skipf("cannot resolve this process's cgroup: %v", err)
	}
	if id.Path == "" {
		t.Skip("this process has no unified cgroup path")
	}
	if strings.TrimSuffix(id.Path, "/") == "" {
		// Everything on this host lives in the root cgroup, which is not a usable
		// authorization constraint and is rejected as a selector. Common on WSL2
		// and on hosts without systemd.
		t.Skipf("this process is in the root cgroup %q, which cannot scope a binding", id.Path)
	}
	return id.Path
}

// A cgroupPath selector naming the caller's own cgroup must admit it. This is the
// positive control: without it, a test that only checks denials would pass even if
// matching were broken outright.
func TestShimDelivery_CgroupPathSelectorAdmitsTheCaller(t *testing.T) {
	own := ownCgroup(t)

	socketPath := startAuthzServer(t, []secrets.Binding{{
		Name:     "own-cgroup",
		Selector: secrets.Selector{Binary: "env", CgroupPath: own},
		Secrets:  []secrets.Secret{{Name: "CGROUP_SCOPED_SECRET", Value: "delivered"}},
	}}, false)

	stdout, stderr, err := runShim(t, socketPath, "env")
	if err != nil {
		t.Fatalf("shim failed: %v\nstderr: %s", err, stderr)
	}
	if !strings.Contains(stdout, "CGROUP_SCOPED_SECRET=delivered") {
		t.Errorf("secret not delivered to a caller inside the selected cgroup\nstdout: %s", stdout)
	}
}

// The negative control, and the point of the whole mechanism: a binding scoped to
// a cgroup the caller is not in must not be served, however the request names its
// binary.
func TestShimDelivery_CgroupPathSelectorRefusesOthers(t *testing.T) {
	requireCgroups(t)

	socketPath := startAuthzServer(t, []secrets.Binding{{
		Name: "someone-elses-cgroup",
		Selector: secrets.Selector{
			Binary:     "env",
			CgroupPath: "/kubepods.slice/kubepods-burstable.slice/kubepods-burstable-podffffffff_ffff_ffff_ffff_ffffffffffff.slice",
		},
		Secrets: []secrets.Secret{{Name: "OTHER_POD_SECRET", Value: "must-not-appear"}},
	}}, false)

	stdout, stderr, err := runShim(t, socketPath, "env")

	// The shim fails closed by default, so a refused request is expected to stop
	// the process rather than start it unprotected.
	if err == nil && strings.Contains(stdout, "must-not-appear") {
		t.Fatalf("a binding scoped to another cgroup was delivered\nstdout: %s", stdout)
	}
	if strings.Contains(stdout, "OTHER_POD_SECRET") {
		t.Errorf("the secret leaked into the environment\nstdout: %s", stdout)
	}
	if err == nil {
		t.Errorf("the request was served; expected a refusal\nstderr: %s", stderr)
	}
}

// An ancestor cgroup must cover its descendants, or selecting a slice would mean
// naming every container ID inside it by hand.
func TestShimDelivery_AncestorCgroupPathAdmitsTheCaller(t *testing.T) {
	own := ownCgroup(t)

	parent := filepath.Dir(own)
	if parent == "." || parent == own {
		t.Skipf("cgroup %q has no usable parent to select on", own)
	}

	socketPath := startAuthzServer(t, []secrets.Binding{{
		Name:     "parent-cgroup",
		Selector: secrets.Selector{Binary: "env", CgroupPath: parent},
		Secrets:  []secrets.Secret{{Name: "ANCESTOR_SCOPED_SECRET", Value: "delivered"}},
	}}, false)

	stdout, stderr, err := runShim(t, socketPath, "env")
	if err != nil {
		t.Fatalf("shim failed: %v\nstderr: %s", err, stderr)
	}
	if !strings.Contains(stdout, "ANCESTOR_SCOPED_SECRET=delivered") {
		t.Errorf("a descendant of the selected cgroup was not admitted\nstdout: %s", stdout)
	}
}

// On a host with no pods, required mode has nothing to attribute a caller to, so
// every request must be refused. An agent that cannot identify callers must not
// fall back to serving them.
func TestShimDelivery_RequiredModeRefusesANonPodCaller(t *testing.T) {
	requireCgroups(t)

	socketPath := startAuthzServer(t, []secrets.Binding{{
		Name:     "needs-a-pod",
		Selector: secrets.Selector{Binary: "env", Namespace: "payments"},
		Secrets:  []secrets.Secret{{Name: "POD_SCOPED_SECRET", Value: "must-not-appear"}},
	}}, true)

	stdout, _, err := runShim(t, socketPath, "env")

	if strings.Contains(stdout, "must-not-appear") {
		t.Fatalf("a pod-scoped binding was served to a host process\nstdout: %s", stdout)
	}
	if err == nil {
		t.Errorf("the request was served in required mode with no pod to attribute it to\nstdout: %s", stdout)
	}
}
