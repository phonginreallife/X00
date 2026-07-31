// Package integration contains integration and system tests for KernelSeal.
package integration

import (
	"bufio"
	"os"
	"os/exec"
	"os/user"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"testing"

	"github.com/phonginreallife/kernelseal/internal/secrets"
	"github.com/phonginreallife/kernelseal/internal/server"
)

// stubProtector stands in for the BPF manager so the delivery path can be tested
// on kernels without BPF-LSM. It records the order of operations, which is what
// matters: a PID must be protected before its secrets are released.
type stubProtector struct {
	mu          sync.Mutex
	calls       []string
	protected   []uint32
	failProtect bool
}

func (s *stubProtector) ProtectPID(pid uint32) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.calls = append(s.calls, "protect")
	if s.failProtect {
		return os.ErrPermission
	}
	s.protected = append(s.protected, pid)
	return nil
}

func (s *stubProtector) UnprotectPID(pid uint32) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.calls = append(s.calls, "unprotect")
	return nil
}

func (s *stubProtector) TrackPID(pid uint32) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.calls = append(s.calls, "track")
	return nil
}

func (s *stubProtector) snapshot() ([]string, []uint32) {
	s.mu.Lock()
	defer s.mu.Unlock()
	return append([]string(nil), s.calls...), append([]uint32(nil), s.protected...)
}

// buildShim compiles kernelseal-exec once for the test binary's lifetime.
var buildShim = sync.OnceValues(func() (string, error) {
	dir, err := os.MkdirTemp("", "kernelseal-shim-*")
	if err != nil {
		return "", err
	}

	out := filepath.Join(dir, "kernelseal-exec")
	cmd := exec.Command("go", "build", "-o", out, "./cmd/kernelseal-exec")
	cmd.Dir = repoRoot()
	if combined, err := cmd.CombinedOutput(); err != nil {
		return "", &buildError{output: string(combined), err: err}
	}
	return out, nil
})

type buildError struct {
	output string
	err    error
}

func (e *buildError) Error() string {
	return "building kernelseal-exec: " + e.err.Error() + "\n" + e.output
}

func repoRoot() string {
	// This package lives at <root>/test/integration.
	return filepath.Join("..", "..")
}

// startServer brings up the socket server on a short temp path. Unix socket paths
// are limited to about 100 bytes, so avoid the long default TempDir names.
func startServer(t *testing.T, registry *secrets.Registry, protector server.Protector, requireProtection bool) string {
	t.Helper()

	dir, err := os.MkdirTemp("/tmp", "ks-*")
	if err != nil {
		t.Fatalf("creating socket dir: %v", err)
	}
	t.Cleanup(func() { os.RemoveAll(dir) })

	socketPath := filepath.Join(dir, "s.sock")

	srv := server.New(server.Config{
		SocketPath:        socketPath,
		SocketMode:        0o666, // the test process may run as any uid
		RequireProtection: requireProtection,
	}, registry, protector, nil)

	if err := srv.Listen(); err != nil {
		t.Fatalf("Listen: %v", err)
	}
	srv.Serve()
	t.Cleanup(srv.Close)

	return socketPath
}

// runShim executes the shim, which replaces itself with the given command.
func runShim(t *testing.T, socketPath string, args ...string) (stdout, stderr string, err error) {
	t.Helper()

	shim, buildErr := buildShim()
	if buildErr != nil {
		t.Fatalf("%v", buildErr)
	}

	argv := append([]string{"-socket", socketPath, "-timeout", "5s", "--"}, args...)
	cmd := exec.Command(shim, argv...)
	cmd.Env = []string{"PATH=" + os.Getenv("PATH"), "EXISTING_VAR=inherited"}

	var outBuf, errBuf strings.Builder
	cmd.Stdout = &outBuf
	cmd.Stderr = &errBuf
	err = cmd.Run()

	return outBuf.String(), errBuf.String(), err
}

// probeChown reports whether this environment can set a file's group to gid.
func probeChown(t *testing.T, gid int) error {
	t.Helper()

	f, err := os.CreateTemp("/tmp", "ks-chown-probe-*")
	if err != nil {
		return err
	}
	defer func() {
		f.Close()
		os.Remove(f.Name())
	}()

	return os.Chown(f.Name(), -1, gid)
}

func envValue(output, name string) (string, bool) {
	scanner := bufio.NewScanner(strings.NewReader(output))
	for scanner.Scan() {
		if v, ok := strings.CutPrefix(scanner.Text(), name+"="); ok {
			return v, true
		}
	}
	return "", false
}

// TestShimDelivery_SecretsReachTargetEnvironment is the end-to-end check that
// KernelSeal's central claim holds: the application sees its secrets as ordinary
// environment variables, without the secret ever touching the filesystem.
func TestShimDelivery_SecretsReachTargetEnvironment(t *testing.T) {
	registry := secrets.NewRegistry()
	registry.Replace([]secrets.Binding{{
		Name:     "env",
		Selector: secrets.Selector{Binary: "env"},
		Secrets: []secrets.Secret{
			{Name: "TEST_SECRET", Value: "integration-test-value"},
			{Name: "TEST_TOKEN", Value: "second-value"},
		},
	}})

	protector := &stubProtector{}
	socketPath := startServer(t, registry, protector, true)

	stdout, stderr, err := runShim(t, socketPath, "env")
	if err != nil {
		t.Fatalf("shim failed: %v\nstderr: %s", err, stderr)
	}

	if got, ok := envValue(stdout, "TEST_SECRET"); !ok || got != "integration-test-value" {
		t.Errorf("TEST_SECRET = %q (present=%v), want %q", got, ok, "integration-test-value")
	}
	if got, ok := envValue(stdout, "TEST_TOKEN"); !ok || got != "second-value" {
		t.Errorf("TEST_TOKEN = %q (present=%v), want %q", got, ok, "second-value")
	}

	// The inherited environment must survive.
	if got, ok := envValue(stdout, "EXISTING_VAR"); !ok || got != "inherited" {
		t.Errorf("EXISTING_VAR = %q (present=%v), want inherited", got, ok)
	}

	// Protection must be installed before the secrets are handed over.
	calls, protected := protector.snapshot()
	if len(protected) != 1 {
		t.Fatalf("ProtectPID called for %d pids, want 1 (calls: %v)", len(protected), calls)
	}
	if len(calls) == 0 || calls[0] != "protect" {
		t.Errorf("first protector call = %v, want protect to come first", calls)
	}
}

// A binary with no secrets bound must still start, unchanged.
func TestShimDelivery_NoSecretsBoundStillExecs(t *testing.T) {
	protector := &stubProtector{}
	socketPath := startServer(t, secrets.NewRegistry(), protector, true)

	stdout, stderr, err := runShim(t, socketPath, "env")
	if err != nil {
		t.Fatalf("shim failed: %v\nstderr: %s", err, stderr)
	}

	if got, ok := envValue(stdout, "EXISTING_VAR"); !ok || got != "inherited" {
		t.Errorf("EXISTING_VAR = %q (present=%v), want inherited", got, ok)
	}

	if _, protected := protector.snapshot(); len(protected) != 0 {
		t.Errorf("ProtectPID called %d times for a binary with no secrets, want 0", len(protected))
	}
}

// With RequireProtection set, secrets must be withheld when the kernel cannot
// guard them, and the shim must refuse to start rather than run unprotected.
func TestShimDelivery_FailsClosedWhenProtectionUnavailable(t *testing.T) {
	registry := secrets.NewRegistry()
	registry.Replace([]secrets.Binding{{
		Name:     "env",
		Selector: secrets.Selector{Binary: "env"},
		Secrets: []secrets.Secret{
			{Name: "TEST_SECRET", Value: "must-not-leak"},
		},
	}})

	protector := &stubProtector{failProtect: true}
	socketPath := startServer(t, registry, protector, true)

	stdout, stderr, err := runShim(t, socketPath, "env")
	if err == nil {
		t.Fatalf("shim succeeded but should have failed closed; stdout: %s", stdout)
	}
	if strings.Contains(stdout, "must-not-leak") {
		t.Error("secret value leaked into the target environment despite protection failing")
	}
	if !strings.Contains(stderr, "refusing to start") {
		t.Errorf("stderr did not explain the refusal: %s", stderr)
	}
}

// The shim must fail loudly rather than hang when the agent is absent.
func TestShimDelivery_UnreachableAgentFailsClosed(t *testing.T) {
	shim, err := buildShim()
	if err != nil {
		t.Fatalf("%v", err)
	}

	cmd := exec.Command(shim,
		"-socket", "/tmp/ks-does-not-exist.sock",
		"-timeout", "300ms",
		"-retry-interval", "50ms",
		"--", "env")
	cmd.Env = []string{"PATH=" + os.Getenv("PATH")}

	out, runErr := cmd.CombinedOutput()
	if runErr == nil {
		t.Fatalf("shim succeeded with no agent present; output: %s", out)
	}
	if !strings.Contains(string(out), "refusing to start") {
		t.Errorf("output did not explain the refusal: %s", out)
	}
}

// TestShimDelivery_UnprivilegedCallerReachesRootSocket covers the case a real
// deployment always hits: the agent runs as root, the application does not.
//
// A 0660 socket owned by root:root is reachable only by root, so the shim fails
// with EACCES on connect and, failing closed, refuses to start the application at
// all. Setting the socket group is what makes the unprivileged case work.
func TestShimDelivery_UnprivilegedCallerReachesRootSocket(t *testing.T) {
	if os.Getuid() != 0 {
		t.Skip("requires root to create a root-owned socket and drop privileges")
	}

	nobody, err := user.Lookup("nobody")
	if err != nil {
		t.Skipf("no nobody user to test with: %v", err)
	}
	uid, err := strconv.Atoi(nobody.Uid)
	if err != nil {
		t.Skipf("nobody has a non-numeric uid %q", nobody.Uid)
	}
	gid, err := strconv.Atoi(nobody.Gid)
	if err != nil {
		t.Skipf("nobody has a non-numeric gid %q", nobody.Gid)
	}

	// Sandboxes and user namespaces frequently cannot map a foreign gid, which
	// would fail as a chown error unrelated to what is being tested.
	if err := probeChown(t, gid); err != nil {
		t.Skipf("cannot chown to gid %d in this environment: %v", gid, err)
	}

	shim, err := buildShim()
	if err != nil {
		t.Fatalf("%v", err)
	}
	// MkdirTemp uses 0700, so an unprivileged process could not traverse to the
	// binary. Widen the path, not the binary.
	if err := os.Chmod(filepath.Dir(shim), 0o755); err != nil {
		t.Fatalf("widening shim directory: %v", err)
	}

	registry := secrets.NewRegistry()
	registry.Replace([]secrets.Binding{{
		Name:     "env",
		Selector: secrets.Selector{Binary: "env"},
		Secrets: []secrets.Secret{
			{Name: "TEST_SECRET", Value: "reached-across-privilege-boundary"},
		},
	}})

	dir, err := os.MkdirTemp("/tmp", "ks-priv-*")
	if err != nil {
		t.Fatalf("creating socket dir: %v", err)
	}
	t.Cleanup(func() { os.RemoveAll(dir) })

	socketPath := filepath.Join(dir, "s.sock")

	srv := server.New(server.Config{
		SocketPath: socketPath,
		SocketMode: 0o660,
		// Without this the socket stays root:root and the connect below fails.
		SocketGroup:       nobody.Gid,
		RequireProtection: false,
	}, registry, &stubProtector{}, nil)

	if err := srv.Listen(); err != nil {
		t.Fatalf("Listen: %v", err)
	}
	srv.Serve()
	t.Cleanup(srv.Close)

	cmd := exec.Command(shim, "-socket", socketPath, "-timeout", "5s", "--", "env")
	cmd.Env = []string{"PATH=" + os.Getenv("PATH")}
	cmd.SysProcAttr = &syscall.SysProcAttr{
		Credential: &syscall.Credential{Uid: uint32(uid), Gid: uint32(gid)},
	}

	var outBuf, errBuf strings.Builder
	cmd.Stdout = &outBuf
	cmd.Stderr = &errBuf

	if err := cmd.Run(); err != nil {
		t.Fatalf("shim failed as an unprivileged caller: %v\nstderr: %s", err, errBuf.String())
	}

	if got, ok := envValue(outBuf.String(), "TEST_SECRET"); !ok || got != "reached-across-privilege-boundary" {
		t.Errorf("TEST_SECRET = %q (present=%v), want the delivered value", got, ok)
	}
}

// With -on-error=continue the shim starts the application anyway.
func TestShimDelivery_ContinueOnErrorExecsWithoutSecrets(t *testing.T) {
	shim, err := buildShim()
	if err != nil {
		t.Fatalf("%v", err)
	}

	cmd := exec.Command(shim,
		"-socket", "/tmp/ks-does-not-exist.sock",
		"-timeout", "300ms",
		"-retry-interval", "50ms",
		"-on-error", "continue",
		"--", "env")
	cmd.Env = []string{"PATH=" + os.Getenv("PATH"), "EXISTING_VAR=inherited"}

	out, runErr := cmd.CombinedOutput()
	if runErr != nil {
		t.Fatalf("shim failed despite -on-error=continue: %v\noutput: %s", runErr, out)
	}
	if got, ok := envValue(string(out), "EXISTING_VAR"); !ok || got != "inherited" {
		t.Errorf("EXISTING_VAR = %q (present=%v), want inherited", got, ok)
	}
}
