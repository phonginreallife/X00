package server

import (
	"os"
	"os/user"
	"path/filepath"
	"strconv"
	"syscall"
	"testing"

	"github.com/phonginreallife/kernelseal/internal/secrets"
)

// noopProtector satisfies the Protector interface for tests that only care about
// socket setup.
type noopProtector struct{}

func (noopProtector) ProtectPID(uint32) error   { return nil }
func (noopProtector) UnprotectPID(uint32) error { return nil }
func (noopProtector) TrackPID(uint32) error     { return nil }

// shortSocketDir returns a directory with a short path, since unix socket paths
// are limited to roughly 100 bytes.
func shortSocketDir(t *testing.T) string {
	t.Helper()

	dir, err := os.MkdirTemp("/tmp", "ks-sock-*")
	if err != nil {
		t.Fatalf("creating socket dir: %v", err)
	}
	t.Cleanup(func() { os.RemoveAll(dir) })
	return dir
}

func TestListen_AppliesSocketMode(t *testing.T) {
	socketPath := filepath.Join(shortSocketDir(t), "s.sock")

	srv := New(Config{SocketPath: socketPath, SocketMode: 0o660},
		secrets.NewRegistry(), noopProtector{})

	if err := srv.Listen(); err != nil {
		t.Fatalf("Listen: %v", err)
	}
	defer srv.Close()

	info, err := os.Stat(socketPath)
	if err != nil {
		t.Fatalf("stat socket: %v", err)
	}
	if perm := info.Mode().Perm(); perm != 0o660 {
		t.Errorf("socket mode = %#o, want 0660", perm)
	}
}

func TestListen_DefaultsSocketMode(t *testing.T) {
	socketPath := filepath.Join(shortSocketDir(t), "s.sock")

	// A zero mode must not produce an inaccessible socket.
	srv := New(Config{SocketPath: socketPath}, secrets.NewRegistry(), noopProtector{})

	if err := srv.Listen(); err != nil {
		t.Fatalf("Listen: %v", err)
	}
	defer srv.Close()

	info, err := os.Stat(socketPath)
	if err != nil {
		t.Fatalf("stat socket: %v", err)
	}
	if perm := info.Mode().Perm(); perm != 0o660 {
		t.Errorf("default socket mode = %#o, want 0660", perm)
	}
}

// A socket left behind by an unclean shutdown must not prevent startup.
func TestListen_ReplacesStaleSocket(t *testing.T) {
	socketPath := filepath.Join(shortSocketDir(t), "s.sock")

	if err := os.WriteFile(socketPath, []byte("stale"), 0o600); err != nil {
		t.Fatalf("creating stale socket file: %v", err)
	}

	srv := New(Config{SocketPath: socketPath}, secrets.NewRegistry(), noopProtector{})
	if err := srv.Listen(); err != nil {
		t.Fatalf("Listen over a stale socket: %v", err)
	}
	srv.Close()
}

func TestListen_CreatesParentDirectory(t *testing.T) {
	socketPath := filepath.Join(shortSocketDir(t), "nested", "s.sock")

	srv := New(Config{SocketPath: socketPath}, secrets.NewRegistry(), noopProtector{})
	if err := srv.Listen(); err != nil {
		t.Fatalf("Listen: %v", err)
	}
	defer srv.Close()

	if _, err := os.Stat(socketPath); err != nil {
		t.Errorf("socket not created in a new directory: %v", err)
	}
}

func TestListen_UnknownSocketGroupFails(t *testing.T) {
	socketPath := filepath.Join(shortSocketDir(t), "s.sock")

	srv := New(Config{
		SocketPath:  socketPath,
		SocketGroup: "definitely-not-a-real-group-name",
	}, secrets.NewRegistry(), noopProtector{})

	if err := srv.Listen(); err == nil {
		srv.Close()
		t.Error("Listen accepted an unknown socket group; it should fail loudly")
	}
}

// The socket group is what lets an unprivileged caller reach a root-owned socket,
// so a numeric GID must work even where group name lookup does not.
func TestListen_AppliesNumericSocketGroup(t *testing.T) {
	socketPath := filepath.Join(shortSocketDir(t), "s.sock")

	gid := os.Getgid()
	srv := New(Config{
		SocketPath:  socketPath,
		SocketGroup: strconv.Itoa(gid),
	}, secrets.NewRegistry(), noopProtector{})

	if err := srv.Listen(); err != nil {
		t.Fatalf("Listen with a numeric group: %v", err)
	}
	defer srv.Close()

	if _, err := os.Stat(socketPath); err != nil {
		t.Errorf("stat socket: %v", err)
	}
}

// Callers traverse the parent directory before they can open the socket.
func TestListen_AppliesSocketGroupToParentDirectory(t *testing.T) {
	base := shortSocketDir(t)
	socketPath := filepath.Join(base, "nested", "s.sock")

	gid := os.Getgid()
	srv := New(Config{
		SocketPath:  socketPath,
		SocketGroup: strconv.Itoa(gid),
	}, secrets.NewRegistry(), noopProtector{})

	if err := srv.Listen(); err != nil {
		t.Fatalf("Listen: %v", err)
	}
	defer srv.Close()

	dirInfo, err := os.Stat(filepath.Dir(socketPath))
	if err != nil {
		t.Fatalf("stat parent directory: %v", err)
	}
	if got := dirInfo.Sys().(*syscall.Stat_t).Gid; got != uint32(gid) {
		t.Errorf("parent directory gid = %d, want %d", got, gid)
	}
	if perm := dirInfo.Mode().Perm(); perm != 0o750 {
		t.Errorf("parent directory mode = %#o, want 0750", perm)
	}
}

func TestLookupGID(t *testing.T) {
	// Numeric values pass through untouched.
	if gid, err := lookupGID("0"); err != nil || gid != 0 {
		t.Errorf("lookupGID(\"0\") = %d, %v; want 0, nil", gid, err)
	}

	// A name that exists on effectively every Linux system.
	grp, err := user.LookupGroupId(strconv.Itoa(os.Getgid()))
	if err != nil {
		t.Skipf("cannot resolve the current gid to a name: %v", err)
	}

	gid, err := lookupGID(grp.Name)
	if err != nil {
		t.Fatalf("lookupGID(%q): %v", grp.Name, err)
	}
	if gid != os.Getgid() {
		t.Errorf("lookupGID(%q) = %d, want %d", grp.Name, gid, os.Getgid())
	}
}

func TestLookupGID_Unknown(t *testing.T) {
	if _, err := lookupGID("definitely-not-a-real-group-name"); err == nil {
		t.Error("expected an error for an unknown group name")
	}
}

// Close must be safe to call twice, since shutdown paths can overlap.
func TestClose_Idempotent(t *testing.T) {
	socketPath := filepath.Join(shortSocketDir(t), "s.sock")

	srv := New(Config{SocketPath: socketPath}, secrets.NewRegistry(), noopProtector{})
	if err := srv.Listen(); err != nil {
		t.Fatalf("Listen: %v", err)
	}
	srv.Serve()

	srv.Close()
	srv.Close()

	if _, err := os.Stat(socketPath); !os.IsNotExist(err) {
		t.Errorf("socket still present after Close: %v", err)
	}
}
