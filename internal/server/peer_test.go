package server

import (
	"os"
	"os/exec"
	"strings"
	"testing"
)

func TestProcessStartTime_CurrentProcess(t *testing.T) {
	pid := uint32(os.Getpid())

	got, err := processStartTime(pid)
	if err != nil {
		t.Fatalf("processStartTime: %v", err)
	}
	if got == 0 {
		t.Error("start time = 0, want a non-zero tick count")
	}

	// The value must be stable, since the whole point is to detect PID reuse.
	again, err := processStartTime(pid)
	if err != nil {
		t.Fatalf("processStartTime (second call): %v", err)
	}
	if again != got {
		t.Errorf("start time changed between calls: %d then %d", got, again)
	}
}

func TestProcessStartTime_NonexistentPID(t *testing.T) {
	if _, err := processStartTime(0); err == nil {
		t.Error("expected an error for pid 0")
	}
}

// A process whose name contains spaces and parentheses must still parse, because
// field 2 of /proc/<pid>/stat is unescaped and would break naive splitting.
func TestProcessStartTime_AwkwardProcessName(t *testing.T) {
	dir := t.TempDir()
	weird := dir + "/we ird) (name"

	// Copy a small, reliably present binary under an awkward name.
	sleepPath, err := exec.LookPath("sleep")
	if err != nil {
		t.Skip("sleep not available")
	}
	data, err := os.ReadFile(sleepPath)
	if err != nil {
		t.Skipf("cannot read %s: %v", sleepPath, err)
	}
	if err := os.WriteFile(weird, data, 0o755); err != nil { //nolint:gosec // test fixture must be executable
		t.Fatalf("writing fixture: %v", err)
	}

	cmd := exec.Command(weird, "5")
	if err := cmd.Start(); err != nil {
		t.Skipf("cannot start fixture: %v", err)
	}
	t.Cleanup(func() {
		_ = cmd.Process.Kill()
		_, _ = cmd.Process.Wait()
	})

	// #nosec G115 - a PID is always positive and fits in uint32
	got, err := processStartTime(uint32(cmd.Process.Pid)) //nolint:gosec
	if err != nil {
		t.Fatalf("processStartTime on a process named %q: %v", weird, err)
	}
	if got == 0 {
		t.Error("start time = 0, want a non-zero tick count")
	}
}

func TestProcessExe(t *testing.T) {
	// #nosec G115 - a PID is always positive and fits in uint32
	got := processExe(uint32(os.Getpid())) //nolint:gosec
	if got == "unknown" || got == "" {
		t.Errorf("processExe = %q, want a resolved path", got)
	}
}

func TestProcessExe_NonexistentPID(t *testing.T) {
	if got := processExe(0); got != "unknown" {
		t.Errorf("processExe(0) = %q, want unknown", got)
	}
}

func TestProcessCgroup(t *testing.T) {
	// #nosec G115 - a PID is always positive and fits in uint32
	got := processCgroup(uint32(os.Getpid())) //nolint:gosec
	if got == "" {
		t.Error("processCgroup returned an empty string")
	}
	if got != "unknown" && !strings.HasPrefix(got, "/") {
		t.Errorf("processCgroup = %q, want a path or unknown", got)
	}
}

func TestProcessCgroup_NonexistentPID(t *testing.T) {
	if got := processCgroup(0); got != "unknown" {
		t.Errorf("processCgroup(0) = %q, want unknown", got)
	}
}
