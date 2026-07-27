// Package integration contains integration and system tests for KernelSeal.
//
// The tests in this file need root, a kernel booted with bpf in its lsm= list,
// and compiled BPF objects. They skip otherwise, so a normal `go test` run is
// still useful; a privileged runner is required to actually exercise
// enforcement. Run them with: make test-integration
package integration

import (
	"errors"
	"os"
	"os/exec"
	"runtime"
	"strings"
	"syscall"
	"testing"
	"time"

	"kernelseal/internal/bpf"
	"kernelseal/internal/types"
)

const (
	execMonitorObject = "../../bpf/exec_monitor.bpf.o"
	lsmObject         = "../../bpf/lsm_file_protect.bpf.o"
)

// bpfLSMAvailable reports whether the running kernel exposes the BPF LSM hook.
func bpfLSMAvailable() bool {
	data, err := os.ReadFile("/sys/kernel/security/lsm")
	if err != nil {
		return false
	}
	for _, name := range strings.Split(strings.TrimSpace(string(data)), ",") {
		if name == "bpf" {
			return true
		}
	}
	return false
}

func requireLSM(t *testing.T) {
	t.Helper()

	if os.Getuid() != 0 {
		t.Skip("requires root")
	}
	if !bpfLSMAvailable() {
		t.Skip("requires a kernel booted with bpf in its lsm= list")
	}
	if _, err := os.Stat(lsmObject); os.IsNotExist(err) {
		t.Skip("BPF objects not compiled; run make bpf")
	}
}

// loadLSM brings up the LSM programs in enforce mode. It deliberately does not
// add the test process to the allow list, so the test itself is subject to
// enforcement.
func loadLSM(t *testing.T) *bpf.Manager {
	t.Helper()

	mgr := bpf.NewManager()
	if err := mgr.LoadLSM(lsmObject); err != nil {
		t.Fatalf("LoadLSM: %v", err)
	}
	if !mgr.IsLSMLoaded() {
		t.Skip("LSM programs did not attach on this kernel")
	}
	t.Cleanup(mgr.Stop)

	if err := mgr.ConfigurePolicy(types.NewDefaultPolicy()); err != nil {
		t.Fatalf("ConfigurePolicy: %v", err)
	}
	return mgr
}

// startSleeper spawns a child process for the test to target.
func startSleeper(t *testing.T) uint32 {
	t.Helper()

	cmd := exec.Command("sleep", "30")
	if err := cmd.Start(); err != nil {
		t.Fatalf("starting child: %v", err)
	}
	t.Cleanup(func() {
		_ = cmd.Process.Kill()
		_, _ = cmd.Process.Wait()
	})

	// #nosec G115 - a PID is always positive and fits in uint32
	return uint32(cmd.Process.Pid) //nolint:gosec
}

// TestLSM_BlocksEnvironRead is the test that proves KernelSeal's core promise:
// once a process is protected, another process cannot read its environment.
func TestLSM_BlocksEnvironRead(t *testing.T) {
	requireLSM(t)
	mgr := loadLSM(t)

	pid := startSleeper(t)
	environPath := procPath(pid, "environ")

	// Control: readable before protection.
	if _, err := os.ReadFile(environPath); err != nil {
		t.Fatalf("environ should be readable before protection: %v", err)
	}

	if err := mgr.ProtectPID(pid); err != nil {
		t.Fatalf("ProtectPID: %v", err)
	}

	if _, err := os.ReadFile(environPath); !errors.Is(err, syscall.EPERM) {
		t.Errorf("reading a protected process's environ = %v, want EPERM", err)
	}
}

// TestLSM_BlocksMemRead covers /proc/<pid>/mem.
func TestLSM_BlocksMemRead(t *testing.T) {
	requireLSM(t)
	mgr := loadLSM(t)

	pid := startSleeper(t)
	if err := mgr.ProtectPID(pid); err != nil {
		t.Fatalf("ProtectPID: %v", err)
	}

	f, err := os.Open(procPath(pid, "mem"))
	if err == nil {
		f.Close()
		t.Error("opening a protected process's mem succeeded, want EPERM")
		return
	}
	if !errors.Is(err, syscall.EPERM) {
		t.Errorf("opening a protected process's mem = %v, want EPERM", err)
	}
}

// TestLSM_BlocksMaps exercises the blockMaps policy field, which was present in
// the config and the shared header but had no enforcement behind it.
func TestLSM_BlocksMaps(t *testing.T) {
	requireLSM(t)
	mgr := loadLSM(t)

	policy := types.NewDefaultPolicy()
	policy.BlockMaps = 1
	if err := mgr.ConfigurePolicy(policy); err != nil {
		t.Fatalf("ConfigurePolicy: %v", err)
	}

	pid := startSleeper(t)
	if err := mgr.ProtectPID(pid); err != nil {
		t.Fatalf("ProtectPID: %v", err)
	}

	if _, err := os.ReadFile(procPath(pid, "maps")); !errors.Is(err, syscall.EPERM) {
		t.Errorf("reading a protected process's maps = %v, want EPERM", err)
	}
}

// TestLSM_BlocksPtrace verifies the ptrace hook. This is the behavior that the
// policy struct mismatch silently disabled: blockPtrace was read from the wrong
// byte, so it was always zero.
func TestLSM_BlocksPtrace(t *testing.T) {
	requireLSM(t)
	mgr := loadLSM(t)

	pid := startSleeper(t)
	if err := mgr.ProtectPID(pid); err != nil {
		t.Fatalf("ProtectPID: %v", err)
	}

	// ptrace state is per-thread, so the attach must happen on a pinned thread.
	runtime.LockOSThread()
	defer runtime.UnlockOSThread()

	err := syscall.PtraceAttach(int(pid))
	if err == nil {
		_ = syscall.PtraceDetach(int(pid))
		t.Error("ptrace attach to a protected process succeeded, want EPERM")
		return
	}
	if !errors.Is(err, syscall.EPERM) {
		t.Errorf("ptrace attach to a protected process = %v, want EPERM", err)
	}
}

// TestLSM_LeavesUnprotectedProcessesAlone is the control case: enforcement must
// not become a blanket denial of /proc.
func TestLSM_LeavesUnprotectedProcessesAlone(t *testing.T) {
	requireLSM(t)
	loadLSM(t)

	pid := startSleeper(t)

	if _, err := os.ReadFile(procPath(pid, "environ")); err != nil {
		t.Errorf("reading an unprotected process's environ failed: %v", err)
	}
}

// TestLSM_UnprotectRestoresAccess confirms cleanup actually lifts enforcement,
// so a recycled PID is not left guarded.
func TestLSM_UnprotectRestoresAccess(t *testing.T) {
	requireLSM(t)
	mgr := loadLSM(t)

	pid := startSleeper(t)
	environPath := procPath(pid, "environ")

	if err := mgr.ProtectPID(pid); err != nil {
		t.Fatalf("ProtectPID: %v", err)
	}
	if _, err := os.ReadFile(environPath); !errors.Is(err, syscall.EPERM) {
		t.Fatalf("environ read = %v, want EPERM while protected", err)
	}

	if err := mgr.UnprotectPID(pid); err != nil {
		t.Fatalf("UnprotectPID: %v", err)
	}
	if _, err := os.ReadFile(environPath); err != nil {
		t.Errorf("environ should be readable after unprotect: %v", err)
	}
}

// TestBPF_ExecMonitorReportsExec checks that the exec tracepoint actually
// delivers events to user space.
func TestBPF_ExecMonitorReportsExec(t *testing.T) {
	if os.Getuid() != 0 {
		t.Skip("requires root")
	}
	if _, err := os.Stat(execMonitorObject); os.IsNotExist(err) {
		t.Skip("BPF objects not compiled; run make bpf")
	}

	mgr := bpf.NewManager()
	if err := mgr.LoadExecMonitor(execMonitorObject); err != nil {
		// Sandboxes and containers often lack CAP_BPF, CAP_PERFMON or
		// CAP_SYS_RESOURCE even when running as uid 0.
		if errors.Is(err, syscall.EPERM) || errors.Is(err, syscall.EACCES) {
			t.Skipf("insufficient privileges to load BPF here: %v", err)
		}
		t.Fatalf("LoadExecMonitor: %v", err)
	}

	events := make(chan *types.ExecEvent, 128)
	mgr.SetExecHandler(func(event *types.ExecEvent) {
		select {
		case events <- event:
		default:
		}
	})

	mgr.Start()
	defer mgr.Stop()

	// Give the ring buffer reader a moment to come up before generating traffic.
	time.Sleep(100 * time.Millisecond)

	if err := exec.Command("true").Run(); err != nil {
		t.Fatalf("running /bin/true: %v", err)
	}

	deadline := time.After(5 * time.Second)
	for {
		select {
		case event := <-events:
			if event.EventType == types.EventExec && event.PID != 0 {
				return
			}
		case <-deadline:
			t.Fatal("no exec event received within 5s")
		}
	}
}

func procPath(pid uint32, file string) string {
	return "/proc/" + itoa(pid) + "/" + file
}

func itoa(v uint32) string {
	if v == 0 {
		return "0"
	}
	var buf [10]byte
	i := len(buf)
	for v > 0 {
		i--
		buf[i] = byte('0' + v%10)
		v /= 10
	}
	return string(buf[i:])
}
