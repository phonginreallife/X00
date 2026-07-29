// Package integration contains integration and system tests for KernelSeal.
//
// The tests in this file close the gap that let a protection leak ship: the LSM
// tests write protected_pids directly and never exec, and the shim delivery tests
// use a stub protector. Neither exercises the path that actually matters in
// production - the shim receives secrets, execs the target, and the target's
// environment must still be guarded afterwards.
package integration

import (
	"errors"
	"os"
	"os/exec"
	"strings"
	"syscall"
	"testing"
	"time"

	"kernelseal/internal/bpf"
	"kernelseal/internal/reconcile"
	"kernelseal/internal/secrets"
	"kernelseal/internal/types"
)

// startShim launches the shim without waiting for it, so the test can inspect the
// process it turns into. The returned PID survives the exec.
func startShim(t *testing.T, socketPath string, args ...string) (*exec.Cmd, uint32) {
	t.Helper()

	shim, buildErr := buildShim()
	if buildErr != nil {
		t.Fatalf("%v", buildErr)
	}

	argv := append([]string{"-socket", socketPath, "-timeout", "5s", "--"}, args...)
	cmd := exec.Command(shim, argv...)
	cmd.Env = []string{"PATH=" + os.Getenv("PATH")}

	var errBuf strings.Builder
	cmd.Stderr = &errBuf

	if err := cmd.Start(); err != nil {
		t.Fatalf("starting shim: %v", err)
	}
	t.Cleanup(func() {
		_ = cmd.Process.Kill()
		_, _ = cmd.Process.Wait()
		if errBuf.Len() > 0 {
			t.Logf("shim stderr: %s", errBuf.String())
		}
	})

	// #nosec G115 - a PID is always positive and fits in uint32
	return cmd, uint32(cmd.Process.Pid) //nolint:gosec
}

// waitForComm blocks until the process's comm matches want, which is how the test
// knows the shim has finished exec'ing into the target.
func waitForComm(t *testing.T, pid uint32, want string) {
	t.Helper()

	deadline := time.Now().Add(10 * time.Second)
	for time.Now().Before(deadline) {
		data, err := os.ReadFile(procPath(pid, "comm"))
		if err != nil {
			t.Fatalf("pid %d disappeared before exec'ing into %q: %v", pid, want, err)
		}
		if strings.TrimSpace(string(data)) == want {
			return
		}
		time.Sleep(20 * time.Millisecond)
	}
	t.Fatalf("pid %d never exec'd into %q", pid, want)
}

// loadExecMonitor brings up the exec tracepoints and returns the manager plus a
// channel of every event delivered to user space.
func loadExecMonitor(t *testing.T) (*bpf.Manager, <-chan *types.ExecEvent) {
	t.Helper()

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

	events := make(chan *types.ExecEvent, 1024)
	mgr.SetExecHandler(func(event *types.ExecEvent) {
		select {
		case events <- event:
		default:
		}
	})

	mgr.Start()
	t.Cleanup(mgr.Stop)

	// Let the ring buffer reader come up before generating traffic.
	time.Sleep(100 * time.Millisecond)

	return mgr, events
}

// TestExecMonitor_ThreadExitIsNotProcessExit pins the tracepoint semantics that
// caused the leak. sched_process_exit fires for every thread, and everything in
// the exec monitor is keyed by tgid, so a sibling thread's exit used to be
// reported as the process exiting. Any multithreaded process tripped it, and the
// shim trips it every time: execve zaps the Go runtime's other threads before the
// target ever starts.
func TestExecMonitor_ThreadExitIsNotProcessExit(t *testing.T) {
	_, events := loadExecMonitor(t)

	// An empty registry means the shim execs immediately without asking to be
	// protected; this test is only about which lifecycle events are reported.
	socketPath := startServer(t, secrets.NewRegistry(), &stubProtector{}, false)

	cmd, pid := startShim(t, socketPath, "sleep", "30")
	waitForComm(t, pid, "sleep")

	// The shim is multithreaded and has just exec'd, so if thread exits leaked
	// through as process exits, the event is already queued.
	drain := time.After(1500 * time.Millisecond)
	for {
		select {
		case event := <-events:
			if event.EventType == types.EventExit && event.PID == pid {
				t.Fatalf("got an exit event for PID %d while it is still running "+
					"(a sibling thread's exit was reported as the process exiting)", pid)
			}
		case <-drain:
			goto killIt
		}
	}

killIt:
	// The real exit must still be reported, or the fix would have traded a
	// protection leak for stale entries that only the reconcile sweep clears.
	if err := cmd.Process.Kill(); err != nil {
		t.Fatalf("killing target: %v", err)
	}
	_, _ = cmd.Process.Wait()

	deadline := time.After(5 * time.Second)
	for {
		select {
		case event := <-events:
			if event.EventType == types.EventExit && event.PID == pid {
				return
			}
		case <-deadline:
			t.Fatalf("no exit event for PID %d within 5s after it was killed", pid)
		}
	}
}

// TestShimDelivery_ProtectionSurvivesExec is the end-to-end regression test: run
// the real shim against the real BPF-LSM and confirm the target's environment is
// unreadable once it is running. Before the exec monitor learned to ignore
// non-final thread exits, the exit event fired during the shim's own execve and
// user space dropped protection microseconds after installing it, so the secrets
// were readable out of /proc for the whole life of the process.
func TestShimDelivery_ProtectionSurvivesExec(t *testing.T) {
	requireLSM(t)

	mgr, _ := loadExecMonitor(t)

	if err := mgr.LoadLSM(lsmObject); err != nil {
		t.Fatalf("LoadLSM: %v", err)
	}
	if !mgr.IsLSMLoaded() {
		t.Skip("LSM programs did not attach on this kernel")
	}
	if err := mgr.ConfigurePolicy(types.NewDefaultPolicy()); err != nil {
		t.Fatalf("ConfigurePolicy: %v", err)
	}

	// Mirror the agent's exit handling, including its refusal to act on an exit
	// report for a process that is demonstrably still alive.
	mgr.SetExecHandler(func(event *types.ExecEvent) {
		if event.EventType != types.EventExit {
			return
		}
		if reconcile.ProcessAlive(event.PID) {
			return
		}
		if err := mgr.UnprotectPID(event.PID); err != nil {
			t.Logf("UnprotectPID(%d): %v", event.PID, err)
		}
	})

	registry := secrets.NewRegistry()
	registry.RegisterForBinary("sleep", []secrets.Secret{
		{Name: "TEST_SECRET", Value: "must-not-be-readable"},
	})
	socketPath := startServer(t, registry, mgr, true)

	_, pid := startShim(t, socketPath, "sleep", "30")
	waitForComm(t, pid, "sleep")

	// Give any spurious exit event time to be processed, so a regression fails
	// here rather than racing past.
	time.Sleep(500 * time.Millisecond)

	protected, err := mgr.ListProtectedPIDs()
	if err != nil {
		t.Fatalf("ListProtectedPIDs: %v", err)
	}
	if !containsPID(protected, pid) {
		t.Errorf("PID %d is not in protected_pids after exec (protected: %v)", pid, protected)
	}

	data, err := os.ReadFile(procPath(pid, "environ"))
	if !errors.Is(err, syscall.EPERM) {
		t.Errorf("reading the target's environ = %v, want EPERM", err)
	}
	if strings.Contains(string(data), "must-not-be-readable") {
		t.Error("the secret was readable out of /proc after the shim exec'd")
	}
}

func containsPID(pids []uint32, want uint32) bool {
	for _, pid := range pids {
		if pid == want {
			return true
		}
	}
	return false
}
