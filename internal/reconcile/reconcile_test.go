package reconcile

import (
	"errors"
	"os"
	"sync"
	"testing"
	"time"
)

type fakeStore struct {
	mu           sync.Mutex
	pids         []uint32
	unprotected  []uint32
	listErr      error
	unprotectErr error
}

func (f *fakeStore) ListProtectedPIDs() ([]uint32, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.listErr != nil {
		return nil, f.listErr
	}
	return append([]uint32(nil), f.pids...), nil
}

func (f *fakeStore) UnprotectPID(pid uint32) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.unprotectErr != nil {
		return f.unprotectErr
	}
	f.unprotected = append(f.unprotected, pid)
	return nil
}

func (f *fakeStore) unprotectedPIDs() []uint32 {
	f.mu.Lock()
	defer f.mu.Unlock()
	return append([]uint32(nil), f.unprotected...)
}

func TestSweep_DropsOnlyDeadPIDs(t *testing.T) {
	store := &fakeStore{pids: []uint32{100, 200, 300}}

	r := New(store, time.Minute)
	r.alive = func(pid uint32) bool { return pid == 200 }

	removed, err := r.Sweep()
	if err != nil {
		t.Fatalf("Sweep: %v", err)
	}
	if removed != 2 {
		t.Errorf("removed = %d, want 2", removed)
	}

	got := store.unprotectedPIDs()
	want := []uint32{100, 300}
	if len(got) != len(want) {
		t.Fatalf("unprotected = %v, want %v", got, want)
	}
	for i := range want {
		if got[i] != want[i] {
			t.Fatalf("unprotected = %v, want %v", got, want)
		}
	}

	if r.Reclaimed() != 2 {
		t.Errorf("Reclaimed = %d, want 2", r.Reclaimed())
	}
}

func TestSweep_AllAliveIsNoOp(t *testing.T) {
	store := &fakeStore{pids: []uint32{1, 2, 3}}

	r := New(store, time.Minute)
	r.alive = func(uint32) bool { return true }

	removed, err := r.Sweep()
	if err != nil {
		t.Fatalf("Sweep: %v", err)
	}
	if removed != 0 {
		t.Errorf("removed = %d, want 0", removed)
	}
	if got := store.unprotectedPIDs(); len(got) != 0 {
		t.Errorf("unprotected = %v, want none", got)
	}
}

func TestSweep_PropagatesListError(t *testing.T) {
	sentinel := errors.New("map iteration failed")
	r := New(&fakeStore{listErr: sentinel}, time.Minute)

	if _, err := r.Sweep(); !errors.Is(err, sentinel) {
		t.Errorf("Sweep error = %v, want %v", err, sentinel)
	}
}

// A PID that cannot be unprotected must not be counted as reclaimed, otherwise
// the metric would suggest cleanup that did not happen.
func TestSweep_UnprotectFailureNotCounted(t *testing.T) {
	store := &fakeStore{
		pids:         []uint32{100},
		unprotectErr: errors.New("map delete failed"),
	}

	r := New(store, time.Minute)
	r.alive = func(uint32) bool { return false }

	removed, err := r.Sweep()
	if err != nil {
		t.Fatalf("Sweep: %v", err)
	}
	if removed != 0 {
		t.Errorf("removed = %d, want 0", removed)
	}
	if r.Reclaimed() != 0 {
		t.Errorf("Reclaimed = %d, want 0", r.Reclaimed())
	}
}

func TestNew_DefaultsInterval(t *testing.T) {
	if got := New(&fakeStore{}, 0).interval; got != DefaultInterval {
		t.Errorf("interval = %v, want %v", got, DefaultInterval)
	}
	if got := New(&fakeStore{}, -time.Second).interval; got != DefaultInterval {
		t.Errorf("interval = %v, want %v", got, DefaultInterval)
	}
}

func TestStartStop_SweepsPeriodically(t *testing.T) {
	store := &fakeStore{pids: []uint32{42}}

	r := New(store, 10*time.Millisecond)
	r.alive = func(uint32) bool { return false }

	r.Start()
	defer r.Stop()

	deadline := time.After(2 * time.Second)
	for {
		if r.Reclaimed() > 0 {
			return
		}
		select {
		case <-deadline:
			t.Fatal("reconciler did not sweep within 2s")
		case <-time.After(5 * time.Millisecond):
		}
	}
}

// Stop must be safe to call more than once, since shutdown paths can overlap.
func TestStop_Idempotent(t *testing.T) {
	r := New(&fakeStore{}, time.Minute)
	r.Start()
	r.Stop()
	r.Stop()
}

func TestProcessAlive(t *testing.T) {
	if !ProcessAlive(uint32(os.Getpid())) {
		t.Error("ProcessAlive returned false for the current process")
	}
	// PID 0 is never a userspace process, so /proc/0 does not exist.
	if ProcessAlive(0) {
		t.Error("ProcessAlive returned true for pid 0")
	}
}
