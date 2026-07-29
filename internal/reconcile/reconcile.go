// Package reconcile keeps the kernel's protected-PID set from drifting out of
// sync with reality.
//
// Cleanup normally happens when the sched_process_exit tracepoint reports a
// process going away. That path is not guaranteed: the BPF map driving it is an
// LRU hash, so under load an entry can be evicted before the process exits and
// the exit event is then never reported. A protected entry left behind would
// eventually be inherited by an unrelated process reusing that PID, so a periodic
// sweep drops entries whose process no longer exists.
package reconcile

import (
	"log"
	"os"
	"strconv"
	"sync"
	"sync/atomic"
	"time"
)

// DefaultInterval is how often the sweep runs when no interval is configured.
const DefaultInterval = 30 * time.Second

// Store is the subset of the BPF manager the reconciler needs.
type Store interface {
	ListProtectedPIDs() ([]uint32, error)
	UnprotectPID(pid uint32) error
}

// Reconciler periodically drops protection for processes that no longer exist.
type Reconciler struct {
	store    Store
	interval time.Duration

	// alive reports whether a PID is still running. Overridable for tests.
	alive func(pid uint32) bool

	reclaimed atomic.Uint64

	stopCh chan struct{}
	wg     sync.WaitGroup
	closer sync.Once
}

// New creates a reconciler. An interval of zero selects DefaultInterval.
func New(store Store, interval time.Duration) *Reconciler {
	if interval <= 0 {
		interval = DefaultInterval
	}
	return &Reconciler{
		store:    store,
		interval: interval,
		alive:    processAlive,
		stopCh:   make(chan struct{}),
	}
}

// Reclaimed reports how many stale entries have been dropped.
func (r *Reconciler) Reclaimed() uint64 { return r.reclaimed.Load() }

// Start runs the sweep loop in the background.
func (r *Reconciler) Start() {
	r.wg.Add(1)
	go func() {
		defer r.wg.Done()

		ticker := time.NewTicker(r.interval)
		defer ticker.Stop()

		for {
			select {
			case <-r.stopCh:
				return
			case <-ticker.C:
				if n, err := r.Sweep(); err != nil {
					log.Printf("[WARN] Reconcile sweep failed: %v", err)
				} else if n > 0 {
					log.Printf("[RECONCILE] Released protection for %d exited process(es)", n)
				}
			}
		}
	}()
}

// Stop ends the sweep loop.
func (r *Reconciler) Stop() {
	r.closer.Do(func() {
		close(r.stopCh)
		r.wg.Wait()
	})
}

// Sweep drops protection for every protected PID that is no longer running and
// returns how many entries it removed.
func (r *Reconciler) Sweep() (int, error) {
	pids, err := r.store.ListProtectedPIDs()
	if err != nil {
		return 0, err
	}

	removed := 0
	for _, pid := range pids {
		if r.alive(pid) {
			continue
		}
		if err := r.store.UnprotectPID(pid); err != nil {
			log.Printf("[WARN] Failed to release protection for exited PID %d: %v", pid, err)
			continue
		}
		removed++
	}

	if removed > 0 {
		r.reclaimed.Add(uint64(removed))
	}
	return removed, nil
}

// processAlive reports whether a PID currently exists.
//
// This is only sound on the sweep's timescale. It cannot be reused to validate
// an exit event: sched_process_exit fires from inside do_exit(), so the task
// still has a /proc entry at that moment and every genuine exit would look like
// a live process.
func processAlive(pid uint32) bool {
	_, err := os.Stat("/proc/" + strconv.FormatUint(uint64(pid), 10))
	return err == nil
}
