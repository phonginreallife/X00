// Package secrets holds the resolved secret values and decides which of them
// apply to a given process.
//
// KernelSeal does not write secrets into the filesystem and does not rewrite a
// running process's memory. Values are handed to the kernelseal-exec shim over a
// unix socket and applied to the environment before the target binary is exec'd,
// so the application reads them as ordinary environment variables. See
// internal/server for the delivery path.
package secrets

import (
	"log"
	"sync"
)

// Secret is a single environment variable to hand to a target process.
type Secret struct {
	Name  string // Environment variable name
	Value string // Secret value
}

// Registry maps process selectors to the secrets that apply to them.
type Registry struct {
	byBinary map[string][]Secret
	byCgroup map[uint64][]Secret

	// unresolved records secrets that the configuration binds to a binary but
	// whose source could not be read. Without this, a binding whose every source
	// failed is indistinguishable from a binary with no secrets configured at
	// all, and the delivery path treats the two identically: it hands out
	// nothing, installs no protection, and says nothing. A typo in a fileRef
	// then silently downgrades an application to zero protection.
	unresolved map[string][]string

	mu sync.RWMutex
}

// NewRegistry creates an empty registry.
func NewRegistry() *Registry {
	return &Registry{
		byBinary:   make(map[string][]Secret),
		byCgroup:   make(map[uint64][]Secret),
		unresolved: make(map[string][]string),
	}
}

// RegisterForBinary associates secrets with a binary name, replacing any
// previous registration for that name.
func (r *Registry) RegisterForBinary(binaryName string, s []Secret) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.byBinary[binaryName] = s
	log.Printf("[REGISTER] %d secrets registered for binary: %s", len(s), binaryName)
}

// SetUnresolved records which secrets are configured for a binary but could not
// be resolved. Pass nil to clear a previous record, so a reload that fixes the
// source does not leave a stale complaint behind.
func (r *Registry) SetUnresolved(binaryName string, names []string) {
	r.mu.Lock()
	defer r.mu.Unlock()

	if len(names) == 0 {
		delete(r.unresolved, binaryName)
		return
	}
	r.unresolved[binaryName] = append([]string(nil), names...)
}

// Unresolved returns the names of secrets bound to a binary whose source could
// not be read. A non-empty result means the configuration intended to protect
// this binary, so delivering nothing is a misconfiguration rather than a binary
// that simply has no secrets.
func (r *Registry) Unresolved(binaryName string) []string {
	r.mu.RLock()
	defer r.mu.RUnlock()

	return append([]string(nil), r.unresolved[binaryName]...)
}

// RegisterForCgroup associates secrets with a cgroup ID.
func (r *Registry) RegisterForCgroup(cgroupID uint64, s []Secret) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.byCgroup[cgroupID] = s
	log.Printf("[REGISTER] %d secrets registered for cgroup: %d", len(s), cgroupID)
}

// Lookup returns every secret that applies to a process, combining binary and
// cgroup matches. The result is a copy, safe to use after concurrent updates.
func (r *Registry) Lookup(binaryName string, cgroupID uint64) []Secret {
	r.mu.RLock()
	defer r.mu.RUnlock()

	var out []Secret
	out = append(out, r.byBinary[binaryName]...)
	out = append(out, r.byCgroup[cgroupID]...)
	return out
}

// TargetBinaries lists every binary name that has secrets registered. Used to
// program the kernel-side exec filter.
func (r *Registry) TargetBinaries() []string {
	r.mu.RLock()
	defer r.mu.RUnlock()

	out := make([]string, 0, len(r.byBinary))
	for name := range r.byBinary {
		out = append(out, name)
	}
	return out
}
