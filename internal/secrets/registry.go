// Package secrets holds the resolved secret values and decides which of them
// apply to a given caller.
//
// KernelSeal does not write secrets into the filesystem and does not rewrite a
// running process's memory. Values are handed to the kernelseal-exec shim over a
// unix socket and applied to the environment before the target binary is exec'd,
// so the application reads them as ordinary environment variables. See
// internal/server for the delivery path.
//
// Matching is the authorization decision. The binary name in a request is a claim
// the caller makes about itself and only ever narrows which bindings are
// candidates; what admits a caller to a binding is its pod identity, which the
// kernel supplies and a container cannot forge. See Selector.
package secrets

import (
	"log"
	"sort"
	"strings"
	"sync"

	"github.com/phonginreallife/kernelseal/internal/kube"
)

// Secret is a single environment variable to hand to a target process.
type Secret struct {
	Name  string // Environment variable name
	Value string // Secret value
}

// Selector decides which callers a binding applies to.
//
// Binary is a claim and is never sufficient on its own to authorize anything: it
// selects among the bindings a caller is already entitled to. The other fields
// derive from the caller's cgroup, which the kernel sets when the container is
// created, so they are identity rather than assertion.
type Selector struct {
	Binary     string
	Container  string
	Namespace  string
	Labels     map[string]string
	CgroupPath string
}

// IsPodScoped reports whether the selector constrains which pod may match. A
// selector that does not is satisfied by any caller that names the right binary,
// which is only safe when the socket itself is already scoped to one pod.
func (s Selector) IsPodScoped() bool {
	return s.Namespace != "" || len(s.Labels) > 0 || s.CgroupPath != "" || s.Container != ""
}

// Caller is everything known about a requesting process that does not come from
// the request body.
type Caller struct {
	// CgroupPath and CgroupID come from the kernel by way of procfs and cgroupfs.
	CgroupPath string
	CgroupID   uint64

	// CgroupPathRelative reports that CgroupPath is anchored to the agent's own
	// cgroup namespace rather than to the hierarchy root, so it cannot be
	// compared against a configured path.
	CgroupPathRelative bool

	// PodUID and ContainerID are parsed out of CgroupPath.
	PodUID      string
	ContainerID string

	// Pod is the API server's record of the caller's pod, nil when the caller
	// could not be mapped to one.
	Pod *kube.Pod
}

// admits reports whether a selector's pod constraints accept this caller, and
// names the first constraint that did not if they do not.
func (s Selector) admits(c Caller) (bool, string) {
	if s.CgroupPath != "" {
		// The caller's path is anchored somewhere this selector is not, so any
		// comparison between them is meaningless. Refusing is the only safe
		// answer: a coincidental match would authorize the wrong cgroup.
		if c.CgroupPathRelative {
			return false, "cgroupPath (agent is in its own cgroup namespace, so caller paths are not comparable)"
		}
		if !cgroupPathMatches(s.CgroupPath, c.CgroupPath) {
			return false, "cgroupPath"
		}
	}

	// Everything below needs the API server's view. A caller that could not be
	// mapped to a pod fails these rather than skipping them, because "unknown"
	// must never widen what a selector admits.
	if s.Namespace != "" {
		if c.Pod == nil || c.Pod.Namespace != s.Namespace {
			return false, "namespace"
		}
	}

	for k, v := range s.Labels {
		if c.Pod == nil || c.Pod.Labels[k] != v {
			return false, "labels"
		}
	}

	if s.Container != "" {
		if c.Pod == nil || c.ContainerID == "" || c.Pod.Containers[c.ContainerID] != s.Container {
			return false, "container"
		}
	}

	return true, ""
}

// cgroupPathMatches accepts an exact path or any descendant of it, so an operator
// can select a whole slice without naming every container beneath it.
func cgroupPathMatches(want, got string) bool {
	want = strings.TrimSuffix(want, "/")
	if want == "" {
		return false
	}
	return got == want || strings.HasPrefix(got, want+"/")
}

// Binding is one configured group of secrets and the callers it applies to.
type Binding struct {
	// Name is the binding's name in the configuration, used in logs.
	Name string

	Selector Selector

	// Secrets are the values that resolved.
	Secrets []Secret

	// Unresolved names secrets the configuration binds here but whose source
	// could not be read. Without this, a binding whose every source failed is
	// indistinguishable from a binary with no secrets configured at all, and the
	// delivery path treats the two identically: it hands out nothing, installs no
	// protection, and says nothing. A typo in a fileRef then silently downgrades
	// an application to zero protection.
	Unresolved []string

	// Rejected, when non-empty, says why this binding cannot serve anyone under
	// the active policy. A rejected binding still participates in matching so the
	// delivery path can refuse loudly instead of behaving as though the binary
	// were simply unconfigured.
	Rejected string
}

// Match is the outcome of resolving a request.
type Match struct {
	// Secrets are the values to release, combined across every binding that
	// admitted the caller.
	Secrets []Secret

	// Unresolved names configured secrets that could not be read, from the
	// bindings that admitted the caller.
	Unresolved []string

	// Refused names bindings whose binary matched but whose selector did not
	// admit this caller. Non-empty with no Secrets is the case the cgroup work
	// exists to catch: a caller naming a binary that belongs to another pod.
	Refused []string

	// Rejected names bindings that matched the binary but are unservable because
	// the configuration is invalid under the active policy.
	Rejected []string
}

// Empty reports whether the request matched nothing at all, which is the only
// case where starting the process unchanged is correct.
func (m Match) Empty() bool {
	return len(m.Secrets) == 0 && len(m.Unresolved) == 0 &&
		len(m.Refused) == 0 && len(m.Rejected) == 0
}

// Registry holds the active bindings.
type Registry struct {
	mu       sync.RWMutex
	bindings []Binding
}

// NewRegistry creates an empty registry.
func NewRegistry() *Registry {
	return &Registry{}
}

// Replace swaps in a new set of bindings atomically, so a reload never leaves a
// caller matching a half-applied configuration.
func (r *Registry) Replace(bindings []Binding) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.bindings = bindings

	for _, b := range bindings {
		switch {
		case b.Rejected != "":
			log.Printf("[REGISTER] binding %q REJECTED: %s", b.Name, b.Rejected)
		case b.Selector.IsPodScoped():
			log.Printf("[REGISTER] %d secret(s) for binding %q (binary=%q, pod-scoped)",
				len(b.Secrets), b.Name, b.Selector.Binary)
		default:
			log.Printf("[REGISTER] %d secret(s) for binding %q (binary=%q, NOT pod-scoped)",
				len(b.Secrets), b.Name, b.Selector.Binary)
		}
	}
}

// Lookup returns everything that applies to a caller requesting a binary.
//
// The result distinguishes four outcomes that a plain secret slice cannot: served,
// misconfigured, refused on identity, and genuinely unconfigured. The delivery
// path needs all four, because three of them must not start the process.
func (r *Registry) Lookup(binaryName string, caller Caller) Match {
	r.mu.RLock()
	defer r.mu.RUnlock()

	var m Match
	for _, b := range r.bindings {
		if b.Selector.Binary != "" && b.Selector.Binary != binaryName {
			continue
		}

		if b.Rejected != "" {
			m.Rejected = append(m.Rejected, b.Name)
			continue
		}

		if ok, why := b.Selector.admits(caller); !ok {
			m.Refused = append(m.Refused, b.Name+" ("+why+")")
			continue
		}

		m.Secrets = append(m.Secrets, b.Secrets...)
		m.Unresolved = append(m.Unresolved, b.Unresolved...)
	}

	sort.Strings(m.Unresolved)
	return m
}

// TargetBinaries lists every binary name a binding selects on. Used to program
// the kernel-side exec filter.
func (r *Registry) TargetBinaries() []string {
	r.mu.RLock()
	defer r.mu.RUnlock()

	seen := make(map[string]bool, len(r.bindings))
	out := make([]string, 0, len(r.bindings))
	for _, b := range r.bindings {
		name := b.Selector.Binary
		if name == "" || seen[name] {
			continue
		}
		seen[name] = true
		out = append(out, name)
	}
	sort.Strings(out)
	return out
}
