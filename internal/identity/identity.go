// Package identity turns a caller's PID into the pod identity that secret
// bindings are authorized against.
//
// It joins the two halves: internal/cgroup reads what the kernel says about a
// process, and internal/kube says what the API server knows about the pod that
// cgroup belongs to. Neither half alone is enough. The cgroup path is
// unforgeable but says nothing about namespaces or labels; the API server knows
// those but cannot tell which pod is on the other end of a socket.
package identity

import (
	"errors"
	"fmt"

	"github.com/phonginreallife/kernelseal/internal/cgroup"
	"github.com/phonginreallife/kernelseal/internal/kube"
	"github.com/phonginreallife/kernelseal/internal/secrets"
)

// PodLookup is the part of the pod watcher this package needs.
type PodLookup interface {
	Lookup(uid string) (kube.Pod, bool)
	HasSynced() bool
}

// Resolver identifies callers.
type Resolver struct {
	cgroups *cgroup.Resolver
	pods    PodLookup
}

// New creates a resolver. pods may be nil, in which case callers are identified
// by cgroup only and never carry a Pod, so every pod-scoped selector refuses
// them.
func New(cgroups *cgroup.Resolver, pods PodLookup) *Resolver {
	return &Resolver{cgroups: cgroups, pods: pods}
}

// Identify reports everything known about a calling process.
//
// An error means the caller could not be placed in a cgroup at all. It is not the
// same as a caller that resolved to a host process or to a pod the agent has not
// seen: those return a usable Caller with no Pod, which pod-scoped selectors
// refuse on their own. Conflating the two would let a resolution failure read as
// a legitimate unscoped caller.
func (r *Resolver) Identify(pid uint32) (secrets.Caller, error) {
	id, err := r.cgroups.Resolve(pid)
	caller := secrets.Caller{
		CgroupPath:         id.Path,
		CgroupID:           id.ID,
		PodUID:             id.PodUID,
		ContainerID:        id.ContainerID,
		CgroupPathRelative: id.Relative,
	}

	// A missing numeric cgroup ID does not block attribution. The pod UID is
	// parsed from the path, which has already been read, and no selector matches
	// on the ID; it exists to correlate with BPF events. Refusing here would take
	// the agent down on hosts where cgroupfs is mounted somewhere unexpected, for
	// no gain in what the decision is actually based on.
	if err != nil && !errors.Is(err, cgroup.ErrNoID) {
		return caller, fmt.Errorf("resolving cgroup for pid %d: %w", pid, err)
	}

	if r.pods == nil || !id.IsPod() {
		return caller, nil
	}

	if !r.pods.HasSynced() {
		// A miss against a cold cache means "unknown", not "no such pod". Saying
		// so lets the delivery path refuse rather than treat the caller as a host
		// process that simply has no pod.
		return caller, fmt.Errorf("pod cache is not synced, cannot attribute pid %d to pod %s", pid, id.PodUID)
	}

	pod, ok := r.pods.Lookup(id.PodUID)
	if !ok {
		return caller, fmt.Errorf("pid %d is in pod %s, which is not in this node's pod cache", pid, id.PodUID)
	}

	caller.Pod = &pod
	return caller, nil
}
