// Package cgroup resolves the kernel's view of which cgroup a caller belongs to.
//
// This is the identity KernelSeal authorizes on. The binary name in a request is
// a claim the caller makes about itself; the cgroup is set by the kernel when the
// container is created and cannot be forged from inside it. In Kubernetes a
// cgroup maps 1:1 to a pod, so resolving it turns "whoever can reach the socket"
// into "this specific pod".
//
// Two values come out of a resolution and they are not interchangeable. ID is the
// u64 that bpf_get_current_cgroup_id() returns, used to correlate with BPF events.
// PodUID is parsed out of the cgroup path and is what the pod watcher looks up.
package cgroup

import (
	"encoding/binary"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"syscall"

	"golang.org/x/sys/unix"
)

// DefaultRoot is where the unified cgroup hierarchy is normally mounted. The
// DaemonSet bind-mounts the host's copy here.
const DefaultRoot = "/sys/fs/cgroup"

// DefaultProcRoot is the procfs mount used to read a caller's cgroup membership.
const DefaultProcRoot = "/proc"

// ErrNoID reports that a caller's cgroup path was read but its numeric ID could
// not be. The path alone is enough to attribute a caller to a pod, so this is a
// partial success: callers that only need identity may continue, while anything
// correlating with BPF events must not.
var ErrNoID = errors.New("cgroup id unavailable")

// Identity is what the kernel says about a caller's cgroup.
type Identity struct {
	// Path is the unified (v2) cgroup path, rooted at the hierarchy root.
	Path string

	// ID matches bpf_get_current_cgroup_id() for the same cgroup. Zero means the
	// path could not be resolved to a live cgroup directory.
	ID uint64

	// PodUID is the Kubernetes pod UID parsed out of Path, normalized to the
	// dashed lowercase form the API server reports. Empty when the path does not
	// belong to a pod, which is the normal case for host processes.
	PodUID string

	// ContainerID is the runtime's container ID parsed out of Path, without its
	// runtime prefix. Empty when the path names a pod but not a container, or a
	// shape this parser does not recognize.
	ContainerID string

	// Relative reports that the kernel rendered Path relative to the reading
	// process's cgroup namespace rather than to the hierarchy root, which it does
	// when the target's cgroup is not underneath that namespace's root. Such a
	// path looks like "/../kubepods.slice/..." and cannot be compared against a
	// configured cgroupPath, because the two are anchored differently.
	//
	// Pod attribution still works, since the pod UID is parsed from a segment
	// rather than from the path as a whole. Only cgroupPath selectors are
	// affected, and they refuse rather than risk matching the wrong cgroup.
	//
	// This means the agent is running in its own cgroup namespace. Give it the
	// host's; see SECURITY.md.
	Relative bool
}

// IsPod reports whether the cgroup belongs to a Kubernetes pod.
func (i Identity) IsPod() bool { return i.PodUID != "" }

// Resolver reads cgroup membership for arbitrary PIDs.
//
// Both roots are configurable because the agent normally runs in a container: it
// sees the host's procfs at /host/proc and the host's cgroup hierarchy at
// /sys/fs/cgroup, neither of which is where they live on the host itself.
type Resolver struct {
	procRoot   string
	cgroupRoot string
}

// NewResolver creates a resolver. Empty arguments select the defaults.
func NewResolver(procRoot, cgroupRoot string) *Resolver {
	if procRoot == "" {
		procRoot = DefaultProcRoot
	}
	if cgroupRoot == "" {
		cgroupRoot = DefaultRoot
	}
	return &Resolver{procRoot: procRoot, cgroupRoot: cgroupRoot}
}

// Resolve reports the cgroup a PID belongs to.
//
// A returned error means the caller could not be placed in a cgroup at all,
// which callers must treat as a failure to identify rather than as "not in a
// pod". The two are very different: the first is a reason to refuse, the second
// is an ordinary host process.
func (r *Resolver) Resolve(pid uint32) (Identity, error) {
	path, err := r.pathFor(pid)
	if err != nil {
		return Identity{}, err
	}

	podUID, containerID := ParsePod(path)
	identity := Identity{
		Path:        path,
		PodUID:      podUID,
		ContainerID: containerID,
		Relative:    isRelative(path),
	}

	id, err := r.idFor(path)
	if err != nil {
		// Everything parsed out of the path is still valid when the directory is
		// gone, and a denial is much easier to explain with the pod UID in it, so
		// report the partial identity alongside the failure.
		return identity, fmt.Errorf("%w for %s: %v", ErrNoID, path, err)
	}

	identity.ID = id
	return identity, nil
}

// pathFor reads a process's unified cgroup path from procfs.
//
// The path the kernel prints is relative to the *reading* process's cgroup
// namespace. The agent therefore has to share the host's cgroup namespace for
// other pods' paths to be meaningful; see SECURITY.md.
func (r *Resolver) pathFor(pid uint32) (string, error) {
	name := filepath.Join(r.procRoot, fmt.Sprint(pid), "cgroup")
	data, err := os.ReadFile(name)
	if err != nil {
		return "", fmt.Errorf("reading %s: %w", name, err)
	}

	lines := strings.Split(strings.TrimSpace(string(data)), "\n")

	// The unified hierarchy is the "0::" entry. Prefer it: on a v1/v2 hybrid host
	// the v1 controllers each get their own line and their paths can differ.
	for _, line := range lines {
		if strings.HasPrefix(line, "0::") {
			return strings.TrimPrefix(line, "0::"), nil
		}
	}

	// Pure cgroup v1. Any controller's path identifies the container, so take the
	// first one rather than failing outright.
	for _, line := range lines {
		if parts := strings.SplitN(line, ":", 3); len(parts) == 3 && parts[2] != "" {
			return parts[2], nil
		}
	}

	return "", fmt.Errorf("no cgroup membership in %s", name)
}

// idFor returns the u64 cgroup ID for a cgroup path.
//
// name_to_handle_at is used rather than stat because it is the interface that is
// guaranteed to yield the same identifier the kernel exposes to BPF. On cgroup2fs
// the handle is the 8-byte kernfs node ID, which is what
// bpf_get_current_cgroup_id() returns. stat's st_ino happens to agree there, and
// is the fallback for kernels or filesystems where the handle is unavailable.
func (r *Resolver) idFor(cgroupPath string) (uint64, error) {
	dir := filepath.Join(r.cgroupRoot, filepath.Clean("/"+cgroupPath))

	handle, _, err := unix.NameToHandleAt(unix.AT_FDCWD, dir, 0)
	if err == nil {
		b := handle.Bytes()
		if len(b) >= 8 {
			return binary.LittleEndian.Uint64(b[:8]), nil
		}
		// A handle too short to carry a u64 is not the cgroup2fs shape we know how
		// to read, so fall through rather than inventing an ID from part of it.
	}

	var st syscall.Stat_t
	if serr := syscall.Stat(dir, &st); serr != nil {
		if err == nil {
			err = serr
		}
		return 0, fmt.Errorf("stat %s: %w", dir, err)
	}
	return st.Ino, nil
}

// Kubernetes writes a pod's UID into the cgroup path, but the spelling depends on
// the kubelet's cgroup driver:
//
//	systemd   /kubepods.slice/kubepods-burstable.slice/kubepods-burstable-pod<uid>.slice/cri-containerd-<id>.scope
//	cgroupfs  /kubepods/burstable/pod<uid>/<id>
//
// The systemd driver replaces the UUID's dashes with underscores because dashes
// are path separators in a slice unit name. Guaranteed-QoS pods have no QoS
// segment at all, and the whole tree may sit under a parent slice when the
// kubelet is given a non-default cgroup root, so the segments are scanned rather
// than matched positionally.
var podUIDSegment = regexp.MustCompile(
	`(?:^|-)pod([0-9a-fA-F]{8}[-_][0-9a-fA-F]{4}[-_][0-9a-fA-F]{4}[-_][0-9a-fA-F]{4}[-_][0-9a-fA-F]{12})(?:\.slice)?$`)

// containerIDSegment matches the leaf segment naming a container. containerd,
// CRI-O and Docker each use their own prefix under the systemd driver; the
// cgroupfs driver usually writes the bare ID.
var containerIDSegment = regexp.MustCompile(
	`^(?:cri-containerd-|crio-|docker-|libpod-)?([0-9a-fA-F]{12,64})(?:\.scope)?$`)

// isRelative reports whether a cgroup path is anchored somewhere other than the
// hierarchy root. The kernel writes ".." segments when the cgroup being described
// is not a descendant of the reader's cgroup namespace root.
func isRelative(cgroupPath string) bool {
	for _, seg := range strings.Split(cgroupPath, "/") {
		if seg == ".." {
			return true
		}
	}
	return false
}

// ParsePod extracts the pod UID and container ID from a cgroup path. Both are
// empty when the path does not describe a Kubernetes container, which is the
// expected result for ordinary host processes.
//
// The pod UID is normalized to the dashed lowercase form, so a caller can look it
// up against what the API server reports regardless of which driver produced it.
func ParsePod(cgroupPath string) (podUID, containerID string) {
	segments := strings.Split(cgroupPath, "/")

	for i, seg := range segments {
		m := podUIDSegment.FindStringSubmatch(seg)
		if m == nil {
			continue
		}
		podUID = strings.ToLower(strings.ReplaceAll(m[1], "_", "-"))

		// The container is the segment directly below the pod. Anything deeper is
		// the container's own sub-hierarchy, which does not change which container
		// it is, so the first match below the pod wins.
		if i+1 < len(segments) {
			if cm := containerIDSegment.FindStringSubmatch(segments[i+1]); cm != nil {
				containerID = strings.ToLower(cm[1])
			}
		}
		return podUID, containerID
	}

	return "", ""
}
