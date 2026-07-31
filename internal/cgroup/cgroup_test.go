package cgroup

import (
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

const (
	// The same pod, spelled the way each cgroup driver spells it.
	uidDashed     = "3f8a1b2c-4d5e-6f70-8192-a3b4c5d6e7f8"
	uidUnderscore = "3f8a1b2c_4d5e_6f70_8192_a3b4c5d6e7f8"

	containerID = "9a8b7c6d5e4f3a2b1c0d9e8f7a6b5c4d3e2f1a0b9c8d7e6f5a4b3c2d1e0f9a8b"
)

// The shapes here are the ones a real node produces. The cgroup driver and the
// container runtime vary independently, and getting any of these wrong means the
// agent cannot map a caller to a pod and fails closed on a legitimate request.
func TestParsePod(t *testing.T) {
	tests := []struct {
		name       string
		path       string
		wantPodUID string
		wantCtrID  string
	}{
		{
			name:       "systemd driver, containerd, burstable",
			path:       "/kubepods.slice/kubepods-burstable.slice/kubepods-burstable-pod" + uidUnderscore + ".slice/cri-containerd-" + containerID + ".scope",
			wantPodUID: uidDashed,
			wantCtrID:  containerID,
		},
		{
			name:       "systemd driver, containerd, guaranteed has no QoS segment",
			path:       "/kubepods.slice/kubepods-pod" + uidUnderscore + ".slice/cri-containerd-" + containerID + ".scope",
			wantPodUID: uidDashed,
			wantCtrID:  containerID,
		},
		{
			name:       "systemd driver, CRI-O, besteffort",
			path:       "/kubepods.slice/kubepods-besteffort.slice/kubepods-besteffort-pod" + uidUnderscore + ".slice/crio-" + containerID + ".scope",
			wantPodUID: uidDashed,
			wantCtrID:  containerID,
		},
		{
			name:       "systemd driver, Docker",
			path:       "/kubepods.slice/kubepods-burstable.slice/kubepods-burstable-pod" + uidUnderscore + ".slice/docker-" + containerID + ".scope",
			wantPodUID: uidDashed,
			wantCtrID:  containerID,
		},
		{
			name:       "cgroupfs driver, burstable",
			path:       "/kubepods/burstable/pod" + uidDashed + "/" + containerID,
			wantPodUID: uidDashed,
			wantCtrID:  containerID,
		},
		{
			name:       "cgroupfs driver, guaranteed has no QoS segment",
			path:       "/kubepods/pod" + uidDashed + "/" + containerID,
			wantPodUID: uidDashed,
			wantCtrID:  containerID,
		},
		{
			name:       "cgroupfs driver, CRI-O prefixes the leaf",
			path:       "/kubepods/burstable/pod" + uidDashed + "/crio-" + containerID,
			wantPodUID: uidDashed,
			wantCtrID:  containerID,
		},
		{
			// A non-default kubelet cgroup root nests the whole tree, so the pod
			// segment cannot be found by counting from the start of the path.
			name:       "nested under a parent slice",
			path:       "/system.slice/kubepods.slice/kubepods-burstable.slice/kubepods-burstable-pod" + uidUnderscore + ".slice/cri-containerd-" + containerID + ".scope",
			wantPodUID: uidDashed,
			wantCtrID:  containerID,
		},
		{
			// The pod's own cgroup, above any container. Still a pod, so it must
			// resolve, but there is no container to name.
			name:       "pod cgroup with no container below it",
			path:       "/kubepods.slice/kubepods-burstable.slice/kubepods-burstable-pod" + uidUnderscore + ".slice",
			wantPodUID: uidDashed,
			wantCtrID:  "",
		},
		{
			name:       "uppercase UID normalizes to lowercase",
			path:       "/kubepods/burstable/pod3F8A1B2C-4D5E-6F70-8192-A3B4C5D6E7F8/" + containerID,
			wantPodUID: uidDashed,
			wantCtrID:  containerID,
		},
		{
			// A container's own sub-hierarchy. The container is still the segment
			// directly below the pod, not the leaf.
			name:       "container subtree keeps naming the container",
			path:       "/kubepods.slice/kubepods-burstable.slice/kubepods-burstable-pod" + uidUnderscore + ".slice/cri-containerd-" + containerID + ".scope/init",
			wantPodUID: uidDashed,
			wantCtrID:  containerID,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			podUID, ctrID := ParsePod(tt.path)
			if podUID != tt.wantPodUID {
				t.Errorf("pod UID = %q, want %q", podUID, tt.wantPodUID)
			}
			if ctrID != tt.wantCtrID {
				t.Errorf("container ID = %q, want %q", ctrID, tt.wantCtrID)
			}
		})
	}
}

// A host process must not be mistaken for a pod. Returning a bogus UID here would
// let an unrelated process match a binding meant for a pod.
func TestParsePod_NonPodPaths(t *testing.T) {
	paths := []string{
		"/",
		"",
		"/init.scope",
		"/system.slice/sshd.service",
		"/system.slice/containerd.service",
		"/user.slice/user-1000.slice/session-3.scope",
		"/docker/" + containerID,
		// "pod" appears but is not followed by anything UID-shaped.
		"/kubepods.slice/kubepods-burstable.slice/podsomething.slice",
		// Truncated UID.
		"/kubepods/burstable/pod3f8a1b2c-4d5e/" + containerID,
	}

	for _, p := range paths {
		t.Run(p, func(t *testing.T) {
			podUID, ctrID := ParsePod(p)
			if podUID != "" {
				t.Errorf("ParsePod(%q) pod UID = %q, want empty", p, podUID)
			}
			if ctrID != "" {
				t.Errorf("ParsePod(%q) container ID = %q, want empty", p, ctrID)
			}
		})
	}
}

func TestIdentity_IsPod(t *testing.T) {
	if (Identity{}).IsPod() {
		t.Error("an empty Identity reports IsPod")
	}
	if !(Identity{PodUID: uidDashed}).IsPod() {
		t.Error("an Identity with a pod UID does not report IsPod")
	}
}

// The cgroup ID has to match what bpf_get_current_cgroup_id() reports for the
// same cgroup. That equivalence cannot be checked without loading BPF, but the
// resolution path itself can be: it must agree with the kernfs node ID, which on
// cgroup2fs is the directory's inode.
func TestResolve_CurrentProcess(t *testing.T) {
	if _, err := os.Stat(DefaultRoot); err != nil {
		t.Skipf("no cgroup hierarchy at %s: %v", DefaultRoot, err)
	}

	r := NewResolver("", "")

	// #nosec G115 - a PID is always positive and fits in uint32
	got, err := r.Resolve(uint32(os.Getpid())) //nolint:gosec
	if err != nil {
		t.Fatalf("Resolve: %v", err)
	}

	if !strings.HasPrefix(got.Path, "/") {
		t.Errorf("path = %q, want an absolute cgroup path", got.Path)
	}
	if got.ID == 0 {
		t.Error("cgroup ID = 0, want the kernfs node ID")
	}

	dir := filepath.Join(DefaultRoot, filepath.Clean("/"+got.Path))
	info, err := os.Stat(dir)
	if err != nil {
		t.Fatalf("stat %s: %v", dir, err)
	}
	if !info.IsDir() {
		t.Fatalf("%s is not a directory", dir)
	}
}

func TestResolve_NonexistentPID(t *testing.T) {
	r := NewResolver("", "")
	if _, err := r.Resolve(0); err == nil {
		t.Error("expected an error resolving pid 0")
	}
}

// A caller that cannot be placed in a cgroup must surface as an error, not as an
// Identity that merely looks like a host process. Authorization treats those two
// differently and conflating them would fail open.
func TestResolve_UnreadableProcRoot(t *testing.T) {
	r := NewResolver(t.TempDir(), "")
	if _, err := r.Resolve(1); err == nil {
		t.Error("expected an error when procfs has no entry for the pid")
	}
}

func TestResolve_V1OnlyFallsBackToAControllerPath(t *testing.T) {
	procRoot := t.TempDir()
	pidDir := filepath.Join(procRoot, "1234")
	if err := os.MkdirAll(pidDir, 0o755); err != nil {
		t.Fatalf("creating fixture: %v", err)
	}

	// A pure v1 host has no "0::" line at all.
	body := "11:devices:/kubepods/burstable/pod" + uidDashed + "/" + containerID + "\n" +
		"10:memory:/kubepods/burstable/pod" + uidDashed + "/" + containerID + "\n"
	if err := os.WriteFile(filepath.Join(pidDir, "cgroup"), []byte(body), 0o600); err != nil {
		t.Fatalf("writing fixture: %v", err)
	}

	r := NewResolver(procRoot, t.TempDir())

	// The cgroup directory does not exist under the temporary root, so the ID
	// cannot resolve. The path still has to come back for auditing.
	got, err := r.Resolve(1234)
	if err == nil {
		t.Fatal("expected an error resolving an ID for a path that does not exist")
	}

	// The failure has to be distinguishable, because a missing numeric ID still
	// leaves a usable identity while an unreadable path does not.
	if !errors.Is(err, ErrNoID) {
		t.Errorf("error = %v, want it to wrap ErrNoID", err)
	}
	want := "/kubepods/burstable/pod" + uidDashed + "/" + containerID
	if got.Path != want {
		t.Errorf("path = %q, want %q", got.Path, want)
	}
}

// The unified entry wins on a hybrid host, where the v1 controllers can report a
// different path than v2 for the same process.
func TestResolve_PrefersUnifiedHierarchy(t *testing.T) {
	procRoot := t.TempDir()
	pidDir := filepath.Join(procRoot, "77")
	if err := os.MkdirAll(pidDir, 0o755); err != nil {
		t.Fatalf("creating fixture: %v", err)
	}

	body := "11:devices:/some/v1/path\n0::/kubepods.slice/kubepods-pod" + uidUnderscore + ".slice\n"
	if err := os.WriteFile(filepath.Join(pidDir, "cgroup"), []byte(body), 0o600); err != nil {
		t.Fatalf("writing fixture: %v", err)
	}

	r := NewResolver(procRoot, t.TempDir())
	got, _ := r.Resolve(77)

	want := "/kubepods.slice/kubepods-pod" + uidUnderscore + ".slice"
	if got.Path != want {
		t.Errorf("path = %q, want the unified entry %q", got.Path, want)
	}
	if got.PodUID != uidDashed {
		t.Errorf("pod UID = %q, want %q", got.PodUID, uidDashed)
	}
}

// When the agent has its own cgroup namespace, the kernel renders another
// process's cgroup relative to the agent's, with ".." segments. Measured against
// Docker with a private cgroup namespace and --pid=host, which is the same shape
// a DaemonSet sees.
func TestResolve_DetectsNamespaceRelativePaths(t *testing.T) {
	const relative = "/../kubepods.slice/kubepods-burstable.slice/kubepods-burstable-pod" +
		uidUnderscore + ".slice/cri-containerd-" + containerID + ".scope"

	procRoot := t.TempDir()
	pidDir := filepath.Join(procRoot, "55")
	if err := os.MkdirAll(pidDir, 0o755); err != nil {
		t.Fatalf("creating fixture: %v", err)
	}
	if err := os.WriteFile(filepath.Join(pidDir, "cgroup"), []byte("0::"+relative+"\n"), 0o600); err != nil {
		t.Fatalf("writing fixture: %v", err)
	}

	got, _ := NewResolver(procRoot, t.TempDir()).Resolve(55)

	if !got.Relative {
		t.Error("a path with a .. segment was not reported as namespace-relative")
	}

	// Pod attribution must survive it, because the UID lives in a segment rather
	// than in the path as a whole. This is what keeps namespace and labels
	// selectors working where cgroupPath cannot.
	if got.PodUID != uidDashed {
		t.Errorf("pod UID = %q, want %q parsed out of a relative path", got.PodUID, uidDashed)
	}
	if got.ContainerID != containerID {
		t.Errorf("container ID = %q, want %q", got.ContainerID, containerID)
	}
}

func TestIsRelative(t *testing.T) {
	relative := []string{
		"/../docker-abc.scope",
		"/../../kubepods.slice/pod.slice",
		"/..",
	}
	for _, p := range relative {
		if !isRelative(p) {
			t.Errorf("isRelative(%q) = false, want true", p)
		}
	}

	absolute := []string{
		"/",
		"/kubepods.slice/kubepods-burstable.slice",
		"/system.slice/sshd.service",
		// ".." only counts as a whole segment; a name containing dots does not.
		"/system.slice/my..service",
	}
	for _, p := range absolute {
		if isRelative(p) {
			t.Errorf("isRelative(%q) = true, want false", p)
		}
	}
}
