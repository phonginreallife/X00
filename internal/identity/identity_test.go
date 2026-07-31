package identity

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/phonginreallife/kernelseal/internal/cgroup"
	"github.com/phonginreallife/kernelseal/internal/kube"
)

const (
	podUID      = "3f8a1b2c-4d5e-6f70-8192-a3b4c5d6e7f8"
	podUIDSlice = "3f8a1b2c_4d5e_6f70_8192_a3b4c5d6e7f8"
	containerID = "9a8b7c6d5e4f3a2b1c0d9e8f7a6b5c4d3e2f1a0b9c8d7e6f5a4b3c2d1e0f9a8b"
)

// fakePods stands in for the watcher.
type fakePods struct {
	pods   map[string]kube.Pod
	synced bool
}

func (f fakePods) Lookup(uid string) (kube.Pod, bool) {
	p, ok := f.pods[uid]
	return p, ok
}

func (f fakePods) HasSynced() bool { return f.synced }

// procWith writes a /proc/<pid>/cgroup fixture and returns a resolver rooted at it.
func procWith(t *testing.T, pid string, cgroupPath string) *cgroup.Resolver {
	t.Helper()

	procRoot := t.TempDir()
	dir := filepath.Join(procRoot, pid)
	if err := os.MkdirAll(dir, 0o755); err != nil {
		t.Fatalf("creating fixture: %v", err)
	}
	if err := os.WriteFile(filepath.Join(dir, "cgroup"), []byte("0::"+cgroupPath+"\n"), 0o600); err != nil {
		t.Fatalf("writing fixture: %v", err)
	}

	// The cgroup root is a temporary directory, so the cgroup ID never resolves.
	// That is deliberate: it isolates the pod attribution being tested here from
	// the kernel interaction covered in internal/cgroup.
	return cgroup.NewResolver(procRoot, t.TempDir())
}

func podCgroup(uid string) string {
	return "/kubepods.slice/kubepods-burstable.slice/kubepods-burstable-pod" + uid +
		".slice/cri-containerd-" + containerID + ".scope"
}

func TestIdentify_AttachesThePod(t *testing.T) {
	cgroups := procWith(t, "100", podCgroup(podUIDSlice))
	pods := fakePods{
		synced: true,
		pods: map[string]kube.Pod{
			podUID: {UID: podUID, Name: "checkout-abc", Namespace: "payments"},
		},
	}

	got, err := New(cgroups, pods).Identify(100)
	// The cgroup ID cannot resolve against a temporary root, which is expected;
	// the pod attribution is what matters here.
	if err != nil && !strings.Contains(err.Error(), "resolving cgroup id") {
		t.Fatalf("Identify: %v", err)
	}

	if got.PodUID != podUID {
		t.Errorf("PodUID = %q, want %q", got.PodUID, podUID)
	}
	if got.ContainerID != containerID {
		t.Errorf("ContainerID = %q, want %q", got.ContainerID, containerID)
	}
	if got.Pod == nil {
		t.Fatal("Pod is nil, want the pod from the cache")
	}
	if got.Pod.Namespace != "payments" {
		t.Errorf("namespace = %q, want payments", got.Pod.Namespace)
	}
}

// A host process is not an error. It has no pod, which pod-scoped selectors
// refuse on their own.
func TestIdentify_HostProcessHasNoPod(t *testing.T) {
	cgroups := procWith(t, "200", "/system.slice/sshd.service")
	pods := fakePods{synced: true, pods: map[string]kube.Pod{}}

	got, _ := New(cgroups, pods).Identify(200)

	if got.PodUID != "" {
		t.Errorf("PodUID = %q, want empty for a host process", got.PodUID)
	}
	if got.Pod != nil {
		t.Errorf("Pod = %+v, want nil", got.Pod)
	}
}

// A pod the cache has never heard of must be an error, not a caller that simply
// has no pod. The second reads as a host process, which some selectors would
// otherwise treat as merely unscoped.
func TestIdentify_UnknownPodIsAnError(t *testing.T) {
	cgroups := procWith(t, "300", podCgroup(podUIDSlice))
	pods := fakePods{synced: true, pods: map[string]kube.Pod{}}

	got, err := New(cgroups, pods).Identify(300)

	if err == nil {
		t.Fatal("expected an error for a pod that is not in the cache")
	}
	if !strings.Contains(err.Error(), podUID) {
		t.Errorf("error = %v, want it to name the pod UID", err)
	}
	if got.Pod != nil {
		t.Error("Pod is set for a pod the cache does not have")
	}
	// The parsed identity is still needed to audit the refusal.
	if got.PodUID != podUID {
		t.Errorf("PodUID = %q, want it preserved for auditing", got.PodUID)
	}
}

// Before the cache is warm, a miss means "unknown", not "no such pod". Serving on
// that basis would be a race the agent loses at every rollout.
func TestIdentify_ColdCacheIsAnError(t *testing.T) {
	cgroups := procWith(t, "400", podCgroup(podUIDSlice))
	pods := fakePods{synced: false, pods: map[string]kube.Pod{}}

	_, err := New(cgroups, pods).Identify(400)
	if err == nil {
		t.Fatal("expected an error while the pod cache is unsynced")
	}
	if !strings.Contains(err.Error(), "synced") {
		t.Errorf("error = %v, want it to say the cache is not synced", err)
	}
}

// Without a pod watcher the agent can still read cgroups, which is enough for
// cgroupPath selectors and nothing else.
func TestIdentify_NoWatcherStillResolvesTheCgroup(t *testing.T) {
	cgroups := procWith(t, "500", podCgroup(podUIDSlice))

	got, _ := New(cgroups, nil).Identify(500)

	if got.PodUID != podUID {
		t.Errorf("PodUID = %q, want it parsed from the cgroup path", got.PodUID)
	}
	if got.Pod != nil {
		t.Error("Pod is set with no watcher configured")
	}
	if got.CgroupPath == "" {
		t.Error("CgroupPath is empty, so cgroupPath selectors could not match")
	}
}

func TestIdentify_UnreadableProcIsAnError(t *testing.T) {
	cgroups := cgroup.NewResolver(t.TempDir(), t.TempDir())

	if _, err := New(cgroups, nil).Identify(999); err == nil {
		t.Error("expected an error when the caller has no procfs entry")
	}
}
