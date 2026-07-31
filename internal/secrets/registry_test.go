package secrets

import (
	"strings"
	"sync"
	"testing"

	"github.com/phonginreallife/kernelseal/internal/kube"
)

const (
	victimUID   = "3f8a1b2c-4d5e-6f70-8192-a3b4c5d6e7f8"
	attackerUID = "aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee"

	victimCgroup   = "/kubepods.slice/kubepods-burstable.slice/kubepods-burstable-pod3f8a1b2c_4d5e_6f70_8192_a3b4c5d6e7f8.slice/cri-containerd-abc123def456.scope"
	attackerCgroup = "/kubepods.slice/kubepods-burstable.slice/kubepods-burstable-podaaaaaaaa_bbbb_cccc_dddd_eeeeeeeeeeee.slice/cri-containerd-999888777666.scope"
)

func victimCaller() Caller {
	return Caller{
		CgroupPath:  victimCgroup,
		CgroupID:    4242,
		PodUID:      victimUID,
		ContainerID: "abc123def456",
		Pod: &kube.Pod{
			UID:        victimUID,
			Name:       "checkout-abc",
			Namespace:  "payments",
			Labels:     map[string]string{"app": "checkout", "tier": "prod"},
			Containers: map[string]string{"abc123def456": "server"},
		},
	}
}

func attackerCaller() Caller {
	return Caller{
		CgroupPath:  attackerCgroup,
		CgroupID:    9999,
		PodUID:      attackerUID,
		ContainerID: "999888777666",
		Pod: &kube.Pod{
			UID:        attackerUID,
			Name:       "scratch-xyz",
			Namespace:  "sandbox",
			Labels:     map[string]string{"app": "scratch"},
			Containers: map[string]string{"999888777666": "shell"},
		},
	}
}

func dbBinding() Binding {
	return Binding{
		Name: "checkout-db",
		Selector: Selector{
			Binary:    "node",
			Namespace: "payments",
			Labels:    map[string]string{"app": "checkout"},
		},
		Secrets: []Secret{{Name: "DB_PASSWORD", Value: "hunter2"}},
	}
}

func names(secrets []Secret) []string {
	out := make([]string, 0, len(secrets))
	for _, s := range secrets {
		out = append(out, s.Name)
	}
	return out
}

func TestNewRegistry(t *testing.T) {
	r := NewRegistry()
	if r == nil {
		t.Fatal("NewRegistry returned nil")
	}
	if got := r.Lookup("anything", victimCaller()); !got.Empty() {
		t.Errorf("fresh registry returned %+v, want an empty match", got)
	}
}

// The whole point of the cgroup work. A pod that names another pod's binary must
// come away with nothing, and the attempt must be visible rather than looking
// like an unconfigured binary.
func TestLookup_RefusesAnotherPodsBinding(t *testing.T) {
	r := NewRegistry()
	r.Replace([]Binding{dbBinding()})

	got := r.Lookup("node", attackerCaller())

	if len(got.Secrets) != 0 {
		t.Errorf("released %v to a pod the binding does not select", names(got.Secrets))
	}
	if len(got.Refused) == 0 {
		t.Error("Refused is empty, so the denial would not be audited")
	}
	if got.Empty() {
		t.Error("Match reports Empty, which the delivery path treats as an unconfigured binary")
	}
}

func TestLookup_ServesTheMatchingPod(t *testing.T) {
	r := NewRegistry()
	r.Replace([]Binding{dbBinding()})

	got := r.Lookup("node", victimCaller())

	if len(got.Secrets) != 1 || got.Secrets[0].Name != "DB_PASSWORD" {
		t.Fatalf("secrets = %v, want DB_PASSWORD", names(got.Secrets))
	}
	if len(got.Refused) != 0 {
		t.Errorf("Refused = %v, want empty for the pod the binding selects", got.Refused)
	}
}

// Two pods on one node, each with its own binding for the same binary. Neither
// may see the other's secrets, and the non-matching binding must not turn into a
// denial for the pod that does match.
func TestLookup_TwoPodsSameBinary(t *testing.T) {
	other := Binding{
		Name:     "scratch-db",
		Selector: Selector{Binary: "node", Namespace: "sandbox"},
		Secrets:  []Secret{{Name: "SCRATCH_TOKEN", Value: "t"}},
	}

	r := NewRegistry()
	r.Replace([]Binding{dbBinding(), other})

	got := r.Lookup("node", victimCaller())
	if len(got.Secrets) != 1 || got.Secrets[0].Name != "DB_PASSWORD" {
		t.Errorf("payments pod got %v, want only DB_PASSWORD", names(got.Secrets))
	}

	got = r.Lookup("node", attackerCaller())
	if len(got.Secrets) != 1 || got.Secrets[0].Name != "SCRATCH_TOKEN" {
		t.Errorf("sandbox pod got %v, want only SCRATCH_TOKEN", names(got.Secrets))
	}
}

// A caller the agent could not map to a pod must fail every pod-scoped
// constraint. Treating unknown as unconstrained would fail open.
func TestLookup_UnidentifiedCallerMatchesNoPodScopedBinding(t *testing.T) {
	r := NewRegistry()
	r.Replace([]Binding{dbBinding()})

	unknown := Caller{CgroupPath: "/system.slice/sshd.service"}
	got := r.Lookup("node", unknown)

	if len(got.Secrets) != 0 {
		t.Errorf("released %v to a caller with no pod identity", names(got.Secrets))
	}
	if len(got.Refused) == 0 {
		t.Error("an unidentified caller was not recorded as refused")
	}
}

func TestSelectorAdmits(t *testing.T) {
	tests := []struct {
		name     string
		selector Selector
		caller   Caller
		want     bool
	}{
		{
			name:     "namespace matches",
			selector: Selector{Namespace: "payments"},
			caller:   victimCaller(),
			want:     true,
		},
		{
			name:     "namespace differs",
			selector: Selector{Namespace: "sandbox"},
			caller:   victimCaller(),
			want:     false,
		},
		{
			name:     "all labels must match",
			selector: Selector{Labels: map[string]string{"app": "checkout", "tier": "prod"}},
			caller:   victimCaller(),
			want:     true,
		},
		{
			name:     "one wrong label is enough to refuse",
			selector: Selector{Labels: map[string]string{"app": "checkout", "tier": "dev"}},
			caller:   victimCaller(),
			want:     false,
		},
		{
			name:     "a label the pod does not carry",
			selector: Selector{Labels: map[string]string{"absent": "x"}},
			caller:   victimCaller(),
			want:     false,
		},
		{
			name:     "container name resolves through the container ID",
			selector: Selector{Container: "server"},
			caller:   victimCaller(),
			want:     true,
		},
		{
			name:     "wrong container in the right pod",
			selector: Selector{Container: "sidecar"},
			caller:   victimCaller(),
			want:     false,
		},
		{
			name:     "exact cgroup path",
			selector: Selector{CgroupPath: victimCgroup},
			caller:   victimCaller(),
			want:     true,
		},
		{
			// Selecting a slice must cover the containers beneath it, or an
			// operator has to name every container ID by hand.
			name:     "ancestor cgroup path covers descendants",
			selector: Selector{CgroupPath: "/kubepods.slice/kubepods-burstable.slice"},
			caller:   victimCaller(),
			want:     true,
		},
		{
			// A prefix that is not a path boundary must not match, or
			// /kubepods-burst would admit /kubepods-burstable.
			name:     "string prefix that is not a path boundary",
			selector: Selector{CgroupPath: "/kubepods.slice/kubepods-burst"},
			caller:   victimCaller(),
			want:     false,
		},
		{
			name:     "a selector with no pod constraints admits anyone",
			selector: Selector{Binary: "node"},
			caller:   attackerCaller(),
			want:     true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, why := tt.selector.admits(tt.caller)
			if got != tt.want {
				t.Errorf("admits = %v (%s), want %v", got, why, tt.want)
			}
			if !got && why == "" {
				t.Error("a refusal did not name the constraint that failed")
			}
		})
	}
}

func TestSelector_IsPodScoped(t *testing.T) {
	scoped := []Selector{
		{Namespace: "payments"},
		{Labels: map[string]string{"app": "checkout"}},
		{CgroupPath: "/kubepods.slice"},
		{Container: "server"},
	}
	for _, s := range scoped {
		if !s.IsPodScoped() {
			t.Errorf("%+v does not report as pod-scoped", s)
		}
	}

	if (Selector{Binary: "node"}).IsPodScoped() {
		t.Error("a binary-only selector reports as pod-scoped")
	}
	if (Selector{}).IsPodScoped() {
		t.Error("an empty selector reports as pod-scoped")
	}
}

// A rejected binding must not read as "this binary has no secrets". That is the
// silent downgrade the unresolved bookkeeping already guards against.
func TestLookup_RejectedBindingIsNotSilent(t *testing.T) {
	b := dbBinding()
	b.Selector = Selector{Binary: "node"}
	b.Rejected = "podIdentity is required but the selector names no pod"

	r := NewRegistry()
	r.Replace([]Binding{b})

	got := r.Lookup("node", victimCaller())
	if len(got.Secrets) != 0 {
		t.Errorf("a rejected binding released %v", names(got.Secrets))
	}
	if len(got.Rejected) != 1 {
		t.Errorf("Rejected = %v, want the binding named", got.Rejected)
	}
	if got.Empty() {
		t.Error("Match reports Empty for a rejected binding")
	}
}

func TestLookup_UnconfiguredBinaryIsEmpty(t *testing.T) {
	r := NewRegistry()
	r.Replace([]Binding{dbBinding()})

	got := r.Lookup("python", victimCaller())
	if !got.Empty() {
		t.Errorf("an unconfigured binary produced %+v, want an empty match", got)
	}
}

func TestLookup_CarriesUnresolvedFromMatchedBindings(t *testing.T) {
	b := dbBinding()
	b.Unresolved = []string{"API_KEY"}

	r := NewRegistry()
	r.Replace([]Binding{b})

	got := r.Lookup("node", victimCaller())
	if len(got.Unresolved) != 1 || got.Unresolved[0] != "API_KEY" {
		t.Errorf("Unresolved = %v, want [API_KEY]", got.Unresolved)
	}

	// A caller the binding refuses must not learn what it failed to resolve.
	got = r.Lookup("node", attackerCaller())
	if len(got.Unresolved) != 0 {
		t.Errorf("Unresolved = %v leaked to a refused caller", got.Unresolved)
	}
}

func TestTargetBinaries(t *testing.T) {
	r := NewRegistry()
	r.Replace([]Binding{
		{Name: "a", Selector: Selector{Binary: "node"}},
		{Name: "b", Selector: Selector{Binary: "python"}},
		{Name: "c", Selector: Selector{Binary: "node"}},
		{Name: "d", Selector: Selector{Namespace: "payments"}},
	})

	got := r.TargetBinaries()
	want := []string{"node", "python"}
	if len(got) != len(want) {
		t.Fatalf("TargetBinaries = %v, want %v", got, want)
	}
	for i := range want {
		if got[i] != want[i] {
			t.Errorf("TargetBinaries = %v, want %v", got, want)
			break
		}
	}
}

// A reload must never leave a caller matching a half-applied configuration.
func TestReplace_IsAtomic(t *testing.T) {
	r := NewRegistry()
	r.Replace([]Binding{dbBinding()})

	if got := r.Lookup("node", victimCaller()); len(got.Secrets) != 1 {
		t.Fatalf("setup: got %d secrets, want 1", len(got.Secrets))
	}

	r.Replace(nil)
	if got := r.Lookup("node", victimCaller()); !got.Empty() {
		t.Errorf("after Replace(nil), Lookup returned %+v", got)
	}
}

// Lookup builds a fresh result, so a caller holding one must not see a later
// reload through it.
func TestLookup_ResultIsolated(t *testing.T) {
	r := NewRegistry()
	r.Replace([]Binding{dbBinding()})

	held := r.Lookup("node", victimCaller())

	replaced := dbBinding()
	replaced.Secrets = []Secret{{Name: "ROTATED", Value: "new"}}
	r.Replace([]Binding{replaced})

	if held.Secrets[0].Name != "DB_PASSWORD" {
		t.Errorf("a previously returned match mutated to %q", held.Secrets[0].Name)
	}
}

func TestRegistry_ConcurrentAccess(t *testing.T) {
	r := NewRegistry()

	var wg sync.WaitGroup
	wg.Add(3)

	go func() {
		defer wg.Done()
		for i := 0; i < 200; i++ {
			r.Replace([]Binding{dbBinding()})
		}
	}()
	go func() {
		defer wg.Done()
		for i := 0; i < 200; i++ {
			_ = r.Lookup("node", victimCaller())
		}
	}()
	go func() {
		defer wg.Done()
		for i := 0; i < 200; i++ {
			_ = r.TargetBinaries()
		}
	}()

	wg.Wait()
}

// A caller whose cgroup path is anchored to the agent's own namespace cannot be
// compared against a configured path, so a cgroupPath selector must refuse rather
// than risk a coincidental match against the wrong cgroup.
func TestSelectorAdmits_RelativeCgroupPathRefuses(t *testing.T) {
	caller := victimCaller()
	caller.CgroupPathRelative = true

	sel := Selector{CgroupPath: victimCgroup}
	got, why := sel.admits(caller)

	if got {
		t.Error("a cgroupPath selector matched a namespace-relative caller path")
	}
	if !strings.Contains(why, "cgroup namespace") {
		t.Errorf("reason = %q, want it to explain that the paths are not comparable", why)
	}
}

// Pod-based selectors go through the pod UID rather than the path, so they must
// keep working where cgroupPath cannot. Otherwise a private cgroup namespace
// would take out authorization entirely.
func TestSelectorAdmits_RelativePathStillAllowsPodSelectors(t *testing.T) {
	caller := victimCaller()
	caller.CgroupPathRelative = true

	for _, sel := range []Selector{
		{Namespace: "payments"},
		{Labels: map[string]string{"app": "checkout"}},
		{Container: "server"},
	} {
		if ok, why := sel.admits(caller); !ok {
			t.Errorf("%+v refused a namespace-relative caller: %s", sel, why)
		}
	}
}
