package server

import (
	"errors"
	"strings"
	"testing"

	"github.com/phonginreallife/kernelseal/internal/kube"
	"github.com/phonginreallife/kernelseal/internal/secrets"
)

const (
	victimUID   = "3f8a1b2c-4d5e-6f70-8192-a3b4c5d6e7f8"
	attackerUID = "aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee"
)

// fixedIdentifier returns the same caller for every PID, standing in for the
// cgroup and pod lookups that need a real node.
type fixedIdentifier struct {
	caller secrets.Caller
	err    error
}

func (f fixedIdentifier) Identify(uint32) (secrets.Caller, error) {
	return f.caller, f.err
}

func inPod(uid, namespace, name string, labels map[string]string) secrets.Caller {
	return secrets.Caller{
		CgroupPath: "/kubepods.slice/kubepods-burstable.slice/kubepods-burstable-pod" + uid + ".slice/cri-containerd-abc.scope",
		CgroupID:   4242,
		PodUID:     uid,
		Pod: &kube.Pod{
			UID:       uid,
			Name:      name,
			Namespace: namespace,
			Labels:    labels,
		},
	}
}

func paymentsBinding() secrets.Binding {
	return secrets.Binding{
		Name: "checkout-db",
		Selector: secrets.Selector{
			Binary:    "node",
			Namespace: "payments",
		},
		Secrets: []secrets.Secret{{Name: "DB_PASSWORD", Value: "hunter2"}},
	}
}

type authzServer struct {
	srv     *Server
	denials []string
}

func newAuthzServer(t *testing.T, bindings []secrets.Binding, ident Identifier, cfg Config) *authzServer {
	t.Helper()

	registry := secrets.NewRegistry()
	registry.Replace(bindings)

	cfg.SocketPath = t.TempDir() + "/s.sock"

	a := &authzServer{}
	a.srv = New(cfg, registry, &recordingProtector{}, ident)
	a.srv.SetDeniedCallback(func(_ uint32, reason string) {
		a.denials = append(a.denials, reason)
	})
	return a
}

// The exact scenario from the issue: a pod opens the socket and names a binary
// that belongs to another pod. Before the cgroup work this returned that pod's
// secrets.
func TestHandle_DeniesAnotherPodsBinding(t *testing.T) {
	a := newAuthzServer(t,
		[]secrets.Binding{paymentsBinding()},
		fixedIdentifier{caller: inPod(attackerUID, "sandbox", "scratch-xyz", nil)},
		Config{IdentifyCallers: true, RequirePodIdentity: true, RequireProtection: true},
	)

	resp := a.srv.handle(selfCred(t), request("node"))

	if resp.OK {
		t.Error("a pod in sandbox was served a binding scoped to payments")
	}
	if len(resp.Env) != 0 {
		t.Errorf("Env = %v, want nothing released", resp.Env)
	}
	if len(a.denials) == 0 {
		t.Error("the denial was not reported, so it would not be audited or counted")
	}
}

func TestHandle_ServesTheMatchingPod(t *testing.T) {
	a := newAuthzServer(t,
		[]secrets.Binding{paymentsBinding()},
		fixedIdentifier{caller: inPod(victimUID, "payments", "checkout-abc", nil)},
		Config{IdentifyCallers: true, RequirePodIdentity: true, RequireProtection: true},
	)

	resp := a.srv.handle(selfCred(t), request("node"))

	if !resp.OK {
		t.Fatalf("resp = %+v, want the pod the binding selects to be served", resp)
	}
	if resp.Env["DB_PASSWORD"] != "hunter2" {
		t.Errorf("Env = %v, want DB_PASSWORD delivered", resp.Env)
	}
	if len(a.denials) != 0 {
		t.Errorf("denials = %v, want none", a.denials)
	}
}

// Refusing a caller is an authorization decision, not a protection one, so it
// must not depend on whether the policy requires kernel protection. Audit mode
// weakens what the kernel blocks; it does not make secrets public.
func TestHandle_DeniesAnotherPodEvenWhenProtectionIsOptional(t *testing.T) {
	a := newAuthzServer(t,
		[]secrets.Binding{paymentsBinding()},
		fixedIdentifier{caller: inPod(attackerUID, "sandbox", "scratch-xyz", nil)},
		Config{IdentifyCallers: true, RequirePodIdentity: true, RequireProtection: false},
	)

	resp := a.srv.handle(selfCred(t), request("node"))

	if resp.OK {
		t.Error("a non-matching pod was served because protection was optional")
	}
	if len(a.denials) == 0 {
		t.Error("the denial was not reported")
	}
}

// A caller the agent cannot place in a pod is exactly the raw `nc -U` case, which
// has no cgroup the agent recognizes.
func TestHandle_RequiredModeDeniesAnUnidentifiableCaller(t *testing.T) {
	a := newAuthzServer(t,
		[]secrets.Binding{paymentsBinding()},
		fixedIdentifier{err: errors.New("no cgroup membership")},
		Config{IdentifyCallers: true, RequirePodIdentity: true, RequireProtection: true},
	)

	resp := a.srv.handle(selfCred(t), request("node"))

	if resp.OK {
		t.Error("an unidentifiable caller was served")
	}
	if !strings.Contains(resp.Error, "pod") {
		t.Errorf("Error = %q, want it to say the caller could not be attributed to a pod", resp.Error)
	}
	if len(a.denials) == 0 {
		t.Error("the denial was not reported")
	}
}

// A host process is identifiable but is not a pod. In required mode it must still
// be refused, or anything running on the node could collect secrets.
func TestHandle_RequiredModeDeniesAHostProcess(t *testing.T) {
	a := newAuthzServer(t,
		[]secrets.Binding{paymentsBinding()},
		fixedIdentifier{caller: secrets.Caller{CgroupPath: "/system.slice/sshd.service"}},
		Config{IdentifyCallers: true, RequirePodIdentity: true, RequireProtection: true},
	)

	if resp := a.srv.handle(selfCred(t), request("node")); resp.OK {
		t.Error("a host process was served in required mode")
	}
	if len(a.denials) == 0 {
		t.Error("the denial was not reported")
	}
}

// In preferred mode a host process is not refused outright, but a pod-scoped
// binding must still not match it.
func TestHandle_PreferredModeStillRefusesPodScopedBindings(t *testing.T) {
	a := newAuthzServer(t,
		[]secrets.Binding{paymentsBinding()},
		fixedIdentifier{caller: secrets.Caller{CgroupPath: "/system.slice/sshd.service"}},
		Config{IdentifyCallers: true, RequirePodIdentity: false, RequireProtection: true},
	)

	resp := a.srv.handle(selfCred(t), request("node"))
	if resp.OK {
		t.Error("a host process matched a namespace-scoped binding in preferred mode")
	}
	if len(resp.Env) != 0 {
		t.Errorf("Env = %v, want nothing released", resp.Env)
	}
}

// The sidecar case: the socket is already scoped to one pod, so a binding with no
// pod selector is legitimate and must still be served.
func TestHandle_PreferredModeServesUnscopedBindings(t *testing.T) {
	unscoped := secrets.Binding{
		Name:     "myapp",
		Selector: secrets.Selector{Binary: "node"},
		Secrets:  []secrets.Secret{{Name: "API_KEY", Value: "k"}},
	}

	a := newAuthzServer(t,
		[]secrets.Binding{unscoped},
		fixedIdentifier{caller: inPod(victimUID, "payments", "checkout-abc", nil)},
		Config{IdentifyCallers: true, RequirePodIdentity: false, RequireProtection: true},
	)

	resp := a.srv.handle(selfCred(t), request("node"))
	if !resp.OK || resp.Env["API_KEY"] != "k" {
		t.Errorf("resp = %+v, want the unscoped binding served in preferred mode", resp)
	}
}

// A binding rejected by policy must fail closed rather than read as an
// unconfigured binary, which would start the app with no secrets and no
// protection and say nothing.
func TestHandle_RejectedBindingIsDeniedNotSilent(t *testing.T) {
	rejected := secrets.Binding{
		Name:     "myapp",
		Selector: secrets.Selector{Binary: "node"},
		Secrets:  []secrets.Secret{{Name: "API_KEY", Value: "k"}},
		Rejected: "policy.podIdentity is required but this selector names no pod",
	}

	a := newAuthzServer(t,
		[]secrets.Binding{rejected},
		fixedIdentifier{caller: inPod(victimUID, "payments", "checkout-abc", nil)},
		Config{IdentifyCallers: true, RequirePodIdentity: true, RequireProtection: true},
	)

	resp := a.srv.handle(selfCred(t), request("node"))

	if resp.OK {
		t.Error("a binding rejected by policy was served")
	}
	if !strings.Contains(resp.Error, "myapp") {
		t.Errorf("Error = %q, want it to name the rejected binding", resp.Error)
	}
	if len(a.denials) == 0 {
		t.Error("the denial was not reported")
	}
}

// A binary nobody configured is still not an error, in any mode.
func TestHandle_UnconfiguredBinaryStaysQuietInRequiredMode(t *testing.T) {
	a := newAuthzServer(t,
		[]secrets.Binding{paymentsBinding()},
		fixedIdentifier{caller: inPod(victimUID, "payments", "checkout-abc", nil)},
		Config{IdentifyCallers: true, RequirePodIdentity: true, RequireProtection: true},
	)

	resp := a.srv.handle(selfCred(t), request("env"))
	if !resp.OK || resp.Error != "" {
		t.Errorf("resp = %+v, want a quiet allow for an unconfigured binary", resp)
	}
	if len(a.denials) != 0 {
		t.Errorf("denials = %v, want none", a.denials)
	}
}

// With identification enabled but no identifier wired, every caller must be
// refused rather than falling through to binary-only matching.
func TestHandle_MisconfiguredIdentifierFailsClosed(t *testing.T) {
	a := newAuthzServer(t,
		[]secrets.Binding{paymentsBinding()},
		nil,
		Config{IdentifyCallers: true, RequirePodIdentity: true, RequireProtection: true},
	)

	if resp := a.srv.handle(selfCred(t), request("node")); resp.OK {
		t.Error("a request was served with identification enabled and no identifier")
	}
}

// Two pods, one binary, one node. Each gets its own secrets and neither sees the
// other's. This is what a node-wide agent has to get right to be usable at all.
func TestHandle_TwoPodsOnOneNodeAreIsolated(t *testing.T) {
	sandbox := secrets.Binding{
		Name:     "scratch",
		Selector: secrets.Selector{Binary: "node", Namespace: "sandbox"},
		Secrets:  []secrets.Secret{{Name: "SCRATCH_TOKEN", Value: "t"}},
	}
	bindings := []secrets.Binding{paymentsBinding(), sandbox}
	cfg := Config{IdentifyCallers: true, RequirePodIdentity: true, RequireProtection: true}

	payments := newAuthzServer(t, bindings,
		fixedIdentifier{caller: inPod(victimUID, "payments", "checkout-abc", nil)}, cfg)
	resp := payments.srv.handle(selfCred(t), request("node"))
	if resp.Env["DB_PASSWORD"] != "hunter2" {
		t.Errorf("payments pod Env = %v, want DB_PASSWORD", resp.Env)
	}
	if _, leaked := resp.Env["SCRATCH_TOKEN"]; leaked {
		t.Error("the payments pod received the sandbox pod's secret")
	}

	sandboxSrv := newAuthzServer(t, bindings,
		fixedIdentifier{caller: inPod(attackerUID, "sandbox", "scratch-xyz", nil)}, cfg)
	resp = sandboxSrv.srv.handle(selfCred(t), request("node"))
	if resp.Env["SCRATCH_TOKEN"] != "t" {
		t.Errorf("sandbox pod Env = %v, want SCRATCH_TOKEN", resp.Env)
	}
	if _, leaked := resp.Env["DB_PASSWORD"]; leaked {
		t.Error("the sandbox pod received the payments pod's secret")
	}
}

// One binding serves while another for the same binary is rejected. The request
// succeeds, because a served binding is not a denial, but the application is
// starting without values its configuration names and must be told.
func TestHandle_ServedRequestWarnsAboutRejectedBindings(t *testing.T) {
	served := secrets.Binding{
		Name:     "checkout-db",
		Selector: secrets.Selector{Binary: "node", Namespace: "payments"},
		Secrets:  []secrets.Secret{{Name: "DB_PASSWORD", Value: "hunter2"}},
	}
	rejected := secrets.Binding{
		Name:     "legacy-api",
		Selector: secrets.Selector{Binary: "node"},
		Secrets:  []secrets.Secret{{Name: "API_KEY", Value: "k"}},
		Rejected: "policy.podIdentity is required but this selector names no pod",
	}

	a := newAuthzServer(t,
		[]secrets.Binding{served, rejected},
		fixedIdentifier{caller: inPod(victimUID, "payments", "checkout-abc", nil)},
		Config{IdentifyCallers: true, RequirePodIdentity: true, RequireProtection: true},
	)

	resp := a.srv.handle(selfCred(t), request("node"))

	if !resp.OK {
		t.Fatalf("resp = %+v, want the well-formed binding served", resp)
	}
	if resp.Env["DB_PASSWORD"] != "hunter2" {
		t.Errorf("Env = %v, want DB_PASSWORD delivered", resp.Env)
	}
	if _, leaked := resp.Env["API_KEY"]; leaked {
		t.Error("a rejected binding contributed a secret")
	}
	if !strings.Contains(resp.Warning, "legacy-api") {
		t.Errorf("Warning = %q, want it to name the rejected binding", resp.Warning)
	}
}
