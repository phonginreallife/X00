package server

import (
	"strings"
	"syscall"
	"testing"

	"kernelseal/internal/protocol"
	"kernelseal/internal/secrets"
)

func request(binary string) protocol.Request {
	return protocol.Request{Binary: "/usr/bin/" + binary}
}

// recordingProtector notes whether protection was ever installed, which is the
// thing that must not happen silently for a misconfigured binding.
type recordingProtector struct {
	protected []uint32
}

func (p *recordingProtector) ProtectPID(pid uint32) error {
	p.protected = append(p.protected, pid)
	return nil
}
func (p *recordingProtector) UnprotectPID(uint32) error { return nil }
func (p *recordingProtector) TrackPID(uint32) error     { return nil }

// selfCred describes this process, so handle() sees a caller that really exists
// and its /proc start-time checks pass.
func selfCred(t *testing.T) *syscall.Ucred {
	t.Helper()
	return &syscall.Ucred{
		Pid: int32(syscall.Getpid()),
		Uid: uint32(syscall.Getuid()),
		Gid: uint32(syscall.Getgid()),
	}
}

func newServer(t *testing.T, registry *secrets.Registry, p Protector, requireProtection bool) *Server {
	t.Helper()
	return New(Config{
		SocketPath:        t.TempDir() + "/s.sock",
		RequireProtection: requireProtection,
	}, registry, p)
}

// A binary with nothing configured is not an error and must stay quiet: the shim
// legitimately fronts binaries that have no secrets.
func TestHandle_NoBindingIsQuiet(t *testing.T) {
	p := &recordingProtector{}
	srv := newServer(t, secrets.NewRegistry(), p, true)

	resp := srv.handle(selfCred(t), request("env"))

	if !resp.OK || resp.Error != "" {
		t.Errorf("resp = %+v, want OK with no error", resp)
	}
	if resp.Warning != "" {
		t.Errorf("Warning = %q, want empty for a binary with no bindings", resp.Warning)
	}
	if len(p.protected) != 0 {
		t.Errorf("ProtectPID called %v, want no calls", p.protected)
	}
}

// The regression this guards: a binding whose every source failed used to be
// indistinguishable from no binding at all, so the process started with no
// secrets AND no protection, silently, even in enforce mode.
func TestHandle_AllSecretsUnresolvedIsDeniedWhenProtectionRequired(t *testing.T) {
	registry := secrets.NewRegistry()
	registry.RegisterForBinary("node", nil)
	registry.SetUnresolved("node", []string{"JWT_SECRET", "API_KEY"})

	p := &recordingProtector{}
	srv := newServer(t, registry, p, true)

	resp := srv.handle(selfCred(t), request("node"))

	if resp.OK {
		t.Error("request was served; a binding that resolved to nothing must fail closed")
	}
	if !strings.Contains(resp.Error, "JWT_SECRET") || !strings.Contains(resp.Error, "API_KEY") {
		t.Errorf("Error = %q, want it to name the unresolved secrets", resp.Error)
	}
	if len(resp.Env) != 0 {
		t.Errorf("Env = %v, want empty", resp.Env)
	}
	if len(p.protected) != 0 {
		t.Errorf("ProtectPID called %v, want no calls for a denied request", p.protected)
	}
}

// Outside enforce mode the process still starts, but the operator must be told.
func TestHandle_AllSecretsUnresolvedWarnsWhenProtectionOptional(t *testing.T) {
	registry := secrets.NewRegistry()
	registry.RegisterForBinary("node", nil)
	registry.SetUnresolved("node", []string{"JWT_SECRET"})

	srv := newServer(t, registry, &recordingProtector{}, false)

	resp := srv.handle(selfCred(t), request("node"))

	if !resp.OK {
		t.Errorf("resp = %+v, want the exec to be allowed when protection is optional", resp)
	}
	if resp.Protected {
		t.Error("Protected = true, but nothing was protected")
	}
	if !strings.Contains(resp.Warning, "JWT_SECRET") {
		t.Errorf("Warning = %q, want it to name the unresolved secret", resp.Warning)
	}
}

// A partial resolution is usable and protected, so it must be served - but the
// app is missing a secret its config says it needs, so it must warn.
func TestHandle_PartialResolutionServesAndWarns(t *testing.T) {
	registry := secrets.NewRegistry()
	registry.RegisterForBinary("node", []secrets.Secret{{Name: "JWT_SECRET", Value: "v"}})
	registry.SetUnresolved("node", []string{"API_KEY"})

	p := &recordingProtector{}
	srv := newServer(t, registry, p, true)

	resp := srv.handle(selfCred(t), request("node"))

	if !resp.OK || !resp.Protected {
		t.Fatalf("resp = %+v, want a served, protected response", resp)
	}
	if resp.Env["JWT_SECRET"] != "v" {
		t.Errorf("Env = %v, want the resolved secret delivered", resp.Env)
	}
	if _, ok := resp.Env["API_KEY"]; ok {
		t.Error("Env contains API_KEY, which never resolved")
	}
	if !strings.Contains(resp.Warning, "API_KEY") {
		t.Errorf("Warning = %q, want it to name the unresolved secret", resp.Warning)
	}
	if len(p.protected) != 1 {
		t.Errorf("ProtectPID called %v, want exactly one call", p.protected)
	}
}

// A reload that fixes the source must clear the complaint rather than leave the
// binary permanently denied.
func TestHandle_ResolvingLaterClearsTheDenial(t *testing.T) {
	registry := secrets.NewRegistry()
	registry.RegisterForBinary("node", nil)
	registry.SetUnresolved("node", []string{"API_KEY"})

	srv := newServer(t, registry, &recordingProtector{}, true)

	if resp := srv.handle(selfCred(t), request("node")); resp.OK {
		t.Fatal("expected the first request to be denied")
	}

	registry.RegisterForBinary("node", []secrets.Secret{{Name: "API_KEY", Value: "v"}})
	registry.SetUnresolved("node", nil)

	resp := srv.handle(selfCred(t), request("node"))
	if !resp.OK || resp.Warning != "" {
		t.Errorf("resp = %+v, want a clean served response after the source was fixed", resp)
	}
}
