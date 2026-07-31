package internal

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/phonginreallife/kernelseal/internal/secrets"
	"github.com/phonginreallife/kernelseal/internal/types"
)

func TestDefaultConfig(t *testing.T) {
	config := DefaultConfig()

	if config.Version != "v1" {
		t.Errorf("Version = %v, want v1", config.Version)
	}
	if config.Policy.Mode != "enforce" {
		t.Errorf("Policy.Mode = %v, want enforce", config.Policy.Mode)
	}
	if !config.Policy.BlockEnviron {
		t.Error("Policy.BlockEnviron should be true by default")
	}
	if !config.Policy.BlockMem {
		t.Error("Policy.BlockMem should be true by default")
	}
	if config.Policy.BlockMaps {
		t.Error("Policy.BlockMaps should be false by default")
	}
	if !config.Policy.BlockPtrace {
		t.Error("Policy.BlockPtrace should be true by default")
	}
	if !config.Policy.AllowSelfRead {
		t.Error("Policy.AllowSelfRead should be true by default")
	}
	if config.Monitoring.MetricsPort != 9090 {
		t.Errorf("Monitoring.MetricsPort = %v, want 9090", config.Monitoring.MetricsPort)
	}
}

func TestNewPolicyManager(t *testing.T) {
	registry := secrets.NewRegistry()
	pm := NewPolicyManager(registry)

	if pm == nil {
		t.Fatal("NewPolicyManager returned nil")
	}
	if pm.config == nil {
		t.Error("PolicyManager.config is nil")
	}
}

func TestPolicyManager_GetBPFPolicy(t *testing.T) {
	tests := []struct {
		name     string
		mode     string
		expected types.EnforceMode
	}{
		{"Disabled mode", "disabled", types.ModeDisabled},
		{"Audit mode", "audit", types.ModeAudit},
		{"Enforce mode", "enforce", types.ModeEnforce},
		{"Unknown mode defaults to enforce", "unknown", types.ModeEnforce},
		{"Empty mode defaults to enforce", "", types.ModeEnforce},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			pm := NewPolicyManager(nil)
			pm.config.Policy.Mode = tt.mode
			policy := pm.GetBPFPolicy()
			if policy.EnforceMode != tt.expected {
				t.Errorf("EnforceMode = %v, want %v", policy.EnforceMode, tt.expected)
			}
		})
	}
}

func TestPolicyManager_GetBPFPolicy_BoolConversion(t *testing.T) {
	pm := NewPolicyManager(nil)
	pm.config.Policy.BlockEnviron = true
	pm.config.Policy.BlockMem = false
	pm.config.Policy.BlockMaps = true
	pm.config.Policy.BlockPtrace = false
	pm.config.Policy.AllowSelfRead = true
	pm.config.Policy.AuditAll = false

	policy := pm.GetBPFPolicy()

	if policy.BlockEnviron != 1 {
		t.Errorf("BlockEnviron = %v, want 1", policy.BlockEnviron)
	}
	if policy.BlockMem != 0 {
		t.Errorf("BlockMem = %v, want 0", policy.BlockMem)
	}
	if policy.BlockMaps != 1 {
		t.Errorf("BlockMaps = %v, want 1", policy.BlockMaps)
	}
	if policy.BlockPtrace != 0 {
		t.Errorf("BlockPtrace = %v, want 0", policy.BlockPtrace)
	}
	if policy.AllowSelfRead != 1 {
		t.Errorf("AllowSelfRead = %v, want 1", policy.AllowSelfRead)
	}
	if policy.AuditAll != 0 {
		t.Errorf("AuditAll = %v, want 0", policy.AuditAll)
	}
}

func TestPolicyManager_LoadConfigFromFile_YAML(t *testing.T) {
	tmpDir := t.TempDir()
	configPath := filepath.Join(tmpDir, "config.yaml")

	configContent := `
version: v1
policy:
  mode: audit
  blockEnviron: false
  blockMem: true
  blockMaps: true
  blockPtrace: false
  allowSelfRead: false
  auditAll: true
monitoring:
  enabled: true
  metricsPort: 8080
  logLevel: debug
`
	if err := os.WriteFile(configPath, []byte(configContent), 0644); err != nil {
		t.Fatalf("Failed to write test config: %v", err)
	}

	pm := NewPolicyManager(nil)
	if err := pm.LoadConfig(configPath); err != nil {
		t.Fatalf("LoadConfig failed: %v", err)
	}

	config := pm.GetConfig()
	if config.Policy.Mode != "audit" {
		t.Errorf("Policy.Mode = %v, want audit", config.Policy.Mode)
	}
	if config.Policy.BlockEnviron {
		t.Error("Policy.BlockEnviron should be false")
	}
	if !config.Policy.BlockMem {
		t.Error("Policy.BlockMem should be true")
	}
	if !config.Policy.BlockMaps {
		t.Error("Policy.BlockMaps should be true")
	}
	if config.Monitoring.MetricsPort != 8080 {
		t.Errorf("Monitoring.MetricsPort = %v, want 8080", config.Monitoring.MetricsPort)
	}
}

func TestPolicyManager_LoadConfigFromFile_JSON(t *testing.T) {
	tmpDir := t.TempDir()
	configPath := filepath.Join(tmpDir, "config.json")

	configContent := `{
  "version": "v1",
  "policy": {
    "mode": "enforce",
    "blockEnviron": true,
    "blockMem": true
  },
  "monitoring": {
    "enabled": false,
    "metricsPort": 9999
  }
}`
	if err := os.WriteFile(configPath, []byte(configContent), 0644); err != nil {
		t.Fatalf("Failed to write test config: %v", err)
	}

	pm := NewPolicyManager(nil)
	if err := pm.LoadConfig(configPath); err != nil {
		t.Fatalf("LoadConfig failed: %v", err)
	}

	config := pm.GetConfig()
	if config.Policy.Mode != "enforce" {
		t.Errorf("Policy.Mode = %v, want enforce", config.Policy.Mode)
	}
	if config.Monitoring.MetricsPort != 9999 {
		t.Errorf("Monitoring.MetricsPort = %v, want 9999", config.Monitoring.MetricsPort)
	}
}

func TestPolicyManager_LoadConfigFromDir(t *testing.T) {
	tmpDir := t.TempDir()

	policyContent := `
mode: audit
blockEnviron: false
blockMem: true
`
	if err := os.WriteFile(filepath.Join(tmpDir, "policy.yaml"), []byte(policyContent), 0644); err != nil {
		t.Fatalf("Failed to write policy.yaml: %v", err)
	}

	monitoringContent := `
enabled: true
metricsPort: 7777
logLevel: warn
`
	if err := os.WriteFile(filepath.Join(tmpDir, "monitoring.yaml"), []byte(monitoringContent), 0644); err != nil {
		t.Fatalf("Failed to write monitoring.yaml: %v", err)
	}

	pm := NewPolicyManager(nil)
	if err := pm.LoadConfig(tmpDir); err != nil {
		t.Fatalf("LoadConfig failed: %v", err)
	}

	config := pm.GetConfig()
	if config.Policy.Mode != "audit" {
		t.Errorf("Policy.Mode = %v, want audit", config.Policy.Mode)
	}
	if config.Monitoring.MetricsPort != 7777 {
		t.Errorf("Monitoring.MetricsPort = %v, want 7777", config.Monitoring.MetricsPort)
	}
}

func TestPolicyManager_LoadConfig_InvalidPath(t *testing.T) {
	pm := NewPolicyManager(nil)
	err := pm.LoadConfig("/nonexistent/path/config.yaml")
	if err == nil {
		t.Error("Expected error for invalid path, got nil")
	}
}

func TestPolicyManager_LoadConfig_InvalidFormat(t *testing.T) {
	tmpDir := t.TempDir()
	configPath := filepath.Join(tmpDir, "config.txt")

	if err := os.WriteFile(configPath, []byte("some content"), 0644); err != nil {
		t.Fatalf("Failed to write test file: %v", err)
	}

	pm := NewPolicyManager(nil)
	err := pm.LoadConfig(configPath)
	if err == nil {
		t.Error("Expected error for unsupported format, got nil")
	}
}

func TestPolicyManager_LoadConfig_InvalidYAML(t *testing.T) {
	tmpDir := t.TempDir()
	configPath := filepath.Join(tmpDir, "config.yaml")

	if err := os.WriteFile(configPath, []byte("invalid: yaml: content: ["), 0644); err != nil {
		t.Fatalf("Failed to write test file: %v", err)
	}

	pm := NewPolicyManager(nil)
	err := pm.LoadConfig(configPath)
	if err == nil {
		t.Error("Expected error for invalid YAML, got nil")
	}
}

func TestPolicyManager_SetPolicyUpdateCallback(t *testing.T) {
	pm := NewPolicyManager(nil)

	var callbackCalled bool
	var receivedPolicy types.PolicyConfig

	pm.SetPolicyUpdateCallback(func(policy types.PolicyConfig) {
		callbackCalled = true
		receivedPolicy = policy
	})

	tmpDir := t.TempDir()
	configPath := filepath.Join(tmpDir, "config.yaml")
	configContent := `
version: v1
policy:
  mode: audit
`
	if err := os.WriteFile(configPath, []byte(configContent), 0644); err != nil {
		t.Fatalf("Failed to write test config: %v", err)
	}

	if err := pm.LoadConfig(configPath); err != nil {
		t.Fatalf("LoadConfig failed: %v", err)
	}

	if !callbackCalled {
		t.Error("Policy update callback was not called")
	}
	if receivedPolicy.EnforceMode != types.ModeAudit {
		t.Errorf("Received policy mode = %v, want %v", receivedPolicy.EnforceMode, types.ModeAudit)
	}
}

func TestPolicyManager_SecretsFor_NoRegistry(t *testing.T) {
	pm := NewPolicyManager(nil)

	result := pm.SecretsFor("myapp", secrets.Caller{})
	if !result.Empty() {
		t.Errorf("Expected an empty match when no registry, got %+v", result)
	}
}

func TestPolicyManager_SecretsFor_WithRegistry(t *testing.T) {
	registry := secrets.NewRegistry()
	registry.Replace([]secrets.Binding{{
		Name:     "myapp",
		Selector: secrets.Selector{Binary: "myapp"},
		Secrets:  []secrets.Secret{{Name: "DB_PASSWORD", Value: "secret123"}},
	}})

	pm := NewPolicyManager(registry)

	result := pm.SecretsFor("myapp", secrets.Caller{})
	if len(result.Secrets) != 1 {
		t.Fatalf("Expected 1 secret, got %d", len(result.Secrets))
	}
	if result.Secrets[0].Name != "DB_PASSWORD" {
		t.Errorf("Secret name = %v, want DB_PASSWORD", result.Secrets[0].Name)
	}
}

func TestPolicyManager_ResolveSecretValue_EnvRef(t *testing.T) {
	os.Setenv("TEST_SECRET", "my-secret-value")
	defer os.Unsetenv("TEST_SECRET")

	pm := NewPolicyManager(nil)
	source := SecretSource{EnvRef: "TEST_SECRET"}

	value, err := pm.resolveSecretValue(source)
	if err != nil {
		t.Fatalf("resolveSecretValue failed: %v", err)
	}
	if value != "my-secret-value" {
		t.Errorf("value = %v, want my-secret-value", value)
	}
}

func TestPolicyManager_ResolveSecretValue_EnvRef_NotSet(t *testing.T) {
	pm := NewPolicyManager(nil)
	source := SecretSource{EnvRef: "NONEXISTENT_VAR"}

	_, err := pm.resolveSecretValue(source)
	if err == nil {
		t.Error("Expected error for unset environment variable")
	}
}

func TestPolicyManager_ResolveSecretValue_FileRef(t *testing.T) {
	tmpDir := t.TempDir()
	secretFile := filepath.Join(tmpDir, "secret.txt")
	if err := os.WriteFile(secretFile, []byte("  file-secret-value  \n"), 0644); err != nil {
		t.Fatalf("Failed to write secret file: %v", err)
	}

	pm := NewPolicyManager(nil)
	source := SecretSource{FileRef: secretFile}

	value, err := pm.resolveSecretValue(source)
	if err != nil {
		t.Fatalf("resolveSecretValue failed: %v", err)
	}
	if value != "file-secret-value" {
		t.Errorf("value = %v, want file-secret-value (trimmed)", value)
	}
}

func TestPolicyManager_ResolveSecretValue_FileRef_NotFound(t *testing.T) {
	pm := NewPolicyManager(nil)
	source := SecretSource{FileRef: "/nonexistent/path/secret.txt"}

	_, err := pm.resolveSecretValue(source)
	if err == nil {
		t.Error("Expected error for nonexistent file")
	}
}

func TestPolicyManager_ResolveSecretValue_NoSource(t *testing.T) {
	pm := NewPolicyManager(nil)
	source := SecretSource{}

	_, err := pm.resolveSecretValue(source)
	if err == nil {
		t.Error("Expected error for empty source")
	}
}

func TestPolicyManager_ResolveSecretValue_VaultRef(t *testing.T) {
	pm := NewPolicyManager(nil)
	source := SecretSource{
		VaultRef: &VaultRef{Path: "secret/data/myapp", Key: "password"},
	}

	_, err := pm.resolveSecretValue(source)
	if err == nil {
		t.Error("Expected error for unimplemented Vault integration")
	}
}

func TestBoolToUint8(t *testing.T) {
	if boolToUint8(true) != 1 {
		t.Error("boolToUint8(true) should return 1")
	}
	if boolToUint8(false) != 0 {
		t.Error("boolToUint8(false) should return 0")
	}
}

func TestPolicyManager_LoadConfigWithSecrets(t *testing.T) {
	tmpDir := t.TempDir()
	configPath := filepath.Join(tmpDir, "config.yaml")

	os.Setenv("TEST_DB_PASS", "testpassword")
	defer os.Unsetenv("TEST_DB_PASS")

	configContent := `
version: v1
policy:
  mode: enforce
secrets:
  - name: db-secrets
    selector:
      binary: "postgres"
    secretRefs:
      - name: PGPASSWORD
        source:
          envRef: "TEST_DB_PASS"
`
	if err := os.WriteFile(configPath, []byte(configContent), 0644); err != nil {
		t.Fatalf("Failed to write test config: %v", err)
	}

	registry := secrets.NewRegistry()
	pm := NewPolicyManager(registry)

	if err := pm.LoadConfig(configPath); err != nil {
		t.Fatalf("LoadConfig failed: %v", err)
	}

	result := registry.Lookup("postgres", secrets.Caller{})
	if len(result.Secrets) != 1 {
		t.Fatalf("Expected 1 secret, got %d", len(result.Secrets))
	}
	if result.Secrets[0].Name != "PGPASSWORD" {
		t.Errorf("Secret name = %v, want PGPASSWORD", result.Secrets[0].Name)
	}
	if result.Secrets[0].Value != "testpassword" {
		t.Errorf("Secret value = %v, want testpassword", result.Secrets[0].Value)
	}
}

func TestParsePodIdentity(t *testing.T) {
	tests := []struct {
		in      string
		want    PodIdentityMode
		wantErr bool
	}{
		{"", PodIdentityPreferred, false},
		{"preferred", PodIdentityPreferred, false},
		{"required", PodIdentityRequired, false},
		{"disabled", PodIdentityDisabled, false},
		{"  Required  ", PodIdentityRequired, false},
		{"REQUIRED", PodIdentityRequired, false},
	}

	for _, tt := range tests {
		got, err := parsePodIdentity(tt.in)
		if (err != nil) != tt.wantErr {
			t.Errorf("parsePodIdentity(%q) error = %v, wantErr %v", tt.in, err, tt.wantErr)
		}
		if got != tt.want {
			t.Errorf("parsePodIdentity(%q) = %v, want %v", tt.in, got, tt.want)
		}
	}
}

// An unrecognized value in the setting that governs authorization must fail
// closed. Falling back to the default would silently widen who can be served, and
// "strict" is exactly the kind of plausible-sounding value an operator writes
// while expecting it to be at least as restrictive as required.
func TestParsePodIdentity_UnknownValueFailsClosed(t *testing.T) {
	for _, in := range []string{"strict", "enforce", "true", "on"} {
		got, err := parsePodIdentity(in)
		if err == nil {
			t.Errorf("parsePodIdentity(%q) returned no error for an unrecognized mode", in)
		}
		if got != PodIdentityRequired {
			t.Errorf("parsePodIdentity(%q) = %v, want required so an unreadable setting cannot widen access", in, got)
		}
	}
}

func TestPodIdentityMode_String(t *testing.T) {
	cases := map[PodIdentityMode]string{
		PodIdentityPreferred: "preferred",
		PodIdentityRequired:  "required",
		PodIdentityDisabled:  "disabled",
	}
	for mode, want := range cases {
		if got := mode.String(); got != want {
			t.Errorf("%d.String() = %q, want %q", mode, got, want)
		}
	}
}

func TestRejectionFor(t *testing.T) {
	binaryOnly := secrets.Selector{Binary: "node"}
	podScoped := secrets.Selector{Binary: "node", Namespace: "payments"}

	// In required mode a binary-only binding is claimable by any pod that reaches
	// the socket, which is the whole exposure, so it must not be servable.
	if got := rejectionFor(binaryOnly, PodIdentityRequired); got == "" {
		t.Error("a binary-only binding was accepted in required mode")
	}
	if got := rejectionFor(podScoped, PodIdentityRequired); got != "" {
		t.Errorf("a pod-scoped binding was rejected in required mode: %s", got)
	}

	// Preferred mode serves both shapes: the sidecar's socket is already scoped.
	if got := rejectionFor(binaryOnly, PodIdentityPreferred); got != "" {
		t.Errorf("a binary-only binding was rejected in preferred mode: %s", got)
	}
	if got := rejectionFor(podScoped, PodIdentityPreferred); got != "" {
		t.Errorf("a pod-scoped binding was rejected in preferred mode: %s", got)
	}

	// With identification off, a pod-scoped selector can never be evaluated, so
	// accepting it would mean a binding that silently matches nothing.
	if got := rejectionFor(podScoped, PodIdentityDisabled); got == "" {
		t.Error("a pod-scoped binding was accepted with podIdentity disabled")
	}
	if got := rejectionFor(binaryOnly, PodIdentityDisabled); got != "" {
		t.Errorf("a binary-only binding was rejected with podIdentity disabled: %s", got)
	}

	// A selector that names nothing matches nothing, in any mode.
	for _, mode := range []PodIdentityMode{PodIdentityRequired, PodIdentityPreferred, PodIdentityDisabled} {
		if got := rejectionFor(secrets.Selector{}, mode); got == "" {
			t.Errorf("an empty selector was accepted in %s mode", mode)
		}
	}
}

// The end-to-end config path: a binary-only binding loaded under required mode
// must reach the registry marked rejected, not simply dropped. Dropping it would
// make the binary look unconfigured, which starts the app unprotected in silence.
func TestLoadConfig_RejectsBinaryOnlyBindingInRequiredMode(t *testing.T) {
	dir := t.TempDir()
	configPath := dir + "/config.yaml"
	configContent := `
version: v1
policy:
  mode: enforce
  podIdentity: required
secrets:
  - name: myapp-secrets
    selector:
      binary: "node"
    secretRefs:
      - name: API_KEY
        source:
          value: "literal"
`
	if err := os.WriteFile(configPath, []byte(configContent), 0644); err != nil {
		t.Fatalf("writing config: %v", err)
	}

	registry := secrets.NewRegistry()
	pm := NewPolicyManager(registry)
	if err := pm.LoadConfig(configPath); err != nil {
		t.Fatalf("LoadConfig: %v", err)
	}

	if pm.PodIdentityMode() != PodIdentityRequired {
		t.Fatalf("mode = %v, want required", pm.PodIdentityMode())
	}

	got := registry.Lookup("node", secrets.Caller{})
	if len(got.Secrets) != 0 {
		t.Errorf("a binary-only binding served %d secret(s) in required mode", len(got.Secrets))
	}
	if len(got.Rejected) != 1 {
		t.Errorf("Rejected = %v, want the binding named so delivery can refuse loudly", got.Rejected)
	}
	if got.Empty() {
		t.Error("the match reports Empty, so the binary would look unconfigured")
	}
}

// The same config under the default mode is served, so the sidecar path keeps
// working exactly as it did in 1.1.0.
func TestLoadConfig_ServesBinaryOnlyBindingByDefault(t *testing.T) {
	dir := t.TempDir()
	configPath := dir + "/config.yaml"
	configContent := `
version: v1
policy:
  mode: enforce
secrets:
  - name: myapp-secrets
    selector:
      binary: "node"
    secretRefs:
      - name: API_KEY
        source:
          value: "literal"
`
	if err := os.WriteFile(configPath, []byte(configContent), 0644); err != nil {
		t.Fatalf("writing config: %v", err)
	}

	registry := secrets.NewRegistry()
	pm := NewPolicyManager(registry)
	if err := pm.LoadConfig(configPath); err != nil {
		t.Fatalf("LoadConfig: %v", err)
	}

	if pm.PodIdentityMode() != PodIdentityPreferred {
		t.Errorf("default mode = %v, want preferred", pm.PodIdentityMode())
	}

	got := registry.Lookup("node", secrets.Caller{})
	if len(got.Secrets) != 1 || got.Secrets[0].Name != "API_KEY" {
		t.Errorf("secrets = %+v, want API_KEY served under the default mode", got.Secrets)
	}
}

// Pod selectors have to survive parsing and reach the registry, or matching would
// silently fall back to the binary name.
func TestLoadConfig_CarriesPodSelectorsIntoTheRegistry(t *testing.T) {
	dir := t.TempDir()
	configPath := dir + "/config.yaml"
	configContent := `
version: v1
policy:
  mode: enforce
  podIdentity: required
secrets:
  - name: checkout-db
    selector:
      binary: "node"
      namespace: "payments"
      container: "server"
      labels:
        app: checkout
    secretRefs:
      - name: DB_PASSWORD
        source:
          value: "hunter2"
`
	if err := os.WriteFile(configPath, []byte(configContent), 0644); err != nil {
		t.Fatalf("writing config: %v", err)
	}

	registry := secrets.NewRegistry()
	pm := NewPolicyManager(registry)
	if err := pm.LoadConfig(configPath); err != nil {
		t.Fatalf("LoadConfig: %v", err)
	}

	// A caller with no pod identity must be refused by every one of those
	// constraints rather than matching on the binary name.
	got := registry.Lookup("node", secrets.Caller{})
	if len(got.Secrets) != 0 {
		t.Errorf("released %d secret(s) to a caller with no pod identity", len(got.Secrets))
	}
	if len(got.Refused) != 1 {
		t.Errorf("Refused = %v, want the binding refused on identity", got.Refused)
	}
	if len(got.Rejected) != 0 {
		t.Errorf("Rejected = %v, want none: the binding is well formed", got.Rejected)
	}
}
