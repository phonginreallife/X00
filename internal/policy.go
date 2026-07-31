// Package internal provides core KernelSeal functionality
package internal

import (
	"encoding/json"
	"fmt"
	"io"
	"log"
	"os"
	"path/filepath"
	"strings"
	"sync"

	"gopkg.in/yaml.v3"

	"github.com/phonginreallife/kernelseal/internal/secrets"
	"github.com/phonginreallife/kernelseal/internal/types"
)

// PolicyManager manages KernelSeal security policies
type PolicyManager struct {
	config     *KernelSealConfig
	configPath string
	registry   *secrets.Registry
	mu         sync.RWMutex

	// Callbacks for policy updates
	onPolicyUpdate func(types.PolicyConfig)
}

// KernelSealConfig represents the complete KernelSeal configuration
type KernelSealConfig struct {
	Version    string           `yaml:"version" json:"version"`
	Policy     PolicySpec       `yaml:"policy" json:"policy"`
	Secrets    []SecretBinding  `yaml:"secrets" json:"secrets"`
	Monitoring MonitoringConfig `yaml:"monitoring" json:"monitoring"`
}

// PolicySpec defines the LSM policy settings
type PolicySpec struct {
	Mode          string `yaml:"mode" json:"mode"` // disabled, audit, enforce
	BlockEnviron  bool   `yaml:"blockEnviron" json:"blockEnviron"`
	BlockMem      bool   `yaml:"blockMem" json:"blockMem"`
	BlockMaps     bool   `yaml:"blockMaps" json:"blockMaps"`
	BlockPtrace   bool   `yaml:"blockPtrace" json:"blockPtrace"`
	AllowSelfRead bool   `yaml:"allowSelfRead" json:"allowSelfRead"`
	AuditAll      bool   `yaml:"auditAll" json:"auditAll"`

	// Kernel-side filtering options
	// When enabled, only processes matching configured binaries will be monitored
	// This significantly reduces overhead for systems with many processes
	KernelBinaryFilter bool `yaml:"kernelBinaryFilter" json:"kernelBinaryFilter"`

	// PodIdentity decides how much the agent must know about a caller before it
	// will release anything. See PodIdentityMode.
	PodIdentity string `yaml:"podIdentity" json:"podIdentity"`
}

// PodIdentityMode says how a caller must be identified before secrets are
// released to it.
//
// The binary name in a request is a claim, so a binding selected by binary alone
// is served to anything that can open the socket and name it. Whether that is
// acceptable depends entirely on who can reach the socket, which is a deployment
// question the agent cannot answer for itself.
type PodIdentityMode int

const (
	// PodIdentityPreferred resolves the caller's pod when it can and enforces
	// every pod-scoped selector against it, but still serves bindings that carry
	// no pod selector. Correct for the per-pod sidecar, where the socket is
	// already scoped to one pod and the binary name only picks among that pod's
	// own bindings.
	PodIdentityPreferred PodIdentityMode = iota

	// PodIdentityRequired refuses to serve anything it cannot attribute to a pod,
	// and refuses bindings that name no pod at all. Correct for a node-wide agent,
	// where the socket is reachable by every pod that mounts it and the binary
	// name would otherwise be the only thing standing between them.
	PodIdentityRequired

	// PodIdentityDisabled does not resolve callers at all. Bindings are selected
	// by binary name alone, which is the 1.1.0 behavior.
	PodIdentityDisabled
)

func (m PodIdentityMode) String() string {
	switch m {
	case PodIdentityRequired:
		return "required"
	case PodIdentityDisabled:
		return "disabled"
	default:
		return "preferred"
	}
}

// parsePodIdentity maps the configured string to a mode. An unrecognized value
// selects required rather than the default, because a typo in the setting that
// governs authorization must not quietly widen it.
func parsePodIdentity(s string) (PodIdentityMode, error) {
	switch strings.ToLower(strings.TrimSpace(s)) {
	case "", "preferred":
		return PodIdentityPreferred, nil
	case "required":
		return PodIdentityRequired, nil
	case "disabled":
		return PodIdentityDisabled, nil
	default:
		return PodIdentityRequired, fmt.Errorf("unknown podIdentity %q; want required, preferred or disabled", s)
	}
}

// SecretBinding binds secrets to specific processes
type SecretBinding struct {
	Name       string          `yaml:"name" json:"name"`             // Binding name
	Selector   ProcessSelector `yaml:"selector" json:"selector"`     // How to select processes
	SecretRefs []SecretRef     `yaml:"secretRefs" json:"secretRefs"` // References to secrets
}

// ProcessSelector defines how to select target processes
type ProcessSelector struct {
	Binary     string            `yaml:"binary,omitempty" json:"binary,omitempty"`         // Match by binary name
	Container  string            `yaml:"container,omitempty" json:"container,omitempty"`   // Match by container name
	Labels     map[string]string `yaml:"labels,omitempty" json:"labels,omitempty"`         // Match by pod labels
	Namespace  string            `yaml:"namespace,omitempty" json:"namespace,omitempty"`   // Match by namespace
	CgroupPath string            `yaml:"cgroupPath,omitempty" json:"cgroupPath,omitempty"` // Match by cgroup path
}

// SecretRef references a secret source
type SecretRef struct {
	Name   string       `yaml:"name" json:"name"`     // Environment variable name
	Source SecretSource `yaml:"source" json:"source"` // Secret source
}

// SecretSource defines where to get the secret value
type SecretSource struct {
	// Literal value
	Value string `yaml:"value,omitempty" json:"value,omitempty"`
	// Kubernetes secret reference
	SecretKeyRef *SecretKeyRef `yaml:"secretKeyRef,omitempty" json:"secretKeyRef,omitempty"`
	// File path reference
	FileRef string `yaml:"fileRef,omitempty" json:"fileRef,omitempty"`
	// Environment variable reference
	EnvRef string `yaml:"envRef,omitempty" json:"envRef,omitempty"`
	// Vault reference (future)
	VaultRef *VaultRef `yaml:"vaultRef,omitempty" json:"vaultRef,omitempty"`
}

// SecretKeyRef references a Kubernetes secret
type SecretKeyRef struct {
	Name      string `yaml:"name" json:"name"`
	Key       string `yaml:"key" json:"key"`
	Namespace string `yaml:"namespace,omitempty" json:"namespace,omitempty"`
}

// VaultRef references a HashiCorp Vault secret
type VaultRef struct {
	Path string `yaml:"path" json:"path"`
	Key  string `yaml:"key" json:"key"`
}

// MonitoringConfig defines monitoring settings
type MonitoringConfig struct {
	Enabled     bool   `yaml:"enabled" json:"enabled"`
	MetricsPort int    `yaml:"metricsPort" json:"metricsPort"`
	LogLevel    string `yaml:"logLevel" json:"logLevel"`
	AuditLog    string `yaml:"auditLog" json:"auditLog"` // Path to audit log file
}

// NewPolicyManager creates a new policy manager. The registry may be nil, in
// which case secret bindings are parsed but not registered.
func NewPolicyManager(registry *secrets.Registry) *PolicyManager {
	return &PolicyManager{
		config:   DefaultConfig(),
		registry: registry,
	}
}

// DefaultConfig returns the default KernelSeal configuration
func DefaultConfig() *KernelSealConfig {
	return &KernelSealConfig{
		Version: "v1",
		Policy: PolicySpec{
			Mode:               "enforce",
			BlockEnviron:       true,
			BlockMem:           true,
			BlockMaps:          false,
			BlockPtrace:        true,
			AllowSelfRead:      true,
			AuditAll:           false,
			KernelBinaryFilter: true, // Enable kernel-side filtering by default

			// Preferred, not required, because the default cannot know who can
			// reach the socket. The per-pod sidecar scopes it to one pod already;
			// the node-wide DaemonSet does not, and its manifest sets required.
			PodIdentity: "preferred",
		},
		Secrets: []SecretBinding{},
		Monitoring: MonitoringConfig{
			Enabled:     true,
			MetricsPort: 9090,
			LogLevel:    "info",
			AuditLog:    "/var/log/kernelseal/audit.log",
		},
	}
}

// SetPolicyUpdateCallback sets the callback for policy updates
func (pm *PolicyManager) SetPolicyUpdateCallback(cb func(types.PolicyConfig)) {
	pm.mu.Lock()
	defer pm.mu.Unlock()
	pm.onPolicyUpdate = cb
}

// LoadConfig loads configuration from a file or directory
func (pm *PolicyManager) LoadConfig(path string) error {
	info, err := os.Stat(path)
	if err != nil {
		return fmt.Errorf("failed to stat config path: %w", err)
	}

	var config *KernelSealConfig
	if info.IsDir() {
		config, err = pm.loadConfigFromDir(path)
	} else {
		config, err = pm.loadConfigFromFile(path)
	}

	if err != nil {
		return err
	}

	// Update config under lock
	pm.mu.Lock()
	pm.configPath = path
	pm.config = config
	pm.mu.Unlock()

	log.Printf("[CONFIG] Loaded KernelSeal configuration from %s", path)

	// Apply policy (these methods handle their own locking)
	pm.applyPolicy()

	// Load secrets
	pm.loadSecrets()

	return nil
}

func (pm *PolicyManager) loadConfigFromFile(path string) (*KernelSealConfig, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()

	data, err := io.ReadAll(f)
	if err != nil {
		return nil, err
	}

	config := DefaultConfig()

	ext := strings.ToLower(filepath.Ext(path))
	switch ext {
	case ".yaml", ".yml":
		if err := yaml.Unmarshal(data, config); err != nil {
			return nil, fmt.Errorf("failed to parse YAML config: %w", err)
		}
	case ".json":
		if err := json.Unmarshal(data, config); err != nil {
			return nil, fmt.Errorf("failed to parse JSON config: %w", err)
		}
	default:
		return nil, fmt.Errorf("unsupported config format: %s", ext)
	}

	return config, nil
}

func (pm *PolicyManager) loadConfigFromDir(dir string) (*KernelSealConfig, error) {
	// Look for config files in the directory (ConfigMap mount style)
	config := DefaultConfig()

	// Check for policy.yaml
	policyPath := filepath.Join(dir, "policy.yaml")
	if data, err := os.ReadFile(policyPath); err == nil {
		if err := yaml.Unmarshal(data, &config.Policy); err != nil {
			log.Printf("[WARN] Failed to parse policy.yaml: %v", err)
		}
	}

	// Check for secrets.yaml
	secretsPath := filepath.Join(dir, "secrets.yaml")
	if data, err := os.ReadFile(secretsPath); err == nil {
		var secretBindings []SecretBinding
		if err := yaml.Unmarshal(data, &secretBindings); err != nil {
			log.Printf("[WARN] Failed to parse secrets.yaml: %v", err)
		} else {
			config.Secrets = secretBindings
		}
	}

	// Check for monitoring.yaml
	monitoringPath := filepath.Join(dir, "monitoring.yaml")
	if data, err := os.ReadFile(monitoringPath); err == nil {
		if err := yaml.Unmarshal(data, &config.Monitoring); err != nil {
			log.Printf("[WARN] Failed to parse monitoring.yaml: %v", err)
		}
	}

	return config, nil
}

func (pm *PolicyManager) applyPolicy() {
	policy := pm.GetBPFPolicy()

	pm.mu.RLock()
	cb := pm.onPolicyUpdate
	mode := pm.config.Policy.Mode
	pm.mu.RUnlock()

	if cb != nil {
		cb(policy)
	}

	identity := pm.PodIdentityMode()
	log.Printf("[CONFIG] Policy applied: mode=%s podIdentity=%s", mode, identity)

	if identity != PodIdentityRequired {
		log.Printf("[CONFIG] Bindings without a pod selector are served to any caller that " +
			"can reach the socket and name the binary.")
		log.Printf("[CONFIG]   That is scoped to one pod only if the socket is. On a node-wide " +
			"agent set policy.podIdentity: required.")
	}
}

func (pm *PolicyManager) loadSecrets() {
	if pm.registry == nil {
		return
	}

	mode := pm.PodIdentityMode()
	built := make([]secrets.Binding, 0, len(pm.config.Secrets))

	for i, binding := range pm.config.Secrets {
		name := binding.Name
		if name == "" {
			name = fmt.Sprintf("secrets[%d]", i)
		}

		selector := secrets.Selector{
			Binary:     binding.Selector.Binary,
			Container:  binding.Selector.Container,
			Namespace:  binding.Selector.Namespace,
			Labels:     binding.Selector.Labels,
			CgroupPath: binding.Selector.CgroupPath,
		}

		out := secrets.Binding{Name: name, Selector: selector}

		for _, ref := range binding.SecretRefs {
			value, err := pm.resolveSecretValue(ref.Source)
			if err != nil {
				log.Printf("[WARN] Failed to resolve secret %s: %v", ref.Name, err)
				out.Unresolved = append(out.Unresolved, ref.Name)
				continue
			}
			out.Secrets = append(out.Secrets, secrets.Secret{Name: ref.Name, Value: value})
		}

		out.Rejected = rejectionFor(selector, mode)
		if out.Rejected != "" {
			log.Printf("[DENY] Binding %q will not be served: %s", name, out.Rejected)
		}

		if len(out.Unresolved) > 0 {
			log.Printf("[WARN] Binding %q has %d unresolved secret(s): %v",
				name, len(out.Unresolved), out.Unresolved)
			if len(out.Secrets) == 0 {
				log.Printf("[WARN]   every secret for %q failed to resolve, so it will "+
					"not be protected; requests will be refused in enforce mode", name)
			}
		}

		built = append(built, out)
	}

	pm.registry.Replace(built)
}

// rejectionFor reports why a binding cannot serve anyone under the active mode,
// or the empty string when it can.
//
// A rejected binding is kept rather than dropped. Dropping it would make the
// binary look unconfigured, and an unconfigured binary starts unprotected without
// complaint, which turns a configuration mistake into a silent loss of the
// guarantee the agent exists to provide.
func rejectionFor(s secrets.Selector, mode PodIdentityMode) string {
	if s.Binary == "" && !s.IsPodScoped() {
		return "the selector names neither a binary nor a pod, so it matches nothing"
	}

	// The root cgroup is every process on the host, so as an authorization
	// constraint it says nothing. Matching it would hand the binding to anything
	// that asks; refusing it silently would look like a selector that works. Say
	// so instead.
	if cleaned := strings.TrimSuffix(strings.TrimSpace(s.CgroupPath), "/"); s.CgroupPath != "" && cleaned == "" {
		return "cgroupPath selects the root cgroup, which every process on the host is under; " +
			"name the pod's own cgroup, or select on namespace and labels instead"
	}

	switch mode {
	case PodIdentityRequired:
		if !s.IsPodScoped() {
			return "policy.podIdentity is required, but this selector names no pod; " +
				"add namespace, labels, container or cgroupPath so the binding cannot be " +
				"claimed by any pod that reaches the socket"
		}

	case PodIdentityDisabled:
		if s.IsPodScoped() {
			return "policy.podIdentity is disabled, so pod selectors cannot be evaluated " +
				"and this binding would never match; set podIdentity to preferred or required"
		}
		if s.Binary == "" {
			return "policy.podIdentity is disabled, so only the binary selector is usable"
		}

	case PodIdentityPreferred:
		// Both shapes are servable: pod-scoped selectors are enforced when the
		// caller resolves, and binary-only bindings rely on the socket already
		// being scoped to one pod.
	}

	return ""
}

func (pm *PolicyManager) resolveSecretValue(source SecretSource) (string, error) {
	// Literal value (inline secret)
	if source.Value != "" {
		return source.Value, nil
	}

	// Environment variable reference
	if source.EnvRef != "" {
		value := os.Getenv(source.EnvRef)
		if value == "" {
			return "", fmt.Errorf("environment variable %s not set", source.EnvRef)
		}
		return value, nil
	}

	// File reference
	if source.FileRef != "" {
		data, err := os.ReadFile(source.FileRef)
		if err != nil {
			return "", fmt.Errorf("failed to read file %s: %w", source.FileRef, err)
		}
		return strings.TrimSpace(string(data)), nil
	}

	// Kubernetes secret reference (requires k8s client)
	if source.SecretKeyRef != nil {
		// For now, check if the secret is mounted as a file
		// This is the typical pattern when using K8s secrets as volume mounts
		mountPath := fmt.Sprintf("/var/run/secrets/kernelseal/%s/%s",
			source.SecretKeyRef.Name, source.SecretKeyRef.Key)
		if data, err := os.ReadFile(mountPath); err == nil {
			return strings.TrimSpace(string(data)), nil
		}

		// Alternative: read from standard k8s secret mount
		altPath := fmt.Sprintf("/var/run/secrets/kubernetes.io/serviceaccount/%s",
			source.SecretKeyRef.Key)
		if data, err := os.ReadFile(altPath); err == nil {
			return strings.TrimSpace(string(data)), nil
		}

		return "", fmt.Errorf("kubernetes secret %s/%s not found",
			source.SecretKeyRef.Name, source.SecretKeyRef.Key)
	}

	// Vault reference (future implementation)
	if source.VaultRef != nil {
		return "", fmt.Errorf("vault integration not yet implemented")
	}

	return "", fmt.Errorf("no valid secret source specified")
}

// GetBPFPolicy converts the policy spec to BPF policy config
func (pm *PolicyManager) GetBPFPolicy() types.PolicyConfig {
	pm.mu.RLock()
	defer pm.mu.RUnlock()

	policy := types.PolicyConfig{
		AllowSelfRead: boolToUint8(pm.config.Policy.AllowSelfRead),
		BlockEnviron:  boolToUint8(pm.config.Policy.BlockEnviron),
		BlockMem:      boolToUint8(pm.config.Policy.BlockMem),
		BlockMaps:     boolToUint8(pm.config.Policy.BlockMaps),
		BlockPtrace:   boolToUint8(pm.config.Policy.BlockPtrace),
		AuditAll:      boolToUint8(pm.config.Policy.AuditAll),
	}

	switch strings.ToLower(pm.config.Policy.Mode) {
	case "disabled":
		policy.EnforceMode = types.ModeDisabled
	case "audit":
		policy.EnforceMode = types.ModeAudit
	case "enforce":
		policy.EnforceMode = types.ModeEnforce
	default:
		policy.EnforceMode = types.ModeEnforce
	}

	return policy
}

// GetConfig returns the current configuration
func (pm *PolicyManager) GetConfig() *KernelSealConfig {
	pm.mu.RLock()
	defer pm.mu.RUnlock()
	return pm.config
}

// PodIdentityMode reports how callers must be identified. An unparseable value
// is reported as required, matching parsePodIdentity: a typo in the setting that
// governs authorization must fail closed.
func (pm *PolicyManager) PodIdentityMode() PodIdentityMode {
	pm.mu.RLock()
	configured := pm.config.Policy.PodIdentity
	pm.mu.RUnlock()

	mode, err := parsePodIdentity(configured)
	if err != nil {
		log.Printf("[WARN] %v; refusing callers that cannot be attributed to a pod", err)
	}
	return mode
}

// SecretsFor returns the secrets that apply to a caller. Secret delivery itself
// happens in internal/server; this is used for reporting and tests.
func (pm *PolicyManager) SecretsFor(binaryName string, caller secrets.Caller) secrets.Match {
	if pm.registry == nil {
		return secrets.Match{}
	}
	return pm.registry.Lookup(binaryName, caller)
}

// GetTargetBinaries returns every binary name that has secrets bound to it
// This is used to configure kernel-side binary filtering
func (pm *PolicyManager) GetTargetBinaries() []string {
	pm.mu.RLock()
	defer pm.mu.RUnlock()

	binaries := make([]string, 0)
	seen := make(map[string]bool)

	for _, binding := range pm.config.Secrets {
		if binding.Selector.Binary != "" && !seen[binding.Selector.Binary] {
			binaries = append(binaries, binding.Selector.Binary)
			seen[binding.Selector.Binary] = true
		}
	}

	return binaries
}

// IsKernelBinaryFilterEnabled returns whether kernel-side binary filtering is enabled
func (pm *PolicyManager) IsKernelBinaryFilterEnabled() bool {
	pm.mu.RLock()
	defer pm.mu.RUnlock()
	return pm.config.Policy.KernelBinaryFilter
}

func boolToUint8(b bool) uint8 {
	if b {
		return 1
	}
	return 0
}

// ApplyFileProtectionPolicy is a legacy function for backwards compatibility
func ApplyFileProtectionPolicy() {
	log.Println("[INFO] [KernelSeal] File protection policy initialized (see BPF manager for LSM hooks)")
}
