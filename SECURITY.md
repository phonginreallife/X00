# Security Policy

## Table of Contents

- [Supported Versions](#supported-versions)
- [Reporting a Vulnerability](#reporting-a-vulnerability)
- [Threat Model](#threat-model)
- [Security Architecture](#security-architecture)
- [Security Controls](#security-controls)
- [Deployment Security](#deployment-security)
- [Supply Chain Security](#supply-chain-security)
- [Incident Response](#incident-response)
- [Hardening Checklist](#hardening-checklist)
- [License](#license)

## Supported Versions

| Version | Supported | Notes |
|---------|-----------|-------|
| 1.x.x   | Yes | Current stable release |

Versioning restarted at 1.0.0 with the first public release. Tags published before
it were removed rather than left to be found: in each of them the protection
guarantee was either incomplete or actively broken, so none should be used.

We recommend always running the latest stable version.

## Reporting a Vulnerability

We take security seriously. If you discover a security vulnerability in KernelSeal, please report it responsibly.

### How to Report

1. **DO NOT** create a public GitHub issue for security vulnerabilities
2. Use GitHub's private vulnerability reporting: [Report a vulnerability](../../security/advisories/new)
3. Or email: phonginreallife@gmail.com

### Required Information

Please include:

| Field | Description |
|-------|-------------|
| **Summary** | Brief description of the vulnerability |
| **Severity** | Your assessment (Critical/High/Medium/Low) |
| **Affected Components** | Which parts of KernelSeal are affected |
| **Steps to Reproduce** | Detailed reproduction steps |
| **Impact** | What an attacker could achieve |
| **Proof of Concept** | Code, logs, or screenshots if available |
| **Suggested Fix** | Optional remediation suggestions |

### Response Timeline

| Phase | Timeline |
|-------|----------|
| Acknowledgment | Within 48 hours |
| Initial Assessment | Within 7 days |
| Status Update | Every 7 days until resolved |

**Resolution by Severity:**

| Severity | CVSS Score | Resolution Target |
|----------|------------|-------------------|
| Critical | 9.0 - 10.0 | 7 days |
| High | 7.0 - 8.9 | 14 days |
| Medium | 4.0 - 6.9 | 30 days |
| Low | 0.1 - 3.9 | 60 days |

### Scope

**In Scope:**

- KernelSeal agent binary and dependencies
- The `kernelseal-exec` shim and the socket protocol between them
- BPF programs (`exec_monitor.bpf.c`, `lsm_file_protect.bpf.c`)
- Secret delivery and the protect-before-release ordering
- Policy enforcement bypass, including BPF/Go struct layout mismatches
- Container/VM escape via KernelSeal
- Privilege escalation
- Information disclosure
- Authentication/authorization bypass

**Out of Scope:**

- Vulnerabilities requiring physical access
- Social engineering attacks
- Denial of service without security impact
- Issues in unsupported versions
- Third-party dependencies without working exploit

## Threat Model

### Assets Protected

1. **Application Secrets** - API keys, database credentials, tokens
2. **Process Memory** - Runtime secret storage
3. **Kernel Integrity** - BPF program execution environment

### Threat Actors

| Actor | Capability | Motivation |
|-------|------------|------------|
| Compromised Container | Root access within container | Steal secrets from other processes |
| Malicious Insider | Cluster access | Exfiltrate sensitive data |
| Supply Chain Attacker | Inject malicious code | Backdoor deployments |
| Adjacent Pod | Network access | Lateral movement |

### Attack Vectors

```
┌─────────────────────────────────────────────────────────────────┐
│                     Attack Surface                              │
├─────────────────────────────────────────────────────────────────┤
│                                                                 │
│  ┌──────────────┐    ┌──────────────┐    ┌──────────────┐       │
│  │ /proc/*/     │    │ ptrace()     │    │ Environment  │       │
│  │ environ,mem  │    │ syscall      │    │ Variables    │       │
│  └──────┬───────┘    └──────┬───────┘    └──────┬───────┘       │
│         │                   │                   │               │
│         └─────────┬─────────┴─────────┬─────────┘               │
│                   │                   │                         │
│                   ▼                   ▼                         │
│         ┌─────────────────────────────────────┐                 │
│         │         BPF-LSM Protection          │                 │
│         │   (Kernel-level Access Control)     │                 │
│         └─────────────────────────────────────┘                 │
│                                                                 │
└─────────────────────────────────────────────────────────────────┘
```

### Mitigations by Attack Vector

| Attack Vector | Protection | Implementation |
|---------------|------------|----------------|
| `/proc/*/environ` read | BPF-LSM `file_open` hook | Blocks unauthorized readers |
| `/proc/*/mem` read | BPF-LSM `file_open` hook | Blocks memory inspection |
| `/proc/*/maps` read | BPF-LSM `file_open` hook | Optional, via `blockMaps` |
| `ptrace` attach | BPF-LSM `ptrace_access_check` | Prevents debugger attach |
| Secrets on disk | Socket delivery | Nothing is written to a filesystem |
| Unprotected startup window | Protect-before-release ordering | See below |
| Enforcement unavailable | Fail closed | Secrets withheld in enforce mode |
| Container escape | Kernel verification | BPF verifier guarantees |

### Secret Delivery and the Startup Window

Secrets are delivered by `kernelseal-exec`, which connects to the agent, receives
the environment, and then `execve`s the target binary. The agent marks the
caller's PID protected **before** writing the response. Because `execve` preserves
the PID, the application starts already protected; there is no interval during
which a process holds secrets that can still be read out of `/proc`.

Two properties follow:

- The caller is identified with `SO_PEERCRED`, which the kernel populates. A
  client cannot claim to be a different PID or UID.
- The PID is paired with its start time from `/proc/<pid>/stat` and re-checked
  after protection is applied, so a caller that exits mid-handshake cannot cause
  protection to be attached to a recycled PID.

### Authorization Boundary

**Socket reachability is the authorization boundary.** The agent cannot verify
which binary the shim is about to execute: at handshake time `/proc/<pid>/exe`
still points at the shim itself, because the `execve` has not happened yet. The
binary name in the request therefore selects *which* secrets apply; it is not an
identity claim.

The practical consequence is that any process able to open the socket can request
the secrets bound to any configured binary by naming it. This requires no
subterfuge: the request is a JSON object containing a string, so a compromised
container does not need to install the binary, rename anything, or execute
anything. Writing to the socket is sufficient.

```bash
# Any process that can reach the socket, without the shim involved at all
echo '{"binary":"/usr/bin/node"}' | nc -U /run/kernelseal/kernelseal.sock
```

With a node-wide `hostPath` socket, that means **any pod on the node that mounts
`/run/kernelseal` can obtain every secret in that node's configuration.** On nodes
dedicated to a single application this is self-only and harmless. On shared nodes
it is cross-tenant secret disclosure, and the sidecar pattern with a pod-scoped
`emptyDir` socket is the correct deployment.

Closing this properly requires authorizing on something the container cannot
forge. The caller's cgroup qualifies — it is set by the kernel and maps to a pod —
so a future release resolves the peer's cgroup to a pod and matches bindings on
namespace and labels, leaving the binary name to select only *within* what that pod
is entitled to. Tracked for 1.1.0. Until then, scope the socket:

- Mount the socket volume only into pods that should receive those secrets. Use a
  pod-scoped `emptyDir` rather than a node-wide `hostPath` when a DaemonSet is not
  required.
- Prefer one binding set per pod over a single node-wide configuration listing
  every application's secrets.
- Keep the socket mode at the default `0660` and use `fsGroup` to share it, rather
  than widening it to `0666`.

### Trust Boundary

Inside the trust boundary:

- The agent, which holds every resolved secret value in memory.
- The `kernelseal-exec` shim, which holds plaintext secrets between reading the
  socket and calling `execve`.
- The BPF programs and their maps.

Outside the trust boundary:

- The application itself. It receives its own secrets and nothing else.
- Every other process on the host, including root, which the LSM hooks refuse.

### Agent Restarts End Protection Silently

**Restarting the agent leaves every already-running protected process
unprotected, permanently, with nothing logged.**

Protection is installed once, during the shim's handshake, immediately before
`execve`. The protected PID set lives in a BPF map owned by the agent process, and
the LSM programs are attached for that process's lifetime. When the agent exits —
upgrade, `rollout restart`, OOM kill, eviction, node pressure — the map and the
attachment go with it. The replacement agent starts with an empty map.

Applications that are already running never handshake again, because their `execve`
is long past. Their `/proc/<pid>/environ` becomes readable again and no audit event
is emitted, because from the new agent's point of view those processes were never
protected. Nothing in the logs marks the transition.

This affects the DaemonSet and sidecar deployments equally. A sidecar container
restart leaves the application container running, so the same gap opens; native
sidecars (Kubernetes 1.29+ `initContainers` with `restartPolicy: Always`) behave
the same way.

Until this is fixed, treat an agent restart as an event that requires restarting
the workloads it protects:

```bash
kubectl rollout restart ds/kernelseal -n kernelseal-system
kubectl rollout restart deploy/<your-app> -n <your-namespace>   # agent first, then app
```

- Set `updateStrategy: OnDelete` on the DaemonSet so agent restarts are deliberate
  rather than triggered by any manifest change.
- Alert on `kernelseal_protected_pids` falling below the number of protected
  workloads on that node. It is the only signal this has happened.

The fix is to pin the BPF links and the protected-PID map to bpffs so both survive
the agent process, which removes the gap during the restart as well as after it.
Tracked for 1.1.0.

### Residual Risks

| Risk | Impact | Notes |
|------|--------|-------|
| Agent restart | Running protected processes silently lose protection for the rest of their lives | Nothing is pinned to bpffs yet; restart the workload after the agent |
| Same-pod process requests another binary's secrets | Reads secrets bound to any configured binary | Socket reachability is the boundary; scope volumes per pod |
| Child processes inherit the environment | Children hold secrets but are not themselves protected | Protection is per-PID |
| Secrets remain in the agent's heap | Values may persist until garbage collected | Go strings cannot be reliably zeroed |
| BPF-LSM unavailable | No enforcement possible | Enforce mode fails closed and reports `not ready` |
| Compromised agent or shim image | Full disclosure | Both are inside the trust boundary; verify image integrity |

## Security Architecture

### Defense in Depth

```
┌─────────────────────────────────────────────────────────────────┐
│ Layer 1: Kubernetes Security                                    │
│ - RBAC, Network Policies, Pod Security Standards                │
├─────────────────────────────────────────────────────────────────┤
│ Layer 2: Container Security                                     │
│ - Read-only filesystem, Dropped capabilities, Seccomp           │
├─────────────────────────────────────────────────────────────────┤
│ Layer 3: KernelSeal Application                                 │
│ - Policy enforcement, Binary filtering, Audit logging           │
├─────────────────────────────────────────────────────────────────┤
│ Layer 4: BPF-LSM Kernel Protection                              │
│ - Mandatory access control, Syscall interception                │
└─────────────────────────────────────────────────────────────────┘
```

### BPF Program Security

KernelSeal's BPF programs run in kernel space with strict safety guarantees:

| Control | Description |
|---------|-------------|
| **Verifier Protection** | All programs pass Linux kernel BPF verifier |
| **Bounded Execution** | No unbounded loops, guaranteed termination |
| **Memory Safety** | All memory accesses bounds-checked |
| **Type Safety** | BTF (BPF Type Format) ensures type correctness |
| **Minimal Hooks** | Only essential syscalls are intercepted |
| **ABI Pinning** | Struct layouts are asserted against the C header in CI |

#### Why the ABI is a security control

The policy the kernel enforces is written from user space into a BPF map as a raw
struct. If the Go struct and the C struct disagree on field order, the map update
still succeeds, because both are the same size; the kernel simply reads each
setting from the wrong byte. The result is a policy that silently differs from the
configured one, with no error anywhere.

This is not hypothetical. An earlier revision of
`bpf/lsm_file_protect.bpf.c` declared its own copy of the policy struct that was
missing two fields, which meant `blockPtrace: true` had no effect and the setting
that actually enabled ptrace blocking was `blockMaps`. Both sides now include
`bpf/kernelseal_common.h`, and `make abi-check` fails the build if the layouts
drift or if any BPF source redeclares a shared struct.

Secret lifecycle:

1. At rest - held in the source (Kubernetes Secret, file, or the agent's own
   environment), never copied to a container filesystem.
2. In transit - passed over a unix socket with mode `0660`. No temporary file,
   no tmpfs mount, no `/proc` write.
3. In use - present in the target process's environment, with reads of
   `/proc/<pid>/environ`, `/proc/<pid>/mem` and `ptrace` refused by BPF-LSM.
4. Disposal - the kernel reclaims the process's memory on exit, and the
   `sched_process_exit` tracepoint plus a periodic reconciler remove the PID from
   the protected set so a recycled PID does not inherit protection.

### RBAC Configuration

```yaml
apiVersion: rbac.authorization.k8s.io/v1
kind: Role
metadata:
  name: kernelseal-role
rules:
  - apiGroups: [""]
    resources: ["secrets"]
    verbs: ["get"]                          # Read-only secret access
    resourceNames: ["app-secrets"]          # Specific secrets only
---
apiVersion: rbac.authorization.k8s.io/v1
kind: RoleBinding
metadata:
  name: kernelseal-binding
subjects:
  - kind: ServiceAccount
    name: kernelseal-sa
roleRef:
  kind: Role
  name: kernelseal-role
  apiGroup: rbac.authorization.k8s.io
```

### Network Policy

```yaml
apiVersion: networking.k8s.io/v1
kind: NetworkPolicy
metadata:
  name: kernelseal-network
spec:
  podSelector:
    matchLabels:
      app: kernelseal
  policyTypes:
    - Ingress
    - Egress
  ingress: []                               # No inbound traffic
  egress:
    - to:
        - namespaceSelector:
            matchLabels:
              name: vault                   # Only Vault namespace
      ports:
        - port: 8200
          protocol: TCP
```

### Production Policy Configuration

```yaml
version: v1
policy:
  mode: enforce                             # Always enforce in production
  blockEnviron: true                        # Block /proc/*/environ
  blockMem: true                            # Block /proc/*/mem
  blockMaps: true                           # Block /proc/*/maps
  blockPtrace: true                         # Block ptrace attach
  allowSelfRead: true                       # Allow process self-inspection
  auditAll: true                            # Log all access attempts
  kernelBinaryFilter: true                  # Efficient kernel-side filtering

secrets:
  - name: myapp-secrets
    selector:
      binary: "myapp"                       # Matches what the shim will exec
    secretRefs:
      - name: DB_PASSWORD
        source:
          # Written by a Vault agent sidecar into the KernelSeal container.
          # Direct vaultRef is not yet implemented.
          fileRef: /vault/secrets/db-password
```

Note that `auditAll: true` logs every allowed access to a protected process as
well as every denial. It is useful while establishing a baseline, but on a busy
node it is a significant volume of events; leave it off unless you are actively
investigating.

## Supply Chain Security

### Build Verification

| Check | Tool | CI Integration |
|-------|------|----------------|
| Dependency vulnerabilities | govulncheck | Every PR |
| Container vulnerabilities | Trivy | Every build |
| Code security issues | gosec, CodeQL | Every PR |
| Secret detection | Gitleaks, TruffleHog | Every commit |
| Dockerfile best practices | Hadolint | Every PR |

### Verifying a Release

Release images and artifacts are signed with [cosign](https://github.com/sigstore/cosign)
keyless signing. There is no public key to distribute: the signature carries a
short-lived Sigstore certificate proving which GitHub workflow, in which
repository, at which tag produced the artifact. That is what you verify against,
so both flags below are required. `cosign verify` without them accepts a
signature from *any* identity, which is the most common way this check is run
and gets nothing out of it.

```bash
IMAGE=ghcr.io/phonginreallife/kernelseal
VERSION=v1.0.0
IDENTITY="https://github.com/phonginreallife/kernelseal/.github/workflows/release.yaml@refs/tags/${VERSION}"

cosign verify \
  --certificate-identity "$IDENTITY" \
  --certificate-oidc-issuer https://token.actions.githubusercontent.com \
  "${IMAGE}:${VERSION}"
```

Signatures are attached to the image digest rather than the tag, because a tag
can be moved to a different image afterwards while a digest cannot. To pin what
you verified, resolve the digest and deploy that:

```bash
crane digest "${IMAGE}:${VERSION}"    # sha256:...
```

The release tarballs are covered by a signature over `checksums.txt`, since that
file contains their SHA-256 hashes:

```bash
cosign verify-blob \
  --bundle checksums.txt.cosign.bundle \
  --certificate-identity "$IDENTITY" \
  --certificate-oidc-issuer https://token.actions.githubusercontent.com \
  checksums.txt

sha256sum -c checksums.txt
```

### SBOM

Every release publishes an SPDX SBOM, both as a release asset
(`kernelseal-<version>-sbom.spdx.json`) and as a cosign attestation on the
image, so a cluster that only knows the digest can still recover it:

```bash
cosign verify-attestation \
  --type spdxjson \
  --certificate-identity "$IDENTITY" \
  --certificate-oidc-issuer https://token.actions.githubusercontent.com \
  "${IMAGE}:${VERSION}" | jq -r '.payload' | base64 -d | jq '.predicate' > sbom.json

grype sbom:sbom.json
```

### Dependency Policy

- All dependencies pinned to specific versions
- Dependabot enabled for automated updates
- Security updates applied within 7 days
- Major version updates reviewed manually

## Incident Response

### Detection

KernelSeal provides audit logs for security monitoring:

```bash
# Blocked access attempts
kubectl logs -l app=kernelseal | grep "\[LSM BLOCKED\]"

# Accesses observed but allowed (audit mode, or auditAll)
kubectl logs -l app=kernelseal | grep "\[LSM AUDIT\]"

# Refused secret requests, e.g. protection unavailable or a recycled PID
kubectl logs -l app=kernelseal | grep "\[DENY\]"

# Current counters
kubectl exec -it <kernelseal-pod> -- \
  wget -qO- localhost:9090/metrics | grep -E "kernelseal_(access|secrets)"
```

### Response Playbook

**1. Suspected Secret Compromise**

```bash
# Immediate: Rotate affected secrets
vault write -force secret/data/myapp/db password=$(openssl rand -base64 32)

# Investigate: Check audit logs
kubectl logs -l app=kernelseal --since=1h | grep -E "(BLOCK|AUDIT)"

# Verify: the application received the rotated values. Note that exec'ing into
# the pod starts a new process, which is not the protected one, so its own
# environment will not contain the secrets.
kubectl logs -l app=kernelseal | grep "\[ISSUE\]"   # names only, never values
```

**2. Unauthorized Access Attempt**

```bash
# Identify source
kubectl logs -l app=kernelseal | grep "PID=<suspicious_pid>"

# Check process details
kubectl exec -it <pod> -- cat /proc/<pid>/comm
kubectl exec -it <pod> -- cat /proc/<pid>/cmdline

# Escalate if needed
# - Container may be compromised
# - Consider pod termination and forensics
```

### Alerting Integration

```yaml
groups:
  - name: kernelseal
    rules:
      # Something is repeatedly trying to read protected process state.
      - alert: SecretAccessBlocked
        expr: increase(kernelseal_access_blocked_total[5m]) > 10
        for: 1m
        labels:
          severity: warning
        annotations:
          summary: "Multiple secret access attempts blocked"
          description: "{{ $value }} access attempts blocked in the last 5 minutes"

      # Enforcement is not actually active. In enforce mode this also means
      # secret requests are being refused, so applications will fail to start.
      - alert: KernelSealLSMNotLoaded
        expr: kernelseal_lsm_loaded == 0
        for: 5m
        labels:
          severity: critical
        annotations:
          summary: "KernelSeal is not enforcing protection"
          description: "BPF-LSM is not loaded; check that the kernel was booted with bpf in its lsm= list"

      # Applications are asking for secrets and not getting them.
      - alert: KernelSealSecretsDenied
        expr: increase(kernelseal_secrets_denied_total[5m]) > 0
        for: 1m
        labels:
          severity: warning
        annotations:
          summary: "KernelSeal refused a secret request"
          description: "{{ $value }} requests refused in the last 5 minutes; check the agent logs for [DENY]"
```

## Hardening Checklist

### Pre-Deployment

- [ ] Confirm the kernel lists `bpf` in `/sys/kernel/security/lsm`, which
      `deploy/kernelseal-probe.yaml` checks per node
- [ ] Verify the image signature with both `--certificate-identity` and
      `--certificate-oidc-issuer`, and deploy the digest you verified
- [ ] Review and customize policy configuration
- [ ] Configure the binary allowlist for your applications
- [ ] Set up secret source (Vault, K8s Secrets, etc.)
- [ ] Scope the socket volume to the pod that should receive those secrets
- [ ] Wrap each application entrypoint with `kernelseal-exec`
- [ ] Leave the shim's `-on-error` at its `fail` default so an application cannot
      start unprotected
- [ ] Configure RBAC with least privilege
- [ ] Set up network policies
- [ ] Configure alerting for security events

### Runtime

- [ ] KernelSeal running in `enforce` mode
- [ ] `kernelseal_lsm_loaded` reporting 1
- [ ] Readiness probe passing, which confirms enforcement is available
- [ ] Read-only root filesystem enabled on application containers
- [ ] Capabilities limited to `SYS_ADMIN`, `BPF`, `PERFMON`, `SYS_RESOURCE`
- [ ] Socket mode left at `0660` with a shared `fsGroup`
- [ ] Resource limits configured
- [ ] Secrets rotated on schedule
- [ ] `updateStrategy: OnDelete` on the DaemonSet, so agent restarts are deliberate
- [ ] A documented procedure to restart protected workloads after any agent
      restart, since protection does not survive it

### Monitoring

- [ ] Audit logs forwarded to SIEM
- [ ] Alerts configured for blocked access
- [ ] Alert on `kernelseal_protected_pids` dropping below the expected count,
      which is the only indication that an agent restart ended protection
- [ ] Regular review of access patterns
- [ ] Vulnerability scanning in CI/CD
- [ ] Dependency updates monitored

### Periodic Review

- [ ] Quarterly: Review and update policies
- [ ] Monthly: Review audit logs for anomalies
- [ ] Weekly: Apply security updates
- [ ] On change: Re-validate security controls

## Security Scanning

This repository includes automated security scanning:

| Tool | Purpose | Frequency |
|------|---------|-----------|
| **gosec** | Go security static analysis | Every PR |
| **govulncheck** | Go vulnerability detection | Every PR |
| **Trivy** | Container vulnerability scanning | Every build |
| **CodeQL** | Semantic code analysis | Every PR |
| **Gitleaks** | Secret detection | Every commit |
| **Hadolint** | Dockerfile linting | Every PR |
| **Dependabot** | Dependency vulnerability alerts | Daily |

## License

KernelSeal BPF programs are dual-licensed under **GPL-2.0 OR BSD-3-Clause** as required for BPF programs.

Userspace components are licensed under **Apache-2.0**.

---

*Last updated: January 2026*
