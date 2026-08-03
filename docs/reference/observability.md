# Observability

The agent serves three endpoints on `monitoring.metricsPort`.

| Path | Purpose |
|---|---|
| `/metrics` | Prometheus exposition |
| `/healthz` | Liveness. Succeeds whenever the process is running |
| `/ready` | Readiness. Fails when policy requires BPF-LSM but it is not loaded |

Liveness deliberately does not depend on readiness, so a degraded agent is not
restarted in a loop.

## Metrics

| Metric | Meaning |
|---|---|
| `kernelseal_exec_events_total` | Process executions observed |
| `kernelseal_secrets_issued_total` | Secrets released to processes |
| `kernelseal_secrets_denied_total` | Secret requests refused |
| `kernelseal_access_blocked_total` | Accesses blocked by the LSM |
| `kernelseal_access_audit_total` | Accesses audited but allowed |
| `kernelseal_protected_pids` | Currently protected processes |
| `kernelseal_pods_watched` | Size of the pod cache |
| `kernelseal_lsm_loaded` | 1 when the LSM programs are attached |

Two of these deserve alerts:

**`kernelseal_protected_pids` dropping below the expected count** is the only
indication that an agent restart ended protection for running workloads. The BPF
maps do not survive the agent process, so an upgrade, OOM kill or eviction leaves
already-running protected processes unprotected, with nothing in their own logs to
say so.

**`kernelseal_pods_watched` at zero on a node-wide agent** means every request is
being refused, which is otherwise hard to distinguish from an agent with nothing
to do.

## Logging

`monitoring.logLevel` accepts `debug`, `info`, `warn` or `error` and defaults to
`info`. Per-exec tracing sits at `debug`, because a host that runs a configured
binary in a loop otherwise produces a continuous stream of `[EXEC]` lines that
buries everything else. Secret delivery and LSM decisions are logged at `info` and
above, so the default level shows what matters.

```
[START] Starting KernelSeal - Secret Protection System
   Version: v1.2.0
[CONFIG] Loaded KernelSeal configuration from /etc/kernelseal/config.yaml
[REGISTER] 2 secrets registered for binary: myapp
[OK] Exec monitor BPF programs loaded and attached
[FILTER] Kernel-side filtering enabled for 1 binaries: [myapp]
[OK] LSM BPF programs loaded and attached
[CONFIG] Policy configured: mode=enforce, environ=true, mem=true, ptrace=true
[SOCKET] Listening on /run/kernelseal/kernelseal.sock (mode 0660)
[METRICS] Serving /metrics, /healthz and /ready on [::]:9090

[PROTECT] pid=5678 marked protected before release (pid=5678 uid=1000 ...)
[ISSUE] Released 2 secrets to "myapp" [API_KEY DB_PASSWORD] (pid=5678 ...)
[LSM BLOCKED] PID=9999 (cat) uid=0 attempted environ access to PID=5678
```

!!! tip "The most useful line in the log"

    `[REGISTER] N secrets registered for binary: ...` with N of zero means the
    sources did not resolve. The shim will be told the binary has nothing bound to
    it and the process runs unprotected, which looks identical to enforcement
    being broken. Check this first.

Denials name the calling pod's namespace, name and UID rather than only a PID,
which is usually gone by the time anyone reads the log.

## Verifying protection is actually on

```bash
# Blocked access attempts
curl -s localhost:9090/metrics | grep kernelseal_access_blocked_total

# Currently protected processes
curl -s localhost:9090/metrics | grep kernelseal_protected_pids

# Enforcement is available
curl -s localhost:9090/metrics | grep kernelseal_lsm_loaded
```

Note that `kubectl exec` into a pod starts a **new** process, which is not the
protected one, so its own environment will not contain the secrets. That is
expected and is not evidence that delivery failed.
