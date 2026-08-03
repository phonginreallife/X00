# Configuration

```yaml
version: v1

policy:
  mode: enforce            # disabled, audit, enforce
  podIdentity: preferred   # required, preferred, disabled
  blockEnviron: true
  blockMem: true
  blockMaps: false
  blockPtrace: true
  allowSelfRead: true
  auditAll: false
  kernelBinaryFilter: true

secrets:
  - name: myapp-secrets
    selector:
      binary: "myapp"
      namespace: "payments"
      labels:
        app: checkout
    secretRefs:
      - name: API_KEY
        source:
          fileRef: "/run/secrets/api-key"

monitoring:
  enabled: true
  metricsPort: 9090
  logLevel: info
```

A binary listed under `secrets` only receives them if it is started through the
shim. Adding a binding does not affect processes launched any other way.

## Policy

| Setting | Effect |
|---|---|
| `mode` | `disabled` does nothing, `audit` logs would-be denials but allows them, `enforce` logs and denies |
| `podIdentity` | How strictly callers must be attributable to a pod. See [Authorization](../concepts/authorization.md) |
| `blockEnviron` | Refuse reads of `/proc/<pid>/environ` |
| `blockMem` | Refuse reads of `/proc/<pid>/mem` |
| `blockMaps` | Refuse reads of `/proc/<pid>/maps`. Some debugging tools need this |
| `blockPtrace` | Refuse debugger attach |
| `allowSelfRead` | Let a process read its own `/proc` files |
| `auditAll` | Emit events for allowed accesses too, not only denied ones |
| `kernelBinaryFilter` | Observe only configured binaries instead of every exec on the host |

`kernelBinaryFilter: true` is recommended in production: a host that runs a
configured binary in a loop otherwise generates continuous ring-buffer traffic for
processes nobody cares about.

## Selectors

| Selector | Authorizes? | Notes |
|---|---|---|
| `namespace` | Yes | Derived from the caller's cgroup |
| `labels` | Yes | Mutable; see the caveat in [Authorization](../concepts/authorization.md) |
| `container` | Yes | Container name within the pod |
| `cgroupPath` | Yes | Refuses when the agent has its own cgroup namespace. `/` is rejected at load |
| `binary` | **No** | Narrows which of a pod's bindings apply. Not an identity claim |

A binding the policy cannot serve as written is kept and marked rejected rather
than dropped. A dropped binding makes its binary look unconfigured, and an
unconfigured binary starts unprotected without complaint, which turns a
configuration mistake into a silent loss of the guarantee.

## Secret sources

```yaml
secretRefs:
  # Literal value, useful for testing
  - name: TOKEN
    source:
      value: "inline-value"

  # From the agent's own environment
  - name: DB_PASSWORD
    source:
      envRef: "SOURCE_DB_PASSWORD"

  # From a file, for example written by a Vault agent sidecar
  - name: API_KEY
    source:
      fileRef: "/vault/secrets/api-key"

  # From a Kubernetes Secret mounted into the agent container
  - name: JWT_SECRET
    source:
      secretKeyRef:
        name: my-secret
        key: jwt
```

`secretKeyRef` reads the value from a mounted path rather than calling the
Kubernetes API. Mount the Secret into the agent container at
`/var/run/secrets/kernelseal/<name>/<key>`.

`fileRef` is the general-purpose escape hatch: it reads whatever another process
wrote, which covers most secret backends including Vault agent sidecars.

!!! info "`vaultRef` is parsed but not implemented"

    It is accepted by the config parser and returns an error at resolution time.
    Use `fileRef` against a Vault agent sidecar's output in the meantime. Tracked
    on the [roadmap](https://github.com/phonginreallife/kernelseal/issues/16).

## Fail-closed behavior

Secrets are withheld when protection was requested but is unavailable, and a
binary whose configured secrets **all** fail to resolve is refused rather than
started unprotected. A typo in a `fileRef` cannot quietly reduce an application to
no protection.
