# Authorization

**The binary name in a request is a claim, not an identity.** The agent cannot
verify which binary the shim is about to execute: at handshake time
`/proc/<pid>/exe` still points at the shim, because the `execve` has not happened
yet. The binary name selects *which* secrets apply; it never establishes *who is
asking*.

## What it used to be

Before 1.2.0 that claim was the only authorization input, so any process able to
open the socket could request the secrets bound to any configured binary by naming
it. This required no subterfuge. The request is a JSON object containing a string,
so a compromised container did not need to install the binary, rename anything, or
execute anything:

```bash
echo '{"binary":"/usr/bin/node"}' | nc -U /run/kernelseal/kernelseal.sock
```

With a node-wide `hostPath` socket, any pod on the node that mounted
`/run/kernelseal` could obtain every secret in that node's configuration. On a
dedicated node that was self-only; on a shared one it was cross-tenant secret
disclosure.

## What authorizes a caller now

Since 1.2.0 the agent authorizes on the caller's **cgroup**, which the kernel sets
when the container is created and which a process cannot change from inside it.

The agent reads the peer's cgroup path from procfs, resolves the pod UID out of
it, and looks that UID up against the pods scheduled on its own node. Bindings
then select on `namespace`, `labels`, `container` and `cgroupPath`, and the binary
name only narrows what that pod is already entitled to.

```yaml
secrets:
  - name: checkout-db
    selector:
      binary: node            # narrows which of this pod's bindings apply
      namespace: payments     # authorizes: derived from the caller's cgroup
      labels:
        app: checkout
```

The `nc` command above now fails on a node-wide agent. `nc` runs in some pod's
cgroup, that pod does not match the selector, and the request is refused and
audited whatever it calls itself.

Refusing a caller on identity does not depend on `policy.mode`. Audit mode weakens
what the kernel blocks; it does not make one pod's secrets available to another.

## `policy.podIdentity`

How strictly this applies depends on who can reach the socket, which is a
deployment question rather than a preference.

| Mode | Behavior | Use when |
|---|---|---|
| `required` | Refuses any caller it cannot attribute to a pod, and rejects bindings that name no pod | A node-wide DaemonSet. Every pod on the node can open the socket, so the socket is not a boundary |
| `preferred` (default) | Enforces pod selectors when present; still serves bindings that carry none | A per-pod sidecar. The `emptyDir` socket is reachable only from inside one pod |
| `disabled` | Does not identify callers at all | Only where the pre-1.2.0 behavior is needed deliberately |

`deploy/manifests/daemonset.yaml` ships `required`;
`deploy/kernelseal-sidecar.yaml` ships `preferred`. In `required` mode the agent
refuses to start if it cannot watch pods, rather than running as a pod that looks
healthy while refusing every request.

An unrecognized `podIdentity` value is treated as `required`, so a typo in the
setting that governs authorization cannot quietly widen it.

## What this does not close

- **Within a single pod, the binary name is still only a claim.** Any process in a
  pod can request any binding that pod is entitled to. Pod identity separates
  tenants, not processes inside one tenant.
- **A binding with no pod selector is served to any caller** under `preferred`.
  That is correct only if the socket is genuinely pod-scoped. On a node-wide
  agent, use `required`; nothing else in the configuration will catch the mistake
  for you.
- **Pod labels are mutable.** Anyone who can patch a pod's labels, or create a pod
  carrying them, can make it match a `labels` selector. Bind on `namespace` as
  well, and treat label-write access as equivalent to access to the secrets those
  labels select.
- **The pod cache can be stale.** It is a list-watch against the API server, so a
  label change takes effect when the watch delivers it. A caller the agent cannot
  attribute to a known pod is refused in `required` mode rather than served.

## Cgroup namespaces and `cgroupPath`

The kernel renders `/proc/<pid>/cgroup` relative to the *reading* process's cgroup
namespace. An agent with its own namespace, the default for a container on a
cgroup v2 host, therefore sees other pods anchored to itself:

```
# Agent in its own cgroup namespace, reading another container's cgroup
0::/../docker-7f2a660030ce....scope

# Same read, agent in the host's cgroup namespace
0::/system.slice/docker-7f2a660030ce....scope
```

Pod attribution is unaffected, because the pod UID is parsed from a path segment
rather than from the path as a whole, so `namespace`, `labels` and `container`
work either way. Only `cgroupPath` is affected, and it refuses rather than
comparing two paths anchored differently, since a coincidental match would
authorize the wrong cgroup. The agent detects and logs this at startup.

A `cgroupPath` of `/` is rejected at load, since every process on the host is under
the root cgroup and it therefore constrains nothing.

## Maturity

The cgroup-to-pod mapping is covered by unit tests over recorded path shapes for
the systemd and cgroupfs drivers with containerd, CRI-O and Docker, including
guaranteed-QoS pods, non-default kubelet cgroup roots and cgroup v1 hosts. It has
not yet been exercised on a live EKS node. Reports from clusters the maintainer
did not build are especially welcome.
