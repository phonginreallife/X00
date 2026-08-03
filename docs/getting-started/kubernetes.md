# Deploy to Kubernetes

In order: probe the nodes, deploy the per-pod sidecar, and reach for the
node-wide DaemonSet only if you actually need it.

## 1. Check the nodes first

```bash
kubectl apply -f deploy/kernelseal-probe.yaml
kubectl logs -f job/kernelseal-probe
kubectl delete -f deploy/kernelseal-probe.yaml
```

See [Requirements](requirements.md) for what it checks and why a static check is
not enough.

## 2. Sidecar, one agent per pod

Start here. The agent's socket lives on an `emptyDir` reachable only from inside
one pod, so reaching it already proves which pod is asking.

[`deploy/kernelseal-sidecar.yaml`](https://github.com/phonginreallife/kernelseal/blob/main/deploy/kernelseal-sidecar.yaml)
is a complete runnable example. The pieces an application pod needs:

```yaml
spec:
  shareProcessNamespace: true   # so the agent can protect the app's processes
  securityContext:
    fsGroup: 1000               # so both containers can use the socket

  initContainers:
  # Copies the shim in, so the application image needs no changes
  - name: install-shim
    image: ghcr.io/phonginreallife/kernelseal:v1.2.0
    command: ["/bin/sh", "-c", "cp /usr/local/bin/kernelseal-exec /kernelseal/"]
    volumeMounts:
    - {name: kernelseal-bin, mountPath: /kernelseal}

  containers:
  - name: myapp
    image: myapp:latest
    # The original entrypoint becomes an argument to the shim
    command: ["/kernelseal/kernelseal-exec", "--", "/usr/bin/myapp"]
    volumeMounts:
    - {name: kernelseal-bin, mountPath: /kernelseal, readOnly: true}
    - {name: kernelseal-socket, mountPath: /run/kernelseal}

  volumes:
  - name: kernelseal-bin
    emptyDir: {}
  - name: kernelseal-socket
    emptyDir: {medium: Memory, sizeLimit: 1Mi}
```

This template ships `podIdentity: preferred`, which enforces pod selectors when a
binding carries one and still serves bindings that do not. That is correct here
because the socket is already scoped to a single pod.

## 3. DaemonSet, one agent per node

A node-wide agent serves a single socket to every pod that mounts it, so the
socket is not a boundary. Pod identity has to do that job instead.

```bash
kubectl apply -f deploy/manifests/namespace.yaml
kubectl apply -f deploy/manifests/configmap.yaml
kubectl apply -f deploy/manifests/daemonset.yaml
```

The shipped DaemonSet sets `podIdentity: required`, which refuses any caller it
cannot attribute to a pod and rejects bindings that name no pod. Every binding
therefore needs a pod selector:

```yaml
secrets:
  - name: checkout-db
    selector:
      binary: node
      namespace: payments
      labels:
        app: checkout
```

!!! warning "Upgrading a node-wide agent from 1.1.0 or earlier"

    `podIdentity: required` rejects binary-only bindings. If you run a node-wide
    agent with bindings that name no pod, they will be marked rejected after
    upgrading and their binaries will not receive secrets. This is deliberate: it
    is the configuration that allowed any pod on the node to request any binding.
    Add pod selectors, or set `podIdentity: preferred` knowingly.

In `required` mode the agent refuses to start if it cannot watch pods, rather than
running as a pod that looks healthy while refusing every request.

## Non-root applications

The delivery socket is `0660 root:root`. If your application runs as non-root, add
`-socket-group=<gid>` to the agent's args and a matching `supplementalGroups` on
the application pod, or the shim gets `EACCES` on connect.

## Pinning what you deploy

Signatures attach to the image digest rather than the tag. Verify, then deploy the
digest you verified. See [Verifying a release](../reference/verifying-releases.md).
