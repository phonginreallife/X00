# Standalone Linux

KernelSeal does not require Kubernetes. The shim, the agent, the socket handshake
and both BPF-LSM hooks are plain Linux, and the quick start on this site is
already a standalone example.

Only two things are Kubernetes-specific: pod attribution, which is opt-in, and the
`secretKeyRef` secret source, which reads a mounted Secret path. `value`, `envRef`
and `fileRef` work anywhere.

## Requirements

Identical to the Kubernetes case, minus the cluster. See
[Requirements](requirements.md): Linux 5.7+, `bpf` in the boot-time `lsm=` list,
and kernel BTF present.

```bash
cat /sys/kernel/security/lsm    # must contain: bpf
ls -l /sys/kernel/btf/vmlinux
```

There is no probe job to run, since that is a Kubernetes `Job`. Those two commands
plus starting the agent are the equivalent: the agent reports whether the LSM
programs attached.

## Install

Take the binaries and BPF objects from a release, or build from source as in the
[quick start](quickstart.md).

```bash
VERSION=v1.2.0
curl -fsSLO https://github.com/phonginreallife/kernelseal/releases/download/${VERSION}/kernelseal-${VERSION}-linux-amd64.tar.gz
curl -fsSLO https://github.com/phonginreallife/kernelseal/releases/download/${VERSION}/checksums.txt
sha256sum -c checksums.txt --ignore-missing

tar -xzf kernelseal-${VERSION}-linux-amd64.tar.gz
sudo install -m 0755 kernelseal-linux-amd64      /usr/local/bin/kernelseal
sudo install -m 0755 kernelseal-exec-linux-amd64 /usr/local/bin/kernelseal-exec
sudo install -d -m 0755 /usr/local/lib/kernelseal
sudo install -m 0444 bpf/*.bpf.o /usr/local/lib/kernelseal/
```

Verify the signature over `checksums.txt` before trusting either binary. See
[Verifying a release](../reference/verifying-releases.md).

## Run the agent

```ini title="/etc/systemd/system/kernelseal.service"
[Unit]
Description=KernelSeal agent
Documentation=https://phonginreallife.github.io/kernelseal/
After=network.target

[Service]
Type=simple
ExecStart=/usr/local/bin/kernelseal \
  -config /etc/kernelseal/config.yaml \
  -exec-monitor /usr/local/lib/kernelseal/exec_monitor.bpf.o \
  -lsm /usr/local/lib/kernelseal/lsm_file_protect.bpf.o \
  -socket-group kernelseal

# Loading BPF and attaching LSM programs needs these.
AmbientCapabilities=CAP_SYS_ADMIN CAP_BPF CAP_PERFMON CAP_SYS_RESOURCE
LimitMEMLOCK=infinity

# Do not use RestartSec-driven restarts casually: the protected-PID map does not
# survive this process, so a restart silently unprotects everything already
# running. Restart deliberately and restart the workloads after it.
Restart=no

[Install]
WantedBy=multi-user.target
```

Create the group the socket will belong to, so services that are not root can
reach it:

```bash
sudo groupadd --system kernelseal
sudo systemctl daemon-reload
sudo systemctl start kernelseal
journalctl -u kernelseal -f
```

Two lines in the log decide whether anything works:

```
[OK] LSM BPF programs loaded and attached
[REGISTER] 2 secrets registered for binary: myapp
```

A zero on the second means the sources did not resolve, and the service will start
unprotected.

## Wrap a service

The shim goes in front of the real `ExecStart`:

```ini title="/etc/systemd/system/myapp.service"
[Service]
ExecStart=/usr/local/bin/kernelseal-exec -- /usr/bin/myapp --serve
User=myapp
# So the shim can open the 0660 delivery socket
SupplementaryGroups=kernelseal
```

`kernelseal-exec` execs the real binary in place, so systemd's `MainPID` tracking,
`Type=notify` readiness and log capture all behave exactly as before. The PID
systemd supervises is the PID that was marked protected.

## Authorization on a standalone host

This is where a standalone deployment is stronger than it first appears. Every
systemd service runs in its own cgroup, the kernel assigns it, and a process
cannot change its own. So `cgroupPath` is real identity here for the same reason
pod attribution is under Kubernetes.

```yaml
version: v1

policy:
  mode: enforce
  podIdentity: preferred     # required would refuse to start off-cluster
  blockEnviron: true
  blockMem: true
  blockPtrace: true
  allowSelfRead: true
  kernelBinaryFilter: true

secrets:
  - name: myapp-db
    selector:
      binary: myapp
      cgroupPath: /system.slice/myapp.service
    secretRefs:
      - name: DB_PASSWORD
        source:
          fileRef: /etc/kernelseal/secrets/db-password
```

A `cgroupPath` matches that path **or any descendant**, so `/system.slice` selects
every system service and `/system.slice/myapp.service` selects one. That means a
request naming `myapp` from some other unit's cgroup is refused, not served.

!!! warning "Run the agent on the host, not in a container"

    The kernel renders `/proc/<pid>/cgroup` relative to the *reading* process's
    cgroup namespace. An agent with its own namespace sees callers anchored to
    itself, cannot compare those paths against a configured one, and refuses
    rather than risking a coincidental match. `cgroupPath` therefore needs the
    agent in the host's cgroup namespace.

    The agent logs this at startup if it detects it.

## `podIdentity` off-cluster

| Mode | Standalone behavior |
|---|---|
| `preferred` (default) | Starts. Callers are identified by cgroup only. `cgroupPath` works; `namespace`, `labels` and `container` match nothing |
| `required` | **Refuses to start.** No caller could be attributed to a pod, so every request would be refused, and a startup failure is better than an agent that looks healthy while serving nothing |
| `disabled` | No caller identification. Any process that can reach the socket can request any binding by naming it |

Selectors that need the API server fail closed rather than being skipped when
there is no pod, so a `namespace` selector on a standalone host denies everything
rather than admitting everyone.

## Docker without Kubernetes

`demo/docker-compose.yaml` runs the agent and an application container together.
The agent needs the same capabilities as above, plus `/sys/kernel/security`,
`/sys/kernel/btf`, `/sys/fs/bpf` and tracefs mounted in, and the application
container needs the socket. `cgroupPath` selectors will refuse in that setup
unless the agent shares the host's cgroup namespace.

## What does not apply

| Feature | Standalone |
|---|---|
| `secretKeyRef` | No. Use `fileRef` against a path you write |
| `namespace`, `labels`, `container` selectors | No. They need the API server |
| `cgroupPath`, `binary` selectors | Yes |
| `deploy/kernelseal-probe.yaml` | No, it is a Kubernetes Job |
| Everything else | Yes |
