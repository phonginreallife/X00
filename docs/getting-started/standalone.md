# Standalone Linux

On a single host, KernelSeal is two pieces: an agent running as a system service,
and applications started through the shim. The agent loads the BPF programs,
listens on a unix socket, and hands each process its secrets in the instant before
it execs the real binary.

This is the environment the guarantee is built out of. Every part of it is a kernel
mechanism: the protected-PID set is a BPF map, the caller's identity comes from
`SO_PEERCRED` and procfs, and the refusals come from LSM hooks. Nothing in that
chain needs an orchestrator.

Authorization has a natural home here too. Every systemd service runs in its own
cgroup, assigned by the kernel and unchangeable from inside the process, so a
binding can name `/system.slice/myapp.service` and no other unit can claim it.

## Requirements

Linux 5.7 or newer, booted with `bpf` in its `lsm=` list, and kernel BTF present.
[Requirements](requirements.md) has the detail, including the reboot that usually
comes with the `lsm=` change.

```bash
cat /sys/kernel/security/lsm    # must contain: bpf
ls -l /sys/kernel/btf/vmlinux
```

Starting the agent is the real check. It reports whether the LSM programs
attached, and in `enforce` mode it refuses to release secrets rather than run
without them.

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

## Authorization by cgroup

The binary name in a request is a claim. The agent cannot verify it, because at
handshake time `/proc/<pid>/exe` still points at the shim, so on its own it says
which secrets are wanted rather than who is entitled to them.

The cgroup is not a claim. systemd puts every service in its own, the kernel
assigns it, and a process cannot move itself out of it. Selecting on it therefore
authorizes:

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

## Which selectors authorize

| Mode | Standalone behavior |
|---|---|
| `preferred` (default) | Callers are identified by cgroup. This is the mode to run |
| `required` | **Refuses to start.** It demands that every caller be attributed to a pod, which cannot happen here, and a startup failure beats an agent that looks healthy while serving nothing |
| `disabled` | No caller identification at all. Any process that can reach the socket can request any binding by naming it |

`cgroupPath` and `binary` are the selectors that mean something on a host.
`namespace`, `labels` and `container` are resolved from a pod, so they match
nothing here, and they **deny** rather than being skipped: a binding carrying one
admits no caller instead of admitting every caller.

## Docker

`demo/docker-compose.yaml` runs the agent and an application container together.
The agent needs the same capabilities as above, plus `/sys/kernel/security`,
`/sys/kernel/btf`, `/sys/fs/bpf` and tracefs mounted in, and the application
container needs the socket. `cgroupPath` selectors will refuse in that setup
unless the agent shares the host's cgroup namespace.

## Feature support

| Feature | On a host |
|---|---|
| Protection of `environ`, `mem`, `maps` and ptrace | Yes |
| `value`, `envRef`, `fileRef` secret sources | Yes |
| `binary` and `cgroupPath` selectors | Yes |
| Audit mode, fail-closed, metrics and health endpoints | Yes |
| Kernel-side binary filtering | Yes |
| `secretKeyRef` | No. It reads a projected Secret path. Use `fileRef` |
| `namespace`, `labels`, `container` selectors | No. They are resolved from a pod |
