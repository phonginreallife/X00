# KernelSeal

**Kernel-level secret protection for Linux and Kubernetes, using eBPF and BPF-LSM**

KernelSeal delivers application secrets directly into a process's environment at
exec time and uses BPF-LSM to stop anything else on the host from reading them
back out. Secrets are never written to a filesystem, never mounted as a volume,
and cannot be recovered from `/proc/<pid>/environ` afterwards, even by root. It
runs on any Linux host that satisfies the kernel requirements; Kubernetes adds
authorization by pod.

![An application reads its secret from the environment while root is refused by
the kernel: environ, mem and maps all return "Operation not permitted", a ptrace
attach is denied, and id -u reports 0](kernelseal-demo.gif)

## The gap this fills

Every secrets manager solves delivery. Vault, External Secrets Operator,
sealed-secrets, SOPS: they fetch a secret from somewhere safe and put it where
your application can reach it. Then they stop. The secret is now an environment
variable or a file inside your pod, and anything with sufficient privilege on that
node can read it.

```console
$ kubectl exec -it myapp -- sh
/ # cat /proc/1/environ | tr '\0' '\n' | grep PASSWORD
DB_PASSWORD=hunter2-actual-production-password
```

No exploit, no privilege escalation. That is `/proc` working as designed.
KernelSeal starts where those tools stop, and it complements rather than replaces
them: `fileRef` reads whatever a Vault agent sidecar wrote.

## Key properties

- **No secrets on disk.** Values move from the agent to the target process over a
  unix socket. Nothing is written to a file or a tmpfs mount.
- **Ordinary environment variables.** The application reads `os.Getenv` or
  `$DB_PASSWORD` as usual. No SDK, no code changes.
- **Protected before the process starts.** The agent marks the PID protected
  before it returns any secrets, so the environment is never readable, not even
  for a moment. See [How it works](concepts/how-it-works.md).
- **Authorized by the kernel, not by the caller.** Requests are attributed to the
  pod that owns the calling process's cgroup. See
  [Authorization](concepts/authorization.md).
- **Fails closed.** In enforce mode, secrets are withheld entirely if the kernel
  cannot guarantee protection.

## Start here

<div class="grid cards" markdown>

- **Can my nodes run it?**

    Everything depends on the kernel listing `bpf` as an active LSM, which is not
    the default. One `kubectl apply` answers it in about twenty seconds.

    [Requirements and the node probe](getting-started/requirements.md)

- **Try it on a host**

    Build the agent and the shim, start a protected process, and watch root fail
    to read its environment.

    [Quick start](getting-started/quickstart.md)

- **Not running Kubernetes?**

    The agent and the shim are plain Linux. On a systemd host, `cgroupPath`
    selectors authorize by unit rather than by pod.

    [Standalone Linux](getting-started/standalone.md)

- **Deploy it**

    Probe the nodes, then the per-pod sidecar, then the node-wide DaemonSet if you
    actually need it.

    [Deploy to Kubernetes](getting-started/kubernetes.md)

- **Is it trustworthy?**

    The threat model, what the guarantee covers, and what it does not.

    [Security](security.md)

</div>

## Requirements in one line

Linux 5.7+, booted with `bpf` in its `lsm=` list, with kernel BTF present.
`CONFIG_BPF_LSM=y` alone is not enough.

```bash
cat /sys/kernel/security/lsm    # must contain: bpf
```

If that does not list `bpf`, KernelSeal starts but cannot enforce anything. In
enforce mode it refuses to release secrets and reports `not ready` rather than
pretending to protect them.
