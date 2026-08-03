# Requirements

One requirement decides whether KernelSeal can do anything at all, and it is not
the one people expect.

## The one that matters

The kernel must list `bpf` as an **active LSM**. Building the kernel with
`CONFIG_BPF_LSM=y` is not sufficient; `bpf` also has to appear in the boot-time
`lsm=` list.

```bash
cat /sys/kernel/security/lsm
# lockdown,capability,landlock,yama,apparmor,bpf
```

On most distributions, and on EKS AL2023, this means a kernel command line change
and a reboot.

!!! danger "`lsm=` replaces the list, it does not append to it"

    Setting `lsm=bpf` alone disables apparmor, lockdown and everything else that
    was active. Always read the current value first and append to it.

    ```bash
    CURRENT=$(cat /sys/kernel/security/lsm)
    sudo grubby --update-kernel=ALL --args="lsm=${CURRENT},bpf"
    sudo reboot
    ```

## Everything else

| Requirement | Why |
|---|---|
| Linux 5.7 or newer | BPF-LSM landed in 5.7 |
| Kernel BTF at `/sys/kernel/btf/vmlinux` | CO-RE relocates the prebuilt objects to your kernel |
| `CONFIG_BPF=y`, `CONFIG_BPF_SYSCALL=y`, `CONFIG_BPF_LSM=y`, `CONFIG_DEBUG_INFO_BTF=y` | Loading and attaching |
| `SYS_ADMIN`, `BPF`, `PERFMON`, `SYS_RESOURCE` | The last raises `RLIMIT_MEMLOCK` for BPF maps |
| Kubernetes 1.20+, containerd or CRI-O | Only for authorization by pod. Not needed [standalone](standalone.md) |

## Check a node properly

Static checks can all pass on a node where the attach still fails, so the probe
loads and attaches for real. It runs in `audit` mode with no secret bindings, so
nothing can be blocked and no secret is read, which makes it safe against a
production node.

```bash
kubectl apply -f deploy/kernelseal-probe.yaml
kubectl logs -f job/kernelseal-probe
kubectl delete -f deploy/kernelseal-probe.yaml
```

It ends with either `RESULT: node is ready for KernelSeal` or one `[FAIL]` line
per unmet requirement, each with the fix.

By default the probe lands wherever the scheduler puts it, which is fine when
every node group shares an AMI and misleading when they do not. Uncomment
`nodeName` in the manifest to target a specific node.

## Without Kubernetes

```bash
cat /sys/kernel/security/lsm     # must contain bpf
ls -l /sys/kernel/btf/vmlinux    # must exist
```

## If the kernel cannot enforce

KernelSeal still starts, and in `audit` mode it will report what it *would* have
blocked, which is useful for evaluating against a live workload before committing
to a reboot. In `enforce` mode it refuses to release secrets and reports
`not ready` on its readiness probe. It does not pretend.
