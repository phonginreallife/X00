# Making Kubernetes secrets unreadable to root

Every secrets manager solves the same half of the problem.

Vault, External Secrets Operator, sealed-secrets, SOPS, whatever you run: they
fetch a secret from somewhere safe and put it somewhere your application can
reach. Then they stop. The secret is now an environment variable or a file inside
your pod, and anything with sufficient privilege on that node can read it.

That is not a criticism of those tools. Delivery is their job and they do it well.
It is a statement about where the job ends.

Here is the part that ends it, on a cluster with a perfectly configured secrets
pipeline:

```console
$ kubectl exec -it myapp -- sh
/ # cat /proc/1/environ | tr '\0' '\n' | grep PASSWORD
DB_PASSWORD=hunter2-actual-production-password
```

Root in the container reads the environment of the process holding your database
password. No exploit, no privilege escalation, no CVE. This is `/proc` working
exactly as designed.

So the question I wanted to answer was: can the kernel refuse that read, even for
root, without changing the application?

## The ordering is the whole idea

KernelSeal has two pieces. An agent that holds secrets and loads BPF programs, and
`kernelseal-exec`, a small shim that wraps an application's entrypoint.

The naive version of this design has a hole in it. If you deliver secrets to a
process and then protect it, there is a window between those two events where the
secrets are readable. Windows like that get found.

So the order is inverted:

1. The shim connects to the agent over a unix socket and asks for the secrets
   bound to the binary it is about to run.
2. The agent marks the calling PID protected **first**, in a BPF map.
3. Only then does it return the values.
4. The shim applies them to its environment and calls `execve`.

The load-bearing detail is that `execve` **preserves the PID**. The shim and the
application it becomes are the same process, with the same PID, and that PID was
already in the protected set before any secret crossed the socket.

There is no window. Not a small one. None. The process is protected before it has
anything worth stealing, and it inherits both the environment and the protection
through the exec.

From that point two BPF-LSM hooks do the refusing. `file_open` denies reads of
`/proc/<pid>/environ`, `/proc/<pid>/mem` and `/proc/<pid>/maps` for protected
PIDs, and `ptrace_access_check` denies debugger attach:

```console
$ sudo cat /proc/$APP_PID/environ
cat: /proc/12345/environ: Operation not permitted

$ sudo gdb -p $APP_PID
ptrace: Operation not permitted.

$ id -u
0
```

The application itself reads `$DB_PASSWORD` like it always has. No SDK, no library,
no code change. `allowSelfRead` lets it inspect its own `/proc` files, because
plenty of runtimes do that at startup and breaking them buys nothing.

## Identity has to come from the kernel

An agent that hands out secrets needs to know who is asking, and it cannot ask the
caller, because the caller is exactly who it is trying to establish.

So it does not. The agent reads `SO_PEERCRED` on the socket, which the kernel
fills in with the peer's PID, UID and GID. A client cannot forge it or lie about
it. Secret delivery is bound to a real process that really exists, which is also
what makes step 2 above possible: the agent knows which PID to protect because the
kernel told it.

But `SO_PEERCRED` proves *which process* is calling. It does not prove *which
binary that process is about to become*. At handshake time `/proc/<pid>/exe` still
points at the shim, because the exec has not happened yet.

For two releases that gap was wider than I was comfortable with, and it is worth
describing plainly rather than in the abstract. The binary name in the request was
the only thing authorization rested on, and the request is a JSON object containing
a string:

```bash
echo '{"binary":"/usr/bin/node"}' | nc -U /run/kernelseal/kernelseal.sock
```

No subterfuge. A compromised container did not need to install that binary, rename
anything, or execute anything. On a node-wide DaemonSet, whose socket is a
`hostPath` that every pod can mount, that was cross-tenant secret disclosure. The
documented answer was to run one agent per pod so the socket itself was the
boundary, which works but amounts to telling you to deploy around the problem.

The fix is to authorize on something the caller cannot say. The kernel puts every
container in a cgroup when it is created, and a process cannot change its own
cgroup from inside the container. So the agent reads the calling PID's cgroup from
procfs, parses the pod UID out of the path, and looks that UID up against the pods
scheduled on its own node. Bindings then select on the pod:

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
audited whatever it calls itself. The binary name survives as what it always
honestly was: a way to narrow what a pod is already entitled to.

How strictly this applies is a deployment question rather than a preference, so it
is a setting. `required` refuses any caller it cannot attribute to a pod and is
what the DaemonSet ships. `preferred`, the default, enforces pod selectors when
they are present but still serves bindings without one, which is right for a
sidecar whose socket is already reachable from exactly one pod. An unrecognized
value is treated as `required`, because a typo in the setting that governs
authorization should not quietly widen it.

Two things this deliberately does not close. Inside a single pod the binary name is
still only a claim, so pod identity separates tenants and not processes within one
tenant. And pod labels are mutable, so anyone who can patch a pod's labels can make
it match a `labels` selector; bind on `namespace` too, and treat label-write access
as equivalent to access to the secrets those labels select.

## Two bugs that are worth your time

Both of these are the kind that pass every test you thought to write.

### An 8-byte struct that was wrong in a way nothing could detect

The policy that the LSM programs enforce lives in a BPF map, written from Go,
read from C. The C side:

```c
struct ks_policy_config {
    __u8 enforce_mode;
    __u8 block_environ;
    __u8 block_mem;
    __u8 block_maps;
    __u8 block_ptrace;
    __u8 allow_self_read;
    __u8 audit_all;
    __u8 reserved;
};
```

Eight single-byte fields. Eight bytes. Now reorder two fields on the Go side.

The struct is still eight bytes. The map update still succeeds. No error, anywhere,
at any layer. What changed is that `block_ptrace` now writes into the byte the
kernel reads as `allow_self_read`. The enforced policy silently differs from the
configured one, and the only way to notice is to test every field's effect
independently against a live kernel.

This is why `make abi-check` exists and runs in CI. It compares the Go structs
against the C definitions field by field, including padding the compiler inserts
implicitly, and it separately verifies that every program and map name the loader
resolves by name actually exists in the compiled objects. A security control whose
misconfiguration is invisible needs a test whose failure is loud.

### `sched_process_exit` fires per thread, not per process

Protection has to be released when a process exits, or a recycled PID inherits it.
The obvious source is the `sched_process_exit` tracepoint.

The obvious source is wrong. That tracepoint fires for **every thread**, not once
per process. The shim is a Go program, so it has a runtime with several threads,
and when it execs its target those sibling threads exit first. Each one was
reported as the process exiting. Protection was dropped from the map moments after
the secrets were delivered, and `/proc/<pid>/environ` stayed readable for the
entire life of the application.

The fix is a kernel-side check on `signal->live`, emitting an exit event only when
the last thread of the group leaves.

Then I made it worse by being careful. It seemed prudent to add a second opinion in
user space: before unprotecting a PID, check the process is really gone. That check
cannot work, and the reason is a nice piece of kernel trivia. `sched_process_exit`
fires from inside `do_exit()`, so when the event arrives in user space the task is
still mid-exit or a zombie awaiting reap, and `/proc/<pid>` still exists. Every
genuine exit therefore looked alive. Protection was never released on exit at all;
cleanup fell entirely to a 30 second reconcile sweep, behind one warning line per
exiting process.

That defensive check shipped in one release and was reverted in the next. The
lesson I would take from it is that "add a redundant safety check" is not free and
is not automatically safe. This one converted a correct fast path into a slow path
plus log noise.

## What it does not do

A security tool that only lists its strengths is asking you to find the gaps
yourself.

- **It needs `bpf` in the kernel's active `lsm=` list.** `CONFIG_BPF_LSM=y` is not
  enough. On most distributions, and on EKS AL2023, this means a kernel command
  line change and a reboot. Note that `lsm=` replaces the list rather than
  appending to it, so read the current value before setting it.
- **Within a pod, the binary name is still only a claim.** Cgroup authorization
  separates tenants, not processes inside one tenant. Any process in a pod can ask
  for any binding that pod is entitled to.
- **The cgroup-to-pod mapping has unit tests, not field miles.** It is covered
  against recorded path shapes for the systemd and cgroupfs drivers with
  containerd, CRI-O and Docker, including guaranteed-QoS pods, non-default kubelet
  cgroup roots and cgroup v1. It has not yet run on a live EKS node. If you try it
  on a cluster I did not build, that is the report I most want.
- **The shim is inside the trust boundary.** It handles plaintext between the
  socket read and the exec.
- **Agent restarts end protection silently.** The BPF maps do not survive the agent
  process, so an upgrade or an OOM kill leaves running processes unprotected with
  nothing in their own logs to say so.
- **Protection does not follow forks.** A child inherits the environment without
  being marked protected.
- **Go strings cannot be reliably zeroed**, so values may persist in the agent's
  heap until collected.

The gaps are tracked in the open. The largest one on that list until recently was
the authorization boundary described above, which is the section of this post I
have most enjoyed rewriting.

## Try it against your own nodes

The only question that matters first is whether your kernel can enforce anything.
One job answers it, in audit mode with no secret bindings, so nothing can be
blocked and no secret is read:

```bash
kubectl apply -f deploy/kernelseal-probe.yaml
kubectl logs -f job/kernelseal-probe
```

It loads and attaches for real, because every static check can pass on a node where
the attach still fails.

KernelSeal is Apache 2.0 at
[github.com/phonginreallife/kernelseal](https://github.com/phonginreallife/kernelseal).
Release images and artifacts are signed with cosign keyless signing and ship an
SPDX SBOM, and the verification instructions insist on the certificate identity,
because `cosign verify` without it accepts a signature from anybody at all.

What I would most like back is the part of the claim above that does not hold.
