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

I want to be precise about the limit of this, because it is the kind of thing
people assume is stronger than it is. `SO_PEERCRED` proves *which process* is
calling. It does not prove *which binary that process is about to become*. At
handshake time `/proc/<pid>/exe` still points at the shim, since the exec has not
happened yet. The binary name in the request selects which secrets apply. It is
not an identity claim, and KernelSeal's docs say so in those words.

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
- **Socket reachability is the authorization boundary.** Any process that can open
  the delivery socket can request the secrets bound to any configured binary by
  naming it. Run one agent per pod. A node-wide agent serves one socket to every
  pod on the node.
- **The shim is inside the trust boundary.** It handles plaintext between the
  socket read and the exec.
- **Agent restarts end protection silently.** The BPF maps do not survive the agent
  process, so an upgrade or an OOM kill leaves running processes unprotected with
  nothing in their own logs to say so.
- **Protection does not follow forks.** A child inherits the environment without
  being marked protected.
- **Go strings cannot be reliably zeroed**, so values may persist in the agent's
  heap until collected.

The gaps are tracked in the open, and several of them converge on the same fix:
authorize on the caller's cgroup, which the kernel sets and which maps to a pod,
instead of on a name the caller supplies.

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
SPDX SBOM. I am most interested in hearing from anyone who tries the probe against
a cluster they did not build themselves, and in being told which part of the claim
above does not hold.
