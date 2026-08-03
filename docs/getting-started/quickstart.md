# Quick start

This runs the agent and a protected process on a single host. You need root, and
a kernel that satisfies the [requirements](requirements.md), or nothing will be
blocked.

## Build from source

```bash
git clone https://github.com/phonginreallife/kernelseal.git
cd kernelseal

# Requires clang, llvm, libbpf-dev and bpftool
sudo make install-deps
make all

# Formatting, vet, the ABI check, unit and delivery tests
make verify
```

This produces two binaries:

| Binary | Runs where | Purpose |
|---|---|---|
| `build/kernelseal` | Privileged sidecar or DaemonSet | Loads BPF, serves secrets |
| `build/kernelseal-exec` | Inside the application container | Wraps the entrypoint |

`bpf/vmlinux.h` is generated from the running kernel's BTF and is gitignored. On
a host without BTF, build the objects in a container with `make docker-dev`.

## Run it

Start the agent with the secret in its own environment:

```bash
sudo MY_SECRET_VALUE="super-secret-value" ./build/kernelseal \
  -config examples/config.yaml \
  -exec-monitor bpf/exec_monitor.bpf.o \
  -lsm bpf/lsm_file_protect.bpf.o \
  -socket-group "$(id -gn)"
```

!!! warning "Check the registration count before going further"

    The log must say `[REGISTER] 2 secrets registered for binary: sleep`. A zero
    there means the secret sources did not resolve, the shim will be told the
    binary has nothing bound to it, and nothing will be protected. The next step
    then appears to work while proving nothing.

Two details in that command are worth knowing:

- The value is passed on the `sudo` command line rather than exported and used
  with `sudo -E`. Many sudoers configurations reject `-E` outright with
  "preserving the entire environment is not supported", and the agent then starts
  with the source variable unset.
- `-socket-group` hands the socket to your group. The agent runs as root and the
  socket is `0660`, so without it a non-root shim gets `EACCES` on connect.

In another shell, start a process through the shim:

```bash
./build/kernelseal-exec -- sleep 300 &
SLEEP_PID=$!
```

The secret is in its environment, and unreadable from anywhere else:

```console
$ cat /proc/$SLEEP_PID/environ
cat: /proc/12345/environ: Operation not permitted

$ sudo cat /proc/$SLEEP_PID/mem
cat: /proc/12345/mem: Operation not permitted

$ sudo strace -p $SLEEP_PID
strace: attach: ptrace(PTRACE_SEIZE, 12345): Operation not permitted
```

## The full demo

`scripts/run-node-demo.sh` runs a real Node service end to end and asserts what
the quick start only shows: that secrets arrive intact, that the app can use them
to sign and verify a token, that its own `/proc` reads still work, that everyone
else is refused, and that protection survives OS threads exiting inside the live
process.

```bash
sudo env "PATH=$PATH" ./scripts/run-node-demo.sh
```

## Tests

```bash
make verify            # what CI runs
make test              # unit tests only
make test-delivery     # end-to-end secret delivery, no privileges needed
make test-integration  # adds LSM enforcement tests, needs root and BPF-LSM
```

`make test-delivery` exercises the real socket handshake and exec path on any
machine. The enforcement tests **skip** rather than fail when they do not find
root and a `bpf`-enabled kernel, so a green `make verify` on an ordinary laptop is
not evidence that enforcement was tested.
