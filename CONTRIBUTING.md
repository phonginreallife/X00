# Contributing to KernelSeal

Thanks for your interest. This document covers what you need to build the
project, which tests you can realistically run, and the two review points that
are specific to a BPF codebase.

## Before you start

For anything larger than a bug fix, open an issue or a
[discussion](https://github.com/phonginreallife/kernelseal/discussions) first.
KernelSeal makes a narrow security claim, and a change that widens the trust
boundary needs to be talked through before either of us spends time on code.

For security issues, do not open an issue. Follow
[SECURITY.md](https://github.com/phonginreallife/kernelseal/blob/main/SECURITY.md) instead.

## Development setup

You need Go 1.22+, clang, llvm, libbpf-dev and bpftool. On a Debian or Ubuntu
host:

```bash
sudo make install-deps
```

If your distribution ships `bpftool` only as a wrapper that fails to find a
matching `linux-tools` package, install `linux-tools-$(uname -r)` explicitly.
[scripts/ci-install-bpf-deps.sh](https://github.com/phonginreallife/kernelseal/blob/main/scripts/ci-install-bpf-deps.sh) is what CI uses
to work around this on GitHub runners.

Then:

```bash
make vmlinux    # generate bpf/vmlinux.h from the running kernel's BTF
make bpf        # compile the BPF programs
make build      # build the agent and the shim
make verify     # what CI runs
```

`bpf/vmlinux.h` is generated and gitignored, so it is never committed. On a host
without BTF at `/sys/kernel/btf/vmlinux`, build the objects in a container with
`make docker-dev`.

## Tests

The suites differ in what they need, which matters because most contributors
cannot run all of them:

| Command | Needs | Covers |
|---|---|---|
| `make test` | nothing | unit tests |
| `make test-delivery` | nothing | the real socket handshake and exec path |
| `make test-integration` | root, and a kernel booted with `bpf` in `lsm=` | LSM enforcement |

`make test-delivery` is the important one to run locally: it exercises delivery
end to end on any machine. The enforcement tests skip themselves rather than fail
when they do not find root and BPF-LSM, so a green `make verify` on an ordinary
laptop does not mean enforcement was tested. CI runs the same tests under the
same constraint, so a change to the LSM programs needs either a suitable local
kernel or a note in the pull request that it is untested.

To check whether a machine can run the enforcement tests:

```bash
cat /sys/kernel/security/lsm    # must contain: bpf
```

## Two things reviewers will look for

**Keep the ABI check passing.** `make abi-check` compares the Go structs in
[internal/types/events.go](https://github.com/phonginreallife/kernelseal/blob/main/internal/types/events.go) against the C definitions in
[bpf/kernelseal_common.h](https://github.com/phonginreallife/kernelseal/blob/main/bpf/kernelseal_common.h) field by field, including
padding the compiler inserts implicitly. This is not a formality. Both sides of
the policy struct are 8 bytes, so reordering a field on one side still updates
the map successfully and simply writes each setting to the wrong byte: the
enforced policy then differs from the configured one, with no error anywhere. The
same check verifies that every program and map name the loader resolves through
an `ebpf:"..."` tag exists in the compiled objects, so a rename in the BPF source
fails in CI rather than at someone's agent startup.

**Do not widen the window.** The security property is an ordering one. The agent
marks a PID protected *before* it releases any secret, and `execve` preserves the
PID, so there is no moment at which a protected process is running with readable
secrets. A change that moves work between those two points, or that adds a path
where secrets are released without protection being confirmed, is changing the
guarantee rather than the implementation. Say so in the pull request.

## Pull requests

- Run `make verify` first. It covers formatting, vet, the ABI check, and the unit
  and delivery tests.
- Commit messages follow [Conventional Commits](https://www.conventionalcommits.org/):
  `feat:`, `fix:`, `docs:`, `ci:`, `chore:`, with an optional scope such as
  `fix(deploy):`. Explain why the change is needed in the body, not just what it
  does.
- Keep one logical change per pull request.
- Update `SECURITY.md` when a change affects the threat model, and `README.md`
  when it affects configuration or deployment.
- New limitations belong in the README's known limitations list. Documenting a
  gap honestly is preferred to leaving it implicit.

## Where to start

Issues labelled `good first issue` are scoped to be self contained. Beyond those,
the [roadmap issue](https://github.com/phonginreallife/kernelseal/issues/16) is the
honest list of what is missing, and the known limitations in
[README.md](https://github.com/phonginreallife/kernelseal/blob/main/README.md#known-limitations)
say the same in shorter form. `vaultRef` is still parsed but unimplemented, and
the cgroup-to-pod mapping added in 1.2.0 has unit tests over recorded path shapes
but has not been exercised on a live cloud cluster.

## License

Contributions are accepted under the [Apache 2.0 License](https://github.com/phonginreallife/kernelseal/blob/main/LICENSE) that covers
the project.
