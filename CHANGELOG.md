# Changelog

All notable changes to this project are documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [1.0.0] - 2026-07-29

First public release.

Earlier tags existed while the design was still moving and every one of them is
superseded by this release, so they were removed rather than left to be found and
trusted. Nothing before this point should be used: the protection guarantee was
either incomplete or actively broken in each of them.

### Added

- **Kernel-enforced secret protection.** Secrets are delivered to a process over
  a unix socket and applied to its environment immediately before `execve`, so
  they are never written to disk and never exist in an unprotected process. A
  BPF-LSM `file_open` hook then denies reads of that process's
  `/proc/<pid>/{environ,mem,maps}` from anything else, and a
  `ptrace_access_check` hook denies debugger attach.
- **`kernelseal-exec` shim.** Wraps an application's entrypoint, fetches its
  secrets, and `exec`s the real command in place. No application changes and no
  image rebuild: the shim can be copied in by an init container.
- **Secret sources.** Inline values, environment variables (`envRef`), files
  (`fileRef`), and Kubernetes Secrets projected into the agent
  (`secretKeyRef`, read from `/var/run/secrets/kernelseal/<name>/<key>`).
- **Policy modes.** `disabled`, `audit` (report what would be blocked) and
  `enforce` (block and report), with per-resource switches for environ, mem,
  maps and ptrace, plus `allowSelfRead` so a process can still inspect itself.
- **Fail-closed by default.** Secrets are withheld when kernel protection was
  requested but is unavailable, and a binary whose configured secrets *all* fail
  to resolve is refused rather than started unprotected, so a misconfigured
  source cannot quietly downgrade an application to no protection.
- **Kernel-side binary filtering.** Only configured binaries generate exec
  events, so an idle host produces no ring-buffer traffic.
- **Reconciliation.** A periodic sweep releases protection for PIDs whose process
  is gone, covering exits that were never reported.
- **Observability.** Prometheus metrics plus `/healthz` and `/ready` on a
  configurable port, and audit events for every blocked or audited access.
- **Deployment.** DaemonSet (node-wide) and sidecar (pod-scoped) manifests, a
  container image at `ghcr.io/phonginreallife/kernelseal`, and multi-arch
  release archives for amd64 and arm64 with the BPF objects included.
- **Node probe.** Reports whether a node can enforce anything at all, covering
  the active LSM list, kernel BTF, tracefs, and a real load-and-attach, before
  you deploy.
- **Node demo application** (`demo/node-app/`) and an end-to-end test
  (`scripts/run-node-demo.sh`) that asserts delivery, self-read, `EPERM` from
  outside, and that protection survives OS threads exiting inside a live process.

### Requirements

- Linux 5.7+ with `CONFIG_BPF_LSM=y` **and** `bpf` in the kernel's active
  `lsm=` list. Verify with `cat /sys/kernel/security/lsm`; on most distributions
  and on EKS AL2023 this needs a kernel command line change and a reboot.
- Kernel BTF at `/sys/kernel/btf/vmlinux` for CO-RE.
- Root, or `CAP_BPF` + `CAP_PERFMON` + `CAP_SYS_RESOURCE`.
