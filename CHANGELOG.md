# Changelog

All notable changes to this project are documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [3.0.2] - 2026-07-29

### Fixed

- Reverted the 3.0.1 user-space exit check. `sched_process_exit` fires from inside `do_exit()`, so the exiting task still has a `/proc/<pid>` entry when the event reaches user space. The check therefore rejected *every* genuine exit, logging `Ignoring exit event for PID N: process is still running` for each one and leaving protection release entirely to the 30s reconcile sweep. The exit handler releases protection unconditionally again; the kernel-side filter added in 3.0.1 is what makes that safe.

### Note

3.0.1 does not leak secrets — the reverted check erred toward keeping protection — but it delays cleanup and floods the log. Upgrade to 3.0.2.

## [3.0.1] - 2026-07-29

### Fixed

- Exec monitor no longer reports sibling thread exits as process exits. When a multithreaded shim execs its target, `sched_process_exit` used to fire for zapped Go runtime threads and user space dropped BPF protection while the target was still running and held secrets.
- Agent exit handler verifies `/proc/<pid>` still exists before unprotecting, as a user-space backstop for any misreported exit events.

### Added

- Integration tests (`test/integration/shim_protection_test.go`) that reproduce the protection leak with the real shim and assert environ reads return `EPERM` after exec.

## [3.0.0] - 2026-07-29

### Added

- `kernelseal-exec` shim for exec-time secret delivery over a unix socket.
- Agent unix socket server with `SO_PEERCRED` caller verification and protect-before-release ordering.
- Prometheus metrics on `:9090/metrics` plus `/healthz` and `/ready` probes.
- `-version` flag and build-time version stamping for both binaries.
- Configurable log levels (`monitoring.logLevel`).
- Protected PID reconciliation loop for stale BPF map entries.
- BPF/Go ABI regression tests (`internal/types/abi_test.go`, `internal/bpf/spec_test.go`).
- Shim delivery integration tests (`test/integration/shim_delivery_test.go`).
- `-socket-group` flag to share the delivery socket with unprivileged callers.

### Changed

- **Breaking:** secrets are delivered only through `kernelseal-exec`; the old `/proc/mem` injector was removed.
- **Breaking:** enforce mode withholds secrets when BPF-LSM is unavailable (fail closed).
- Rewrote `lsm_file_protect.bpf.c` to use the shared BPF header and fixed struct layout drift.
- `blockMaps` and `auditAll` policy flags are now wired through to the LSM programs.
- LSM block events now use the correct `EventBlocked` type instead of being logged as audit-only.
- Documentation, demo, Docker image, Kubernetes manifests, and CI updated for the shim model.

### Fixed

- `ptrace_access_check` now uses `child->tgid` instead of `child->pid`.
- `RLIMIT_MEMLOCK` is raised before creating BPF maps.
- DaemonSet args preserve BPF object paths instead of overriding them silently.
- CI/release Docker and BPF dependency installation on GitHub-hosted Ubuntu runners.

### Removed

- `internal/secrets/injector.go` and related fake memory-injection tests.

## [2.0.3] - 2026-01-06

Maintenance and CI fixes for the 2.x line.

## [2.0.0] - 2026-01-06

KernelSeal rebrand, inline secret values in config, and expanded security documentation.

[3.0.1]: https://github.com/phonginreallife/kernelseal/compare/v3.0.0...v3.0.1
[3.0.0]: https://github.com/phonginreallife/kernelseal/compare/v2.0.3...v3.0.0
[2.0.3]: https://github.com/phonginreallife/kernelseal/compare/v2.0.0...v2.0.3
[2.0.0]: https://github.com/phonginreallife/kernelseal/releases/tag/v2.0.0
