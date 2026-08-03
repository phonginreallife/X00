# Changelog

All notable changes to this project are documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [1.2.0] - 2026-08-03

### Added

- **Authorization by cgroup.** The agent now resolves a caller's cgroup, maps it
  to the pod that owns it, and matches secret bindings against that pod. The
  cgroup is set by the kernel when the container is created and cannot be changed
  from inside it, so it is identity rather than assertion. The `namespace`,
  `labels`, `container` and `cgroupPath` selectors were accepted by the parser and
  ignored when matching; they now decide who a binding applies to. Closes the hole
  where any process that could open the socket could request the secrets bound to
  any configured binary by naming it.
- **`policy.podIdentity`**, with three modes. `required` refuses any caller that
  cannot be attributed to a pod and rejects bindings that name no pod; it is what
  `deploy/manifests/daemonset.yaml` now ships, because a node-wide agent serves one
  socket to every pod on the node. `preferred`, the default, enforces pod selectors
  when they are present but still serves bindings without one, which is correct for
  the per-pod sidecar whose socket is already scoped to a single pod. `disabled` is
  the 1.1.0 behavior. An unrecognized value is treated as `required`, so a typo in
  the setting that governs authorization cannot quietly widen it.
- **A pod watcher**, a list-watch of the pods on the agent's own node, restricted
  with a `spec.nodeName` field selector. It is written against the API server
  directly rather than through client-go, which would have added tens of megabytes
  of dependencies to a binary whose purpose is to be a small static thing that
  loads BPF. The RBAC it needs was already granted in 1.0.0 and unused.
- **`kernelseal_pods_watched`**, the size of that cache. On a node-wide agent a
  zero here means every request is being refused, which is otherwise hard to tell
  from an agent with nothing to do.

### Changed

- Denials now name the calling pod's namespace, name and UID rather than only a
  PID, which is usually gone by the time anyone reads the log.
- A binding the policy cannot serve as written is kept and marked rejected instead
  of being dropped. A dropped binding makes its binary look unconfigured, and an
  unconfigured binary starts unprotected without complaint, which turns a
  configuration mistake into a silent loss of the guarantee.
- Refusing a caller on identity does not depend on `policy.mode`. Audit mode
  weakens what the kernel blocks; it does not make one pod's secrets available to
  another.

### Notes

A `cgroupPath` selector refuses when the agent runs in its own cgroup namespace,
because the kernel then renders callers' paths relative to the agent rather than to
the hierarchy root and the two cannot be compared. Pod attribution is unaffected,
so `namespace`, `labels` and `container` work in both cases. The agent reports the
condition at startup.

A `cgroupPath` of `/` is rejected at load: every process on the host is under the
root cgroup, so it constrains nothing.

Existing configurations keep working: the default `preferred` mode serves
binary-only bindings exactly as 1.1.0 did. Setting `podIdentity: required`, which
the DaemonSet manifest now does, requires every binding to carry a pod selector.

The cgroup-to-pod mapping is covered by unit tests over recorded path shapes for
the systemd and cgroupfs drivers with containerd, CRI-O and Docker, including
guaranteed-QoS pods, non-default kubelet cgroup roots and cgroup v1 hosts. It has
not yet been exercised on a live EKS node.

## [1.1.0] - 2026-07-30

Supply chain and documentation. The agent, the shim and the BPF programs are
unchanged, so the protection guarantee is identical to 1.0.0.

### Added

- **Signed releases.** Images and release artifacts are signed with cosign keyless
  signing, so there is no key to store or rotate. Signatures bind to the image
  digest rather than the tag, because a tag can be moved to a different image
  afterwards while a digest cannot. The tarballs are covered by a signature over
  `checksums.txt`.
- **SBOM.** An SPDX SBOM ships as a release asset and as a cosign attestation on
  the image, so a cluster that only knows a digest can still recover it.
- **`deploy/kernelseal-probe.yaml`.** Reports whether a node can enforce anything,
  covering the active LSM list, kernel BTF, tracefs and a real load-and-attach. It
  was referenced by the 1.0.0 release notes without having been committed.
- **`CONTRIBUTING.md`**, a code of conduct, issue forms and a pull request
  template.

### Changed

- **The Go module path is now `github.com/phonginreallife/kernelseal`**, which
  breaks any existing import of these packages. It was `kernelseal`, a path the
  toolchain cannot resolve, so the packages could not be imported and the binaries
  could not be installed with `go install`. The built binaries and the deployment
  are unaffected.
- The Kubernetes documentation now leads with the probe and the per-pod sidecar
  rather than the DaemonSet. A node-wide agent serves one socket to every pod that
  mounts it, and socket reachability is the authorization boundary.
- `SECURITY.md` verification instructions now match what actually signs the
  artifacts, and require `--certificate-identity` and `--certificate-oidc-issuer`.
  Without both, `cosign verify` accepts a signature from any identity.

### Fixed

- **TruffleHog was scanning nothing.** Its `base` was the default branch, which on
  a push to `main` resolves to the same commit as `head`, so it diffed a commit
  against itself, reported zero bytes and passed. Pushes now scan the push range,
  and the weekly run scans the full history.
- **Gitleaks was failing** on a false positive in `scripts/run-node-demo.sh`, where
  `curl-auth-header` matched a shell variable holding a locally-minted demo JWT.
  Neither scanner had run since before 1.0.0, because GitHub had disabled the
  Security workflow for inactivity.

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
