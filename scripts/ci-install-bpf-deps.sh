#!/usr/bin/env bash
# Install clang/llvm/libbpf and a working bpftool on GitHub-hosted Ubuntu runners.
#
# Ubuntu exposes bpftool as a virtual package. On Azure runners the binary lives
# under /usr/lib/linux-azure-*-tools-* (linked from /usr/lib/linux-tools/<kver>/).
# Do not install linux-tools-azure meta packages here: they upgrade the host
# kernel without rebooting, leaving uname -r on an older kernel with no binary.
set -euo pipefail

sudo apt-get update -y

KVER="$(uname -r)"

sudo DEBIAN_FRONTEND=noninteractive apt-get install -y --no-install-recommends \
  clang llvm libbpf-dev linux-tools-common "$@"

TOOL_PKGS=("linux-tools-${KVER}" "linux-cloud-tools-${KVER}")

sudo DEBIAN_FRONTEND=noninteractive apt-get install -y --no-upgrade "${TOOL_PKGS[@]}"

# linux-tools-${KVER} is often a metapackage that symlinks into linux-azure-*-tools-*.
# Install the backing package explicitly so the bpftool binary is on disk.
if [ -L "/usr/lib/linux-tools/${KVER}" ]; then
  backing="$(basename "$(readlink -f "/usr/lib/linux-tools/${KVER}")")"
  if apt-cache show "$backing" >/dev/null 2>&1; then
    sudo DEBIAN_FRONTEND=noninteractive apt-get install -y --no-upgrade "$backing"
  fi
fi

bpftool_usable() {
  local candidate="$1"
  local resolved
  resolved="$(readlink -f "$candidate" 2>/dev/null || true)"
  [ -n "$resolved" ] && [ -f "$resolved" ] && sudo "$resolved" version >/dev/null 2>&1
}

resolve_bpftool() {
  local kver="$1"
  local candidate resolved

  for candidate in \
    "/usr/lib/linux-tools/${kver}/bpftool" \
    "/usr/lib/linux-tools/${kver%-azure}/bpftool"; do
    if bpftool_usable "$candidate"; then
      resolved="$(readlink -f "$candidate")"
      sudo ln -sf "$resolved" /usr/local/bin/bpftool
      echo "Using bpftool: $resolved"
      sudo /usr/local/bin/bpftool version
      return 0
    fi
  done

  while IFS= read -r candidate; do
    [ -n "$candidate" ] || continue
    if bpftool_usable "$candidate"; then
      resolved="$(readlink -f "$candidate")"
      sudo ln -sf "$resolved" /usr/local/bin/bpftool
      echo "Using bpftool (from package file list): $resolved"
      sudo /usr/local/bin/bpftool version
      return 0
    fi
  done < <(dpkg -L "linux-tools-${kver}" 2>/dev/null | grep '/bpftool$' || true)

  # Any kernel tools tree on the runner is fine for `bpftool btf dump`.
  while IFS= read -r candidate; do
    if bpftool_usable "$candidate"; then
      resolved="$(readlink -f "$candidate")"
      sudo ln -sf "$resolved" /usr/local/bin/bpftool
      echo "Using bpftool (discovered): $resolved"
      sudo /usr/local/bin/bpftool version
      return 0
    fi
  done < <(find /usr/lib -name bpftool 2>/dev/null)

  if command -v bpftool >/dev/null 2>&1 && bpftool version >/dev/null 2>&1; then
    echo "Using bpftool: $(command -v bpftool)"
    bpftool version
    return 0
  fi

  # Deliberately not ::error:: - this function is called again after installing a
  # fallback tools package, and that retry usually succeeds. Annotating the run
  # as failed here made every green release look broken, which is a good way to
  # train yourself to ignore real errors. Only the caller's final failure is an
  # error.
  echo "::warning::bpftool not usable for kernel ${kver} after installing: ${TOOL_PKGS[*]}; trying fallbacks"
  ls -la /usr/lib/linux-tools/ 2>/dev/null || true
  find /usr/lib -name 'bpftool*' -ls 2>/dev/null || true
  return 1
}

finish() {
  if [ -n "${GITHUB_PATH:-}" ]; then
    echo "/usr/local/bin" >> "$GITHUB_PATH"
  fi
}

if resolve_bpftool "$KVER"; then
  finish
  exit 0
fi

# Running kernel tools may no longer be published; any recent bpftool can dump BTF.
fallback="$(apt-cache search --names-only '^linux-azure-.*-tools-' 2>/dev/null | awk '{print $1}' | sort -V | tail -1 || true)"
if [ -n "$fallback" ]; then
  echo "Trying fallback tools package: $fallback"
  sudo DEBIAN_FRONTEND=noninteractive apt-get install -y --no-upgrade "$fallback"
  if resolve_bpftool "$KVER"; then
    finish
    exit 0
  fi
fi

echo "::error::bpftool not found for kernel ${KVER}"
exit 1
