#!/usr/bin/env bash
# Install clang/llvm/libbpf and a working bpftool on GitHub-hosted Ubuntu runners.
#
# Ubuntu exposes bpftool as a virtual package. On Azure runners the useful binary
# lives under /usr/lib/linux-tools/<kver>/ (often via symlinks into
# linux-azure-*-tools-*). Using --no-install-recommends on the kernel tools
# packages leaves those symlinks without a binary, so kernel tools are installed
# with recommends enabled.
set -euo pipefail

sudo apt-get update -y

KVER="$(uname -r)"

sudo DEBIAN_FRONTEND=noninteractive apt-get install -y --no-install-recommends \
  clang llvm libbpf-dev linux-tools-common "$@"

TOOL_PKGS=("linux-tools-${KVER}" "linux-cloud-tools-${KVER}")
for pkg in linux-tools-azure linux-cloud-tools-azure; do
  if apt-cache show "$pkg" >/dev/null 2>&1; then
    TOOL_PKGS+=("$pkg")
  fi
done

sudo DEBIAN_FRONTEND=noninteractive apt-get install -y "${TOOL_PKGS[@]}"

resolve_bpftool() {
  local kver="$1"
  local candidate resolved

  for candidate in \
    "/usr/lib/linux-tools/${kver}/bpftool" \
    "/usr/lib/linux-tools/${kver%-azure}/bpftool"; do
    resolved="$(readlink -f "$candidate" 2>/dev/null || true)"
    if [ -n "$resolved" ] && [ -x "$resolved" ]; then
      sudo ln -sf "$resolved" /usr/local/bin/bpftool
      echo "Using bpftool: $resolved"
      /usr/local/bin/bpftool version
      return 0
    fi
  done

  while IFS= read -r candidate; do
    [ -n "$candidate" ] || continue
    resolved="$(readlink -f "$candidate" 2>/dev/null || true)"
    if [ -n "$resolved" ] && [ -x "$resolved" ]; then
      sudo ln -sf "$resolved" /usr/local/bin/bpftool
      echo "Using bpftool (from package file list): $resolved"
      /usr/local/bin/bpftool version
      return 0
    fi
  done < <(dpkg -L "linux-tools-${kver}" 2>/dev/null | grep '/bpftool$' || true)

  while IFS= read -r candidate; do
    resolved="$(readlink -f "$candidate" 2>/dev/null || true)"
    if [ -n "$resolved" ] && [ -x "$resolved" ]; then
      sudo ln -sf "$resolved" /usr/local/bin/bpftool
      echo "Using bpftool (discovered): $resolved"
      /usr/local/bin/bpftool version
      return 0
    fi
  done < <(find /usr/lib -name bpftool \( -type f -o -type l \) 2>/dev/null)

  if command -v bpftool >/dev/null 2>&1 && bpftool version >/dev/null 2>&1; then
    echo "Using bpftool: $(command -v bpftool)"
    bpftool version
    return 0
  fi

  echo "::error::bpftool not found for kernel ${kver} after installing: ${TOOL_PKGS[*]}"
  ls -la /usr/lib/linux-tools/ 2>/dev/null || true
  find /usr/lib -name 'bpftool*' 2>/dev/null || true
  return 1
}

resolve_bpftool "$KVER"

if [ -n "${GITHUB_PATH:-}" ]; then
  echo "/usr/local/bin" >> "$GITHUB_PATH"
fi
