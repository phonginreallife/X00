#!/bin/bash
# KernelSeal local demo.
#
# Builds everything, starts the agent, and prints the commands to launch a
# process through the shim and confirm its environment is protected.

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$(dirname "$SCRIPT_DIR")"
cd "$PROJECT_ROOT"

RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m'

echo -e "${BLUE}==============================================================${NC}"
echo -e "${BLUE}            KernelSeal Secret Protection Demo${NC}"
echo -e "${BLUE}==============================================================${NC}"
echo ""

# Locate the Go toolchain.
#
# Under sudo this needs care: sudo's secure_path replaces PATH, and a Go
# installed at /usr/local/go/bin is not on it. Rather than fail with a bare
# "go: command not found", look in the usual places and in the invoking user's
# home if we were escalated.
find_go() {
    if command -v go &> /dev/null; then
        command -v go
        return 0
    fi

    local candidates=(/usr/local/go/bin/go /usr/lib/go/bin/go /snap/bin/go /opt/go/bin/go)

    if [ -n "${SUDO_USER:-}" ]; then
        local home
        home="$(getent passwd "$SUDO_USER" | cut -d: -f6)"
        if [ -n "$home" ]; then
            candidates+=("$home/go/bin/go" "$home/.local/go/bin/go")
        fi
    fi

    local candidate
    for candidate in "${candidates[@]}"; do
        if [ -x "$candidate" ]; then
            echo "$candidate"
            return 0
        fi
    done

    return 1
}

if ! GO="$(find_go)"; then
    echo -e "${RED}Could not find the go toolchain.${NC}"
    if [ "$EUID" -eq 0 ]; then
        echo -e "${YELLOW}  Running under sudo replaces PATH with secure_path, so a Go${NC}"
        echo -e "${YELLOW}  installed outside it is invisible. Run this script without sudo;${NC}"
        echo -e "${YELLOW}  it will ask for privileges only when it needs them.${NC}"
    else
        echo -e "${YELLOW}  Install Go 1.22+ and make sure it is on your PATH.${NC}"
    fi
    exit 1
fi
export PATH="$(dirname "$GO"):$PATH"

CONFIG=examples/demo-config.yaml

# Without BPF-LSM there is nothing to enforce with. Say so clearly, and explain
# the one-line change that still makes the delivery half of the demo work,
# because in enforce mode the agent deliberately refuses to hand out secrets it
# cannot protect and the demo would otherwise look broken.
explain_no_lsm() {
    echo -e "${YELLOW}  Consequence: in enforce mode the agent refuses to release secrets,${NC}"
    echo -e "${YELLOW}  which is intended fail-closed behavior. The demo app will start but${NC}"
    echo -e "${YELLOW}  report its secrets as NOT set.${NC}"
    echo ""
    echo -e "${YELLOW}  To watch secret delivery work anyway, set this in $CONFIG:${NC}"
    echo -e "${YELLOW}      mode: audit${NC}"
    echo -e "${YELLOW}  Secrets are then delivered and the shim warns that the kernel is not${NC}"
    echo -e "${YELLOW}  guarding them. Blocking still needs a kernel booted with lsm=...,bpf.${NC}"
    echo ""
}

if [ ! -r /sys/kernel/security/lsm ]; then
    echo -e "${YELLOW}Warning: /sys/kernel/security/lsm is not readable, so this kernel has${NC}"
    echo -e "${YELLOW}  no BPF-LSM support. This is normal on WSL2 and most stock kernels.${NC}"
    explain_no_lsm
elif ! grep -q bpf /sys/kernel/security/lsm; then
    echo -e "${YELLOW}Warning: this kernel's lsm list does not include bpf:${NC}"
    echo -e "${YELLOW}  $(cat /sys/kernel/security/lsm)${NC}"
    explain_no_lsm
fi

CURRENT_MODE="$(grep -E '^\s*mode:' "$CONFIG" | head -1 | awk '{print $2}')"

# SECURITY: placeholder values for the demo only. Never use these in production;
# source real values from a secret manager.
export KERNELSEAL_DEMO_API_KEY="${KERNELSEAL_DEMO_API_KEY:-demo-placeholder-api-key}"
export KERNELSEAL_DEMO_DB_PASSWORD="${KERNELSEAL_DEMO_DB_PASSWORD:-demo-placeholder-password}"
export KERNELSEAL_DEMO_SECRET="${KERNELSEAL_DEMO_SECRET:-demo-placeholder-secret}"

echo -e "${GREEN}Demo secret values are set in this shell's environment.${NC}"
echo ""

if [ ! -f "bpf/exec_monitor.bpf.o" ]; then
    echo -e "${BLUE}Compiling BPF programs...${NC}"
    if ! command -v clang &> /dev/null; then
        echo -e "${RED}clang not found.${NC}"
        echo -e "${YELLOW}  Install clang and llvm, or build in Docker: make docker-dev${NC}"
        exit 1
    fi
    make bpf || {
        echo -e "${RED}BPF compilation failed.${NC}"
        echo -e "${YELLOW}  Try: make docker-dev (requires Docker)${NC}"
        exit 1
    }
fi
echo -e "${GREEN}BPF objects ready.${NC}"

echo -e "${BLUE}Building binaries...${NC}"
make build >/dev/null
echo -e "${GREEN}Built build/kernelseal and build/kernelseal-exec.${NC}"
echo ""

echo -e "${BLUE}==============================================================${NC}"
echo -e "${BLUE}Configuration: examples/demo-config.yaml${NC}"
echo -e "${BLUE}==============================================================${NC}"
echo ""
echo "  Secrets are bound to:"
echo "    sleep         -> DEMO_SECRET"
echo "    demo-app.sh   -> DEMO_API_KEY, DEMO_DB_PASSWORD"
echo ""
echo "  Policy mode: ${CURRENT_MODE:-unknown}"
echo ""
echo -e "${YELLOW}Secrets only reach a process started through the shim.${NC}"
echo ""

echo -e "${BLUE}==============================================================${NC}"
echo -e "${GREEN}Starting the agent...${NC}"
echo -e "${BLUE}==============================================================${NC}"
echo ""
echo -e "${YELLOW}From another terminal, in $(pwd):${NC}"
echo ""
echo "  # Start a process through the shim. Nothing is delivered without this;"
echo "  # a plain 'sleep 600' receives no secrets."
echo "  ./build/kernelseal-exec -- sleep 600 &"
echo ""
echo "  # Confirm it received them (agent logs the names, never the values)"
echo "  #   look for [ISSUE] Released 1 secrets to \"sleep\" [DEMO_SECRET]"
echo ""
echo "  # Its environment is unreadable, even as root"
echo "  sudo cat /proc/\$!/environ      # Operation not permitted"
echo ""
echo "  # ptrace is refused too"
echo "  sudo gdb -p \$!                 # ptrace: Operation not permitted"
echo ""
echo "  # An unwrapped process is untouched"
echo "  sleep 600 & sudo cat /proc/\$!/environ   # readable"
echo ""
echo "  # Counters"
echo "  curl -s localhost:9090/metrics | grep kernelseal_"
echo ""
echo -e "${YELLOW}Press Ctrl+C to stop.${NC}"
echo ""

AGENT_ARGS=(
    -config "$CONFIG"
    -exec-monitor bpf/exec_monitor.bpf.o
    -lsm bpf/lsm_file_protect.bpf.o
)

# The agent runs as root, so a 0660 socket would be reachable only by root and
# the shim would fail with EACCES on connect. Hand the socket to the invoking
# user's group so they can run the shim unprivileged, as a real application would.
DEMO_USER="${SUDO_USER:-$(id -un)}"
if DEMO_GROUP="$(id -gn "$DEMO_USER" 2>/dev/null)"; then
    AGENT_ARGS+=(-socket-group "$DEMO_GROUP")
    echo -e "${BLUE}Socket will be group-owned by ${DEMO_GROUP} so ${DEMO_USER} can reach it.${NC}"
    echo ""
fi

# Only loading BPF programs needs privileges, so escalate here rather than
# requiring the whole script to run as root.
if [ "$EUID" -eq 0 ]; then
    exec ./build/kernelseal "${AGENT_ARGS[@]}"
fi

echo -e "${BLUE}Loading BPF programs requires root; requesting privileges...${NC}"

# --preserve-env keeps the secret values out of the process's argv, where any
# user on the host could read them from ps.
exec sudo --preserve-env=KERNELSEAL_DEMO_API_KEY,KERNELSEAL_DEMO_DB_PASSWORD,KERNELSEAL_DEMO_SECRET \
    ./build/kernelseal "${AGENT_ARGS[@]}"
