#!/bin/bash
# KernelSeal Docker demo runner.
#
# Brings up the agent and a demo application whose entrypoint is wrapped with
# kernelseal-exec, so the app receives its secrets as environment variables while
# the kernel refuses to let anything else read them back.

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$(dirname "$SCRIPT_DIR")"
cd "$SCRIPT_DIR"

RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m'

echo -e "${BLUE}==============================================================${NC}"
echo -e "${BLUE}         KernelSeal Docker Demo - Secret Protection${NC}"
echo -e "${BLUE}==============================================================${NC}"
echo ""

if ! command -v docker &> /dev/null; then
    echo -e "${RED}Docker is not installed.${NC}"
    exit 1
fi

if ! docker info &> /dev/null; then
    echo -e "${RED}The Docker daemon is not running.${NC}"
    exit 1
fi

# Prefer the compose plugin, fall back to the standalone binary.
if docker compose version &> /dev/null; then
    COMPOSE=(docker compose)
elif command -v docker-compose &> /dev/null; then
    COMPOSE=(docker-compose)
else
    echo -e "${RED}Neither 'docker compose' nor 'docker-compose' is available.${NC}"
    exit 1
fi

echo -e "${GREEN}Docker is available.${NC}"

# The BPF compile inside the image needs vmlinux.h from this host's BTF, and it is
# gitignored, so generate it before building.
if [ ! -f "$PROJECT_ROOT/bpf/vmlinux.h" ]; then
    echo -e "${BLUE}Generating bpf/vmlinux.h from the host's BTF...${NC}"
    if [ ! -f /sys/kernel/btf/vmlinux ]; then
        echo -e "${RED}/sys/kernel/btf/vmlinux is missing, so BPF cannot be compiled.${NC}"
        echo -e "${YELLOW}  This kernel lacks CONFIG_DEBUG_INFO_BTF.${NC}"
        exit 1
    fi
    ( cd "$PROJECT_ROOT" && make vmlinux )
fi
echo -e "${GREEN}bpf/vmlinux.h is present.${NC}"
echo ""

if [ ! -r /sys/kernel/security/lsm ] || ! grep -q bpf /sys/kernel/security/lsm; then
    echo -e "${YELLOW}Warning: this kernel does not expose the BPF LSM hook.${NC}"
    echo -e "${YELLOW}  Secret delivery will be refused in enforce mode, which is the${NC}"
    echo -e "${YELLOW}  intended fail-closed behavior. Boot with lsm=...,bpf to enable it.${NC}"
    echo ""
fi

echo -e "${BLUE}Building images...${NC}"
"${COMPOSE[@]}" build

echo ""
echo -e "${GREEN}Starting the demo...${NC}"
echo ""
echo -e "${YELLOW}Two services will start:${NC}"
echo "  kernelseal - the agent: loads BPF and serves secrets over a socket"
echo "  demo-app   - an application started through kernelseal-exec"
echo ""
echo -e "${YELLOW}Watch for:${NC}"
echo "  [ISSUE]        secrets released to the app, names only"
echo "  [PROTECT]      the PID marked protected before release"
echo "  [LSM BLOCKED]  an access attempt refused"
echo ""
echo -e "${YELLOW}To prove it yourself, in another terminal:${NC}"
echo "  docker compose exec demo-app pgrep -f demo-app.sh"
echo "  docker compose exec kernelseal cat /proc/<pid>/environ"
echo "      expected: Operation not permitted"
echo ""
echo -e "${YELLOW}Press Ctrl+C to stop.${NC}"
echo ""

cleanup() {
    echo ""
    echo -e "${BLUE}Cleaning up...${NC}"
    "${COMPOSE[@]}" down --volumes
    echo -e "${GREEN}Demo stopped.${NC}"
}
trap cleanup EXIT

"${COMPOSE[@]}" up
