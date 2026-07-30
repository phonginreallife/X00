#!/usr/bin/env bash
# Drives the 40 second demo that gets recorded for the README.
#
# It is deliberately not the full end-to-end test. scripts/run-node-demo.sh
# proves the property; this one shows it. Everything here is real: a real
# agent, a real protected process, and real EPERM from the kernel.
#
# Record it with:
#
#   asciinema rec kernelseal.cast -c 'sudo ./demo/record-demo.sh'
#
# Needs root, and a kernel booted with bpf in its lsm= list. Without that the
# reads below succeed and the recording shows nothing worth showing, so the
# script checks first and refuses.

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$(dirname "$SCRIPT_DIR")"
cd "$PROJECT_ROOT"

DIM='\033[2m'
GREEN='\033[0;32m'
RED='\033[0;31m'
BOLD='\033[1m'
NC='\033[0m'

WORKDIR="$(mktemp -d -t kernelseal-demo-XXXXXX)"
AGENT_LOG="$WORKDIR/agent.log"
AGENT_PID=""
APP_PID=""

cleanup() {
    [ -n "$APP_PID" ] && kill "$APP_PID" 2>/dev/null || true
    [ -n "$AGENT_PID" ] && kill "$AGENT_PID" 2>/dev/null || true
    rm -rf "$WORKDIR"
}
trap cleanup EXIT

# Pacing. A recording that scrolls faster than it can be read is useless, and
# these are the only sleeps in the script.
beat()  { sleep "${DEMO_SPEED:-1.4}"; }
pause() { sleep "$(echo "${DEMO_SPEED:-1.4} * 2" | bc 2>/dev/null || echo 3)"; }

# Echo a command the way a person would type it, then run it.
run() {
    printf "${BOLD}$ %s${NC}\n" "$*"
    beat
    eval "$@" || true
    beat
}

note() {
    printf "${DIM}# %s${NC}\n" "$*"
    beat
}

# --- preflight ------------------------------------------------------------

if [ "$(id -u)" -ne 0 ]; then
    printf "${RED}Run as root. BPF needs it.${NC}\n" >&2
    exit 1
fi

if ! grep -q bpf /sys/kernel/security/lsm 2>/dev/null; then
    printf "${RED}This kernel does not list bpf as an active LSM.${NC}\n" >&2
    printf "Nothing would be blocked, so there is nothing to record.\n" >&2
    printf "Check with: cat /sys/kernel/security/lsm\n" >&2
    exit 1
fi

for f in build/kernelseal build/kernelseal-exec bpf/exec_monitor.bpf.o \
         bpf/lsm_file_protect.bpf.o; do
    if [ ! -f "$f" ]; then
        printf "${RED}Missing %s. Run: make bpf && make build${NC}\n" "$f" >&2
        exit 1
    fi
done

# Something has to actually attempt a ptrace attach. Checked up front rather
# than at the point of use: a missing binary there prints an exec error into the
# middle of the recording, which reads as KernelSeal failing rather than as the
# kernel refusing the attach.
if command -v gdb >/dev/null 2>&1; then
    PTRACE_TOOL=gdb
elif command -v strace >/dev/null 2>&1; then
    PTRACE_TOOL=strace
else
    printf "${RED}Need gdb or strace to demonstrate the ptrace denial.${NC}\n" >&2
    printf "  apt-get install -y gdb\n" >&2
    exit 1
fi

cat > "$WORKDIR/config.yaml" <<'EOF'
version: v1
policy:
  mode: enforce
  blockEnviron: true
  blockMem: true
  blockMaps: true
  blockPtrace: true
  allowSelfRead: true
  kernelBinaryFilter: true
secrets:
  - name: demo
    selector:
      binary: "sh"
    secretRefs:
      - name: DB_PASSWORD
        source:
          envRef: DEMO_DB_PASSWORD
monitoring:
  enabled: false
EOF

clear

# --- the demo -------------------------------------------------------------

printf "${BOLD}KernelSeal: secrets your app can read and root cannot${NC}\n\n"
pause

note "Start the agent. The secret lives in its environment, never on disk."
DEMO_DB_PASSWORD='hunter2-actual-production-password' \
    ./build/kernelseal \
    -config "$WORKDIR/config.yaml" \
    -exec-monitor bpf/exec_monitor.bpf.o \
    -lsm bpf/lsm_file_protect.bpf.o \
    > "$AGENT_LOG" 2>&1 &
AGENT_PID=$!

for _ in $(seq 1 50); do
    grep -q 'LSM BPF programs loaded and attached' "$AGENT_LOG" && break
    sleep 0.1
done
grep -E '\[REGISTER\]|LSM BPF programs loaded' "$AGENT_LOG" | sed 's/^/  /'
pause

note "Start an app through the shim. No SDK, no code changes."
printf "${BOLD}$ kernelseal-exec -- sh -c 'echo \"app reads: \$DB_PASSWORD\"; sleep 300'${NC}\n"
beat
./build/kernelseal-exec -- sh -c 'echo "  app reads: $DB_PASSWORD"; sleep 300' &
APP_PID=$!
sleep 1
pause

note "The app has its secret. Now try to steal it, as root."
run "cat /proc/$APP_PID/environ"
run "cat /proc/$APP_PID/mem"
run "cat /proc/$APP_PID/maps"

note "Even a debugger."
if [ "$PTRACE_TOOL" = gdb ]; then
    run "timeout 5 gdb -p $APP_PID -batch -ex 'info registers' 2>&1 | tail -2"
else
    run "timeout 5 strace -p $APP_PID 2>&1 | head -2"
fi

printf "\n"
note "id -u says 0. The kernel does not care."
run "id -u"

printf "\n${GREEN}${BOLD}The secret was never on disk, never in a volume,${NC}\n"
printf "${GREEN}${BOLD}and is not readable from anywhere but the process itself.${NC}\n"
pause
