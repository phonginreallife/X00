#!/usr/bin/env bash
# End-to-end test of KernelSeal against a real Node service.
#
# What this proves, in order:
#
#   1. Secrets reach the app's environment through the shim handshake.
#   2. The app can use them (issues and verifies a signed token).
#   3. The app can read its own /proc files (allowSelfRead).
#   4. Nobody else can: environ, mem and maps all return EPERM.
#   5. Protection survives OS threads exiting inside the running process. This is
#      the regression that shipped in v3.0.0: sched_process_exit fires per thread,
#      and a sibling thread's exit used to be reported as the process exiting.
#
# Run from the repository root. Needs root for BPF, and a kernel booted with bpf
# in its lsm= list for steps 4 and 5 to mean anything.

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$(dirname "$SCRIPT_DIR")"
cd "$PROJECT_ROOT"

RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m'

CONFIG=examples/node-demo.yaml
APP=demo/node-app/server.js
PORT="${PORT:-8080}"
METRICS_PORT=9099
SECRET_DIR=/run/kernelseal-demo
API_KEY_FILE="$SECRET_DIR/api-key"

AGENT_PID=""
APP_PID=""
AGENT_LOG="$(mktemp -t kernelseal-agent-XXXXXX.log)"
APP_LOG="$(mktemp -t kernelseal-app-XXXXXX.log)"

FAILURES=0

pass() { echo -e "  ${GREEN}PASS${NC}  $1"; }
fail() { echo -e "  ${RED}FAIL${NC}  $1"; FAILURES=$((FAILURES + 1)); }
info() { echo -e "  ${BLUE}·${NC}     $1"; }
warn() { echo -e "  ${YELLOW}!${NC}     $1"; }

cleanup() {
    local status=$?
    echo ""
    echo -e "${BLUE}Cleaning up...${NC}"

    [ -n "$APP_PID" ] && kill "$APP_PID" 2>/dev/null || true
    [ -n "$AGENT_PID" ] && kill "$AGENT_PID" 2>/dev/null || true
    wait 2>/dev/null || true

    # The API key must not outlive the demo.
    rm -f "$API_KEY_FILE"
    rmdir "$SECRET_DIR" 2>/dev/null || true

    if [ "$status" -ne 0 ] || [ "$FAILURES" -ne 0 ]; then
        echo -e "${YELLOW}Agent log: $AGENT_LOG${NC}"
        echo -e "${YELLOW}App log:   $APP_LOG${NC}"
    else
        rm -f "$AGENT_LOG" "$APP_LOG"
    fi
}
trap cleanup EXIT

echo -e "${BLUE}==============================================================${NC}"
echo -e "${BLUE}       KernelSeal end-to-end test: real Node service${NC}"
echo -e "${BLUE}==============================================================${NC}"
echo ""

# ---------------------------------------------------------------------------
# Preflight
# ---------------------------------------------------------------------------
echo -e "${BLUE}[1/7] Preflight${NC}"

if [ "$EUID" -ne 0 ]; then
    fail "must run as root (BPF program loading needs it)"
    # Not sudo -E: many sudoers configurations refuse it outright with
    # "preserving the entire environment is not supported", and sudo's
    # secure_path would then hide a node installed under nvm. Passing PATH
    # explicitly works everywhere; this script sets its own secret values.
    echo -e "${YELLOW}      Try: sudo env \"PATH=\$PATH\" $0${NC}"
    exit 1
fi
pass "running as root"

command -v node >/dev/null || { fail "node not found on PATH"; exit 1; }
pass "node $(node --version)"

command -v curl >/dev/null || { fail "curl not found on PATH"; exit 1; }

if [ ! -r /sys/kernel/security/lsm ]; then
    warn "no /sys/kernel/security/lsm: this kernel has no BPF-LSM (normal on WSL2)"
    warn "delivery is still tested, but nothing can be enforced"
elif ! grep -q bpf /sys/kernel/security/lsm; then
    warn "kernel lsm list has no bpf: $(cat /sys/kernel/security/lsm)"
    warn "boot with lsm=...,bpf for enforcement to work"
else
    pass "BPF-LSM available: $(cat /sys/kernel/security/lsm)"
fi

# A second agent leaves two sets of BPF programs attached with separate
# protected-PID maps, and whichever owns the socket serves the shim. Results are
# then not reproducible, so refuse to run.
#
# The pattern matches the agent by basename, not by build/ path: a stray
# ./kernelseal copied to the repo root is just as capable of attaching its own
# LSM programs, and matching only build/ would leave it running invisibly. The
# trailing ( |$) keeps it from matching kernelseal-exec.
if pgrep -f '(^|/)kernelseal( |$)' >/dev/null 2>&1; then
    fail "another kernelseal agent is already running:"
    pgrep -af '(^|/)kernelseal( |$)' | sed 's/^/          /'
    echo ""
    echo -e "${YELLOW}      Stop them with:${NC}"
    echo -e "${YELLOW}        sudo pkill -f '(^|/)kernelseal( |\$)'; sleep 2${NC}"
    echo -e "${YELLOW}        sudo pkill -9 -f '(^|/)kernelseal( |\$)'   # if any survive${NC}"
    echo ""
    echo -e "${YELLOW}      An agent that outlives SIGTERM is worth reporting: capture${NC}"
    echo -e "${YELLOW}        ps -o pid,stat,wchan:25,cmd -p \$(pgrep -d, -f '(^|/)kernelseal( |\$)')${NC}"
    echo -e "${YELLOW}      before killing it, so the hang can be diagnosed.${NC}"
    exit 1
fi
pass "no other agent running"

for obj in bpf/exec_monitor.bpf.o bpf/lsm_file_protect.bpf.o; do
    [ -f "$obj" ] || { fail "$obj missing; run: make bpf"; exit 1; }
done

# The version string is stamped into the Go binary, not the BPF objects, so a
# rebuilt agent paired with a stale object looks correct and silently leaks. The
# thread-group check reads signal->live, which leaves that type in the object's
# BTF.
if strings bpf/exec_monitor.bpf.o | grep -qx signal_struct; then
    pass "bpf/exec_monitor.bpf.o carries the thread-group exit fix"
else
    fail "bpf/exec_monitor.bpf.o predates the thread-group exit fix; run: make bpf"
    exit 1
fi

[ -x build/kernelseal ] && [ -x build/kernelseal-exec ] || { fail "binaries missing; run: make build"; exit 1; }
pass "agent $(./build/kernelseal -version)"
echo ""

# ---------------------------------------------------------------------------
# Secret sources
# ---------------------------------------------------------------------------
echo -e "${BLUE}[2/7] Preparing secret sources${NC}"

# SECURITY: demo placeholders only. Source real values from a secret manager.
export KERNELSEAL_DEMO_JWT_SECRET="${KERNELSEAL_DEMO_JWT_SECRET:-demo-jwt-$(openssl rand -hex 8 2>/dev/null || echo fallback0011)}"
export KERNELSEAL_DEMO_DATABASE_URL="${KERNELSEAL_DEMO_DATABASE_URL:-postgres://demo:demo@127.0.0.1:5432/demo}"

mkdir -p "$SECRET_DIR"
chmod 700 "$SECRET_DIR"
(umask 077 && printf 'demo-api-key-%s' "$(openssl rand -hex 6 2>/dev/null || echo aabbcc)" > "$API_KEY_FILE")
API_KEY="$(cat "$API_KEY_FILE")"

pass "JWT_SECRET via envRef, DATABASE_URL via envRef"
pass "API_KEY via fileRef $API_KEY_FILE (mode $(stat -c %a "$API_KEY_FILE"))"
echo ""

# ---------------------------------------------------------------------------
# Agent
# ---------------------------------------------------------------------------
echo -e "${BLUE}[3/7] Starting the agent${NC}"

./build/kernelseal \
    -config "$CONFIG" \
    -exec-monitor bpf/exec_monitor.bpf.o \
    -lsm bpf/lsm_file_protect.bpf.o \
    >"$AGENT_LOG" 2>&1 &
AGENT_PID=$!

for _ in $(seq 1 50); do
    grep -q 'KernelSeal running' "$AGENT_LOG" && break
    kill -0 "$AGENT_PID" 2>/dev/null || { fail "agent exited during startup"; cat "$AGENT_LOG"; exit 1; }
    sleep 0.2
done
grep -q 'KernelSeal running' "$AGENT_LOG" || { fail "agent did not come up"; cat "$AGENT_LOG"; exit 1; }
pass "agent running (pid $AGENT_PID)"

# The single most useful line in the log: zero secrets means the shim will be
# told Protected=false and the process is never guarded, which is
# indistinguishable from enforcement being broken.
REGISTERED="$(grep -oP '\[REGISTER\] \K\d+(?= secrets registered for binary: node)' "$AGENT_LOG" | tail -1 || true)"
if [ "${REGISTERED:-0}" -ge 3 ]; then
    pass "$REGISTERED secrets registered for binary: node"
else
    fail "only ${REGISTERED:-0} secrets registered for node, expected 3"
    grep -E '\[WARN\]|\[REGISTER\]' "$AGENT_LOG" | sed 's/^/          /'
    exit 1
fi

grep -q 'LSM BPF programs loaded and attached' "$AGENT_LOG" \
    && pass "LSM programs attached" \
    || warn "LSM programs not attached; enforcement checks will fail"
echo ""

# ---------------------------------------------------------------------------
# App through the shim
# ---------------------------------------------------------------------------
echo -e "${BLUE}[4/7] Starting the app through the shim${NC}"

PORT="$PORT" ./build/kernelseal-exec -- node "$APP" >"$APP_LOG" 2>&1 &
APP_PID=$!

for _ in $(seq 1 75); do
    curl -sf "http://127.0.0.1:$PORT/healthz" >/dev/null 2>&1 && break
    kill -0 "$APP_PID" 2>/dev/null || { fail "app exited during startup"; cat "$APP_LOG"; exit 1; }
    sleep 0.2
done

if ! curl -sf "http://127.0.0.1:$PORT/healthz" >/dev/null 2>&1; then
    fail "app never became healthy"
    cat "$APP_LOG"
    exit 1
fi
pass "app healthy on 127.0.0.1:$PORT (pid $APP_PID)"

# The shim execs in place, so the pid it was launched with is now node itself.
COMM="$(cat "/proc/$APP_PID/comm" 2>/dev/null || echo '?')"
[ "$COMM" = "node" ] && pass "pid $APP_PID is now 'node' (shim exec'd in place)" \
                     || fail "pid $APP_PID has comm '$COMM', expected 'node'"
echo ""

# ---------------------------------------------------------------------------
# Delivery and use
# ---------------------------------------------------------------------------
echo -e "${BLUE}[5/7] Secret delivery and use${NC}"

WHOAMI="$(curl -sf "http://127.0.0.1:$PORT/whoami")"
node -e '
  const w = JSON.parse(process.argv[1]);
  const need = ["JWT_SECRET", "API_KEY"];
  const bad = need.filter((n) => !w.secrets[n] || !w.secrets[n].present);
  if (bad.length) { console.error("missing: " + bad.join(", ")); process.exit(1); }
  if (!w.secrets.DATABASE_URL.present) { console.error("DATABASE_URL missing"); process.exit(1); }
' "$WHOAMI" && pass "app reports all three secrets present" \
            || fail "app is missing secrets: $WHOAMI"

# A token that verifies proves JWT_SECRET arrived byte-for-byte, and the 200 on
# /login proves the same for API_KEY.
TOKEN="$(curl -sf -X POST "http://127.0.0.1:$PORT/login" \
    -H "x-api-key: $API_KEY" -H 'content-type: application/json' \
    -d '{"user":"demo"}' | node -e 'process.stdout.write(JSON.parse(require("fs").readFileSync(0,"utf8")).token||"")')"

if [ -n "$TOKEN" ]; then
    pass "POST /login issued a token (API_KEY accepted)"
else
    fail "POST /login did not return a token"
fi

if [ -n "$TOKEN" ] && curl -sf "http://127.0.0.1:$PORT/me" -H "Authorization: Bearer $TOKEN" \
        | grep -q '"sub":"demo"'; then
    pass "GET /me verified the token (JWT_SECRET intact end to end)"
else
    fail "GET /me did not verify the token"
fi

# Wrong key must be rejected, or the check above proves nothing.
if [ "$(curl -s -o /dev/null -w '%{http_code}' -X POST "http://127.0.0.1:$PORT/login" \
        -H 'x-api-key: not-the-key')" = "401" ]; then
    pass "POST /login rejects a wrong API key"
else
    fail "POST /login accepted a wrong API key"
fi

if grep -qF "$API_KEY" "$APP_LOG" || grep -qF "$KERNELSEAL_DEMO_JWT_SECRET" "$APP_LOG"; then
    fail "a secret value leaked into the app log"
else
    pass "no secret value appears in the app log"
fi
echo ""

# ---------------------------------------------------------------------------
# Enforcement
# ---------------------------------------------------------------------------
echo -e "${BLUE}[6/7] Kernel enforcement${NC}"

if command -v bpftool >/dev/null 2>&1; then
    if bpftool map dump name protected_pids 2>/dev/null | grep -q .; then
        pass "protected_pids is populated"
    else
        fail "protected_pids is empty; the app was never marked protected"
    fi
fi

# allowSelfRead is on, so the process may inspect itself. It reported its own
# secret fingerprints above, which is that path already exercised.
if [ "$(curl -s -o /dev/null -w '%{http_code}' "http://127.0.0.1:$PORT/whoami")" = "200" ]; then
    pass "app can still read its own environment (allowSelfRead)"
fi

check_blocked() {
    local file="$1" out rc
    out="$(cat "/proc/$APP_PID/$file" 2>&1 >/dev/null)" && rc=0 || rc=$?

    if [ "$rc" -ne 0 ] && printf '%s' "$out" | grep -qi 'not permitted'; then
        pass "reading /proc/$APP_PID/$file from outside is denied (EPERM)"
    else
        fail "reading /proc/$APP_PID/$file from outside SUCCEEDED (rc=$rc) - secrets are exposed"
    fi
}

check_blocked environ
check_blocked mem
check_blocked maps

if command -v gdb >/dev/null 2>&1; then
    if gdb -p "$APP_PID" -batch -ex quit >/dev/null 2>&1; then
        fail "gdb attached to the protected process"
    else
        pass "ptrace attach is denied"
    fi
else
    info "gdb not installed, skipping the ptrace check"
fi
echo ""

# ---------------------------------------------------------------------------
# The regression
# ---------------------------------------------------------------------------
echo -e "${BLUE}[7/7] Protection survives thread exits${NC}"

# This is what a sleeping process cannot test. Each worker is a real OS thread,
# and every one of them exits while the process keeps running and keeps its
# secrets. Before the fix, the first of these exits was reported as the process
# exiting and user space dropped the PID from protected_pids.
CHURN="$(curl -sf -X POST "http://127.0.0.1:$PORT/workers?n=8")"
EXITED="$(printf '%s' "$CHURN" | node -e 'process.stdout.write(String(JSON.parse(require("fs").readFileSync(0,"utf8")).exited||0))')"

if [ "${EXITED:-0}" -ge 8 ]; then
    pass "$EXITED OS threads spawned and exited inside pid $APP_PID"
else
    fail "expected at least 8 thread exits, got ${EXITED:-0}: $CHURN"
fi

# Give the exit events time to travel the ring buffer and be handled.
sleep 1

if curl -sf "http://127.0.0.1:$PORT/healthz" >/dev/null 2>&1; then
    pass "app is still running after the thread churn"
else
    fail "app died during the thread churn"
fi

check_blocked environ

if command -v bpftool >/dev/null 2>&1; then
    if bpftool map dump name protected_pids 2>/dev/null | grep -q .; then
        pass "protected_pids still populated after the thread churn"
    else
        fail "protected_pids emptied by the thread churn - this is the v3.0.0 leak"
    fi
fi

if grep -q 'Ignoring exit event' "$AGENT_LOG"; then
    fail "agent logged 'Ignoring exit event' (the reverted v3.0.1 guard is present)"
else
    pass "no reverted-guard warnings in the agent log"
fi
echo ""

# ---------------------------------------------------------------------------
echo -e "${BLUE}==============================================================${NC}"
if [ "$FAILURES" -eq 0 ]; then
    echo -e "${GREEN}All checks passed.${NC}"
    echo ""
    echo "Blocked access attempts recorded by the agent:"
    curl -s "http://127.0.0.1:$METRICS_PORT/metrics" 2>/dev/null \
        | grep -E '^kernelseal_(access_blocked|secrets_issued|protected_pids)' | sed 's/^/  /' || true
else
    echo -e "${RED}$FAILURES check(s) failed.${NC}"
fi
echo -e "${BLUE}==============================================================${NC}"

exit "$FAILURES"
