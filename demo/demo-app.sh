#!/bin/sh
# KernelSeal Demo Application
#
# Started via: kernelseal-exec -- /demo/demo-app.sh
#
# The shim fetches this script's secrets from the agent and applies them to the
# environment before exec'ing it, so they are read here as ordinary environment
# variables. The same shim handshake marks this PID protected first, which is why
# the environment is unreadable from outside the process.

set -eu

mask() {
    value="$1"
    length=$(printf '%s' "$value" | wc -c)
    if [ "$length" -le 4 ]; then
        printf '****'
    else
        printf '%.4s… (%s chars)' "$value" "$length"
    fi
}

echo "=========================================="
echo "  KernelSeal Demo Application"
echo "=========================================="
echo "PID: $$"
echo ""

echo "Secrets received from KernelSeal:"
missing=0
for name in DEMO_API_KEY DEMO_DB_PASSWORD; do
    value=$(printenv "$name" 2>/dev/null || true)
    if [ -n "$value" ]; then
        printf '  %s = %s\n' "$name" "$(mask "$value")"
    else
        printf '  %s is NOT set\n' "$name"
        missing=1
    fi
done
echo ""

if [ "$missing" -eq 1 ]; then
    echo "Some secrets are missing. Check that:"
    echo "  - the agent is running and its socket is reachable"
    echo "  - the config binds secrets to the binary \"demo-app.sh\""
    echo "  - the source variables are set in the agent's environment"
    echo ""
fi

# allowSelfRead is on by default, so a process may inspect its own environment.
echo "Reading our own /proc/$$/environ (allowed by allowSelfRead):"
if head -c 64 "/proc/$$/environ" >/dev/null 2>&1; then
    echo "  readable, as expected"
else
    echo "  refused - allowSelfRead is disabled in the active policy"
fi
echo ""

echo "From another shell on this host, confirm the protection:"
echo "  cat /proc/$$/environ    # expect: Operation not permitted"
echo "  curl -s localhost:9090/metrics | grep kernelseal_access_blocked_total"
echo ""

echo "Running. Press Ctrl+C to stop."
while true; do
    sleep 30
done
