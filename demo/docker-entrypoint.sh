#!/bin/bash
# KernelSeal all-in-one demo entrypoint.
#
# Starts the agent, then tells you how to launch a process through the shim and
# confirm that its environment is unreadable from outside.

set -euo pipefail

echo "=============================================================="
echo "            KernelSeal Secret Protection Demo"
echo "=============================================================="
echo ""

# SECURITY: these are placeholder values for the demo only. Never use them in
# production; source real values from a secret manager.
export KERNELSEAL_DEMO_API_KEY="${KERNELSEAL_DEMO_API_KEY:-demo-placeholder-api-key}"
export KERNELSEAL_DEMO_DB_PASSWORD="${KERNELSEAL_DEMO_DB_PASSWORD:-demo-placeholder-password}"
export KERNELSEAL_DEMO_SECRET="${KERNELSEAL_DEMO_SECRET:-demo-placeholder-secret}"

echo "Demo configuration:"
echo "   API_KEY: ${KERNELSEAL_DEMO_API_KEY:0:15}..."
echo "   DB_PASS: ${KERNELSEAL_DEMO_DB_PASSWORD:0:10}..."
echo ""

# Secrets are bound to the binaries the shim will exec. Wrapping `sleep` keeps the
# demo easy to reason about: it is a long-lived process with a stable PID.
cat > /etc/kernelseal/config.yaml << 'EOF'
version: v1

policy:
  mode: enforce
  blockEnviron: true
  blockMem: true
  blockMaps: false
  blockPtrace: true
  allowSelfRead: true
  auditAll: false
  kernelBinaryFilter: true

secrets:
  - name: sleep-demo
    selector:
      binary: "sleep"
    secretRefs:
      - name: DEMO_API_KEY
        source:
          envRef: "KERNELSEAL_DEMO_API_KEY"
      - name: DEMO_DB_PASSWORD
        source:
          envRef: "KERNELSEAL_DEMO_DB_PASSWORD"

  - name: demo-app
    selector:
      binary: "demo-app.sh"
    secretRefs:
      - name: DEMO_SECRET
        source:
          envRef: "KERNELSEAL_DEMO_SECRET"

monitoring:
  enabled: true
  metricsPort: 9090
  logLevel: info
EOF

echo "Starting KernelSeal..."
echo ""
echo "--------------------------------------------------------------"
echo "From another terminal, start a process through the shim:"
echo ""
echo "  docker exec -d kernelseal-demo \\"
echo "    /usr/local/bin/kernelseal-exec -- sleep 600"
echo ""
echo "Then find its PID and try to read its environment:"
echo ""
echo "  docker exec -it kernelseal-demo pgrep -x sleep"
echo "  docker exec -it kernelseal-demo cat /proc/<pid>/environ"
echo "      expected: Operation not permitted"
echo ""
echo "Check the counters:"
echo ""
echo "  docker exec -it kernelseal-demo \\"
echo "    wget -qO- localhost:9090/metrics | grep kernelseal_"
echo ""
echo "Watch this terminal for [ISSUE] on delivery and [LSM BLOCKED] on denial."
echo "--------------------------------------------------------------"
echo ""

exec /usr/local/bin/kernelseal \
    -config /etc/kernelseal/config.yaml \
    -exec-monitor /bpf/exec_monitor.bpf.o \
    -lsm /bpf/lsm_file_protect.bpf.o
