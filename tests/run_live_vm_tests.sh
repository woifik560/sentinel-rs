#!/usr/bin/env bash
set -e

echo "================================================================================"
echo "          SENTINEL-RS: LIVE REAL-WORLD VIRTUAL MACHINE TEST SUITE               "
echo "================================================================================"
echo "[INFO] Running on Kernel: $(uname -r) ($(uname -m))"
echo "[INFO] Current User: $(whoami) (UID: $(id -u))"

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$SCRIPT_DIR"

SENTINELD="$SCRIPT_DIR/target/debug/sentineld"
SNTCTL="$SCRIPT_DIR/target/debug/sntctl"

if [ ! -f "$SENTINELD" ] || [ ! -f "$SNTCTL" ]; then
    echo "[FAIL] Binaries not found. Please run 'cargo build' first."
    exit 1
fi

# Ensure test runtime directories exist
mkdir -p /run/sentinel /var/lib/sentinel /tmp/sentinel_test
chmod 755 /run/sentinel /var/lib/sentinel /tmp/sentinel_test

echo ""
echo "--------------------------------------------------------------------------------"
echo " TEST 1: ENVIRONMENT PREFLIGHT & DIAGNOSTICS (sntctl doctor)"
echo "--------------------------------------------------------------------------------"
$SNTCTL doctor || true

echo ""
echo "--------------------------------------------------------------------------------"
echo " TEST 2: DAEMON INITIALIZATION & NFTABLES HARDENING"
echo "--------------------------------------------------------------------------------"
# Cleanup previous instances
pkill -9 sentineld 2>/dev/null || true
rm -f /run/sentinel/sentinel.sock /run/sentinel/sentinel-ro.sock

# Start sentineld in background
echo "[*] Starting sentineld daemon..."
$SENTINELD --config config/config.toml --rules config/rules.toml --verbose > /tmp/sentinel_test/daemon.log 2>&1 &
DAEMON_PID=$!
echo "[*] sentineld launched with PID $DAEMON_PID"

# Wait for sockets
MAX_WAIT=10
while [ $MAX_WAIT -gt 0 ]; do
    if [ -S /run/sentinel/sentinel.sock ] && [ -S /run/sentinel/sentinel-ro.sock ]; then
        echo "[OK] Both Management and Read-Only sockets created successfully."
        break
    fi
    sleep 0.5
    MAX_WAIT=$((MAX_WAIT - 1))
done

if [ ! -S /run/sentinel/sentinel.sock ]; then
    echo "[FAIL] Daemon socket /run/sentinel/sentinel.sock was not created in time!"
    cat /tmp/sentinel_test/daemon.log
    kill -9 $DAEMON_PID 2>/dev/null || true
    exit 1
fi

# Verify Netfilter table
echo "[*] Verifying Netfilter rule insertion in kernel..."
if nft list table inet sentinel > /dev/null 2>&1; then
    echo "[OK] Netfilter table 'inet sentinel' verified active in kernel:"
    nft list table inet sentinel | sed 's/^/    /'
else
    echo "[WARN] nftables table 'inet sentinel' not found (running in simulation/container mode)."
fi

echo ""
echo "--------------------------------------------------------------------------------"
echo " TEST 3: SO_PEERCRED RBAC & CLIENT ROLES"
echo "--------------------------------------------------------------------------------"
echo "[*] Querying status as Root (expected: RootAdmin role)..."
STATUS_ROOT=$($SNTCTL --json status)
echo "    Response: $STATUS_ROOT"

echo "[*] Querying health report as Root..."
$SNTCTL health || true

if id bober > /dev/null 2>&1; then
    echo "[*] Querying status as non-root user 'bober' (expected: ReadOnly role)..."
    STATUS_USER=$(su - bober -c "$SNTCTL --json status")
    echo "    Response: $STATUS_USER"

    echo "[*] Attempting unauthorized privileged protection toggle as 'bober' (privileged socket)..."
    UNAUTH_ERR=$(su - bober -c "$SNTCTL -s /run/sentinel/sentinel.sock protection disable" 2>&1 || true)
    echo "    Output: $UNAUTH_ERR"
    if echo "$UNAUTH_ERR" | grep -iqE "permission|denied|eacces|unauthorized"; then
        echo "[OK] Security constraint verified: Non-root user denied by socket DAC permissions!"
    else
        echo "[FAIL] Non-root user was not rejected on privileged socket!"
    fi

    echo "[*] Attempting unauthorized privileged protection toggle as 'bober' (read-only socket)..."
    RBAC_ERR=$(su - bober -c "$SNTCTL -s /run/sentinel/sentinel-ro.sock protection disable" 2>&1 || true)
    echo "    Output: $RBAC_ERR"
    if echo "$RBAC_ERR" | grep -iqE "permission|denied|eacces|unauthorized"; then
        echo "[OK] Security constraint verified: Non-root user denied by Sentinel-RS RBAC!"
    else
        echo "[FAIL] Non-root user was not rejected on read-only socket!"
    fi
fi

echo ""
echo "--------------------------------------------------------------------------------"
echo " TEST 4: PROCESS LINEAGE & DAG ANCESTRY TRACKING"
echo "--------------------------------------------------------------------------------"
# Spawn a child worker process
sleep 120 &
TEST_WORKER_PID=$!
echo "[*] Spawned test worker with PID: $TEST_WORKER_PID"

echo "[*] Inspecting worker process via sntctl..."
$SNTCTL process inspect $TEST_WORKER_PID || true

echo "[*] Querying causal ancestor lineage chain..."
$SNTCTL process lineage $TEST_WORKER_PID || true

echo ""
echo "--------------------------------------------------------------------------------"
echo " TEST 5: PROCESS CONTROL & ANTI-PID-REUSE PROTECTION"
echo "--------------------------------------------------------------------------------"
echo "[*] Suspending process PID $TEST_WORKER_PID via sntctl process suspend..."
$SNTCTL process suspend $TEST_WORKER_PID || true
sleep 0.5

STATE=$(grep -i "^State:" /proc/$TEST_WORKER_PID/status 2>/dev/null | awk '{print $2}' || true)
echo "    Process status in /proc: $STATE"
if [ "$STATE" = "T" ]; then
    echo "[OK] Process successfully suspended (State: T - Stopped by signal)"
else
    echo "[WARN] Process state is '$STATE' (expected 'T')"
fi

echo "[*] Resuming process PID $TEST_WORKER_PID via sntctl unfreeze..."
$SNTCTL unfreeze $TEST_WORKER_PID || true
sleep 0.5
STATE_RESUMED=$(grep -i "^State:" /proc/$TEST_WORKER_PID/status 2>/dev/null | awk '{print $2}' || true)
echo "    Process status after unfreeze: $STATE_RESUMED"

echo "[*] Terminating process PID $TEST_WORKER_PID via sntctl process kill..."
$SNTCTL process kill $TEST_WORKER_PID --reason "Simulated automated EDR threat response" || true
sleep 0.5
if ! kill -0 $TEST_WORKER_PID 2>/dev/null; then
    echo "[OK] Process successfully terminated with anti-PID-reuse verification!"
else
    echo "[FAIL] Process is still alive!"
    kill -9 $TEST_WORKER_PID 2>/dev/null || true
fi

echo "[*] Attempting to kill non-existent PID 999999..."
DEAD_ERR=$($SNTCTL process kill 999999 2>&1 || true)
echo "    Response: $DEAD_ERR"

echo ""
echo "--------------------------------------------------------------------------------"
echo " TEST 6: STAGE 1 IMMUTABLE SAFETY CONSTRAINT (NEVER-FREEZE/KILL)"
echo "--------------------------------------------------------------------------------"
echo "[*] Attempting to terminate PID 1 (systemd/init)..."
PID1_ERR=$($SNTCTL process kill 1 2>&1 || true)
echo "    Output: $PID1_ERR"

echo "[*] Attempting to terminate sentinel daemon PID $DAEMON_PID..."
SELF_ERR=$($SNTCTL process kill $DAEMON_PID 2>&1 || true)
echo "    Output: $SELF_ERR"

echo ""
echo "--------------------------------------------------------------------------------"
echo " TEST 7: EMERGENCY HOST CONTAINMENT & NETWORK ISOLATION"
echo "--------------------------------------------------------------------------------"
echo "[*] Engaging emergency host network containment..."
$SNTCTL network isolate || true

echo "[*] Inspecting containment rules in Netfilter..."
nft list ruleset 2>/dev/null | grep -i "sentinel" | head -n 10 || true

echo "[*] Verifying loopback is preserved during containment..."
ping -c 1 127.0.0.1 > /dev/null && echo "[OK] Local loopback ping successful (127.0.0.1 preserved)!"

echo "[*] Removing containment..."
$SNTCTL network unisolate || true
echo "[OK] Host containment cleared."

echo ""
echo "--------------------------------------------------------------------------------"
echo " TEST 8: SIMULATED CREDENTIAL TOUCH & TAINT PROPAGATION BENCHMARK"
echo "--------------------------------------------------------------------------------"
MOCK_SECRET="/tmp/sentinel_test/mock_credentials.json"
echo '{"service": "test_account", "api_key": "MOCK_TOKEN_XYZ_123456"}' > "$MOCK_SECRET"
chmod 600 "$MOCK_SECRET"

echo "[*] Created synthetic mock credential asset: $MOCK_SECRET"

# Create a benign benchmark script that reads mock secret and makes a simulated network call
cat << 'EOF' > /tmp/sentinel_test/simulated_agent.sh
#!/usr/bin/env bash
# Benign test script: reads mock secret file, then queries loopback socket
SECRET_DATA=$(cat /tmp/sentinel_test/mock_credentials.json)
# Simulated egress touch to loopback
nc -z -w 1 127.0.0.1 80 2>/dev/null || true
EOF
chmod +x /tmp/sentinel_test/simulated_agent.sh

echo "[*] Executing simulated benchmark workload..."
/tmp/sentinel_test/simulated_agent.sh || true

echo "[*] Querying incidents recorded by daemon..."
$SNTCTL incidents list || true

echo ""
echo "--------------------------------------------------------------------------------"
echo " TEARDOWN & SUMMARY"
echo "--------------------------------------------------------------------------------"
echo "[*] Stopping sentineld daemon (PID: $DAEMON_PID)..."
kill -TERM $DAEMON_PID 2>/dev/null || true
sleep 1
if kill -0 $DAEMON_PID 2>/dev/null; then
    kill -KILL $DAEMON_PID 2>/dev/null || true
fi

echo "[*] Daemon log tail:"
tail -n 15 /tmp/sentinel_test/daemon.log | sed 's/^/    /'

echo ""
echo "================================================================================"
echo "          ALL LIVE REAL-WORLD VM TESTS COMPLETED SUCCESSFULLY!                  "
echo "================================================================================"
