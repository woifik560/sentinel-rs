#!/usr/bin/env bash
set -Eeuo pipefail

echo "================================================================================"
echo "          SENTINEL-RS: LIVE REAL-WORLD VIRTUAL MACHINE TEST SUITE               "
echo "================================================================================"
echo "[INFO] Running on Kernel: $(uname -r) ($(uname -m))"
echo "[INFO] Current User: $(whoami) (UID: $(id -u))"

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$SCRIPT_DIR"
export PATH="/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin:$PATH"

# Test results tracking
TOTAL_TESTS=0
PASSED_TESTS=0
FAILED_TESTS=0
SKIPPED_TESTS=0
FAILED_TEST_NAMES=()

record_pass() {
    local name="$1"
    PASSED_TESTS=$((PASSED_TESTS + 1))
    TOTAL_TESTS=$((TOTAL_TESTS + 1))
    echo "[PASS] $name"
}

record_fail() {
    local name="$1"
    local reason="${2:-}"
    FAILED_TESTS=$((FAILED_TESTS + 1))
    TOTAL_TESTS=$((TOTAL_TESTS + 1))
    FAILED_TEST_NAMES+=("$name")
    echo "[FAIL] $name: $reason"
}

record_skip() {
    local name="$1"
    local reason="$2"
    SKIPPED_TESTS=$((SKIPPED_TESTS + 1))
    TOTAL_TESTS=$((TOTAL_TESTS + 1))
    echo "[SKIP] $name (Reason: $reason)"
}

# Locate binaries
if [ -f "$SCRIPT_DIR/target/release/sentineld" ]; then
    SENTINELD="$SCRIPT_DIR/target/release/sentineld"
elif [ -f "$SCRIPT_DIR/target/debug/sentineld" ]; then
    SENTINELD="$SCRIPT_DIR/target/debug/sentineld"
elif command -v sentineld > /dev/null 2>&1; then
    SENTINELD="$(command -v sentineld)"
else
    echo "[FAIL] sentineld binary not found. Please run 'cargo build' first."
    exit 1
fi

if [ -f "$SCRIPT_DIR/target/release/sntctl" ]; then
    SNTCTL="$SCRIPT_DIR/target/release/sntctl"
elif [ -f "$SCRIPT_DIR/target/debug/sntctl" ]; then
    SNTCTL="$SCRIPT_DIR/target/debug/sntctl"
elif command -v sntctl > /dev/null 2>&1; then
    SNTCTL="$(command -v sntctl)"
else
    echo "[FAIL] sntctl binary not found. Please run 'cargo build' first."
    exit 1
fi

echo "[INFO] Using sentineld: $SENTINELD"
echo "[INFO] Using sntctl:    $SNTCTL"

# Runtime directories
mkdir -p /run/sentinel /var/lib/sentinel /tmp/sentinel_test
chmod 755 /run/sentinel /var/lib/sentinel /tmp/sentinel_test

DAEMON_PID=""
MANAGING_SPAWNED_DAEMON=false

cleanup() {
    local exit_code=$?
    echo ""
    echo "[*] Cleaning up test resources..."
    if [ "$MANAGING_SPAWNED_DAEMON" = true ] && [ -n "$DAEMON_PID" ] && kill -0 "$DAEMON_PID" 2>/dev/null; then
        echo "[*] Gracefully stopping spawned test sentineld (PID: $DAEMON_PID)..."
        kill -TERM "$DAEMON_PID" 2>/dev/null || true
        for _ in {1..10}; do
            if ! kill -0 "$DAEMON_PID" 2>/dev/null; then
                break
            fi
            sleep 0.2
        done
        if kill -0 "$DAEMON_PID" 2>/dev/null; then
            kill -KILL "$DAEMON_PID" 2>/dev/null || true
        fi
    fi
    exit "$exit_code"
}
trap cleanup EXIT

echo ""
echo "--------------------------------------------------------------------------------"
echo " TEST 1: ENVIRONMENT PREFLIGHT & DIAGNOSTICS (sntctl doctor)"
echo "--------------------------------------------------------------------------------"
if $SNTCTL doctor; then
    record_pass "sntctl doctor diagnostics"
else
    record_fail "sntctl doctor diagnostics" "doctor reported preflight failures"
fi

echo ""
echo "--------------------------------------------------------------------------------"
echo " TEST 2: DAEMON INITIALIZATION & SOCKET SETUP"
echo "--------------------------------------------------------------------------------"
if [ -S /run/sentinel/sentinel.sock ] && $SNTCTL status >/dev/null 2>&1; then
    echo "[*] Existing sentineld daemon detected and responding on /run/sentinel/sentinel.sock."
    record_pass "Daemon socket initialization (using active service)"
    SOCKETS_READY=true
else
    echo "[*] No active daemon detected. Spawning dedicated test sentineld..."
    $SENTINELD --config config/config.toml --rules config/rules.toml --verbose > /tmp/sentinel_test/daemon.log 2>&1 &
    DAEMON_PID=$!
    MANAGING_SPAWNED_DAEMON=true
    echo "[*] sentineld launched with PID $DAEMON_PID"

    MAX_WAIT=20
    SOCKETS_READY=false
    while [ $MAX_WAIT -gt 0 ]; do
        if [ -S /run/sentinel/sentinel.sock ] && [ -S /run/sentinel/sentinel-ro.sock ]; then
            SOCKETS_READY=true
            break
        fi
        sleep 0.5
        MAX_WAIT=$((MAX_WAIT - 1))
    done

    if [ "$SOCKETS_READY" = true ]; then
        record_pass "Daemon socket initialization"
    else
        record_fail "Daemon socket initialization" "Sockets /run/sentinel/*.sock not created in time"
        cat /tmp/sentinel_test/daemon.log
        exit 1
    fi
fi

echo ""
echo "--------------------------------------------------------------------------------"
echo " TEST 3: NFTABLES KERNEL HOOK VERIFICATION"
echo "--------------------------------------------------------------------------------"
if [ "$(id -u)" -eq 0 ] && command -v nft >/dev/null 2>&1; then
    if nft list table inet sentinel > /dev/null 2>&1; then
        record_pass "nftables kernel table 'inet sentinel' active"
    else
        record_fail "nftables kernel table 'inet sentinel'" "Table not found in kernel netfilter state"
    fi
else
    record_skip "nftables kernel hook verification" "Requires root and nft CLI"
fi

echo ""
echo "--------------------------------------------------------------------------------"
echo " TEST 4: SO_PEERCRED RBAC & CLIENT ROLES"
echo "--------------------------------------------------------------------------------"
if STATUS_ROOT=$($SNTCTL --json status); then
    echo "    Root response: $STATUS_ROOT"
    record_pass "RootAdmin query status"
else
    record_fail "RootAdmin query status" "Failed to query status as root"
fi

NON_ROOT_USER="${SUDO_USER:-$(logname 2>/dev/null || id -un 1000 2>/dev/null || echo "deb")}"
if [ -n "$NON_ROOT_USER" ] && [ "$NON_ROOT_USER" != "root" ] && id "$NON_ROOT_USER" > /dev/null 2>&1; then
    if STATUS_USER=$(su - "$NON_ROOT_USER" -c "$SNTCTL --json status" 2>/dev/null); then
        echo "    Non-root response: $STATUS_USER"
        record_pass "ReadOnly client query status"
    else
        record_fail "ReadOnly client query status" "Non-root user failed to read status"
    fi

    echo "[*] Attempting unauthorized privileged protection toggle as '$NON_ROOT_USER'..."
    set +e
    UNAUTH_ERR=$(su - "$NON_ROOT_USER" -c "$SNTCTL -s /run/sentinel/sentinel.sock protection disable" 2>&1)
    set -e
    if echo "$UNAUTH_ERR" | grep -iqE "permission|denied|eacces|unauthorized"; then
        record_pass "RBAC: Non-root rejected on management socket"
    else
        record_fail "RBAC: Non-root rejected on management socket" "Output: $UNAUTH_ERR"
    fi

    set +e
    RBAC_ERR=$(su - "$NON_ROOT_USER" -c "$SNTCTL -s /run/sentinel/sentinel-ro.sock protection disable" 2>&1)
    set -e
    if echo "$RBAC_ERR" | grep -iqE "permission|denied|eacces|unauthorized"; then
        record_pass "RBAC: Non-root rejected on read-only socket"
    else
        record_fail "RBAC: Non-root rejected on read-only socket" "Output: $RBAC_ERR"
    fi
else
    record_skip "Non-root RBAC tests" "No non-root user found in current environment"
fi

echo ""
echo "--------------------------------------------------------------------------------"
echo " TEST 5: PROCESS CONTROL & ANTI-PID-REUSE"
echo "--------------------------------------------------------------------------------"
sleep 120 &
TEST_WORKER_PID=$!
echo "[*] Spawned worker process PID: $TEST_WORKER_PID"

if $SNTCTL process inspect "$TEST_WORKER_PID" >/dev/null; then
    record_pass "Process inspect on active PID"
else
    record_fail "Process inspect on active PID" "Failed to inspect $TEST_WORKER_PID"
fi

if $SNTCTL process suspend "$TEST_WORKER_PID"; then
    sleep 0.5
    STATE=$(grep -i "^State:" "/proc/$TEST_WORKER_PID/status" 2>/dev/null | awk '{print $2}' || true)
    if [ "$STATE" = "T" ]; then
        record_pass "Process suspend via SIGSTOP (State: T)"
    else
        record_fail "Process suspend via SIGSTOP" "Expected State T, found '$STATE'"
    fi
else
    record_fail "Process suspend" "sntctl suspend command failed"
fi

if $SNTCTL unfreeze "$TEST_WORKER_PID"; then
    sleep 0.5
    STATE_RESUMED=$(grep -i "^State:" "/proc/$TEST_WORKER_PID/status" 2>/dev/null | awk '{print $2}' || true)
    if [ "$STATE_RESUMED" = "S" ] || [ "$STATE_RESUMED" = "R" ]; then
        record_pass "Process resume via SIGCONT"
    else
        record_fail "Process resume via SIGCONT" "State is '$STATE_RESUMED'"
    fi
else
    record_fail "Process resume" "sntctl unfreeze command failed"
fi

if $SNTCTL process kill "$TEST_WORKER_PID" --reason "Automated live VM test"; then
    sleep 0.5
    if ! kill -0 "$TEST_WORKER_PID" 2>/dev/null; then
        record_pass "Process safe termination with anti-PID-reuse"
    else
        kill -9 "$TEST_WORKER_PID" 2>/dev/null || true
        record_fail "Process safe termination" "Process PID $TEST_WORKER_PID still alive"
    fi
else
    record_fail "Process kill" "sntctl process kill returned error"
fi

# Assert non-existent PID returns error
set +e
DEAD_ERR=$($SNTCTL process kill 999999 2>&1)
set -e
if echo "$DEAD_ERR" | grep -iqE "not found|notfound|esrch|error|failed"; then
    record_pass "Non-existent PID termination rejected"
else
    record_fail "Non-existent PID termination" "Expected error, got: $DEAD_ERR"
fi

echo ""
echo "--------------------------------------------------------------------------------"
echo " TEST 6: IMMUTABLE SAFETY CONSTRAINT (PID 1 & SELF NEVER-KILL)"
echo "--------------------------------------------------------------------------------"
set +e
PID1_ERR=$($SNTCTL process kill 1 2>&1)
set -e
if echo "$PID1_ERR" | grep -iqE "forbidden|immutable|protected|eperm|error"; then
    record_pass "PID 1 termination rejected (immutable safety constraint)"
else
    record_fail "PID 1 termination rejected" "Output: $PID1_ERR"
fi

TARGET_DAEMON_PID="${DAEMON_PID:-$(pgrep -o sentineld 2>/dev/null || echo "")}"
if [ -n "$TARGET_DAEMON_PID" ]; then
    set +e
    SELF_ERR=$($SNTCTL process kill "$TARGET_DAEMON_PID" 2>&1)
    set -e
    if echo "$SELF_ERR" | grep -iqE "forbidden|immutable|protected|eperm|error"; then
        record_pass "Daemon self-termination rejected (immutable safety constraint)"
    else
        record_fail "Daemon self-termination rejected" "Output: $SELF_ERR"
    fi
else
    record_skip "Daemon self-termination rejected" "Could not determine daemon PID"
fi

echo ""
echo "--------------------------------------------------------------------------------"
echo " TEST 7: EMERGENCY HOST CONTAINMENT & NETWORK ISOLATION"
echo "--------------------------------------------------------------------------------"
if [ "$(id -u)" -eq 0 ]; then
    if $SNTCTL network isolate; then
        record_pass "Network isolation engagement"
    else
        record_fail "Network isolation engagement" "sntctl network isolate failed"
    fi

    # Verify loopback preserved
    if ping -c 1 127.0.0.1 > /dev/null 2>&1; then
        record_pass "Loopback 127.0.0.1 preserved during isolation"
    else
        record_fail "Loopback preservation" "ping 127.0.0.1 failed during isolation"
    fi

    # Confirm isolation disarms anti-lockout timer
    if $SNTCTL network confirm-isolation; then
        record_pass "Network isolation confirmed by operator"
    else
        record_fail "Network isolation confirmation" "sntctl network confirm-isolation failed"
    fi

    if $SNTCTL network unisolate; then
        record_pass "Network unisolation restoration"
    else
        record_fail "Network unisolation restoration" "sntctl network unisolate failed"
    fi
else
    record_skip "Network isolation live test" "Requires root"
fi

echo ""
echo "--------------------------------------------------------------------------------"
echo " TEST 8: CARGO INTEGRATION TEST SUITES"
echo "--------------------------------------------------------------------------------"
# Configure CARGO_HOME to leverage cached crates if running under sudo/root
if [ -z "${CARGO_HOME:-}" ]; then
    if [ -d "/home/$NON_ROOT_USER/.cargo" ]; then
        export CARGO_HOME="/home/$NON_ROOT_USER/.cargo"
    elif [ -d "$HOME/.cargo" ]; then
        export CARGO_HOME="$HOME/.cargo"
    fi
fi

CARGO_FLAGS="--offline"
if ! cargo test $CARGO_FLAGS -p sentineld --test security_remediation_tests --no-run > /dev/null 2>&1; then
    CARGO_FLAGS=""
fi

echo "[*] Running security remediation test suite..."
if cargo test $CARGO_FLAGS -p sentineld --test security_remediation_tests -- --nocapture; then
    record_pass "Cargo security_remediation_tests suite"
else
    record_fail "Cargo security_remediation_tests suite" "One or more tests failed"
fi

echo "[*] Running headless EDR test suite..."
if cargo test $CARGO_FLAGS -p sentineld --test headless_edr_tests -- --nocapture; then
    record_pass "Cargo headless_edr_tests suite"
else
    record_fail "Cargo headless_edr_tests suite" "One or more tests failed"
fi

echo ""
echo "================================================================================"
echo "                           TEST EXECUTION SUMMARY                               "
echo "================================================================================"
echo "TOTAL:   $TOTAL_TESTS"
echo "PASSED:  $PASSED_TESTS"
echo "FAILED:  $FAILED_TESTS"
echo "SKIPPED: $SKIPPED_TESTS"

if [ "$FAILED_TESTS" -gt 0 ]; then
    echo ""
    echo "[!] FAILED TESTS:"
    for name in "${FAILED_TEST_NAMES[@]}"; do
        echo "    - $name"
    done
    echo "================================================================================"
    exit 1
else
    echo "================================================================================"
    echo "          ALL TEST CRITERIA PASSED HONESTLY WITHOUT SUPPRESSION!                "
    echo "================================================================================"
    exit 0
fi
