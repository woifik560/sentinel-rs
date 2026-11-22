# Sentinel-RS Testing & Verification Framework

## 1. Test Architecture Overview

Sentinel-RS uses a rigorous multi-layered verification strategy across unit, component, integration, adversarial, security remediation, and red team test suites:

```
+--------------------------------------------------------------------------+
|                        Red Team & E2E Suites                             |
|  - tests/adversarial_e2e.rs (22 scenarios)                               |
|  - tests/red_team.rs (16 scenarios)                                      |
|  - tests/headless_edr_tests.rs (5 scenarios)                             |
|  - tests/adversarial_sec_suite.rs (12 scenarios)                         |
|  - tests/security_remediation_tests.rs (8 scenarios)                     |
+--------------------------------------------------------------------------+
                                     |
                                     v
+--------------------------------------------------------------------------+
|                       Subsystem Component Tests                          |
|  - sentineld (lib & bin tests: 17 tests)                                 |
|  - sentinel-ebpf (maps, hooks, Ring0 tests: 19 tests)                    |
|  - sentinel-common (events, risk, policy, process tests: 9 tests)        |
+--------------------------------------------------------------------------+
```

Total Automated Test Coverage: **122 automated tests** executing in $\sim 2\text{s}$ during continuous integration with 100% pass rate.

---

## 2. Test Execution Commands

### Run all tests across the workspace:
```bash
cargo test --workspace
```

### Run specific test suites:
```bash
# Security Remediation & RBAC verification:
cargo test --test security_remediation_tests

# Adversarial Security Suite (DoS, ScmRights, Anti-Lockout, Quotas):
cargo test --test adversarial_sec_suite

# Core headless EDR integration tests (PID reuse, 6-stage precedence):
cargo test --test headless_edr_tests

# Adversarial end-to-end suite (22 attack scenarios):
cargo test --test adversarial_e2e

# Red team simulation suite (16 real-world threat actor scenarios):
cargo test --test red_team

# Kernel Ring0 & Preflight tests:
cargo test --test kernel_ring0

# Subsystem unit tests:
cargo test -p sentineld --lib
cargo test -p sentinel-ebpf --lib
cargo test -p sentinel-common --lib
```

---

## 3. Test Suites Detailed

### 3.1 Security Remediation Suite (`tests/security_remediation_tests.rs`)
- `test_incidents_clear_requires_root_admin`: Enforces that `IncidentsClear` cannot be executed by `ReadOnly` or `Operator`, returning `EACCES`.
- `test_readonly_denied_sensitive_queries`: Verifies that `ReadOnly` clients on `sentinel-ro.sock` cannot inspect incidents, process lineage, or policy rules.
- `test_protection_toggle_controls_real_state`: Verifies that `ProtectionEnable` and `ProtectionDisable` actually toggle the runtime daemon state and require `RootAdmin`.
- `test_anti_pid_reuse_verification`: Verifies that process identity checks strictly compare `/proc/<pid>/stat` start times against canonical `ProcessKey`. Mismatches return `TerminationError::PidReuseDetected`.
- `test_unsupported_commands_return_enotsup`: Ensures unknown or unimplemented commands return `ENOTSUP` and fail closed, never returning fake success.
- `test_network_anti_lockout_confirm_state`: Validates that `confirm_isolation()` disarms the Anti-Lockout timer and arms confirmed status, and returns `ENOTCONN` when host is not isolated.
- `test_nftables_syntax_generator_correctness`: Validates that generated batch scripts for `FullIsolation`, `Restricted`, and `Selective` are syntactically valid and contain loopback and SSH anti-lockout rules.
- `test_rules_config_parsing_error`: Verifies that malformed TOML rules configurations fail safely without panicking.
- `test_missing_start_time_fails_closed`: Verifies that process identity verification strictly fails closed when start time is 0 and no strong identity is provided.
- `test_privileged_helper_rejection_for_unauthorized_user`: Verifies that `sentinel-privileged` helper rejects requests from non-root callers with `EPERM`.
- `test_restricted_isolation_omits_broad_established_bypass`: Verifies that restricted isolation only permits established traffic matching specific allowed destinations and loopback.
- `test_selective_isolation_policy_blocks_designated_targets`: Verifies that selective isolation strictly drops designated IPs and ports while keeping general traffic open.

---

## 4. Live Virtual Machine & Bare-Metal Test Suite (`tests/run_live_vm_tests.sh`)

Sentinel-RS includes an end-to-end live testing script for verifying actual kernel interaction on real Linux VMs and physical hosts. It executes 20 distinct verification checks without test suppression or masking:

1. **TEST 1: ENVIRONMENT PREFLIGHT & DIAGNOSTICS (`sntctl doctor`)**: Checks kernel version, BPF LSM support in `/sys/kernel/security/lsm`, IPC directory, and table status.
2. **TEST 2: DAEMON INITIALIZATION & SOCKET SETUP**: Launches `sentineld` and verifies creation and permissions of `/run/sentinel/sentinel.sock` (`0660`) and `/run/sentinel/sentinel-ro.sock` (`0666`).
3. **TEST 3: NFTABLES KERNEL HOOK VERIFICATION**: Queries `nft list table inet sentinel` in kernel netfilter state.
4. **TEST 4: SO_PEERCRED RBAC & CLIENT ROLES**: Executes queries as root (`RootAdmin`) and non-root user (`ReadOnly`); asserts that non-root mutation attempts return permission denied.
5. **TEST 5: PROCESS CONTROL & ANTI-PID-REUSE**: Spawns a real child process, inspects state, suspends with `SIGSTOP`, resumes with `SIGCONT`, and securely terminates using `pidfd` verification; verifies non-existent PID rejection.
6. **TEST 6: IMMUTABLE SAFETY CONSTRAINT**: Asserts that `terminate_process` requests against `PID 1` and the daemon itself (`PID self`) are unconditionally rejected.
7. **TEST 7: EMERGENCY HOST CONTAINMENT & NETWORK ISOLATION**:
   - Engages isolation via `sntctl network isolate`.
   - Verifies loopback (`127.0.0.1`) remains functional for IPC and local health checks.
   - Confirms isolation via `sntctl network confirm-isolation` to disarm anti-lockout timer.
   - Restores connectivity via `sntctl network unisolate`.
8. **TEST 8: CARGO INTEGRATION TEST SUITES**: Runs both `security_remediation_tests` (12 tests) and `headless_edr_tests` (5 tests).

### Execution:
```bash
sudo bash tests/run_live_vm_tests.sh
```

### 3.2 Adversarial Security Suite (`tests/adversarial_sec_suite.rs`)
- `test_sec_001_pid_reuse_safety`: Verifies fail-closed process termination under simulated recycled PIDs.
- `test_sec_002_unprivileged_client_rejection`: Enforces `SO_PEERCRED` RBAC boundaries.
- `test_sec_003_ringbuffer_overflow_drop_tracking`: Validates overflow metrics under event saturation.
- `test_sec_004_bpf_lsm_loss_handling`: Tests graceful degradation when BPF LSM hooks are lost.
- `test_sec_005_giant_ipc_message_buffer_limit`: Defends against giant IPC message allocation DoS.
- `test_sec_006_unauthorized_network_isolation`: Verifies that only `RootAdmin` can trigger network isolation.
- `test_sec_007_daemon_crash_recovery_integrity`: Tests SQLite database recovery and WAL integrity across sudden process termination.
- `test_sec_008_isolation_idempotency`: Verifies that applying isolation multiple times is strictly idempotent.
- `test_sec_009_disk_quota_guard`: Ensures low disk space (< 500 MB) drops raw events to protect root partition integrity.
- `test_sec_010_fork_bomb_event_throttling`: Validates per-PID rate limiting against fork-bomb flood attacks.
- `test_sec_011_scm_rights_descriptor_passing`: Verifies taint tracking across `SCM_RIGHTS` file descriptor passing.
- `test_sec_012_legitimate_backup_fp_immunity`: Ensures legitimate root backup utilities (`borg`, `tar`, `rsync`) do not trigger false positive termination.

### 3.3 Headless EDR Integration (`tests/headless_edr_tests.rs`)
- `test_pid_reuse_protection_mechanisms`: Validates canonical `ProcessKey` verification.
- `test_six_stage_policy_precedence`: Verifies that Stage 1 Safety Rules (PID 1, sentinel daemon) take absolute precedence over administrator deny rules, whitelists, and risk thresholds.
- `test_operating_mode_autonomous_verdicts`: Verifies autonomous behavior across `Audit`, `Balanced`, and `Strict` modes.
- `test_multi_stage_attack_evidence_compounding`: Validates that progression across multiple MITRE attack stages compounds risk scores.
- `test_incident_lifecycle_and_temporal_correlation`: Verifies the full incident state machine (`DETECTED` $\rightarrow$ `CONTAINED` $\rightarrow$ `INVESTIGATING` $\rightarrow$ `RESOLVED`).

### 3.4 Adversarial End-to-End Suite (`tests/adversarial_e2e.rs`)
- 22 comprehensive scenarios verifying pipe taint propagation, established socket bypass prevention, `memfd_create` detection, ptrace memory snooping defense, dynamic netfilter marks, and packaging integrity.

### 3.5 Red Team Simulation Suite (`tests/red_team.rs`)
- 16 real-world scenarios testing evasion tradecraft: LoLBin abuse (`curl`, `socat`, `nc`), intermediate file staging, cross-process `/proc/<pid>/environ` snoop, UDP/QUIC exfiltration, and multi-threaded stealer group-leader taint tracking.

---

## 4. Environment & Integration Testing

### Running on Real Linux Kernel (WSL2 / Bare Metal):
Tests can be executed directly as an unprivileged user:
```bash
cargo test
```

### Running with Real Netfilter Isolation (Requires root / CAP_NET_ADMIN):
```bash
sudo $(which cargo) test --test adversarial_sec_suite test_sec_008_isolation_idempotency -- --nocapture
```
This tests actual `nft` atomic rule insertion into the `inet sentinel` table.
