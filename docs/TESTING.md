# Sentinel-RS Testing & Verification Framework

## 1. Test Architecture Overview

Sentinel-RS uses a multi-layered verification strategy across unit, component, integration, adversarial, and red team test suites:

```
+--------------------------------------------------------------------------+
|                        Red Team & E2E Suites                             |
|  - tests/adversarial_e2e.rs (22 scenarios)                               |
|  - tests/red_team.rs (16 scenarios)                                      |
|  - tests/headless_edr_tests.rs (5 scenarios)                             |
+--------------------------------------------------------------------------+
                                     |
                                     v
+--------------------------------------------------------------------------+
|                       Subsystem Component Tests                          |
|  - sentineld (lib & bin tests: 24 tests)                                 |
|  - sentinel-ebpf (maps, hooks, Ring0 tests: 19 tests)                    |
|  - sentinel-common (events, risk, policy, process tests: 9 tests)        |
+--------------------------------------------------------------------------+
```

Total Test Coverage: **95 automated tests** executing in $< 1\text{s}$ during continuous integration.

---

## 2. Test Execution Commands

Run tests across the entire workspace:
```bash
cargo test --workspace
```

Run specific test suites:
```bash
# Core headless EDR integration tests:
cargo test --test headless_edr_tests

# Adversarial end-to-end tests:
cargo test --test adversarial_e2e

# Red team evasion and attack simulation tests:
cargo test --test red_team

# Subsystem unit tests:
cargo test -p sentineld --lib
cargo test -p sentinel-ebpf --lib
cargo test -p sentinel-common --lib
```

---

## 3. Test Suites Detailed

### 3.1 Headless EDR Integration (`tests/headless_edr_tests.rs`)
- `test_pid_reuse_protection_mechanisms`: Validates that process termination checks `/proc/<pid>/stat` start times, preventing termination if a PID has been recycled by the kernel.
- `test_six_stage_policy_precedence`: Verifies that Stage 1 Safety Rules (PID 1, sentinel daemon) take absolute precedence over administrator deny rules, whitelists, and risk thresholds.
- `test_operating_mode_autonomous_verdicts`: Verifies autonomous behavior across `Audit`, `Balanced`, and `Strict` modes for identical risk profiles.
- `test_multi_stage_attack_evidence_compounding`: Validates that progression across multiple MITRE attack stages multiplies the base score up to the $1.6\times$ ceiling.
- `test_incident_lifecycle_and_temporal_correlation`: Verifies the full incident state machine (`DETECTED` $\rightarrow$ `CONTAINED` $\rightarrow$ `INVESTIGATING` $\rightarrow$ `RESOLVED`).

### 3.2 Adversarial End-to-End Suite (`tests/adversarial_e2e.rs`)
- `test_1_cat_secret_pipe_curl`: Validates data-flow taint propagation through anonymous pipes (`cat ~/.ssh/id_rsa | curl`).
- `test_2_established_socket_bypass_sendmsg`: Tests interception of established TCP flows using socket storage marks.
- `test_3_scm_rights_and_mmap_file`: Validates taint inheritance when sensitive file descriptors are passed via `SCM_RIGHTS` over AF_UNIX.
- `test_4_memfd_anon_exec`: Detects fileless execution from in-memory anonymous file descriptors (`memfd_create`).
- `test_7_ptrace_memory_snooping_lsm_defense`: Verifies BPF LSM denies `PTRACE_ATTACH` and `process_vm_readv` on protected processes.
- `test_9_dynamic_mark_correlation_concurrent`: Concurrency test for dynamic netfilter mark allocation without collision.
- `test_16_zero_userspace_gui_attestation_and_sealing`: Verifies that no GUI attestation, X11 PINs, or desktop sessions are required for daemon startup or enforcement.
- `test_17_hybrid_watchdog_fail_safe_clean_fail_close_tainted`: Tests watchdog fail-safe behavior under daemon stall.

### 3.3 Red Team Simulation Suite (`tests/red_team.rs`)
- Simulates realistic threat actor tradecraft:
  - LoLBin abuse (`curl`, `socat`, `nc`)
  - Intermediate file staging (`/tmp/staged.txt`)
  - Cross-process `/proc/<pid>/environ` credential extraction
  - UDP/QUIC connectionless covert channels
  - Multi-threaded stealer group-leader taint tracking
