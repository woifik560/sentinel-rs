# Sentinel-RS Security & Architecture Findings Log

**Document Version:** 1.0.0  
**Audit Date:** 2026-11-22  
**Auditor:** Senior Linux Security Engineer & Application Security Auditor  
**Workspace:** `firewall_linux`  

---

## 1. Finding Severity Definitions

- **P0 (Critical):** Immediate host compromise, kernel panic, lock-out of administrative access, bypass of security isolation, or arbitrary signal/process termination.
- **P1 (High):** Integrity/availability degradation under concurrency, privilege escalation vector, unhandled TOCTOU, silent failure or misleading operational status.
- **P2 (Medium):** Sub-optimal fallback behavior, missing timeouts, edge-case denial of service, resource leaks.
- **P3 (Low / Informational):** Code cleanliness, missing telemetry fields, non-idiomatic patterns.

---

## 2. Summary Table of Audited Vulnerabilities & Defects

| Finding ID | Severity | Subsystem | Description | Status |
| :--- | :--- | :--- | :--- | :--- |
| **SEC-P0-01** | **P0** | Network Isolation | Netfilter chain policy lockout and table residue when transitioning between isolation tiers | **RESOLVED** |
| **SEC-P0-02** | **P0** | Privileged Helper | TOCTOU PID reuse vulnerability in `sentinel-privileged::SignalProcess` | **RESOLVED** |
| **SEC-P0-03** | **P0** | Health / Telemetry | False "healthy" status reported when BPF LSM hooks fail to attach | **RESOLVED** |
| **SEC-P1-01** | **P1** | Kernel Setup | Destructive bootloader modification without backup, verification, or rollback | **RESOLVED** |
| **SEC-P1-02** | **P1** | IPC / RBAC | Role mismatch between command declaration (`ReadOnly`) and dispatch (`Operator`) | **RESOLVED** |
| **REL-P1-01** | **P1** | Storage (SQLite) | `SQLITE_BUSY` contention on reader connections and uncontrolled database growth | **RESOLVED** |
| **DET-P1-01** | **P1** | Detection & Risk | Missing MITRE ATT&CK technique IDs and recommended response actions on incidents | **RESOLVED** |
| **QUAL-P1-01**| **P1** | Code Quality | Global suppression `#![allow(warnings)]` masking latent defects and clippy violations | **RESOLVED** |
| **SEC-P2-01** | **P2** | Network Isolation | Missing explicit loopback and DNS protection rules in selective isolation tiers | **RESOLVED** |
| **REL-P2-01** | **P2** | Process Lineage | Infinite iterator loop in DAG search leading to potential thread hang | **RESOLVED** |

---

## 3. Deep Dive Findings & Remediation Records

### SEC-P0-01: Netfilter Chain Lockout & State Inconsistency During Isolation Transitions

- **Severity:** P0 (Critical)
- **Crate / File:** `crates/sentineld/src/network/nftables.rs`
- **Root Cause:**
  When transitioning a host from `IsolationTier::FullIsolation` back to `IsolationTier::None` or `IsolationTier::Restricted`, the daemon executed `flush table inet sentinel`. In `nftables`, `flush table` empties existing rules within chains but does **NOT** delete the chains themselves nor reset their default policies. Consequently, the input filter chain created during `FullIsolation` with `policy drop;` remained in effect. All inbound network traffic was permanently dropped, locking the administrator out of the machine even after issuing an un-isolation command. Furthermore, flushing the table did not clean up dangling sets, and partial batch failures left the system in a half-configured state.
- **Threat Scenario / Exploit:**
  An operator isolates a server during a security incident. Upon remediating the incident, the operator sends `sntctl isolate --tier none`. The daemon executes `flush table`, but because the input chain retains `policy drop;`, the server becomes completely unreachable over the network, requiring an out-of-band console reboot.
- **Remediation Implemented:**
  Replaced all partial flush operations with an atomic table delete-and-recreate idiom:
  ```nft
  add table inet sentinel
  delete table inet sentinel
  add table inet sentinel
  ```
  Additionally, for `None`, `Selective`, and `Restricted` tiers, explicitly generated an input chain with `policy accept`:
  ```nft
  add chain inet sentinel input { type filter hook input priority 0; policy accept; }
  ```
- **Verification:**
  Unit test `test_anti_lockout_ssh_isolation` and live kernel integration test verifying atomic transition from `FullIsolation` to `None`. Kernel state verified via `nft list table inet sentinel`.
- **Status:** **RESOLVED**

---

### SEC-P0-02: TOCTOU PID Reuse in Privileged Helper Process Signaling

- **Severity:** P0 (Critical)
- **Crate / File:** `crates/sentinel-privileged/src/lib.rs`, `crates/sentinel-privileged/src/server.rs`, `crates/sentineld/src/response/process_term.rs`
- **Root Cause:**
  `sentineld` delegated process termination to `sentinel-privileged` via IPC operation `PrivilegedOp::SignalProcess { pid, signal }`. The privileged helper executed `kill(pid, sig)` or `pidfd_send_signal` using only the raw PID. On high-churn systems where PIDs wrap around quickly (e.g. containers, fork-bombs, compiler builds), the target malicious process could exit between detection and response, and an innocent process (or critical system service) could acquire the recycled PID. The helper would blindly terminate the innocent process.
- **Threat Scenario / Exploit:**
  Attacker spawns a malicious process (PID 45000), executes a cryptominer, and immediately exits while triggering a high-volume process spawn burst. By the time `sentineld` decides to terminate PID 45000, a new process running `sshd` or `systemd-journald` is allocated PID 45000. Sentinel terminates the legitimate service.
- **Remediation Implemented:**
  1. Extended `PrivilegedOp::SignalProcess` to include process identity verification tokens:
     ```rust
     PrivilegedOp::SignalProcess {
         pid: u32,
         signal: i32,
         expected_start_time: Option<u64>,
         expected_exe: Option<String>,
     }
     ```
  2. Implemented `verify_identity(pid, expected_start_time, expected_exe)` in `sentinel-privileged`:
     - Reads `/proc/<pid>/stat` to extract the exact process start time in jiffies.
     - Resolves the `/proc/<pid>/exe` symlink.
     - Rejects termination with `PrivilegedResult::Error("EPERM")` if start time or executable does not match.
  3. Added explicit rejection of PID 1 and kernel threads.
- **Verification:**
  Added unit tests in `sentinel-privileged/src/server.rs`:
  - `test_privileged_signal_pid_1_rejected`
  - `test_privileged_signal_start_time_mismatch_rejected`
  - `test_privileged_signal_exe_mismatch_rejected`
- **Status:** **RESOLVED**

---

### SEC-P0-03: Deceptive "Healthy" Status Reporting When BPF LSM Hooks Are Inactive

- **Severity:** P0 (Critical)
- **Crate / File:** `crates/sentineld/src/ipc_server.rs`, `crates/sentineld/src/health/metrics.rs`, `crates/sentinel-ebpf/src/loader.rs`
- **Root Cause:**
  When queried via `sntctl status` or the IPC socket (`IpcCommand::StatusGet`), `sentineld` returned `"status": "healthy"` regardless of whether the BPF LSM hooks were actually attached in the kernel. In environments without `CONFIG_BPF_LSM=y` or missing BTF `/sys/kernel/btf/vmlinux`, the eBPF loader silently degraded to tracepoints or disabled hooks, yet the health subsystem continued to report a pristine green state.
- **Threat Scenario / Exploit:**
  An enterprise security team deploys Sentinel-RS on a fleet of servers expecting active in-kernel security LSM enforcement (`bprm_check_security`). Due to missing kernel boot parameters (`lsm=lockdown,yama,bpf`), the hooks are not loaded. Because the daemon reports `healthy`, monitoring alerts never trigger, leaving hosts vulnerable to bypass.
- **Remediation Implemented:**
  1. Enforced truthful health status logic in `crates/sentineld/src/ipc_server.rs`:
     ```rust
     let overall_status = if state.bpf_lsm_active && state.network_holding_active {
         "healthy"
     } else if state.bpf_lsm_active || state.network_holding_active {
         "degraded"
     } else {
         "disabled"
     };
     ```
  2. Updated `crates/sentinel-ebpf/src/loader.rs` to set `ring_buffer_state = MechanismState::Degraded` when only tracepoint fallback is active.
- **Verification:**
  Validated via `cargo test -p sentineld` and integration tests. In test environments without BTF, status truthfully outputs `"degraded"`.
- **Status:** **RESOLVED**

---

### SEC-P1-01: Destructive Bootloader Modification Without Backup, Verification, or Rollback

- **Severity:** P1 (High)
- **Crate / File:** `crates/sntctl/src/commands/setup_kernel.rs`, `crates/sntctl/src/main.rs`
- **Root Cause:**
  The command `sntctl setup-kernel` modified critical bootloader files (`/etc/default/grub`, `/boot/loader/entries/*.conf`) in-place without creating backups. If the command `update-grub` failed (e.g. disk full, permission issue), the exit code was ignored, leaving the system with potentially corrupted boot configuration. Furthermore, there was no rollback mechanism.
- **Threat Scenario / Exploit:**
  A system administrator runs `sntctl setup-kernel`. A syntax error in GRUB configuration or an interrupted update leaves GRUB unbootable. The machine fails to reboot, causing an unrecoverable outage.
- **Remediation Implemented:**
  1. Implemented automatic timestamped backup (`.sentinel.bak`) before any bootloader configuration file is touched.
  2. Implemented strict exit status verification on `update-grub` / `grub2-mkconfig`. If the command fails, the original configuration file is automatically restored from backup before exiting with an error.
  3. Added `--rollback` flag to `sntctl setup-kernel` to allow administrators to undo kernel parameter modifications at any time.
- **Verification:**
  Unit tests in `sntctl/src/commands/setup_kernel.rs`:
  - `test_setup_kernel_grub_patching_and_rollback`
  - `test_setup_kernel_systemd_boot_patching`
  - `test_setup_kernel_rollback_no_backup`
- **Status:** **RESOLVED**

---

### SEC-P1-02: RBAC Inconsistency Between Command Whitelist and Execution Dispatch

- **Severity:** P1 (High)
- **Crate / File:** `crates/sentineld/src/ipc_server.rs`
- **Root Cause:**
  In `required_role_for_command`, `IpcCommand::IncidentsList` and `IpcCommand::IncidentsShow` were mapped to `ClientRole::ReadOnly`. However, in `handle_ipc_command`, they were matched with a guard requiring `ClientRole::Operator`. Consequently, read-only callers attempting to query incidents were rejected with an unhelpful internal error, while documentation incorrectly stated that read-only tokens could inspect incidents.
- **Remediation Implemented:**
  Aligned the RBAC matrix in `required_role_for_command` and `handle_ipc_command` to consistently require `ClientRole::Operator` for viewing incident details, while providing a clear error message if an unprivileged role calls the API.
- **Verification:**
  Tested with local mock IPC connections passing different UID credentials.
- **Status:** **RESOLVED**

---

### REL-P1-01: SQLite Contention Under Heavy Ingestion & Uncontrolled Database Growth

- **Severity:** P1 (High)
- **Crate / File:** `crates/sentineld/src/storage/database.rs`
- **Root Cause:**
  1. Reader connections instantiated in `list_incidents`, `get_incident`, and `clear_all_incidents` did not set `busy_timeout`. Under heavy write traffic (burst of security alerts), reader threads immediately received `sqlite3_step: database is locked (SQLITE_BUSY)` and crashed or returned empty data.
  2. The SQLite database file had no size limit. Over months of running in production, event tables could grow indefinitely until exhausting the root filesystem.
- **Remediation Implemented:**
  1. Standardized all connection creation through `open_sqlite_connection(path)`:
     - `PRAGMA journal_mode = WAL;`
     - `PRAGMA busy_timeout = 5000;`
     - `PRAGMA synchronous = NORMAL;`
     - `PRAGMA foreign_keys = ON;`
  2. Added an automatic disk quota guard: when the database file exceeds 500 MB, the storage engine triggers an automated FIFO purge of the oldest 20% of events and executes `PRAGMA wal_checkpoint(TRUNCATE);`.
- **Verification:**
  Unit tests in `sentineld/src/storage/database.rs`:
  - `test_sqlite_wal_pragmas`
  - `test_sqlite_concurrent_readers_and_writers`
  - `test_sqlite_file_size_growth_guard`
- **Status:** **RESOLVED**

---

### DET-P1-01: Missing MITRE ATT&CK Mapping & Response Guidance on Incident Reports

- **Severity:** P1 (High)
- **Crate / File:** `crates/sentinel-common/src/incident.rs`, `crates/sentinel-common/src/risk.rs`, `crates/sentineld/src/main.rs`
- **Root Cause:**
  Security incidents lacked standardized MITRE ATT&CK enterprise technique references. When Sentinel generated an alert for credential dumping, egress tunneling, or code injection, SOC analysts and SIEM systems received raw numeric rule IDs without contextual ATT&CK tactic/technique metadata or recommended mitigation actions.
- **Remediation Implemented:**
  1. Added `AttckTechnique` enum in `sentinel-common` with techniques:
     - `T1003` (OS Credential Dumping)
     - `T1048_003` (Exfiltration Over Alternative Protocol)
     - `T1204_002` (Malicious File Execution)
     - `T1620` (Reflective Code Loading)
     - `T1059` (Command and Scripting Interpreter)
     - `T1071` (Application Layer Protocol)
     - `T1554` (Compromise Host Software Binary)
     - `T1055_008` (Process Injection: Ptrace)
  2. Added `mitre_attck()` method to `RuleId` and `RuleFiring`.
  3. Added `attck_technique` and `recommended_response` fields to `IncidentReport`.
- **Verification:**
  Unit tests in `sentinel-common/src/risk.rs` and `sentineld/src/main.rs`.
- **Status:** **RESOLVED**

---

### QUAL-P1-01: Global Warning Suppression Masking Latent Bugs

- **Severity:** P1 (High)
- **Crate / File:** `crates/sentineld/src/main.rs`
- **Root Cause:**
  `crates/sentineld/src/main.rs` contained `#![allow(warnings)]` at the crate root. This suppressed all compiler warnings and clippy diagnostics across the entire daemon, hiding unused variables, dead code paths, collapsible logic, and an iterator bug in `lineage/graph.rs`.
- **Remediation Implemented:**
  1. Removed `#![allow(warnings)]`.
  2. Addressed all underlying clippy warnings across the workspace.
  3. Fixed iterator search logic in `crates/sentineld/src/lineage/graph.rs` (replaced broken `for ... return` with `.find(...)`).
  4. Enforced clean compilation: `cargo clippy -p sentineld --lib` now passes with 0 warnings.
- **Verification:**
  Clippy and `cargo check` clean pass.
- **Status:** **RESOLVED**

---
**Audit Complete:** All 10 audited findings have been fully remediated and verified.
