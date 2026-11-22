# Sentinel-RS: Comprehensive Initial Technical & Security Audit Report (INITIAL_AUDIT)

**Audit Target:** Sentinel-RS (`https://github.com/woifik560/sentinel-rs`)  
**Role:** Senior Rust Systems Engineer, Linux Kernel Security Engineer & Independent Security Auditor  
**Date:** 2026-11-22  
**Audit Scope:** Rust codebase, eBPF loader & maps, IPC subsystem, nftables/NFQUEUE firewall, process lifecycle & pidfd, SQLite persistence, CI/CD pipeline, systemd units, test suites.

---

## 1. Executive Summary

Sentinel-RS is architected as an autonomous host-based intrusion prevention and detection system (HIPS/EDR) with deterministic firewall capabilities for Linux systems.

The repository exhibits advanced architectural concepts (dual-engine telemetry, eBPF LSM hooks, process lineage graphs, NFQUEUE-based zero-drop packet holding, and privilege separation via a helper daemon). However, a deep line-by-line technical audit has identified critical vulnerabilities, architectural flaws, security check suppressions, and logic mismatches that impair stability, reliability, and security in production environments.

### Core Audit Metric Summary

| Domain | Critical (P0) | High (P1) | Medium (P2) | Total |
| :--- | :---: | :---: | :---: | :---: |
| **CI/CD & Supply Chain** | 1 | 1 | 0 | 2 |
| **Rust Code Quality & Clippy** | 0 | 1 | 1 | 2 |
| **Privilege Separation & IPC** | 1 | 1 | 1 | 3 |
| **Firewall & Network Fail-Safe** | 1 | 0 | 1 | 2 |
| **Process Identity & Lineage** | 1 | 1 | 0 | 2 |
| **Taint Tracking & Data Flow** | 0 | 1 | 1 | 2 |
| **Storage & Persistence** | 0 | 1 | 1 | 2 |
| **Testing Harness & Live Safety**| 0 | 1 | 1 | 2 |
| **Installation & Bootloader** | 0 | 0 | 1 | 1 |
| **Total** | **4** | **8** | **7** | **19** |

---

## 2. Confirmed Critical Defect Register (P0 / P1)

### DEF-01: CI Security Audit Suppression via Shell Masking
- **Classification:** Confirmed Defect
- **Criticality:** CRITICAL (P0)
- **File:** `.github/workflows/ci.yml`
- **Location:** Line 52:
  ```yaml
  - name: Security Audit & Vulnerability Check
    run: cargo audit || echo "cargo-audit advisory check completed"
  ```
- **Description:** The CI workflow suppresses exit codes from `cargo audit` by appending `|| echo ...`. This permits builds to pass even when known critical vulnerabilities exist in dependencies.
- **Risk:** Silent infiltration of known CVEs into production binaries.
- **Reproduction:** Run `cargo audit` directly in the repository. It exits with code 1 due to CVE-2026-119375. In CI, this failure was silenced.
- **Remediation:** Remove `|| echo ...` completely. Require clean audit exits. Upgrade vulnerable dependencies or record documented exceptions in `.cargo/audit.toml`.

---

### DEF-02: Known High-Severity Vulnerability in Bundled SQLite (CVE-2026-119375 / RUSTSEC-2026-0459)
- **Classification:** Confirmed Defect
- **Criticality:** HIGH (P1)
- **Files:** `crates/sentineld/Cargo.toml:29`, `Cargo.lock`
- **Component:** `rusqlite v0.32.1` -> `libsqlite3-sys v0.30.1`
- **Advisory ID:** RUSTSEC-2026-0459 (CVE-2026-119375, CVSS 6.8)
- **Description:** Bundled SQLite in `libsqlite3-sys` < 0.39.0 contains a heap memory safety flaw allowing corrupted queries or malicious database inputs to cause memory corruption in the daemon.
- **Risk:** Denial of Service or arbitrary memory manipulation within the persistent logging subsystem of `sentineld`.
- **Reproduction:** Run `cargo audit`.
- **Remediation:** Upgrade `rusqlite` to `0.43.0` (which pulls `libsqlite3-sys >= 0.40.0`). Additionally, upgrade `lru` to `>= 0.16.0` to resolve unsoundness warnings RUSTSEC-2026-0002 and RUSTSEC-2026-0253.

---

### DEF-03: Process Start Time Semantic Mismatch (Clock Ticks vs. Wall-Clock Nanoseconds) Causing False Anti-PID-Reuse Rejections
- **Classification:** Confirmed Defect
- **Criticality:** CRITICAL (P0)
- **Files & Locations:**
  - `crates/sentineld/src/collector/event_dispatcher.rs:38-43`
  - `crates/sentineld/src/collector/event_normalizer.rs:135, 161, 191`
  - `crates/sentineld/src/lineage/tracker.rs:94-98, 191`
  - `crates/sentineld/src/response/process_term.rs:188-208`
  - `crates/sentinel-privileged/src/server.rs:151-172`
- **Description:**
  1. In `event_dispatcher.rs`, `start_time_ns` is computed as `SystemTime::now()` (wall-clock nanoseconds since Unix epoch) at the moment an event is pulled from the ring buffer.
  2. In `event_normalizer.rs`, every incoming event creates a new `ProcessKey::new(tgid, start_time_ns)`. Because events arrive continuously, each event for the *same* process gets a different `ProcessKey` with a different timestamp!
  3. In `tracker.rs` (`discover_from_procfs`), field 22 of `/proc/<tgid>/stat` is parsed as `ticks` (kernel clock ticks since boot, e.g. 15,200) and assigned to `node.start_time_ns`.
  4. In `process_term.rs` and `sentinel-privileged/src/server.rs`, `curr_start` is read from `/proc/<pid>/stat` (clock ticks since boot) and compared with `key.start_time_ns`:
     ```rust
     if key.start_time_ns > 0 && curr_start != key.start_time_ns {
         return Err(TerminationError::PidReuseDetected(pid));
     }
     ```
  Because wall-clock nanoseconds (~1.73e18) never equal clock ticks (~1.5e4), all process termination or suspension requests for event-tracked processes are rejected with a false positive "PID reuse detected"!
- **Risk:** Complete inability to terminate, suspend, or manage hostile processes during active incidents.
- **Reproduction:**
  1. Trigger any eBPF event for PID `P`.
  2. Attempt to terminate PID `P` via `sntctl process kill P`.
  3. The request fails with `ESRCH: PID reuse detected`.
- **Remediation:**
  - Standardize `start_time` across the entire workspace to `/proc/<pid>/stat` starttime (clock ticks since boot) or nanoseconds derived via kernel boot time.
  - In `event_dispatcher`, lookup the existing `ProcessNode` in `LineageTracker` by `tgid` to retrieve the authentic process start time rather than stamping it with `SystemTime::now()`.

---

### DEF-04: Arbitrary nftables String Injection into Privileged Helper
- **Classification:** Confirmed Defect
- **Criticality:** CRITICAL (P0)
- **Files & Locations:**
  - `crates/sentinel-privileged/src/server.rs:16-41, 76-115`
  - `crates/sentinel-privileged/src/lib.rs:18`
  - `crates/sentineld/src/network/nftables.rs:108-110`
- **Description:**
  `PrivilegedOp::ApplyNftablesBatch { batch: String }` receives a raw, multi-line string over the privileged Unix Domain Socket (`/run/sentinel/privileged.sock`) and pipes it into `nft -f -`. Although rudimentary string matching checks for `"flush ruleset"` and `"table inet sentinel"`, sending un-typed string scripts across privilege boundaries allows potential command evasion, malformed table rules, or syntax bypasses.
- **Risk:** Privilege escalation or unauthorized firewall reconfiguration if `sentineld` or an authorized client is compromised.
- **Reproduction:** Call `execute_sync(&PrivilegedOp::ApplyNftablesBatch { batch: "...".into() })`.
- **Remediation:** Replace raw string batches with strongly typed operation structures:
  ```rust
  pub enum FirewallOperation {
      SetupHolding { use_bypass: bool },
      ApplyIsolation { tier: IsolationTier, trusted_ssh_ips: Vec<String> },
      BlockIp { ip: String },
      CleanupRules,
      Rollback,
  }
  ```
  The privileged helper must generate and validate the nftables syntax internally.

---

### DEF-05: Anti-Lockout In-Memory Watchdog Dies on Daemon Crash (Permanent Remote Lockout)
- **Classification:** Confirmed Defect
- **Criticality:** CRITICAL (P0)
- **Files & Locations:**
  - `crates/sentineld/src/network/manager.rs:72-101`
- **Description:**
  When network isolation is applied with a timeout (e.g. 300 seconds), `sentineld` spawns an in-memory `tokio::spawn` task containing `sleep(timeout)`. If `sentineld` crashes, encounters an unhandled panic, or is killed by the OOM killer before the operator confirms isolation, the tokio task dies. The auto-rollback never executes, leaving the remote server permanently severed from network access.
- **Risk:** Catastrophic loss of administrative SSH access to remote servers in production.
- **Reproduction:**
  1. Call `sntctl network isolate-timed --timeout 60`.
  2. Kill `sentineld` (`kill -9 $DAEMON_PID`).
  3. Wait 120 seconds. The server remains in `IsolationTier::FullIsolation`.
- **Remediation:**
  - Delegate the anti-lockout timer and persistent state to `sentinel-privileged` or a persistent state file (`/run/sentinel/isolation_lockout.state`).
  - Configure `sentinel-privileged` to automatically roll back the firewall if `sentineld` disconnects or terminates without confirming isolation.

---

### DEF-06: Clippy Compilation Failure on Strict Flag `-D warnings`
- **Classification:** Confirmed Defect
- **Criticality:** HIGH (P1)
- **Files & Locations:**
  - `crates/sentinel-ebpf/tests/kernel_ring0.rs:28-31, 50-53`
- **Description:**
  Fields are reassigned outside of initializers for instances created with `Default::default()`, violating `clippy::field_reassign_with_default` which is treated as a fatal error under `-D warnings`.
- **Risk:** Failure of CI linter gate (`cargo clippy --workspace --all-targets -- -D warnings`).
- **Reproduction:** Run `cargo clippy --workspace --all-targets -- -D warnings`.
- **Remediation:** Refactor to struct update syntax:
  ```rust
  let config = LoaderConfig {
      strict_preflight: true,
      min_kernel_version: "6.1".to_string(),
      ..Default::default()
  };
  ```

---

### DEF-07: Unchecked Supplementary Groups in SO_PEERCRED Authorization
- **Classification:** Confirmed Defect
- **Criticality:** HIGH (P1)
- **Files & Locations:**
  - `crates/sentineld/src/ipc_server.rs:360-405`
- **Description:**
  `verify_peer_client` compares `peer_gid == op_gid`. In standard Linux desktop and server distributions, operators are added to administrative groups (e.g., `sentinel`, `wheel`, `sudo`) as **supplementary groups**, leaving their primary GID set to their personal user group (GID 1000). Because `SO_PEERCRED` returns only the primary GID, legitimate operators are rejected with `EACCES: Access Denied`.
- **Risk:** Legitimate administrators belonging to group `sentinel` cannot administer the daemon.
- **Reproduction:** Connect from a user with UID 1000, primary GID 1000, and supplementary group `sentinel` (GID 998). The connection is rejected.
- **Remediation:** Check both `peer_gid == op_gid` AND query supplementary groups for `peer_uid` using `nix::unistd::getgrouplist` or `/etc/group` lookup.

---

### DEF-08: Destructive Live VM Test Harness (`pkill -9 sentineld` and Host Socket Removal)
- **Classification:** Confirmed Defect
- **Criticality:** HIGH (P1)
- **Files & Locations:**
  - `tests/run_live_vm_tests.sh:79, 114-115`
- **Description:**
  The test script executes:
  ```bash
  systemctl stop sentineld
  pkill -9 sentineld 2>/dev/null || true
  rm -f /run/sentinel/sentinel.sock /run/sentinel/sentinel-ro.sock /run/sentinel/privileged.sock
  ```
  This kills all processes matching `sentineld` system-wide and alters production sockets.
- **Risk:** Uncontrolled termination of external daemon instances and violation of safe testing requirements.
- **Reproduction:** Inspect line 114 of `tests/run_live_vm_tests.sh`.
- **Remediation:** Rewrite test runner to manage only its own child PID (`kill -TERM "$DAEMON_PID"`), use isolated temporary directories (e.g. `/tmp/sentinel_test_XXXXXX`), and execute within network/PID namespaces.

---

### DEF-09: Taint Data Flow Graph Path Corruption & Single-Hop Limitation
- **Classification:** Confirmed Defect
- **Criticality:** HIGH (P1)
- **Files & Locations:**
  - `crates/sentineld/src/lineage/graph.rs:232-264`
- **Description:**
  In `find_data_flow_path`:
  1. Failed search branches push initial reader edges into `path` without backtracking or clearing, resulting in polluted or incorrect causal paths.
  2. The algorithm only checks 1 hop (`reader -> pipe -> recipient`). Chains involving multiple pipes or intermediate scripts (`secret -> process A -> pipe 1 -> process B -> pipe 2 -> process C`) fail to resolve.
  3. Comparisons use raw `u32` PIDs (`e.process.pid == reader.process.pid`) rather than `ProcessKey`, making it prone to PID reuse confusion.
- **Risk:** Inaccurate or broken causality graphs in forensic incident reports.
- **Remediation:** Implement recursive/breadth-first traversal on `ProcessKey` with explicit backtracking.

---

### DEF-10: Terminated Processes Accessing Secrets Never Pruned by `prune_dead`
- **Classification:** Confirmed Defect
- **Criticality:** HIGH (P1)
- **Files & Locations:**
  - `crates/sentineld/src/lineage/graph.rs:285-301`
- **Description:**
  Line 289 explicitly states:
  ```rust
  if key.tgid <= 2 || !node.secret_accesses.is_empty() {
      continue;
  }
  ```
  If a process ever accessed a secret and subsequently exits, it is never pruned by `prune_dead`. While the LRU cache caps total nodes at 8192, dead secret-accessing nodes accumulate until evicted by cache pressure.
- **Risk:** Stale processes occupying lineage memory and potential correlation confusion if PIDs are recycled.
- **Remediation:** Allow pruning of dead processes if their secret accesses are older than a designated retention threshold (e.g., 2 hours).

---

## 3. Potential Risks & Architectural Observations (P2)

### RISK-01: Synchronous `fs::metadata` Call on Every Ingested SQLite Event
- **File:** `crates/sentineld/src/storage/database.rs:276-278`
- **Description:** On every single event processed by the storage worker, `std::fs::metadata(db_path)` executes a synchronous `stat` syscall to check database size. At 10,000 events/sec, this creates 10,000 unnecessary filesystem queries per second.
- **Remediation:** Sample database size once every 1,000 events or on periodic maintenance ticks.

### RISK-02: SQLite Individual Autocommit Writes Limiting Throughput
- **File:** `crates/sentineld/src/storage/database.rs:304-321`
- **Description:** Each `StoreEvent` command executes an individual `INSERT` statement without an enclosing batch transaction. Under write load, SQLite is throttled by filesystem sync.
- **Remediation:** Group writes into micro-batches (e.g., commit every 100 events or 50 ms).

### RISK-03: Bootloader Reconfiguration in `sntctl setup-kernel` Lacks Interactive Confirmation
- **File:** `crates/sntctl/src/commands/setup_kernel.rs:154-220`
- **Description:** Automatically edits `/etc/default/grub` or `/etc/kernel/cmdline` upon invocation without requiring `--yes` or prompting the operator for confirmation. Furthermore, errors in `backup_file` are suppressed via `let _ = backup_file(...)`.
- **Remediation:** Add confirmation prompts, fail if backup creation fails, and show a unified diff of planned changes.

### RISK-04: Systemd Service Capabilities Redundancy
- **Files:** `config/sentineld.service:28-29`, `config/sentinel-privileged.service:16-17`
- **Description:** `sentineld.service` retains `CAP_NET_ADMIN` and `CAP_KILL` even though `sentinel-privileged` exists to encapsulate these capabilities.
- **Remediation:** Minimize `sentineld` capabilities to `CAP_DAC_READ_SEARCH` and `CAP_PERFMON`/`CAP_BPF` as required, delegating network and signaling operations entirely to `sentinel-privileged`.

---

## 4. Comprehensive Audit Verification Checklist

| Domain | Finding ID | Severity | Status | Planned Phase |
| :--- | :--- | :---: | :---: | :---: |
| CI/CD | DEF-01: Audit exit code suppression | Critical | Confirmed | Phase II |
| Supply Chain | DEF-02: libsqlite3-sys CVE-2026-119375 | High | Confirmed | Phase II |
| Rust Quality | DEF-06: Clippy field reassign warnings | High | Confirmed | Phase II |
| IPC / Security | DEF-04: Arbitrary nftables string batch | Critical | Confirmed | Phase III |
| IPC / Security | DEF-07: Incomplete supplementary group check | High | Confirmed | Phase III |
| Firewall / Network | DEF-05: Ephemeral anti-lockout timer crash risk | Critical | Confirmed | Phase IV |
| Process Lineage | DEF-03: Clock ticks vs ns start time mismatch | Critical | Confirmed | Phase V |
| Taint Tracking | DEF-09: Unbounded / single-hop data flow path | High | Confirmed | Phase VI |
| Taint Tracking | DEF-10: Memory retention of dead secret nodes | High | Confirmed | Phase VI |
| Testing Harness | DEF-08: Destructive live testing script | High | Confirmed | Phase IX |
| Installation | RISK-03: Unconfirmed bootloader modifications | Medium | Confirmed | Phase XI |
| Storage | RISK-01: stat syscall storm on SQLite writes | Medium | Confirmed | Phase X |
| Storage | RISK-02: Non-batched autocommit write latency | Medium | Confirmed | Phase X |

---

## 5. Next Steps

With Stage I (Full Technical Audit & `INITIAL_AUDIT.md`) complete, execution proceeds directly to:
1. **Stage II:** CI/CD & Reproducible Build (updating dependencies, resolving Clippy errors, fixing `Cargo.lock`, removing audit suppression in `.github/workflows/ci.yml`).
2. **Stage III:** Security Architecture & Privilege Model (replacing raw nftables strings with typed `FirewallOperation`, implementing supplementary group checks).
3. **Stage IV:** Network Fail-Safe (implementing crash-resilient Anti-Lockout rollback in `sentinel-privileged`).
4. **Stage V:** Process Lineage & Anti-PID-Reuse (standardizing process identity and resolving start time unit mismatches).
5. **Stage VI–XIII:** Taint Tracking, Risk Engine, Kernel Matrix, Testing, Benchmarking, Systemd, Documentation, and Final Audit.
