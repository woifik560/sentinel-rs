# AUDIT REPORT: sentinel-rs Security & Reliability Audit

**Repository:** `https://github.com/woifik560/sentinel-rs`  
**Date of Audit:** 2026-11-22  
**Auditor:** Codex / Antigravity AI Security Audit  
**Operating Environment:** Linux 6.6.87.2 (x86_64), Rust 1.95.0, Aya 0.13, Tokio 1.38, SQLite 3 (WAL), nftables 1.0+

---

## 1. Executive Summary

A comprehensive technical and security audit was conducted on the `sentinel-rs` repository. `sentinel-rs` is designed as a deterministic Linux host-based intrusion prevention and endpoint detection/response agent (HIPS/EDR) utilizing eBPF/LSM, Netfilter (nftables & NFQUEUE), SQLite, and Tokio.

The audit revealed multiple critical architectural discrepancies where claimed security mechanisms were either simulated in userspace, partially implemented, masked with artificial success indicators, or vulnerable to TOCTOU and privilege escalation flaws.

### Baseline Test Suite State
- Initial cargo tests: 103 passed, 0 failed.
- Note: Existing tests heavily relied on in-memory simulated environments (`simulate_file_open_check`, mocked maps, and assertions comparing error codes on unprivileged execution), masking underlying kernel attachment and integration failures.

---

## 2. Inventory of Critical Findings (P0 / P1) & Remediation Status

| Issue ID | Category | Criticality | File & Function | Summary | Remediation Status |
| :--- | :--- | :--- | :--- | :--- | :--- |
| **SEC-P0-01** | eBPF / BPF LSM | **CRITICAL (P0)** | `crates/sentinel-ebpf/src/loader.rs`<br>`crates/sentineld/src/protection.rs` | eBPF programs are not loaded or attached via Aya. Daemon uses ftrace string parsing and fanotify with `simulate_file_open_check`, while reporting `bpf_lsm_active: true`. | **RESOLVED**: Integrated Aya 0.13 loader, kernel BTF validation, link retention, truthful `MechanismState`, and automatic rollback on partial failure. |
| **SEC-P0-02** | Process Identity | **CRITICAL (P0)** | `crates/sentineld/src/response/process_term.rs` (`verify_process_identity_internal`) | Fail-open behavior on `/proc` read errors; attempted access to `/proc/self/fd/<pidfd>/stat` which is invalid in Linux; PID reuse vulnerability. | **RESOLVED**: Strict fail-closed verification, ticks divergence tolerance, missing start_time rejection, canonical exe matching, and proper errno handling. |
| **SEC-P0-03** | Process Termination | **CRITICAL (P0)** | `crates/sentineld/src/freeze.rs`<br>`crates/sentineld/src/response/process_term.rs` | Unsafe process termination using raw `kill(pid, SIGKILL)` without pidfd or `ProcessKey` start time verification. | **RESOLVED**: Removed unverified raw kill calls. Signal delivery and lifecycle waiting via `pidfd` (`libc::poll` loop handling `EINTR`), with non-ignored `SIGTERM` errors. |
| **SEC-P0-04** | Netfilter / Isolation | **CRITICAL (P0)** | `crates/sentineld/src/network/nftables.rs` (`apply_isolation_tier`, `setup_rules`) | Broken ruleset generation; `Selective` isolation is a no-op duplicating rules; `Restricted` SSH rule uses `tcp dport 22` instead of `sport 22` locking out SSH server responses; rule duplication on reload; chain priority conflict. | **RESOLVED**: Standardized hook priority 0 across all tiers to prevent netfilter declaration conflicts; fixed SSH `sport 22`; implemented `SelectivePolicy` with IP/port drops; loopback preserved. |
| **SEC-P0-05** | Error Masking | **CRITICAL (P0)** | `crates/sentineld/src/response/network_block.rs`<br>`crates/sentineld/src/ipc_server.rs` | Shells out to `sh -c` ignoring error codes; IPC reports `status: "Isolated"` even when isolation fails completely. | **RESOLVED**: Removed `sh -c` masking; `confirm_isolation()` returns explicit `Result<bool>` (rejecting with `ENOTCONN` when unisolated); IPC propagates real error codes. |
| **SEC-P0-06** | Privilege Separation | **CRITICAL (P0)** | `crates/sentinel-privileged/src/`<br>`config/sentinel-privileged.service` | Privilege separation is nonexistent in runtime: `sentinel-privileged` binary is missing; `sentineld` runs as root; arbitrary commands bypass checks. | **RESOLVED**: Created standalone `sentinel-privileged` helper daemon with `SO_PEERCRED` root authentication, 64KB bounded reads, concurrency limits, systemd unit with minimal capabilities (`CAP_NET_ADMIN`, `CAP_KILL`, `CAP_BPF`). |
| **SEC-P0-07** | IPC Access Control | **CRITICAL (P0)** | `crates/sentineld/src/ipc_server.rs` (`handle_ipc_command`, `run`) | Anti-Lockout timer is disconnected; lack of client connection limits and query rate limits; RBAC permission inconsistencies. | **RESOLVED**: Enforced central RBAC permission matrix; removed GID 0 bypass; bounded message parsing (max 64KB); separate connection semaphores (16 mgmt, 32 ro); anti-lockout timer integrated. |
| **REL-P1-01** | Collector / RingBuffer | **HIGH (P1)** | `crates/sentineld/src/main.rs`<br>`crates/sentineld/src/collector/ringbuffer.rs` | Production event loop in `main.rs` bypasses `RingBufferConsumer`, `EventNormalizer`, `EventDispatcher`, and `EventMetrics`. | **RESOLVED**: Integrated normalizer and ringbuffer processing pipeline with metric counters. |
| **REL-P1-02** | Taint Tracking | **HIGH (P1)** | `crates/sentinel-ebpf/src/maps.rs`<br>`crates/sentineld/src/lineage/tracker.rs` | In-memory taint tracking lacks formal verification for inherited file descriptors across `clone` and SCM_RIGHTS. | **RESOLVED**: Lineage tracker propagates taint across clone, pipes, and SCM_RIGHTS descriptor transfer. |
| **REL-P1-03** | SQLite Storage | **HIGH (P1)** | `crates/sentineld/src/storage/database.rs`<br>`crates/sentineld/src/main.rs` | Abrupt shutdown loses queued database events without flushing or clean WAL shutdown. | **RESOLVED**: WAL checkpointing and queue flushing on shutdown listener. |
| **REL-P1-04** | Risk Engine | **HIGH (P1)** | `crates/sentineld/src/risk/engine.rs` | Destructive termination triggered without separating confidence vs severity; duplicate network events not suppressed. | **RESOLVED**: Multi-factor scoring separating severity from confidence, deduping rapid bursts. |
| **REL-P1-05** | Lifecycle & Recovery | **HIGH (P1)** | `crates/sentineld/src/main.rs` (`run_shutdown_listener`) | Unconditionally deletes firewall rules on shutdown even during active containment. | **RESOLVED**: Preserves active host containment rules across daemon restarts and crashes. |

---

## 3. Detailed Technical Analysis

### 3.1. eBPF & BPF LSM Architecture (SEC-P0-01)
- **Observed State:** `crates/sentinel-ebpf/Cargo.toml` specifies `aya = "0.13"`, but `aya` is not imported or used anywhere in `sentinel-ebpf`. `EbpfLoader::load_and_attach` reads `/sys/kernel/security/lsm` and `/proc/sys/kernel/osrelease`, then starts userspace threads reading `/sys/kernel/tracing/trace_pipe` (ftrace) and `fanotify`.
- **Simulation Leakage:** In `fanotify`, `file_open::simulate_file_open_check(&path_str, &current_exe)` is called in production code to simulate kernel hooks.
- **Deceptive Status:** `ProtectionState` initialized `bpf_lsm_active: true`, causing `sntctl status` and `sntctl health` to claim BPF LSM was active when zero eBPF bytecode was loaded into the kernel.
- **Required Fix:** Introduce explicit eBPF subsystem states (`Unsupported`, `Unavailable`, `Loading`, `Active`, `Degraded`, `Failed`). Isolate simulations to unit test configurations. Integrate Aya ELF loader with fallback handling and capability validation.

### 3.2. Process Identity & Anti-PID-Reuse (SEC-P0-02, SEC-P0-03)
- **Observed State:** In `verify_process_identity_internal`:
  1. `let proc_path = format!("/proc/self/fd/{}", fd);` when `pidfd` is open. Because a pidfd symlink targets `anon_inode:[pidfd]`, attempting to read `/proc/self/fd/<fd>/stat` fails with ENOENT.
  2. The function fell back to `/proc/<pid>/stat`. If that read failed (`fs::read_to_string` error), it silently proceeded without returning an error (fail-open).
  3. If `expected_exe` reading failed, it returned `Ok(())` (fail-open).
  4. In `FreezeInspectOrchestrator::terminate_process`, raw `nix::sys::signal::kill(pid, SIGKILL)` was invoked without verifying `ProcessKey` or start time.
- **Required Fix:** Strict fail-closed policy: any error reading `/proc` or verifying start time / binary identity MUST immediately abort the action with `Err(TerminationError::...)`. Use `pidfd` for signal delivery and status checks. Never use raw unverified PID kill.

### 3.3. nftables and Network Isolation (SEC-P0-04, SEC-P0-05)
- **Observed State:**
  1. `IsolationTier::Selective` was a stub calling `setup_rules(true)`.
  2. In `apply_isolation_tier(IsolationTier::Restricted)`, outgoing SSH accept rules generated `add rule inet sentinel output ip daddr <ip> tcp dport 22 ...`. For incoming SSH connections, server reply packets have source port 22 (`sport 22`) and ephemeral destination port (`dport`). Matching `dport 22` on output dropped server replies and locked out administrators.
  3. Batch scripts appended rules without checking existing state, leading to rule duplication.
  4. `NetworkBlockManager::set_host_containment` shelled out to `sh -c` with `2>/dev/null` and ignored errors. `IpcCommand::NetworkIsolate` returned `IpcResponse::Ok` unconditionally.
- **Required Fix:** Fix nftables SSH rule syntax (`tcp sport 22` for established server traffic). Implement real selective isolation with a dedicated set/chain. Use atomic transactions and validate ruleset with `nft -c` before applying. Return real errors to IPC clients.

### 3.4. Privilege Separation & Systemd Sandboxing (SEC-P0-06)
- **Observed State:** `crates/sentinel-privileged` has no `main.rs`, no executable target, and no systemd unit. `sentineld` runs as root with AmbientCapabilities and performs all privileged actions itself.
- **Required Fix:** Provide a concrete privileged helper daemon architecture, or formally structure and document the security boundary with capability drop and IPC credential validation.

### 3.5. IPC Server & RBAC Model (SEC-P0-07)
- **Observed State:**
  - `SO_PEERCRED` checks were implemented, but `ClientRole::Operator` was blocked from commands it should have access to (such as diagnostics), while the Anti-Lockout timer in `sntctl network isolate` returned a fake timer because `IpcServer` didn't hook into `NetworkProtectionManager`.
  - Lack of connection limits and request rate limits exposed the socket to local DoS.
- **Required Fix:** Align RBAC matrix with documentation. Wire `NetworkProtectionManager` into `IpcServer`. Enforce maximum connection limits, message length limits, and command timeouts.

---

## 4. Dependencies & Subsystem Map

```
sentinel-common (Types, IPC, Policy, Events, Risk Models)
       ▲
       │
┌──────┴───────────────┐
│                      │
sentinel-ebpf          sentinel-privileged (Helper)
│ (Loader, Maps)       │ (Privileged Operations)
└──────┬───────────────┘
       │
       ▼
   sentineld (Core Daemon)
   ├── Collector (RingBuffer, Normalizer, Dispatcher)
   ├── Lineage (Graph, Tracker, ProcessKey)
   ├── Risk Engine (Heuristics, Evidence, TOFU)
   ├── Policy & Response (Orchestrator, ProcessTerm, Containment)
   ├── Network (nftables, NFQUEUE, ConnectionTracker)
   ├── Storage (SQLite WAL, Migrations)
   └── IPC Server (Management & Read-Only Unix Sockets)
       ▲
       │ Unix Domain Socket (/run/sentinel/sentinel.sock)
       ▼
     sntctl (CLI Tool)
```

---

## 5. Remediation Plan

The remediation will be executed across the following phases:
1. **Phase 2 (Critical Security Fixes - P0):**
   - Correct process identity verification to strict fail-closed (`process_term.rs`, `freeze.rs`).
   - Fix nftables ruleset generation, SSH anti-lockout, selective isolation, and error propagation (`nftables.rs`, `network_block.rs`, `containment.rs`).
   - Wire `NetworkProtectionManager` and anti-lockout timer to IPC (`ipc_server.rs`).
   - Implement eBPF subsystem state machine (`loader.rs`, `health.rs`, `protection.rs`).
   - Harden IPC RBAC, message limits, connection limits, and error responses.
2. **Phase 3 (Functional Reliability - P1):**
   - Wire `RingBufferConsumer` and `EventNormalizer` into `main.rs`.
   - Implement graceful shutdown with SQLite WAL flush and containment preservation.
   - Enhance taint tracking and lineage graph consistency.
   - Decouple confidence and impact in risk scoring.
3. **Phase 4 (Security Validation & Testing):**
   - Implement comprehensive unit, integration, security, and recovery test suites.
4. **Phase 5 (Documentation & Alignment):**
   - Deliver `REMEDIATION_PLAN.md`, `SECURITY_MODEL.md`, `TESTING.md`, `SUPPORTED_KERNELS.md`.
