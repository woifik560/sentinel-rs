# REMEDIATION PLAN: sentinel-rs Security & Reliability Hardening

**Plan Target:** Complete remediation of P0 (Critical Security) and P1 (Functional Reliability) defects identified in `AUDIT_REPORT.md`.

---

## Stage 2: Critical Security Fixes (P0)

### 2.1 Process Identity & Anti-PID-Reuse (P0)
- **Target File:** `crates/sentineld/src/response/process_term.rs`
- **Actions:**
  1. Rewrite `verify_process_identity_internal`:
     - Reject with `TerminationError::NotFound` if process stat cannot be read.
     - Reject with `TerminationError::VerificationFailed` on parse failure or IO error (strictly fail-closed; never silently ignore errors).
     - Fix `pidfd` verification: do not attempt to read `/proc/self/fd/<pidfd>/stat`. Instead, verify start time from `/proc/<pid>/stat` before opening pidfd, or verify `/proc/<pid>/stat` against the pinned process, and use `pidfd_send_signal(pidfd, 0, NULL, 0)` for atomic liveness check.
     - Strictly enforce expected executable check: if `expected_exe` is provided and `/proc/<pid>/exe` read fails or does not match canonical path, reject immediately.
     - Reject if `key.start_time_ns == 0` and no other attributes can be verified.
  2. Audit `crates/sentineld/src/freeze.rs`:
     - Remove raw `kill(pid, SIGKILL)` in `FreezeInspectOrchestrator::terminate_process`.
     - Route process termination through `safe_terminate_process` with `ProcessKey` and start time verification.
  3. Audit `crates/sentineld/src/main.rs`:
     - Ensure event loop destructive actions on `Verdict::High` use `safe_terminate_process` with validated keys.

### 2.2 eBPF Loader & BPF LSM State Machine (P0)
- **Target Files:**
  - `crates/sentinel-ebpf/src/loader.rs`
  - `crates/sentinel-common/src/health.rs`
  - `crates/sentineld/src/protection.rs`
- **Actions:**
  1. Define explicit subsystem states:
     - `Unsupported`: Kernel is older than required baseline or lacks eBPF support.
     - `Unavailable`: eBPF bytecode not loaded / BTF absent.
     - `Loading`: Currently initializing probes.
     - `Active`: Verified attachment of eBPF programs to kernel hooks.
     - `Degraded`: Partial hook attachment or running in tracepoint-only fallback.
     - `Failed`: Critical attachment failure.
  2. Implement Aya loader integration:
     - Check for eBPF ELF binary at configured/embedded path (`/usr/lib/sentinel/bpf/sentinel.bpf.o` or env `SENTINEL_BPF_OBJ`).
     - If available and kernel supports BPF LSM + BTF, load and attach using Aya.
     - If not available or unsupported, clearly transition to `Unavailable` or `Degraded` (Tracepoints fallback).
     - NEVER set `bpf_lsm_active = true` if LSM BPF programs are not attached.
  3. Cleanly isolate test simulations:
     - Explicitly document `simulate_file_open_check` as a test / fallback fixture.

### 2.3 nftables & Network Isolation (P0)
- **Target Files:**
  - `crates/sentineld/src/network/nftables.rs`
  - `crates/sentineld/src/network/manager.rs`
  - `crates/sentineld/src/response/network_block.rs`
  - `crates/sentineld/src/response/containment.rs`
- **Actions:**
  1. Fix nftables ruleset syntax:
     - In `Restricted` mode, fix SSH server response rule: match incoming established SSH traffic with `tcp sport 22` on output (not `dport 22`).
     - Implement real `Selective` isolation tier: maintain a dedicated set of blocked IP destinations and drop rules for marked flows, without wiping or duplicating general rules.
     - Prevent rule duplication by idempotently managing table `inet sentinel` (flushing specific chains or using named sets).
     - Validate batch rulesets with `nft -c -f -` prior to atomic execution.
  2. Fix error propagation:
     - Stop using raw `sh -c "nft ... 2>/dev/null"`. All operations must execute through `NftablesManager` with stderr capture and bubble errors up to the caller.
     - Fix `HostContainment::isolate_host()` to return `Result<(), anyhow::Error>`.

### 2.4 Privilege Separation & RBAC (P0)
- **Target Files:**
  - `crates/sentinel-privileged/src/`
  - `crates/sentineld/src/ipc_server.rs`
  - `config/sentineld.service`
- **Actions:**
  1. Formulate clear RBAC permissions matrix:
     - `RootAdmin` (UID 0): Full control (policy reload, protection toggle, manual kill, network isolation, unfreeze, incident clear).
     - `Operator` (GID 0 / sentinel group): Observability & diagnostics (status, health, doctor, lineage inspect, incident list/show, event streaming).
     - `ReadOnly` (UID >= 1000 on `sentinel-ro.sock`): Public queries & event streaming only.
  2. Harden IPC Server:
     - Wire `NetworkProtectionManager` with real Anti-Lockout timer to `IpcServer`.
     - Enforce concurrent connection limit (e.g. max 16 simultaneous clients).
     - Enforce command read and execution timeouts.
     - Never return fake success when operations fail.

---

## Stage 3: Functional Reliability (P1)

### 3.1 RingBuffer & Event Pipeline (P1)
- **Target Files:** `crates/sentineld/src/main.rs`, `crates/sentineld/src/collector/ringbuffer.rs`
- **Actions:**
  - Wire `RingBufferConsumer` with `EventMetrics` and rate limiting into the event processing pipeline in `main.rs`.
  - Expose drop and overflow metrics in `sntctl health` and `diagnostics`.

### 3.2 Process Lineage & Taint Tracking (P1)
- **Target Files:** `crates/sentineld/src/lineage/graph.rs`, `crates/sentinel-ebpf/src/maps.rs`
- **Actions:**
  - Ensure parent-child relationships and SCM_RIGHTS descriptor passing maintain causal integrity without mixing up recycled PIDs.

### 3.3 SQLite Persistence & Crash Recovery (P1)
- **Target Files:** `crates/sentineld/src/storage/database.rs`, `crates/sentineld/src/main.rs`
- **Actions:**
  - Ensure graceful shutdown drains the storage command queue and runs `PRAGMA wal_checkpoint(TRUNCATE)`.
  - Maintain disk space guard and integrity validation.

### 3.4 Daemon Lifecycle (P1)
- **Target Files:** `crates/sentineld/src/main.rs`
- **Actions:**
  - On SIGTERM/SIGINT, do not flush `table inet sentinel` if emergency containment was engaged by admin.
  - Coordinate shutdown of all background tasks.

---

## Stage 4: Test Infrastructure & Verification
- Unit tests for all updated modules.
- Integration tests in Linux WSL environment.
- Security tests covering PID reuse, unauthorized IPC commands, corrupted inputs.
- Recovery tests for daemon crashes and isolation rollbacks.
