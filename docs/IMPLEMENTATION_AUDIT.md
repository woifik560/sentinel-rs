# Sentinel-RS Implementation Audit & Repository Inventory
**Phase 0: Complete Repository Baseline & Architecture Audit**
**Date:** 2026-11-17
**Architect:** Principal Linux Security Architect & Senior Rust Systems Engineer

---

## 1. Executive Summary

This document establishes the verified inventory, dependency map, security architecture audit, and baseline verification for **Sentinel-RS** prior to transformation from a desktop GUI firewall/anti-stealer into a headless, autonomous Linux HIPS/EDR agent.

### Baseline Status
- **Workspace Build:** `cargo check --workspace` — **PASSED** (0 errors, 2 warnings in `sentinel-gui`).
- **Workspace Tests:** `cargo test --workspace` — **PASSED** (76 tests passed, 0 failed, 0 ignored).
- **Rust Toolchain:** rustc 1.95.0, cargo 1.95.0, host target `x86_64-unknown-linux-gnu`.
- **Operating Environment:** Linux 6.6.87.2-microsoft-standard-WSL2.

---

## 2. Workspace Crate Inventory

| Crate | Directory | Target Type | Responsibilities & Status |
| :--- | :--- | :--- | :--- |
| `sentinel-common` | `crates/sentinel-common` | Library | Core data structures: `EbpfEvent`, `ProcessNode`, `RiskScore`, `IncidentReport`, IPC messages, configuration models. **Keep & extend**. |
| `sentinel-ebpf` | `crates/sentinel-ebpf` | Library | eBPF userspace loader (`EbpfLoader`), BPF maps manager (`TaintMapManager`), kernel LSM hook abstractions, tracepoint definitions. **Keep & harden**. |
| `sentineld` | `crates/sentineld` | Binary & Lib | Core daemon: event ingestion, lineage tracking, NFQUEUE holding, TOFU, DPKG integrity, risk scoring, IPC server. **Transform into autonomous HIPS/EDR daemon**. |
| `sntctl` | `crates/sntctl` | Binary | CLI management utility: doctor, status, monitor, export, unfreeze, kernel setup. **Expand for full headless agent control**. |
| `sentinel-gui` | `crates/sentinel-gui` | Binary | Slint-based graphical user interface for interactive prompt triage. **TARGET FOR COMPLETE REMOVAL**. |

---

## 3. GUI Dependency Map (To Be Completely Removed)

### 3.1. Crates and Dependencies
- `crates/sentinel-gui/`: Complete deletion.
- Cargo manifests: `Cargo.toml` workspace member `"crates/sentinel-gui"`.
- Crates using Slint (`slint = "1.8"`).
- Build scripts and visual assets (`sentinel-gui.service`).

### 3.2. GUI Authentication & Desktop Session Ties
- **`ClientRole::AuthorizedGui`**: Located in `sentinel-common/src/ipc.rs` and `sentineld/src/ipc_server.rs`.
- **GUI Binary Attestation**: In `sentinel-ebpf/src/maps.rs` (`register_gui_binary`, `is_registered_gui_binary`, `set_gui_pid`, `is_verified_gui`) and `bprm_check_security.rs`.
- **X11 Verification PIN & Session Checks**: `is_x11_session`, `auth_pin`, `failed_pin_attempts` in `sentinel-common/src/ipc.rs` and `sentineld/src/ipc_server.rs`.
- **Interactive Verdict Workflows**: `PromptRequest`, `PromptVerdict`, `PromptAction` in `sentinel-common/src/ipc.rs`; `VerdictRouter::route` routing `Verdict::Grey` to interactive prompt; `FreezeInspectOrchestrator` waiting for user verdicts.
- **Config & Allowlist References**: `gui_binary_path` in `SocketConfig` and `sentinel-gui` in `default_never_freeze_list()`.

### 3.3. Rationale for Replacement
The previous GUI attestation protected against unprivileged local malware connecting to `/run/sentinel/sentinel.sock` under the same user UID and approving its own network connections. In the headless HIPS/EDR agent:
- All decisions are made **autonomously** by the deterministic Policy Engine.
- No user prompts exist.
- Management IPC is restricted via `SO_PEERCRED` with explicit role-based access control (RBAC): `ROOT_ADMIN` (UID 0), `OPERATOR`, and `READ_ONLY`.

---

## 4. Kernel eBPF Architecture & Map Inventory

### 4.1. Programs and Hooks
1. `lsm/bprm_check_security`: Intercepts `security_bprm_check_security`. Identifies anonymous memory executions (`memfd_create`), sets `PROFILE_FILELESS_MEMFD`, and pre-evaluates baseline profile in `TASK_STORAGE`.
2. `lsm/file_open`: Intercepts `security_file_open`. Detects sensitive credential access (`~/.ssh`, `~/.gnupg`, browser vaults, wallets, cloud tokens) and sets taint flags in `TASK_STORAGE`.
3. `lsm/file_permission`: Intercepts `security_file_permission`. Enforces taint hygiene and tracks data-flow taint propagation across pipes (`cat secret | curl`), FIFOs, and temporary files.
4. `lsm/file_receive`: Intercepts `security_file_receive` for file descriptors passed via `SCM_RIGHTS` over AF_UNIX sockets.
5. `lsm/mmap_file`: Intercepts `security_mmap_file`. Detects secret reads via `mmap(MAP_SHARED)`, shared memory taint, and anonymous executable mappings (`PROT_EXEC` on deleted/tmpfs files).
6. `sched/sched_process_exec`: Tracepoint capturing binary executions, executable replacement, and command lines.
7. `sched/sched_process_fork`: Tracepoint capturing process fork events; propagates taint flags from parent `TASK_STORAGE` to child `TASK_STORAGE`.
8. `lsm/ptrace_access_check`: Intercepts `security_ptrace_access_check`. Prevents tainted processes from inspecting memory of untainted processes and protects the daemon.
9. `lsm/socket_connect`: Intercepts `security_socket_connect`. Fast-Path allow for clean processes, Slow-Path packet hold via `SO_MARK` (0x5E000000 prefix) for tainted processes.
10. `lsm/socket_sendmsg`: Intercepts `security_socket_sendmsg` for connectionless UDP (DNS, QUIC) and pre-opened sockets.
11. `lsm/unix_may_send`: Intercepts `security_unix_may_send` to block taint laundering attempts over AF_UNIX sockets.

### 4.2. Storage & Maps
- **`TASK_STORAGE`** (`BPF_MAP_TYPE_TASK_STORAGE`): BPF object storage per task struct. Stores `TaskStorageEntry` (taint flags, baseline profile, execution ID, cgroup ID). Eliminates PID reuse races.
- **`INODE_STORAGE`** (`BPF_MAP_TYPE_INODE_STORAGE`): Inode storage tracking secret flags, taint status, and trusted package cache.
- **`SK_STORAGE`** (`BPF_MAP_TYPE_SK_STORAGE`): Per-socket storage for socket cookies, marks, and connection state.
- **`flow_mark_ctx`**: BPF hash map mapping monotonic `flow_id` to `FlowContext` synchronously before socket marks are applied.
- **`watchdog_heartbeat`**: BPF array map updated with kernel timestamp every 500ms for hybrid kernel watchdog.
- **RingBuffer**: Event delivery stream from kernel to userspace (`EbpfEvent`).

---

## 5. Event Pipeline and Representation

### 5.1. Raw eBPF Events
- `RawFileOpenEvent`
- `RawFilePermissionEvent`
- `RawBprmCheckSecurityEvent`
- `RawProcessForkEvent`
- `RawProcessExecEvent`
- `RawSocketConnectEvent`
- `RawSocketSendmsgEvent`
- `RawUnixMaySendEvent`
- `RawPtraceAccessCheckEvent`
- `RawMmapFileEvent`
- `RawFileReceiveEvent`

### 5.2. Deficiencies Identified in Existing Pipeline
1. **Lack of Central Event Normalizer:** Events are matched directly in a `while let Some(event) = event_rx.recv().await` loop in `main.rs`.
2. **Missing Canonical Process Key:** Existing lineage tracks `tgid: u32` directly without combining PID with process start time or kernel boot timestamp, leaving a potential edge case for PID recycling.
3. **Absence of Event Metrics:** No drop counters, queue saturation metrics, or latency tracking.
4. **Missing Storage Persistence:** Events and incidents are only held in memory in LRU structures; no persistent SQLite storage exists.

---

## 6. IPC Protocol and Command Map

### 6.1. Current State
- Dual socket: `/run/sentinel/sentinel.sock` (privileged) and `/run/sentinel/sentinel-ro.sock` (read-only).
- JSON line-delimited message streaming.
- Supported messages: `Prompt`, `Verdict`, `StatusRequest`, `StatusResponse`, `Subscribe`, `Event`, `Unfreeze`, `ExportRequest`, `ExportResponse`, `AuthError`.

### 6.2. Transformation Requirements
1. Unify on `/run/sentinel/sentinel.sock` with fine-grained per-command RBAC validated via `SO_PEERCRED`.
2. Adopt a structured request/response protocol with `request_id`, status, timestamp, and typed payloads.
3. Remove interactive prompt/verdict commands.
4. Implement complete command suite:
   - `status`, `health`, `diagnostics`
   - `protection.status`, `protection.enable`, `protection.disable`
   - `events.list`, `events.show`, `events.export`
   - `incidents.list`, `incidents.show`, `incidents.export`
   - `policy.list`, `policy.show`, `policy.validate`, `policy.reload`
   - `rules.list`, `rules.show`
   - `process.inspect`, `process.lineage`
   - `network.status`, `network.blocked`

---

## 7. Systemd and Linux Capabilities

### 7.1. Current Unit Configuration (`config/sentineld.service`)
- `Type=simple`
- Capabilities: `CAP_BPF`, `CAP_NET_ADMIN`, `CAP_DAC_READ_SEARCH`, `CAP_SYS_PTRACE`.
- Hardening: `ProtectHome=read-only`, `ProtectSystem=strict`, `PrivateTmp=yes`, `LockPersonality=yes`, `RestrictRealtime=yes`, `NoNewPrivileges=yes`.

### 7.2. Transformation Requirements
- Switch to `Type=notify` using native `sd_notify` (`READY=1` on complete initialization, `WATCHDOG=1` during active processing loop).
- Add signal handling for `SIGTERM`/`SIGINT` (graceful shutdown) and `SIGHUP` (transactional configuration reload).
- Remove `sentinel-gui.service`.
- Audit capabilities: ensure `CAP_SYS_ADMIN` or fallback capabilities are documented for older kernels.

---

## 8. Test Baseline Verification

Baseline tests executed in WSL2 (Kernel 6.6.87.2, Rust 1.95.0):
```text
running 9 tests in sentinel_common ... ok
running 16 tests in sentinel_ebpf ... ok
running 3 tests in kernel_ring0 ... ok
running 10 tests in sentineld (lib) ... ok
running 10 tests in sentineld (main) ... ok
running 22 tests in adversarial_e2e ... ok
running 16 tests in red_team ... ok
Total: 76 passed, 0 failed, 0 ignored.
```

---

## 9. Next Steps (Phase Progression)

1. **PHASE 1: GUI Removal** — Eliminate `crates/sentinel-gui`, remove Slint, clean Cargo manifests, remove GUI attestation and X11 PINs, replace interactive verdicts with deterministic decisions.
2. **PHASE 2: Headless Daemon** — Restructure `sentineld` into modular subsystems (`collector`, `lineage`, `behavior`, `risk`, `policy`, `response`, `incidents`, `storage`, `network`, `ipc`, `health`, `config`, `audit`).
3. **PHASE 3: Secure IPC & CLI Expansion** — Versioned protocol, SO_PEERCRED RBAC, full command set in `sntctl`.
4. **PHASE 4: Event Collection & Process Lineage** — Normalizer, canonical process keys (`pid + start_time_ns`), drop metrics.
5. **PHASE 5: Behavior Detection Engine** — Deterministic detection rules, correlation windows, anti-evasion.
6. **PHASE 6: Autonomous Policy & Risk Engine** — Precedence hierarchy, AUDIT/BALANCED/STRICT/CUSTOM modes.
7. **PHASE 7: Response Engine** — Automated containment, process termination verification, atomic nftables isolation.
8. **PHASE 8: SQLite Storage & Incident Management** — WAL mode, schema migrations, persistent incidents and forensic history.
9. **PHASE 9: Systemd Integration & Hardening** — `sd_notify`, watchdog integration, signal handling.
10. **PHASE 10: Validation & Documentation** — Comprehensive test execution, compatibility matrix, benchmark analysis, documentation.
