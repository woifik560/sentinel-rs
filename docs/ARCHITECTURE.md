# Sentinel-RS Architecture Specification

## 1. Executive Summary

Sentinel-RS is a high-performance, autonomous, headless Host-based Intrusion Prevention System (HIPS) and Endpoint Detection & Response (EDR) agent engineered entirely in Rust for Linux Desktop and Linux Server platforms.

The system enforces real-time kernel-level behavioral prevention, deep causal process lineage tracking, multi-stage threat detection, and automated containment without any graphical desktop dependencies (no X11, Wayland, or Slint) and without interactive prompt requirements.

```
+-----------------------------------------------------------------------------------+
|                                  sntctl (CLI)                                     |
|  - SO_PEERCRED authentication over Unix domain sockets (/run/sentinel/sentinel.sock) |
+-----------------------------------------------------------------------------------+
                                          |
                                    Unix Sockets
                                          v
+-----------------------------------------------------------------------------------+
|                             sentineld (Host Daemon)                                |
|                                                                                   |
|  +---------------------+   +---------------------+   +--------------------------+ |
|  |   Event Collector   |-->|   Event Normalizer  |-->|  Process Lineage Engine  | |
|  | (Bounded RingBuffer)|   | (PID reuse, timing) |   | (Causal DAG & Identity)  | |
|  +---------------------+   +---------------------+   +--------------------------+ |
|                                                                    |              |
|  +---------------------+   +---------------------+                 v              |
|  |     Watchdog        |<--|    Health Monitor   |<----+ +----------------------+ |
|  | (sd_notify & BPF)   |   | (Subsystem Metrics) |     | |   Behavior Engine    | |
|  +---------------------+   +---------------------+     | | (Detection Rules)    | |
|                                                        | +----------------------+ |
|  +---------------------+   +---------------------+     |           |              |
|  |     Audit Logger    |<--|   Storage Manager   |     |           v              |
|  |  (RFC 5424 / WAL)   |   | (SQLite WAL Worker) |     | +----------------------+ |
|  +---------------------+   +---------------------+     | |     Risk Engine      | |
|                                      ^                 | | (Multi-stage Decay)  | |
|                                      |                 | +----------------------+ |
|  +---------------------+             |                 |           |              |
|  |  Incident Manager   |-------------+                 |           v              |
|  | (Temporal Correl.)  |                               | +----------------------+ |
|  +---------------------+                               | |    Policy Engine     | |
|            ^                                           | | (6-Stage Precedence) | |
|            |                                           | +----------------------+ |
|  +---------------------------------------------------+ |           |              |
|  |                 Response Orchestrator             |<+           v              |
|  |  (Anti-PID-Reuse Kill, Process Suspend, NetBlock) |<------------+              |
|  +---------------------------------------------------+                            |
+-----------------------------------------------------------------------------------+
                                          |
                                    eBPF / Netfilter
                                          v
+-----------------------------------------------------------------------------------+
|                               Kernel Space (Linux)                                |
|                                                                                   |
|  +---------------------+   +---------------------+   +--------------------------+ |
|  |    BPF LSM Hooks    |   |  BPF Tracepoints    |   |   BPF Maps & Storages    | |
|  | (bprm_check, mmap,  |   | (sched_process_exec,|   | (task_storage, sk_storage| |
|  |  file_open, ptrace) |   |  fork, sys_enter)   |   |  ring_buffer, taint_map) | |
|  +---------------------+   +---------------------+   +--------------------------+ |
|                                                                                   |
|  +---------------------+   +----------------------------------------------------+ |
|  |  Netfilter NFQUEUE  |   | nftables ruleset (sentinel-filter)                 | |
|  +---------------------+   +----------------------------------------------------+ |
+-----------------------------------------------------------------------------------+
```

---

## 2. Kernel Space Subsystem (`sentinel-ebpf`)

The kernel component operates at Ring 0 via eBPF (Extended Berkeley Packet Filter) and BPF LSM (Linux Security Module).

### 2.1 Hook Points
- **`lsm/bprm_check_security`**: Intercepts binary execution prior to memory mapping. Validates execution paths, detects fileless in-memory executions (`memfd_create`), verifies immutable administrative protections, and applies process credentials.
- **`lsm/file_open` & `lsm/file_permission`**: Monitors credential access (`/etc/shadow`, `~/.ssh/id_*`, GNOME Keyring, browser profiles, AWS/GCP cloud tokens) and enforces taint propagation across pipes and FIFOs.
- **`lsm/mmap_file`**: Detects anonymous executable mappings (`PROT_EXEC` on anonymous or writable memory) and cross-process shared memory injection.
- **`lsm/ptrace_access_check`**: Defends against debugging and process memory snooping (`PTRACE_ATTACH`, `process_vm_readv`, `/proc/$pid/mem`).
- **`lsm/unix_may_send`**: Intercepts inter-process communication over AF_UNIX sockets to track and prevent taint laundering across daemon boundaries.
- **`lsm/socket_connect` & `lsm/socket_sendmsg`**: Extracts destination socket endpoints (IPv4/IPv6, port) and binds flow contexts to socket storage (`sk_storage`).
- **`tracepoint/sched/sched_process_fork` & `sched_process_exec`**: Captures process lifecycle transitions to maintain causal ancestry without losing short-lived fork/exec sequences.

### 2.2 BPF Maps
- `ring_buffer`: Delivers low-latency, zero-copy security events from kernel to userspace daemon.
- `task_storage`: Per-task kernel metadata tracking PID taint flags, credential access counters, and lineage references.
- `sk_storage`: Per-socket metadata associating network flows with process security context.
- `taint_map`: Hash map tracking tainted processes, active policy marks, and broker process identities.
- `watchdog_map`: Array map holding userspace daemon heartbeat timestamps; monitored by kernel watchdog routines.

---

## 3. Userspace Daemon Subsystem (`sentineld`)

The daemon runs continuously as a privileged background systemd service (`Type=notify`).

### 3.1 Event Pipeline
1. **Collector (`src/collector/`)**: Pulls raw eBPF events from the BPF ring buffer asynchronously. Employs bounded queues to prevent unbounded memory growth under event bursts.
2. **Normalizer (`src/collector/event_normalizer.rs`)**: Transforms raw kernel structs into unified `NormalizedEvent` records, resolving PIDs, start timestamps, execution hashes, and security context.
3. **Process Lineage Engine (`src/lineage/`)**: Constructs a causal Directed Acyclic Graph (DAG) of all running processes. Tracks ancestor chains (`ancestor_chain`), detects orphan re-parenting, and identifies PID reuse via `/proc/<pid>/stat` start times.

### 3.2 Detection and Risk Evaluation
1. **Behavior Engine (`src/behavior/`)**: Evaluates incoming process, file, and network operations against a deterministic rule engine (LoLBin execution, reverse shells, shadow harvesting, memory dumping).
2. **Risk Engine (`src/risk/`)**: Calculates a normalized deterministic score ($0 \le S \le 100$). Supports:
   - Evidence deduplication within rolling evaluation windows.
   - Exponential half-life decay ($T_{1/2} = 300\text{s}$) for transient events.
   - Multi-stage attack compounding ($1.0\times$ for single tactic up to $1.6\times$ for full kill-chain progression).
   - Severity classification: **Low** (0-29), **Medium** (30-59), **High** (60-84), **Critical** (85-100).

### 3.3 Autonomous Policy Engine (`src/policy/`)
Evaluates decisions strictly through an immutable 6-stage precedence hierarchy:
1. **Stage 1 (Safety Rules)**: Never-Freeze allowlist (PID 1 systemd, PID 2 kthreadd, sentinel-rs processes). Absolute immunity against termination or suspension.
2. **Stage 2 (Protected Resources)**: Kernel and system-critical integrity invariants.
3. **Stage 3 (Administrative Deny)**: Explicit administrator blacklist rules (`PathPrefix`, `ExactPath`, `Sha256`, `CidrBlock`).
4. **Stage 4 (Administrative Allow)**: Explicit administrator whitelist rules.
5. **Stage 5 (Behavior Detection Matches)**: Rule-triggered actions based on confirmed high-confidence attack behaviors.
6. **Stage 6 (Operating Mode Defaults)**:
   - **AUDIT**: Log all events, permit all execution.
   - **BALANCED**: Terminate Critical threats, isolate/deny High network threats, monitor Medium/Low.
   - **STRICT**: Block/terminate High and Critical threats; deny non-whitelisted network activity.
   - **CUSTOM**: User-tailored action matrices based on granular severity thresholds.

### 3.4 Response Orchestrator (`src/response/`)
Executes precise response actions without human intervention:
- **Process Termination**: Enforces two-phase verification. Queries `/proc/<pid>/stat` (start time) and `/proc/<pid>/exe` prior to sending signals (`SIGSTOP` $\rightarrow$ verify $\rightarrow$ `SIGTERM` $\rightarrow$ `SIGKILL`) to prevent killing reused PIDs.
- **Process Suspension**: Issues `SIGSTOP` to halt suspect processes for forensic memory inspection; supports administrative unfreeze via `SIGCONT`.
- **Network Blocking & Isolation**: Manipulates kernel netfilter sets dynamically via `nftables` to drop targeted TCP/UDP flows or place the entire host in emergency quarantine (preserving loopback and management IPC).

### 3.5 Storage and Audit
- **Storage Manager (`src/storage/`)**: Asynchronous worker thread managing SQLite in Write-Ahead Logging (WAL) mode. Bounded event queue (`10,000` items) drops non-critical telemetry under extreme load to prevent memory exhaustion, while response actions and incident records are guaranteed storage.
- **Audit Logger (`src/audit/`)**: Emits structured RFC 5424 syslog and JSON audit trails for compliance and SIEM integration.

---

## 4. CLI Management Tool (`sntctl`)

`sntctl` is a lightweight, zero-dependency command-line client communicating with `sentineld` over `/run/sentinel/sentinel.sock` using JSON Lines IPC.

Capabilities include:
- `sntctl status` & `sntctl health`: Live system health, memory consumption, queue saturation, and degraded state metrics.
- `sntctl doctor`: Comprehensive environment diagnostics (kernel version, BPF LSM, BTF, cgroups, nftables).
- `sntctl protection [enable|disable|status]`: Global enforcement state toggle.
- `sntctl events tail`: Real-time streaming audit and telemetry feed.
- `sntctl incidents [list|show|resolve]`: Incident lifecycle and forensic investigation.
- `sntctl policy [list|reload|test]`: Security rule management and offline syntax validation.
- `sntctl process [inspect|lineage|kill|suspend|unfreeze]`: Targeted process control with PID-reuse protection.
- `sntctl network [status|isolate|unisolate|block-ip|unblock-ip]`: Host network containment and IP filtering.

---

## 5. Platform Compatibility Architecture

Both Linux Desktop and Linux Server platforms share an identical security engine core:
- **Server Environments**: Headless server distributions (Ubuntu Server, Debian, RHEL, Rocky Linux) run `sentineld` as a minimal background daemon consuming $< 30\text{MB}$ RSS.
- **Desktop Environments**: Modern desktop installations (Ubuntu, Fedora, Arch) benefit from the same headless engine without requiring desktop session integrations, desktop display managers, or graphical toolkits.
