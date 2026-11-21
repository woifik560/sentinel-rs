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
|                          sentineld (Core Daemon, Unprivileged)                    |
|                                                                                   |
|  +---------------------+   +---------------------+   +--------------------------+ |
|  |   Event Collector   |-->|   Event Normalizer  |-->|  Process Lineage Engine  | |
|  | (RingBuffer Drops)  |   | (C ABI, Repr C, TS) |   | (2-Tier DAG: Process &   | |
|  +---------------------+   +---------------------+   |  Data Flow, ProcessKey)  | |
|                                                      +--------------------------+ |
|  +---------------------+   +---------------------+                 |              |
|  |     Watchdog        |<--|    Health Monitor   |<----+           v              |
|  | (sd_notify 15s /    |   | (AgentState Machine,|     | +----------------------+ |
|  |  WATCHDOG=1 on OK)  |   |  FailurePolicyMgr)  |     | |   Behavior Engine    | |
|  +---------------------+   +---------------------+     | | (Detection Rules)    | |
|                                                        | +----------------------+ |
|  +---------------------+   +---------------------+     |           |              |
|  |     Audit Logger    |<--|   Storage Manager   |     |           v              |
|  |  (RFC 5424 / WAL)   |   | (SQLite WAL/Checkpt)|     | +----------------------+ |
|  +---------------------+   +---------------------+     | |  Evidence Risk Engine| |
|                                      ^                 | |(Confidence & Impact) | |
|                                      |                 | +----------------------+ |
|  +---------------------+             |                 |           |              |
|  |  Incident Manager   |-------------+                 |           v              |
|  | (Temporal Correl.)  |                               | +----------------------+ |
|  +---------------------+                               | |    Policy Engine     | |
|            ^                                           | |(Decision Verification)| |
|            |                                           | +----------------------+ |
|  +---------------------------------------------------+ |           |              |
|  |                 Response Orchestrator             |<+           v              |
|  | (ProcessProtectionPolicy, Anti-Lockout Isolation) |<------------+              |
|  +---------------------------------------------------+                            |
+-----------------------------------------------------------------------------------+
                                          |
                               Privileged IPC (/run/sentinel/privileged.sock)
                                          v
+-----------------------------------------------------------------------------------+
|                         sentinel-privileged (Privileged Helper)                   |
|  - eBPF probe attach/detach & BPF maps management                                  |
|  - Linux pidfd operations (pidfd_open, pidfd_send_signal SIGSTOP/SIGTERM/SIGKILL)   |
|  - nftables atomic batch transactions (table inet sentinel only)                  |
|  - Minimized capabilities: CAP_BPF, CAP_PERFMON, CAP_NET_ADMIN, CAP_KILL,          |
|    CAP_DAC_READ_SEARCH (CAP_SYS_ADMIN and CAP_SYS_PTRACE dropped)                |
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
|  |  Netfilter NFQUEUE  |   | nftables ruleset (table inet sentinel)             | |
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

The daemon runs continuously as a hardened background systemd service (`Type=notify`, `WatchdogSec=15s`).

### 3.1 Event Pipeline
1. **Collector (`src/collector/`)**: Pulls raw eBPF events from the BPF ring buffer asynchronously. Tracks ring buffer loss metrics (`RingBufferMetrics`), per-PID rate limits with safety bypass for critical events, and bounds check guarantees.
2. **Normalizer (`src/collector/event_normalizer.rs`)**: Transforms raw C-compatible kernel structs (`#[repr(C)]`) into validated, type-safe `NormalizedEvent` records, preventing unsafe slice casts and validating alignment and string bounds.
3. **Two-Tier Process Lineage Engine (`src/lineage/`)**:
   - **Composite ProcessKey**: Processes are tracked using `ProcessKey` (`pid`, `tgid`, `start_time_ns`, `pid_namespace`, `dev_ino`, `exe_path`), stored in an `LruCache<ProcessKey, ProcessNode>` with secondary `tgid -> Vec<ProcessKey>` indexing to eliminate PID reuse collisions.
   - **Process Graph**: Maintains lifecycle ancestry edges (`ProcessEdge`: Fork, Exec, Exit).
   - **Data Flow Graph**: Maintains data propagation edges (`DataFlowEdge`: `ScmRightsTransfer`, `PipeTransfer`, `SocketDataTransfer`) for causal taint tracking through Unix sockets, pipes, and FIFOs.

### 3.2 Evidence-Based Risk Evaluation (`src/risk/`)
Evaluates events using an evidence-based engine:
- **Evidence Framework**: Evaluates threat evidence with calibrated `Confidence` (`Low`, `Medium`, `High`, `Certain`) and `Impact` (`Informational`, `Low`, `Medium`, `High`, `Critical`).
- **Taint-Aware Scoring**: Compounds risk based on `TaintLevel` (`None`, `Observed`, `SensitiveAccess`, `SuspectedPropagation`, `ConfirmedPropagation`) and `SensitiveSource` (SSH keys, shadow file, cloud metadata, API tokens).
- **Multi-Stage Compounding**: Combines evidence across attack stages ($1.0\times$ up to $1.6\times$ for full kill-chain progression) with exponential half-life decay ($T_{1/2} = 300\text{s}$).

### 3.3 Autonomous Policy Engine (`src/policy/`)
Evaluates decisions strictly through an immutable 6-stage precedence hierarchy and records audit trails in `DecisionRecord`:
1. **Stage 1 (Safety Rules / ProcessProtectionPolicy)**: Critical process protection (PID 1, PID 2, sentinel daemon, canonical system binaries like `/usr/lib/systemd/systemd`, `/usr/sbin/sshd`). Absolute immunity against termination or suspension.
2. **Stage 2 (Protected Resources)**: Kernel and system-critical integrity invariants.
3. **Stage 3 (Administrative Deny)**: Explicit administrator blacklist rules (`PathPrefix`, `ExactPath`, `Sha256`, `CidrBlock`).
4. **Stage 4 (Administrative Allow)**: Explicit administrator whitelist rules.
5. **Stage 5 (Behavior Detection Matches)**: Rule-triggered actions based on confirmed high-confidence attack behaviors. Automated process kill requires high confidence, critical impact, and confirmed taint propagation.
6. **Stage 6 (Operating Mode Defaults)**:
   - **AUDIT**: Log all events, permit all execution.
   - **BALANCED**: Terminate Critical threats, isolate/deny High network threats, monitor Medium/Low.
   - **STRICT**: Block/terminate High and Critical threats; deny non-whitelisted network activity.
   - **CUSTOM**: User-tailored action matrices based on granular severity thresholds.

### 3.4 Response Orchestrator (`src/response/`)
Executes precise response actions without human intervention:
- **Process Termination with Linux `pidfd`**: Eliminates TOCTOU races by obtaining a file descriptor via `pidfd_open(pid, 0)`. The protocol follows: `pidfd_open` $\rightarrow$ verify `/proc/<pid>/stat` start timestamp $\rightarrow$ `pidfd_send_signal(SIGSTOP)` $\rightarrow$ re-verify under freeze $\rightarrow$ `pidfd_send_signal(SIGTERM)` $\rightarrow$ (50ms grace) $\rightarrow$ `pidfd_send_signal(SIGKILL)`. On kernels $< 5.3$, fallback verification verifies `/proc/<pid>/stat` prior to sending any signal, returning `Err(PidReuseDetected)` without touching mismatched processes.
- **Process Protection Policy (`src/protection.rs`)**: Verifies executable canonical paths, device/inode on trusted filesystems, package provenance, and sentinel self-identity. If a protected binary is compromised, actions are downgraded to `Alert` and network socket isolation.
- **Transactional Network Isolation Manager (`src/network/`)**: Implements 3 containment tiers:
  - `Selective`: Drops targeted malicious sockets/flows.
  - `Restricted`: Permits only essential services (DNS, Sentinel C2, loopback, trusted SSH).
  - `FullIsolation`: Complete quarantine preserving only loopback and recovery channels.
  All rules are applied atomically inside table `inet sentinel` via batch commands (`nft -f -`). Never executes `nft flush ruleset`. Includes an **Anti-Lockout Timer** (default 300s) that automatically rolls back isolation if not confirmed via `sntctl network confirm-isolation`.

### 3.5 Storage and Audit
- **Storage Manager (`src/storage/database.rs`)**: SQLite in Write-Ahead Logging (`WAL`) mode with automatic checkpointing (`PRAGMA wal_checkpoint(TRUNCATE)`), disk space monitoring (disk quota guard suppresses raw events when free disk $< 500\text{MB}$), and an automated background retention policy thread.
- **Audit Logger (`src/audit/`)**: Emits structured RFC 5424 syslog and JSON audit trails for compliance and SIEM integration.

### 3.6 Privilege Separation (`sentinel-privileged`)
To reduce attack surface, privileged actions are isolated into `sentinel-privileged`:
- Handles eBPF program loading and attachment, atomic nftables batch execution, and pidfd signal delivery.
- Drops dangerous capabilities `CAP_SYS_ADMIN` and `CAP_SYS_PTRACE`.
- Restricts ambient and bounding capabilities strictly to: `CAP_BPF`, `CAP_PERFMON`, `CAP_NET_ADMIN`, `CAP_KILL`, and `CAP_DAC_READ_SEARCH`.
- The core analysis engine `sentineld` runs with minimal privileges and connects to the privileged helper over a restricted Unix domain socket (`/run/sentinel/privileged.sock`).

### 3.7 Health Monitoring, Watchdog & State Machine (`src/health/`)
- **Agent State Machine**: Formal state transitions: `Starting` $\rightarrow$ `Healthy` $\rightarrow$ `Degraded` $\rightarrow$ `ProtectionUnavailable` $\rightarrow$ `Recovering` $\rightarrow$ `Stopping`.
- **FailurePolicyManager**: Coordinates subsystem degradation policies (ring buffer drops, eBPF sensor failures, storage pressure).
- **Systemd Watchdog Integration**: Sends `READY=1` upon completed initialization. Sends `WATCHDOG=1` every 4 seconds only if `HealthMonitor::check_all()` passes. Suppresses heartbeat if in `ProtectionUnavailable` for $> 30\text{s}$ (forcing systemd to restart the agent), and sends `STOPPING=1` on clean shutdown.

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
