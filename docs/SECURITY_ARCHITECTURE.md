# Sentinel-RS: Security Architecture & Threat Defense

## 1. Architectural Philosophy

Sentinel-RS is engineered as an autonomous, high-assurance Linux Host Intrusion Prevention System (HIPS) and Endpoint Detection & Response (EDR) platform. It follows four immutable security axioms:

1. **Principle of Least Privilege (PoLP)**: Execution is segregated between unprivileged telemetry evaluation (`sentineld`) and a capability-bounded micro-helper (`sentinel-privileged`).
2. **Deterministic Fail-Safe Operation**: A security failure must never brick remote connectivity, induce kernel panics, or silently execute malicious payloads.
3. **Defense-in-Depth**: Multi-layered verification across LSM eBPF hooks, Netfilter NFQUEUE packet triage, process lineage validation, and cryptographic executable hashing.
4. **Zero Shell Execution**: No subshell invocations (`/bin/sh`, `exec`, or command concatenation). Every system interaction is strongly typed and validated through kernel APIs (`pidfd`, `nftables` AST/transactions, Netlink).

---

## 2. Process Separation & Capability Model

```
+-----------------------------------------------------------------------------------+
| USER SPACE (Untrusted / Operator Context)                                         |
|   +---------------------------------+     +-----------------------------------+   |
|   |  sntctl (CLI / Management tool) |     |  Monitoring Tools / GUI (future)  |   |
|   +---------------------------------+     +-----------------------------------+   |
|                 | (SO_PEERCRED GID 0 / sentinel group)      | (Read-Only)         |
|                 v                                           v                     |
|   +---------------------------------------------------------------------------+   |
|   | sentineld (Telemetry, Lineage DAG, Risk Engine, Storage Daemon)           |   |
|   | - Linux Capabilities: CAP_DAC_READ_SEARCH, CAP_PERFMON                   |   |
|   | - Socket Paths: /run/sentinel/sentinel.sock (0660), sentinel-ro.sock(0666)|   |
|   +---------------------------------------------------------------------------+   |
|                 |                                                                 |
|                 | Unix Domain Socket /run/sentinel/privileged.sock (0600)          |
|                 | Authenticated via SO_PEERCRED (Strictly UID 0 / Root)           |
|                 v                                                                 |
|   +---------------------------------------------------------------------------+   |
|   | sentinel-privileged (Minimal Privileged Operations Helper)                |   |
|   | - Linux Capabilities: CAP_NET_ADMIN, CAP_KILL, CAP_BPF                   |   |
|   | - Strictly bounded API: FirewallOperation, Safe pidfd SignalProcess       |   |
|   | - Watchdog state: /run/sentinel/isolation_lockout.state                   |   |
|   +---------------------------------------------------------------------------+   |
+-----------------------------------------------------------------------------------+
                                  |
                                  v
+-----------------------------------------------------------------------------------+
| LINUX KERNEL (Ring 0 Security Boundary)                                           |
|   +-----------------------------+     +---------------------------------------+   |
|   | BPF LSM Hooks (bprm_check,  |     | Netfilter / nftables (inet sentinel)  |   |
|   | file_open, socket_connect)  |     | NFQUEUE Triage, SO_MARK Diversion     |   |
|   +-----------------------------+     +---------------------------------------+   |
|                 |                                     |                           |
|                 v                                     v                           |
|   eBPF Maps (TaintMap, RateLimit)        Atomic Packet Verdicts (Accept/Drop)     |
+-----------------------------------------------------------------------------------+
```

---

## 3. Privilege Boundaries & Authentication

### 3.1 Privileged Helper Authentication (`SO_PEERCRED`)
- The privileged socket `/run/sentinel/privileged.sock` is locked down to mode `0600` (`root:root`).
- Each inbound connection is verified using kernel-level socket options (`getsockopt(stream, SOL_SOCKET, SO_PEERCRED)`).
- If `creds.uid != 0`, the helper immediately terminates the socket connection.

### 3.2 Management IPC RBAC & Supplementary Groups
The management socket `/run/sentinel/sentinel.sock` enforces three roles:
1. **`RootAdmin` (UID 0)**: Full administrative authority (policy updates, protection toggling, manual isolation, rule reloading).
2. **`Operator` (GID matches sentinel group or in supplementary groups)**: Query status, list incidents, view telemetry, inspect process lineage.
   - **Supplementary Group Resolution**: When evaluating `SO_PEERCRED`, the daemon inspects both the primary GID and queries the user's supplementary group list via `nix::unistd::getgrouplist`. This ensures administrators belonging to the `sentinel` group without primary GID switching are correctly authenticated.
3. **`ReadOnly` (Local users UID >= 1000)**: Permitted on `/run/sentinel/sentinel-ro.sock` (`0666`) for live status queries and read-only diagnostics.

---

## 4. Input Validation & Type Safety

### 4.1 Strongly-Typed Firewall Operations
The privileged helper prohibits arbitrary string batch commands. Operations must conform to the `FirewallOperation` protocol:
- `SetupHolding { use_bypass }`
- `ApplyIsolation { tier, trusted_ssh_ips, blocked_ips, blocked_ports }`
- `BlockIp { ip }`
- `CleanupRules`
- `ArmAntiLockout { timeout_secs, trusted_ssh_ips }`
- `ConfirmAntiLockout`
- `Rollback`

Every IP address is parsed into `std::net::IpAddr` before rule compilation. Non-conforming or malformed IP addresses are rejected with `EINVAL` before reaching the Netfilter subsystem.

### 4.2 Safe Process Signaling via `pidfd`
Process termination and freezing operations avoid standard `kill(pid, sig)` race conditions:
1. `pidfd_open(pid, 0)` acquires a kernel handle pinned to the specific process instance.
2. Anti-PID-reuse verification cross-checks `/proc/<pid>/stat` field 22 (`start_time` clock ticks) and `/proc/<pid>/exe`.
3. If the process has terminated and its PID recycled by another application, the request is rejected with `ESRCH` ("PID reuse detected").
4. PID 1 (`init` / `systemd`) is protected by unconditional kernel-level and userspace guards.

---

## 5. Failure Modes & Resilience Matrix

| Component | Failure Condition | Security Posture | Recovery Behavior |
| :--- | :--- | :--- | :--- |
| `sentineld` | Process crash / SIGKILL | Fail-Safe / Anti-Lockout | `sentinel-privileged` watchdog rolls back network isolation after timeout expiration. |
| `sentinel-privileged` | Helper process crash | Fallback to Direct Execution | `sentineld` executes firewall rules directly if local capabilities allow; checks persisted state file upon restart. |
| Host Firewall | Netfilter table corruption | Atomic Rollback | `nft -c -f -` pre-validates syntax; failures trigger automatic rollback to `IsolationTier::None`. |
| NFQUEUE Queue | User-space queue saturation | Fail-Open with Bypass | Packet mark rules include `bypass` flag to prevent dropping legitimate traffic under overload. |
| eBPF Ring Buffer | Event flood (> 100k events/s)| Bounded Drop Tracking | Ring buffer overflow increments lost event counter and triggers burst throttling without panicking. |
