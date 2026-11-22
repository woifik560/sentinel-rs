# Sentinel-RS: Privilege Separation & Security Model

## 1. Architectural Philosophy

Sentinel-RS adheres to the **Principle of Least Privilege (PoLP)** and the **Defense-in-Depth** model. The platform divides responsibilities across two independent processes running in separate security domains:

1. **`sentineld` (Telemetry, Detection & Lineage Daemon)**:
   - Evaluates process behavior, manages the Lineage DAG, calculates risk scores, and maintains the SQLite database.
   - Operates with minimal capabilities, incapable of directly modifying firewall rules or terminating arbitrary system processes.
2. **`sentinel-privileged` (Privileged Operations Helper)**:
   - Minimal, tightly audited micro-daemon running as `root` with strictly bounded capabilities.
   - Executes only predefined, structured security operations requested over an authenticated Unix socket.
   - Has zero shell execution capabilities (cannot run `/bin/sh` or arbitrary commands).

---

## 2. Capability Matrix

| Binary | Linux Capabilities Retained | Justification |
| :--- | :--- | :--- |
| `sentineld` | `CAP_DAC_READ_SEARCH`, `CAP_PERFMON` | Reading `/proc/<pid>/stat`, inspecting binary hashes, and reading eBPF tracepoint streams. |
| `sentinel-privileged` | `CAP_NET_ADMIN`, `CAP_KILL`, `CAP_BPF` | Managing netfilter tables via `nftables`, sending signals via `pidfd_send_signal`, loading BPF programs into kernel memory. |

---

## 3. Privileged Helper IPC Protocol

### 3.1 Unix Socket Transport
- **Path**: `/run/sentinel/privileged.sock`
- **File Mode**: `0600` (readable and writable exclusively by `root:root`).
- **Authentication**: The helper queries the kernel networking stack for peer credentials via `getsockopt(..., SO_PEERCRED)`. Any client connection where `uid != 0` is terminated immediately with `EPERM`.

### 3.2 Bounded Resources & Anti-DoS
- **Concurrency Semaphore**: At most 16 concurrent requests. Additional connections receive `EBUSY` and are closed.
- **Message Size Limit**: Request payloads are bounded to 64 KB (`65536` bytes). Payloads exceeding this limit trigger an `EMSGSIZE` error and socket teardown.
- **Read Timeout**: 5 seconds per request.

### 3.3 Strongly-Typed API Operations

The helper rejects raw shell strings. It only accepts strongly-typed JSON-RPC requests conforming to `PrivilegedOp`:

```rust
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum FirewallOperation {
    SetupHolding { use_bypass: bool },
    ApplyIsolation {
        tier: String,
        trusted_ssh_ips: Vec<String>,
        blocked_ips: Vec<String>,
        blocked_ports: Vec<u16>,
    },
    BlockIp { ip: String },
    CleanupRules,
    ArmAntiLockout {
        timeout_secs: u64,
        trusted_ssh_ips: Vec<String>,
    },
    ConfirmAntiLockout,
    Rollback,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum PrivilegedOp {
    /// Strongly-typed firewall operations executed safely by the privileged helper
    Firewall(FirewallOperation),
    /// Deprecated atomic batch fallback
    ApplyNftablesBatch { batch: String },
    /// Safe pidfd signaling of a process instance with anti-PID-reuse verification
    SignalProcess {
        pid: u32,
        signal: i32,
        expected_start_time: Option<u64>,
        expected_exe: Option<String>,
    },
    /// Health ping
    Ping,
}
```

### 3.4 Invariant Enforcement
1. **Firewall Syntax Pre-Check**: Before applying any batch of nftables rules, the helper runs a dry-run check (`nft -c -f -`). If the dry run returns an error, the batch is aborted, preventing corrupted firewall rulesets.
2. **PID 1 & Self Never-Kill**: Any request with `pid <= 1` or targeting `sentinel-privileged` itself is unconditionally rejected with an `EPERM` error.
3. **Crash-Resilient Anti-Lockout Watchdog**: State is persisted to `/run/sentinel/isolation_lockout.state` with background timers to prevent host bricking if `sentineld` crashes during isolation.
4. **Supplementary Group Authorization**: Peer credential authentication queries `nix::unistd::getgrouplist` to ensure members of the `sentinel` group with different primary GIDs are recognized as Operators.

---

## 4. Systemd Service Sandboxing

Both services define strict systemd sandboxing directives in their unit files:

### `sentinel-privileged.service`
```ini
[Unit]
Description=Sentinel-RS Privileged Security Operations Helper
Documentation=https://github.com/woifik560/sentinel-rs
Before=sentineld.service

[Service]
Type=simple
ExecStart=/usr/local/bin/sentinel-privileged
Restart=on-failure
RestartSec=3s
RuntimeDirectory=sentinel
RuntimeDirectoryMode=0750
CapabilityBoundingSet=CAP_NET_ADMIN CAP_KILL CAP_BPF CAP_PERFMON CAP_DAC_READ_SEARCH
AmbientCapabilities=CAP_NET_ADMIN CAP_KILL CAP_BPF CAP_PERFMON CAP_DAC_READ_SEARCH
NoNewPrivileges=no
ProtectSystem=strict
ProtectHome=read-only
PrivateTmp=yes
```

### `sentineld.service`
```ini
[Unit]
Description=Sentinel-RS Headless Linux HIPS/EDR Daemon
Documentation=https://github.com/woifik560/sentinel-rs
After=network.target sentinel-privileged.service
Wants=sentinel-privileged.service

[Service]
Type=simple
ExecStart=/usr/local/bin/sentineld --config /etc/sentinel/config.toml --rules /etc/sentinel/rules.toml
Restart=always
RestartSec=5s
RuntimeDirectory=sentinel
RuntimeDirectoryMode=0755
StateDirectory=sentinel
StateDirectoryMode=0700
CapabilityBoundingSet=CAP_DAC_READ_SEARCH CAP_PERFMON
AmbientCapabilities=CAP_DAC_READ_SEARCH CAP_PERFMON
ProtectSystem=full
ProtectHome=read-only
PrivateTmp=yes
```
