# Sentinel-RS: eBPF & BPF LSM Architecture Design

## 1. Overview and Core Philosophy

Sentinel-RS uses a dual-engine telemetry and enforcement architecture:
1. **BPF LSM (Linux Security Modules) via Aya 0.13**: In-kernel active prevention and contextual decision-making.
2. **eBPF RingBuffer**: High-throughput, zero-copy kernel-to-userspace structured binary event transport.
3. **Tracepoints & fanotify Fallback**: Passive monitoring modes when running on legacy or non-LSM-enabled kernels.

---

## 2. ELF Lifecycle Management

### 2.1 Object Discovery
The daemon searches for pre-compiled eBPF ELF binaries in standard locations:
- Direct override via `SENTINEL_BPF_OBJ` environment variable.
- `/usr/lib/sentinel/bpf/sentinel.bpf.o`
- `/etc/sentinel/bpf/sentinel.bpf.o`

### 2.2 Aya Loader & BTF Verification
Before attempting to load BPF LSM bytecode, `sentinel-ebpf` verifies kernel BPF Type Format (BTF) support:
```rust
let btf = match Btf::from_sys_fs() {
    Ok(btf) => btf,
    Err(e) => {
        tracing::warn!("Kernel BTF unavailable: {}. LSM attachment aborted.", e);
        return Ok(MechanismState::Unavailable);
    }
};
```

### 2.3 Program Type Downcasting & Loading
Each BPF program within the ELF is inspected and downcast to `aya::programs::Lsm`:
```rust
let program: &mut aya::programs::Lsm = bpf
    .program_mut(&prog_name)
    .context("Program not found")?
    .try_into()
    .context("Program is not LSM")?;

program.load(&prog_name, &btf)?;
let link_id = program.attach()?;
self.attached_links.push(link_id);
```

### 2.4 Atomic Rollback on Partial Failures
If any mandatory LSM hook fails verifier checks or attachment, all previously attached links are immediately detached (`program.detach(link_id)`) to prevent half-functional security states, and the subsystem transitions to `MechanismState::Failed`.

---

## 3. Mandatory LSM Hooks Matrix

| Hook Name | Kernel Function Target | Event Emitted | Action / Enforcement |
| :--- | :--- | :--- | :--- |
| `bprm_check_security` | Executable launch | `ProcessExec` | Inspects binary hashes, denies unauthorized untrusted binaries. |
| `file_open` | File open syscall | `FileAccess` | Monitors access to sensitive assets (`/etc/shadow`, `~/.ssh/id_*`). |
| `file_permission` | Inode permission check | `FileAccess` | Taint tracking on credential access. |
| `mmap_file` | File memory mapping | `MemoryMap` | Detects `PROT_EXEC` anonymous memory and library injection. |
| `socket_connect` | Network connect initiation | `SocketConnect` | Pre-connect evaluation, detects unauthorized C2 connections. |
| `socket_sendmsg` | Outbound packet transmission | `SocketSend` | Blocks data exfiltration bursts from tainted tasks. |
| `ptrace_access_check`| Process memory inspection | `ProcessInspect` | Prevents credential theft from unprivileged debuggers. |
| `unix_may_send` | Unix domain socket communication| `IpcAccess` | Taint propagation across local IPC channels. |

---

## 4. Kernel-to-Userspace RingBuffer Design

### 4.1 BPF RingBuffer vs Perf Buffer
Sentinel-RS utilizes `BPF_MAP_TYPE_RINGBUF` introduced in Linux 5.8:
- Single memory-mapped circular buffer shared across all CPUs (eliminates per-CPU memory fragmentation).
- Variable-length record support (no padding waste).
- In-kernel memory barriers guaranteeing zero-copy delivery.

### 4.2 Binary Event Layout
All events transmitted via the RingBuffer share a strict C-compatible 64-bit aligned structure:
```rust
#[repr(C)]
pub struct RawKernelEvent {
    pub magic: u32,             // 0x534E544C ('SNTL')
    pub event_type: u16,        // EventType enum
    pub version: u8,            // Protocol version (1)
    pub reserved: u8,
    pub timestamp_ns: u64,      // Monotonic ktime
    pub pid: u32,
    pub tgid: u32,
    pub uid: u32,
    pub gid: u32,
    pub payload_len: u32,
    // Variable payload follows
}
```

### 4.3 Overflow & Lost Event Tracking
When event bursts exceed the RingBuffer capacity:
1. The kernel drops events and increments the ringbuffer dropped counter.
2. Userspace consumer detects sequence gaps via `lost_events` counter.
3. Subsystem telemetry raises `EventMetrics::record_lost()` and flags `MechanismState::Degraded` if loss exceeds 1% of total throughput.

---

## 5. Graceful Degradation & Fallback Model

If BPF LSM or BTF is missing in the host kernel:
1. **Tracepoint Observer**: Subscribes to `sched_process_exec`, `sched_process_exit`, and `sock:inet_sock_set_state`.
2. **fanotify Passive Monitor**: Captures file access events in userspace.
3. **Netfilter / NFQUEUE**: Enforces network drop policies directly in the kernel netfilter stack.
4. **pidfd Signals**: Process termination uses `SYS_pidfd_open` and `SYS_pidfd_send_signal`.
5. **Truthful Telemetry**: The daemon reports `MechanismState::Degraded` (or `Unavailable`) instead of falsely advertising `FULL_PROTECTION`.
