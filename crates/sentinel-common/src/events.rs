//! eBPF event types received via RingBuffer from kernel-space probes.
//!
//! These structures mirror the `#[repr(C)]` layout used in eBPF programs
//! so that userspace can safely read them from the ring buffer.

use serde::{Deserialize, Serialize};
use std::net::{Ipv4Addr, Ipv6Addr};
use std::path::PathBuf;

/// Legacy/Default Sentinel SO_MARK tag placed on suspicious or tainted sockets.
pub const SENTINEL_SO_MARK: u32 = 0x5E170001;

/// 16-bit Magic prefix identifying Sentinel-RS marks: 0x5E17xxxx.
pub const SENTINEL_SO_MARK_PREFIX: u32 = 0x5E170000;
pub const SENTINEL_SO_MARK_MASK: u32 = 0xFFFF0000;

/// Re-evaluation bit (0x40000000) for packets belonging to already-established connections
/// where a process subsequently became tainted. Placed higher than `ct state established` in Netfilter!
pub const SENTINEL_MARK_REVAL_BIT: u32 = 0x40000000;

/// 16-bit mask for dynamic flow sequence IDs.
pub const SENTINEL_MARK_FLOW_ID_MASK: u32 = 0x0000FFFF;

/// Encode dynamic socket / packet mark with monotonic flow sequence ID.
pub fn encode_flow_mark(flow_id: u16, requires_reval: bool) -> u32 {
    let mut mark = SENTINEL_SO_MARK_PREFIX | (flow_id as u32 & SENTINEL_MARK_FLOW_ID_MASK);
    if requires_reval {
        mark |= SENTINEL_MARK_REVAL_BIT;
    }
    mark
}

/// Decode a packet mark to determine whether it is managed by Sentinel, whether it requires re-eval, and its flow_id.
pub fn decode_flow_mark(mark: u32) -> (bool, bool, u16) {
    let is_sentinel = (mark & SENTINEL_SO_MARK_MASK) == SENTINEL_SO_MARK_PREFIX;
    let requires_reval = (mark & SENTINEL_MARK_REVAL_BIT) != 0;
    let flow_id = (mark & SENTINEL_MARK_FLOW_ID_MASK) as u16;
    (is_sentinel, requires_reval, flow_id)
}

/// Synchronous flow context stored in eBPF map `flow_mark_ctx` (mark -> FlowContext).
///
/// Written synchronously in kernel eBPF before setting socket mark, eliminating any race
/// condition with asynchronous RingBuffer consumption.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, Serialize, Deserialize)]
pub struct FlowContext {
    pub mark: u32,
    pub tgid: u32,
    pub pid: u32,
    pub uid: u32,
    pub cgroup_id: u64,
    pub sock_cookie: u64,
    pub taint_flags: u32,
    pub exe_inode: u64,
    pub exec_id: u64,
}

/// Default Netfilter Queue number for holding packets in userspace.
pub const SENTINEL_NFQUEUE_NUM: u16 = 100;

/// Maximum path length for eBPF events (matches kernel PATH_MAX).
pub const MAX_PATH_LEN: usize = 256;

/// Maximum number of cmdline arguments captured.
pub const MAX_CMDLINE_ARGS: usize = 16;

/// Permission access mask flags for `lsm/file_permission`.
pub const MAY_READ: u32 = 0x00000004;
pub const MAY_WRITE: u32 = 0x00000002;
pub const MAY_EXEC: u32 = 0x00000001;

/// Raw event structure as received from eBPF ring buffer.
///
/// Fields use fixed-size types compatible with `#[repr(C)]` eBPF structs.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum EbpfEvent {
    /// LSM hook `lsm/file_open` — a process opened a file.
    FileOpen {
        tgid: u32,
        uid: u32,
        path: PathBuf,
        dev: u64,
        ino: u64,
        flags: u32,
    },

    /// LSM hook `lsm/file_permission` — file/pipe/FIFO read/write access check.
    /// Used for tracking taint propagation across pipes (`cat secret | curl`) and temp files.
    FilePermission {
        tgid: u32,
        uid: u32,
        path: PathBuf,
        dev: u64,
        ino: u64,
        mask: u32,
        is_pipe: bool,
        is_fifo: bool,
    },

    /// LSM hook `lsm/bprm_check_security` — early binary execution check before execve completes.
    /// Detects memfd/fileless launch and pre-tags process baseline profile in TASK_STORAGE.
    BprmCheckSecurity {
        tgid: u32,
        uid: u32,
        exe_path: PathBuf,
        dev: u64,
        ino: u64,
        is_memfd: bool,
    },

    /// Tracepoint `sched/sched_process_fork` — a new process was forked.
    ProcessFork {
        parent_tgid: u32,
        child_tgid: u32,
    },

    /// Tracepoint `sched/sched_process_exec` — a process executed a new binary.
    ProcessExec {
        tgid: u32,
        exe_path: PathBuf,
        cmdline: Vec<String>,
    },

    /// LSM hook `lsm/socket_connect` — a process initiated a TCP/UDP connection.
    SocketConnect {
        tgid: u32,
        group_leader_tgid: u32,
        addr_family: u16,
        dst_ipv4: Option<Ipv4Addr>,
        dst_ipv6: Option<Ipv6Addr>,
        dst_port: u16,
        protocol: u8,
        so_mark: u32,
    },

    /// LSM hook `lsm/socket_sendmsg` — connectionless UDP or pre-opened socket transmission.
    SocketSendmsg {
        tgid: u32,
        group_leader_tgid: u32,
        addr_family: u16,
        dst_ipv4: Option<Ipv4Addr>,
        dst_ipv6: Option<Ipv6Addr>,
        dst_port: u16,
        so_mark: u32,
        is_preopened: bool,
    },

    /// LSM hook `lsm/unix_may_send` — IPC AF_UNIX message transfer between processes.
    /// Intercepts taint laundering attempts via local Unix domain sockets.
    UnixMaySend {
        sender_tgid: u32,
        receiver_tgid: u32,
        sock_path: PathBuf,
        is_blocked: bool,
    },

    /// LSM hook `lsm/ptrace_access_check` — inspects memory attachment or cross-process reading.
    /// Blocks tainted processes from attaching to or snooping memory of clean processes.
    PtraceAccessCheck {
        tracer_tgid: u32,
        tracee_tgid: u32,
        mode: u32,
        is_blocked: bool,
    },

    /// LSM hook `lsm/file_open` on /proc/*/environ or /proc/*/mem of another process.
    ProcEnvironAccess {
        reader_tgid: u32,
        target_tgid: u32,
        path: PathBuf,
        is_blocked: bool,
    },

    /// LSM hook `lsm/mmap_file` — memory-mapping of files or anonymous memory.
    /// Intercepts secret reading via mmap(MAP_SHARED), shared memory taint writing,
    /// and executable mmap of unlinked/tmpfs files (fileless JIT / loader detection).
    MmapFile {
        tgid: u32,
        uid: u32,
        path: PathBuf,
        dev: u64,
        ino: u64,
        prot: u32,
        flags: u32,
        is_secret: bool,
        is_write_shared: bool,
        is_exec: bool,
    },

    /// LSM hook `lsm/file_receive` — receiving a file descriptor passed via SCM_RIGHTS over AF_UNIX.
    /// Propagates taint to the receiving process if the transferred descriptor is tainted or a secret.
    FileReceive {
        receiver_tgid: u32,
        sender_tgid: u32,
        path: PathBuf,
        dev: u64,
        ino: u64,
        is_tainted: bool,
    },
}

/// Raw C-compatible structure for ring buffer transport (file_open).
#[repr(C)]
#[derive(Debug, Clone, Copy)]
pub struct RawFileOpenEvent {
    pub tgid: u32,
    pub uid: u32,
    pub path: [u8; MAX_PATH_LEN],
    pub path_len: u32,
    pub dev: u64,
    pub ino: u64,
    pub flags: u32,
}

/// Raw C-compatible structure for ring buffer transport (file_permission).
#[repr(C)]
#[derive(Debug, Clone, Copy)]
pub struct RawFilePermissionEvent {
    pub tgid: u32,
    pub uid: u32,
    pub path: [u8; MAX_PATH_LEN],
    pub path_len: u32,
    pub dev: u64,
    pub ino: u64,
    pub mask: u32,
    pub is_pipe: u8,
    pub is_fifo: u8,
    pub _pad: [u8; 6],
}

/// Raw C-compatible structure for ring buffer transport (bprm_check_security).
#[repr(C)]
#[derive(Debug, Clone, Copy)]
pub struct RawBprmCheckSecurityEvent {
    pub tgid: u32,
    pub uid: u32,
    pub exe_path: [u8; MAX_PATH_LEN],
    pub exe_path_len: u32,
    pub dev: u64,
    pub ino: u64,
    pub is_memfd: u8,
    pub _pad: [u8; 7],
}

/// Raw C-compatible structure for ring buffer transport (process_fork).
#[repr(C)]
#[derive(Debug, Clone, Copy)]
pub struct RawProcessForkEvent {
    pub parent_tgid: u32,
    pub child_tgid: u32,
}

/// Raw C-compatible structure for ring buffer transport (process_exec).
#[repr(C)]
#[derive(Debug, Clone, Copy)]
pub struct RawProcessExecEvent {
    pub tgid: u32,
    pub exe_path: [u8; MAX_PATH_LEN],
    pub exe_path_len: u32,
    pub cmdline: [[u8; MAX_PATH_LEN]; MAX_CMDLINE_ARGS],
    pub cmdline_lens: [u32; MAX_CMDLINE_ARGS],
    pub cmdline_count: u32,
}

/// Raw C-compatible structure for ring buffer transport (socket_connect).
#[repr(C)]
#[derive(Debug, Clone, Copy)]
pub struct RawSocketConnectEvent {
    pub tgid: u32,
    pub addr_family: u16,
    pub dst_ipv4: u32,
    pub dst_ipv6: [u8; 16],
    pub dst_port: u16,
    pub protocol: u8,
    pub _pad: u8,
    pub so_mark: u32,
}

/// Raw C-compatible structure for ring buffer transport (socket_sendmsg).
#[repr(C)]
#[derive(Debug, Clone, Copy)]
pub struct RawSocketSendmsgEvent {
    pub tgid: u32,
    pub addr_family: u16,
    pub dst_ipv4: u32,
    pub dst_ipv6: [u8; 16],
    pub dst_port: u16,
    pub _pad: u8,
    pub is_preopened: u8,
    pub so_mark: u32,
}

/// Raw C-compatible structure for ring buffer transport (unix_may_send).
#[repr(C)]
#[derive(Debug, Clone, Copy)]
pub struct RawUnixMaySendEvent {
    pub sender_tgid: u32,
    pub receiver_tgid: u32,
    pub sock_path: [u8; MAX_PATH_LEN],
    pub sock_path_len: u32,
    pub is_blocked: u8,
    pub _pad: [u8; 3],
}

/// Raw C-compatible structure for ring buffer transport (ptrace_access_check).
#[repr(C)]
#[derive(Debug, Clone, Copy)]
pub struct RawPtraceAccessCheckEvent {
    pub tracer_tgid: u32,
    pub tracee_tgid: u32,
    pub mode: u32,
    pub is_blocked: u8,
    pub _pad: [u8; 3],
}

/// Raw C-compatible structure for ring buffer transport (mmap_file).
#[repr(C)]
#[derive(Debug, Clone, Copy)]
pub struct RawMmapFileEvent {
    pub tgid: u32,
    pub uid: u32,
    pub path: [u8; MAX_PATH_LEN],
    pub path_len: u32,
    pub dev: u64,
    pub ino: u64,
    pub prot: u32,
    pub flags: u32,
    pub is_secret: u8,
    pub is_write_shared: u8,
    pub is_exec: u8,
    pub _pad: [u8; 5],
}

/// Raw C-compatible structure for ring buffer transport (file_receive / SCM_RIGHTS).
#[repr(C)]
#[derive(Debug, Clone, Copy)]
pub struct RawFileReceiveEvent {
    pub receiver_tgid: u32,
    pub sender_tgid: u32,
    pub path: [u8; MAX_PATH_LEN],
    pub path_len: u32,
    pub dev: u64,
    pub ino: u64,
    pub is_tainted: u8,
    pub _pad: [u8; 7],
}
