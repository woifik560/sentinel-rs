//! eBPF event types received via RingBuffer from kernel-space probes.
//!
//! These structures mirror the `#[repr(C)]` layout used in eBPF programs
//! so that userspace can safely read them from the ring buffer.

use serde::{Deserialize, Serialize};
use std::net::{Ipv4Addr, Ipv6Addr};
use std::path::PathBuf;

/// Sentinel SO_MARK tag placed on suspicious or tainted sockets.
/// Unprivileged processes cannot spoof or clear this mark without CAP_NET_ADMIN.
pub const SENTINEL_SO_MARK: u32 = 0x5E170001;

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
        addr_family: u16,
        dst_ipv4: Option<Ipv4Addr>,
        dst_ipv6: Option<Ipv6Addr>,
        dst_port: u16,
        protocol: u8,
        so_mark: u32,
    },

    /// LSM hook `lsm/socket_sendmsg` — connectionless UDP sendmsg.
    SocketSendmsg {
        tgid: u32,
        addr_family: u16,
        dst_ipv4: Option<Ipv4Addr>,
        dst_ipv6: Option<Ipv6Addr>,
        dst_port: u16,
        so_mark: u32,
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
    pub _pad: u16,
    pub so_mark: u32,
}
