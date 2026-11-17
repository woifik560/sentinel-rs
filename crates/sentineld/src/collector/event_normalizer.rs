//! Normalizes raw eBPF events into a unified userspace schema with canonical process keys.

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use std::net::{Ipv4Addr, Ipv6Addr};
use std::path::PathBuf;
use uuid::Uuid;

use sentinel_common::events::EbpfEvent;

pub use crate::lineage::ProcessKey;

/// Unified userspace normalized event.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct NormalizedEvent {
    pub event_id: String,
    pub timestamp: DateTime<Utc>,
    pub event_type: NormalizedEventType,
    pub source: EventSource,
    pub process_key: ProcessKey,
    pub pid: u32,
    pub tgid: u32,
    pub uid: u32,
    pub gid: u32,
    pub exe_path: Option<PathBuf>,
    pub exe_hash: Option<String>,
    pub parent_key: Option<ProcessKey>,
    pub details: EventDetails,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum EventSource {
    EbpfLsm,
    Tracepoint,
    NetfilterQueue,
    SyntheticAudit,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum NormalizedEventType {
    ProcessExec,
    ProcessFork,
    ProcessExit,
    FileOpen,
    FilePermission,
    FileReceive,
    MmapExecution,
    SocketConnect,
    SocketSendmsg,
    UnixMaySend,
    PtraceAccess,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "type")]
pub enum EventDetails {
    ProcessExec {
        exe_path: PathBuf,
        cmdline: Vec<String>,
        is_memfd: bool,
    },
    ProcessFork {
        parent_tgid: u32,
        child_tgid: u32,
    },
    FileOpen {
        path: PathBuf,
        flags: u32,
        dev: u64,
        ino: u64,
    },
    FilePermission {
        path: PathBuf,
        mask: u32,
        is_pipe: bool,
        is_fifo: bool,
    },
    FileReceive {
        sender_tgid: u32,
        receiver_tgid: u32,
        path: PathBuf,
        is_tainted: bool,
    },
    MmapExecution {
        path: PathBuf,
        prot: u32,
        flags: u32,
        is_secret: bool,
        is_exec: bool,
    },
    SocketConnect {
        addr_family: u16,
        dst_ipv4: Option<Ipv4Addr>,
        dst_ipv6: Option<Ipv6Addr>,
        dst_port: u16,
        protocol: u8,
        so_mark: u32,
    },
    SocketSendmsg {
        addr_family: u16,
        dst_ipv4: Option<Ipv4Addr>,
        dst_ipv6: Option<Ipv6Addr>,
        dst_port: u16,
        so_mark: u32,
        is_preopened: bool,
    },
    UnixMaySend {
        sender_tgid: u32,
        receiver_tgid: u32,
        sock_path: PathBuf,
        is_blocked: bool,
    },
    PtraceAccess {
        tracer_tgid: u32,
        tracee_tgid: u32,
        mode: u32,
        is_blocked: bool,
    },
}

pub struct EventNormalizer;

impl EventNormalizer {
    pub fn normalize(event: EbpfEvent, start_time_ns: u64) -> NormalizedEvent {
        let event_id = Uuid::new_v4().to_string();
        let timestamp = Utc::now();

        match event {
            EbpfEvent::ProcessExec { tgid, exe_path, cmdline } => {
                let is_memfd = exe_path.to_string_lossy().contains("memfd");
                let key = ProcessKey::new(tgid, start_time_ns);
                NormalizedEvent {
                    event_id,
                    timestamp,
                    event_type: NormalizedEventType::ProcessExec,
                    source: EventSource::Tracepoint,
                    process_key: key,
                    pid: tgid,
                    tgid,
                    uid: 0,
                    gid: 0,
                    exe_path: Some(exe_path.clone()),
                    exe_hash: None,
                    parent_key: None,
                    details: EventDetails::ProcessExec {
                        exe_path,
                        cmdline,
                        is_memfd,
                    },
                }
            }

            EbpfEvent::ProcessFork { parent_tgid, child_tgid } => {
                let key = ProcessKey::new(child_tgid, start_time_ns);
                let parent_key = ProcessKey::new(parent_tgid, 0);
                NormalizedEvent {
                    event_id,
                    timestamp,
                    event_type: NormalizedEventType::ProcessFork,
                    source: EventSource::Tracepoint,
                    process_key: key,
                    pid: child_tgid,
                    tgid: child_tgid,
                    uid: 0,
                    gid: 0,
                    exe_path: None,
                    exe_hash: None,
                    parent_key: Some(parent_key),
                    details: EventDetails::ProcessFork { parent_tgid, child_tgid },
                }
            }

            EbpfEvent::FileOpen { tgid, uid, path, dev, ino, flags } => {
                let key = ProcessKey::new(tgid, start_time_ns);
                NormalizedEvent {
                    event_id,
                    timestamp,
                    event_type: NormalizedEventType::FileOpen,
                    source: EventSource::EbpfLsm,
                    process_key: key,
                    pid: tgid,
                    tgid,
                    uid,
                    gid: 0,
                    exe_path: None,
                    exe_hash: None,
                    parent_key: None,
                    details: EventDetails::FileOpen { path, flags, dev, ino },
                }
            }

            EbpfEvent::FilePermission { tgid, uid, path, mask, is_pipe, is_fifo, .. } => {
                let key = ProcessKey::new(tgid, start_time_ns);
                NormalizedEvent {
                    event_id,
                    timestamp,
                    event_type: NormalizedEventType::FilePermission,
                    source: EventSource::EbpfLsm,
                    process_key: key,
                    pid: tgid,
                    tgid,
                    uid,
                    gid: 0,
                    exe_path: None,
                    exe_hash: None,
                    parent_key: None,
                    details: EventDetails::FilePermission { path, mask, is_pipe, is_fifo },
                }
            }

            EbpfEvent::BprmCheckSecurity { tgid, uid, exe_path, is_memfd, .. } => {
                let key = ProcessKey::new(tgid, start_time_ns);
                NormalizedEvent {
                    event_id,
                    timestamp,
                    event_type: NormalizedEventType::ProcessExec,
                    source: EventSource::EbpfLsm,
                    process_key: key,
                    pid: tgid,
                    tgid,
                    uid,
                    gid: 0,
                    exe_path: Some(exe_path.clone()),
                    exe_hash: None,
                    parent_key: None,
                    details: EventDetails::ProcessExec {
                        exe_path,
                        cmdline: Vec::new(),
                        is_memfd,
                    },
                }
            }

            EbpfEvent::SocketConnect {
                tgid,
                addr_family,
                dst_ipv4,
                dst_ipv6,
                dst_port,
                protocol,
                so_mark,
                ..
            } => {
                let key = ProcessKey::new(tgid, start_time_ns);
                NormalizedEvent {
                    event_id,
                    timestamp,
                    event_type: NormalizedEventType::SocketConnect,
                    source: EventSource::EbpfLsm,
                    process_key: key,
                    pid: tgid,
                    tgid,
                    uid: 0,
                    gid: 0,
                    exe_path: None,
                    exe_hash: None,
                    parent_key: None,
                    details: EventDetails::SocketConnect {
                        addr_family,
                        dst_ipv4,
                        dst_ipv6,
                        dst_port,
                        protocol,
                        so_mark,
                    },
                }
            }

            EbpfEvent::SocketSendmsg {
                tgid,
                addr_family,
                dst_ipv4,
                dst_ipv6,
                dst_port,
                so_mark,
                is_preopened,
                ..
            } => {
                let key = ProcessKey::new(tgid, start_time_ns);
                NormalizedEvent {
                    event_id,
                    timestamp,
                    event_type: NormalizedEventType::SocketSendmsg,
                    source: EventSource::EbpfLsm,
                    process_key: key,
                    pid: tgid,
                    tgid,
                    uid: 0,
                    gid: 0,
                    exe_path: None,
                    exe_hash: None,
                    parent_key: None,
                    details: EventDetails::SocketSendmsg {
                        addr_family,
                        dst_ipv4,
                        dst_ipv6,
                        dst_port,
                        so_mark,
                        is_preopened,
                    },
                }
            }

            EbpfEvent::UnixMaySend { sender_tgid, receiver_tgid, sock_path, is_blocked } => {
                let key = ProcessKey::new(sender_tgid, start_time_ns);
                NormalizedEvent {
                    event_id,
                    timestamp,
                    event_type: NormalizedEventType::UnixMaySend,
                    source: EventSource::EbpfLsm,
                    process_key: key,
                    pid: sender_tgid,
                    tgid: sender_tgid,
                    uid: 0,
                    gid: 0,
                    exe_path: None,
                    exe_hash: None,
                    parent_key: None,
                    details: EventDetails::UnixMaySend {
                        sender_tgid,
                        receiver_tgid,
                        sock_path,
                        is_blocked,
                    },
                }
            }

            EbpfEvent::PtraceAccessCheck { tracer_tgid, tracee_tgid, mode, is_blocked } => {
                let key = ProcessKey::new(tracer_tgid, start_time_ns);
                NormalizedEvent {
                    event_id,
                    timestamp,
                    event_type: NormalizedEventType::PtraceAccess,
                    source: EventSource::EbpfLsm,
                    process_key: key,
                    pid: tracer_tgid,
                    tgid: tracer_tgid,
                    uid: 0,
                    gid: 0,
                    exe_path: None,
                    exe_hash: None,
                    parent_key: None,
                    details: EventDetails::PtraceAccess {
                        tracer_tgid,
                        tracee_tgid,
                        mode,
                        is_blocked,
                    },
                }
            }

            EbpfEvent::ProcEnvironAccess { reader_tgid, target_tgid, path: _path, is_blocked } => {
                let key = ProcessKey::new(reader_tgid, start_time_ns);
                NormalizedEvent {
                    event_id,
                    timestamp,
                    event_type: NormalizedEventType::PtraceAccess,
                    source: EventSource::EbpfLsm,
                    process_key: key,
                    pid: reader_tgid,
                    tgid: reader_tgid,
                    uid: 0,
                    gid: 0,
                    exe_path: None,
                    exe_hash: None,
                    parent_key: None,
                    details: EventDetails::PtraceAccess {
                        tracer_tgid: reader_tgid,
                        tracee_tgid: target_tgid,
                        mode: 0,
                        is_blocked,
                    },
                }
            }

            EbpfEvent::MmapFile { tgid, uid, path, prot, flags, is_secret, is_exec, .. } => {
                let key = ProcessKey::new(tgid, start_time_ns);
                NormalizedEvent {
                    event_id,
                    timestamp,
                    event_type: NormalizedEventType::MmapExecution,
                    source: EventSource::EbpfLsm,
                    process_key: key,
                    pid: tgid,
                    tgid,
                    uid,
                    gid: 0,
                    exe_path: Some(path.clone()),
                    exe_hash: None,
                    parent_key: None,
                    details: EventDetails::MmapExecution {
                        path,
                        prot,
                        flags,
                        is_secret,
                        is_exec,
                    },
                }
            }

            EbpfEvent::FileReceive { receiver_tgid, sender_tgid, path, is_tainted, .. } => {
                let key = ProcessKey::new(receiver_tgid, start_time_ns);
                NormalizedEvent {
                    event_id,
                    timestamp,
                    event_type: NormalizedEventType::FileReceive,
                    source: EventSource::EbpfLsm,
                    process_key: key,
                    pid: receiver_tgid,
                    tgid: receiver_tgid,
                    uid: 0,
                    gid: 0,
                    exe_path: Some(path.clone()),
                    exe_hash: None,
                    parent_key: None,
                    details: EventDetails::FileReceive {
                        sender_tgid,
                        receiver_tgid,
                        path,
                        is_tainted,
                    },
                }
            }
        }
    }
}
