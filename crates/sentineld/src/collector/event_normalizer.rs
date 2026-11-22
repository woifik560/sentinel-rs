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
            EbpfEvent::ProcessExec {
                tgid,
                exe_path,
                cmdline,
            } => {
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

            EbpfEvent::ProcessFork {
                parent_tgid,
                child_tgid,
            } => {
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
                    details: EventDetails::ProcessFork {
                        parent_tgid,
                        child_tgid,
                    },
                }
            }

            EbpfEvent::FileOpen {
                tgid,
                uid,
                path,
                dev,
                ino,
                flags,
            } => {
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
                    details: EventDetails::FileOpen {
                        path,
                        flags,
                        dev,
                        ino,
                    },
                }
            }

            EbpfEvent::FilePermission {
                tgid,
                uid,
                path,
                mask,
                is_pipe,
                is_fifo,
                ..
            } => {
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
                    details: EventDetails::FilePermission {
                        path,
                        mask,
                        is_pipe,
                        is_fifo,
                    },
                }
            }

            EbpfEvent::BprmCheckSecurity {
                tgid,
                uid,
                exe_path,
                is_memfd,
                ..
            } => {
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

            EbpfEvent::UnixMaySend {
                sender_tgid,
                receiver_tgid,
                sock_path,
                is_blocked,
            } => {
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

            EbpfEvent::PtraceAccessCheck {
                tracer_tgid,
                tracee_tgid,
                mode,
                is_blocked,
            } => {
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

            EbpfEvent::ProcEnvironAccess {
                reader_tgid,
                target_tgid,
                path: _path,
                is_blocked,
            } => {
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

            EbpfEvent::MmapFile {
                tgid,
                uid,
                path,
                prot,
                flags,
                is_secret,
                is_exec,
                ..
            } => {
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

            EbpfEvent::FileReceive {
                receiver_tgid,
                sender_tgid,
                path,
                is_tainted,
                ..
            } => {
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

    /// Deserializes a raw C-compatible #[repr(C)] eBPF byte slice directly into a NormalizedEvent.
    /// Strictly guarantees safe unaligned reading, bounds checks, and stable ABI across compilers.
    pub fn normalize_raw_bytes(event_type: u32, bytes: &[u8]) -> Option<NormalizedEvent> {
        use sentinel_common::events::*;

        let event_id = Uuid::new_v4().to_string();
        let timestamp = Utc::now();

        match event_type {
            EVENT_TYPE_FILE_OPEN => {
                if bytes.len() < std::mem::size_of::<RawFileOpenEvent>() {
                    return None;
                }
                let raw =
                    unsafe { std::ptr::read_unaligned(bytes.as_ptr() as *const RawFileOpenEvent) };
                let len = (raw.path_len as usize).min(raw.path.len());
                let path_str = String::from_utf8_lossy(&raw.path[..len]).to_string();
                let path = PathBuf::from(path_str);
                let key = ProcessKey::new(raw.tgid, 0);

                Some(NormalizedEvent {
                    event_id,
                    timestamp,
                    event_type: NormalizedEventType::FileOpen,
                    source: EventSource::EbpfLsm,
                    process_key: key,
                    pid: raw.tgid,
                    tgid: raw.tgid,
                    uid: raw.uid,
                    gid: 0,
                    exe_path: None,
                    exe_hash: None,
                    parent_key: None,
                    details: EventDetails::FileOpen {
                        path,
                        flags: raw.flags,
                        dev: raw.dev,
                        ino: raw.ino,
                    },
                })
            }
            EVENT_TYPE_PROCESS_FORK => {
                if bytes.len() < std::mem::size_of::<RawProcessForkEvent>() {
                    return None;
                }
                let raw = unsafe {
                    std::ptr::read_unaligned(bytes.as_ptr() as *const RawProcessForkEvent)
                };
                let key = ProcessKey::new(raw.child_tgid, 0);
                Some(NormalizedEvent {
                    event_id,
                    timestamp,
                    event_type: NormalizedEventType::ProcessFork,
                    source: EventSource::Tracepoint,
                    process_key: key,
                    pid: raw.child_tgid,
                    tgid: raw.child_tgid,
                    uid: 0,
                    gid: 0,
                    exe_path: None,
                    exe_hash: None,
                    parent_key: Some(ProcessKey::new(raw.parent_tgid, 0)),
                    details: EventDetails::ProcessFork {
                        parent_tgid: raw.parent_tgid,
                        child_tgid: raw.child_tgid,
                    },
                })
            }
            _ => None,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use sentinel_common::events::{RawFileOpenEvent, EVENT_TYPE_FILE_OPEN, MAX_PATH_LEN};

    #[test]
    fn test_raw_c_abi_deserialization_safety() {
        let mut raw_event = RawFileOpenEvent {
            tgid: 1234,
            uid: 1000,
            path: [0u8; MAX_PATH_LEN],
            path_len: 11,
            dev: 2049,
            ino: 554433,
            flags: 0o644,
        };

        let path_bytes = b"/etc/shadow";
        raw_event.path[..path_bytes.len()].copy_from_slice(path_bytes);

        let bytes = unsafe {
            std::slice::from_raw_parts(
                &raw_event as *const RawFileOpenEvent as *const u8,
                std::mem::size_of::<RawFileOpenEvent>(),
            )
        };

        let normalized = EventNormalizer::normalize_raw_bytes(EVENT_TYPE_FILE_OPEN, bytes)
            .expect("Failed to normalize raw bytes");
        assert_eq!(normalized.event_type, NormalizedEventType::FileOpen);
        assert_eq!(normalized.pid, 1234);
        assert_eq!(normalized.tgid, 1234);
        match normalized.details {
            EventDetails::FileOpen {
                path,
                flags,
                dev,
                ino,
            } => {
                assert_eq!(path, PathBuf::from("/etc/shadow"));
                assert_eq!(flags, 0o644);
                assert_eq!(dev, 2049);
                assert_eq!(ino, 554433);
            }
            _ => panic!("Expected FileOpen details"),
        }
    }
}
