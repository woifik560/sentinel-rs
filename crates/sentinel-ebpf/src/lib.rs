//! sentinel-ebpf — eBPF kernel program definitions, maps, and userspace loader.
//!
//! Provides the interface to Linux eBPF LSM and tracepoint hooks for:
//! - Secret access detection (`lsm/file_open`)
//! - Pipe/file taint tracking (`lsm/file_permission`)
//! - Early tagging & memfd detection (`lsm/bprm_check_security`)
//! - Lineage tracking (`sched/sched_process_fork`, `sched/sched_process_exec`)
//! - Fast-Path / Slow-Path network interception (`lsm/socket_connect`, `lsm/socket_sendmsg`, `SO_MARK`)
//!
//! Replaces legacy PID maps with BPF object storages (`TASK_STORAGE`, `INODE_STORAGE`, `SK_STORAGE`).

pub mod loader;
pub mod maps;
pub mod programs;

pub use loader::EbpfLoader;
pub use maps::{
    InodeStorageEntry, PtraceVerdict, SkStorageEntry, TaskStorageEntry, TaintFlags, TaintHygiene,
    TaintMapManager, UnixSendVerdict,
};
