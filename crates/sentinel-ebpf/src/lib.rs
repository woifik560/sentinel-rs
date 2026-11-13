//! sentinel-ebpf — eBPF kernel program definitions, maps, and userspace loader.
//!
//! Provides the interface to Linux eBPF LSM and tracepoint hooks for:
//! - Secret access detection (`lsm/file_open`)
//! - Lineage tracking (`sched/sched_process_fork`, `sched/sched_process_exec`)
//! - Network interception (`lsm/socket_connect`, `lsm/socket_sendmsg`)
//!
//! Includes userspace loader (`EbpfLoader`) and map managers.

pub mod loader;
pub mod maps;
pub mod programs;

pub use loader::EbpfLoader;
pub use maps::{TaintFlags, TaintMapManager};
