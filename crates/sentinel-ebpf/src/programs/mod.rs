//! eBPF kernel program definitions for LSM hooks and tracepoints.
//!
//! In production, these programs are compiled to eBPF bytecode using `bpf-linker`
//! and embedded or loaded dynamically by `EbpfLoader`.
//!
//! Each sub-module models kernel-side behavior and object storage operations:
//! - `file_open`: intercepts `security_file_open` to identify secret access & mark TASK_STORAGE
//! - `file_permission`: intercepts `security_file_permission` to track taint flow across pipes/FIFOs/files
//! - `bprm_check_security`: intercepts `security_bprm_check_security` for early tagging and memfd detection
//! - `process_fork`: intercepts `sched_process_fork` to inherit taint flags across processes
//! - `process_exec`: intercepts `sched_process_exec` to track binary replacements and cmdline
//! - `socket_connect`: Fast-Path allow or Slow-Path packet hold via `SO_MARK` (0x5E170001) in NFQUEUE
//! - `socket_sendmsg`: UDP connectionless protection with `SO_MARK` holding

pub mod bprm_check_security;
pub mod file_open;
pub mod file_permission;
pub mod file_receive;
pub mod mmap_file;
pub mod process_exec;
pub mod process_fork;
pub mod ptrace_access_check;
pub mod socket_connect;
pub mod socket_sendmsg;
pub mod unix_may_send;
