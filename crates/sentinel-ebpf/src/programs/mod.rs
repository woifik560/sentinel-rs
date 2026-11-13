//! eBPF kernel program definitions for LSM hooks and tracepoints.
//!
//! In production, these programs are compiled to eBPF bytecode using `bpf-linker`
//! and embedded or loaded dynamically by `EbpfLoader`.
//!
//! Each sub-module documents and models the kernel-side behavior:
//! - `file_open`: intercepts `security_file_open` to identify secret access & mark TGID
//! - `process_fork`: intercepts `sched_process_fork` to inherit taint flags across processes
//! - `process_exec`: intercepts `sched_process_exec` to track binary replacements and memfd
//! - `socket_connect`: intercepts `security_socket_connect` to enforce network policies (-EPERM)
//! - `socket_sendmsg`: intercepts `security_socket_sendmsg` for connectionless UDP protection

pub mod file_open;
pub mod process_fork;
pub mod process_exec;
pub mod socket_connect;
pub mod socket_sendmsg;
