//! eBPF LSM hook: `lsm/ptrace_access_check` (`security_ptrace_access_check`)
//!
//! # Kernel Logic & Memory Isolation:
//! Intercepts attempts by one process to inspect, attach, or read another process's
//! virtual address space via `ptrace(PTRACE_ATTACH)`, `ptrace(PTRACE_SEIZE)`,
//! or `process_vm_readv()` / `process_vm_writev()`.
//!
//! 1. Resolves `tracer->group_leader` and `tracee->group_leader`.
//! 2. If tracer is `TAINTED` and tracee is clean:
//!    - Immediately returns `-EPERM`! A tainted infostealer cannot hijack or inject
//!      shellcode into an untainted system process to launder its connection.
//! 3. If tracee is `TAINTED` and tracer is clean:
//!    - If attachment proceeds, tracer's `TASK_STORAGE` is tainted to prevent
//!      covert memory leakage.
//! 4. Emits `RawPtraceAccessCheckEvent` to the RingBuffer.

use sentinel_common::events::RawPtraceAccessCheckEvent;
use crate::maps::{PtraceVerdict, TaintMapManager};

/// Evaluates a `ptrace_access_check` hook invocation.
pub fn evaluate_ptrace_access_check(
    manager: &TaintMapManager,
    tracer_id: u32,
    tracee_id: u32,
    mode: u32,
) -> PtraceVerdict {
    manager.handle_ptrace_access_check(tracer_id, tracee_id, mode)
}

/// Helper to create a raw event for testing and RingBuffer simulation.
pub fn create_raw_ptrace_event(
    tracer_tgid: u32,
    tracee_tgid: u32,
    mode: u32,
    is_blocked: bool,
) -> RawPtraceAccessCheckEvent {
    RawPtraceAccessCheckEvent {
        tracer_tgid,
        tracee_tgid,
        mode,
        is_blocked: if is_blocked { 1 } else { 0 },
        _pad: [0; 3],
    }
}
