//! Tracepoint hook: `sched/sched_process_fork`
//!
//! # Kernel Logic:
//! 1. Captures `parent->tgid` and `child->tgid`.
//! 2. Queries `tainted_processes` map for `parent->tgid`.
//! 3. If parent is tainted, sets `child->tgid` with the same taint flags in `tainted_processes`.
//! 4. Emits `RawProcessForkEvent` to the eBPF RingBuffer so `sentineld` updates its
//!    causal lineage DAG in userspace.

use sentinel_common::events::RawProcessForkEvent;

/// Helper to simulate fork inheritance in userspace tests.
pub fn simulate_fork(parent_tgid: u32, child_tgid: u32) -> RawProcessForkEvent {
    RawProcessForkEvent {
        parent_tgid,
        child_tgid,
    }
}
