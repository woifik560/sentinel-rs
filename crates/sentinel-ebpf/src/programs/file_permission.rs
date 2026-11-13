//! eBPF LSM hook: `lsm/file_permission` (`security_file_permission`)
//!
//! # Kernel Logic:
//! Intercepts read and write access to files, pipes, and FIFOs.
//!
//! 1. **Write Path** (`MAY_WRITE`):
//!    - Checks if the caller task (`current->tgid`) has `TAINTED` bitflag in `BPF_MAP_TYPE_TASK_STORAGE`.
//!    - If tainted and target inode is a pipe, FIFO, or temporary file:
//!      - Sets `TAINTED` flag in the target's `BPF_MAP_TYPE_INODE_STORAGE`.
//!      - Submits a `RawFilePermissionEvent` to the RingBuffer.
//!
//! 2. **Read Path** (`MAY_READ`):
//!    - Checks if the target inode has `TAINTED` flag in `BPF_MAP_TYPE_INODE_STORAGE`.
//!    - If tainted (e.g. `curl` reading from the other end of `cat ~/.ssh/id_rsa |` pipe):
//!      - Immediately inherits the `TAINTED` flag into the reader task's `BPF_MAP_TYPE_TASK_STORAGE`!
//!      - Submits a `RawFilePermissionEvent` to the RingBuffer.
//!
//! 3. **Taint Hygiene**:
//!    - Ignores pseudo-terminals (`/dev/pts/*`), `/dev/null`, system log files,
//!      and GUI session sockets (Wayland/X11) to avoid over-tainting the desktop environment.

use std::path::Path;
use sentinel_common::events::{RawFilePermissionEvent, MAY_READ, MAY_WRITE, MAX_PATH_LEN};
use crate::maps::{TaintFlags, TaintHygiene, TaintMapManager};

/// Evaluates a `file_permission` hook invocation in userspace or simulation.
pub fn evaluate_file_permission(
    manager: &TaintMapManager,
    tgid: u32,
    dev: u64,
    ino: u64,
    path: &Path,
    mask: u32,
    is_pipe: bool,
    is_fifo: bool,
) -> Option<TaintFlags> {
    manager.handle_file_permission(tgid, dev, ino, path, mask, is_pipe, is_fifo)
}

/// Helper to format raw permission event for testing and RingBuffer simulation.
pub fn create_raw_permission_event(
    tgid: u32,
    uid: u32,
    path_str: &str,
    dev: u64,
    ino: u64,
    mask: u32,
    is_pipe: bool,
    is_fifo: bool,
) -> RawFilePermissionEvent {
    let mut path_buf = [0u8; MAX_PATH_LEN];
    let bytes = path_str.as_bytes();
    let len = bytes.len().min(MAX_PATH_LEN);
    path_buf[..len].copy_from_slice(&bytes[..len]);

    RawFilePermissionEvent {
        tgid,
        uid,
        path: path_buf,
        path_len: len as u32,
        dev,
        ino,
        mask,
        is_pipe: if is_pipe { 1 } else { 0 },
        is_fifo: if is_fifo { 1 } else { 0 },
        _pad: [0; 6],
    }
}
