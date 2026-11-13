//! eBPF LSM hook: `lsm/file_receive` (`security_file_receive`)
//!
//! # Kernel Logic & SCM_RIGHTS Descriptors:
//! Intercepts passing of open file descriptors across Unix domain sockets (`AF_UNIX`)
//! using ancillary data (`SCM_RIGHTS`).
//!
//! 1. Resolves `struct file *` being transferred from `sender` to `receiver`.
//! 2. If the file descriptor points to a protected credential (e.g. `~/.ssh/id_*`)
//!    or an inode tagged as tainted in `BPF_MAP_TYPE_INODE_STORAGE`:
//!    - Instantly propagates the taint to `receiver->group_leader` in `TASK_STORAGE`!
//! 3. Closes the loophole where an infostealer opens a secret and transfers the fd to
//!    a clean worker process to bypass file opening hooks.
//! 4. Emits `RawFileReceiveEvent` to the RingBuffer.

use std::path::Path;
use sentinel_common::events::{RawFileReceiveEvent, MAX_PATH_LEN};
use crate::maps::{FileReceiveVerdict, TaintMapManager};

/// Evaluates a `file_receive` LSM hook invocation.
pub fn evaluate_file_receive(
    manager: &TaintMapManager,
    receiver_id: u32,
    sender_id: u32,
    dev: u64,
    ino: u64,
    path: &Path,
) -> FileReceiveVerdict {
    manager.handle_file_receive(receiver_id, sender_id, dev, ino, path)
}

/// Helper to create a raw event for testing and RingBuffer simulation.
pub fn create_raw_file_receive_event(
    receiver_tgid: u32,
    sender_tgid: u32,
    path_str: &str,
    dev: u64,
    ino: u64,
    is_tainted: bool,
) -> RawFileReceiveEvent {
    let mut path_buf = [0u8; MAX_PATH_LEN];
    let bytes = path_str.as_bytes();
    let len = bytes.len().min(MAX_PATH_LEN);
    path_buf[..len].copy_from_slice(&bytes[..len]);

    RawFileReceiveEvent {
        receiver_tgid,
        sender_tgid,
        path: path_buf,
        path_len: len as u32,
        dev,
        ino,
        is_tainted: if is_tainted { 1 } else { 0 },
        _pad: [0; 7],
    }
}
