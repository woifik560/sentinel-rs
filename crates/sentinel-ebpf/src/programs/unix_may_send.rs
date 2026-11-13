//! eBPF LSM hook: `lsm/unix_may_send` (`security_unix_may_send`)
//!
//! # Kernel Logic & Anti-Taint Laundering:
//! Intercepts IPC datagram and stream message transmission over AF_UNIX domain sockets.
//!
//! 1. Identifies the sender's group leader `current->group_leader` and receiver socket peer.
//! 2. If the sender is `TAINTED`:
//!    - Verifies if destination socket is an exempt system infrastructure socket
//!      (Wayland compositor `/run/user/<uid>/wayland-0`, X11 `/tmp/.X11-unix/X0`,
//!       D-Bus session bus `/run/user/<uid>/bus`, or Sentinel `/run/sentinel/sentinel.sock`).
//!    - If not exempt:
//!      - Propagates taint to the receiving process's `TASK_STORAGE` (group leader)
//!        or blocks the transfer with `-EPERM`, completely neutralizing AF_UNIX taint laundering!
//! 3. Emits `RawUnixMaySendEvent` to the RingBuffer.

use std::path::Path;
use sentinel_common::events::{RawUnixMaySendEvent, MAX_PATH_LEN};
use crate::maps::{TaintMapManager, UnixSendVerdict};

/// Evaluates a `unix_may_send` hook invocation in userspace or simulation.
pub fn evaluate_unix_may_send(
    manager: &TaintMapManager,
    sender_id: u32,
    receiver_id: u32,
    sock_path: &Path,
) -> UnixSendVerdict {
    manager.handle_unix_may_send(sender_id, receiver_id, sock_path)
}

/// Helper to create a raw event for testing and RingBuffer simulation.
pub fn create_raw_unix_may_send_event(
    sender_tgid: u32,
    receiver_tgid: u32,
    sock_path_str: &str,
    is_blocked: bool,
) -> RawUnixMaySendEvent {
    let mut sock_buf = [0u8; MAX_PATH_LEN];
    let bytes = sock_path_str.as_bytes();
    let len = bytes.len().min(MAX_PATH_LEN);
    sock_buf[..len].copy_from_slice(&bytes[..len]);

    RawUnixMaySendEvent {
        sender_tgid,
        receiver_tgid,
        sock_path: sock_buf,
        sock_path_len: len as u32,
        is_blocked: if is_blocked { 1 } else { 0 },
        _pad: [0; 3],
    }
}
