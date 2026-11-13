//! eBPF LSM hook: `lsm/socket_sendmsg` (`security_socket_sendmsg`)
//!
//! # Kernel Logic:
//! Intercepts connectionless UDP packets (sent via `sendto` / `sendmsg` without `connect()`).
//! Applies the identical taint check and drops unauthorized exfiltration packets before transmission.

use super::socket_connect::{evaluate_socket_connect, SocketConnectVerdict};

pub fn evaluate_socket_sendmsg(is_tainted: bool, is_allowed: bool) -> SocketConnectVerdict {
    evaluate_socket_connect(is_tainted, is_allowed, false)
}
