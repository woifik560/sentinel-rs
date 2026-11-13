//! eBPF LSM / cgroup hook: `lsm/socket_sendmsg` (`security_socket_sendmsg`)
//!
//! # Kernel Logic:
//! Intercepts connectionless UDP packets (sent via `sendto` / `sendmsg` without `connect()`).
//! Applies the identical Fast-Path / Slow-Path logic, setting `sk->mark = 0x5E170001`
//! on tainted UDP sockets so unauthorized exfiltration packets are frozen in Netfilter NFQUEUE.

use super::socket_connect::{evaluate_socket_connect, SocketConnectVerdict};

pub fn evaluate_socket_sendmsg(
    is_tainted: bool,
    is_allowed: bool,
    is_trusted_profile: bool,
    use_nfqueue: bool,
) -> SocketConnectVerdict {
    evaluate_socket_connect(is_tainted, is_allowed, is_trusted_profile, use_nfqueue)
}
