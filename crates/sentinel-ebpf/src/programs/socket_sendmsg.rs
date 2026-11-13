//! eBPF LSM / cgroup hooks:
//! - `lsm/socket_sendmsg` (`security_socket_sendmsg`)
//! - `cgroup/sendmsg4`, `cgroup/sendmsg6`
//! - `cgroup/connect4`, `cgroup/connect6`
//! - `cgroup_skb/egress`
//!
//! # Kernel Logic & Anti-Bypass Protection:
//! 1. **Connectionless Exfiltration (UDP / QUIC / DNS)**:
//!    - Intercepts raw UDP and QUIC packets (sent via `sendto` / `sendmsg` without `connect()`).
//!    - Hooks at syscall entry (`cgroup/sendmsg4/6`) set `sk->mark = 0x5E170001` on every packet.
//!
//! 2. **Pre-Opened Socket Protection**:
//!    - If a process opened a socket BEFORE reading a secret (gaining initial clean state in conntrack),
//!      and subsequently accessed a secret (becoming tainted in `TASK_STORAGE` via `group_leader`),
//!      every subsequent `sendmsg()` or egress write will detect the taint!
//!    - Immediately sets `SO_MARK = 0x5E170001` on the socket or returns `-EPERM`, instantly halting
//!      exfiltration over pre-established TCP, WebSocket, or HTTP/2 channels.

use super::socket_connect::{evaluate_socket_connect, SocketConnectVerdict};

/// Evaluates a `socket_sendmsg` or `cgroup_skb/egress` hook invocation.
pub fn evaluate_socket_sendmsg(
    is_tainted: bool,
    is_allowed: bool,
    is_trusted_profile: bool,
    use_nfqueue: bool,
    _is_preopened: bool,
) -> SocketConnectVerdict {
    // If process is tainted, even a pre-opened approved socket is blocked from sending new payload!
    if is_tainted && !is_allowed {
        if use_nfqueue {
            SocketConnectVerdict::SlowPathHoldNfqueue {
                so_mark: sentinel_common::events::SENTINEL_SO_MARK,
            }
        } else {
            SocketConnectVerdict::DenyEperm
        }
    } else {
        evaluate_socket_connect(is_tainted, is_allowed, is_trusted_profile, use_nfqueue)
    }
}
