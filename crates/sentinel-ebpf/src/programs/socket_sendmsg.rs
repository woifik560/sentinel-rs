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

use sentinel_common::events::{SENTINEL_MARK_REVAL_BIT, SENTINEL_SO_MARK};
use super::socket_connect::{evaluate_socket_connect_with_mark, SocketConnectVerdict};

/// Evaluates a `socket_sendmsg` or `cgroup_skb/egress` hook invocation.
///
/// # Established Connection Anti-Bypass:
/// - If `is_high_risk` is true (e.g. direct private key / crypto theft):
///   Returns `SocketConnectVerdict::DenyEperm` immediately in kernel space without NFQUEUE roundtrip.
/// - If `is_preopened` is true and `is_tainted` is true:
///   Sets `SENTINEL_MARK_REVAL_BIT` (0x40000000 | flow_id) to divert packet above `ct state established`.
pub fn evaluate_socket_sendmsg(
    is_tainted: bool,
    is_allowed: bool,
    is_trusted_profile: bool,
    use_nfqueue: bool,
    is_preopened: bool,
) -> SocketConnectVerdict {
    evaluate_socket_sendmsg_ext(
        is_tainted,
        is_allowed,
        is_trusted_profile,
        use_nfqueue,
        is_preopened,
        false,
        SENTINEL_SO_MARK,
    )
}

pub fn evaluate_socket_sendmsg_ext(
    is_tainted: bool,
    is_allowed: bool,
    is_trusted_profile: bool,
    use_nfqueue: bool,
    is_preopened: bool,
    is_high_risk: bool,
    flow_mark: u32,
) -> SocketConnectVerdict {
    if is_allowed {
        return SocketConnectVerdict::FastPathAllow;
    }

    if is_tainted {
        // High risk: immediate stop right in lsm/socket_sendmsg with -EPERM!
        if is_high_risk || !use_nfqueue {
            return SocketConnectVerdict::DenyEperm;
        }

        // Established / preopened connection: Divert to NFQUEUE with revalidation mark!
        if is_preopened {
            let reval_mark = flow_mark | SENTINEL_MARK_REVAL_BIT;
            return SocketConnectVerdict::RevalidateHoldNfqueue {
                so_mark: reval_mark,
            };
        }

        return SocketConnectVerdict::SlowPathHoldNfqueue {
            so_mark: flow_mark,
        };
    }

    evaluate_socket_connect_with_mark(
        is_tainted,
        is_allowed,
        is_trusted_profile,
        use_nfqueue,
        flow_mark,
    )
}
