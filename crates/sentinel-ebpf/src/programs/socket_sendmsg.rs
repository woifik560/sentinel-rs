//! eBPF LSM, cgroup, and sock_ops hooks for network packet interception:
//! - `lsm/socket_sendmsg` (`security_socket_sendmsg`) [Process Syscall Context: returns -EPERM]
//! - `cgroup/sendmsg4`, `cgroup/sendmsg6` [UDP Datagram Context: sets SO_MARK via bpf_setsockopt]
//! - `cgroup/connect4`, `cgroup/connect6` [Connect Context: sets SO_MARK before Netfilter]
//! - `sock_ops` [TCP State Changes: sets SO_MARK before SYN/DATA egress]
//! - `cgroup_skb/egress` [ip_finish_output Context: immediate packet drop fail-safe]
//!
//! # Kernel Hook Ordering & Anti-Bypass Architecture:
//! In the Linux kernel network stack, `cgroup_skb/egress` is called in `ip_finish_output()` —
//! which is AFTER Netfilter `NF_INET_LOCAL_OUT` and `NF_INET_POST_ROUTING`. Therefore,
//! setting `skb->mark` inside `cgroup_skb/egress` cannot be captured by NFQUEUE in output chains.
//!
//! Sentinel-RS implements the dual-phase solution:
//! 1. **Early Syscall Interception (`lsm/socket_sendmsg`)**:
//!    - For HIGH-risk processes (direct credential/crypto theft): returns `-EPERM` immediately
//!      in the process syscall context, stopping the transmission before any packet is allocated.
//! 2. **Pre-Netfilter Socket Marking (`cgroup/sendmsg4|6`, `cgroup/connect4|6`, `sock_ops`)**:
//!    - Sets `SO_MARK` (`0x5E000000 | flow_id` or `0x5E800000 | flow_id`) via `bpf_setsockopt`
//!      directly on the struct `sock` before the packet traverses Netfilter!
//! 3. **Egress Drop Fail-Safe (`cgroup_skb/egress`)**:
//!    - For tainted tasks with packets already in-flight or on pre-opened sockets,
//!      `cgroup_skb/egress` drops the packet (`return 0`) until user verdict is granted.

use sentinel_common::events::{SENTINEL_MARK_REVAL_BIT, SENTINEL_SO_MARK};
use super::socket_connect::{evaluate_socket_connect_with_mark, SocketConnectVerdict};

/// Action to be taken by network hook.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum EgressAction {
    /// Allow packet to proceed.
    Pass,
    /// Return -EPERM to userspace syscall in lsm/socket_sendmsg.
    SyscallEperm,
    /// Drop packet immediately in cgroup_skb/egress (return 0).
    EgressDrop,
    /// Divert to NFQUEUE via SO_MARK (set via bpf_setsockopt or sock_ops).
    HoldNfqueue { mark: u32 },
}

/// Evaluates a `socket_sendmsg` invocation in syscall context.
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

/// Evaluates network data transmission with full context and dynamic mark.
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
        // Prevents packet creation at the syscall level.
        if is_high_risk || !use_nfqueue {
            return SocketConnectVerdict::DenyEperm;
        }

        // Established / pre-opened connection: mark with revalidation flag (0x5E800000 | flow_id)
        // Set via bpf_setsockopt in sock_ops/cgroup before Netfilter!
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

/// Evaluates egress packet filtering at `cgroup_skb/egress` (in ip_finish_output).
pub fn evaluate_cgroup_skb_egress(is_tainted: bool, is_held_in_queue: bool) -> EgressAction {
    if is_tainted && is_held_in_queue {
        // Drop packet at egress until userspace delivers NF_ACCEPT verdict
        EgressAction::EgressDrop
    } else {
        EgressAction::Pass
    }
}
