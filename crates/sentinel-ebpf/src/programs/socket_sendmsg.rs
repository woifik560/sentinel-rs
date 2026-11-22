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

use super::socket_connect::{evaluate_socket_connect_with_mark, SocketConnectVerdict};
use crate::maps::TaintMapManager;
use sentinel_common::events::{encode_flow_mark, SENTINEL_MARK_REVAL_BIT, SENTINEL_SO_MARK};

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

/// Specialized verdict for `socket_sendmsg` hook.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SocketSendmsgVerdict {
    Pass,
    Drop,
    DenyEperm,
    HoldForRevalidation { reval_mark: u32 },
    SlowPathHoldNfqueue { so_mark: u32 },
}

/// Evaluates network data transmission on an established socket via TaintMapManager.
pub fn evaluate_socket_sendmsg_ext(
    manager: &TaintMapManager,
    tgid: u32,
    is_preopened: bool,
    is_high_risk: bool,
    flow_id: u32,
) -> SocketSendmsgVerdict {
    let leader_tgid = manager.resolve_group_leader(tgid);
    let is_tainted = manager.is_tainted(leader_tgid);
    let is_allowed = manager.is_allowed(leader_tgid);

    if is_allowed {
        return SocketSendmsgVerdict::Pass;
    }

    if is_tainted {
        if is_high_risk {
            return SocketSendmsgVerdict::DenyEperm;
        }

        if is_preopened {
            let reval_mark = encode_flow_mark(flow_id, true);
            return SocketSendmsgVerdict::HoldForRevalidation { reval_mark };
        }

        let mark = encode_flow_mark(flow_id, false);
        return SocketSendmsgVerdict::SlowPathHoldNfqueue { so_mark: mark };
    }

    SocketSendmsgVerdict::Pass
}

/// Evaluates a `socket_sendmsg` invocation in syscall context using raw parameters.
pub fn evaluate_socket_sendmsg(
    is_tainted: bool,
    is_allowed: bool,
    is_trusted_profile: bool,
    use_nfqueue: bool,
    is_preopened: bool,
) -> SocketConnectVerdict {
    evaluate_socket_sendmsg_raw(
        is_tainted,
        is_allowed,
        is_trusted_profile,
        use_nfqueue,
        is_preopened,
        false,
        SENTINEL_SO_MARK,
    )
}

/// Raw evaluator matching low-level kernel eBPF parameter layout.
pub fn evaluate_socket_sendmsg_raw(
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
        if is_high_risk || !use_nfqueue {
            return SocketConnectVerdict::DenyEperm;
        }

        if is_preopened {
            let reval_mark = flow_mark | SENTINEL_MARK_REVAL_BIT;
            return SocketConnectVerdict::RevalidateHoldNfqueue {
                so_mark: reval_mark,
            };
        }

        return SocketConnectVerdict::SlowPathHoldNfqueue { so_mark: flow_mark };
    }

    evaluate_socket_connect_with_mark(
        is_tainted,
        is_allowed,
        is_trusted_profile,
        use_nfqueue,
        flow_mark,
    )
}

/// Hybrid in-kernel watchdog evaluator with covert DNS tunnel inspection:
/// - If destination is local DNS resolver (127.0.0.53:53 or 127.0.0.0/8:53) and process is tainted:
///   Refuses silent loopback bypass and blocks transmission (-EPERM).
/// - If sentineld daemon is unresponsive (> 2.0s watchdog limit):
///   - Clean process: Pass (Fail-Safe keeps desktop/browsers running seamlessly).
///   - Tainted process: SyscallEperm / Drop (Fail-Close prevents malware escaping via daemon crash!).
pub fn evaluate_socket_sendmsg_watchdog(
    manager: &TaintMapManager,
    tgid: u32,
    now_ns: u64,
    dest_ip: Option<&str>,
    dest_port: u16,
) -> EgressAction {
    let leader_tgid = manager.resolve_group_leader(tgid);
    let is_tainted = manager.is_tainted(leader_tgid);

    // 1. Covert Local DNS Tunnel Protection:
    if let Some(ip) = dest_ip {
        if dest_port == 53 && (ip == "127.0.0.53" || ip.starts_with("127.")) && is_tainted {
            return EgressAction::SyscallEperm;
        }
    }

    // 2. Hybrid In-Kernel Watchdog:
    if !manager.is_daemon_alive(now_ns) {
        if !is_tainted {
            return EgressAction::Pass;
        } else {
            return EgressAction::SyscallEperm;
        }
    }

    if is_tainted {
        EgressAction::SyscallEperm
    } else {
        EgressAction::Pass
    }
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
