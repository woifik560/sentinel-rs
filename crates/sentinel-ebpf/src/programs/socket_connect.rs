//! eBPF LSM / cgroup hook: `lsm/socket_connect` (`security_socket_connect`)
//!
//! # Fast-Path vs Slow-Path Architecture:
//!
//! 1. **Fast-Path (In-Kernel, Nanosecond Latency)**:
//!    - Queries `BPF_MAP_TYPE_TASK_STORAGE` for `current->tgid`.
//!    - If `taint_flags.is_empty()` and task is in allowlist or has `PROFILE_TRUSTED_PKG`:
//!      - Immediately returns `0` (Allow).
//!      - Bypasses userspace daemon and NFQUEUE completely: zero network latency!
//!
//! 2. **Slow-Path (Tainted / Suspicious Traffic Hold)**:
//!    - If task has `TAINTED` bitflag or suspicious origin:
//!      - In NFQUEUE mode (Production): Sets socket security mark `sk->mark = 0x5E170001` (SENTINEL_SO_MARK)
//!        in `BPF_MAP_TYPE_SK_STORAGE`.
//!      - Packet is routed by nftables directly into NFQUEUE (queue num 100), where it is
//!        physically frozen at Netfilter hook until sentineld or user returns NF_ACCEPT/NF_DROP.
//!      - In strict/legacy mode: Returns `-EPERM` (1) immediately.
//!    - Emits `RawSocketConnectEvent` to the eBPF RingBuffer.

use sentinel_common::events::SENTINEL_SO_MARK;

/// Evaluated action for an intercepted socket connection.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SocketConnectVerdict {
    /// Fast-Path: Allow connection immediately with zero latency.
    FastPathAllow,
    /// Slow-Path: Hold initial SYN packet in Netfilter queue via SO_MARK (0x5E170001).
    SlowPathHoldNfqueue { so_mark: u32 },
    /// Strict/Legacy fallback: Deny connection with -EPERM.
    DenyEperm,
}

/// Evaluates network connection request, choosing Fast-Path or Slow-Path.
pub fn evaluate_socket_connect(
    is_tainted: bool,
    is_allowed: bool,
    is_trusted_profile: bool,
    use_nfqueue: bool,
) -> SocketConnectVerdict {
    if is_allowed {
        return SocketConnectVerdict::FastPathAllow;
    }

    if !is_tainted && is_trusted_profile {
        // Fast-Path: clean task with trusted package origin
        SocketConnectVerdict::FastPathAllow
    } else if is_tainted || !is_trusted_profile {
        // Slow-Path: mark socket for zero-drop packet holding in NFQUEUE
        if use_nfqueue {
            SocketConnectVerdict::SlowPathHoldNfqueue {
                so_mark: SENTINEL_SO_MARK,
            }
        } else {
            SocketConnectVerdict::DenyEperm
        }
    } else {
        SocketConnectVerdict::FastPathAllow
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_fast_path_clean_process() {
        // Untainted process with trusted profile -> Fast-Path Allow
        let verdict = evaluate_socket_connect(false, false, true, true);
        assert_eq!(verdict, SocketConnectVerdict::FastPathAllow);
    }

    #[test]
    fn test_slow_path_tainted_process_nfqueue() {
        // Tainted process -> Slow-Path hold via SO_MARK in NFQUEUE
        let verdict = evaluate_socket_connect(true, false, true, true);
        assert_eq!(
            verdict,
            SocketConnectVerdict::SlowPathHoldNfqueue {
                so_mark: SENTINEL_SO_MARK
            }
        );
    }

    #[test]
    fn test_allowed_override() {
        let verdict = evaluate_socket_connect(true, true, false, true);
        assert_eq!(verdict, SocketConnectVerdict::FastPathAllow);
    }
}
