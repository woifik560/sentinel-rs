//! eBPF LSM hook: `lsm/socket_connect` (`security_socket_connect`)
//!
//! # Kernel Logic:
//! 1. Intercepts outbound TCP/UDP `connect()` calls.
//! 2. Reads `current->tgid`.
//! 3. Checks the `allowed_processes` eBPF map: if present, allows immediately (`return 0`).
//! 4. Checks the `tainted_processes` eBPF map:
//!    - If tainted:
//!      - In MVP mode: returns `-EPERM` (1), drops the connection before SYN packet is sent,
//!        and calls `bpf_send_signal(SIGSTOP)` on the caller.
//!      - In NFQUEUE mode: sets `sk_mark = SENTINEL_PENDING_MARK` for zero-drop packet holding.
//! 5. Pushes `RawSocketConnectEvent` to the RingBuffer for daemon risk scoring and user prompt.

/// Simulated evaluation of a socket_connect hook invocation.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SocketConnectVerdict {
    /// Allow connection through.
    Allow,
    /// Deny connection with -EPERM.
    DenyEperm,
    /// Hold connection in NFQUEUE.
    HoldPending,
}

pub fn evaluate_socket_connect(
    is_tainted: bool,
    is_allowed: bool,
    use_nfqueue: bool,
) -> SocketConnectVerdict {
    if is_allowed {
        SocketConnectVerdict::Allow
    } else if is_tainted {
        if use_nfqueue {
            SocketConnectVerdict::HoldPending
        } else {
            SocketConnectVerdict::DenyEperm
        }
    } else {
        SocketConnectVerdict::Allow
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_socket_connect_verdicts() {
        assert_eq!(
            evaluate_socket_connect(false, false, false),
            SocketConnectVerdict::Allow
        );
        assert_eq!(
            evaluate_socket_connect(true, false, false),
            SocketConnectVerdict::DenyEperm
        );
        assert_eq!(
            evaluate_socket_connect(true, false, true),
            SocketConnectVerdict::HoldPending
        );
        assert_eq!(
            evaluate_socket_connect(true, true, false),
            SocketConnectVerdict::Allow
        );
    }
}
