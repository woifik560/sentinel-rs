//! Minimal privileged helper for Sentinel-RS.
//!
//! Encapsulates operations requiring Linux capabilities (CAP_BPF, CAP_NET_ADMIN, CAP_KILL):
//! - Atomic nftables batch transactions inside `inet sentinel`
//! - Safe pidfd process signaling
//! - eBPF map & program lifecycle management
//!
//! Exposes a local Unix Domain Socket at `/run/sentinel/privileged.sock` with SO_PEERCRED authentication.

pub mod client;
pub mod server;

use serde::{Deserialize, Serialize};

/// Strongly typed firewall operations handled securely by the privileged helper.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum FirewallOperation {
    /// Configure base Sentinel holding rules and NFQUEUE hooks.
    SetupHolding { use_bypass: bool },
    /// Apply an isolation tier with trusted SSH IPs and optional selective policy.
    ApplyIsolation {
        tier: String,
        trusted_ssh_ips: Vec<String>,
        blocked_ips: Vec<String>,
        blocked_ports: Vec<u16>,
    },
    /// Block a specific destination IP address.
    BlockIp { ip: String },
    /// Clean up Sentinel rules by deleting table inet sentinel.
    CleanupRules,
    /// Arm an anti-lockout timer inside the privileged helper (or rollback if expired).
    ArmAntiLockout {
        timeout_secs: u64,
        trusted_ssh_ips: Vec<String>,
    },
    /// Disarm the anti-lockout timer (operator confirmed).
    ConfirmAntiLockout,
    /// Rollback isolation to Tier::None immediately.
    Rollback,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum PrivilegedOp {
    /// Strongly-typed firewall operations executed safely by the privileged helper.
    Firewall(FirewallOperation),
    /// Atomic batch transaction execution in nftables. Strictly scoped to `inet sentinel`.
    #[deprecated(note = "Use Firewall(FirewallOperation) instead for strong typing")]
    ApplyNftablesBatch { batch: String },
    /// Safe pidfd signaling of a process instance with anti-PID-reuse verification.
    SignalProcess {
        pid: u32,
        signal: i32,
        expected_start_time: Option<u64>,
        expected_exe: Option<String>,
    },
    /// Health ping.
    Ping,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum PrivilegedResult {
    Ok(serde_json::Value),
    Error { code: String, message: String },
}
