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

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum PrivilegedOp {
    /// Atomic batch transaction execution in nftables. Strictly scoped to `inet sentinel`.
    ApplyNftablesBatch { batch: String },
    /// Safe pidfd signaling of a process instance.
    SignalProcess { pid: u32, signal: i32 },
    /// Health ping.
    Ping,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum PrivilegedResult {
    Ok(serde_json::Value),
    Error { code: String, message: String },
}
