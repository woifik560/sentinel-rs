//! IPC protocol types for communication between sentineld and clients.
//!
//! Uses Unix Domain Socket at `/run/sentinel/sentinel.sock` with
//! `SO_PEERCRED` authentication as described in ТЗ section 4.2.

use serde::{Deserialize, Serialize};
use std::path::PathBuf;

/// A single step in the process lineage chain for display in prompts.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LineageStep {
    /// Process TGID.
    pub tgid: u32,
    /// Executable name (basename).
    pub exe_name: String,
    /// Script path for interpreter processes.
    pub script_path: Option<PathBuf>,
}

impl std::fmt::Display for LineageStep {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        if let Some(ref script) = self.script_path {
            write!(f, "{} ({}) [PID {}]", self.exe_name, script.display(), self.tgid)
        } else {
            write!(f, "{} [PID {}]", self.exe_name, self.tgid)
        }
    }
}

/// Interactive prompt request sent from sentineld to GUI/CLI clients (ТЗ 4.2).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PromptRequest {
    /// Unique incident identifier.
    pub incident_id: String,
    /// Computed risk score (0..100).
    pub risk_score: u32,
    /// Process ancestry chain (root → current).
    pub lineage: Vec<LineageStep>,
    /// Path of the accessed secret.
    pub secret_path: Option<String>,
    /// Time in milliseconds between secret read and network attempt.
    pub time_delta_ms: Option<u64>,
    /// Destination IP address.
    pub dest_ip: Option<String>,
    /// Destination port.
    pub dest_port: Option<u16>,
    /// Destination domain (from cached DNS, if available).
    pub dest_domain: Option<String>,
    /// Human-readable list of fired rule explanations.
    pub reasons: Vec<String>,
    /// Unix timestamp when this prompt expires (Fail-Closed).
    pub expires_at_unix: u64,
    /// Indicates whether the active desktop session is running under X11.
    /// If true, GUI requires entry of `auth_pin` to prevent X11 synthetic input injection.
    #[serde(default)]
    pub is_x11_session: bool,
    /// Ephemeral 4-digit verification PIN required for sensitive verdicts under X11.
    pub auth_pin: Option<String>,
}

/// Possible user actions in response to a prompt (ТЗ 4.2).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum PromptAction {
    /// Send SIGKILL to the process.
    Kill,
    /// Block this single connection attempt.
    DenyOnce,
    /// Allow this single connection (add temporary token).
    AllowOnce,
    /// Temporarily allow network flows for this process for the given duration in seconds (e.g. 300s for builds).
    AllowForDuration { seconds: u64 },
    /// Allow connections to this specific destination host / IP.
    AllowHost { host: String },
    /// Allow all connections from this specific process instance.
    AllowProcess,
    /// Add process to App Scope whitelist in config.toml.
    AllowAppScope,
}

/// User verdict sent from GUI/CLI back to sentineld.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PromptVerdict {
    /// Must match the incident_id from PromptRequest.
    pub incident_id: String,
    /// The chosen action.
    pub action: PromptAction,
    /// Optional authorization PIN entered by user under X11 sessions.
    #[serde(default)]
    pub auth_pin: Option<String>,
}

/// Verified authorization level of an IPC client connection.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum ClientRole {
    /// Read-only monitor (sentinelctl monitor, status, export).
    ReadOnly,
    /// Cryptographically verified GUI process (sentinel-gui).
    AuthorizedGui,
    /// Superuser root administrator (UID 0).
    RootAdmin,
}

/// Top-level IPC message envelope for bidirectional communication.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "type")]
pub enum IpcMessage {
    /// Prompt request from daemon to client.
    Prompt(PromptRequest),
    /// User verdict from client to daemon.
    Verdict(PromptVerdict),
    /// Request current daemon status.
    StatusRequest,
    /// Daemon status response.
    StatusResponse {
        /// Daemon uptime in seconds.
        uptime_secs: u64,
        /// Number of tracked processes in lineage graph.
        tracked_processes: usize,
        /// Number of incidents since start.
        total_incidents: u64,
        /// Number of currently frozen processes.
        frozen_count: usize,
    },
    /// Subscribe to event stream (for sentinelctl monitor).
    Subscribe,
    /// An event in the stream.
    Event {
        /// Timestamp as ISO 8601 string.
        timestamp: String,
        /// Event summary.
        summary: String,
        /// Associated risk score, if any.
        risk_score: Option<u32>,
    },
    /// Request to unfreeze a process.
    Unfreeze {
        /// TGID of the process to unfreeze.
        tgid: u32,
    },
    /// Export incident report.
    ExportRequest {
        /// Incident ID to export.
        incident_id: String,
    },
    /// Exported incident report data.
    ExportResponse {
        /// The serialized incident report JSON.
        report_json: String,
    },
    /// Security / Authorization error returned when unauthenticated peer sends privileged command.
    AuthError {
        message: String,
    },
}
