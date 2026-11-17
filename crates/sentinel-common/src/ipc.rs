//! IPC protocol types for communication between sentineld and sntctl management CLI.
//!
//! Uses Unix Domain Socket at `/run/sentinel/sentinel.sock` with
//! `SO_PEERCRED` authentication and role-based access control (RBAC).

use serde::{Deserialize, Serialize};
use std::path::PathBuf;

use crate::health::AgentHealthReport;
use crate::policy::PolicyDecision;

/// A single step in the process lineage chain.
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

/// Prompt request structure maintained for telemetry and inspection.
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
    /// Unix timestamp when this prompt expires.
    pub expires_at_unix: u64,
}

/// Actions supported for manual overrides or autonomous enforcement.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum PromptAction {
    /// Send SIGKILL to the process.
    Kill,
    /// Block this single connection attempt.
    DenyOnce,
    /// Allow this single connection.
    AllowOnce,
    /// Temporarily allow network flows for this process for duration in seconds.
    AllowForDuration { seconds: u64 },
    /// Allow connections to specific destination host / IP.
    AllowHost { host: String },
    /// Allow all connections from this specific process instance.
    AllowProcess,
    /// Add process to App Scope whitelist in config.toml.
    AllowAppScope,
}

/// Verdict message format for administrative intervention.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PromptVerdict {
    /// Must match the incident_id.
    pub incident_id: String,
    /// The chosen action.
    pub action: PromptAction,
}

/// Verified authorization level of an IPC client connection via SO_PEERCRED.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum ClientRole {
    /// Superuser root administrator (UID 0):
    /// Policy management, protection toggling, configuration reload,
    /// exception management, response management, full incident export.
    RootAdmin,
    /// Operator (configured operator GID/UID):
    /// Status, health, events, incidents, diagnostics, read-only queries.
    Operator,
    /// Read-only monitor (sntctl monitor, status, public diagnostics).
    ReadOnly,
}

impl ClientRole {
    /// Checks if this role is permitted to perform policy and response modifications.
    pub fn can_manage_protection(&self) -> bool {
        matches!(self, ClientRole::RootAdmin)
    }

    /// Checks if this role is permitted to execute operator queries.
    pub fn can_inspect(&self) -> bool {
        matches!(self, ClientRole::RootAdmin | ClientRole::Operator | ClientRole::ReadOnly)
    }
}

/// Structured IPC command enumeration matching Part 14.2.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "command", content = "params")]
pub enum IpcCommand {
    /// sntctl status
    Status,
    /// sntctl health
    Health,
    /// sntctl diagnostics
    Diagnostics,
    /// sntctl doctor
    Doctor,
    /// sntctl protection status
    ProtectionStatus,
    /// sntctl protection enable
    ProtectionEnable,
    /// sntctl protection disable
    ProtectionDisable,
    /// sntctl events list
    EventsList { limit: Option<usize>, offset: Option<usize> },
    /// sntctl events show <ID>
    EventsShow { event_id: String },
    /// sntctl events export
    EventsExport { format: String },
    /// sntctl incidents list
    IncidentsList { limit: Option<usize>, offset: Option<usize> },
    /// sntctl incidents show <ID>
    IncidentsShow { incident_id: String },
    /// sntctl incidents export <ID>
    IncidentsExport { incident_id: String, format: String },
    /// sntctl policy list
    PolicyList,
    /// sntctl policy show <ID>
    PolicyShow { policy_id: String },
    /// sntctl policy validate
    PolicyValidate { policy_content: String },
    /// sntctl policy reload
    PolicyReload,
    /// sntctl rules list
    RulesList,
    /// sntctl rules show <ID>
    RulesShow { rule_id: String },
    /// sntctl process inspect <PID>
    ProcessInspect { tgid: u32 },
    /// sntctl process lineage <PID>
    ProcessLineage { tgid: u32 },
    /// sntctl network status
    NetworkStatus,
    /// sntctl network blocked
    NetworkBlocked,
    /// sntctl config validate
    ConfigValidate,
    /// Manual process unfreeze
    Unfreeze { tgid: u32 },
}

/// Structured IPC response payload.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "status", content = "data")]
pub enum IpcResponse {
    Ok(serde_json::Value),
    Error { code: String, message: String },
    Health(AgentHealthReport),
    PolicyDecision(PolicyDecision),
}

/// Length-prefixed / structured JSON message envelope.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct IpcEnvelope {
    pub version: u32,
    pub request_id: String,
    pub payload: IpcPayload,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(untagged)]
pub enum IpcPayload {
    Command(IpcCommand),
    Response(IpcResponse),
    Legacy(IpcMessage),
}

/// Legacy and streaming message envelope for backward compatibility and live event feeds.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "type")]
pub enum IpcMessage {
    /// Autonomous telemetry prompt record.
    Prompt(PromptRequest),
    /// Administrative override verdict.
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
        /// Number of currently frozen or isolated processes.
        frozen_count: usize,
        /// Current operating mode.
        mode: String,
    },
    /// Subscribe to event stream (for sntctl monitor).
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
    /// Request to unfreeze or un-isolate a process.
    Unfreeze {
        /// TGID of the process.
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
    /// Structured response wrapper.
    StructuredResponse {
        success: bool,
        data: serde_json::Value,
    },
}
