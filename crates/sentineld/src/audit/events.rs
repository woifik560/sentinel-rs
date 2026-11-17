//! Security audit event representations.

use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum AuditCategory {
    PolicyDecision,
    ResponseAction,
    ConfigurationChange,
    IpcManagement,
    HealthStateChange,
    IncidentLifecycle,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AuditRecord {
    pub audit_id: String,
    pub timestamp_ns: u64,
    pub category: AuditCategory,
    pub operator_uid: Option<u32>,
    pub operator_gid: Option<u32>,
    pub target_pid: Option<u32>,
    pub action: String,
    pub summary: String,
    pub metadata_json: String,
}
