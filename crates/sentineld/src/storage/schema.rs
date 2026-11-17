//! Database schema models and query records.

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct StoredEventRecord {
    pub event_id: String,
    pub timestamp: DateTime<Utc>,
    pub event_type: String,
    pub source: String,
    pub process_key: String,
    pub pid: u32,
    pub tgid: u32,
    pub uid: u32,
    pub gid: u32,
    pub exe_path: Option<String>,
    pub details_json: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct StoredIncidentRecord {
    pub incident_id: String,
    pub created_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
    pub severity: String,
    pub risk_score: u32,
    pub process_key: String,
    pub status: String,
    pub verdict: String,
    pub human_summary: String,
    pub details_json: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct StoredResponseRecord {
    pub action_id: String,
    pub timestamp: DateTime<Utc>,
    pub incident_id: Option<String>,
    pub process_key: String,
    pub action_type: String,
    pub status: String,
    pub details_json: String,
}
