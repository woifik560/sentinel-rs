//! EDR Incident Manager: lifecycle, persistence, detail, export, and status transitions.

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::sync::{Arc, RwLock};
use tracing::info;
use uuid::Uuid;

use sentinel_common::ipc::LineageStep;
use sentinel_common::policy::PolicyAction;
use sentinel_common::risk::{RuleFiring, SeverityLevel, Verdict};
use crate::collector::ProcessKey;
use crate::incidents::correlator::IncidentCorrelator;
use crate::storage::{StorageManager, StoredIncidentRecord};

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum IncidentStatus {
    Detected,
    Investigating,
    Contained,
    Resolved,
    FalsePositive,
}

impl std::fmt::Display for IncidentStatus {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            IncidentStatus::Detected => write!(f, "DETECTED"),
            IncidentStatus::Investigating => write!(f, "INVESTIGATING"),
            IncidentStatus::Contained => write!(f, "CONTAINED"),
            IncidentStatus::Resolved => write!(f, "RESOLVED"),
            IncidentStatus::FalsePositive => write!(f, "FALSE_POSITIVE"),
        }
    }
}

impl std::str::FromStr for IncidentStatus {
    type Err = String;
    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s.to_ascii_uppercase().as_str() {
            "DETECTED" => Ok(IncidentStatus::Detected),
            "INVESTIGATING" => Ok(IncidentStatus::Investigating),
            "CONTAINED" => Ok(IncidentStatus::Contained),
            "RESOLVED" => Ok(IncidentStatus::Resolved),
            "FALSE_POSITIVE" => Ok(IncidentStatus::FalsePositive),
            other => Err(format!("Unknown incident status: {}", other)),
        }
    }
}

/// Comprehensive EDR security incident.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Incident {
    pub id: String,
    pub created_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
    pub severity: SeverityLevel,
    pub risk_score: u32,
    pub primary_process_key: ProcessKey,
    pub process_lineage: Vec<LineageStep>,
    pub triggered_rules: Vec<RuleFiring>,
    pub event_references: Vec<String>,
    pub policy_action: PolicyAction,
    pub response_actions: Vec<String>,
    pub status: IncidentStatus,
    pub human_summary: String,
}

pub struct IncidentManager {
    correlator: IncidentCorrelator,
    active_incidents: Arc<RwLock<HashMap<String, Incident>>>,
    storage: Option<StorageManager>,
}

impl IncidentManager {
    pub fn new(window_secs: i64, storage: Option<StorageManager>) -> Self {
        Self {
            correlator: IncidentCorrelator::new(window_secs),
            active_incidents: Arc::new(RwLock::new(HashMap::new())),
            storage,
        }
    }

    /// Record a security event firing, either creating a new incident or correlating with an existing one.
    pub fn record_threat(
        &self,
        process_key: ProcessKey,
        risk_score: u32,
        severity: SeverityLevel,
        lineage: Vec<LineageStep>,
        fired_rules: Vec<RuleFiring>,
        policy_action: PolicyAction,
        human_summary: String,
        event_id: Option<String>,
    ) -> String {
        let (incident_id, is_new) = self.correlator.correlate_or_create(&process_key, || {
            Uuid::new_v4().to_string()
        });

        let now = Utc::now();
        let mut map = self.active_incidents.write().unwrap();

        if is_new {
            let mut event_refs = Vec::new();
            if let Some(ref eid) = event_id {
                event_refs.push(eid.clone());
            }

            let incident = Incident {
                id: incident_id.clone(),
                created_at: now,
                updated_at: now,
                severity,
                risk_score,
                primary_process_key: process_key.clone(),
                process_lineage: lineage,
                triggered_rules: fired_rules,
                event_references: event_refs,
                policy_action,
                response_actions: Vec::new(),
                status: IncidentStatus::Detected,
                human_summary: human_summary.clone(),
            };

            // Queue to persistent SQLite storage
            if let Some(ref store) = self.storage {
                let details_json = serde_json::to_string(&incident).unwrap_or_default();
                store.queue_incident(StoredIncidentRecord {
                    incident_id: incident.id.clone(),
                    created_at: incident.created_at,
                    updated_at: incident.updated_at,
                    severity: format!("{:?}", incident.severity),
                    risk_score: incident.risk_score,
                    process_key: incident.primary_process_key.to_string_id(),
                    status: format!("{:?}", incident.status),
                    verdict: format!("{:?}", Verdict::High),
                    human_summary: incident.human_summary.clone(),
                    details_json,
                });

                if let Some(eid) = event_id {
                    store.link_incident_event(incident.id.clone(), eid);
                }
            }

            map.insert(incident_id.clone(), incident);
            info!("Created new EDR incident: {} (risk={})", incident_id, risk_score);
        } else if let Some(inc) = map.get_mut(&incident_id) {
            inc.updated_at = now;
            if risk_score > inc.risk_score {
                inc.risk_score = risk_score;
                inc.severity = severity;
            }
            if let Some(eid) = event_id {
                if !inc.event_references.contains(&eid) {
                    inc.event_references.push(eid.clone());
                    if let Some(ref store) = self.storage {
                        store.link_incident_event(inc.id.clone(), eid);
                    }
                }
            }
            info!("Correlated threat event into active incident {}", incident_id);
        }

        incident_id
    }

    /// Update incident status.
    pub fn update_status(&self, incident_id: &str, status: IncidentStatus) -> bool {
        let mut map = self.active_incidents.write().unwrap();
        if let Some(inc) = map.get_mut(incident_id) {
            inc.status = status;
            inc.updated_at = Utc::now();
            true
        } else {
            false
        }
    }

    /// Retrieve incident by ID.
    pub fn get(&self, incident_id: &str) -> Option<Incident> {
        let map = self.active_incidents.read().unwrap();
        map.get(incident_id).cloned()
    }

    /// Export incident as formatted JSON string.
    pub fn export_json(&self, incident_id: &str) -> Option<String> {
        let inc = self.get(incident_id)?;
        serde_json::to_string_pretty(&inc).ok()
    }

    /// List active incident IDs.
    pub fn list_ids(&self) -> Vec<String> {
        let map = self.active_incidents.read().unwrap();
        map.keys().cloned().collect()
    }
}
