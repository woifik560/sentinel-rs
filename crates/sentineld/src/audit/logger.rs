//! Security Audit Logger.

use std::sync::Arc;
use tracing::info;
use crate::storage::StorageManager;
use super::events::{AuditCategory, AuditRecord};

pub struct AuditLogger {
    #[allow(dead_code)]
    storage: Arc<StorageManager>,
}

impl AuditLogger {
    pub fn new(storage: Arc<StorageManager>) -> Self {
        Self { storage }
    }

    pub fn storage(&self) -> &Arc<StorageManager> {
        &self.storage
    }

    pub fn log(
        &self,
        category: AuditCategory,
        operator: Option<(u32, u32)>,
        target_pid: Option<u32>,
        action: &str,
        summary: &str,
        metadata: serde_json::Value,
    ) {
        let audit_id = uuid::Uuid::new_v4().to_string();
        let timestamp_ns = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_nanos() as u64)
            .unwrap_or(0);

        let (operator_uid, operator_gid) = operator.map(|(u, g)| (Some(u), Some(g))).unwrap_or((None, None));

        info!(
            target: "sentinel_audit",
            "AUDIT [{:?}] Action: {}, Target: {:?}, Operator: {:?}/{:?}, Summary: {}",
            category, action, target_pid, operator_uid, operator_gid, summary
        );

        let _record = AuditRecord {
            audit_id,
            timestamp_ns,
            category,
            operator_uid,
            operator_gid,
            target_pid,
            action: action.to_string(),
            summary: summary.to_string(),
            metadata_json: metadata.to_string(),
        };

        // Note: For high performance, audit records can be saved in SQLite policy_audit/history tables
    }
}
