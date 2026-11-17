//! Central response action orchestrator.

use chrono::Utc;
use std::sync::Arc;
use std::time::Duration;
use tracing::{error, info, warn};
use sentinel_common::policy::{PolicyAction, PolicyDecision};
use crate::policy::PolicyContext;
use crate::storage::{StorageManager, StoredResponseRecord};
use super::network_block::NetworkBlockManager;
use super::process_term::safe_terminate_process;

pub struct ResponseOrchestrator {
    storage: Arc<StorageManager>,
    network_blocks: Arc<NetworkBlockManager>,
}

impl ResponseOrchestrator {
    pub fn new(storage: Arc<StorageManager>, network_blocks: Arc<NetworkBlockManager>) -> Self {
        Self {
            storage,
            network_blocks,
        }
    }

    /// Executes the required policy action against the target process context.
    pub fn execute_action(
        &self,
        decision: &PolicyDecision,
        ctx: &PolicyContext,
        incident_id: Option<String>,
    ) -> String {
        let action_id = uuid::Uuid::new_v4().to_string();
        let target_pid = ctx.process_key.pid;
        let mut status = "SUCCESS".to_string();
        let mut err_msg = None;

        info!(
            "Executing response action {:?} for PID {} (Reason: {})",
            decision.action, target_pid, decision.reason
        );

        match decision.action {
            PolicyAction::Allow => {
                // No defensive intervention required
            }
            PolicyAction::Audit => {
                // Log and record only
            }
            PolicyAction::Monitor => {
                warn!("MONITOR [PID {}]: {}", target_pid, decision.reason);
            }
            PolicyAction::TemporaryNetworkIsolation => {
                self.network_blocks.block_pid(target_pid);
                info!("Isolated network for PID {}", target_pid);
            }
            PolicyAction::Deny | PolicyAction::DenyNetwork => {
                self.network_blocks.block_pid(target_pid);
                if let Some(ref ip) = ctx.dest_ip {
                    self.network_blocks.block_ip(ip.clone());
                }
            }
            PolicyAction::TerminateProcess => {
                if let Err(e) = safe_terminate_process(
                    &ctx.process_key,
                    Some(&ctx.exe_path),
                    Duration::from_millis(500),
                ) {
                    error!("Failed to terminate PID {}: {}", target_pid, e);
                    status = "FAILED".to_string();
                    err_msg = Some(e.to_string());
                }
            }
        }

        // Persist audit record of response action to SQLite
        let record = StoredResponseRecord {
            action_id,
            timestamp: Utc::now(),
            incident_id,
            process_key: ctx.process_key.to_string_id(),
            action_type: decision.action.as_str().to_string(),
            status: status.clone(),
            details_json: serde_json::json!({
                "reason": decision.reason,
                "rule_matched": decision.rule_id,
                "exe_path": ctx.exe_path.to_string_lossy(),
                "error": err_msg,
            })
            .to_string(),
        };

        self.storage.enqueue_response(record);
        status
    }
}
