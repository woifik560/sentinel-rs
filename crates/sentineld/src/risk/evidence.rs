//! Evidence models and aggregation for the Risk Engine.

use sentinel_common::risk::RuleFiring;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;

/// Attack stage categorization aligned with MITRE ATT&CK.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum AttackStage {
    InitialAccess,
    Execution,
    Persistence,
    PrivilegeEscalation,
    DefenseEvasion,
    CredentialAccess,
    Discovery,
    LateralMovement,
    Collection,
    CommandAndControl,
    Exfiltration,
    Impact,
}

/// A structured piece of evidence contributing to risk.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RiskEvidence {
    pub rule_id: String,
    pub weight: i32,
    pub reason: String,
    pub timestamp_ns: u64,
    pub stage: AttackStage,
    pub count: u32,
}

/// Deduplicates and aggregates evidence items within a sliding temporal window.
#[derive(Debug, Clone, Default)]
pub struct EvidenceAggregator {
    evidences: HashMap<String, RiskEvidence>,
}

impl EvidenceAggregator {
    pub fn new() -> Self {
        Self {
            evidences: HashMap::new(),
        }
    }

    /// Add a rule firing to the aggregator with deduplication.
    pub fn add_firing(&mut self, firing: &RuleFiring, stage: AttackStage, now_ns: u64) {
        let key = firing.rule_id.as_str().to_string();
        if let Some(existing) = self.evidences.get_mut(&key) {
            existing.count += 1;
            existing.timestamp_ns = now_ns;
            // Cap repeat weight contribution (diminishing returns)
            if existing.count <= 3 {
                existing.weight = (existing.weight + (firing.weight / 2)).clamp(0, 100);
            }
        } else {
            self.evidences.insert(
                key,
                RiskEvidence {
                    rule_id: firing.rule_id.as_str().to_string(),
                    weight: firing.weight,
                    reason: firing.reason.clone(),
                    timestamp_ns: now_ns,
                    stage,
                    count: 1,
                },
            );
        }
    }

    /// Calculate aggregate score and compounding multi-stage multiplier.
    pub fn calculate_aggregate(&self) -> (u32, Vec<RiskEvidence>) {
        if self.evidences.is_empty() {
            return (0, Vec::new());
        }

        let mut base_score: i32 = 0;
        let mut stages = std::collections::HashSet::new();
        let mut evidence_list = Vec::with_capacity(self.evidences.len());

        for ev in self.evidences.values() {
            base_score = base_score.saturating_add(ev.weight);
            stages.insert(ev.stage);
            evidence_list.push(ev.clone());
        }

        let positive_base = base_score.max(0) as f64;

        // Compounding weight if multiple attack stages are observed together
        // e.g. CredentialAccess + LateralMovement + Exfiltration
        let stage_multiplier = match stages.len() {
            0 | 1 => 1.0,
            2 => 1.15,
            3 => 1.30,
            _ => 1.50,
        };

        let final_score = (positive_base * stage_multiplier).round() as u32;
        (final_score.min(100), evidence_list)
    }

    pub fn is_empty(&self) -> bool {
        self.evidences.is_empty()
    }
}
