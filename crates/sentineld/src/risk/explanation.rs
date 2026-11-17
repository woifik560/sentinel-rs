//! Risk score explanations for security operators and telemetry.

use super::evidence::RiskEvidence;
use serde::{Deserialize, Serialize};
use sentinel_common::risk::SeverityLevel;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RiskAssessment {
    pub score: u32,
    pub severity: SeverityLevel,
    pub primary_reason: String,
    pub explanations: Vec<String>,
    pub evidences: Vec<RiskEvidence>,
}

impl RiskAssessment {
    pub fn new(score: u32, evidences: Vec<RiskEvidence>) -> Self {
        let severity = SeverityLevel::from_score(score);
        let mut explanations = Vec::new();

        for ev in &evidences {
            let desc = if ev.count > 1 {
                format!("[+{}] {} (repeated {}x)", ev.weight, ev.reason, ev.count)
            } else {
                format!("[+{}] {}", ev.weight, ev.reason)
            };
            explanations.push(desc);
        }

        let primary_reason = evidences
            .iter()
            .max_by_key(|e| e.weight)
            .map(|e| e.reason.clone())
            .unwrap_or_else(|| "No risk indicators detected".to_string());

        Self {
            score,
            severity,
            primary_reason,
            explanations,
            evidences,
        }
    }

    pub fn to_summary(&self) -> String {
        format!(
            "Risk Score: {}/100 [{:?}]. Primary Factor: {}. Total Signals: {}",
            self.score,
            self.severity,
            self.primary_reason,
            self.evidences.len()
        )
    }
}
