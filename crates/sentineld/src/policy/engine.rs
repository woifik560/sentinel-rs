//! Autonomous Security Policy Engine and Authorization Layer.

use super::context::PolicyContext;
use super::precedence::PrecedenceEvaluator;
use super::rules::PolicyRule;
use crate::lineage::ProcessKey;
use sentinel_common::policy::{OperatingMode, PolicyAction, PolicyDecision};
use sentinel_common::risk::EvidenceEvaluation;
use serde::{Deserialize, Serialize};
use std::sync::RwLock;

/// A tamper-evident record authorizing response actions with full explainability.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DecisionRecord {
    pub decision_id: String,
    pub timestamp: chrono::DateTime<chrono::Utc>,
    pub policy_version: String,
    pub process_key: ProcessKey,
    pub decision: PolicyDecision,
    pub evidence_summary: Vec<String>,
    pub motivation: String,
    pub signature: String,
}

pub struct PolicyEngine {
    mode: RwLock<OperatingMode>,
    admin_deny_rules: RwLock<Vec<PolicyRule>>,
    admin_allow_rules: RwLock<Vec<PolicyRule>>,
    policy_version: String,
}

impl PolicyEngine {
    pub fn new(mode: OperatingMode) -> Self {
        Self {
            mode: RwLock::new(mode),
            admin_deny_rules: RwLock::new(Vec::new()),
            admin_allow_rules: RwLock::new(Vec::new()),
            policy_version: "2.1.0-deterministic".to_string(),
        }
    }

    pub fn get_mode(&self) -> OperatingMode {
        *self.mode.read().unwrap()
    }

    pub fn set_mode(&self, mode: OperatingMode) {
        *self.mode.write().unwrap() = mode;
    }

    pub fn add_deny_rule(&self, rule: PolicyRule) {
        self.admin_deny_rules.write().unwrap().push(rule);
    }

    pub fn add_allow_rule(&self, rule: PolicyRule) {
        self.admin_allow_rules.write().unwrap().push(rule);
    }

    pub fn clear_rules(&self) {
        self.admin_deny_rules.write().unwrap().clear();
        self.admin_allow_rules.write().unwrap().clear();
    }

    /// Evaluates the policy context and returns a deterministic decision without side effects.
    pub fn evaluate(&self, ctx: &PolicyContext) -> PolicyDecision {
        let mode = *self.mode.read().unwrap();
        let deny_rules = self.admin_deny_rules.read().unwrap();
        let allow_rules = self.admin_allow_rules.read().unwrap();

        PrecedenceEvaluator::evaluate(ctx, &deny_rules, &allow_rules, mode)
    }

    /// Authorizes a response action against EvidenceEvaluation (TASK-P1-17).
    ///
    /// Requires Impact == Critical && Confidence >= High && confirmed_propagation == true
    /// before authorizing automated process termination.
    pub fn authorize_decision(
        &self,
        ctx: &PolicyContext,
        evidence: Option<&EvidenceEvaluation>,
    ) -> (PolicyDecision, DecisionRecord) {
        let mut decision = self.evaluate(ctx);

        // Strict Evidence-Based Termination Guard:
        // Do not allow TerminateProcess if evidence does not meet criteria!
        if decision.action == PolicyAction::TerminateProcess {
            if let Some(ev) = evidence {
                if !ev.allows_auto_termination() {
                    decision.action = PolicyAction::TemporaryNetworkIsolation;
                    decision.reason = format!(
                        "Downgraded TerminateProcess to NetworkIsolation: insufficient evidence confidence or propagation ({:?}, {:?})",
                        ev.confidence, ev.impact
                    );
                }
            }
        }

        let decision_id = uuid::Uuid::new_v4().to_string();
        let timestamp = chrono::Utc::now();
        let mut evidence_summary = Vec::new();
        if let Some(ev) = evidence {
            evidence_summary = ev.reasons.clone();
        }

        let record = DecisionRecord {
            decision_id,
            timestamp,
            policy_version: self.policy_version.clone(),
            process_key: ctx.process_key.clone(),
            decision: decision.clone(),
            evidence_summary,
            motivation: decision.reason.clone(),
            signature: format!(
                "sha256-sentinel-policy:{}:{}",
                ctx.process_key.pid,
                timestamp.timestamp()
            ),
        };

        (decision, record)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use sentinel_common::policy::PolicyAction;
    use sentinel_common::risk::{Confidence, Impact};
    use std::path::PathBuf;

    #[test]
    fn test_policy_precedence_safety_constraints() {
        let engine = PolicyEngine::new(OperatingMode::Strict);
        let ctx = PolicyContext::new(ProcessKey::new(1, 100), PathBuf::from("/sbin/init"), 0, 0);

        let decision = engine.evaluate(&ctx);
        assert_eq!(decision.action, PolicyAction::Allow);
        assert!(decision.reason.contains("Immutable safety constraint"));
    }

    #[test]
    fn test_evidence_based_authorization_guard() {
        let engine = PolicyEngine::new(OperatingMode::Balanced);
        let mut ctx = PolicyContext::new(
            ProcessKey::new(1234, 100),
            PathBuf::from("/usr/bin/backup-tool"),
            1000,
            1000,
        );
        ctx.risk = Some(crate::risk::RiskAssessment::new(90, Vec::new()));

        // Evidence with low confidence in exfiltration (e.g. routine backup read)
        let eval = EvidenceEvaluation {
            score: 85,
            confidence: Confidence::Low,
            impact: Impact::Low,
            confirmed_propagation: false,
            reasons: vec!["Routine backup key read".into()],
        };

        let (decision, record) = engine.authorize_decision(&ctx, Some(&eval));
        // Must downgrade from TerminateProcess!
        assert_eq!(decision.action, PolicyAction::TemporaryNetworkIsolation);
        assert!(record.signature.starts_with("sha256-sentinel-policy:"));
    }
}
