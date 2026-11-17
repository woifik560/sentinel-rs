//! Autonomous Security Policy Engine.

use std::sync::RwLock;
use sentinel_common::policy::{OperatingMode, PolicyDecision};
use super::context::PolicyContext;
use super::precedence::PrecedenceEvaluator;
use super::rules::PolicyRule;

pub struct PolicyEngine {
    mode: RwLock<OperatingMode>,
    admin_deny_rules: RwLock<Vec<PolicyRule>>,
    admin_allow_rules: RwLock<Vec<PolicyRule>>,
}

impl PolicyEngine {
    pub fn new(mode: OperatingMode) -> Self {
        Self {
            mode: RwLock::new(mode),
            admin_deny_rules: RwLock::new(Vec::new()),
            admin_allow_rules: RwLock::new(Vec::new()),
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

    /// Evaluates the policy context and returns a deterministic decision.
    pub fn evaluate(&self, ctx: &PolicyContext) -> PolicyDecision {
        let mode = *self.mode.read().unwrap();
        let deny_rules = self.admin_deny_rules.read().unwrap();
        let allow_rules = self.admin_allow_rules.read().unwrap();

        PrecedenceEvaluator::evaluate(ctx, &deny_rules, &allow_rules, mode)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::path::PathBuf;
    use sentinel_common::policy::PolicyAction;
    use crate::lineage::ProcessKey;

    #[test]
    fn test_policy_precedence_safety_constraints() {
        let engine = PolicyEngine::new(OperatingMode::Strict);
        let ctx = PolicyContext::new(ProcessKey::new(1, 100), PathBuf::from("/sbin/init"), 0, 0);

        let decision = engine.evaluate(&ctx);
        assert_eq!(decision.action, PolicyAction::Allow);
        assert!(decision.reason.contains("Immutable safety constraint"));
    }

    #[test]
    fn test_policy_modes() {
        let engine = PolicyEngine::new(OperatingMode::Audit);
        let mut ctx = PolicyContext::new(ProcessKey::new(1234, 100), PathBuf::from("/tmp/malware"), 1000, 1000);
        ctx.risk = Some(crate::risk::RiskAssessment::new(90, Vec::new()));

        let decision = engine.evaluate(&ctx);
        // In Audit mode, should never TerminateProcess or Deny
        assert_eq!(decision.action, PolicyAction::Monitor);

        engine.set_mode(OperatingMode::Balanced);
        let decision = engine.evaluate(&ctx);
        assert_eq!(decision.action, PolicyAction::TerminateProcess);
    }
}
