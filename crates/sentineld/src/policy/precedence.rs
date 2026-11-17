//! Strict policy precedence evaluation.
//!
//! Enforces the deterministic decision hierarchy:
//! 1. Immutable Safety Constraints (sentineld, PID 1, kernel threads)
//! 2. Protected System Resources (/etc/sentinel, BPF maps, systemd units)
//! 3. Explicit Admin Deny Rules
//! 4. Explicit Admin Allow Rules
//! 5. Behavior Detection Rule Actions
//! 6. Risk-based Defaults by Operating Mode

use sentinel_common::policy::{OperatingMode, PolicyAction, PolicyDecision};
use sentinel_common::risk::SeverityLevel;
use super::context::PolicyContext;
use super::rules::PolicyRule;

pub struct PrecedenceEvaluator;

impl PrecedenceEvaluator {
    /// Evaluates a security event context through the strict 6-stage precedence hierarchy.
    pub fn evaluate(
        ctx: &PolicyContext,
        admin_deny_rules: &[PolicyRule],
        admin_allow_rules: &[PolicyRule],
        mode: OperatingMode,
    ) -> PolicyDecision {
        let pid = ctx.process_key.pid;
        let process_key_str = ctx.process_key.to_string_id();
        let risk_score = ctx.risk.as_ref().map(|r| r.score).unwrap_or(0);
        let severity = ctx.risk.as_ref().map(|r| r.severity).unwrap_or(SeverityLevel::Low);

        // 1. IMMUTABLE SAFETY CONSTRAINTS
        if pid <= 2 {
            let mut decision = PolicyDecision::new(
                pid,
                process_key_str,
                PolicyAction::Allow,
                0,
                SeverityLevel::Low,
                format!("Immutable safety constraint: System critical process (PID {})", pid),
            );
            decision.rule_id = Some("SAFETY_CRITICAL_PID".into());
            return decision;
        }

        let exe_str = ctx.exe_path.to_string_lossy();
        if exe_str.ends_with("/sentineld") || exe_str.ends_with("/sntctl") {
            let mut decision = PolicyDecision::new(
                pid,
                process_key_str,
                PolicyAction::Allow,
                0,
                SeverityLevel::Low,
                "Immutable safety constraint: Sentinel security agent process".into(),
            );
            decision.rule_id = Some("SAFETY_AGENT_SELF".into());
            return decision;
        }

        // 2. PROTECTED SYSTEM RESOURCES
        if exe_str.starts_with("/etc/sentinel") || exe_str.starts_with("/run/sentinel") {
            if ctx.uid != 0 {
                let mut decision = PolicyDecision::new(
                    pid,
                    process_key_str,
                    PolicyAction::Deny,
                    90,
                    SeverityLevel::Critical,
                    "Protected system resource: Non-root access to sentinel internal paths".into(),
                );
                decision.rule_id = Some("PROTECTED_SYSTEM_RESOURCE".into());
                return decision;
            }
        }

        let behavior_ids: Vec<String> = ctx.behavior_matches.iter().map(|m| m.rule_id.clone()).collect();

        // 3. EXPLICIT ADMIN DENY RULES
        for rule in admin_deny_rules {
            if rule.matches(
                &ctx.exe_path,
                &ctx.cmdline,
                ctx.uid,
                ctx.exe_sha256.as_deref(),
                ctx.dest_port,
                ctx.dest_domain.as_deref(),
                risk_score,
                &behavior_ids,
            ) {
                let mut decision = PolicyDecision::new(
                    pid,
                    process_key_str,
                    rule.action,
                    risk_score,
                    severity,
                    format!("Explicit Admin Deny: {}", rule.name),
                );
                decision.policy_id = Some(rule.id.clone());
                return decision;
            }
        }

        // 4. EXPLICIT ADMIN ALLOW RULES
        for rule in admin_allow_rules {
            if rule.matches(
                &ctx.exe_path,
                &ctx.cmdline,
                ctx.uid,
                ctx.exe_sha256.as_deref(),
                ctx.dest_port,
                ctx.dest_domain.as_deref(),
                risk_score,
                &behavior_ids,
            ) {
                let mut decision = PolicyDecision::new(
                    pid,
                    process_key_str,
                    rule.action,
                    risk_score,
                    severity,
                    format!("Explicit Admin Allow: {}", rule.name),
                );
                decision.policy_id = Some(rule.id.clone());
                return decision;
            }
        }

        // 5. BEHAVIOR DETECTION RULE ACTIONS
        for m in &ctx.behavior_matches {
            if m.action == PolicyAction::TerminateProcess
                || m.action == PolicyAction::Deny
                || m.action == PolicyAction::DenyNetwork
                || m.action == PolicyAction::TemporaryNetworkIsolation
            {
                let mut decision = PolicyDecision::new(
                    pid,
                    process_key_str,
                    m.action,
                    risk_score,
                    severity,
                    format!("Behavior rule fired: {} ({})", m.rule_name, m.reason),
                );
                decision.rule_id = Some(m.rule_id.clone());
                return decision;
            }
        }

        // 6. DEFAULT RISK-BASED POLICY ACTIONS BY OPERATING MODE
        match mode {
            OperatingMode::Audit => {
                let action = if risk_score >= 40 {
                    PolicyAction::Monitor
                } else {
                    PolicyAction::Allow
                };
                let mut decision = PolicyDecision::new(
                    pid,
                    process_key_str,
                    action,
                    risk_score,
                    severity,
                    format!("Audit mode: risk score {}", risk_score),
                );
                decision.rule_id = Some("MODE_AUDIT_DEFAULT".into());
                decision
            }
            OperatingMode::Balanced => {
                let action = if risk_score >= 80 {
                    PolicyAction::TerminateProcess
                } else if risk_score >= 60 {
                    PolicyAction::DenyNetwork
                } else if risk_score >= 40 {
                    PolicyAction::TemporaryNetworkIsolation
                } else if risk_score >= 20 {
                    PolicyAction::Monitor
                } else {
                    PolicyAction::Allow
                };
                let mut decision = PolicyDecision::new(
                    pid,
                    process_key_str,
                    action,
                    risk_score,
                    severity,
                    format!("Balanced mode: risk score {}", risk_score),
                );
                decision.rule_id = Some("MODE_BALANCED_DEFAULT".into());
                decision
            }
            OperatingMode::Strict => {
                let action = if risk_score >= 50 {
                    PolicyAction::TerminateProcess
                } else if risk_score >= 30 {
                    PolicyAction::DenyNetwork
                } else if risk_score >= 15 {
                    PolicyAction::TemporaryNetworkIsolation
                } else {
                    PolicyAction::Allow
                };
                let mut decision = PolicyDecision::new(
                    pid,
                    process_key_str,
                    action,
                    risk_score,
                    severity,
                    format!("Strict zero-trust mode: risk score {}", risk_score),
                );
                decision.rule_id = Some("MODE_STRICT_DEFAULT".into());
                decision
            }
            OperatingMode::Custom => {
                let action = if risk_score >= 80 {
                    PolicyAction::TerminateProcess
                } else if risk_score >= 50 {
                    PolicyAction::DenyNetwork
                } else {
                    PolicyAction::Allow
                };
                let mut decision = PolicyDecision::new(
                    pid,
                    process_key_str,
                    action,
                    risk_score,
                    severity,
                    format!("Custom mode fallback: risk score {}", risk_score),
                );
                decision.rule_id = Some("MODE_CUSTOM_FALLBACK".into());
                decision
            }
        }
    }
}
