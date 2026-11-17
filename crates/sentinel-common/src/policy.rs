//! Autonomous policy definitions, precedence rules, and decision models.
//!
//! Replaces interactive prompts with deterministic autonomous decisions
//! matching the requirements of Part 10.

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use uuid::Uuid;

use crate::risk::SeverityLevel;

/// Autonomous policy actions enforceable by Sentinel-RS.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum PolicyAction {
    /// Allow the operation with no restrictions.
    Allow,
    /// Record the decision in audit log, without active blocking.
    Audit,
    /// Monitor the process/flow closely with increased telemetry.
    Monitor,
    /// Deny the operation at the kernel hook level.
    Deny,
    /// Drop or reject network connection attempt.
    DenyNetwork,
    /// Terminate the violating process (SIGKILL / SIGTERM) after identity verification.
    TerminateProcess,
    /// Temporarily isolate host or process networking.
    TemporaryNetworkIsolation,
}

impl PolicyAction {
    pub fn is_blocking(&self) -> bool {
        matches!(
            self,
            PolicyAction::Deny
                | PolicyAction::DenyNetwork
                | PolicyAction::TerminateProcess
                | PolicyAction::TemporaryNetworkIsolation
        )
    }

    pub fn as_str(&self) -> &'static str {
        match self {
            PolicyAction::Allow => "ALLOW",
            PolicyAction::Audit => "AUDIT",
            PolicyAction::Monitor => "MONITOR",
            PolicyAction::Deny => "DENY",
            PolicyAction::DenyNetwork => "DENY_NETWORK",
            PolicyAction::TerminateProcess => "TERMINATE_PROCESS",
            PolicyAction::TemporaryNetworkIsolation => "TEMPORARY_NETWORK_ISOLATION",
        }
    }
}

impl std::fmt::Display for PolicyAction {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.as_str())
    }
}

/// Agent operational modes for policy enforcement.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum OperatingMode {
    /// Observe and log decisions without enforcing userspace actions.
    Audit,
    /// Balanced protection: prevent high-confidence threats, monitor uncertain behavior.
    Balanced,
    /// Strict protection: aggressive configured prevention while preserving essential OS functionality.
    Strict,
    /// Administrator-defined policies.
    Custom,
}

impl Default for OperatingMode {
    fn default() -> Self {
        OperatingMode::Audit
    }
}

impl std::fmt::Display for OperatingMode {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            OperatingMode::Audit => write!(f, "AUDIT"),
            OperatingMode::Balanced => write!(f, "BALANCED"),
            OperatingMode::Strict => write!(f, "STRICT"),
            OperatingMode::Custom => write!(f, "CUSTOM"),
        }
    }
}

impl std::str::FromStr for OperatingMode {
    type Err = String;
    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s.to_ascii_uppercase().as_str() {
            "AUDIT" => Ok(OperatingMode::Audit),
            "BALANCED" => Ok(OperatingMode::Balanced),
            "STRICT" => Ok(OperatingMode::Strict),
            "CUSTOM" => Ok(OperatingMode::Custom),
            other => Err(format!("Unknown operating mode: {}", other)),
        }
    }
}

/// Deterministic policy decision record.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PolicyDecision {
    /// Unique decision ID (UUID v4).
    pub decision_id: String,
    /// Associated raw or normalized event ID.
    pub event_id: Option<String>,
    /// Target process PID / TGID.
    pub tgid: u32,
    /// Canonical process key (PID + start_time).
    pub process_key: String,
    /// Matched policy identifier.
    pub policy_id: Option<String>,
    /// Matched behavior rule identifier.
    pub rule_id: Option<String>,
    /// Total computed risk score (0..100).
    pub risk_score: u32,
    /// Severity classification.
    pub severity: SeverityLevel,
    /// Human-readable reasoning for the decision.
    pub reason: String,
    /// UTC timestamp of the decision.
    pub timestamp: DateTime<Utc>,
    /// Final chosen action.
    pub action: PolicyAction,
    /// Decision confidence (0.0 .. 1.0).
    pub confidence: f32,
}

impl PolicyDecision {
    pub fn new(
        tgid: u32,
        process_key: String,
        action: PolicyAction,
        risk_score: u32,
        severity: SeverityLevel,
        reason: String,
    ) -> Self {
        Self {
            decision_id: Uuid::new_v4().to_string(),
            event_id: None,
            tgid,
            process_key,
            policy_id: None,
            rule_id: None,
            risk_score,
            severity,
            reason,
            timestamp: Utc::now(),
            action,
            confidence: 1.0,
        }
    }
}
