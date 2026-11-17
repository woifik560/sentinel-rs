//! Verdict Router for classifying and routing autonomous policy actions.
//!
//! Replaces interactive prompts with deterministic autonomous policy decisions
//! matching Part 4.3 and Part 10 of the specification.

use tracing::{error, info, warn};

use sentinel_common::config::RulesConfig;
use sentinel_common::policy::{OperatingMode, PolicyAction};
use sentinel_common::risk::{RiskScore, Verdict};

pub struct VerdictRouter {
    rules_config: RulesConfig,
}

impl VerdictRouter {
    pub fn new(rules_config: RulesConfig) -> Self {
        Self { rules_config }
    }

    /// Route and determine the autonomous policy action for a given risk score and operating mode.
    pub fn route_autonomous(&self, score: &RiskScore, mode: OperatingMode) -> PolicyAction {
        let verdict = self.route(score);
        match mode {
            OperatingMode::Audit => {
                info!("Autonomous policy AUDIT mode: score {} recorded for audit", score.total);
                PolicyAction::Audit
            }
            OperatingMode::Balanced => {
                match verdict {
                    Verdict::Low => PolicyAction::Allow,
                    Verdict::Grey => {
                        warn!("Autonomous policy BALANCED mode: score {} monitored without prompt", score.total);
                        PolicyAction::Monitor
                    }
                    Verdict::High => {
                        error!("Autonomous policy BALANCED mode: score {} denied network", score.total);
                        PolicyAction::DenyNetwork
                    }
                }
            }
            OperatingMode::Strict => {
                match verdict {
                    Verdict::Low => PolicyAction::Allow,
                    Verdict::Grey => {
                        warn!("Autonomous policy STRICT mode: score {} denied network", score.total);
                        PolicyAction::DenyNetwork
                    }
                    Verdict::High => {
                        error!("Autonomous policy STRICT mode: high risk {} denied network", score.total);
                        PolicyAction::DenyNetwork
                    }
                }
            }
            OperatingMode::Custom => {
                match verdict {
                    Verdict::Low => PolicyAction::Allow,
                    Verdict::Grey => PolicyAction::Monitor,
                    Verdict::High => PolicyAction::DenyNetwork,
                }
            }
        }
    }

    /// Route and determine the classification for a given risk score (backward compatible).
    pub fn route(&self, score: &RiskScore) -> Verdict {
        let verdict = score.classify(&self.rules_config.thresholds);
        match &verdict {
            Verdict::Low => {
                info!("Verdict LOW (score: {}): Clean / Allowed", score.total);
            }
            Verdict::Grey => {
                warn!(
                    "Verdict GREY (score: {}): Autonomous Monitor / Inspection",
                    score.total
                );
            }
            Verdict::High => {
                error!(
                    "Verdict HIGH (score: {}): High-risk threat detected",
                    score.total
                );
            }
        }
        verdict
    }
}
