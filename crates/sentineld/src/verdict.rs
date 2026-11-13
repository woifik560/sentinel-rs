//! Verdict Router for classifying and routing incident responses.

use tracing::{error, info, warn};

use sentinel_common::config::RulesConfig;
use sentinel_common::risk::{RiskScore, Verdict};

pub struct VerdictRouter {
    rules_config: RulesConfig,
}

impl VerdictRouter {
    pub fn new(rules_config: RulesConfig) -> Self {
        Self { rules_config }
    }

    /// Route and determine the action for a given risk score.
    pub fn route(&self, score: &RiskScore) -> Verdict {
        let verdict = score.classify(&self.rules_config.thresholds);
        match &verdict {
            Verdict::Low => {
                info!("Verdict LOW (score: {}): Allowed to connect", score.total);
            }
            Verdict::Grey => {
                warn!(
                    "Verdict GREY (score: {}): Routing to Interactive Prompt (Freeze & Inspect)",
                    score.total
                );
            }
            Verdict::High => {
                error!(
                    "Verdict HIGH (score: {}): Immediate kernel drop & SIGSTOP",
                    score.total
                );
            }
        }
        verdict
    }
}
