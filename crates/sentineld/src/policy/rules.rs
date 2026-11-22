//! Policy rule definitions and match conditions.

use sentinel_common::policy::PolicyAction;
use serde::{Deserialize, Serialize};
use std::path::Path;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum RuleCondition {
    PathEquals(String),
    PathPrefix(String),
    CmdlineContains(String),
    UidEquals(u32),
    Sha256Equals(String),
    DestPortEquals(u16),
    DestDomainMatches(String),
    RiskScoreAbove(u32),
    BehaviorRuleFired(String),
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PolicyRule {
    pub id: String,
    pub name: String,
    pub description: String,
    pub conditions: Vec<RuleCondition>,
    pub action: PolicyAction,
    pub is_enabled: bool,
}

impl PolicyRule {
    #[allow(clippy::too_many_arguments)]
    pub fn matches(
        &self,
        exe_path: &Path,
        cmdline: &[String],
        uid: u32,
        sha256: Option<&str>,
        dest_port: Option<u16>,
        dest_domain: Option<&str>,
        risk_score: u32,
        behavior_rules: &[String],
    ) -> bool {
        if !self.is_enabled {
            return false;
        }

        let path_str = exe_path.to_string_lossy();
        let cmd_joined = cmdline.join(" ");

        for cond in &self.conditions {
            match cond {
                RuleCondition::PathEquals(p) => {
                    if path_str != *p {
                        return false;
                    }
                }
                RuleCondition::PathPrefix(prefix) => {
                    if !path_str.starts_with(prefix) {
                        return false;
                    }
                }
                RuleCondition::CmdlineContains(substr) => {
                    if !cmd_joined.contains(substr) {
                        return false;
                    }
                }
                RuleCondition::UidEquals(u) => {
                    if uid != *u {
                        return false;
                    }
                }
                RuleCondition::Sha256Equals(expected) => {
                    if let Some(actual) = sha256 {
                        if !actual.eq_ignore_ascii_case(expected) {
                            return false;
                        }
                    } else {
                        return false;
                    }
                }
                RuleCondition::DestPortEquals(port) => {
                    if dest_port != Some(*port) {
                        return false;
                    }
                }
                RuleCondition::DestDomainMatches(pattern) => {
                    if let Some(domain) = dest_domain {
                        if domain != pattern
                            && !domain.ends_with(&format!(".{}", pattern))
                            && pattern != "*"
                        {
                            return false;
                        }
                    } else {
                        return false;
                    }
                }
                RuleCondition::RiskScoreAbove(threshold) => {
                    if risk_score <= *threshold {
                        return false;
                    }
                }
                RuleCondition::BehaviorRuleFired(rule_id) => {
                    if !behavior_rules.iter().any(|r| r == rule_id) {
                        return false;
                    }
                }
            }
        }

        true
    }
}
