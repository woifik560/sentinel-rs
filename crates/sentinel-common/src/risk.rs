//! Deterministic risk scoring engine types and classification logic.
//!
//! Implements the transparent risk engine described in ТЗ sections 3.2–3.3:
//! scoring 0..100 in < 1 ms with human-readable rule firings.

use serde::{Deserialize, Serialize};
use std::fmt;

/// Identifiers for each scoring rule in the risk engine.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum RuleId {
    /// +40: Secret accessed by a non-owner process (App Scoping violation).
    SecretNonOwner,
    /// +15: Network connection within <= 5 seconds of reading a secret.
    FastExfilBurst,
    /// +25: Binary launched from /tmp, /dev/shm, ~/Downloads, or not in dpkg.
    UntrustedBinaryOrigin,
    /// +50: Fileless execution from anonymous memory (memfd_create).
    FilelessMemfd,
    /// +20: Interpreter with inline code (-c, -e), base64/eval, or piped input.
    SuspiciousInterpreter,
    /// +10: Direct IP connection without preceding DNS query.
    RawIpConnect,
    /// -35: Binary verified in dpkg package database in legitimate context.
    TrustedPackageContext,
}

impl RuleId {
    /// Returns the default weight for this rule as defined in the ТЗ.
    pub fn default_weight(&self) -> i32 {
        match self {
            RuleId::SecretNonOwner => 40,
            RuleId::FastExfilBurst => 15,
            RuleId::UntrustedBinaryOrigin => 25,
            RuleId::FilelessMemfd => 50,
            RuleId::SuspiciousInterpreter => 20,
            RuleId::RawIpConnect => 10,
            RuleId::TrustedPackageContext => -35,
        }
    }

    /// Returns the string ID used in config and logs.
    pub fn as_str(&self) -> &'static str {
        match self {
            RuleId::SecretNonOwner => "SECRET_NON_OWNER",
            RuleId::FastExfilBurst => "FAST_EXFIL_BURST",
            RuleId::UntrustedBinaryOrigin => "UNTRUSTED_BINARY_ORIGIN",
            RuleId::FilelessMemfd => "FILELESS_MEMFD",
            RuleId::SuspiciousInterpreter => "SUSPICIOUS_INTERPRETER",
            RuleId::RawIpConnect => "RAW_IP_CONNECT",
            RuleId::TrustedPackageContext => "TRUSTED_PACKAGE_CONTEXT",
        }
    }
}

impl fmt::Display for RuleId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.as_str())
    }
}

/// A single rule firing with its weight and human-readable reason.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RuleFiring {
    pub rule_id: RuleId,
    pub weight: i32,
    pub reason: String,
}

/// Computed risk score with all contributing rule firings.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RiskScore {
    /// Total risk score, clamped to 0..100.
    pub total: u32,
    /// All rules that contributed to the score.
    pub firings: Vec<RuleFiring>,
}

impl RiskScore {
    /// Compute a risk score from a list of rule firings, clamping to 0..100.
    pub fn compute(firings: Vec<RuleFiring>) -> Self {
        let raw: i32 = firings.iter().map(|f| f.weight).sum();
        let total = raw.clamp(0, 100) as u32;
        Self { total, firings }
    }

    /// Classify this score into a verdict using the given thresholds.
    pub fn classify(&self, thresholds: &RiskThresholds) -> Verdict {
        classify(self.total, thresholds)
    }
}

/// Verdict classification tiers from the Verdict Router (ТЗ 3.3).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum Verdict {
    /// 0..39: Allow and log.
    Low,
    /// 40..74: Interactive prompt (Freeze & Inspect). Fail-Closed on timeout.
    Grey,
    /// 75..100: Immediate drop (-EPERM), SIGSTOP, alert.
    High,
}

impl fmt::Display for Verdict {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Verdict::Low => write!(f, "LOW (0..39)"),
            Verdict::Grey => write!(f, "GREY (40..74)"),
            Verdict::High => write!(f, "HIGH (75..100)"),
        }
    }
}

/// Configurable thresholds for verdict classification (ТЗ 3.3).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RiskThresholds {
    /// Maximum score for LOW verdict (inclusive). Default: 39.
    pub low_max: u32,
    /// Maximum score for GREY verdict (inclusive). Default: 74.
    pub grey_max: u32,
}

impl Default for RiskThresholds {
    fn default() -> Self {
        Self {
            low_max: 39,
            grey_max: 74,
        }
    }
}

/// Classify a risk score into a verdict tier.
pub fn classify(score: u32, thresholds: &RiskThresholds) -> Verdict {
    if score <= thresholds.low_max {
        Verdict::Low
    } else if score <= thresholds.grey_max {
        Verdict::Grey
    } else {
        Verdict::High
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_score_clamp_lower_bound() {
        let firings = vec![RuleFiring {
            rule_id: RuleId::TrustedPackageContext,
            weight: -35,
            reason: "Verified package".to_string(),
        }];
        let score = RiskScore::compute(firings);
        assert_eq!(score.total, 0);
    }

    #[test]
    fn test_score_clamp_upper_bound() {
        let firings = vec![
            RuleFiring {
                rule_id: RuleId::FilelessMemfd,
                weight: 50,
                reason: "memfd execution".to_string(),
            },
            RuleFiring {
                rule_id: RuleId::SecretNonOwner,
                weight: 40,
                reason: "SSH key access".to_string(),
            },
            RuleFiring {
                rule_id: RuleId::UntrustedBinaryOrigin,
                weight: 25,
                reason: "From /tmp".to_string(),
            },
        ];
        let score = RiskScore::compute(firings);
        assert_eq!(score.total, 100); // 115 clamped to 100
    }

    #[test]
    fn test_classify_low() {
        let thresholds = RiskThresholds::default();
        assert_eq!(classify(0, &thresholds), Verdict::Low);
        assert_eq!(classify(39, &thresholds), Verdict::Low);
    }

    #[test]
    fn test_classify_grey() {
        let thresholds = RiskThresholds::default();
        assert_eq!(classify(40, &thresholds), Verdict::Grey);
        assert_eq!(classify(74, &thresholds), Verdict::Grey);
    }

    #[test]
    fn test_classify_high() {
        let thresholds = RiskThresholds::default();
        assert_eq!(classify(75, &thresholds), Verdict::High);
        assert_eq!(classify(100, &thresholds), Verdict::High);
    }

    #[test]
    fn test_default_weights_match_spec() {
        assert_eq!(RuleId::SecretNonOwner.default_weight(), 40);
        assert_eq!(RuleId::FastExfilBurst.default_weight(), 15);
        assert_eq!(RuleId::UntrustedBinaryOrigin.default_weight(), 25);
        assert_eq!(RuleId::FilelessMemfd.default_weight(), 50);
        assert_eq!(RuleId::SuspiciousInterpreter.default_weight(), 20);
        assert_eq!(RuleId::RawIpConnect.default_weight(), 10);
        assert_eq!(RuleId::TrustedPackageContext.default_weight(), -35);
    }

    #[test]
    fn test_infoleaker_scenario() {
        // ТЗ example: python3 from /tmp reads SSH key, connects to raw IP within 5s
        let firings = vec![
            RuleFiring {
                rule_id: RuleId::SecretNonOwner,
                weight: 40,
                reason: "Доступ к SSH-ключам неуполномоченным процессом".to_string(),
            },
            RuleFiring {
                rule_id: RuleId::UntrustedBinaryOrigin,
                weight: 25,
                reason: "Скрипт запущен из /tmp".to_string(),
            },
            RuleFiring {
                rule_id: RuleId::FastExfilBurst,
                weight: 15,
                reason: "Попытка эксфильтрации в течение 5 секунд".to_string(),
            },
            RuleFiring {
                rule_id: RuleId::RawIpConnect,
                weight: 10,
                reason: "Прямое подключение по IP-адресу".to_string(),
            },
        ];
        let score = RiskScore::compute(firings);
        assert_eq!(score.total, 90);
        assert_eq!(score.classify(&RiskThresholds::default()), Verdict::High);
    }
}
