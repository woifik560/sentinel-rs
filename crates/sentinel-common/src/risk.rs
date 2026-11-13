//! Deterministic risk scoring engine types and classification logic.
//!
//! Implements the transparent risk engine described in ТЗ sections 3.2–3.3:
//! scoring 0..100 in < 1 ms with human-readable rule firings and LoLBin-hardened
//! hierarchical thresholds.

use serde::{Deserialize, Serialize};
use std::fmt;

/// Identifiers for each scoring rule in the risk engine.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum RuleId {
    /// +40: Secret accessed by a non-owner process (App Scoping violation / Taint).
    SecretNonOwner,
    /// +15: Network connection within <= 5 seconds of reading a secret.
    FastExfilBurst,
    /// +25: Binary launched from /tmp, /dev/shm, ~/Downloads, or not in dpkg.
    UntrustedBinaryOrigin,
    /// +50: Fileless execution from anonymous memory (memfd_create).
    FilelessMemfd,
    /// +35: Executable anonymous mapping or unlinked tmpfs file (mmap PROT_EXEC on i_nlink==0 or memfd dlopen).
    FilelessAnonExec,
    /// +20: Interpreter with inline code (-c, -e), base64/eval, or piped input.
    SuspiciousInterpreter,
    /// +25: Interpreter reading secrets while running via stdin pipe or inline script.
    SuspiciousScriptExecution,
    /// +10: Direct IP connection without preceding DNS query.
    RawIpConnect,
    /// +15: First-time connection to a public destination IP outside RFC1918 / loopback.
    FirstSeenDestination,
    /// +40: Binary hash mismatch against TOFU recorded SHA-256 (tampered non-dpkg binary).
    TofuTamperedBinary,
    /// +30: Taint laundering attempt via AF_UNIX or ptrace memory snooping.
    IpcTaintLaunder,
    /// -35: Binary verified in dpkg package database in legitimate context.
    /// NOTE: Disallowed if SecretNonOwner or Taint is present!
    TrustedPackageContext,
}

impl RuleId {
    /// Returns the default weight for this rule.
    pub fn default_weight(&self) -> i32 {
        match self {
            RuleId::SecretNonOwner => 40,
            RuleId::FastExfilBurst => 15,
            RuleId::UntrustedBinaryOrigin => 25,
            RuleId::FilelessMemfd => 50,
            RuleId::FilelessAnonExec => 35,
            RuleId::SuspiciousInterpreter => 20,
            RuleId::SuspiciousScriptExecution => 25,
            RuleId::RawIpConnect => 10,
            RuleId::FirstSeenDestination => 15,
            RuleId::TofuTamperedBinary => 40,
            RuleId::IpcTaintLaunder => 30,
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
            RuleId::FilelessAnonExec => "FILELESS_ANON_EXEC",
            RuleId::SuspiciousInterpreter => "SUSPICIOUS_INTERPRETER",
            RuleId::SuspiciousScriptExecution => "SUSPICIOUS_SCRIPT_EXECUTION",
            RuleId::RawIpConnect => "RAW_IP_CONNECT",
            RuleId::FirstSeenDestination => "FIRST_SEEN_DESTINATION",
            RuleId::TofuTamperedBinary => "TOFU_TAMPERED_BINARY",
            RuleId::IpcTaintLaunder => "IPC_TAINT_LAUNDER",
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
    /// Total risk score, clamped to 0..100 with non-negotiable floor for tainted secrets.
    pub total: u32,
    /// All rules that contributed to the score.
    pub firings: Vec<RuleFiring>,
}

impl RiskScore {
    /// Compute a risk score from a list of rule firings, enforcing hierarchical rules:
    /// 1. If `SecretNonOwner` is fired, `TrustedPackageContext` (-35) discount is invalidated.
    /// 2. If `SecretNonOwner` is fired, minimum score floor is 40 (GREY zone minimum).
    pub fn compute(mut firings: Vec<RuleFiring>) -> Self {
        let has_secret = firings.iter().any(|f| f.rule_id == RuleId::SecretNonOwner);

        // Hierarchical rule 1: Do not permit dpkg trust discount if non-owner accessed secret
        if has_secret {
            firings.retain(|f| f.rule_id != RuleId::TrustedPackageContext);
        }

        let raw: i32 = firings.iter().map(|f| f.weight).sum();
        let mut total = raw.clamp(0, 100) as u32;

        // Hierarchical rule 2: Floor at GREY zone (40) when reading secret and attempting network
        if has_secret && total < 40 {
            total = 40;
        }

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
    /// 40..74: Interactive prompt (Freeze & Inspect via NFQUEUE / SO_MARK). Fail-Closed on timeout.
    Grey,
    /// 75..100: Immediate drop (-EPERM / NF_DROP), optional SIGSTOP/SIGKILL, alert.
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
        assert_eq!(score.total, 100);
    }

    #[test]
    fn test_lolbin_discount_prevention() {
        // Test that curl/git (trusted dpkg package) reading a secret CANNOT get -35 discount
        let firings = vec![
            RuleFiring {
                rule_id: RuleId::SecretNonOwner,
                weight: 40,
                reason: "SSH private key read".to_string(),
            },
            RuleFiring {
                rule_id: RuleId::TrustedPackageContext,
                weight: -35,
                reason: "dpkg verified curl binary".to_string(),
            },
        ];
        let score = RiskScore::compute(firings);
        // Discount MUST be stripped; score must remain >= 40 (GREY)
        assert_eq!(score.total, 40);
        assert_eq!(score.classify(&RiskThresholds::default()), Verdict::Grey);
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
}
