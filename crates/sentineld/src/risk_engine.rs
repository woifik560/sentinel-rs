//! Transparent Deterministic Risk Engine.
//!
//! Evaluates network and execution events in < 1 ms without external dependencies
//! or LLMs, applying deterministic rule weights clamped to 0..100.

use tracing::debug;

use sentinel_common::config::RulesConfig;
use sentinel_common::process::ProcessNode;
use sentinel_common::risk::{RiskScore, RuleFiring, RuleId};
use crate::lineage::inspect_interpreter;
use crate::pkg_check::DpkgChecker;

/// Context of the network connection event being evaluated.
#[derive(Debug, Clone)]
pub struct NetworkContext {
    pub dest_ip: Option<String>,
    pub dest_port: u16,
    pub has_dns_record: bool,
    pub current_time_ns: u64,
}

pub struct RiskEngine {
    rules_config: RulesConfig,
    dpkg_checker: DpkgChecker,
}

impl RiskEngine {
    pub fn new(rules_config: RulesConfig, dpkg_checker: DpkgChecker) -> Self {
        Self {
            rules_config,
            dpkg_checker,
        }
    }

    /// Evaluates the risk score of a process attempting a network connection.
    ///
    /// Executes in < 1 ms and returns clamped 0..100 `RiskScore`.
    pub fn evaluate(&self, node: &ProcessNode, net: &NetworkContext) -> RiskScore {
        let mut firings = Vec::new();

        // 1. [+50] FILELESS_MEMFD
        if node.is_memfd {
            let weight = self.get_weight(RuleId::FilelessMemfd.as_str(), 50);
            firings.push(RuleFiring {
                rule_id: RuleId::FilelessMemfd,
                weight,
                reason: "Бесфайловое исполнение кода из памяти (memfd_create)".to_string(),
            });
        }

        // 2. [+40] SECRET_NON_OWNER
        let has_secret = !node.secret_accesses.is_empty();
        if has_secret {
            let weight = self.get_weight(RuleId::SecretNonOwner.as_str(), 40);
            firings.push(RuleFiring {
                rule_id: RuleId::SecretNonOwner,
                weight,
                reason: "Чтение защищенного секрета процессом вне App Scope".to_string(),
            });
        }

        // 3. [+15] FAST_EXFIL_BURST (<= 5 seconds after secret read)
        if let Some(last_secret) = node.secret_accesses.last() {
            let delta_ns = net.current_time_ns.saturating_sub(last_secret.timestamp_ns);
            let delta_secs = delta_ns as f64 / 1_000_000_000.0;
            if delta_secs <= 5.0 {
                let weight = self.get_weight(RuleId::FastExfilBurst.as_str(), 15);
                firings.push(RuleFiring {
                    rule_id: RuleId::FastExfilBurst,
                    weight,
                    reason: format!(
                        "Попытка сетевого подключения в течение {:.2} сек после чтения секрета",
                        delta_secs
                    ),
                });
            }
        }

        // 4. [+25] UNTRUSTED_BINARY_ORIGIN
        let target_path = node.script_path.as_deref().unwrap_or(&node.exe_path);
        let path_str = target_path.to_string_lossy();
        let is_untrusted_dir = path_str.starts_with("/tmp")
            || path_str.starts_with("/dev/shm")
            || path_str.contains("/Downloads/")
            || path_str.starts_with("/var/tmp");

        let pkg_owned = self.dpkg_checker.check_package(&node.exe_path).is_some();

        if is_untrusted_dir || (!pkg_owned && !node.is_interpreter()) {
            let weight = self.get_weight(RuleId::UntrustedBinaryOrigin.as_str(), 25);
            firings.push(RuleFiring {
                rule_id: RuleId::UntrustedBinaryOrigin,
                weight,
                reason: format!("Исполняемый файл/скрипт запущен из ненадежного пути: {}", path_str),
            });
        }

        // 5. [+20] SUSPICIOUS_INTERPRETER
        if let Some(info) = inspect_interpreter(&node.exe_path, &node.cmdline) {
            if info.is_inline || info.is_suspicious_flags {
                let weight = self.get_weight(RuleId::SuspiciousInterpreter.as_str(), 20);
                firings.push(RuleFiring {
                    rule_id: RuleId::SuspiciousInterpreter,
                    weight,
                    reason: "Интерпретатор запущен с inline-кодом, eval, base64 или через pipe".to_string(),
                });
            }
        }

        // 6. [+10] RAW_IP_CONNECT
        let is_direct_ip = net.dest_ip.as_ref().map(|ip| is_numeric_ip(ip)).unwrap_or(false);
        if is_direct_ip && !net.has_dns_record {
            let weight = self.get_weight(RuleId::RawIpConnect.as_str(), 10);
            firings.push(RuleFiring {
                rule_id: RuleId::RawIpConnect,
                weight,
                reason: "Сетевое подключение напрямую по IP без зафиксированного DNS-запроса".to_string(),
            });
        }

        // 7. [-35] TRUSTED_PACKAGE_CONTEXT
        // Legitimate binary in dpkg context, and NOT an interpreter executing an untrusted script
        let is_script_untrusted = node.script_path.is_some() || node.is_memfd;
        if pkg_owned && !is_untrusted_dir && !is_script_untrusted {
            let weight = self.get_weight(RuleId::TrustedPackageContext.as_str(), -35);
            firings.push(RuleFiring {
                rule_id: RuleId::TrustedPackageContext,
                weight,
                reason: "Бинарник верифицирован в пакетах системы (dpkg) и запущен в штатном контексте".to_string(),
            });
        }

        let score = RiskScore::compute(firings);
        debug!("Risk evaluation for TGID {}: score={}", node.tgid, score.total);
        score
    }

    fn get_weight(&self, rule_name: &str, default: i32) -> i32 {
        self.rules_config
            .rules
            .get(rule_name)
            .map(|r| r.weight)
            .unwrap_or(default)
    }
}

fn is_numeric_ip(s: &str) -> bool {
    s.parse::<std::net::IpAddr>().is_ok()
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::path::PathBuf;
    use sentinel_common::process::SecretCategory;

    #[test]
    fn test_infostealer_detection() {
        let rules = RulesConfig::default();
        let dpkg = DpkgChecker::new();
        let engine = RiskEngine::new(rules, dpkg);

        let mut node = ProcessNode::new(1420, 1000, 1000, PathBuf::from("/usr/bin/python3"));
        node.script_path = Some(PathBuf::from("/tmp/install.py"));
        node.cmdline = vec!["python3".into(), "/tmp/install.py".into()];

        // Accessed SSH key 100ms ago
        node.record_secret_access(
            PathBuf::from("/home/user/.ssh/id_ed25519"),
            SecretCategory::SshKey,
            1_000_000_000, // 1s
        );

        let net = NetworkContext {
            dest_ip: Some("185.220.101.5".into()),
            dest_port: 443,
            has_dns_record: false,
            current_time_ns: 1_140_000_000, // 1.14s (0.14s delta)
        };

        let score = engine.evaluate(&node, &net);

        // Expected firings:
        // SECRET_NON_OWNER (+40)
        // UNTRUSTED_BINARY_ORIGIN (+25, /tmp/install.py)
        // FAST_EXFIL_BURST (+15, 0.14s delta <= 5s)
        // RAW_IP_CONNECT (+10)
        // Total = 90 (HIGH)
        assert_eq!(score.total, 90);
        let thresholds = sentinel_common::risk::RiskThresholds::default();
        assert_eq!(score.classify(&thresholds), sentinel_common::risk::Verdict::High);
    }

    #[test]
    fn test_fileless_memfd_detection() {
        let rules = RulesConfig::default();
        let dpkg = DpkgChecker::new();
        let engine = RiskEngine::new(rules, dpkg);

        let mut node = ProcessNode::new(2000, 1, 1000, PathBuf::from("/memfd:stealer"));
        node.is_memfd = true;

        let net = NetworkContext {
            dest_ip: Some("192.168.1.50".into()),
            dest_port: 8080,
            has_dns_record: true,
            current_time_ns: 10_000_000_000,
        };

        let score = engine.evaluate(&node, &net);
        // FILELESS_MEMFD (+50)
        assert!(score.total >= 50);
    }
}
