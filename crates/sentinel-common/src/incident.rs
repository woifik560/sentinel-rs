//! Incident report representation and deterministic explanation formatter.
//!
//! Produces structured JSON reports for forensics / SIEM / BYO-AI and
//! human-readable explanation trees as required by ТЗ sections 3.4 and 4.3.

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};

use crate::ipc::LineageStep;
use crate::risk::{RuleFiring, Verdict};

/// Structured forensic report for a security incident.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct IncidentReport {
    /// Unique incident identifier (UUID v4).
    pub id: String,
    /// Timestamp of incident creation.
    pub timestamp: DateTime<Utc>,
    /// Computed risk score (0..100).
    pub risk_score: u32,
    /// Classified verdict.
    pub verdict: Verdict,
    /// Ordered process ancestry chain (root ancestor -> leaf process).
    pub process_chain: Vec<LineageStep>,
    /// Path of the secret file accessed, if any.
    pub secret_path: Option<String>,
    /// Time delta in milliseconds between secret read and network call.
    pub time_delta_ms: Option<u64>,
    /// Destination IP address.
    pub dest_ip: Option<String>,
    /// Destination port.
    pub dest_port: Option<u16>,
    /// Destination hostname if resolved via DNS.
    pub dest_domain: Option<String>,
    /// List of rules that fired with their weights and reasons.
    pub fired_rules: Vec<RuleFiring>,
    /// Human-readable explanation tree.
    pub human_summary: String,
}

impl IncidentReport {
    /// Constructs a human-readable explanation tree matching ТЗ section 3.4.
    ///
    /// Example format:
    /// `Процесс python3 (/tmp/install.py) -> запущен из npm (PID 1420) -> прочитал ~/.ssh/id_ed25519 (0.14s назад) -> connect 185.220.101.5:443 [Risk: 85/100]`
    pub fn format_human_summary(
        process_chain: &[LineageStep],
        secret_path: Option<&str>,
        time_delta_ms: Option<u64>,
        dest_ip: Option<&str>,
        dest_port: Option<u16>,
        risk_score: u32,
    ) -> String {
        let mut parts = Vec::new();

        if let Some(leaf) = process_chain.last() {
            if let Some(ref script) = leaf.script_path {
                parts.push(format!("Процесс {} ({})", leaf.exe_name, script.display()));
            } else {
                parts.push(format!("Процесс {} (PID {})", leaf.exe_name, leaf.tgid));
            }
        }

        // Parent info if available
        if process_chain.len() > 1 {
            let parent = &process_chain[process_chain.len() - 2];
            parts.push(format!("запущен из {} (PID {})", parent.exe_name, parent.tgid));
        }

        // Secret access info
        if let Some(secret) = secret_path {
            if let Some(delta) = time_delta_ms {
                let secs = delta as f64 / 1000.0;
                parts.push(format!("прочитал {} ({:.2}s назад)", secret, secs));
            } else {
                parts.push(format!("прочитал {}", secret));
            }
        }

        // Destination info
        match (dest_ip, dest_port) {
            (Some(ip), Some(port)) => parts.push(format!("connect {}:{}", ip, port)),
            (Some(ip), None) => parts.push(format!("connect {}", ip)),
            _ => {}
        }

        format!("{} [Risk: {}/100]", parts.join(" -> "), risk_score)
    }

    /// Helper constructor that automatically computes `human_summary`.
    pub fn new(
        id: String,
        timestamp: DateTime<Utc>,
        risk_score: u32,
        verdict: Verdict,
        process_chain: Vec<LineageStep>,
        secret_path: Option<String>,
        time_delta_ms: Option<u64>,
        dest_ip: Option<String>,
        dest_port: Option<u16>,
        dest_domain: Option<String>,
        fired_rules: Vec<RuleFiring>,
    ) -> Self {
        let human_summary = Self::format_human_summary(
            &process_chain,
            secret_path.as_deref(),
            time_delta_ms,
            dest_ip.as_deref(),
            dest_port,
            risk_score,
        );

        Self {
            id,
            timestamp,
            risk_score,
            verdict,
            process_chain,
            secret_path,
            time_delta_ms,
            dest_ip,
            dest_port,
            dest_domain,
            fired_rules,
            human_summary,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::path::PathBuf;

    #[test]
    fn test_format_human_summary() {
        let chain = vec![
            LineageStep {
                tgid: 1420,
                exe_name: "npm".to_string(),
                script_path: None,
            },
            LineageStep {
                tgid: 2048,
                exe_name: "python3".to_string(),
                script_path: Some(PathBuf::from("/tmp/install.py")),
            },
        ];

        let summary = IncidentReport::format_human_summary(
            &chain,
            Some("~/.ssh/id_ed25519"),
            Some(140),
            Some("185.220.101.5"),
            Some(443),
            85,
        );

        assert!(summary.contains("Процесс python3 (/tmp/install.py)"));
        assert!(summary.contains("запущен из npm (PID 1420)"));
        assert!(summary.contains("прочитал ~/.ssh/id_ed25519 (0.14s назад)"));
        assert!(summary.contains("connect 185.220.101.5:443"));
        assert!(summary.contains("[Risk: 85/100]"));
    }
}
