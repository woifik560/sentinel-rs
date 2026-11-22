//! Behavior detection rule definitions and interfaces.

use serde::{Deserialize, Serialize};

use crate::collector::{NormalizedEvent, NormalizedEventType};
use crate::lineage::LineageTracker;
use sentinel_common::policy::PolicyAction;
use sentinel_common::risk::SeverityLevel;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BehaviorRule {
    pub id: String,
    pub version: u32,
    pub name: String,
    pub description: String,
    pub enabled: bool,
    pub severity: SeverityLevel,
    pub risk_weight: i32,
    pub target_event_types: Vec<NormalizedEventType>,
    pub correlation_window_ms: u64,
    pub recommended_action: PolicyAction,
}

#[derive(Debug, Clone)]
pub struct DetectionMatch {
    pub rule_id: String,
    pub rule_name: String,
    pub severity: SeverityLevel,
    pub weight: i32,
    pub action: PolicyAction,
    pub reason: String,
    pub confidence: f32,
}

impl BehaviorRule {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        id: &str,
        version: u32,
        name: &str,
        description: &str,
        severity: SeverityLevel,
        risk_weight: i32,
        target_event_types: Vec<NormalizedEventType>,
        correlation_window_ms: u64,
        recommended_action: PolicyAction,
    ) -> Self {
        Self {
            id: id.to_string(),
            version,
            name: name.to_string(),
            description: description.to_string(),
            enabled: true,
            severity,
            risk_weight,
            target_event_types,
            correlation_window_ms,
            recommended_action,
        }
    }

    /// Evaluates if an event matches this rule's heuristics.
    pub fn evaluate(
        &self,
        event: &NormalizedEvent,
        lineage: &LineageTracker,
    ) -> Option<DetectionMatch> {
        if !self.enabled {
            return None;
        }

        if !self.target_event_types.contains(&event.event_type) {
            return None;
        }

        match self.id.as_str() {
            "RULE_SUSPICIOUS_EXEC_PATH" => {
                if let Some(ref path) = event.exe_path {
                    let p = path.to_string_lossy();
                    if p.starts_with("/tmp/")
                        || p.starts_with("/dev/shm/")
                        || p.starts_with("/var/tmp/")
                    {
                        return Some(DetectionMatch {
                            rule_id: self.id.clone(),
                            rule_name: self.name.clone(),
                            severity: self.severity,
                            weight: self.risk_weight,
                            action: self.recommended_action,
                            reason: format!("Binary executed from suspicious directory: {}", p),
                            confidence: 0.85,
                        });
                    }
                }
            }

            "RULE_ANONYMOUS_MEMFD_EXEC" => {
                if let crate::collector::EventDetails::ProcessExec {
                    is_memfd: true,
                    ref exe_path,
                    ..
                } = event.details
                {
                    return Some(DetectionMatch {
                        rule_id: self.id.clone(),
                        rule_name: self.name.clone(),
                        severity: self.severity,
                        weight: self.risk_weight,
                        action: self.recommended_action,
                        reason: format!(
                            "Fileless execution detected from anonymous memory (memfd): {}",
                            exe_path.display()
                        ),
                        confidence: 0.95,
                    });
                }
            }

            "RULE_PTRACE_SNOOPING" => {
                if let crate::collector::EventDetails::PtraceAccess {
                    tracer_tgid,
                    tracee_tgid,
                    is_blocked,
                    ..
                } = event.details
                {
                    return Some(DetectionMatch {
                        rule_id: self.id.clone(),
                        rule_name: self.name.clone(),
                        severity: self.severity,
                        weight: self.risk_weight,
                        action: self.recommended_action,
                        reason: format!("Process memory inspection or ptrace attempt: PID {} snooped PID {} (blocked={})", tracer_tgid, tracee_tgid, is_blocked),
                        confidence: 0.90,
                    });
                }
            }

            "RULE_SUSPICIOUS_PARENT_CHILD" => {
                if let Some(node) = lineage.get(event.tgid) {
                    let chain = lineage.get_ancestor_chain(event.tgid);
                    // Check for unusual web server or desktop app spawning a root shell
                    if chain.iter().any(|s| {
                        s.exe_name == "nginx" || s.exe_name == "apache2" || s.exe_name == "node"
                    }) && (node.exe_path.ends_with("sh") || node.exe_path.ends_with("bash"))
                    {
                        return Some(DetectionMatch {
                            rule_id: self.id.clone(),
                            rule_name: self.name.clone(),
                            severity: self.severity,
                            weight: self.risk_weight,
                            action: self.recommended_action,
                            reason: format!(
                                "Web server process spawned interactive shell: {}",
                                node.exe_path.display()
                            ),
                            confidence: 0.92,
                        });
                    }
                }
            }

            "RULE_TAINTED_NETWORK_EXFIL" => {
                if let crate::collector::EventDetails::SocketConnect {
                    dst_ipv4,
                    dst_port,
                    so_mark,
                    ..
                } = event.details
                {
                    // Check if mark has the reval or tainted flag
                    let (is_sentinel, _, _) = sentinel_common::events::decode_flow_mark(so_mark);
                    if is_sentinel && so_mark != 0 {
                        let ip_str = dst_ipv4
                            .map(|ip| ip.to_string())
                            .unwrap_or_else(|| "remote".into());
                        return Some(DetectionMatch {
                            rule_id: self.id.clone(),
                            rule_name: self.name.clone(),
                            severity: self.severity,
                            weight: self.risk_weight,
                            action: self.recommended_action,
                            reason: format!(
                                "Network connection attempt by tainted process to {}:{}",
                                ip_str, dst_port
                            ),
                            confidence: 0.88,
                        });
                    }
                }
            }

            _ => {}
        }

        None
    }
}
