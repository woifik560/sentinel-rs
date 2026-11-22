//! Behavior detection engine evaluating events and process context against deterministic rules.

use std::sync::{Arc, RwLock};
use tracing::{info, warn};

use crate::behavior::rule::{BehaviorRule, DetectionMatch};
use crate::collector::{NormalizedEvent, NormalizedEventType};
use crate::lineage::LineageTracker;
use sentinel_common::policy::PolicyAction;
use sentinel_common::risk::SeverityLevel;

pub struct BehaviorEngine {
    rules: Arc<RwLock<Vec<BehaviorRule>>>,
    lineage: LineageTracker,
}

impl BehaviorEngine {
    pub fn new(lineage: LineageTracker) -> Self {
        let engine = Self {
            rules: Arc::new(RwLock::new(Vec::new())),
            lineage,
        };
        engine.load_default_rules();
        engine
    }

    pub fn load_default_rules(&self) {
        let mut r = self.rules.write().unwrap();
        r.push(BehaviorRule::new(
            "RULE_SUSPICIOUS_EXEC_PATH",
            1,
            "Suspicious Execution Path",
            "Detects binaries running from world-writable or transient directories (/tmp, /dev/shm, /var/tmp)",
            SeverityLevel::Medium,
            25,
            vec![NormalizedEventType::ProcessExec],
            5000,
            PolicyAction::Monitor,
        ));

        r.push(BehaviorRule::new(
            "RULE_ANONYMOUS_MEMFD_EXEC",
            1,
            "Anonymous Memory Execution",
            "Detects fileless code execution directly from memory via memfd_create",
            SeverityLevel::Critical,
            50,
            vec![NormalizedEventType::ProcessExec],
            5000,
            PolicyAction::Deny,
        ));

        r.push(BehaviorRule::new(
            "RULE_PTRACE_SNOOPING",
            1,
            "Cross-Process Memory Snooping",
            "Detects unauthorized ptrace or /proc/pid/mem access against clean or protected processes",
            SeverityLevel::High,
            30,
            vec![NormalizedEventType::PtraceAccess],
            5000,
            PolicyAction::Deny,
        ));

        r.push(BehaviorRule::new(
            "RULE_SUSPICIOUS_PARENT_CHILD",
            1,
            "Anomalous Process Tree",
            "Detects unexpected parent-child relationships such as web services spawning shells",
            SeverityLevel::Critical,
            40,
            vec![
                NormalizedEventType::ProcessExec,
                NormalizedEventType::ProcessFork,
            ],
            10000,
            PolicyAction::TerminateProcess,
        ));

        r.push(BehaviorRule::new(
            "RULE_TAINTED_NETWORK_EXFIL",
            1,
            "Tainted Network Outbound",
            "Detects network transmission attempts from processes tainted by sensitive credential access",
            SeverityLevel::High,
            35,
            vec![NormalizedEventType::SocketConnect, NormalizedEventType::SocketSendmsg],
            5000,
            PolicyAction::DenyNetwork,
        ));

        info!("Loaded {} default behavior detection rules", r.len());
    }

    /// Evaluates an event against all active behavior rules.
    pub fn evaluate_event(&self, event: &NormalizedEvent) -> Vec<DetectionMatch> {
        let rules = self.rules.read().unwrap();
        let mut matches = Vec::new();

        for rule in rules.iter() {
            if let Some(m) = rule.evaluate(event, &self.lineage) {
                warn!(
                    "Behavior rule matched: {} - {} (weight: {})",
                    m.rule_id, m.rule_name, m.weight
                );
                matches.push(m);
            }
        }

        matches
    }

    /// List currently registered rules.
    pub fn list_rules(&self) -> Vec<BehaviorRule> {
        let rules = self.rules.read().unwrap();
        rules.clone()
    }
}
