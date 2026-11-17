//! Health monitoring and subsystem status representation.
//!
//! Tracks operational health across all Sentinel-RS subsystems (eBPF loader,
//! BPF LSM, RingBuffer, Event Collector, Behavior Engine, Policy Engine,
//! Response Engine, Network Protection, IPC, SQLite, Watchdog).

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};

/// Operational state of a subsystem.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum HealthStatus {
    /// Fully operational with normal telemetry.
    Healthy,
    /// Operating with degraded capabilities (e.g. non-critical hook missing or soak mode).
    Degraded,
    /// Failed mandatory security subsystem (fail-closed or alert).
    Failed,
}

impl std::fmt::Display for HealthStatus {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            HealthStatus::Healthy => write!(f, "HEALTHY"),
            HealthStatus::Degraded => write!(f, "DEGRADED"),
            HealthStatus::Failed => write!(f, "FAILED"),
        }
    }
}

/// Identifiers for all monitored agent subsystems.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum SubsystemId {
    EbpfLoader,
    BpfLsm,
    RequiredBpfPrograms,
    RingBuffer,
    EventCollector,
    BehaviorEngine,
    PolicyEngine,
    ResponseEngine,
    NetworkProtection,
    IpcServer,
    SqliteStorage,
    Watchdog,
}

impl SubsystemId {
    pub fn as_str(&self) -> &'static str {
        match self {
            SubsystemId::EbpfLoader => "ebpf_loader",
            SubsystemId::BpfLsm => "bpf_lsm",
            SubsystemId::RequiredBpfPrograms => "required_bpf_programs",
            SubsystemId::RingBuffer => "ring_buffer",
            SubsystemId::EventCollector => "event_collector",
            SubsystemId::BehaviorEngine => "behavior_engine",
            SubsystemId::PolicyEngine => "policy_engine",
            SubsystemId::ResponseEngine => "response_engine",
            SubsystemId::NetworkProtection => "network_protection",
            SubsystemId::IpcServer => "ipc_server",
            SubsystemId::SqliteStorage => "sqlite_storage",
            SubsystemId::Watchdog => "watchdog",
        }
    }
}

impl std::fmt::Display for SubsystemId {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.as_str())
    }
}

/// Detailed health state for a single subsystem.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SubsystemHealth {
    pub id: SubsystemId,
    pub status: HealthStatus,
    pub mandatory: bool,
    pub last_check: DateTime<Utc>,
    pub message: String,
    pub error_details: Option<String>,
}

/// Overall agent health report exposed via `sntctl health` and IPC.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AgentHealthReport {
    pub overall_status: HealthStatus,
    pub timestamp: DateTime<Utc>,
    pub uptime_secs: u64,
    pub subsystems: Vec<SubsystemHealth>,
    pub version: String,
}

impl AgentHealthReport {
    pub fn new(uptime_secs: u64, subsystems: Vec<SubsystemHealth>) -> Self {
        let mut overall = HealthStatus::Healthy;
        for sub in &subsystems {
            match sub.status {
                HealthStatus::Failed => {
                    if sub.mandatory {
                        overall = HealthStatus::Failed;
                        break;
                    } else if overall == HealthStatus::Healthy {
                        overall = HealthStatus::Degraded;
                    }
                }
                HealthStatus::Degraded => {
                    if overall == HealthStatus::Healthy {
                        overall = HealthStatus::Degraded;
                    }
                }
                HealthStatus::Healthy => {}
            }
        }

        Self {
            overall_status: overall,
            timestamp: Utc::now(),
            uptime_secs,
            subsystems,
            version: env!("CARGO_PKG_VERSION").to_string(),
        }
    }
}
