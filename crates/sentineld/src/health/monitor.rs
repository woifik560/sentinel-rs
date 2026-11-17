//! Health Monitor tracking overall agent status and subsystem health.

use chrono::Utc;
use std::sync::Arc;
use std::time::Instant;
use sentinel_common::health::{AgentHealthReport, HealthStatus, SubsystemHealth, SubsystemId};
use super::degraded::DegradedStateManager;
use super::metrics::SubsystemMetrics;

pub struct HealthMonitor {
    start_time: Instant,
    pub degraded_state: Arc<DegradedStateManager>,
}

impl HealthMonitor {
    pub fn new(degraded_state: Arc<DegradedStateManager>) -> Self {
        Self {
            start_time: Instant::now(),
            degraded_state,
        }
    }

    pub fn get_report(&self, metrics: &SubsystemMetrics) -> AgentHealthReport {
        let uptime = self.start_time.elapsed().as_secs();
        let degradations = self.degraded_state.get_degradations();

        let mut subsystems = Vec::new();

        subsystems.push(SubsystemHealth {
            id: SubsystemId::EventCollector,
            status: if metrics.events_dropped > 1000 {
                HealthStatus::Degraded
            } else {
                HealthStatus::Healthy
            },
            mandatory: true,
            last_check: Utc::now(),
            message: format!("Ingested: {}, Dropped: {}", metrics.events_ingested, metrics.events_dropped),
            error_details: None,
        });

        subsystems.push(SubsystemHealth {
            id: SubsystemId::SqliteStorage,
            status: if metrics.queue_depth > 5_000 {
                HealthStatus::Degraded
            } else {
                HealthStatus::Healthy
            },
            mandatory: true,
            last_check: Utc::now(),
            message: format!("Queue depth: {}", metrics.queue_depth),
            error_details: None,
        });

        subsystems.push(SubsystemHealth {
            id: SubsystemId::BehaviorEngine,
            status: HealthStatus::Healthy,
            mandatory: true,
            last_check: Utc::now(),
            message: format!("Active incidents: {}", metrics.active_incidents),
            error_details: None,
        });

        subsystems.push(SubsystemHealth {
            id: SubsystemId::PolicyEngine,
            status: HealthStatus::Healthy,
            mandatory: true,
            last_check: Utc::now(),
            message: "Policy engine active".into(),
            error_details: None,
        });

        subsystems.push(SubsystemHealth {
            id: SubsystemId::ResponseEngine,
            status: HealthStatus::Healthy,
            mandatory: true,
            last_check: Utc::now(),
            message: "Response engine ready".into(),
            error_details: None,
        });

        subsystems.push(SubsystemHealth {
            id: SubsystemId::NetworkProtection,
            status: HealthStatus::Healthy,
            mandatory: false,
            last_check: Utc::now(),
            message: "Netfilter NFQUEUE active".into(),
            error_details: None,
        });

        subsystems.push(SubsystemHealth {
            id: SubsystemId::IpcServer,
            status: HealthStatus::Healthy,
            mandatory: true,
            last_check: Utc::now(),
            message: "SO_PEERCRED IPC active".into(),
            error_details: None,
        });

        subsystems.push(SubsystemHealth {
            id: SubsystemId::Watchdog,
            status: HealthStatus::Healthy,
            mandatory: false,
            last_check: Utc::now(),
            message: "Hybrid watchdog active".into(),
            error_details: None,
        });

        if !degradations.is_empty() {
            for deg in degradations {
                subsystems.push(SubsystemHealth {
                    id: SubsystemId::EbpfLoader,
                    status: HealthStatus::Degraded,
                    mandatory: false,
                    last_check: Utc::now(),
                    message: format!("{}: {}", deg.subsystem, deg.description),
                    error_details: Some(deg.remediation),
                });
            }
        }

        AgentHealthReport::new(uptime, subsystems)
    }
}
