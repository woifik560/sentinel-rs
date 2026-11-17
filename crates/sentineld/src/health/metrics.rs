//! Health metrics tracking subsystem statistics.

use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct SubsystemMetrics {
    pub events_ingested: u64,
    pub events_dropped: u64,
    pub queue_depth: usize,
    pub active_incidents: usize,
    pub tracked_processes: usize,
    pub memory_rss_bytes: u64,
    pub uptime_secs: u64,
}
