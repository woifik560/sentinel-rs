//! Health monitoring, watchdog, and diagnostics subsystem.

pub mod degraded;
pub mod metrics;
pub mod monitor;
pub mod watchdog;

pub use degraded::{DegradedReason, DegradedStateManager};
pub use metrics::SubsystemMetrics;
pub use monitor::HealthMonitor;
pub use watchdog::Watchdog;
