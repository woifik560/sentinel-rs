//! Hybrid watchdog integrating systemd watchdog and kernel heartbeat.

use sentinel_common::health::AgentState;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::time::{Duration, Instant};
use tracing::{debug, error, info, warn};

use super::metrics::SubsystemMetrics;
use super::monitor::HealthMonitor;

pub struct Watchdog {
    running: Arc<AtomicBool>,
    heartbeat_interval: Duration,
    monitor: Option<Arc<HealthMonitor>>,
    metrics: Option<Arc<SubsystemMetrics>>,
}

impl Watchdog {
    pub fn new(heartbeat_interval: Duration) -> Self {
        Self {
            running: Arc::new(AtomicBool::new(false)),
            heartbeat_interval,
            monitor: None,
            metrics: None,
        }
    }

    pub fn with_monitor(
        heartbeat_interval: Duration,
        monitor: Arc<HealthMonitor>,
        metrics: Arc<SubsystemMetrics>,
    ) -> Self {
        Self {
            running: Arc::new(AtomicBool::new(false)),
            heartbeat_interval,
            monitor: Some(monitor),
            metrics: Some(metrics),
        }
    }

    /// Notify systemd that the daemon is ready (`READY=1`).
    /// Strictly called AFTER all eBPF maps and nftables rules are initialized.
    pub fn notify_ready() {
        if let Ok(socket_path) = std::env::var("NOTIFY_SOCKET") {
            let _ = std::os::unix::net::UnixDatagram::unbound()
                .and_then(|sock| sock.send_to(b"READY=1", socket_path));
            info!("Notified systemd: READY=1 (all eBPF and nftables subsystems ready)");
        }
    }

    /// Notify systemd that the daemon is stopping (`STOPPING=1`).
    /// Called upon receiving SIGTERM / graceful shutdown.
    pub fn notify_stopping() {
        if let Ok(socket_path) = std::env::var("NOTIFY_SOCKET") {
            let _ = std::os::unix::net::UnixDatagram::unbound()
                .and_then(|sock| sock.send_to(b"STOPPING=1", socket_path));
            info!("Notified systemd: STOPPING=1 (graceful shutdown)");
        }
    }

    /// Notify systemd watchdog (`WATCHDOG=1`).
    pub fn notify_watchdog() {
        if let Ok(socket_path) = std::env::var("NOTIFY_SOCKET") {
            let _ = std::os::unix::net::UnixDatagram::unbound()
                .and_then(|sock| sock.send_to(b"WATCHDOG=1", socket_path));
            debug!("Kicked systemd watchdog: WATCHDOG=1");
        }
    }

    /// Starts the background watchdog thread with active health verification.
    ///
    /// If HealthMonitor detects ProtectionUnavailable or hung subsystems, heartbeat
    /// is halted to allow systemd watchdog timeout and service auto-restart.
    pub fn start(&self) {
        self.running.store(true, Ordering::SeqCst);
        let running = self.running.clone();
        let interval = self.heartbeat_interval;
        let monitor = self.monitor.clone();
        let metrics = self.metrics.clone();

        std::thread::Builder::new()
            .name("sentinel-watchdog".into())
            .spawn(move || {
                info!("Sentineld health-aware watchdog thread started with interval {:?}", interval);
                let mut protection_unavailable_since: Option<Instant> = None;

                while running.load(Ordering::SeqCst) {
                    let mut should_kick = true;

                    if let (Some(ref mon), Some(ref met)) = (&monitor, &metrics) {
                        let state = mon.check_all(met);
                        if state == AgentState::ProtectionUnavailable {
                            let first_seen = protection_unavailable_since.get_or_insert_with(Instant::now);
                            if first_seen.elapsed() > Duration::from_secs(30) {
                                error!(
                                    "Protection has been UNAVAILABLE for >30s! Withholding systemd watchdog heartbeat to trigger service recovery."
                                );
                                should_kick = false;
                            } else {
                                warn!("Agent state is ProtectionUnavailable, grace period active ({:?})", first_seen.elapsed());
                            }
                        } else {
                            protection_unavailable_since = None;
                        }
                    }

                    if should_kick {
                        Self::notify_watchdog();
                    }

                    std::thread::sleep(interval);
                }
                info!("Sentineld watchdog thread stopped");
            })
            .expect("Failed to spawn watchdog thread");
    }

    pub fn stop(&self) {
        self.running.store(false, Ordering::SeqCst);
    }
}
