//! Hybrid watchdog integrating systemd watchdog and kernel heartbeat.

use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::time::Duration;
use tracing::{debug, info};

pub struct Watchdog {
    running: Arc<AtomicBool>,
    heartbeat_interval: Duration,
}

impl Watchdog {
    pub fn new(heartbeat_interval: Duration) -> Self {
        Self {
            running: Arc::new(AtomicBool::new(false)),
            heartbeat_interval,
        }
    }

    /// Notify systemd that the daemon is ready (`READY=1`).
    pub fn notify_ready() {
        if let Ok(socket_path) = std::env::var("NOTIFY_SOCKET") {
            let _ = std::os::unix::net::UnixDatagram::unbound()
                .and_then(|sock| sock.send_to(b"READY=1", socket_path));
            info!("Notified systemd: READY=1");
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

    /// Starts the background watchdog thread.
    pub fn start(&self) {
        self.running.store(true, Ordering::SeqCst);
        let running = self.running.clone();
        let interval = self.heartbeat_interval;

        std::thread::Builder::new()
            .name("sentinel-watchdog".into())
            .spawn(move || {
                info!("Sentineld watchdog thread started with interval {:?}", interval);
                while running.load(Ordering::SeqCst) {
                    Self::notify_watchdog();
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
