//! Asynchronous RingBuffer event consumer with bounded backpressure and DoS rate limiting.

use std::collections::HashMap;
use std::sync::Arc;
use tokio::sync::{mpsc, Mutex};
use tracing::{debug, warn};

use crate::collector::event_metrics::EventMetrics;
use crate::health::FailurePolicyManager;
use sentinel_common::events::EbpfEvent;

/// Rate limiter state per PID to throttle event flooding (e.g. fork bombs).
struct PidRateLimiter {
    counts: HashMap<u32, (u32, std::time::Instant)>,
    max_events_per_window: u32,
    window_duration: std::time::Duration,
}

impl PidRateLimiter {
    fn new(max_events_per_window: u32, window_duration: std::time::Duration) -> Self {
        Self {
            counts: HashMap::new(),
            max_events_per_window,
            window_duration,
        }
    }

    /// Check if event from this PID is allowed.
    /// Critical events (secret access, memfd, ptrace) bypass rate limiting!
    fn check_allowed(&mut self, pid: u32, is_critical: bool) -> bool {
        if is_critical {
            return true;
        }

        let now = std::time::Instant::now();
        let entry = self.counts.entry(pid).or_insert((0, now));

        if now.duration_since(entry.1) > self.window_duration {
            *entry = (1, now);
            true
        } else if entry.0 < self.max_events_per_window {
            entry.0 += 1;
            true
        } else {
            false
        }
    }
}

pub struct RingBufferConsumer {
    metrics: Arc<EventMetrics>,
    queue_capacity: usize,
    failure_policy: Option<Arc<FailurePolicyManager>>,
}

impl RingBufferConsumer {
    pub fn new(metrics: Arc<EventMetrics>, queue_capacity: usize) -> Self {
        Self {
            metrics,
            queue_capacity,
            failure_policy: None,
        }
    }

    pub fn with_failure_policy(mut self, policy: Arc<FailurePolicyManager>) -> Self {
        self.failure_policy = Some(policy);
        self
    }

    /// Spawns a background task that consumes from the eBPF event stream and pushes into a bounded channel.
    pub fn start_consumer(
        &self,
        mut raw_rx: mpsc::Receiver<EbpfEvent>,
    ) -> mpsc::Receiver<EbpfEvent> {
        let (tx, rx) = mpsc::channel(self.queue_capacity);
        let metrics = self.metrics.clone();
        let failure_policy = self.failure_policy.clone();
        let limiter = Arc::new(Mutex::new(PidRateLimiter::new(
            1000,
            std::time::Duration::from_millis(100),
        )));

        tokio::spawn(async move {
            debug!("eBPF RingBuffer consumer loop started");
            while let Some(event) = raw_rx.recv().await {
                metrics.inc_ingested();

                // Determine PID and criticality
                let (pid, is_critical) = match &event {
                    EbpfEvent::FileOpen { tgid, .. } => (*tgid, true),
                    EbpfEvent::BprmCheckSecurity { tgid, is_memfd, .. } => (*tgid, *is_memfd),
                    EbpfEvent::PtraceAccessCheck { tracer_tgid, .. } => (*tracer_tgid, true),
                    EbpfEvent::SocketConnect { tgid, .. } => (*tgid, false),
                    EbpfEvent::SocketSendmsg { tgid, .. } => (*tgid, false),
                    EbpfEvent::ProcessFork { child_tgid, .. } => (*child_tgid, false),
                    EbpfEvent::ProcessExec { tgid, .. } => (*tgid, false),
                    EbpfEvent::FilePermission { tgid, .. } => (*tgid, false),
                    EbpfEvent::UnixMaySend { sender_tgid, .. } => (*sender_tgid, false),
                    EbpfEvent::MmapFile { tgid, .. } => (*tgid, true),
                    EbpfEvent::FileReceive { receiver_tgid, .. } => (*receiver_tgid, true),
                    EbpfEvent::ProcEnvironAccess { reader_tgid, .. } => (*reader_tgid, true),
                };

                // Check rate limiter to defend against fork-bomb / syscall flood DoS
                let allowed = {
                    let mut lim = limiter.lock().await;
                    lim.check_allowed(pid, is_critical)
                };

                if !allowed {
                    metrics.inc_rate_limited();
                    if let Some(ref fp) = failure_policy {
                        fp.report_ringbuffer_drop();
                    }
                    continue;
                }

                // Non-blocking try_send to avoid backpressure stalling kernel ring buffer consumption
                match tx.try_send(event) {
                    Ok(_) => {}
                    Err(mpsc::error::TrySendError::Full(evt)) => {
                        metrics.inc_overflow();
                        if let Some(ref fp) = failure_policy {
                            fp.report_ringbuffer_drop();
                        }
                        warn!("Event collection queue full! Dropping event to avoid memory saturation");
                        // As a fail-safe backpressure attempt, await with a strict timeout
                        let _ = tokio::time::timeout(
                            tokio::time::Duration::from_millis(5),
                            tx.send(evt),
                        )
                        .await;
                    }
                    Err(mpsc::error::TrySendError::Closed(_)) => {
                        debug!("Event dispatcher channel closed. Exiting RingBuffer consumer.");
                        break;
                    }
                }
            }
        });

        rx
    }
}
