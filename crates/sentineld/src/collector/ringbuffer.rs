//! Asynchronous RingBuffer event consumer with bounded backpressure.

use std::sync::Arc;
use tokio::sync::mpsc;
use tracing::{debug, warn};

use sentinel_common::events::EbpfEvent;
use crate::collector::event_metrics::EventMetrics;

pub struct RingBufferConsumer {
    metrics: Arc<EventMetrics>,
    queue_capacity: usize,
}

impl RingBufferConsumer {
    pub fn new(metrics: Arc<EventMetrics>, queue_capacity: usize) -> Self {
        Self {
            metrics,
            queue_capacity,
        }
    }

    /// Spawns a background task that consumes from the eBPF event stream and pushes into a bounded channel.
    pub fn start_consumer(
        &self,
        mut raw_rx: mpsc::Receiver<EbpfEvent>,
    ) -> mpsc::Receiver<EbpfEvent> {
        let (tx, rx) = mpsc::channel(self.queue_capacity);
        let metrics = self.metrics.clone();

        tokio::spawn(async move {
            debug!("eBPF RingBuffer consumer loop started");
            while let Some(event) = raw_rx.recv().await {
                metrics.inc_ingested();

                // Non-blocking try_send to avoid backpressure stalling kernel ring buffer consumption
                match tx.try_send(event) {
                    Ok(_) => {}
                    Err(mpsc::error::TrySendError::Full(evt)) => {
                        metrics.inc_overflow();
                        warn!("Event collection queue full! Dropping event to avoid memory saturation");
                        // As a fail-safe backpressure attempt, await with a strict timeout
                        let _ = tokio::time::timeout(tokio::time::Duration::from_millis(5), tx.send(evt)).await;
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
