//! Central event dispatcher coordinating normalized events across subsystems.

use std::sync::Arc;
use tokio::sync::{broadcast, mpsc};
use tracing::debug;

use crate::collector::event_metrics::EventMetrics;
use crate::collector::event_normalizer::{EventNormalizer, NormalizedEvent};
use sentinel_common::events::EbpfEvent;

pub struct EventDispatcher {
    metrics: Arc<EventMetrics>,
    event_tx: broadcast::Sender<NormalizedEvent>,
}

impl EventDispatcher {
    pub fn new(metrics: Arc<EventMetrics>, buffer_size: usize) -> Self {
        let (event_tx, _) = broadcast::channel(buffer_size);
        Self { metrics, event_tx }
    }

    pub fn subscribe(&self) -> broadcast::Receiver<NormalizedEvent> {
        self.event_tx.subscribe()
    }

    pub fn get_metrics(&self) -> Arc<EventMetrics> {
        self.metrics.clone()
    }

    /// Spawns the main dispatch loop processing events from the RingBuffer consumer.
    pub fn start_dispatch_loop(&self, mut event_rx: mpsc::Receiver<EbpfEvent>) {
        let metrics = self.metrics.clone();
        let tx = self.event_tx.clone();

        tokio::spawn(async move {
            debug!("EventDispatcher processing loop active");
            while let Some(raw_event) = event_rx.recv().await {
                let start_time_ns = std::time::SystemTime::now()
                    .duration_since(std::time::UNIX_EPOCH)
                    .map(|d| d.as_nanos() as u64)
                    .unwrap_or(0);

                let normalized = EventNormalizer::normalize(raw_event, start_time_ns);
                metrics.inc_normalized();

                if let Err(_e) = tx.send(normalized) {
                    // Receiver lag or no active listeners
                    metrics.inc_dropped();
                }
            }
            debug!("EventDispatcher processing loop terminated");
        });
    }
}
