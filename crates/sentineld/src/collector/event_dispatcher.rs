//! Central event dispatcher coordinating normalized events across subsystems.

use std::sync::Arc;
use tokio::sync::{broadcast, mpsc};
use tracing::debug;

use crate::collector::event_metrics::EventMetrics;
use crate::collector::event_normalizer::{EventNormalizer, NormalizedEvent};
use crate::lineage::LineageTracker;
use sentinel_common::events::EbpfEvent;

/// Extracts primary TGID from any EbpfEvent variant.
pub fn event_tgid(event: &EbpfEvent) -> u32 {
    match event {
        EbpfEvent::FileOpen { tgid, .. } => *tgid,
        EbpfEvent::FilePermission { tgid, .. } => *tgid,
        EbpfEvent::BprmCheckSecurity { tgid, .. } => *tgid,
        EbpfEvent::ProcessFork { child_tgid, .. } => *child_tgid,
        EbpfEvent::ProcessExec { tgid, .. } => *tgid,
        EbpfEvent::SocketConnect { tgid, .. } => *tgid,
        EbpfEvent::SocketSendmsg { tgid, .. } => *tgid,
        EbpfEvent::UnixMaySend { sender_tgid, .. } => *sender_tgid,
        EbpfEvent::PtraceAccessCheck { tracer_tgid, .. } => *tracer_tgid,
        EbpfEvent::ProcEnvironAccess { reader_tgid, .. } => *reader_tgid,
        EbpfEvent::MmapFile { tgid, .. } => *tgid,
        EbpfEvent::FileReceive { receiver_tgid, .. } => *receiver_tgid,
    }
}

/// Resolves process start_time (clock ticks since boot) with lineage cache and procfs fallback.
pub fn resolve_process_start_time(tgid: u32, lineage: Option<&LineageTracker>) -> u64 {
    if let Some(tracker) = lineage {
        if let Some(node) = tracker.get(tgid) {
            if node.start_time_ns > 0 {
                return node.start_time_ns;
            }
        }
    }

    // Direct /proc/<tgid>/stat inspection (field 22 is clock ticks since boot)
    let stat_path = format!("/proc/{}/stat", tgid);
    if let Ok(content) = std::fs::read_to_string(&stat_path) {
        if let Some(rparen) = content.rfind(')') {
            let rest = &content[rparen + 1..];
            let fields: Vec<&str> = rest.split_whitespace().collect();
            if let Some(starttime_str) = fields.get(19) {
                if let Ok(ticks) = starttime_str.parse::<u64>() {
                    return ticks;
                }
            }
        }
    }

    0
}

pub struct EventDispatcher {
    metrics: Arc<EventMetrics>,
    event_tx: broadcast::Sender<NormalizedEvent>,
    lineage_tracker: Option<LineageTracker>,
}

impl EventDispatcher {
    pub fn new(metrics: Arc<EventMetrics>, buffer_size: usize) -> Self {
        let (event_tx, _) = broadcast::channel(buffer_size);
        Self {
            metrics,
            event_tx,
            lineage_tracker: None,
        }
    }

    pub fn with_lineage_tracker(mut self, tracker: LineageTracker) -> Self {
        self.lineage_tracker = Some(tracker);
        self
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
        let lineage = self.lineage_tracker.clone();

        tokio::spawn(async move {
            debug!("EventDispatcher processing loop active");
            while let Some(raw_event) = event_rx.recv().await {
                let tgid = event_tgid(&raw_event);
                let start_time = resolve_process_start_time(tgid, lineage.as_ref());

                let normalized = EventNormalizer::normalize(raw_event, start_time);
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
