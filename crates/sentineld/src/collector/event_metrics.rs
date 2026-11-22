//! Event collector metrics: drop counters, queue saturation, and throughput.

use std::sync::atomic::{AtomicU64, Ordering};

#[derive(Debug, Default)]
pub struct EventMetrics {
    pub total_ingested: AtomicU64,
    pub total_normalized: AtomicU64,
    pub total_dropped: AtomicU64,
    pub queue_overflow_drops: AtomicU64,
    pub kernel_ringbuffer_drops: AtomicU64,
    pub rate_limit_drops: AtomicU64,
    pub out_of_order_events: AtomicU64,
}

impl EventMetrics {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn inc_ingested(&self) {
        self.total_ingested.fetch_add(1, Ordering::Relaxed);
    }

    pub fn inc_normalized(&self) {
        self.total_normalized.fetch_add(1, Ordering::Relaxed);
    }

    pub fn inc_dropped(&self) {
        self.total_dropped.fetch_add(1, Ordering::Relaxed);
    }

    pub fn inc_overflow(&self) {
        self.queue_overflow_drops.fetch_add(1, Ordering::Relaxed);
        self.total_dropped.fetch_add(1, Ordering::Relaxed);
    }

    pub fn inc_kernel_drops(&self, count: u64) {
        self.kernel_ringbuffer_drops
            .fetch_add(count, Ordering::Relaxed);
        self.total_dropped.fetch_add(count, Ordering::Relaxed);
    }

    pub fn inc_rate_limited(&self) {
        self.rate_limit_drops.fetch_add(1, Ordering::Relaxed);
        self.total_dropped.fetch_add(1, Ordering::Relaxed);
    }

    pub fn inc_out_of_order(&self) {
        self.out_of_order_events.fetch_add(1, Ordering::Relaxed);
    }

    pub fn snapshot(&self) -> MetricsSnapshot {
        MetricsSnapshot {
            total_ingested: self.total_ingested.load(Ordering::Relaxed),
            total_normalized: self.total_normalized.load(Ordering::Relaxed),
            total_dropped: self.total_dropped.load(Ordering::Relaxed),
            queue_overflow_drops: self.queue_overflow_drops.load(Ordering::Relaxed),
            kernel_ringbuffer_drops: self.kernel_ringbuffer_drops.load(Ordering::Relaxed),
            rate_limit_drops: self.rate_limit_drops.load(Ordering::Relaxed),
            out_of_order_events: self.out_of_order_events.load(Ordering::Relaxed),
        }
    }
}

#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct MetricsSnapshot {
    pub total_ingested: u64,
    pub total_normalized: u64,
    pub total_dropped: u64,
    pub queue_overflow_drops: u64,
    pub kernel_ringbuffer_drops: u64,
    pub rate_limit_drops: u64,
    pub out_of_order_events: u64,
}
