//! Event collection and normalization engine.
//!
//! Subsystem for consuming raw eBPF events, normalizing schemas, maintaining
//! drop counters, and dispatching to the Lineage, Behavior, and Storage engines.

pub mod event_dispatcher;
pub mod event_metrics;
pub mod event_normalizer;
pub mod ringbuffer;

pub use event_dispatcher::EventDispatcher;
pub use event_metrics::{EventMetrics, MetricsSnapshot};
pub use event_normalizer::{EventDetails, EventNormalizer, EventSource, NormalizedEvent, NormalizedEventType, ProcessKey};
pub use ringbuffer::RingBufferConsumer;
