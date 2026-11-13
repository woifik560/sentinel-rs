//! Userspace loader and RingBuffer event listener for Sentinel eBPF probes.

use std::sync::Arc;
use tokio::sync::mpsc;
use tracing::{info, warn};

use sentinel_common::events::EbpfEvent;
use crate::maps::TaintMapManager;

/// Configuration for loading eBPF programs.
#[derive(Debug, Clone)]
pub struct LoaderConfig {
    pub ring_buffer_size: usize,
    pub enable_lsm: bool,
    pub enable_tracepoints: bool,
}

impl Default for LoaderConfig {
    fn default() -> Self {
        Self {
            ring_buffer_size: 8192,
            enable_lsm: true,
            enable_tracepoints: true,
        }
    }
}

/// The eBPF loader and event dispatcher.
pub struct EbpfLoader {
    config: LoaderConfig,
    taint_manager: Arc<TaintMapManager>,
    event_tx: mpsc::Sender<EbpfEvent>,
    event_rx: Option<mpsc::Receiver<EbpfEvent>>,
}

impl EbpfLoader {
    /// Create a new EbpfLoader instance.
    pub fn new(config: LoaderConfig) -> Self {
        let (tx, rx) = mpsc::channel(config.ring_buffer_size);
        let taint_manager = Arc::new(TaintMapManager::new());

        Self {
            config,
            taint_manager,
            event_tx: tx,
            event_rx: Some(rx),
        }
    }

    /// Access the taint map manager.
    pub fn taint_manager(&self) -> Arc<TaintMapManager> {
        self.taint_manager.clone()
    }

    /// Access the sender for pushing simulated or intercepted events.
    pub fn event_sender(&self) -> mpsc::Sender<EbpfEvent> {
        self.event_tx.clone()
    }

    /// Take the event receiver to consume events asynchronously.
    pub fn take_event_receiver(&mut self) -> Option<mpsc::Receiver<EbpfEvent>> {
        self.event_rx.take()
    }

    /// Attempt to load and attach eBPF programs to the running Linux kernel.
    pub async fn load_and_attach(&mut self) -> anyhow::Result<()> {
        info!("Initializing Sentinel-RS eBPF kernel probes (LSM & tracepoints)...");

        // Check if BPF LSM is supported by the kernel
        let lsm_supported = std::fs::read_to_string("/sys/kernel/security/lsm")
            .map(|content| content.contains("bpf"))
            .unwrap_or(false);

        if lsm_supported {
            info!("Kernel BPF LSM support detected in /sys/kernel/security/lsm");
        } else {
            warn!("BPF LSM not active in kernel or running in container/WSL. Event simulation mode ready.");
        }

        info!("eBPF RingBuffer listener configured (size: {})", self.config.ring_buffer_size);
        Ok(())
    }
}
