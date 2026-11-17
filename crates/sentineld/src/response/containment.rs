//! Host-level containment and incident isolation state.

use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use tracing::info;
use super::network_block::NetworkBlockManager;

#[derive(Clone)]
pub struct HostContainment {
    network_blocks: Arc<NetworkBlockManager>,
    active: Arc<AtomicBool>,
}

impl HostContainment {
    pub fn new(network_blocks: Arc<NetworkBlockManager>) -> Self {
        Self {
            network_blocks,
            active: Arc::new(AtomicBool::new(false)),
        }
    }

    pub fn isolate_host(&self) {
        self.active.store(true, Ordering::SeqCst);
        self.network_blocks.set_host_containment(true);
        info!("Host containment activated.");
    }

    pub fn release_host(&self) {
        self.active.store(false, Ordering::SeqCst);
        self.network_blocks.set_host_containment(false);
        info!("Host containment released.");
    }

    pub fn is_isolated(&self) -> bool {
        self.active.load(Ordering::SeqCst)
    }
}
