//! Host-level containment and incident isolation state.

use super::network_block::NetworkBlockManager;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use tracing::info;

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

    pub fn isolate_host(&self) -> anyhow::Result<()> {
        self.network_blocks.set_host_containment(true)?;
        self.active.store(true, Ordering::SeqCst);
        info!("Host containment activated.");
        Ok(())
    }

    pub fn release_host(&self) -> anyhow::Result<()> {
        self.network_blocks.set_host_containment(false)?;
        self.active.store(false, Ordering::SeqCst);
        info!("Host containment released.");
        Ok(())
    }

    pub fn is_isolated(&self) -> bool {
        self.active.load(Ordering::SeqCst)
    }
}
