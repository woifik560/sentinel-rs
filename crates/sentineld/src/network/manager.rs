//! Central Network Protection Manager.

use std::sync::Arc;
use std::time::Duration;
use crate::response::NetworkBlockManager;
use super::connection_tracker::ConnectionTracker;
use super::nfqueue::NfqueueManager;
use super::nftables::NftablesManager;
use super::policy::NeverFreezeChecker;

#[derive(Clone)]
pub struct NetworkProtectionManager {
    pub nfqueue: Arc<NfqueueManager>,
    pub tracker: Arc<ConnectionTracker>,
    pub never_freeze: Arc<NeverFreezeChecker>,
    pub block_manager: Arc<NetworkBlockManager>,
}

impl NetworkProtectionManager {
    pub fn new(block_manager: Arc<NetworkBlockManager>, aggregate_window_ms: u64) -> Self {
        Self {
            nfqueue: Arc::new(NfqueueManager::new()),
            tracker: Arc::new(ConnectionTracker::new(Duration::from_millis(aggregate_window_ms))),
            never_freeze: Arc::new(NeverFreezeChecker::new()),
            block_manager,
        }
    }

    pub fn initialize(&self, use_bypass: bool) -> anyhow::Result<()> {
        NftablesManager::setup_rules(use_bypass)
    }

    pub fn shutdown(&self) {
        NftablesManager::cleanup_rules();
    }
}
