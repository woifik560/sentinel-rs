//! Central Network Protection and Transactional Isolation Manager.

use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::Arc;
use std::time::Duration;
use tokio::sync::RwLock;
use tracing::{info, warn};

use crate::response::NetworkBlockManager;
use super::connection_tracker::ConnectionTracker;
use super::nfqueue::NfqueueManager;
use super::nftables::{IsolationTier, NftablesManager};
use super::policy::NeverFreezeChecker;

/// Manages host network protection, NFQUEUE packet triage, and transactional isolation.
#[derive(Clone)]
pub struct NetworkProtectionManager {
    pub nfqueue: Arc<NfqueueManager>,
    pub tracker: Arc<ConnectionTracker>,
    pub never_freeze: Arc<NeverFreezeChecker>,
    pub block_manager: Arc<NetworkBlockManager>,
    pub isolation_tier: Arc<RwLock<IsolationTier>>,
    pub isolation_confirmed: Arc<AtomicBool>,
    pub isolation_timer_active: Arc<AtomicBool>,
    pub timer_expires_epoch: Arc<AtomicU64>,
}

impl NetworkProtectionManager {
    pub fn new(block_manager: Arc<NetworkBlockManager>, aggregate_window_ms: u64) -> Self {
        Self {
            nfqueue: Arc::new(NfqueueManager::new()),
            tracker: Arc::new(ConnectionTracker::new(Duration::from_millis(aggregate_window_ms))),
            never_freeze: Arc::new(NeverFreezeChecker::new()),
            block_manager,
            isolation_tier: Arc::new(RwLock::new(IsolationTier::None)),
            isolation_confirmed: Arc::new(AtomicBool::new(true)),
            isolation_timer_active: Arc::new(AtomicBool::new(false)),
            timer_expires_epoch: Arc::new(AtomicU64::new(0)),
        }
    }

    pub fn initialize(&self, use_bypass: bool) -> anyhow::Result<()> {
        NftablesManager::setup_rules(use_bypass)
    }

    pub fn shutdown(&self) {
        NftablesManager::cleanup_rules();
    }

    /// Engages transactional network isolation with an Anti-Lockout safety timer.
    ///
    /// If `timeout_secs > 0` and the operator does not call `confirm_isolation()` before the timer expires,
    /// the network isolation is automatically rolled back to prevent bricking remote servers!
    pub async fn isolate(
        &self,
        tier: IsolationTier,
        timeout_secs: u64,
        trusted_ssh_ips: Vec<String>,
    ) -> anyhow::Result<()> {
        info!(
            "Engaging network isolation tier {:?} (Anti-Lockout timeout: {}s)",
            tier, timeout_secs
        );

        // Apply rules via atomic batch transaction
        NftablesManager::apply_isolation_tier(tier, &trusted_ssh_ips)?;

        *self.isolation_tier.write().await = tier;

        if timeout_secs > 0 {
            self.isolation_confirmed.store(false, Ordering::SeqCst);
            self.isolation_timer_active.store(true, Ordering::SeqCst);

            let now = std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap_or_default()
                .as_secs();
            self.timer_expires_epoch.store(now + timeout_secs, Ordering::SeqCst);

            // Spawn Anti-Lockout auto-rollback watcher
            let confirmed = self.isolation_confirmed.clone();
            let timer_active = self.isolation_timer_active.clone();
            let tier_lock = self.isolation_tier.clone();

            tokio::spawn(async move {
                tokio::time::sleep(Duration::from_secs(timeout_secs)).await;

                if timer_active.load(Ordering::SeqCst) && !confirmed.load(Ordering::SeqCst) {
                    warn!(
                        "ANTI-LOCKOUT TIMER EXPIRED! Operator failed to confirm network isolation within {}s. \
                         Automatically rolling back network isolation to restore remote access!",
                        timeout_secs
                    );
                    let _ = NftablesManager::apply_isolation_tier(IsolationTier::None, &[]);
                    *tier_lock.write().await = IsolationTier::None;
                    timer_active.store(false, Ordering::SeqCst);
                }
            });
        } else {
            self.isolation_confirmed.store(true, Ordering::SeqCst);
            self.isolation_timer_active.store(false, Ordering::SeqCst);
        }

        Ok(())
    }

    /// Operator confirms network isolation, disarming the Anti-Lockout auto-rollback timer.
    pub async fn confirm_isolation(&self) -> anyhow::Result<bool> {
        let tier = *self.isolation_tier.read().await;
        if tier == IsolationTier::None {
            anyhow::bail!("Cannot confirm isolation: Host is not currently isolated");
        }
        if self.isolation_timer_active.swap(false, Ordering::SeqCst) {
            self.isolation_confirmed.store(true, Ordering::SeqCst);
            info!("Anti-Lockout timer disarmed: Network isolation confirmed by operator.");
            Ok(true)
        } else if self.isolation_confirmed.load(Ordering::SeqCst) {
            Ok(false) // Already confirmed
        } else {
            anyhow::bail!("No active anti-lockout timer to confirm");
        }
    }

    /// Releases network isolation immediately and restores standard traffic filtering.
    pub async fn unisolate(&self) -> anyhow::Result<()> {
        info!("Releasing network isolation");
        self.isolation_timer_active.store(false, Ordering::SeqCst);
        self.isolation_confirmed.store(true, Ordering::SeqCst);

        NftablesManager::apply_isolation_tier(IsolationTier::None, &[])?;
        *self.isolation_tier.write().await = IsolationTier::None;
        Ok(())
    }

    /// Returns current isolation status details.
    pub async fn get_status(&self) -> serde_json::Value {
        let tier = *self.isolation_tier.read().await;
        let is_timed = self.isolation_timer_active.load(Ordering::SeqCst);
        let confirmed = self.isolation_confirmed.load(Ordering::SeqCst);
        let expires_epoch = self.timer_expires_epoch.load(Ordering::SeqCst);
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs();
        let remaining_secs = if is_timed && expires_epoch > now {
            expires_epoch - now
        } else {
            0
        };

        serde_json::json!({
            "isolation_tier": format!("{:?}", tier),
            "is_isolated": tier != IsolationTier::None,
            "timer_active": is_timed,
            "confirmed": confirmed,
            "remaining_rollback_secs": remaining_secs,
        })
    }
}
