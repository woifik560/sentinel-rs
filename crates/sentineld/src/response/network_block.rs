//! Network isolation and blocking actions.

use std::collections::HashSet;
use std::sync::RwLock;
use tracing::{info, warn};

/// Thread-safe in-memory state of blocked IPs, ports, and processes.
pub struct NetworkBlockManager {
    blocked_pids: RwLock<HashSet<u32>>,
    blocked_ips: RwLock<HashSet<String>>,
    is_contained: RwLock<bool>,
}

impl Default for NetworkBlockManager {
    fn default() -> Self {
        Self::new()
    }
}

impl NetworkBlockManager {
    pub fn new() -> Self {
        Self {
            blocked_pids: RwLock::new(HashSet::new()),
            blocked_ips: RwLock::new(HashSet::new()),
            is_contained: RwLock::new(false),
        }
    }

    pub fn block_pid(&self, pid: u32) {
        info!("Blocking network traffic for PID {}", pid);
        self.blocked_pids.write().unwrap().insert(pid);
    }

    pub fn unblock_pid(&self, pid: u32) {
        info!("Unblocking network traffic for PID {}", pid);
        self.blocked_pids.write().unwrap().remove(&pid);
    }

    pub fn is_pid_blocked(&self, pid: u32) -> bool {
        self.blocked_pids.read().unwrap().contains(&pid)
    }

    pub fn block_ip(&self, ip: String) -> anyhow::Result<()> {
        info!("Blocking network destination IP {}", ip);
        self.blocked_ips.write().unwrap().insert(ip.clone());
        crate::network::nftables::NftablesManager::block_ip(&ip)
    }

    pub fn is_ip_blocked(&self, ip: &str) -> bool {
        self.blocked_ips.read().unwrap().contains(ip)
    }

    pub fn set_host_containment(&self, enabled: bool) -> anyhow::Result<()> {
        let mut contained = self.is_contained.write().unwrap();
        if enabled {
            warn!("EMERGENCY: Host network containment ENABLED! All outbound traffic blocked except loopback.");
            crate::network::nftables::NftablesManager::apply_isolation_tier(
                crate::network::nftables::IsolationTier::FullIsolation,
                &[],
            )?;
            *contained = true;
        } else {
            info!("Host network containment disabled. Normal network policy restored.");
            crate::network::nftables::NftablesManager::apply_isolation_tier(
                crate::network::nftables::IsolationTier::None,
                &[],
            )?;
            *contained = false;
        }
        Ok(())
    }

    pub fn is_host_contained(&self) -> bool {
        *self.is_contained.read().unwrap()
    }
}
