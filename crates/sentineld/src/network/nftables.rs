//! Netfilter nftables rule lifecycle management.

use std::process::Command;
use tracing::{info, warn};
use sentinel_common::events::SENTINEL_NFQUEUE_NUM;

pub struct NftablesManager;

impl NftablesManager {
    /// Configure kernel nftables rules for diverting SO_MARK traffic to NFQUEUE.
    pub fn setup_rules(use_bypass: bool) -> anyhow::Result<()> {
        info!(
            "Configuring hardened nftables hook for Sentinel SO_MARK -> NFQUEUE ({}, bypass={})",
            SENTINEL_NFQUEUE_NUM, use_bypass
        );

        let bypass_str = if use_bypass { " bypass" } else { "" };

        let setup_cmd = format!(
            "nft add table inet sentinel 2>/dev/null; \
             nft add chain inet sentinel output '{{ type filter hook output priority 0; }}' 2>/dev/null; \
             nft add rule inet sentinel output 'meta mark & 0xff800000 == 0x5e800000 counter queue num {}{}' 2>/dev/null; \
             nft add rule inet sentinel output 'ct state established,related accept' 2>/dev/null; \
             nft add rule inet sentinel output 'ct state new meta mark & 0xff800000 == 0x5e000000 counter queue num {}{}' 2>/dev/null",
            SENTINEL_NFQUEUE_NUM, bypass_str, SENTINEL_NFQUEUE_NUM, bypass_str
        );

        let status = Command::new("sh")
            .arg("-c")
            .arg(&setup_cmd)
            .status();

        match status {
            Ok(s) if s.success() => info!("nftables NFQUEUE rule successfully active."),
            _ => warn!("nftables command failed or unprivileged. Simulation mode active."),
        }

        Ok(())
    }

    /// Block a specific destination IP address via nftables.
    pub fn block_ip(ip: &str) {
        let cmd = format!("nft add rule inet sentinel output ip daddr {} drop 2>/dev/null", ip);
        let _ = Command::new("sh").arg("-c").arg(&cmd).status();
    }

    /// Clean up Netfilter rules upon daemon shutdown/restart.
    pub fn cleanup_rules() {
        info!("Cleaning up Sentinel nftables rules to restore normal networking...");
        let _ = Command::new("sh")
            .arg("-c")
            .arg("nft delete table inet sentinel 2>/dev/null")
            .status();
    }
}
