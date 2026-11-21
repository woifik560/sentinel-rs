//! Netfilter nftables rule lifecycle management and transactional isolation.

use std::net::IpAddr;
use std::path::{Path, PathBuf};
use std::process::Command;
use serde::{Deserialize, Serialize};
use tracing::{error, info, warn};
use sentinel_common::events::SENTINEL_NFQUEUE_NUM;

/// Network isolation security tiers.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum IsolationTier {
    /// Normal operation, no host-wide isolation.
    None,
    /// Block specific malicious sockets, ports, or processes.
    Selective,
    /// Allow only critical infrastructure: DNS, Sentinel C2, loopback, and established SSH from trusted subnets.
    Restricted,
    /// Complete emergency isolation: only loopback and rescue SSH recovery channel permitted.
    FullIsolation,
}

pub struct NftablesManager;

impl NftablesManager {
    /// Locate the `nft` binary on the system.
    pub fn nft_bin() -> PathBuf {
        if Path::new("/usr/sbin/nft").exists() {
            PathBuf::from("/usr/sbin/nft")
        } else if Path::new("/sbin/nft").exists() {
            PathBuf::from("/sbin/nft")
        } else {
            PathBuf::from("nft")
        }
    }

    /// Execute an nft command with captured output and error reporting.
    pub fn run_nft(args: &[&str]) -> anyhow::Result<()> {
        let bin = Self::nft_bin();
        let output = Command::new(&bin)
            .args(args)
            .output()
            .map_err(|e| anyhow::anyhow!("Failed to execute '{} {:?}': {}", bin.display(), args, e))?;

        if !output.status.success() {
            let stderr = String::from_utf8_lossy(&output.stderr);
            anyhow::bail!(
                "nft command failed (exit code {:?}): {}",
                output.status.code(),
                stderr.trim()
            );
        }
        Ok(())
    }

    /// Execute an atomic batch script of nft commands via stdin (`nft -f -`).
    /// All rules are applied in a single kernel transaction without flushing foreign tables!
    pub fn run_nft_batch(batch_script: &str) -> anyhow::Result<()> {
        let bin = Self::nft_bin();
        let mut child = Command::new(&bin)
            .arg("-f")
            .arg("-")
            .stdin(std::process::Stdio::piped())
            .stdout(std::process::Stdio::piped())
            .stderr(std::process::Stdio::piped())
            .spawn()
            .map_err(|e| anyhow::anyhow!("Failed to spawn '{} -f -': {}", bin.display(), e))?;

        if let Some(mut stdin) = child.stdin.take() {
            use std::io::Write;
            stdin.write_all(batch_script.as_bytes())?;
        }

        let output = child.wait_with_output()?;
        if !output.status.success() {
            let stderr = String::from_utf8_lossy(&output.stderr);
            anyhow::bail!(
                "nft atomic batch failed (exit code {:?}): {}",
                output.status.code(),
                stderr.trim()
            );
        }
        Ok(())
    }

    /// Configure kernel nftables rules for diverting SO_MARK traffic to NFQUEUE atomically.
    pub fn setup_rules(use_bypass: bool) -> anyhow::Result<()> {
        info!(
            "Configuring hardened nftables hook for Sentinel SO_MARK -> NFQUEUE ({}, bypass={})",
            SENTINEL_NFQUEUE_NUM, use_bypass
        );

        let bypass_flag = if use_bypass { " bypass" } else { "" };
        let batch = format!(
            "add table inet sentinel\n\
             add chain inet sentinel output {{ type filter hook output priority 0; policy accept; }}\n\
             add rule inet sentinel output meta mark & 0xff800000 == 0x5e800000 counter queue num {}{}\n\
             add rule inet sentinel output ct state established,related accept\n\
             add rule inet sentinel output ct state new meta mark & 0xff800000 == 0x5e000000 counter queue num {}{}\n",
            SENTINEL_NFQUEUE_NUM, bypass_flag, SENTINEL_NFQUEUE_NUM, bypass_flag
        );

        Self::run_nft_batch(&batch)?;
        info!("nftables rules applied atomically in table inet sentinel.");
        Ok(())
    }

    /// Atomically applies an isolation tier without touching Docker, Kubernetes, or UFW tables.
    pub fn apply_isolation_tier(tier: IsolationTier, trusted_ssh_ips: &[String]) -> anyhow::Result<()> {
        info!("Applying atomic network isolation tier: {:?}", tier);

        match tier {
            IsolationTier::None => {
                // Restore standard NFQUEUE filtering
                Self::setup_rules(true)?;
            }
            IsolationTier::Selective => {
                // Keep base table intact
                Self::setup_rules(true)?;
            }
            IsolationTier::Restricted => {
                let mut ssh_accept_rules = String::new();
                for ip in trusted_ssh_ips {
                    if let Ok(parsed) = ip.parse::<IpAddr>() {
                        match parsed {
                            IpAddr::V4(v4) => {
                                ssh_accept_rules.push_str(&format!(
                                    "add rule inet sentinel output ip daddr {} tcp dport 22 ct state established,related accept\n",
                                    v4
                                ));
                            }
                            IpAddr::V6(v6) => {
                                ssh_accept_rules.push_str(&format!(
                                    "add rule inet sentinel output ip6 daddr {} tcp dport 22 ct state established,related accept\n",
                                    v6
                                ));
                            }
                        }
                    }
                }

                let batch = format!(
                    "add table inet sentinel\n\
                     flush table inet sentinel\n\
                     add chain inet sentinel output {{ type filter hook output priority -10; policy drop; }}\n\
                     add rule inet sentinel output oif \"lo\" accept\n\
                     add rule inet sentinel output ct state established,related accept\n\
                     add rule inet sentinel output udp dport 53 accept\n\
                     add rule inet sentinel output tcp dport 53 accept\n\
                     {}\
                     add rule inet sentinel output tcp dport 22 ct state established,related accept\n",
                    ssh_accept_rules
                );

                Self::run_nft_batch(&batch)?;
            }
            IsolationTier::FullIsolation => {
                // Emergency Host Containment: preserve only loopback and rescue SSH sessions
                let batch =
                    "add table inet sentinel\n\
                     flush table inet sentinel\n\
                     add chain inet sentinel input {{ type filter hook input priority -10; policy drop; }}\n\
                     add chain inet sentinel output {{ type filter hook output priority -10; policy drop; }}\n\
                     add rule inet sentinel input iif \"lo\" accept\n\
                     add rule inet sentinel output oif \"lo\" accept\n\
                     add rule inet sentinel input tcp dport 22 ct state established,related accept\n\
                     add rule inet sentinel output tcp sport 22 ct state established,related accept\n";

                Self::run_nft_batch(batch)?;
            }
        }

        Ok(())
    }

    /// Block a specific destination IP address via nftables with strict IP validation.
    pub fn block_ip(ip: &str) {
        let ip_parsed = match ip.parse::<IpAddr>() {
            Ok(addr) => addr,
            Err(e) => {
                warn!("Refusing to block invalid IP address '{}': {}", ip, e);
                return;
            }
        };

        info!("Blocking malicious destination IP in nftables: {}", ip_parsed);
        let rule = match ip_parsed {
            IpAddr::V4(v4) => format!("insert rule inet sentinel output ip daddr {} drop\n", v4),
            IpAddr::V6(v6) => format!("insert rule inet sentinel output ip6 daddr {} drop\n", v6),
        };

        let batch = format!(
            "add table inet sentinel\n\
             add chain inet sentinel output {{ type filter hook output priority 0; policy accept; }}\n\
             {}",
            rule
        );

        if let Err(e) = Self::run_nft_batch(&batch) {
            error!("Failed to block IP in nftables: {}", e);
        }
    }

    /// Clean up Sentinel rules by deleting table inet sentinel.
    /// CRITICAL: NEVER executes `nft flush ruleset`!
    pub fn cleanup_rules() {
        info!("Cleaning up Sentinel nftables rules (table inet sentinel only)");
        if let Err(e) = Self::run_nft(&["delete", "table", "inet", "sentinel"]) {
            warn!("Failed to delete table inet sentinel (may not exist): {}", e);
        }
    }
}
