//! Netfilter nftables rule lifecycle management and transactional isolation.

use sentinel_common::events::SENTINEL_NFQUEUE_NUM;
use serde::{Deserialize, Serialize};
use std::net::IpAddr;
use std::path::{Path, PathBuf};
use std::process::Command;
use tracing::{error, info, warn};

/// Network isolation security tiers.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum IsolationTier {
    /// Normal operation, no host-wide isolation.
    None,
    /// Block specific malicious sockets, ports, or processes via sets.
    Selective,
    /// Allow only critical infrastructure: DNS, Sentinel C2, loopback, and established SSH from trusted subnets.
    Restricted,
    /// Complete emergency isolation: only loopback and rescue SSH recovery channel permitted.
    FullIsolation,
}

/// Explicit targets for Selective network isolation.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct SelectivePolicy {
    pub blocked_ips: Vec<IpAddr>,
    pub blocked_ports: Vec<u16>,
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
        let output = Command::new(&bin).args(args).output().map_err(|e| {
            anyhow::anyhow!("Failed to execute '{} {:?}': {}", bin.display(), args, e)
        })?;

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

    /// Pre-validates nftables ruleset syntax before applying (`nft -c -f -`).
    pub fn validate_ruleset_syntax(batch_script: &str) -> anyhow::Result<()> {
        let bin = Self::nft_bin();
        let mut child = Command::new(&bin)
            .arg("-c")
            .arg("-f")
            .arg("-")
            .stdin(std::process::Stdio::piped())
            .stdout(std::process::Stdio::piped())
            .stderr(std::process::Stdio::piped())
            .spawn()
            .map_err(|e| {
                anyhow::anyhow!(
                    "Failed to spawn syntax check '{} -c -f -': {}",
                    bin.display(),
                    e
                )
            })?;

        if let Some(mut stdin) = child.stdin.take() {
            use std::io::Write;
            stdin.write_all(batch_script.as_bytes())?;
        }

        let output = child.wait_with_output()?;
        if !output.status.success() {
            let stderr = String::from_utf8_lossy(&output.stderr);
            anyhow::bail!(
                "nft ruleset syntax validation failed (exit code {:?}): {}",
                output.status.code(),
                stderr.trim()
            );
        }
        Ok(())
    }

    /// Execute an atomic batch script of nft commands via stdin (`nft -f -`).
    /// All rules are applied in a single kernel transaction without flushing foreign tables!
    pub fn run_nft_batch(batch_script: &str) -> anyhow::Result<()> {
        // Step 1: Pre-validate syntax before touching kernel netfilter state
        Self::validate_ruleset_syntax(batch_script)?;

        // Step 2: Privilege separation - delegate to privileged helper if available
        let priv_client = sentinel_privileged::client::PrivilegedClient::default();
        if priv_client.is_available() {
            info!("Privilege separation: delegating nftables batch to sentinel-privileged helper via /run/sentinel/privileged.sock");
            match priv_client.execute_sync(&sentinel_privileged::PrivilegedOp::ApplyNftablesBatch {
                batch: batch_script.to_string(),
            }) {
                Ok(sentinel_privileged::PrivilegedResult::Ok(_)) => {
                    info!("Privileged helper successfully applied nftables batch.");
                    return Ok(());
                }
                Ok(sentinel_privileged::PrivilegedResult::Error { code, message }) => {
                    warn!("Privileged helper returned error ({code}): {message}. Attempting direct fallback if capabilities permit.");
                }
                Err(e) => {
                    warn!("Failed to communicate with privileged helper: {e}. Falling back to direct execution.");
                }
            }
        } else {
            info!("Privileged helper not available at /run/sentinel/privileged.sock. Executing nft directly.");
        }

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

    /// Configure kernel nftables rules for diverting SO_MARK traffic to NFQUEUE atomically and idempotently.
    pub fn setup_rules(use_bypass: bool) -> anyhow::Result<()> {
        info!(
            "Configuring hardened nftables hook for Sentinel SO_MARK -> NFQUEUE ({}, bypass={})",
            SENTINEL_NFQUEUE_NUM, use_bypass
        );

        let bypass_flag = if use_bypass { " bypass" } else { "" };
        let batch = format!(
            "add table inet sentinel\n\
             delete table inet sentinel\n\
             add table inet sentinel\n\
             add chain inet sentinel input {{ type filter hook input priority 0; policy accept; }}\n\
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

    /// Generates a valid atomic nftables configuration script for the requested isolation tier.
    pub fn generate_isolation_script(tier: IsolationTier, trusted_ssh_ips: &[String]) -> String {
        Self::generate_isolation_script_with_policy(
            tier,
            trusted_ssh_ips,
            &SelectivePolicy::default(),
        )
    }

    /// Generates isolation ruleset with optional granular selective policy targets.
    pub fn generate_isolation_script_with_policy(
        tier: IsolationTier,
        trusted_ssh_ips: &[String],
        selective_policy: &SelectivePolicy,
    ) -> String {
        match tier {
            IsolationTier::None => {
                let bypass_flag = " bypass";
                format!(
                    "add table inet sentinel\n\
                     delete table inet sentinel\n\
                     add table inet sentinel\n\
                     add set inet sentinel blocked_v4 {{ type ipv4_addr; }}\n\
                     add set inet sentinel blocked_v6 {{ type ipv6_addr; }}\n\
                     add chain inet sentinel input {{ type filter hook input priority 0; policy accept; }}\n\
                     add chain inet sentinel output {{ type filter hook output priority 0; policy accept; }}\n\
                     add rule inet sentinel output oif lo accept\n\
                     add rule inet sentinel output ip daddr @blocked_v4 counter drop\n\
                     add rule inet sentinel output ip6 daddr @blocked_v6 counter drop\n\
                     add rule inet sentinel output ct state established,related accept\n\
                     add rule inet sentinel output meta mark & 0xff800000 == 0x5e800000 counter queue num {}{}\n\
                     add rule inet sentinel output ct state new meta mark & 0xff800000 == 0x5e000000 counter queue num {}{}\n",
                    SENTINEL_NFQUEUE_NUM, bypass_flag, SENTINEL_NFQUEUE_NUM, bypass_flag
                )
            }
            IsolationTier::Selective => {
                let mut set_elements = String::new();
                for ip in &selective_policy.blocked_ips {
                    match ip {
                        IpAddr::V4(v4) => set_elements.push_str(&format!(
                            "add element inet sentinel blocked_v4 {{ {} }}\n",
                            v4
                        )),
                        IpAddr::V6(v6) => set_elements.push_str(&format!(
                            "add element inet sentinel blocked_v6 {{ {} }}\n",
                            v6
                        )),
                    }
                }
                let mut port_rules = String::new();
                for port in &selective_policy.blocked_ports {
                    port_rules.push_str(&format!(
                        "add rule inet sentinel output tcp dport {} counter drop\n\
                         add rule inet sentinel output udp dport {} counter drop\n",
                        port, port
                    ));
                }

                format!(
                    "add table inet sentinel\n\
                     delete table inet sentinel\n\
                     add table inet sentinel\n\
                     add set inet sentinel blocked_v4 {{ type ipv4_addr; }}\n\
                     add set inet sentinel blocked_v6 {{ type ipv6_addr; }}\n\
                     {}\
                     add chain inet sentinel input {{ type filter hook input priority 0; policy accept; }}\n\
                     add chain inet sentinel output {{ type filter hook output priority 0; policy accept; }}\n\
                     add rule inet sentinel output oif lo accept\n\
                     add rule inet sentinel output ip daddr @blocked_v4 counter drop\n\
                     add rule inet sentinel output ip6 daddr @blocked_v6 counter drop\n\
                     {}\
                     add rule inet sentinel output ct state established,related accept\n\
                     add rule inet sentinel output meta mark & 0xff800000 == 0x5e800000 counter queue num 100 bypass\n\
                     add rule inet sentinel output ct state new meta mark & 0xff800000 == 0x5e000000 counter queue num 100 bypass\n",
                    set_elements, port_rules
                )
            }
            IsolationTier::Restricted => {
                let mut ssh_accept_rules = String::new();
                for ip in trusted_ssh_ips {
                    if let Ok(parsed) = ip.parse::<IpAddr>() {
                        match parsed {
                            IpAddr::V4(v4) => {
                                ssh_accept_rules.push_str(&format!(
                                    "add rule inet sentinel output ip daddr {} tcp dport 22 accept\n\
                                     add rule inet sentinel output ip daddr {} tcp sport 22 ct state established,related accept\n",
                                    v4, v4
                                ));
                            }
                            IpAddr::V6(v6) => {
                                ssh_accept_rules.push_str(&format!(
                                    "add rule inet sentinel output ip6 daddr {} tcp dport 22 accept\n\
                                     add rule inet sentinel output ip6 daddr {} tcp sport 22 ct state established,related accept\n",
                                    v6, v6
                                ));
                            }
                        }
                    }
                }
                format!(
                    "add table inet sentinel\n\
                     delete table inet sentinel\n\
                     add table inet sentinel\n\
                     add chain inet sentinel input {{ type filter hook input priority 0; policy accept; }}\n\
                     add chain inet sentinel output {{ type filter hook output priority 0; policy drop; }}\n\
                     add rule inet sentinel output oif lo accept\n\
                     add rule inet sentinel output udp dport 53 accept\n\
                     add rule inet sentinel output tcp dport 53 accept\n\
                     add rule inet sentinel output tcp sport 22 ct state established,related accept\n\
                     {}",
                    ssh_accept_rules
                )
            }
            IsolationTier::FullIsolation => {
                let mut trusted_rules = String::new();
                for ip in trusted_ssh_ips {
                    if let Ok(parsed) = ip.parse::<IpAddr>() {
                        match parsed {
                            IpAddr::V4(v4) => {
                                trusted_rules.push_str(&format!(
                                    "add rule inet sentinel input ip saddr {} tcp dport 22 accept\n\
                                     add rule inet sentinel output ip daddr {} tcp sport 22 ct state established,related accept\n",
                                    v4, v4
                                ));
                            }
                            IpAddr::V6(v6) => {
                                trusted_rules.push_str(&format!(
                                    "add rule inet sentinel input ip6 saddr {} tcp dport 22 accept\n\
                                     add rule inet sentinel output ip6 daddr {} tcp sport 22 ct state established,related accept\n",
                                    v6, v6
                                ));
                            }
                        }
                    }
                }
                format!(
                    "add table inet sentinel\n\
                     delete table inet sentinel\n\
                     add table inet sentinel\n\
                     add chain inet sentinel input {{ type filter hook input priority 0; policy drop; }}\n\
                     add chain inet sentinel output {{ type filter hook output priority 0; policy drop; }}\n\
                     add rule inet sentinel input iif lo accept\n\
                     add rule inet sentinel output oif lo accept\n\
                     add rule inet sentinel input tcp dport 22 ct state established,related accept\n\
                     add rule inet sentinel output tcp sport 22 ct state established,related accept\n\
                     {}",
                    trusted_rules
                )
            }
        }
    }

    /// Atomically applies an isolation tier without touching Docker, Kubernetes, or UFW tables.
    /// Provides automatic rollback on failure to prevent leaving half-configured firewall states.
    pub fn apply_isolation_tier(
        tier: IsolationTier,
        trusted_ssh_ips: &[String],
    ) -> anyhow::Result<()> {
        info!("Applying atomic network isolation tier: {:?}", tier);
        let batch = Self::generate_isolation_script(tier, trusted_ssh_ips);
        let res = Self::run_nft_batch(&batch);
        if let Err(ref e) = res {
            error!(
                "Failed to apply isolation tier {:?}: {}. Attempting rollback to default rules...",
                tier, e
            );
            if tier != IsolationTier::None {
                let _ = Self::setup_rules(true);
            }
        }
        res
    }

    /// Block a specific destination IP address via nftables with strict IP validation.
    pub fn block_ip(ip: &str) -> anyhow::Result<()> {
        let ip_parsed = ip
            .parse::<IpAddr>()
            .map_err(|e| anyhow::anyhow!("Invalid IP address '{}': {}", ip, e))?;

        info!(
            "Blocking malicious destination IP in nftables: {}",
            ip_parsed
        );
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

        Self::run_nft_batch(&batch)
    }

    /// Clean up Sentinel rules by deleting table inet sentinel.
    /// CRITICAL: NEVER executes `nft flush ruleset`!
    pub fn cleanup_rules() {
        info!("Cleaning up Sentinel nftables rules (table inet sentinel only)");
        if let Err(e) = Self::run_nft(&["delete", "table", "inet", "sentinel"]) {
            warn!(
                "Failed to delete table inet sentinel (may not exist): {}",
                e
            );
        }
    }
}
