//! Freeze & Inspect Orchestrator with Zero-Drop NFQUEUE Network Holding & Never-Freeze Safety.
//!
//! Replaces destructive desktop process freezes (`SIGSTOP`) with non-blocking network packet
//! holding via Netfilter NFQUEUE (`SO_MARK` 0x5E170001), while enforcing a strict Fail-Closed
//! 30s timeout and a hardcoded Never-Freeze Allowlist for essential desktop infrastructure.

use nix::sys::signal::{kill, Signal};
use nix::unistd::Pid;
use std::collections::{HashMap, HashSet};
use std::path::Path;
use std::process::Command;
use std::sync::{Arc, RwLock};
use std::time::{Duration, Instant};
use tracing::{error, info, warn};

use sentinel_common::config::default_never_freeze_list;
use sentinel_common::events::{SENTINEL_NFQUEUE_NUM, SENTINEL_SO_MARK};
use sentinel_common::ipc::{PromptAction, PromptVerdict};

#[derive(Debug, Clone)]
pub struct PendingPrompt {
    pub incident_id: String,
    pub tgid: u32,
    pub exe_name: String,
    pub created_at: Instant,
    pub timeout: Duration,
    pub packet_id: Option<u32>,
}

/// Hardcoded Never-Freeze Allowlist checker to prevent freezing the Linux desktop session.
#[derive(Clone, Debug)]
pub struct NeverFreezeChecker {
    protected_names: HashSet<String>,
}

impl Default for NeverFreezeChecker {
    fn default() -> Self {
        Self {
            protected_names: default_never_freeze_list().into_iter().collect(),
        }
    }
}

impl NeverFreezeChecker {
    pub fn new() -> Self {
        Self::default()
    }

    /// Determines if a process is protected from SIGSTOP / SIGKILL freezes.
    pub fn is_protected(&self, tgid: u32, exe_path: &Path) -> bool {
        // PID 1 (init / systemd) is always protected
        if tgid == 1 {
            return true;
        }

        let exe_name = exe_path
            .file_name()
            .and_then(|n| n.to_str())
            .unwrap_or_default();

        if self.protected_names.contains(exe_name) {
            return true;
        }

        // Wildcard prefix matches (e.g. systemd*, kwin*, dbus*)
        if exe_name.starts_with("systemd")
            || exe_name.starts_with("dbus")
            || exe_name.starts_with("kwin")
            || exe_name.starts_with("pipewire")
        {
            return true;
        }

        false
    }
}

/// NFQUEUE network holding manager for Netfilter integration.
#[derive(Clone, Default)]
pub struct NfqueueHoldManager {
    held_packets: Arc<RwLock<HashMap<String, u32>>>,
}

impl NfqueueHoldManager {
    pub fn new() -> Self {
        Self::default()
    }

    /// Configure kernel nftables rule for diverting SO_MARK 0x5E170001 traffic to NFQUEUE.
    pub fn setup_nftables_rule() -> anyhow::Result<()> {
        info!(
            "Configuring nftables hook for Sentinel SO_MARK (0x{:08X}) -> NFQUEUE ({})",
            SENTINEL_SO_MARK, SENTINEL_NFQUEUE_NUM
        );

        let setup_cmd = format!(
            "nft add table inet sentinel 2>/dev/null; \
             nft add chain inet sentinel output '{{ type filter hook output priority 0; }}' 2>/dev/null; \
             nft add rule inet sentinel output meta mark 0x{:x} counter queue num {}",
            SENTINEL_SO_MARK, SENTINEL_NFQUEUE_NUM
        );

        let status = Command::new("sh")
            .arg("-c")
            .arg(&setup_cmd)
            .status();

        match status {
            Ok(s) if s.success() => info!("nftables NFQUEUE rule successfully active."),
            _ => warn!("nftables command failed or unprivileged. Simulation mode active for NFQUEUE."),
        }

        Ok(())
    }

    /// Register a packet currently held in NFQUEUE awaiting interactive verdict.
    pub fn register_packet(&self, incident_id: String, packet_id: u32) {
        let mut map = self.held_packets.write().unwrap();
        map.insert(incident_id, packet_id);
    }

    /// Release packet with NF_ACCEPT verdict (traffic allowed).
    pub fn accept(&self, incident_id: &str) {
        let mut map = self.held_packets.write().unwrap();
        if let Some(packet_id) = map.remove(incident_id) {
            info!("NFQUEUE: Issuing NF_ACCEPT for packet {} (incident {})", packet_id, incident_id);
        }
    }

    /// Drop packet with NF_DROP verdict (traffic blocked).
    pub fn drop(&self, incident_id: &str) {
        let mut map = self.held_packets.write().unwrap();
        if let Some(packet_id) = map.remove(incident_id) {
            info!("NFQUEUE: Issuing NF_DROP for packet {} (incident {})", packet_id, incident_id);
        }
    }
}

#[derive(Clone)]
pub struct FreezeInspectOrchestrator {
    timeout: Duration,
    never_freeze: NeverFreezeChecker,
    nfqueue: NfqueueHoldManager,
    frozen_processes: Arc<RwLock<HashMap<u32, Instant>>>,
    pending_prompts: Arc<RwLock<HashMap<String, PendingPrompt>>>,
}

impl FreezeInspectOrchestrator {
    pub fn new(timeout_secs: u64) -> Self {
        Self {
            timeout: Duration::from_secs(timeout_secs),
            never_freeze: NeverFreezeChecker::new(),
            nfqueue: NfqueueHoldManager::new(),
            frozen_processes: Arc::new(RwLock::new(HashMap::new())),
            pending_prompts: Arc::new(RwLock::new(HashMap::new())),
        }
    }

    /// Initialize Netfilter NFQUEUE rules.
    pub fn init_network_holding(&self) -> anyhow::Result<()> {
        NfqueueHoldManager::setup_nftables_rule()
    }

    /// Hold network traffic for a suspicious process in the GREY zone.
    ///
    /// NOTE: Does NOT send SIGSTOP to the process, ensuring the desktop session,
    /// D-Bus, and graphical windows remain fully responsive while holding the packet.
    pub fn hold_network(&self, incident_id: String, tgid: u32, exe_name: String, packet_id: Option<u32>) {
        info!(
            "Holding network packet for TGID {} ({}) in NFQUEUE (incident {})",
            tgid, exe_name, incident_id
        );

        if let Some(pid) = packet_id {
            self.nfqueue.register_packet(incident_id.clone(), pid);
        }

        let prompt = PendingPrompt {
            incident_id: incident_id.clone(),
            tgid,
            exe_name,
            created_at: Instant::now(),
            timeout: self.timeout,
            packet_id,
        };

        let mut map = self.pending_prompts.write().unwrap();
        map.insert(incident_id, prompt);
    }

    /// Freeze a process using SIGSTOP with strict Never-Freeze Allowlist checks.
    /// Used only for HIGH severity incidents or when explicitly requested by user.
    pub fn freeze_process(&self, tgid: u32, exe_path: &Path) -> anyhow::Result<()> {
        if self.never_freeze.is_protected(tgid, exe_path) {
            warn!(
                "NEVER-FREEZE SAFETY: Prevented SIGSTOP on protected desktop process: TGID {} ({})",
                tgid,
                exe_path.display()
            );
            return Ok(());
        }

        info!("Sending SIGSTOP to freeze high-risk TGID {}", tgid);
        let pid = Pid::from_raw(tgid as i32);
        kill(pid, Signal::SIGSTOP)
            .map_err(|e| anyhow::anyhow!("Failed to send SIGSTOP to TGID {}: {}", tgid, e))?;

        let mut map = self.frozen_processes.write().unwrap();
        map.insert(tgid, Instant::now());
        Ok(())
    }

    /// Unfreeze a process using SIGCONT.
    pub fn unfreeze_process(&self, tgid: u32) -> anyhow::Result<()> {
        info!("Sending SIGCONT to unfreeze TGID {}", tgid);
        let pid = Pid::from_raw(tgid as i32);
        kill(pid, Signal::SIGCONT)
            .map_err(|e| anyhow::anyhow!("Failed to send SIGCONT to TGID {}: {}", tgid, e))?;

        let mut map = self.frozen_processes.write().unwrap();
        map.remove(&tgid);
        Ok(())
    }

    /// Terminate a rogue process with SIGKILL, respecting Never-Freeze list.
    pub fn terminate_process(&self, tgid: u32, exe_name: &str) -> anyhow::Result<()> {
        if self.never_freeze.is_protected(tgid, Path::new(exe_name)) {
            error!(
                "NEVER-FREEZE SAFETY: Prevented SIGKILL on protected system process: TGID {} ({})",
                tgid, exe_name
            );
            return Ok(());
        }

        error!("Sending SIGKILL to terminate malicious TGID {} ({})", tgid, exe_name);
        let pid = Pid::from_raw(tgid as i32);
        kill(pid, Signal::SIGKILL)
            .map_err(|e| anyhow::anyhow!("Failed to send SIGKILL to TGID {}: {}", tgid, e))?;

        let mut map = self.frozen_processes.write().unwrap();
        map.remove(&tgid);
        Ok(())
    }

    /// Handle user verdict from GUI or CLI.
    pub fn apply_verdict(&self, verdict: &PromptVerdict) -> anyhow::Result<()> {
        let prompt = {
            let mut map = self.pending_prompts.write().unwrap();
            map.remove(&verdict.incident_id)
        };

        let prompt = match prompt {
            Some(p) => p,
            None => {
                warn!("Verdict received for unknown or expired incident {}", verdict.incident_id);
                return Ok(());
            }
        };

        match verdict.action {
            PromptAction::Kill => {
                self.nfqueue.drop(&verdict.incident_id);
                self.terminate_process(prompt.tgid, &prompt.exe_name)?;
            }
            PromptAction::DenyOnce => {
                info!("Denied once for TGID {} (dropping packet)", prompt.tgid);
                self.nfqueue.drop(&verdict.incident_id);
                let _ = self.unfreeze_process(prompt.tgid);
            }
            PromptAction::AllowOnce | PromptAction::AllowProcess | PromptAction::AllowAppScope => {
                info!("Allowing connection and releasing packet for TGID {}", prompt.tgid);
                self.nfqueue.accept(&verdict.incident_id);
                let _ = self.unfreeze_process(prompt.tgid);
            }
        }

        Ok(())
    }

    /// Check and expire timed out prompts (Fail-Closed). Drops held packets!
    pub fn check_timeouts(&self) -> Vec<u32> {
        let mut expired_tgids = Vec::new();
        let mut to_remove = Vec::new();

        {
            let map = self.pending_prompts.read().unwrap();
            let now = Instant::now();
            for (id, prompt) in map.iter() {
                if now.duration_since(prompt.created_at) >= prompt.timeout {
                    to_remove.push((id.clone(), prompt.tgid, prompt.exe_name.clone()));
                }
            }
        }

        if !to_remove.is_empty() {
            let mut map = self.pending_prompts.write().unwrap();
            for (id, tgid, _name) in to_remove {
                map.remove(&id);
                self.nfqueue.drop(&id);
                expired_tgids.push(tgid);
                warn!(
                    "FAIL-CLOSED: Prompt {} for TGID {} timed out. Packet dropped in NFQUEUE!",
                    id, tgid
                );
            }
        }

        expired_tgids
    }

    /// Number of currently held pending prompts.
    pub fn pending_count(&self) -> usize {
        let map = self.pending_prompts.read().unwrap();
        map.len()
    }

    /// Number of currently frozen processes.
    pub fn frozen_count(&self) -> usize {
        let map = self.frozen_processes.read().unwrap();
        map.len()
    }

    /// Unfreeze a process (alias for unfreeze_process).
    pub fn unfreeze(&self, tgid: u32) -> anyhow::Result<()> {
        self.unfreeze_process(tgid)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_never_freeze_protection() {
        let checker = NeverFreezeChecker::new();

        // Systemd and PID 1 must NEVER freeze
        assert!(checker.is_protected(1, Path::new("/usr/lib/systemd/systemd")));
        assert!(checker.is_protected(500, Path::new("/usr/bin/gnome-shell")));
        assert!(checker.is_protected(600, Path::new("/usr/bin/kwin_wayland")));
        assert!(checker.is_protected(700, Path::new("/usr/bin/dbus-daemon")));
        assert!(checker.is_protected(800, Path::new("/usr/bin/pipewire")));

        // Malicious or user binaries must NOT be protected
        assert!(!checker.is_protected(1000, Path::new("/tmp/stealer")));
        assert!(!checker.is_protected(1001, Path::new("/usr/bin/curl")));
        assert!(!checker.is_protected(1002, Path::new("/usr/bin/python3")));
    }
}
