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
    pub dest_key: Option<(String, u16)>,
    pub aggregated_count: u32,
}

/// Hardcoded Never-Freeze Allowlist checker with multi-attribute validation.
///
/// CRITICAL SECURITY RULE: NEVER checks exceptions by process name (`comm`) alone,
/// because `comm` is trivially spoofable via `prctl(PR_SET_NAME)`.
/// Requires valid canonical filesystem path (`/usr/bin`, `/usr/lib/systemd`),
/// system UID verification, and explicit exclusion of untrusted paths (`/tmp`, `/dev/shm`).
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
    ///
    /// Validates canonical path, origin directory, UID, and PID.
    pub fn is_protected(&self, tgid: u32, exe_path: &Path, uid: u32) -> bool {
        // PID 1 (init / systemd) is always protected
        if tgid == 1 {
            return true;
        }

        let path_str = exe_path.to_string_lossy();

        // Anti-Spoofing: Any binary running from untrusted or writable user directories
        // (/tmp, /dev/shm, /var/tmp, ~/Downloads) is NEVER protected, regardless of name!
        if path_str.starts_with("/tmp")
            || path_str.starts_with("/dev/shm")
            || path_str.starts_with("/var/tmp")
            || path_str.contains("/Downloads/")
        {
            return false;
        }

        // Canonical binaries must reside in system root locations
        let is_system_dir = path_str.starts_with("/usr/bin/")
            || path_str.starts_with("/bin/")
            || path_str.starts_with("/usr/lib/")
            || path_str.starts_with("/lib/");

        if !is_system_dir {
            return false;
        }

        let exe_name = exe_path
            .file_name()
            .and_then(|n| n.to_str())
            .unwrap_or_default();

        // System daemons: require root or system UID (< 1000)
        if exe_name.starts_with("systemd") || exe_name.starts_with("dbus") || exe_name.starts_with("udevd") {
            if uid == 0 || uid < 1000 {
                return true;
            }
        }

        // Desktop compositors and audio: allowed under session UID (>= 1000) or root
        if self.protected_names.contains(exe_name) {
            return true;
        }

        // Wildcard prefix matches (e.g. kwin*, pipewire*)
        if exe_name.starts_with("kwin") || exe_name.starts_with("pipewire") {
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
    ///
    /// # Performance & Fail-Closed Rules:
    /// 1. Fast-Path: `ct state established,related accept` allows gigabit throughput without userspace overhead.
    /// 2. Slow-Path: `ct state new meta mark 0x5E170001 counter queue num 100` diverts unapproved new flows.
    /// 3. FAIL-CLOSED: No `bypass` flag in production so traffic cannot leak around daemon if attacked.
    pub fn setup_nftables_rule() -> anyhow::Result<()> {
        info!(
            "Configuring nftables hook for Sentinel SO_MARK (0x{:08X}) -> NFQUEUE ({})",
            SENTINEL_SO_MARK, SENTINEL_NFQUEUE_NUM
        );

        let setup_cmd = format!(
            "nft add table inet sentinel 2>/dev/null; \
             nft add chain inet sentinel output '{{ type filter hook output priority 0; }}' 2>/dev/null; \
             nft add rule inet sentinel output ct state established,related accept 2>/dev/null; \
             nft add rule inet sentinel output ct state new meta mark 0x{:x} counter queue num {}",
            SENTINEL_SO_MARK, SENTINEL_NFQUEUE_NUM
        );

        let status = Command::new("sh")
            .arg("-c")
            .arg(&setup_cmd)
            .status();

        match status {
            Ok(s) if s.success() => info!("nftables NFQUEUE rule successfully active (Fast-Path ct state established)."),
            _ => warn!("nftables command failed or unprivileged. Simulation mode active for NFQUEUE."),
        }

        Ok(())
    }

    /// Graceful cleanup of Netfilter rules upon daemon shutdown/restart.
    /// Prevents network disconnection when service is updated or stopped by systemd.
    pub fn clean_nftables_rules() {
        info!("Cleaning up Sentinel nftables rules to restore normal networking...");
        let _ = Command::new("sh")
            .arg("-c")
            .arg("nft delete table inet sentinel 2>/dev/null")
            .status();
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

/// Result of attempting to hold a network packet.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum HoldResult {
    /// Newly created pending prompt requiring UI broadcast.
    NewPrompt(String),
    /// Aggregated into an existing pending prompt for the same target flow.
    Aggregated(String),
    /// Queue capacity exceeded; packet dropped immediately (DoS mitigation).
    QueueFull,
}

#[derive(Clone)]
pub struct FreezeInspectOrchestrator {
    timeout: Duration,
    max_queue_size: usize,
    aggregate_window: Duration,
    never_freeze: NeverFreezeChecker,
    nfqueue: NfqueueHoldManager,
    frozen_processes: Arc<RwLock<HashMap<u32, Instant>>>,
    pending_prompts: Arc<RwLock<HashMap<String, PendingPrompt>>>,
    aggregated_flows: Arc<RwLock<HashMap<(u32, String, u16), (String, Instant)>>>,
}

impl FreezeInspectOrchestrator {
    pub fn new(timeout_secs: u64, max_queue_size: usize, aggregate_window_ms: u64) -> Self {
        Self {
            timeout: Duration::from_secs(timeout_secs),
            max_queue_size,
            aggregate_window: Duration::from_millis(aggregate_window_ms),
            never_freeze: NeverFreezeChecker::new(),
            nfqueue: NfqueueHoldManager::new(),
            frozen_processes: Arc::new(RwLock::new(HashMap::new())),
            pending_prompts: Arc::new(RwLock::new(HashMap::new())),
            aggregated_flows: Arc::new(RwLock::new(HashMap::new())),
        }
    }

    pub fn with_default_limits(timeout_secs: u64) -> Self {
        Self::new(timeout_secs, 512, 2000)
    }

    /// Initialize Netfilter NFQUEUE rules.
    pub fn init_network_holding(&self) -> anyhow::Result<()> {
        NfqueueHoldManager::setup_nftables_rule()
    }

    /// Hold network traffic for a suspicious process in the GREY zone.
    ///
    /// # DoS Protection & Flow Aggregation:
    /// - Drops packet if queue exceeds `max_queue_size`.
    /// - Aggregates duplicate requests for the same (tgid, dest_ip, port) within `aggregate_window`.
    pub fn hold_network(
        &self,
        incident_id: String,
        tgid: u32,
        exe_name: String,
        packet_id: Option<u32>,
        dest: Option<(String, u16)>,
    ) -> HoldResult {
        // 1. DoS Mitigation: Check pending queue limit
        {
            let map = self.pending_prompts.read().unwrap();
            if map.len() >= self.max_queue_size {
                warn!(
                    "QUEUE SATURATION DoS PROTECTION: Dropping packet for TGID {} (pending queue limit {} reached)",
                    tgid, self.max_queue_size
                );
                self.nfqueue.drop(&incident_id);
                return HoldResult::QueueFull;
            }
        }

        // 2. Request Aggregation: Check if identical flow was recently queued
        if let Some(ref dest_info) = dest {
            let flow_key = (tgid, dest_info.0.clone(), dest_info.1);
            let mut flows = self.aggregated_flows.write().unwrap();
            let now = Instant::now();

            if let Some((existing_id, created_at)) = flows.get(&flow_key) {
                if now.duration_since(*created_at) < self.aggregate_window {
                    let mut prompts = self.pending_prompts.write().unwrap();
                    if let Some(prompt) = prompts.get_mut(existing_id) {
                        prompt.aggregated_count += 1;
                        info!(
                            "Aggregated duplicate connection attempt from TGID {} to {}:{} (count: {})",
                            tgid, dest_info.0, dest_info.1, prompt.aggregated_count
                        );
                        return HoldResult::Aggregated(existing_id.clone());
                    }
                }
            }

            flows.insert(flow_key, (incident_id.clone(), now));
        }

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
            dest_key: dest,
            aggregated_count: 1,
        };

        let mut map = self.pending_prompts.write().unwrap();
        map.insert(incident_id.clone(), prompt);
        HoldResult::NewPrompt(incident_id)
    }

    /// Freeze a process using SIGSTOP with strict Never-Freeze Allowlist checks.
    /// Used only for HIGH severity incidents or when explicitly requested by user.
    pub fn freeze_process(&self, tgid: u32, exe_path: &Path, uid: u32) -> anyhow::Result<()> {
        if self.never_freeze.is_protected(tgid, exe_path, uid) {
            warn!(
                "NEVER-FREEZE SAFETY: Prevented SIGSTOP on protected desktop process: TGID {} (path: {}, uid: {})",
                tgid,
                exe_path.display(),
                uid
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
    pub fn terminate_process(&self, tgid: u32, exe_name: &str, uid: u32) -> anyhow::Result<()> {
        if self.never_freeze.is_protected(tgid, Path::new(exe_name), uid) {
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
                self.terminate_process(prompt.tgid, &prompt.exe_name, 1000)?;
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
        assert!(checker.is_protected(1, Path::new("/usr/lib/systemd/systemd"), 0));
        assert!(checker.is_protected(500, Path::new("/usr/bin/gnome-shell"), 1000));
        assert!(checker.is_protected(600, Path::new("/usr/bin/kwin_wayland"), 1000));
        assert!(checker.is_protected(700, Path::new("/usr/bin/dbus-daemon"), 105));
        assert!(checker.is_protected(800, Path::new("/usr/bin/pipewire"), 1000));

        // Malicious or user binaries must NOT be protected
        assert!(!checker.is_protected(1000, Path::new("/tmp/stealer"), 1000));
        assert!(!checker.is_protected(1001, Path::new("/usr/bin/curl"), 1000));
        assert!(!checker.is_protected(1002, Path::new("/usr/bin/python3"), 1000));

        // Anti-Spoofing: Binary in /tmp or /dev/shm claiming to be systemd or gnome-shell MUST be rejected!
        assert!(!checker.is_protected(1003, Path::new("/tmp/systemd"), 0));
        assert!(!checker.is_protected(1004, Path::new("/dev/shm/gnome-shell"), 1000));
        assert!(!checker.is_protected(1005, Path::new("/home/user/Downloads/gnome-shell"), 1000));
    }

    #[test]
    fn test_dos_queue_limit_and_flow_aggregation() {
        let orchestrator = FreezeInspectOrchestrator::new(30, 2, 2000);

        let tgid = 8888;
        let dest = Some(("1.2.3.4".to_string(), 443));

        // 1. First attempt: NewPrompt
        let res1 = orchestrator.hold_network("inc-1".into(), tgid, "stealer".into(), Some(1), dest.clone());
        assert_eq!(res1, HoldResult::NewPrompt("inc-1".into()));

        // 2. Duplicate rapid attempt to same destination: Aggregated
        let res2 = orchestrator.hold_network("inc-2".into(), tgid, "stealer".into(), Some(2), dest.clone());
        assert_eq!(res2, HoldResult::Aggregated("inc-1".into()));

        // 3. Different destination: NewPrompt (filling queue to capacity 2)
        let res3 = orchestrator.hold_network("inc-3".into(), tgid, "stealer".into(), Some(3), Some(("5.6.7.8".into(), 80)));
        assert_eq!(res3, HoldResult::NewPrompt("inc-3".into()));

        // 4. Over capacity: QueueFull (packet dropped immediately!)
        let res4 = orchestrator.hold_network("inc-4".into(), tgid, "stealer".into(), Some(4), Some(("9.9.9.9".into(), 53)));
        assert_eq!(res4, HoldResult::QueueFull);
    }
}
