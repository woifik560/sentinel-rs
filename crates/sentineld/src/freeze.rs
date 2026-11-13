//! Freeze & Inspect Orchestrator.
//!
//! Manages process freezing (`SIGSTOP`), unfreezing (`SIGCONT`), and termination (`SIGKILL`)
//! with strict Fail-Closed timeouts (30s) as defined in ТЗ section 4.1.

use nix::sys::signal::{kill, Signal};
use nix::unistd::Pid;
use std::collections::HashMap;
use std::sync::{Arc, RwLock};
use std::time::{Duration, Instant};
use tracing::{error, info, warn};

use sentinel_common::ipc::{PromptAction, PromptVerdict};

#[derive(Debug, Clone)]
pub struct PendingPrompt {
    pub incident_id: String,
    pub tgid: u32,
    pub created_at: Instant,
    pub timeout: Duration,
}

#[derive(Clone)]
pub struct FreezeInspectOrchestrator {
    timeout: Duration,
    frozen_processes: Arc<RwLock<HashMap<u32, Instant>>>,
    pending_prompts: Arc<RwLock<HashMap<String, PendingPrompt>>>,
}

impl FreezeInspectOrchestrator {
    pub fn new(timeout_secs: u64) -> Self {
        Self {
            timeout: Duration::from_secs(timeout_secs),
            frozen_processes: Arc::new(RwLock::new(HashMap::new())),
            pending_prompts: Arc::new(RwLock::new(HashMap::new())),
        }
    }

    /// Freeze a process using SIGSTOP.
    pub fn freeze(&self, tgid: u32) -> anyhow::Result<()> {
        info!("Sending SIGSTOP to freeze TGID {}", tgid);
        let pid = Pid::from_raw(tgid as i32);
        kill(pid, Signal::SIGSTOP)
            .map_err(|e| anyhow::anyhow!("Failed to send SIGSTOP to TGID {}: {}", tgid, e))?;

        let mut map = self.frozen_processes.write().unwrap();
        map.insert(tgid, Instant::now());
        Ok(())
    }

    /// Unfreeze a process using SIGCONT.
    pub fn unfreeze(&self, tgid: u32) -> anyhow::Result<()> {
        info!("Sending SIGCONT to unfreeze TGID {}", tgid);
        let pid = Pid::from_raw(tgid as i32);
        kill(pid, Signal::SIGCONT)
            .map_err(|e| anyhow::anyhow!("Failed to send SIGCONT to TGID {}: {}", tgid, e))?;

        let mut map = self.frozen_processes.write().unwrap();
        map.remove(&tgid);
        Ok(())
    }

    /// Kill a rogue process with SIGKILL.
    pub fn terminate(&self, tgid: u32) -> anyhow::Result<()> {
        error!("Sending SIGKILL to terminate malicious TGID {}", tgid);
        let pid = Pid::from_raw(tgid as i32);
        kill(pid, Signal::SIGKILL)
            .map_err(|e| anyhow::anyhow!("Failed to send SIGKILL to TGID {}: {}", tgid, e))?;

        let mut map = self.frozen_processes.write().unwrap();
        map.remove(&tgid);
        Ok(())
    }

    /// Register a pending interactive prompt for a frozen process.
    pub fn register_prompt(&self, incident_id: String, tgid: u32) {
        let prompt = PendingPrompt {
            incident_id: incident_id.clone(),
            tgid,
            created_at: Instant::now(),
            timeout: self.timeout,
        };
        let mut map = self.pending_prompts.write().unwrap();
        map.insert(incident_id, prompt);
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
                self.terminate(prompt.tgid)?;
            }
            PromptAction::DenyOnce => {
                info!("Denied once for TGID {}", prompt.tgid);
                let _ = self.unfreeze(prompt.tgid);
            }
            PromptAction::AllowOnce | PromptAction::AllowProcess | PromptAction::AllowAppScope => {
                info!("Allowing and unfreezing TGID {}", prompt.tgid);
                self.unfreeze(prompt.tgid)?;
            }
        }

        Ok(())
    }

    /// Check and expire timed out prompts (Fail-Closed).
    pub fn check_timeouts(&self) -> Vec<u32> {
        let mut expired_tgids = Vec::new();
        let mut to_remove = Vec::new();

        {
            let map = self.pending_prompts.read().unwrap();
            let now = Instant::now();
            for (id, prompt) in map.iter() {
                if now.duration_since(prompt.created_at) >= prompt.timeout {
                    to_remove.push((id.clone(), prompt.tgid));
                }
            }
        }

        if !to_remove.is_empty() {
            let mut map = self.pending_prompts.write().unwrap();
            for (id, tgid) in to_remove {
                map.remove(&id);
                expired_tgids.push(tgid);
                warn!(
                    "Prompt {} for TGID {} timed out. Enforcing Fail-Closed!",
                    id, tgid
                );
            }
        }

        for tgid in &expired_tgids {
            let _ = self.terminate(*tgid);
        }

        expired_tgids
    }

    /// Number of currently frozen processes.
    pub fn frozen_count(&self) -> usize {
        let map = self.frozen_processes.read().unwrap();
        map.len()
    }
}
