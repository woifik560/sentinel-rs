//! Degraded operational states detection and tracking with FailurePolicyManager.

use sentinel_common::health::AgentState;
use serde::{Deserialize, Serialize};
use std::sync::RwLock;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DegradedReason {
    pub subsystem: String,
    pub description: String,
    pub impact: String,
    pub remediation: String,
}

#[derive(Default)]
pub struct DegradedStateManager {
    active_degradations: RwLock<Vec<DegradedReason>>,
}

impl DegradedStateManager {
    pub fn new() -> Self {
        Self {
            active_degradations: RwLock::new(Vec::new()),
        }
    }

    pub fn report_degradation(&self, degradation: DegradedReason) {
        let mut list = self.active_degradations.write().unwrap();
        if !list.iter().any(|d| d.subsystem == degradation.subsystem) {
            list.push(degradation);
        }
    }

    pub fn clear_degradation(&self, subsystem: &str) {
        let mut list = self.active_degradations.write().unwrap();
        list.retain(|d| d.subsystem != subsystem);
    }

    pub fn is_degraded(&self) -> bool {
        !self.active_degradations.read().unwrap().is_empty()
    }

    pub fn get_degradations(&self) -> Vec<DegradedReason> {
        self.active_degradations.read().unwrap().clone()
    }
}

/// The failure policy manager enforces deterministic failure transitions across components:
/// - RingBuffer failure -> Degraded (telemetry drops, but network filter active)
/// - BPF LSM failure -> ProtectionUnavailable (halts blocking, alerts operator)
/// - SQLite failure -> Degraded (in-memory buffering up to limit)
/// - IPC failure -> blocks new privileged commands
pub struct FailurePolicyManager {
    current_state: RwLock<AgentState>,
    ringbuffer_failed: RwLock<bool>,
    bpf_lsm_failed: RwLock<bool>,
    sqlite_failed: RwLock<bool>,
    ipc_failed: RwLock<bool>,
}

impl Default for FailurePolicyManager {
    fn default() -> Self {
        Self::new()
    }
}

impl FailurePolicyManager {
    pub fn new() -> Self {
        Self {
            current_state: RwLock::new(AgentState::Healthy),
            ringbuffer_failed: RwLock::new(false),
            bpf_lsm_failed: RwLock::new(false),
            sqlite_failed: RwLock::new(false),
            ipc_failed: RwLock::new(false),
        }
    }

    pub fn report_ringbuffer_drop(&self) -> AgentState {
        *self.ringbuffer_failed.write().unwrap() = true;
        self.recompute_state()
    }

    pub fn report_bpf_lsm_failure(&self) -> AgentState {
        *self.bpf_lsm_failed.write().unwrap() = true;
        self.recompute_state()
    }

    pub fn report_sqlite_failure(&self) -> AgentState {
        *self.sqlite_failed.write().unwrap() = true;
        self.recompute_state()
    }

    pub fn report_ipc_failure(&self) -> AgentState {
        *self.ipc_failed.write().unwrap() = true;
        self.recompute_state()
    }

    pub fn clear_failures(&self) -> AgentState {
        *self.ringbuffer_failed.write().unwrap() = false;
        *self.bpf_lsm_failed.write().unwrap() = false;
        *self.sqlite_failed.write().unwrap() = false;
        *self.ipc_failed.write().unwrap() = false;
        self.recompute_state()
    }

    pub fn state(&self) -> AgentState {
        *self.current_state.read().unwrap()
    }

    pub fn set_state(&self, state: AgentState) {
        *self.current_state.write().unwrap() = state;
    }

    fn recompute_state(&self) -> AgentState {
        let mut state_lock = self.current_state.write().unwrap();
        if *state_lock == AgentState::Stopping || *state_lock == AgentState::Starting {
            return *state_lock;
        }

        let bpf_failed = *self.bpf_lsm_failed.read().unwrap();
        let rb_failed = *self.ringbuffer_failed.read().unwrap();
        let sqlite_failed = *self.sqlite_failed.read().unwrap();

        let new_state = if bpf_failed {
            AgentState::ProtectionUnavailable
        } else if rb_failed || sqlite_failed {
            AgentState::Degraded
        } else {
            AgentState::Healthy
        };

        *state_lock = new_state;
        new_state
    }
}
