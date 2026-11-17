//! Degraded operational states detection and tracking.

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
