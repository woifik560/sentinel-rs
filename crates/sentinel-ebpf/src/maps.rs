//! eBPF map wrappers and definitions for in-kernel taint tracking.

use serde::{Deserialize, Serialize};
use std::collections::HashSet;
use std::sync::{Arc, RwLock};

/// Bitflags representing taint states of a TGID (thread group / process).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, Serialize, Deserialize)]
pub struct TaintFlags(pub u32);

impl TaintFlags {
    pub const NONE: u32 = 0;
    pub const TAINTED_SSH: u32 = 1 << 0;
    pub const TAINTED_GPG: u32 = 1 << 1;
    pub const TAINTED_BROWSER: u32 = 1 << 2;
    pub const TAINTED_TELEGRAM: u32 = 1 << 3;
    pub const TAINTED_CRYPTO: u32 = 1 << 4;
    pub const TAINTED_SUSPICIOUS: u32 = 1 << 5;
    pub const PENDING_INSPECT: u32 = 1 << 6;

    pub fn is_empty(&self) -> bool {
        self.0 == Self::NONE
    }

    pub fn contains(&self, flag: u32) -> bool {
        (self.0 & flag) != 0
    }

    pub fn insert(&mut self, flag: u32) {
        self.0 |= flag;
    }

    pub fn remove(&mut self, flag: u32) {
        self.0 &= !flag;
    }
}

/// Userspace manager for the in-kernel TaintMap and AllowlistMap.
#[derive(Debug, Clone, Default)]
pub struct TaintMapManager {
    /// In-memory mirror for fast access or simulated environments.
    tainted_tgids: Arc<RwLock<HashSet<u32>>>,
    allowed_tgids: Arc<RwLock<HashSet<u32>>>,
}

impl TaintMapManager {
    pub fn new() -> Self {
        Self::default()
    }

    /// Mark a TGID as tainted.
    pub fn mark_tainted(&self, tgid: u32) {
        let mut map = self.tainted_tgids.write().unwrap();
        map.insert(tgid);
    }

    /// Remove taint from a TGID (e.g. after approval / unfreeze).
    pub fn clear_taint(&self, tgid: u32) {
        let mut map = self.tainted_tgids.write().unwrap();
        map.remove(&tgid);
    }

    /// Check if a TGID is currently marked as tainted.
    pub fn is_tainted(&self, tgid: u32) -> bool {
        let map = self.tainted_tgids.read().unwrap();
        map.contains(&tgid)
    }

    /// Whitelist a specific TGID for network calls.
    pub fn allow_tgid(&self, tgid: u32) {
        let mut map = self.allowed_tgids.write().unwrap();
        map.insert(tgid);
    }

    /// Check if a TGID is in the active allowlist.
    pub fn is_allowed(&self, tgid: u32) -> bool {
        let map = self.allowed_tgids.read().unwrap();
        map.contains(&tgid)
    }

    /// Inherit taint status from parent to child process during fork.
    pub fn inherit_fork(&self, parent_tgid: u32, child_tgid: u32) {
        if self.is_tainted(parent_tgid) {
            self.mark_tainted(child_tgid);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_taint_flags() {
        let mut flags = TaintFlags::default();
        assert!(flags.is_empty());

        flags.insert(TaintFlags::TAINTED_SSH);
        assert!(flags.contains(TaintFlags::TAINTED_SSH));
        assert!(!flags.contains(TaintFlags::TAINTED_BROWSER));

        flags.insert(TaintFlags::TAINTED_BROWSER);
        assert!(flags.contains(TaintFlags::TAINTED_BROWSER));

        flags.remove(TaintFlags::TAINTED_SSH);
        assert!(!flags.contains(TaintFlags::TAINTED_SSH));
        assert!(flags.contains(TaintFlags::TAINTED_BROWSER));
    }

    #[test]
    fn test_taint_manager_fork_inheritance() {
        let mgr = TaintMapManager::new();
        mgr.mark_tainted(100);
        assert!(mgr.is_tainted(100));
        assert!(!mgr.is_tainted(200));

        mgr.inherit_fork(100, 200);
        assert!(mgr.is_tainted(200));

        mgr.clear_taint(200);
        assert!(!mgr.is_tainted(200));
        assert!(mgr.is_tainted(100));
    }
}
