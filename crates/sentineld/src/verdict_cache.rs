//! Persistent and session verdict caching tied to binary cryptographic identity.
//!
//! Enforces that user decisions (AllowOnce, AllowProcess, AllowAppScope, DenyOnce)
//! are bound strictly to `(binary_path, binary_sha256, is_tainted, destination)`.
//! If the binary is modified, replaced, or tampered on disk, its SHA-256 changes,
//! automatically invalidating the decision cache and forcing re-verification.

use std::collections::HashMap;
use std::path::{Path, PathBuf};
use std::sync::{Arc, RwLock};
use std::time::Instant;
use sentinel_common::ipc::PromptAction;

type VerdictKey = (PathBuf, String, bool, String);

#[derive(Clone, Default)]
pub struct VerdictDecisionCache {
    cache: Arc<RwLock<HashMap<VerdictKey, (PromptAction, Instant)>>>,
}

impl VerdictDecisionCache {
    pub fn new() -> Self {
        Self::default()
    }

    /// Store a user verdict decision bound to binary SHA-256.
    pub fn record_decision(
        &self,
        exe_path: PathBuf,
        sha256: String,
        is_tainted: bool,
        destination: String,
        action: PromptAction,
    ) {
        let key = (exe_path, sha256, is_tainted, destination);
        let mut map = self.cache.write().unwrap();
        map.insert(key, (action, Instant::now()));
    }

    /// Check if a valid decision exists for this exact binary binary hash and destination.
    pub fn get_decision(
        &self,
        exe_path: &Path,
        sha256: &str,
        is_tainted: bool,
        destination: &str,
    ) -> Option<PromptAction> {
        let key = (
            exe_path.to_path_buf(),
            sha256.to_string(),
            is_tainted,
            destination.to_string(),
        );
        let map = self.cache.read().unwrap();
        map.get(&key).map(|(act, _)| act.clone())
    }

    /// Invalidate all cached decisions for an executable path when it is overwritten.
    pub fn invalidate_path(&self, exe_path: &Path) {
        let mut map = self.cache.write().unwrap();
        map.retain(|(p, _, _, _), _| p != exe_path);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_verdict_cache_invalidation_on_hash_change() {
        let cache = VerdictDecisionCache::new();
        let path = PathBuf::from("/usr/bin/curl");
        let hash_original = "1111222233334444555566667777888899990000111122223333444455556666";
        let hash_tampered = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";

        cache.record_decision(
            path.clone(),
            hash_original.to_string(),
            false,
            "93.184.216.34".to_string(),
            PromptAction::AllowProcess,
        );

        // Original binary matches
        assert_eq!(
            cache.get_decision(&path, hash_original, false, "93.184.216.34"),
            Some(PromptAction::AllowProcess)
        );

        // If binary is modified on disk -> cache MISS! Requires re-verification!
        assert_eq!(
            cache.get_decision(&path, hash_tampered, false, "93.184.216.34"),
            None
        );
    }
}
