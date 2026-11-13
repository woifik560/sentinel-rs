//! Trust On First Use (TOFU) manager for binaries outside the system package manager (dpkg).
//!
//! Applies to user-compiled code (~/.cargo/bin, Go, local builds), Flatpak applications,
//! AppImages, and third-party binaries to eliminate Alert Fatigue while maintaining
//! cryptographic tampering detection.

use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::fs;
use std::path::{Path, PathBuf};
use std::sync::{Arc, RwLock};
use std::time::{SystemTime, UNIX_EPOCH};
use tracing::{info, warn};

/// Result of evaluating a binary against the TOFU database.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum TofuCheckResult {
    /// Binary recorded for the first time; baseline SHA-256 established.
    NewRegistered { sha256: String },
    /// Binary verified against previously recorded baseline SHA-256.
    Verified { sha256: String },
    /// Cryptographic mismatch! Binary was rewritten or injected after first baseline.
    Tampered { expected: String, actual: String },
}

/// A recorded entry in the TOFU database.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TofuEntry {
    pub path: PathBuf,
    pub sha256: String,
    pub first_seen_unix: u64,
    pub last_seen_unix: u64,
    pub execution_count: u64,
}

#[derive(Clone)]
pub struct TofuManager {
    db_path: PathBuf,
    entries: Arc<RwLock<HashMap<PathBuf, TofuEntry>>>,
}

impl TofuManager {
    pub fn new<P: AsRef<Path>>(db_path: P) -> Self {
        let path = db_path.as_ref().to_path_buf();
        let entries = Self::load_db(&path).unwrap_or_default();
        Self {
            db_path: path,
            entries: Arc::new(RwLock::new(entries)),
        }
    }

    /// Check if a binary path qualifies as a non-dpkg external application.
    pub fn is_non_dpkg_target(path: &Path) -> bool {
        let s = path.to_string_lossy();
        s.contains("/.cargo/bin/")
            || s.contains("/.local/bin/")
            || s.contains("/.local/share/flatpak/")
            || s.contains("/var/lib/flatpak/")
            || s.ends_with(".AppImage")
            || s.contains("/go/bin/")
            || s.starts_with("/opt/")
    }

    /// Evaluate binary against TOFU database using its current SHA-256.
    pub fn check_or_register(&self, path: &Path, current_sha256: &str) -> TofuCheckResult {
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs();

        let mut map = self.entries.write().unwrap();

        if let Some(entry) = map.get_mut(path) {
            if entry.sha256.eq_ignore_ascii_case(current_sha256) {
                entry.last_seen_unix = now;
                entry.execution_count += 1;
                TofuCheckResult::Verified {
                    sha256: entry.sha256.clone(),
                }
            } else {
                warn!(
                    "TOFU TAMPER DETECTED: Binary {} hash changed from {} to {}",
                    path.display(),
                    entry.sha256,
                    current_sha256
                );
                TofuCheckResult::Tampered {
                    expected: entry.sha256.clone(),
                    actual: current_sha256.to_string(),
                }
            }
        } else {
            info!(
                "TOFU: Recording first-use baseline for non-dpkg binary {}: {}",
                path.display(),
                current_sha256
            );
            let entry = TofuEntry {
                path: path.to_path_buf(),
                sha256: current_sha256.to_string(),
                first_seen_unix: now,
                last_seen_unix: now,
                execution_count: 1,
            };
            map.insert(path.to_path_buf(), entry);
            drop(map);
            self.save_db();
            TofuCheckResult::NewRegistered {
                sha256: current_sha256.to_string(),
            }
        }
    }

    fn load_db(path: &Path) -> Option<HashMap<PathBuf, TofuEntry>> {
        if !path.exists() {
            return None;
        }
        let data = fs::read_to_string(path).ok()?;
        serde_json::from_str(&data).ok()
    }

    fn save_db(&self) {
        if let Some(parent) = self.db_path.parent() {
            let _ = fs::create_dir_all(parent);
        }
        let map = self.entries.read().unwrap();
        if let Ok(json) = serde_json::to_string_pretty(&*map) {
            let _ = fs::write(&self.db_path, json);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_tofu_registration_and_verification() {
        let temp_dir = std::env::temp_dir();
        let db_file = temp_dir.join(format!("tofu_test_{}.json", uuid::Uuid::new_v4()));
        let tofu = TofuManager::new(&db_file);

        let binary = Path::new("/home/user/.cargo/bin/my_cli");
        let hash_v1 = "abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789";

        // First run -> NewRegistered
        let res1 = tofu.check_or_register(binary, hash_v1);
        assert_eq!(
            res1,
            TofuCheckResult::NewRegistered {
                sha256: hash_v1.to_string()
            }
        );

        // Second run with same hash -> Verified
        let res2 = tofu.check_or_register(binary, hash_v1);
        assert_eq!(
            res2,
            TofuCheckResult::Verified {
                sha256: hash_v1.to_string()
            }
        );

        // Tampered run with different hash -> Tampered alert!
        let hash_tampered = "ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff";
        let res3 = tofu.check_or_register(binary, hash_tampered);
        assert_eq!(
            res3,
            TofuCheckResult::Tampered {
                expected: hash_v1.to_string(),
                actual: hash_tampered.to_string(),
            }
        );

        let _ = fs::remove_file(db_file);
    }
}
