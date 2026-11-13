//! Verification of executable binary ownership against Debian's dpkg database.

use std::collections::HashMap;
use std::path::{Path, PathBuf};
use std::process::Command;
use std::sync::{Arc, RwLock};
use tracing::debug;

#[derive(Clone, Default)]
pub struct DpkgChecker {
    /// In-memory cache of path -> package name (or None if unmanaged).
    cache: Arc<RwLock<HashMap<PathBuf, Option<String>>>>,
}

impl DpkgChecker {
    pub fn new() -> Self {
        Self::default()
    }

    /// Check if a binary belongs to an installed dpkg package.
    pub fn check_package<P: AsRef<Path>>(&self, path: P) -> Option<String> {
        let path = path.as_ref();
        {
            let cache = self.cache.read().unwrap();
            if let Some(cached) = cache.get(path) {
                return cached.clone();
            }
        }

        let pkg = query_dpkg(path);
        let mut cache = self.cache.write().unwrap();
        cache.insert(path.to_path_buf(), pkg.clone());
        pkg
    }
}

fn query_dpkg(path: &Path) -> Option<String> {
    let output = Command::new("dpkg")
        .arg("-S")
        .arg(path)
        .output()
        .ok()?;

    if !output.status.success() {
        return None;
    }

    let stdout = String::from_utf8_lossy(&output.stdout);
    // dpkg -S output format: "<package>: <path>" or "<package>:amd64: <path>"
    if let Some((pkg_part, _)) = stdout.split_once(':') {
        let clean_pkg = pkg_part.split(':').next().unwrap_or(pkg_part).trim();
        if !clean_pkg.is_empty() {
            debug!("dpkg matched {} -> {}", path.display(), clean_pkg);
            return Some(clean_pkg.to_string());
        }
    }

    None
}
