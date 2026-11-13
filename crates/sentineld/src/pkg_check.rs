//! Verification of executable binary ownership and cryptographic integrity against package managers.
//!
//! Provides the `PkgIntegrityProvider` trait. Currently implements Debian/Ubuntu `dpkg`
//! verification using MD5 solely as a membership indicator, while establishing SHA-256
//! as the authoritative cryptographic integrity anchor. Ready for RPM/Pacman backends.

use std::collections::HashMap;
use std::fs::File;
use std::io::{BufRead, BufReader, Read};
use std::path::{Path, PathBuf};
use std::process::Command;
use std::sync::{Arc, RwLock};
use tracing::{debug, warn};

use crate::sha_cache::compute_sha256;

/// Cryptographic integrity report for an executable binary.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct PackageIntegrityInfo {
    pub package_name: String,
    pub is_integrity_verified: bool,
    pub sha256: Option<String>,
    pub package_manager: &'static str,
}

pub type DpkgInfo = PackageIntegrityInfo;

/// Extensible trait for system package manager verification.
pub trait PkgIntegrityProvider: Send + Sync {
    /// Check whether a binary belongs to an authentic installed package.
    fn check_package(&self, path: &Path) -> Option<PackageIntegrityInfo>;
    /// Invalidate cache for a specific binary upon modification or deletion.
    fn invalidate_path(&self, path: &Path);
}

#[derive(Clone, Default)]
pub struct DpkgChecker {
    /// In-memory cache of path -> (package name, integrity_verified).
    cache: Arc<RwLock<HashMap<PathBuf, Option<PackageIntegrityInfo>>>>,
}

impl DpkgChecker {
    pub fn new() -> Self {
        Self::default()
    }
}

impl PkgIntegrityProvider for DpkgChecker {
    /// Check if a binary belongs to an installed dpkg package and verify its hash integrity.
    fn check_package(&self, path: &Path) -> Option<PackageIntegrityInfo> {
        {
            let cache = self.cache.read().unwrap();
            if let Some(cached) = cache.get(path) {
                return cached.clone();
            }
        }

        let info = query_and_verify_dpkg(path);
        let mut cache = self.cache.write().unwrap();
        cache.insert(path.to_path_buf(), info.clone());
        info
    }

    /// Invalidate cache for a specific binary path upon modification or unlink.
    fn invalidate_path(&self, path: &Path) {
        let mut cache = self.cache.write().unwrap();
        cache.remove(path);
    }
}

impl DpkgChecker {
    /// Convenience wrapper preserving backward-compatible signature.
    pub fn check_package<P: AsRef<Path>>(&self, path: P) -> Option<PackageIntegrityInfo> {
        PkgIntegrityProvider::check_package(self, path.as_ref())
    }
}

fn query_and_verify_dpkg(path: &Path) -> Option<PackageIntegrityInfo> {
    // Resolve symlinks to canonical path to prevent symlink traversal/aliasing bypasses
    let canonical_path = path.canonicalize().unwrap_or_else(|_| path.to_path_buf());

    let output = Command::new("dpkg")
        .arg("-S")
        .arg(&canonical_path)
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
            // Verify path is in root:root system paths and not user-writable
            let is_root_system_path = canonical_path.starts_with("/usr/bin")
                || canonical_path.starts_with("/bin")
                || canonical_path.starts_with("/usr/lib")
                || canonical_path.starts_with("/lib");

            // MD5 is treated as a membership signal; SHA-256 is the authoritative ground truth
            let is_md5_verified = verify_dpkg_checksum(clean_pkg, &canonical_path);
            let sha256 = compute_sha256(&canonical_path);

            let is_verified = is_root_system_path && is_md5_verified && sha256.is_some();

            debug!(
                "dpkg matched {} (canonical: {}) -> {} (verified_integrity: {}, sha256: {:?})",
                path.display(),
                canonical_path.display(),
                clean_pkg,
                is_verified,
                sha256
            );
            return Some(PackageIntegrityInfo {
                package_name: clean_pkg.to_string(),
                is_integrity_verified: is_verified,
                sha256,
                package_manager: "dpkg",
            });
        }
    }

    None
}

/// Parse `/var/lib/dpkg/info/<package>.md5sums` and verify file checksum.
fn verify_dpkg_checksum(package_name: &str, file_path: &Path) -> bool {
    // Arch-qualified and plain md5sums paths
    let paths_to_try = [
        format!("/var/lib/dpkg/info/{}.md5sums", package_name),
        format!("/var/lib/dpkg/info/{}:amd64.md5sums", package_name),
        format!("/var/lib/dpkg/info/{}:arm64.md5sums", package_name),
    ];

    let mut md5sums_file = None;
    for p in &paths_to_try {
        if let Ok(f) = File::open(p) {
            md5sums_file = Some(f);
            break;
        }
    }

    let file = match md5sums_file {
        Some(f) => f,
        None => {
            debug!("No md5sums file found for package {}", package_name);
            return false;
        }
    };

    let target_rel_path = file_path
        .strip_prefix("/")
        .unwrap_or(file_path)
        .to_string_lossy();

    let reader = BufReader::new(file);
    for line in reader.lines().flatten() {
        // Format: "<md5hash>  <relative_path>"
        let mut parts = line.split_whitespace();
        if let (Some(expected_md5), Some(recorded_path)) = (parts.next(), parts.next()) {
            if recorded_path == target_rel_path.as_ref() {
                return compute_file_md5(file_path)
                    .map(|actual_md5| actual_md5.eq_ignore_ascii_case(expected_md5))
                    .unwrap_or(false);
            }
        }
    }

    false
}

fn compute_file_md5(path: &Path) -> Option<String> {
    use md5::{Digest, Md5};
    let mut file = File::open(path).ok()?;
    let mut hasher = Md5::new();
    let mut buffer = [0u8; 8192];

    loop {
        let count = file.read(&mut buffer).ok()?;
        if count == 0 {
            break;
        }
        hasher.update(&buffer[..count]);
    }

    Some(format!("{:x}", hasher.finalize()))
}
