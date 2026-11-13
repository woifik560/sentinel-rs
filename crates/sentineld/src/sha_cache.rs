//! Lazy SHA-256 calculation with in-memory LRU cache keyed by (dev, ino, mtime).

use lru::LruCache;
use sha2::{Digest, Sha256};
use std::fs::File;
use std::io::Read;
use std::num::NonZeroUsize;
use std::path::Path;
use std::sync::{Arc, Mutex};
use tracing::warn;

type CacheKey = (u64, u64, u64, u64); // (dev, ino, mtime_ns, ctime_ns)

#[allow(dead_code)]
#[derive(Clone)]
pub struct ShaCache {
    cache: Arc<Mutex<LruCache<CacheKey, String>>>,
}

impl ShaCache {
    pub fn new(capacity: usize) -> Self {
        let cap = NonZeroUsize::new(capacity).unwrap_or(NonZeroUsize::new(2048).unwrap());
        Self {
            cache: Arc::new(Mutex::new(LruCache::new(cap))),
        }
    }

    /// Retrieve cached SHA-256 or compute and store it lazily.
    pub fn get_or_compute<P: AsRef<Path>>(
        &self,
        path: P,
        dev: u64,
        ino: u64,
        mtime_ns: u64,
        ctime_ns: u64,
    ) -> Option<String> {
        let key = (dev, ino, mtime_ns, ctime_ns);
        {
            let mut cache = self.cache.lock().unwrap();
            if let Some(hash) = cache.get(&key) {
                return Some(hash.clone());
            }
        }

        let hash = compute_sha256(path.as_ref())?;
        let mut cache = self.cache.lock().unwrap();
        cache.put(key, hash.clone());
        Some(hash)
    }

    /// Instantly invalidate all cached hashes for an inode upon write/delete/unlink events.
    pub fn invalidate_inode(&self, dev: u64, ino: u64) {
        let mut cache = self.cache.lock().unwrap();
        // Remove keys matching (dev, ino)
        let keys_to_remove: Vec<CacheKey> = cache
            .iter()
            .filter(|((k_dev, k_ino, _, _), _)| *k_dev == dev && *k_ino == ino)
            .map(|(k, _)| *k)
            .collect();

        for key in keys_to_remove {
            cache.pop(&key);
        }
    }

    /// Invalidate cache for a specific path upon unlink or rename.
    pub fn invalidate_path(&self, path: &Path) {
        if let Ok(meta) = std::fs::metadata(path) {
            #[cfg(unix)]
            {
                use std::os::unix::fs::MetadataExt;
                self.invalidate_inode(meta.dev(), meta.ino());
            }
        }
    }

    /// Read filesystem metadata and compute or retrieve SHA-256.
    pub fn get_for_path(&self, path: &Path) -> Option<(u64, u64, u64, u64, String)> {
        #[cfg(unix)]
        {
            use std::os::unix::fs::MetadataExt;
            if let Ok(meta) = std::fs::metadata(path) {
                let dev = meta.dev();
                let ino = meta.ino();
                let mtime_ns = meta.mtime_nsec() as u64;
                let ctime_ns = meta.ctime_nsec() as u64;
                if let Some(hash) = self.get_or_compute(path, dev, ino, mtime_ns, ctime_ns) {
                    return Some((dev, ino, mtime_ns, ctime_ns, hash));
                }
            }
        }

        #[cfg(not(unix))]
        {
            if let Ok(meta) = std::fs::metadata(path) {
                let mtime_ns = meta.modified().ok()
                    .and_then(|t| t.duration_since(std::time::UNIX_EPOCH).ok())
                    .map(|d| d.as_nanos() as u64)
                    .unwrap_or(0);
                if let Some(hash) = self.get_or_compute(path, 0, 0, mtime_ns, 0) {
                    return Some((0, 0, mtime_ns, 0, hash));
                }
            }
        }

        None
    }
}

/// Compute SHA-256 hash string of a file.
#[allow(dead_code)]
pub fn compute_sha256(path: &Path) -> Option<String> {
    let mut file = match File::open(path) {
        Ok(f) => f,
        Err(e) => {
            warn!("Failed to open file for SHA-256 hash: {}: {}", path.display(), e);
            return None;
        }
    };

    let mut hasher = Sha256::new();
    let mut buffer = [0u8; 8192];
    loop {
        match file.read(&mut buffer) {
            Ok(0) => break,
            Ok(n) => hasher.update(&buffer[..n]),
            Err(_) => return None,
        }
    }

    Some(format!("{:x}", hasher.finalize()))
}
