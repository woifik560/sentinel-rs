//! Lazy SHA-256 calculation with in-memory LRU cache keyed by (dev, ino, mtime).

use lru::LruCache;
use sha2::{Digest, Sha256};
use std::fs::File;
use std::io::Read;
use std::num::NonZeroUsize;
use std::path::Path;
use std::sync::{Arc, Mutex};
use tracing::warn;

type CacheKey = (u64, u64, u64); // (dev, ino, mtime_ns)

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
    pub fn get_or_compute<P: AsRef<Path>>(&self, path: P, dev: u64, ino: u64, mtime_ns: u64) -> Option<String> {
        let key = (dev, ino, mtime_ns);
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
