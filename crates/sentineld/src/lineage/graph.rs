//! In-memory Process Lineage DAG (Directed Acyclic Graph).

use lru::LruCache;
use std::num::NonZeroUsize;
use std::sync::{Arc, Mutex};

use sentinel_common::process::ProcessNode;

#[derive(Clone)]
pub struct LineageGraph {
    nodes: Arc<Mutex<LruCache<u32, ProcessNode>>>,
}

impl LineageGraph {
    pub fn new(capacity: usize) -> Self {
        let cap = NonZeroUsize::new(capacity).unwrap_or(NonZeroUsize::new(8192).unwrap());
        Self {
            nodes: Arc::new(Mutex::new(LruCache::new(cap))),
        }
    }

    pub fn insert(&self, node: ProcessNode) {
        let mut g = self.nodes.lock().unwrap();
        g.put(node.tgid, node);
    }

    pub fn get(&self, tgid: u32) -> Option<ProcessNode> {
        let mut g = self.nodes.lock().unwrap();
        g.get(&tgid).cloned()
    }

    pub fn get_mut_with<F, R>(&self, tgid: u32, f: F) -> Option<R>
    where
        F: FnOnce(&mut ProcessNode) -> R,
    {
        let mut g = self.nodes.lock().unwrap();
        g.get_mut(&tgid).map(f)
    }

    pub fn len(&self) -> usize {
        let g = self.nodes.lock().unwrap();
        g.len()
    }

    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }

    /// Find the most recently tainted process node within max_age_ns.
    pub fn find_recent_tainted(&self, now_ns: u64, max_age_ns: u64) -> Option<ProcessNode> {
        let g = self.nodes.lock().unwrap();
        let mut best: Option<ProcessNode> = None;
        let mut best_ts = 0;

        for (_k, v) in g.iter() {
            if let Some(last_sec) = v.secret_accesses.last() {
                let age = now_ns.saturating_sub(last_sec.timestamp_ns);
                if age <= max_age_ns && last_sec.timestamp_ns >= best_ts {
                    best_ts = last_sec.timestamp_ns;
                    best = Some(v.clone());
                }
            }
        }
        best
    }
}
