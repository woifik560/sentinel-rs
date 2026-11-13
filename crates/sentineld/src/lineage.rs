//! In-memory Causal Lineage Graph (DAG) and Interpreter Context Analyzer.
//!
//! Maintains an LRU cache of 4096–8192 process nodes, preserving process ancestry
//! even after intermediate parent processes have exited.

use lru::LruCache;
use std::num::NonZeroUsize;
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex};
use tracing::debug;

use sentinel_common::ipc::LineageStep;
use sentinel_common::process::{ProcessNode, SecretCategory};

/// Information about an interpreted script invocation.
#[derive(Debug, Clone)]
pub struct ScriptInfo {
    pub script_path: Option<PathBuf>,
    pub is_inline: bool,
    pub is_suspicious_flags: bool,
}

/// The Causal Lineage Tracker maintaining process ancestry in an LRU graph.
#[derive(Clone)]
pub struct LineageTracker {
    graph: Arc<Mutex<LruCache<u32, ProcessNode>>>,
}

impl LineageTracker {
    pub fn new(capacity: usize) -> Self {
        let cap = NonZeroUsize::new(capacity).unwrap_or(NonZeroUsize::new(8192).unwrap());
        Self {
            graph: Arc::new(Mutex::new(LruCache::new(cap))),
        }
    }

    /// Insert or update a process node.
    #[allow(dead_code)]
    pub fn insert(&self, node: ProcessNode) {
        let mut g = self.graph.lock().unwrap();
        g.put(node.tgid, node);
    }

    /// Retrieve a clone of a process node by TGID.
    pub fn get(&self, tgid: u32) -> Option<ProcessNode> {
        let mut g = self.graph.lock().unwrap();
        g.get(&tgid).cloned()
    }

    /// Handle process fork: child inherits metadata and parent pointer from parent TGID.
    pub fn handle_fork(&self, parent_tgid: u32, child_tgid: u32) {
        let mut g = self.graph.lock().unwrap();
        let (uid, exe_path, exe_dev_ino, pkg_origin) = if let Some(parent) = g.get(&parent_tgid) {
            (parent.uid, parent.exe_path.clone(), parent.exe_dev_ino, parent.pkg_origin.clone())
        } else {
            (1000, PathBuf::from("/proc/unknown"), (0, 0), None)
        };

        let mut child = ProcessNode::new(child_tgid, parent_tgid, uid, exe_path);
        child.exe_dev_ino = exe_dev_ino;
        child.pkg_origin = pkg_origin;
        g.put(child_tgid, child);
        debug!("Lineage fork: {} -> {}", parent_tgid, child_tgid);
    }

    /// Handle process exec: updates executable path, cmdline, script analysis, and memfd detection.
    pub fn handle_exec(&self, tgid: u32, exe_path: PathBuf, cmdline: Vec<String>) {
        let mut g = self.graph.lock().unwrap();
        let is_memfd = detect_memfd(&exe_path);
        let script_info = inspect_interpreter(&exe_path, &cmdline);

        if let Some(node) = g.get_mut(&tgid) {
            node.exe_path = exe_path;
            node.cmdline = cmdline;
            node.is_memfd = is_memfd;
            node.script_path = script_info.and_then(|s| s.script_path);
        } else {
            let mut node = ProcessNode::new(tgid, 1, 1000, exe_path);
            node.cmdline = cmdline;
            node.is_memfd = is_memfd;
            node.script_path = script_info.and_then(|s| s.script_path);
            g.put(tgid, node);
        }
        debug!("Lineage exec for TGID {}", tgid);
    }

    /// Record a secret access event for a specific process TGID.
    pub fn record_secret_access(&self, tgid: u32, path: PathBuf, category: SecretCategory, ts: u64) {
        let mut g = self.graph.lock().unwrap();
        if let Some(node) = g.get_mut(&tgid) {
            node.record_secret_access(path, category, ts);
        } else {
            let mut node = ProcessNode::new(tgid, 1, 1000, PathBuf::from("/proc/unknown"));
            node.record_secret_access(path, category, ts);
            g.put(tgid, node);
        }
    }

    /// Walk the ancestry chain of a process up to root or maximum 16 steps.
    pub fn get_ancestor_chain(&self, tgid: u32) -> Vec<LineageStep> {
        let mut chain = Vec::new();
        let mut current_tgid = tgid;
        let mut visited = std::collections::HashSet::new();

        let mut g = self.graph.lock().unwrap();

        for _ in 0..16 {
            if !visited.insert(current_tgid) || current_tgid == 0 {
                break;
            }

            if let Some(node) = g.get(&current_tgid) {
                let exe_name = node
                    .exe_path
                    .file_name()
                    .map(|n| n.to_string_lossy().to_string())
                    .unwrap_or_else(|| node.exe_path.to_string_lossy().to_string());

                chain.push(LineageStep {
                    tgid: node.tgid,
                    exe_name,
                    script_path: node.script_path.clone(),
                });

                let ppid = node.ppid;
                if ppid == 0 || ppid == current_tgid {
                    break;
                }
                current_tgid = ppid;
            } else {
                break;
            }
        }

        // Return from root ancestor to current process
        chain.reverse();
        chain
    }

    /// Total number of currently tracked processes.
    pub fn len(&self) -> usize {
        let g = self.graph.lock().unwrap();
        g.len()
    }

    #[allow(dead_code)]
    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }
}

/// Detect execution from anonymous memory (`memfd_create`).
pub fn detect_memfd(exe_path: &Path) -> bool {
    let p = exe_path.to_string_lossy();
    p.starts_with("/memfd:")
        || p.starts_with("memfd:")
        || p.contains("/memfd:")
        || (p.starts_with("/proc/") && p.contains("/fd/"))
}

/// Inspect interpreter process arguments (python3, bash, sh, node, perl).
pub fn inspect_interpreter(exe_path: &Path, cmdline: &[String]) -> Option<ScriptInfo> {
    let exe_name = exe_path.file_name()?.to_string_lossy();
    let is_interp = matches!(
        exe_name.as_ref(),
        "python3" | "python" | "bash" | "sh" | "zsh" | "node" | "perl"
    );

    if !is_interp {
        return None;
    }

    let mut is_inline = false;
    let mut is_suspicious_flags = false;
    let mut script_path = None;

    let mut iter = cmdline.iter().skip(1);
    while let Some(arg) = iter.next() {
        if arg == "-c" || arg == "-e" {
            is_inline = true;
            if let Some(code) = iter.next() {
                if code.contains("base64") || code.contains("eval(") || code.contains("exec(") || code.contains("urllib") {
                    is_suspicious_flags = true;
                }
            }
        } else if !arg.starts_with('-') && script_path.is_none() {
            script_path = Some(PathBuf::from(arg));
        }
    }

    Some(ScriptInfo {
        script_path,
        is_inline,
        is_suspicious_flags,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_lineage_tracker_ancestry() {
        let tracker = LineageTracker::new(100);

        // Process 1: bash
        let node1 = ProcessNode::new(1000, 1, 1000, PathBuf::from("/bin/bash"));
        tracker.insert(node1);

        // Process 2: npm spawned from bash
        tracker.handle_fork(1000, 1010);
        tracker.handle_exec(1010, PathBuf::from("/usr/bin/npm"), vec!["npm".into(), "run".into(), "build".into()]);

        // Process 3: python3 spawned from npm
        tracker.handle_fork(1010, 1020);
        tracker.handle_exec(
            1020,
            PathBuf::from("/usr/bin/python3"),
            vec!["python3".into(), "/tmp/install.py".into()],
        );

        let chain = tracker.get_ancestor_chain(1020);
        assert_eq!(chain.len(), 3);
        assert_eq!(chain[0].exe_name, "bash");
        assert_eq!(chain[1].exe_name, "npm");
        assert_eq!(chain[2].exe_name, "python3");
        assert_eq!(chain[2].script_path, Some(PathBuf::from("/tmp/install.py")));
    }

    #[test]
    fn test_inspect_interpreter_inline() {
        let exe = PathBuf::from("/usr/bin/python3");
        let cmdline = vec![
            "python3".to_string(),
            "-c".to_string(),
            "import base64; eval(base64.b64decode(...))".to_string(),
        ];
        let info = inspect_interpreter(&exe, &cmdline).expect("Should identify interpreter");
        assert!(info.is_inline);
        assert!(info.is_suspicious_flags);
    }
}
