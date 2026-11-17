//! Causal Lineage Tracker maintaining process ancestry, taint propagation, and interpreter analysis.

use std::path::{Path, PathBuf};
use tracing::debug;

use sentinel_common::ipc::LineageStep;
use sentinel_common::process::{is_interactive_shell_binary, ProcessNode, SecretCategory};
use crate::lineage::graph::LineageGraph;
use crate::lineage::process_key::ProcessKey;

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
    graph: LineageGraph,
}

impl LineageTracker {
    pub fn new(capacity: usize) -> Self {
        Self {
            graph: LineageGraph::new(capacity),
        }
    }

    /// Insert or update a process node.
    pub fn insert(&self, node: ProcessNode) {
        self.graph.insert(node);
    }

    /// Retrieve a clone of a process node by TGID (with on-demand procfs fallback).
    pub fn get(&self, tgid: u32) -> Option<ProcessNode> {
        if let Some(node) = self.graph.get(tgid) {
            return Some(node);
        }

        // On-demand discovery fallback from /proc/<tgid> for pre-existing or external processes
        Self::discover_from_procfs(tgid).map(|node| {
            self.graph.insert(node.clone());
            node
        })
    }

    /// On-demand discovery of process attributes from Linux /proc filesystem.
    pub fn discover_from_procfs(tgid: u32) -> Option<ProcessNode> {
        let proc_dir = format!("/proc/{}", tgid);
        if !Path::new(&proc_dir).exists() {
            return None;
        }

        let exe_link = format!("{}/exe", proc_dir);
        let exe_path = std::fs::read_link(&exe_link)
            .unwrap_or_else(|_| PathBuf::from(format!("/proc/{}/exe", tgid)));

        // Read ppid and uid from /proc/<tgid>/status
        let mut ppid = 1;
        let mut uid = 1000;
        let status_path = format!("{}/status", proc_dir);
        if let Ok(content) = std::fs::read_to_string(&status_path) {
            for line in content.lines() {
                if line.starts_with("PPid:") {
                    if let Some(val) = line.split_whitespace().nth(1) {
                        ppid = val.parse().unwrap_or(1);
                    }
                } else if line.starts_with("Uid:") {
                    if let Some(val) = line.split_whitespace().nth(1) {
                        uid = val.parse().unwrap_or(1000);
                    }
                }
            }
        }

        let mut node = ProcessNode::new(tgid, ppid, uid, exe_path);

        // Read cmdline
        let cmdline_path = format!("{}/cmdline", proc_dir);
        if let Ok(bytes) = std::fs::read(&cmdline_path) {
            let cmdline: Vec<String> = bytes
                .split(|&b| b == 0)
                .filter(|s| !s.is_empty())
                .map(|s| String::from_utf8_lossy(s).to_string())
                .collect();
            if let Some(info) = inspect_interpreter(&node.exe_path, &cmdline) {
                node.script_path = info.script_path;
            }
            node.cmdline = cmdline;
        }

        Some(node)
    }

    /// Obtain canonical process key for a TGID.
    pub fn get_process_key(&self, tgid: u32) -> Option<ProcessKey> {
        self.graph.get(tgid).map(|n| {
            ProcessKey::new(n.tgid, n.start_time_ns)
                .with_exe(n.exe_path, n.exe_dev_ino)
        })
    }

    /// Handle process fork: child inherits metadata and parent pointer from parent TGID.
    pub fn handle_fork(&self, parent_tgid: u32, child_tgid: u32) {
        let (uid, exe_path, exe_dev_ino, pkg_origin, parent_has_secrets, parent_is_shell) =
            if let Some(parent) = self.graph.get(parent_tgid) {
                (
                    parent.uid,
                    parent.exe_path.clone(),
                    parent.exe_dev_ino,
                    parent.pkg_origin.clone(),
                    parent.has_secret_access(),
                    parent.is_interactive_shell,
                )
            } else {
                (1000, PathBuf::from("/proc/unknown"), (0, 0), None, false, false)
            };

        let mut child = ProcessNode::new(child_tgid, parent_tgid, uid, exe_path);
        child.exe_dev_ino = exe_dev_ino;
        child.pkg_origin = pkg_origin;

        // Thread Group tracking
        if parent_tgid == child_tgid {
            self.graph.get_mut_with(parent_tgid, |p| {
                p.add_thread(child_tgid);
            });
        }

        // If parent has secret accesses and is NOT an interactive shell, inherit secret history
        if parent_has_secrets && !parent_is_shell {
            if let Some(parent) = self.graph.get(parent_tgid) {
                child.secret_accesses = parent.secret_accesses.clone();
            }
        }

        self.graph.insert(child);
        debug!("Lineage fork: {} -> {}", parent_tgid, child_tgid);
    }

    /// Link an indirect spawn via D-Bus / systemd broker to its initiator.
    pub fn link_ipc_spawn(&self, initiator_tgid: u32, spawned_tgid: u32) {
        let (has_secrets, secrets) = if let Some(initiator) = self.graph.get(initiator_tgid) {
            (initiator.has_secret_access(), initiator.secret_accesses.clone())
        } else {
            (false, Vec::new())
        };

        if has_secrets {
            self.graph.get_mut_with(spawned_tgid, |spawned| {
                spawned.secret_accesses.extend(secrets);
                debug!(
                    "Lineage IPC spawn linked: {} -> {} (inherited taint via D-Bus/systemd broker)",
                    initiator_tgid, spawned_tgid
                );
            });
        }
    }

    /// Register a thread under its process group leader.
    pub fn register_thread(&self, tid: u32, leader_tgid: u32) {
        self.graph.get_mut_with(leader_tgid, |node| {
            node.add_thread(tid);
        });
    }

    /// Handle process exec: updates executable path, cmdline, script analysis, and memfd detection.
    pub fn handle_exec(&self, tgid: u32, exe_path: PathBuf, cmdline: Vec<String>) {
        let is_memfd = detect_memfd(&exe_path);
        let script_info = inspect_interpreter(&exe_path, &cmdline);
        let is_shell = is_interactive_shell_binary(&exe_path);
        let sha256 = crate::sha_cache::compute_sha256(&exe_path);

        let updated = self.graph.get_mut_with(tgid, |node| {
            node.exe_path = exe_path.clone();
            node.cmdline = cmdline.clone();
            node.is_memfd = is_memfd;
            node.is_interactive_shell = is_shell;
            node.script_path = script_info.as_ref().and_then(|s| s.script_path.clone());
            node.exe_sha256 = sha256.clone();
        });

        if updated.is_none() {
            let mut node = ProcessNode::new(tgid, 1, 1000, exe_path);
            node.cmdline = cmdline;
            node.is_memfd = is_memfd;
            node.is_interactive_shell = is_shell;
            node.script_path = script_info.and_then(|s| s.script_path);
            node.exe_sha256 = sha256;
            self.graph.insert(node);
        }
        debug!("Lineage exec for TGID {}", tgid);
    }

    /// Record a secret access event for a specific process TGID.
    pub fn record_secret_access(&self, tgid: u32, path: PathBuf, category: SecretCategory, ts: u64) {
        let updated = self.graph.get_mut_with(tgid, |node| {
            node.record_secret_access(path.clone(), category.clone(), ts);
        });

        if updated.is_none() {
            let mut node = ProcessNode::new(tgid, 1, 1000, PathBuf::from("/proc/unknown"));
            node.record_secret_access(path, category, ts);
            self.graph.insert(node);
        }
    }

    /// Record an IP contact for a process node. Returns true if this is the first time contacting this IP.
    pub fn record_ip_contact(&self, tgid: u32, ip: &str) -> bool {
        self.graph.get_mut_with(tgid, |node| {
            node.record_ip_contact(ip)
        }).unwrap_or(true)
    }

    /// Clear secret accesses and taint history for a specific TGID.
    pub fn clear_secrets(&self, tgid: u32) {
        self.graph.get_mut_with(tgid, |node| {
            node.secret_accesses.clear();
        });
    }

    /// Walk the ancestry chain of a process up to root or maximum 16 steps.
    pub fn get_ancestor_chain(&self, tgid: u32) -> Vec<LineageStep> {
        let mut chain = Vec::new();
        let mut current_tgid = tgid;
        let mut visited = std::collections::HashSet::new();

        for _ in 0..16 {
            if !visited.insert(current_tgid) || current_tgid == 0 {
                break;
            }

            if let Some(node) = self.get(current_tgid) {
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

        chain.reverse();
        chain
    }

    /// Total number of currently tracked processes.
    pub fn len(&self) -> usize {
        self.graph.len()
    }

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
        || (p.contains("(deleted)") && p.starts_with("/dev/shm"))
}

/// Inspect interpreter command line arguments for scripts or inline execution.
pub fn inspect_interpreter(exe_path: &Path, cmdline: &[String]) -> Option<ScriptInfo> {
    let exe_name = exe_path.file_name()?.to_str()?;

    let is_interp = matches!(
        exe_name,
        "python" | "python3" | "python2"
            | "bash" | "sh" | "zsh" | "dash"
            | "perl"
            | "ruby"
            | "node" | "nodejs"
            | "php"
    );

    if !is_interp {
        return None;
    }

    let mut is_inline = false;
    let mut is_suspicious_flags = false;
    let mut script_path = None;

    let mut skip_next = false;
    for (_i, arg) in cmdline.iter().enumerate().skip(1) {
        if skip_next {
            skip_next = false;
            continue;
        }

        if arg == "-c" || arg == "-e" || arg == "--eval" {
            is_inline = true;
            is_suspicious_flags = true;
            skip_next = true;
            continue;
        }

        if arg == "-m" || arg == "-o" || arg == "-u" {
            skip_next = true;
            continue;
        }

        if arg.starts_with('-') {
            continue;
        }

        if script_path.is_none() {
            script_path = Some(PathBuf::from(arg));
            break;
        }
    }

    if script_path.is_none() && !is_inline && cmdline.len() <= 1 {
        is_suspicious_flags = true;
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

        // Fork: systemd (1) -> bash (1000) -> npm (1010) -> python3 (1020)
        tracker.handle_fork(1, 1000);
        tracker.handle_exec(1000, PathBuf::from("/usr/bin/bash"), vec!["bash".into()]);

        tracker.handle_fork(1000, 1010);
        tracker.handle_exec(1010, PathBuf::from("/usr/bin/npm"), vec!["npm".into(), "install".into()]);

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
}
