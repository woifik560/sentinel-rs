//! Process identity and canonical process keys protecting against PID reuse.

pub use sentinel_common::process::ProcessIdentity;
use serde::{Deserialize, Serialize};
use std::path::PathBuf;

/// A canonical process key uniquely identifying a specific process execution instance.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct ProcessKey {
    pub pid: u32,
    pub tgid: u32,
    pub start_time_ns: u64,
    pub pid_namespace: u64,
    pub exe_path: Option<PathBuf>,
    pub dev_ino: Option<(u64, u64)>,
}

impl ProcessKey {
    pub fn new(pid: u32, start_time_ns: u64) -> Self {
        Self {
            pid,
            tgid: pid,
            start_time_ns,
            pid_namespace: 0,
            exe_path: None,
            dev_ino: None,
        }
    }

    pub fn new_with_tgid(pid: u32, tgid: u32, start_time_ns: u64) -> Self {
        Self {
            pid,
            tgid,
            start_time_ns,
            pid_namespace: 0,
            exe_path: None,
            dev_ino: None,
        }
    }

    pub fn with_namespace(mut self, ns: u64) -> Self {
        self.pid_namespace = ns;
        self
    }

    pub fn with_exe(mut self, path: PathBuf, dev_ino: (u64, u64)) -> Self {
        self.exe_path = Some(path);
        self.dev_ino = Some(dev_ino);
        self
    }

    /// Verifies whether the process instance at `current_start_time` still matches this key.
    pub fn matches_instance(&self, current_start_time: u64) -> bool {
        self.start_time_ns == current_start_time
    }

    pub fn to_string_id(&self) -> String {
        format!("{}:{}:{}", self.tgid, self.pid, self.start_time_ns)
    }

    pub fn to_identity(&self) -> ProcessIdentity {
        ProcessIdentity {
            pid: self.pid,
            tgid: self.tgid,
            start_time_ns: self.start_time_ns,
            pid_namespace: self.pid_namespace,
            exe_path: self.exe_path.clone(),
            dev_ino: self.dev_ino,
        }
    }
}

impl From<ProcessIdentity> for ProcessKey {
    fn from(id: ProcessIdentity) -> Self {
        Self {
            pid: id.pid,
            tgid: id.tgid,
            start_time_ns: id.start_time_ns,
            pid_namespace: id.pid_namespace,
            exe_path: id.exe_path,
            dev_ino: id.dev_ino,
        }
    }
}

impl From<ProcessKey> for ProcessIdentity {
    fn from(k: ProcessKey) -> Self {
        k.to_identity()
    }
}

impl std::fmt::Display for ProcessKey {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}:{}:{}", self.tgid, self.pid, self.start_time_ns)
    }
}
