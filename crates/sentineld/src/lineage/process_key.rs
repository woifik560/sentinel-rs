//! Process identity and canonical process keys protecting against PID reuse.

use serde::{Deserialize, Serialize};
use std::path::PathBuf;

/// A canonical process key uniquely identifying a specific process execution instance.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct ProcessKey {
    pub pid: u32,
    pub start_time_ns: u64,
    pub exe_path: Option<PathBuf>,
    pub dev_ino: Option<(u64, u64)>,
}

impl ProcessKey {
    pub fn new(pid: u32, start_time_ns: u64) -> Self {
        Self {
            pid,
            start_time_ns,
            exe_path: None,
            dev_ino: None,
        }
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
        format!("{}:{}", self.pid, self.start_time_ns)
    }
}

impl std::fmt::Display for ProcessKey {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}:{}", self.pid, self.start_time_ns)
    }
}
