//! Process lineage node and secret access tracking.
//!
//! `ProcessNode` represents a single process in the causal lineage graph,
//! capturing its ancestry, execution context, and any secret accesses.

use serde::{Deserialize, Serialize};
use std::path::PathBuf;

/// Category of a protected secret / sensitive credential.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum SecretCategory {
    /// SSH private keys (~/.ssh/id_*)
    SshKey,
    /// GPG keys and keyrings (~/.gnupg/)
    GpgKey,
    /// Browser cookies, login databases, local storage
    BrowserCookies,
    /// Telegram Desktop session data (tdata/)
    TelegramData,
    /// Cryptocurrency wallet files
    CryptoWallet,
    /// Other sensitive files
    Other(String),
}

/// A single secret access event recorded by eBPF `lsm/file_open`.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SecretAccessEvent {
    /// Absolute path of the accessed secret file.
    pub path: PathBuf,
    /// Category of the secret.
    pub category: SecretCategory,
    /// Kernel timestamp (nanoseconds since boot) of the access.
    pub timestamp_ns: u64,
}

/// A node in the in-memory causal lineage DAG (LRU ring graph).
///
/// Matches the structure defined in ТЗ section 3.1 exactly.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ProcessNode {
    /// Thread Group ID (process PID in Linux).
    pub tgid: u32,
    /// Parent process TGID.
    pub ppid: u32,
    /// User ID of the process.
    pub uid: u32,
    /// Kernel boot-relative start timestamp in nanoseconds.
    pub start_time_ns: u64,
    /// Path to the executable binary.
    pub exe_path: PathBuf,
    /// Device and inode of the executable for identity tracking.
    pub exe_dev_ino: (u64, u64),
    /// Lazily computed SHA-256 hash of the executable, cached by (dev, ino, mtime).
    pub exe_sha256: Option<String>,
    /// Package origin from dpkg database (e.g. "firefox" from dpkg -S).
    pub pkg_origin: Option<String>,
    /// Command-line arguments.
    pub cmdline: Vec<String>,
    /// For interpreters: the path to the script being executed.
    pub script_path: Option<PathBuf>,
    /// Whether the binary was loaded from anonymous memory (memfd_create).
    pub is_memfd: bool,
    /// All secret file accesses performed by this process.
    pub secret_accesses: Vec<SecretAccessEvent>,
}

impl ProcessNode {
    /// Create a new empty process node with the given identifiers.
    pub fn new(tgid: u32, ppid: u32, uid: u32, exe_path: PathBuf) -> Self {
        Self {
            tgid,
            ppid,
            uid,
            start_time_ns: 0,
            exe_path,
            exe_dev_ino: (0, 0),
            exe_sha256: None,
            pkg_origin: None,
            cmdline: Vec::new(),
            script_path: None,
            is_memfd: false,
            secret_accesses: Vec::new(),
        }
    }

    /// Returns the display name: the script path for interpreters, or exe basename.
    pub fn display_name(&self) -> String {
        if let Some(ref script) = self.script_path {
            format!(
                "{} ({})",
                self.exe_path
                    .file_name()
                    .map(|n| n.to_string_lossy().to_string())
                    .unwrap_or_else(|| self.exe_path.to_string_lossy().to_string()),
                script.display()
            )
        } else {
            self.exe_path
                .file_name()
                .map(|n| n.to_string_lossy().to_string())
                .unwrap_or_else(|| self.exe_path.to_string_lossy().to_string())
        }
    }

    /// Check if this process is a known script interpreter.
    pub fn is_interpreter(&self) -> bool {
        const INTERPRETERS: &[&str] = &["python3", "python", "bash", "sh", "node", "perl"];
        if let Some(name) = self.exe_path.file_name() {
            INTERPRETERS.contains(&name.to_string_lossy().as_ref())
        } else {
            false
        }
    }

    /// Record a secret access event.
    pub fn record_secret_access(&mut self, path: PathBuf, category: SecretCategory, ts: u64) {
        self.secret_accesses.push(SecretAccessEvent {
            path,
            category,
            timestamp_ns: ts,
        });
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_display_name_binary() {
        let node = ProcessNode::new(100, 1, 1000, PathBuf::from("/usr/bin/curl"));
        assert_eq!(node.display_name(), "curl");
    }

    #[test]
    fn test_display_name_interpreter_with_script() {
        let mut node = ProcessNode::new(200, 100, 1000, PathBuf::from("/usr/bin/python3"));
        node.script_path = Some(PathBuf::from("/tmp/install.py"));
        assert_eq!(node.display_name(), "python3 (/tmp/install.py)");
    }

    #[test]
    fn test_is_interpreter() {
        let node = ProcessNode::new(200, 100, 1000, PathBuf::from("/usr/bin/python3"));
        assert!(node.is_interpreter());

        let node2 = ProcessNode::new(200, 100, 1000, PathBuf::from("/usr/bin/curl"));
        assert!(!node2.is_interpreter());
    }
}
