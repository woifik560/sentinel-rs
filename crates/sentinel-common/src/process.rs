//! Process lineage node and secret access tracking.
//!
//! `ProcessNode` represents a single process in the causal lineage graph,
//! capturing its ancestry, execution context, and any secret accesses.

use serde::{Deserialize, Serialize};
use std::collections::HashSet;
use std::path::{Path, PathBuf};

/// Baseline profile bitflags stored in TASK_STORAGE.
pub const PROFILE_UNKNOWN: u32 = 0;
pub const PROFILE_TRUSTED_PKG: u32 = 1 << 0;
pub const PROFILE_UNTRUSTED_ORIGIN: u32 = 1 << 1;
pub const PROFILE_INTERPRETER: u32 = 1 << 2;
pub const PROFILE_FILELESS_MEMFD: u32 = 1 << 3;
pub const PROFILE_NEVER_FREEZE: u32 = 1 << 4;

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

/// A single secret access event recorded by eBPF `lsm/file_open` or inherited via `lsm/file_permission`.
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
/// Matches the structure defined in ТЗ section 3.1 with extensions for
/// object storage and LoLBin mitigation.
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
    /// Pre-evaluated baseline profile in TASK_STORAGE.
    pub baseline_profile: u32,
    /// Whether this process is an interactive shell (e.g. bash/zsh), protected from upward taint.
    pub is_interactive_shell: bool,
    /// Set of destination IP strings previously contacted by this process.
    pub contacted_ips: HashSet<String>,
    /// All secret file accesses performed or inherited by this process.
    pub secret_accesses: Vec<SecretAccessEvent>,
}

impl ProcessNode {
    /// Create a new empty process node with the given identifiers.
    pub fn new(tgid: u32, ppid: u32, uid: u32, exe_path: PathBuf) -> Self {
        let is_shell = is_interactive_shell_binary(&exe_path);
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
            baseline_profile: PROFILE_UNKNOWN,
            is_interactive_shell: is_shell,
            contacted_ips: HashSet::new(),
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

    /// Record a secret access on this process node.
    pub fn record_secret_access(&mut self, path: PathBuf, category: SecretCategory, timestamp_ns: u64) {
        self.secret_accesses.push(SecretAccessEvent {
            path,
            category,
            timestamp_ns,
        });
    }

    /// Check if this process has accessed any protected secret.
    pub fn has_secret_access(&self) -> bool {
        !self.secret_accesses.is_empty()
    }

    /// Record an outbound IP contact. Returns true if this is the first time contacting this IP.
    pub fn record_ip_contact(&mut self, ip: &str) -> bool {
        self.contacted_ips.insert(ip.to_string())
    }

    /// Check if the executable is a common scripting interpreter.
    pub fn is_interpreter(&self) -> bool {
        if let Some(name) = self.exe_path.file_name().and_then(|n| n.to_str()) {
            matches!(
                name,
                "python3" | "python" | "bash" | "sh" | "zsh" | "dash" | "node" | "perl" | "ruby" | "php"
            )
        } else {
            false
        }
    }
}

/// Identify if a binary is a common interactive user shell.
pub fn is_interactive_shell_binary(path: &Path) -> bool {
    if let Some(name) = path.file_name().and_then(|n| n.to_str()) {
        matches!(name, "bash" | "zsh" | "fish" | "csh" | "tcsh")
    } else {
        false
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_process_node_display_name() {
        let mut node = ProcessNode::new(100, 1, 1000, PathBuf::from("/usr/bin/python3"));
        assert_eq!(node.display_name(), "python3");

        node.script_path = Some(PathBuf::from("/tmp/install.py"));
        assert_eq!(node.display_name(), "python3 (/tmp/install.py)");
    }

    #[test]
    fn test_interactive_shell_detection() {
        assert!(is_interactive_shell_binary(Path::new("/bin/bash")));
        assert!(is_interactive_shell_binary(Path::new("/usr/bin/zsh")));
        assert!(!is_interactive_shell_binary(Path::new("/usr/bin/curl")));
        assert!(!is_interactive_shell_binary(Path::new("/usr/bin/python3")));
    }
}
