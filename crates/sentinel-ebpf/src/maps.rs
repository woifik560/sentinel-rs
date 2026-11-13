//! eBPF map wrappers and in-kernel object storage managers (TASK_STORAGE, INODE_STORAGE, SK_STORAGE).
//!
//! Replaces legacy PID/TGID maps with task/inode/socket storage to eliminate PID reuse races,
//! memory leaks on process exit, and enforce taint hygiene across pipes and files.

use serde::{Deserialize, Serialize};
use std::collections::{HashMap, HashSet};
use std::path::Path;
use std::sync::{Arc, RwLock};

use sentinel_common::events::{SENTINEL_SO_MARK, MAY_READ, MAY_WRITE};

/// Bitflags representing taint states of a task or inode object.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, Serialize, Deserialize)]
pub struct TaintFlags(pub u32);

impl TaintFlags {
    pub const NONE: u32 = 0;
    pub const TAINTED_SSH: u32 = 1 << 0;
    pub const TAINTED_GPG: u32 = 1 << 1;
    pub const TAINTED_BROWSER: u32 = 1 << 2;
    pub const TAINTED_TELEGRAM: u32 = 1 << 3;
    pub const TAINTED_CRYPTO: u32 = 1 << 4;
    pub const TAINTED_PIPE: u32 = 1 << 5;
    pub const TAINTED_TEMPFILE: u32 = 1 << 6;
    pub const PENDING_INSPECT: u32 = 1 << 7;

    pub fn is_empty(&self) -> bool {
        self.0 == Self::NONE
    }

    pub fn contains(&self, flag: u32) -> bool {
        (self.0 & flag) != 0
    }

    pub fn insert(&mut self, flag: u32) {
        self.0 |= flag;
    }

    pub fn remove(&mut self, flag: u32) {
        self.0 &= !flag;
    }

    pub fn is_tainted(&self) -> bool {
        (self.0 & (Self::TAINTED_SSH
            | Self::TAINTED_GPG
            | Self::TAINTED_BROWSER
            | Self::TAINTED_TELEGRAM
            | Self::TAINTED_CRYPTO
            | Self::TAINTED_PIPE
            | Self::TAINTED_TEMPFILE)) != 0
    }
}

/// In-kernel entry stored in `BPF_MAP_TYPE_TASK_STORAGE` per task struct.
#[derive(Debug, Clone, Copy, Default)]
pub struct TaskStorageEntry {
    pub tgid: u32,
    pub taint_flags: TaintFlags,
    pub baseline_profile: u32,
    pub is_leaf: bool,
    pub parent_tgid: u32,
}

/// In-kernel entry stored in `BPF_MAP_TYPE_INODE_STORAGE` per inode struct (pipe, FIFO, file).
#[derive(Debug, Clone, Copy, Default)]
pub struct InodeStorageEntry {
    pub taint_flags: TaintFlags,
    pub source_tgid: u32,
    pub dev: u64,
    pub ino: u64,
    pub is_pipe: bool,
    pub is_fifo: bool,
}

/// In-kernel entry stored in `BPF_MAP_TYPE_SK_STORAGE` per socket struct.
#[derive(Debug, Clone, Copy, Default)]
pub struct SkStorageEntry {
    pub tgid: u32,
    pub so_mark: u32,
    pub held_in_nfqueue: bool,
}

/// Taint Hygiene validator to prevent over-tainting the entire desktop OS.
pub struct TaintHygiene;

impl TaintHygiene {
    /// Determines whether a path is exempt from inode taint propagation.
    /// Excludes pseudo-terminals (/dev/pts/*), /dev/null, system logs, and Wayland/X11 sockets.
    pub fn is_exempt_path(path: &str) -> bool {
        if path.starts_with("/dev/pts/")
            || path == "/dev/pts"
            || path == "/dev/null"
            || path == "/dev/zero"
            || path == "/dev/urandom"
            || path == "/dev/tty"
        {
            return true;
        }

        if path.starts_with("/var/log/") || path.starts_with("/run/systemd/journal/") {
            return true;
        }

        // GUI display server sockets: Wayland and X11 sockets
        if path.starts_with("/tmp/.X11-unix/")
            || path.contains("/wayland-")
            || path.ends_with("/bus") // DBus session daemon socket
        {
            return true;
        }

        false
    }

    /// Validates if a target secret path is strictly a private secret.
    /// Excludes public keys (*.pub), known_hosts, and ssh config files.
    pub fn is_strictly_private_secret(path: &str) -> bool {
        // SSH hygiene: strictly private keys, never .pub or known_hosts/config
        if path.contains("/.ssh/") {
            if path.ends_with(".pub")
                || path.ends_with("/known_hosts")
                || path.ends_with("/known_hosts.old")
                || path.ends_with("/config")
                || path.ends_with("/authorized_keys")
            {
                return false;
            }
            if path.contains("/id_rsa")
                || path.contains("/id_ed25519")
                || path.contains("/id_ecdsa")
                || path.contains("/id_dsa")
                || path.contains("/.ssh/id_")
            {
                return true;
            }
        }

        // GPG hygiene: private keys only
        if path.contains("/.gnupg/private-keys-v1.d/")
            || path.ends_with("/secring.gpg")
            || path.ends_with("/secring.skr")
        {
            return true;
        }

        // Telegram desktop auth sessions
        if path.contains("/TelegramDesktop/tdata/") {
            if path.ends_with("/key_datas") || path.contains("/D877F783D5D3EF8C") {
                return true;
            }
            return true;
        }

        // Browser credentials and session cookies
        if path.contains("/Cookies")
            || path.ends_with("/cookies.sqlite")
            || path.contains("/Login Data")
        {
            return true;
        }

        // Crypto wallets
        if path.contains("/.electrum/wallets") || path.contains("/.bitcoin/wallets") {
            return true;
        }

        false
    }
}

/// Unified userspace manager and simulation mirror for Kernel Object Storages:
/// - BPF_MAP_TYPE_TASK_STORAGE
/// - BPF_MAP_TYPE_INODE_STORAGE
/// - BPF_MAP_TYPE_SK_STORAGE
#[derive(Debug, Clone, Default)]
pub struct TaintMapManager {
    /// Mirror of `BPF_MAP_TYPE_TASK_STORAGE` keyed by TGID.
    tasks: Arc<RwLock<HashMap<u32, TaskStorageEntry>>>,
    /// Mirror of `BPF_MAP_TYPE_INODE_STORAGE` keyed by (dev, ino).
    inodes: Arc<RwLock<HashMap<(u64, u64), InodeStorageEntry>>>,
    /// Active allowlist for whitelisted TGIDs.
    allowed_tgids: Arc<RwLock<HashSet<u32>>>,
}

impl TaintMapManager {
    pub fn new() -> Self {
        Self::default()
    }

    /// Mark a task (TGID) as tainted in its TASK_STORAGE.
    pub fn mark_tainted(&self, tgid: u32) {
        let mut flags = TaintFlags::default();
        flags.insert(TaintFlags::TAINTED_SSH);
        self.set_task_taint(tgid, flags);
    }

    /// Set explicit taint flags in TASK_STORAGE for a TGID.
    pub fn set_task_taint(&self, tgid: u32, flags: TaintFlags) {
        let mut map = self.tasks.write().unwrap();
        let entry = map.entry(tgid).or_insert_with(|| TaskStorageEntry {
            tgid,
            taint_flags: TaintFlags::default(),
            baseline_profile: 0,
            is_leaf: true,
            parent_tgid: 0,
        });
        entry.taint_flags.0 |= flags.0;
    }

    /// Retrieve the current task storage entry.
    pub fn get_task_storage(&self, tgid: u32) -> Option<TaskStorageEntry> {
        let map = self.tasks.read().unwrap();
        map.get(&tgid).copied()
    }

    /// Check if a TGID is currently tainted in TASK_STORAGE.
    pub fn is_tainted(&self, tgid: u32) -> bool {
        let map = self.tasks.read().unwrap();
        map.get(&tgid)
            .map(|e| e.taint_flags.is_tainted())
            .unwrap_or(false)
    }

    /// Clear taint from a TGID (e.g. after user approval / unfreeze).
    pub fn clear_taint(&self, tgid: u32) {
        let mut map = self.tasks.write().unwrap();
        if let Some(entry) = map.get_mut(&tgid) {
            entry.taint_flags = TaintFlags::default();
        }
    }

    /// Whitelist a specific TGID for network calls.
    pub fn allow_tgid(&self, tgid: u32) {
        let mut map = self.allowed_tgids.write().unwrap();
        map.insert(tgid);
    }

    /// Check if a TGID is in the active allowlist.
    pub fn is_allowed(&self, tgid: u32) -> bool {
        let map = self.allowed_tgids.read().unwrap();
        map.contains(&tgid)
    }

    /// Inherit taint status during fork: child inherits taint from parent's TASK_STORAGE.
    pub fn inherit_fork(&self, parent_tgid: u32, child_tgid: u32) {
        let parent_flags = {
            let map = self.tasks.read().unwrap();
            map.get(&parent_tgid).map(|e| e.taint_flags)
        };

        if let Some(flags) = parent_flags {
            if flags.is_tainted() {
                self.set_task_taint(child_tgid, flags);
            }
        }
    }

    /// Process `lsm/file_permission` hook for data-flow tracking across pipes, FIFOs, and files:
    /// - If a tainted process writes to an inode -> mark inode with INODE_STORAGE taint.
    /// - If any other process reads from a tainted inode -> propagate taint into its TASK_STORAGE.
    pub fn handle_file_permission(
        &self,
        tgid: u32,
        dev: u64,
        ino: u64,
        path: &Path,
        mask: u32,
        is_pipe: bool,
        is_fifo: bool,
    ) -> Option<TaintFlags> {
        let path_str = path.to_string_lossy();

        // Taint hygiene check: skip terminal devices, logs, Wayland/X11 sockets
        if TaintHygiene::is_exempt_path(&path_str) {
            return None;
        }

        let is_writing = (mask & MAY_WRITE) != 0;
        let is_reading = (mask & MAY_READ) != 0;

        // 1. Process Write Path: Tainted task writes to an inode
        if is_writing && self.is_tainted(tgid) {
            let parent_flags = self
                .get_task_storage(tgid)
                .map(|t| t.taint_flags)
                .unwrap_or(TaintFlags(TaintFlags::TAINTED_PIPE));

            let mut inodes = self.inodes.write().unwrap();
            let inode_entry = inodes.entry((dev, ino)).or_insert_with(|| InodeStorageEntry {
                taint_flags: TaintFlags::default(),
                source_tgid: tgid,
                dev,
                ino,
                is_pipe,
                is_fifo,
            });

            inode_entry.taint_flags.0 |= parent_flags.0;
            if is_pipe || is_fifo {
                inode_entry.taint_flags.insert(TaintFlags::TAINTED_PIPE);
            } else {
                inode_entry.taint_flags.insert(TaintFlags::TAINTED_TEMPFILE);
            }

            return Some(inode_entry.taint_flags);
        }

        // 2. Process Read Path: Any task reads from a tainted inode
        if is_reading {
            let inode_taint = {
                let inodes = self.inodes.read().unwrap();
                inodes.get(&(dev, ino)).map(|e| e.taint_flags)
            };

            if let Some(taint) = inode_taint {
                if taint.is_tainted() {
                    // Propagate inherited taint to reader task's TASK_STORAGE
                    self.set_task_taint(tgid, taint);
                    return Some(taint);
                }
            }
        }

        None
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_taint_flags() {
        let mut flags = TaintFlags::default();
        assert!(flags.is_empty());
        assert!(!flags.is_tainted());

        flags.insert(TaintFlags::TAINTED_SSH);
        assert!(flags.contains(TaintFlags::TAINTED_SSH));
        assert!(flags.is_tainted());
        assert!(!flags.contains(TaintFlags::TAINTED_BROWSER));
    }

    #[test]
    fn test_pipe_taint_propagation_cat_secret_curl() {
        let manager = TaintMapManager::new();

        let cat_tgid = 1001;
        let curl_tgid = 1002;
        let pipe_dev = 0;
        let pipe_ino = 99999;
        let pipe_path = Path::new("pipe:[99999]");

        // 1. cat reads SSH key and becomes tainted in TASK_STORAGE
        manager.mark_tainted(cat_tgid);
        assert!(manager.is_tainted(cat_tgid));
        assert!(!manager.is_tainted(curl_tgid));

        // 2. cat writes to stdout (pipe)
        let write_taint = manager.handle_file_permission(
            cat_tgid,
            pipe_dev,
            pipe_ino,
            pipe_path,
            MAY_WRITE,
            true,
            false,
        );
        assert!(write_taint.is_some());

        // 3. curl reads from stdin (same pipe)
        let read_taint = manager.handle_file_permission(
            curl_tgid,
            pipe_dev,
            pipe_ino,
            pipe_path,
            MAY_READ,
            true,
            false,
        );
        assert!(read_taint.is_some());

        // 4. curl must now be tainted in TASK_STORAGE!
        assert!(manager.is_tainted(curl_tgid));
    }

    #[test]
    fn test_taint_hygiene_exemptions() {
        assert!(TaintHygiene::is_exempt_path("/dev/pts/1"));
        assert!(TaintHygiene::is_exempt_path("/dev/null"));
        assert!(TaintHygiene::is_exempt_path("/var/log/syslog"));
        assert!(TaintHygiene::is_exempt_path("/tmp/.X11-unix/X0"));

        assert!(!TaintHygiene::is_exempt_path("/tmp/secret.txt"));
        assert!(!TaintHygiene::is_exempt_path("/home/user/.ssh/id_rsa"));
    }

    #[test]
    fn test_strict_private_secret_matching() {
        assert!(TaintHygiene::is_strictly_private_secret("/home/user/.ssh/id_rsa"));
        assert!(TaintHygiene::is_strictly_private_secret("/home/user/.ssh/id_ed25519"));

        // Public keys and config must NOT be treated as private secrets
        assert!(!TaintHygiene::is_strictly_private_secret("/home/user/.ssh/id_rsa.pub"));
        assert!(!TaintHygiene::is_strictly_private_secret("/home/user/.ssh/config"));
        assert!(!TaintHygiene::is_strictly_private_secret("/home/user/.ssh/known_hosts"));
    }
}
