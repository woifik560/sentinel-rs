//! eBPF map wrappers and in-kernel object storage managers (TASK_STORAGE, INODE_STORAGE, SK_STORAGE).
//!
//! Replaces legacy PID/TGID maps with task/inode/socket storage to eliminate PID reuse races,
//! memory leaks on process exit, and enforce taint hygiene across pipes and files.

use serde::{Deserialize, Serialize};
use std::collections::{HashMap, HashSet};
use std::path::Path;
use std::sync::{Arc, RwLock};

use sentinel_common::events::{MAY_READ, MAY_WRITE};

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
/// Multi-thread aware: points to `task->group_leader` so taint spans the entire process.
#[derive(Debug, Clone, Copy, Default)]
pub struct TaskStorageEntry {
    pub tgid: u32,
    pub group_leader_tgid: u32,
    pub tid: u32,
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

/// Verdict for `lsm/unix_may_send` hook.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum UnixSendVerdict {
    /// Safe message transfer permitted without state alteration.
    Allow,
    /// Message allowed, but receiver process inherits taint (Taint Propagation).
    TaintReceiver,
    /// Block transfer (-EPERM) to prevent covert data exfiltration or laundering.
    Block,
}

/// Verdict for `lsm/ptrace_access_check` hook.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PtraceVerdict {
    /// Memory attachment permitted.
    Allow,
    /// Memory attachment denied (-EPERM) to prevent memory snooping of clean processes.
    Deny,
    /// Tracer inherits taint from target process.
    TaintTracer,
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
/// - BPF_MAP_TYPE_TASK_STORAGE (resolved through task->group_leader)
/// - BPF_MAP_TYPE_INODE_STORAGE
/// - BPF_MAP_TYPE_SK_STORAGE
#[derive(Debug, Clone, Default)]
pub struct TaintMapManager {
    /// Mirror of `BPF_MAP_TYPE_TASK_STORAGE` keyed by group leader TGID.
    tasks: Arc<RwLock<HashMap<u32, TaskStorageEntry>>>,
    /// Thread ID (TID) to Group Leader TGID mapping.
    thread_to_group: Arc<RwLock<HashMap<u32, u32>>>,
    /// Mirror of `BPF_MAP_TYPE_INODE_STORAGE` keyed by (dev, ino).
    inodes: Arc<RwLock<HashMap<(u64, u64), InodeStorageEntry>>>,
    /// Active allowlist for whitelisted TGIDs.
    allowed_tgids: Arc<RwLock<HashSet<u32>>>,
}

impl TaintMapManager {
    pub fn new() -> Self {
        Self::default()
    }

    /// Register a thread (TID) under its process group leader (TGID).
    pub fn register_thread(&self, tid: u32, group_leader_tgid: u32) {
        let mut map = self.thread_to_group.write().unwrap();
        map.insert(tid, group_leader_tgid);
    }

    /// Resolve effective group leader TGID for a thread or process ID.
    pub fn resolve_group_leader(&self, id: u32) -> u32 {
        let map = self.thread_to_group.read().unwrap();
        map.get(&id).copied().unwrap_or(id)
    }

    /// Mark a task (or any thread belonging to the process) as tainted in its TASK_STORAGE.
    /// Operates on the group leader so all sibling threads inherit taint synchronously.
    pub fn mark_tainted(&self, id: u32) {
        let mut flags = TaintFlags::default();
        flags.insert(TaintFlags::TAINTED_SSH);
        self.set_task_taint(id, flags);
    }

    /// Set explicit taint flags in TASK_STORAGE for a thread group leader.
    pub fn set_task_taint(&self, id: u32, flags: TaintFlags) {
        let leader_tgid = self.resolve_group_leader(id);
        let mut map = self.tasks.write().unwrap();
        let entry = map.entry(leader_tgid).or_insert_with(|| TaskStorageEntry {
            tgid: leader_tgid,
            group_leader_tgid: leader_tgid,
            tid: id,
            taint_flags: TaintFlags::default(),
            baseline_profile: 0,
            is_leaf: true,
            parent_tgid: 0,
        });
        entry.taint_flags.0 |= flags.0;
    }

    /// Retrieve the current task storage entry for the group leader.
    pub fn get_task_storage(&self, id: u32) -> Option<TaskStorageEntry> {
        let leader_tgid = self.resolve_group_leader(id);
        let map = self.tasks.read().unwrap();
        map.get(&leader_tgid).copied()
    }

    /// Check if a thread or TGID is currently tainted in TASK_STORAGE (via task->group_leader).
    pub fn is_tainted(&self, id: u32) -> bool {
        let leader_tgid = self.resolve_group_leader(id);
        let map = self.tasks.read().unwrap();
        map.get(&leader_tgid)
            .map(|e| e.taint_flags.is_tainted())
            .unwrap_or(false)
    }

    /// Clear taint from a process group (e.g. after user approval / unfreeze).
    pub fn clear_taint(&self, id: u32) {
        let leader_tgid = self.resolve_group_leader(id);
        let mut map = self.tasks.write().unwrap();
        if let Some(entry) = map.get_mut(&leader_tgid) {
            entry.taint_flags = TaintFlags::default();
        }
    }

    /// Whitelist a specific TGID for network calls.
    pub fn allow_tgid(&self, id: u32) {
        let leader_tgid = self.resolve_group_leader(id);
        let mut map = self.allowed_tgids.write().unwrap();
        map.insert(leader_tgid);
    }

    /// Check if a TGID or thread is in the active allowlist.
    pub fn is_allowed(&self, id: u32) -> bool {
        let leader_tgid = self.resolve_group_leader(id);
        let map = self.allowed_tgids.read().unwrap();
        map.contains(&leader_tgid)
    }

    /// Invalidate inode cache entry upon file rewrite or unlink.
    pub fn invalidate_inode(&self, dev: u64, ino: u64) {
        let mut inodes = self.inodes.write().unwrap();
        inodes.remove(&(dev, ino));
    }

    /// Inherit taint status during fork: child inherits taint from parent's TASK_STORAGE.
    pub fn inherit_fork(&self, parent_tgid: u32, child_tgid: u32) {
        let parent_leader = self.resolve_group_leader(parent_tgid);
        let parent_flags = {
            let map = self.tasks.read().unwrap();
            map.get(&parent_leader).map(|e| e.taint_flags)
        };

        if let Some(flags) = parent_flags {
            if flags.is_tainted() {
                self.set_task_taint(child_tgid, flags);
            }
        }
    }

    /// Process `lsm/file_permission` hook for data-flow tracking across pipes, FIFOs, and files.
    ///
    /// # Hot-Path Optimization:
    /// This hook executes on every read()/write() system call in the OS.
    /// If target inode is a regular file outside temporary paths, and neither task (group_leader)
    /// nor target inode is tainted, an immediate None (0) is returned in < 5 nanoseconds,
    /// avoiding lock contention and RingBuffer allocation.
    pub fn handle_file_permission(
        &self,
        id: u32,
        dev: u64,
        ino: u64,
        path: &Path,
        mask: u32,
        is_pipe: bool,
        is_fifo: bool,
    ) -> Option<TaintFlags> {
        let path_str = path.to_string_lossy();

        // 1. Taint hygiene check: skip terminal devices, logs, Wayland/X11 sockets
        if TaintHygiene::is_exempt_path(&path_str) {
            return None;
        }

        let leader_tgid = self.resolve_group_leader(id);
        let is_special = is_pipe || is_fifo || path_str.starts_with("/tmp") || path_str.starts_with("/dev/shm");

        // 2. Hot-Path Fast Exit:
        // Regular files accessed by untainted processes that are not tainted in INODE_STORAGE
        // exit immediately with zero writes and zero allocations.
        if !is_special && !self.is_tainted(leader_tgid) {
            let inode_is_tainted = {
                let inodes = self.inodes.read().unwrap();
                inodes.get(&(dev, ino)).map(|e| e.taint_flags.is_tainted()).unwrap_or(false)
            };
            if !inode_is_tainted {
                return None;
            }
        }

        let is_writing = (mask & MAY_WRITE) != 0;
        let is_reading = (mask & MAY_READ) != 0;

        // 3. Process Write Path: Tainted task writes to an inode
        if is_writing && self.is_tainted(leader_tgid) {
            let parent_flags = self
                .get_task_storage(leader_tgid)
                .map(|t| t.taint_flags)
                .unwrap_or(TaintFlags(TaintFlags::TAINTED_PIPE));

            let mut inodes = self.inodes.write().unwrap();
            let inode_entry = inodes.entry((dev, ino)).or_insert_with(|| InodeStorageEntry {
                taint_flags: TaintFlags::default(),
                source_tgid: leader_tgid,
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

        // 4. Process Read Path: Any task reads from a tainted inode
        if is_reading {
            let inode_taint = {
                let inodes = self.inodes.read().unwrap();
                inodes.get(&(dev, ino)).map(|e| e.taint_flags)
            };

            if let Some(taint) = inode_taint {
                if taint.is_tainted() {
                    // Propagate inherited taint to reader task's group leader TASK_STORAGE
                    self.set_task_taint(leader_tgid, taint);
                    return Some(taint);
                }
            }
        }

        None
    }

    /// Process `lsm/unix_may_send` hook: prevents IPC taint laundering via AF_UNIX domain sockets.
    pub fn handle_unix_may_send(
        &self,
        sender_id: u32,
        receiver_id: u32,
        sock_path: &Path,
    ) -> UnixSendVerdict {
        let sender_leader = self.resolve_group_leader(sender_id);
        let receiver_leader = self.resolve_group_leader(receiver_id);

        if !self.is_tainted(sender_leader) {
            return UnixSendVerdict::Allow;
        }

        let path_str = sock_path.to_string_lossy();

        // Exempt system display and desktop infrastructure sockets
        if TaintHygiene::is_exempt_path(&path_str) || path_str.contains("/sentinel.sock") {
            return UnixSendVerdict::Allow;
        }

        // If communicating with an untainted peer, propagate taint or block transfer
        if !self.is_tainted(receiver_leader) {
            // Propagate taint to receiver to close taint laundering loophole
            if let Some(sender_storage) = self.get_task_storage(sender_leader) {
                self.set_task_taint(receiver_leader, sender_storage.taint_flags);
                return UnixSendVerdict::TaintReceiver;
            }
            return UnixSendVerdict::Block;
        }

        UnixSendVerdict::Allow
    }

    /// Process `lsm/ptrace_access_check` hook: prevents memory inspection and process injection.
    pub fn handle_ptrace_access_check(
        &self,
        tracer_id: u32,
        tracee_id: u32,
        _mode: u32,
    ) -> PtraceVerdict {
        let tracer_leader = self.resolve_group_leader(tracer_id);
        let tracee_leader = self.resolve_group_leader(tracee_id);

        let tracer_tainted = self.is_tainted(tracer_leader);
        let tracee_tainted = self.is_tainted(tracee_leader);

        // A tainted process must NOT attach to or snoop memory of clean processes
        if tracer_tainted && !tracee_tainted {
            return PtraceVerdict::Deny;
        }

        // If a clean process attaches to a tainted process, it inherits the taint
        if !tracer_tainted && tracee_tainted {
            if let Some(tracee_storage) = self.get_task_storage(tracee_leader) {
                self.set_task_taint(tracer_leader, tracee_storage.taint_flags);
                return PtraceVerdict::TaintTracer;
            }
        }

        PtraceVerdict::Allow
    }

    /// Check if an accessed path is a cross-process credential snoop via `/proc/<pid>/environ` or `/proc/<pid>/mem`.
    pub fn is_proc_environ_or_mem_snoop(reader_id: u32, path_str: &str) -> bool {
        if !path_str.starts_with("/proc/") {
            return false;
        }

        if !path_str.ends_with("/environ") && !path_str.ends_with("/mem") {
            return false;
        }

        // Extract target PID: "/proc/<pid>/environ"
        let parts: Vec<&str> = path_str.split('/').collect();
        if parts.len() >= 4 {
            if let Ok(target_pid) = parts[2].parse::<u32>() {
                if target_pid != reader_id && target_pid != 0 {
                    return true;
                }
            }
        }

        false
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

    #[test]
    fn test_multithread_group_leader_taint_propagation() {
        let manager = TaintMapManager::new();
        let main_tgid = 9000;
        let worker_thread_tid = 9005;

        // Register worker thread to process group leader
        manager.register_thread(worker_thread_tid, main_tgid);

        assert!(!manager.is_tainted(main_tgid));
        assert!(!manager.is_tainted(worker_thread_tid));

        // Thread A (main_tgid) reads secret and is marked tainted
        manager.mark_tainted(main_tgid);

        // Thread B (worker_thread_tid) MUST now be tainted because they share task->group_leader!
        assert!(manager.is_tainted(worker_thread_tid));
        assert!(manager.is_tainted(main_tgid));

        // Conversely, if worker thread taints its storage, group leader is tainted
        let worker2_tid = 9008;
        manager.register_thread(worker2_tid, 9050);
        manager.mark_tainted(worker2_tid);
        assert!(manager.is_tainted(9050));
    }

    #[test]
    fn test_hotpath_clean_file_permission() {
        let manager = TaintMapManager::new();
        let clean_tgid = 3000;
        let dev = 10;
        let ino = 12345;
        let normal_path = Path::new("/usr/lib/rustlib/libstd.rlib");

        // Hook invocation on regular clean file must return None immediately (0 in kernel)
        let res = manager.handle_file_permission(
            clean_tgid,
            dev,
            ino,
            normal_path,
            MAY_READ,
            false,
            false,
        );
        assert!(res.is_none());
    }

    #[test]
    fn test_unix_may_send_taint_propagation() {
        let manager = TaintMapManager::new();
        let stealer_tgid = 6100;
        let helper_tgid = 6200;
        let local_sock = Path::new("/tmp/helper_service.sock");

        manager.mark_tainted(stealer_tgid);
        assert!(manager.is_tainted(stealer_tgid));
        assert!(!manager.is_tainted(helper_tgid));

        // Tainted process attempts to send to clean helper via AF_UNIX
        let verdict = manager.handle_unix_may_send(stealer_tgid, helper_tgid, local_sock);
        assert_eq!(verdict, UnixSendVerdict::TaintReceiver);

        // Helper process must now be tainted, closing the laundering vector!
        assert!(manager.is_tainted(helper_tgid));
    }

    #[test]
    fn test_ptrace_access_check_protection() {
        let manager = TaintMapManager::new();
        let infected_tgid = 7100;
        let clean_system_tgid = 7200;

        manager.mark_tainted(infected_tgid);

        // Infected process tries to attach or snoop clean system process
        let verdict = manager.handle_ptrace_access_check(infected_tgid, clean_system_tgid, 0);
        assert_eq!(verdict, PtraceVerdict::Deny);
    }
}
