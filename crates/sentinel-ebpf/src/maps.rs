//! eBPF map wrappers and in-kernel object storage managers (TASK_STORAGE, INODE_STORAGE, SK_STORAGE).
//!
//! Replaces legacy PID/TGID maps with task/inode/socket storage to eliminate PID reuse races,
//! memory leaks on process exit, and enforce taint hygiene across pipes and files.

use serde::{Deserialize, Serialize};
use std::collections::{HashMap, HashSet};
use std::path::Path;
use std::sync::atomic::{AtomicU32, AtomicU64, Ordering};
use std::sync::{Arc, RwLock};

use sentinel_common::events::{
    decode_flow_mark, encode_flow_mark, FlowContext, MAY_EXEC, MAY_READ, MAY_WRITE,
    SENTINEL_MARK_FLOW_ID_MASK,
};

/// Bitflags representing scoped taint states and secret domains of a task or inode object.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, Serialize, Deserialize)]
pub struct TaintFlags(pub u64);

impl TaintFlags {
    pub const NONE: u64 = 0;
    pub const BIT_SSH_KEYS: u64 = 1 << 0;       // ~/.ssh/*
    pub const BIT_CLOUD_CREDS: u64 = 1 << 1;    // ~/.aws/*, ~/.kube/*, ~/.config/gcloud/*, ~/.gnupg/*
    pub const BIT_CHROMIUM_DATA: u64 = 1 << 2;  // ~/.config/google-chrome/*, ~/.config/chromium/*
    pub const BIT_FIREFOX_DATA: u64 = 1 << 3;   // ~/.mozilla/firefox/*
    pub const BIT_TELEGRAM_DATA: u64 = 1 << 4;  // ~/.local/share/TelegramDesktop/tdata/*
    pub const BIT_CRYPTO_WALLETS: u64 = 1 << 5; // crypto wallet files
    pub const BIT_PIPE: u64 = 1 << 6;
    pub const BIT_TEMPFILE: u64 = 1 << 7;
    pub const BIT_MMAP_SHARED: u64 = 1 << 8;
    pub const BIT_SCM_RIGHTS: u64 = 1 << 9;
    pub const PENDING_INSPECT: u64 = 1 << 10;
    pub const TRUSTED_SYSTEM_PKG: u64 = 1 << 11;
    pub const SECRET_NON_OWNER: u64 = 1 << 12;

    // Backward-compatible aliases
    pub const TAINTED_SSH: u64 = Self::BIT_SSH_KEYS;
    pub const TAINTED_GPG: u64 = Self::BIT_CLOUD_CREDS;
    pub const TAINTED_BROWSER: u64 = Self::BIT_CHROMIUM_DATA;
    pub const TAINTED_TELEGRAM: u64 = Self::BIT_TELEGRAM_DATA;
    pub const TAINTED_CRYPTO: u64 = Self::BIT_CRYPTO_WALLETS;
    pub const TAINTED_PIPE: u64 = Self::BIT_PIPE;
    pub const TAINTED_TEMPFILE: u64 = Self::BIT_TEMPFILE;
    pub const TAINT_MMAP_SHARED: u64 = Self::BIT_MMAP_SHARED;
    pub const TAINT_SCM_RIGHTS: u64 = Self::BIT_SCM_RIGHTS;

    pub fn is_empty(&self) -> bool {
        self.0 == Self::NONE
    }

    pub fn contains(&self, flag: u64) -> bool {
        (self.0 & flag) != 0
    }

    pub fn insert(&mut self, flag: u64) {
        self.0 |= flag;
    }

    pub fn remove(&mut self, flag: u64) {
        self.0 &= !flag;
    }

    pub fn bits(&self) -> u64 {
        self.0
    }

    pub fn from_bits_truncate(bits: u64) -> Self {
        Self(bits)
    }

    pub fn is_tainted(&self) -> bool {
        (self.0 & (Self::BIT_SSH_KEYS
            | Self::BIT_CLOUD_CREDS
            | Self::BIT_CHROMIUM_DATA
            | Self::BIT_FIREFOX_DATA
            | Self::BIT_TELEGRAM_DATA
            | Self::BIT_CRYPTO_WALLETS
            | Self::BIT_PIPE
            | Self::BIT_TEMPFILE
            | Self::BIT_MMAP_SHARED
            | Self::BIT_SCM_RIGHTS
            | Self::SECRET_NON_OWNER)) != 0
    }
}

impl std::ops::BitAnd<u64> for TaintFlags {
    type Output = u64;
    fn bitand(self, rhs: u64) -> Self::Output {
        self.0 & rhs
    }
}

impl std::ops::BitAnd<TaintFlags> for TaintFlags {
    type Output = TaintFlags;
    fn bitand(self, rhs: TaintFlags) -> Self::Output {
        TaintFlags(self.0 & rhs.0)
    }
}

impl std::ops::BitOr<u64> for TaintFlags {
    type Output = TaintFlags;
    fn bitor(self, rhs: u64) -> Self::Output {
        TaintFlags(self.0 | rhs)
    }
}

impl std::ops::BitOr<TaintFlags> for TaintFlags {
    type Output = TaintFlags;
    fn bitor(self, rhs: TaintFlags) -> Self::Output {
        TaintFlags(self.0 | rhs.0)
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
    pub is_verified_gui: bool,
    pub is_sealed: bool,
    pub dns_query_count: u32,
    pub cumulative_dns_subdomain_bytes: u32,
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
    pub is_trusted_system_pkg: bool,
    pub inode_version: u64,
    pub fs_verity_hash: Option<[u8; 32]>,
}

/// In-kernel entry stored in `BPF_MAP_TYPE_SK_STORAGE` per socket struct.
#[derive(Debug, Clone, Copy, Default)]
pub struct SkStorageEntry {
    pub tgid: u32,
    pub so_mark: u32,
    pub held_in_nfqueue: bool,
    pub requires_reval: bool,
}

/// Verdict for `lsm/unix_may_send` hook.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum UnixSendVerdict {
    /// Safe message transfer permitted without state alteration.
    Allow,
    /// Message allowed, but receiver process inherits taint (Taint Propagation).
    TaintReceiver,
    /// Block transfer (-EPERM / -EACCES) to prevent covert data exfiltration or laundering.
    Block,
    /// Local resolver query (127.0.0.53:53 / systemd-resolved socket) requires DNS inspection.
    InspectDns,
}

impl PartialEq<bool> for UnixSendVerdict {
    fn eq(&self, other: &bool) -> bool {
        match self {
            UnixSendVerdict::TaintReceiver => *other,
            _ => !*other,
        }
    }
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

impl PtraceVerdict {
    pub fn as_errno(&self) -> i32 {
        match self {
            PtraceVerdict::Allow => 0,
            PtraceVerdict::Deny => -1,
            PtraceVerdict::TaintTracer => 0,
        }
    }
}

impl PartialEq<i32> for PtraceVerdict {
    fn eq(&self, other: &i32) -> bool {
        self.as_errno() == *other
    }
}

/// Verdict for `lsm/mmap_file` hook.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum MmapVerdict {
    /// Normal file mapping allowed.
    Allow,
    /// Reading mapped secret: taint reader task.
    TaintTask,
    /// Tainted task mapped file with PROT_WRITE | MAP_SHARED: mark target inode tainted.
    TaintInode,
    /// Executable mapping on unlinked/tmpfs file: flag potential fileless execution (+35).
    FlagAnonExec,
    /// Tainted execution blocked (-EPERM / Deny).
    TaintedExecutionBlocked,
    /// GUI sealing violation: unverified / non-root / writable library blocked (-EPERM).
    DenyMmap,
}

/// Verdict for `lsm/file_receive` (SCM_RIGHTS) hook.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FileReceiveVerdict {
    /// Clean descriptor transfer allowed.
    Allow,
    /// Transferred descriptor is tainted or a secret: taint receiver task.
    TaintReceiver,
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
                || path.ends_with(".pem")
                || path.ends_with(".key")
                || path.ends_with(".ppk")
                || path.ends_with(".p12")
                || path.ends_with(".pfx")
                || path.ends_with(".ovpn")
                || path.ends_with("/environment")
                || path.ends_with("/rc")
            {
                return true;
            }
        }

        // Host SSH private keys
        if path.starts_with("/etc/ssh/ssh_host_") && path.ends_with("_key") {
            return true;
        }

        // Developer & Cloud credentials
        if path.ends_with("/.git-credentials")
            || path.ends_with("/.netrc")
            || path.ends_with("/.authinfo")
            || path.ends_with("/.pgpass")
            || path.ends_with("/.my.cnf")
            || path.ends_with("/.npmrc")
            || path.ends_with("/.pypirc")
            || path.ends_with("/.docker/config.json")
            || path.contains("/.config/gh/hosts.yml")
            || path.contains("/.config/glab-cli/config.yml")
            || path.contains("/.aws/")
            || path.contains("/.kube/")
            || path.contains("/.config/gcloud/")
        {
            return true;
        }

        // Shell history files
        if path.ends_with("/.bash_history") || path.ends_with("/.zsh_history") || path.ends_with("/.histfile") {
            return true;
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

        // Cloud provider credentials
        if path.contains("/.aws/")
            || path.contains("/.kube/")
            || path.contains("/.config/gcloud/")
        {
            return true;
        }

        false
    }

    /// Return the scoped secret domain bitmask owned by this executable name (Owner Policy).
    pub fn get_owner_secret_domain(exe_name: &str) -> u64 {
        if exe_name == "chrome" || exe_name == "google-chrome" || exe_name == "chromium" || exe_name == "brave" {
            TaintFlags::BIT_CHROMIUM_DATA
        } else if exe_name == "firefox" || exe_name == "firefox-bin" {
            TaintFlags::BIT_FIREFOX_DATA
        } else if exe_name == "Telegram" || exe_name == "telegram-desktop" {
            TaintFlags::BIT_TELEGRAM_DATA
        } else if exe_name == "ssh" || exe_name == "ssh-add" || exe_name == "scp" || exe_name == "sftp" || exe_name == "git" {
            TaintFlags::BIT_SSH_KEYS
        } else if exe_name == "aws" || exe_name == "kubectl" || exe_name == "gcloud" {
            TaintFlags::BIT_CLOUD_CREDS
        } else {
            TaintFlags::NONE
        }
    }

    /// Return the scoped secret domain bitmask for an accessed path.
    pub fn get_secret_domain_for_path(path_str: &str) -> u64 {
        if path_str.contains("/.ssh/") || path_str.starts_with("/etc/ssh/ssh_host_") {
            TaintFlags::BIT_SSH_KEYS
        } else if path_str.contains("/.aws/")
            || path_str.contains("/.kube/")
            || path_str.contains("/.config/gcloud/")
            || path_str.contains("/.gnupg/")
            || path_str.ends_with("/.git-credentials")
            || path_str.ends_with("/.netrc")
            || path_str.ends_with("/.authinfo")
            || path_str.ends_with("/.pgpass")
            || path_str.ends_with("/.my.cnf")
            || path_str.ends_with("/.npmrc")
            || path_str.ends_with("/.pypirc")
            || path_str.ends_with("/.docker/config.json")
            || path_str.contains("/.config/gh/hosts.yml")
            || path_str.contains("/.config/glab-cli/config.yml")
            || path_str.ends_with("/.bash_history")
            || path_str.ends_with("/.zsh_history")
            || path_str.ends_with("/.histfile")
        {
            TaintFlags::BIT_CLOUD_CREDS
        } else if path_str.contains("/google-chrome/") || path_str.contains("/chromium/") {
            TaintFlags::BIT_CHROMIUM_DATA
        } else if path_str.contains("/.mozilla/firefox/") || path_str.contains("cookies.sqlite") {
            TaintFlags::BIT_FIREFOX_DATA
        } else if path_str.contains("/TelegramDesktop/tdata") {
            TaintFlags::BIT_TELEGRAM_DATA
        } else if path_str.contains("/.electrum/wallets") || path_str.contains("/.bitcoin/wallets") {
            TaintFlags::BIT_CRYPTO_WALLETS
        } else {
            TaintFlags::NONE
        }
    }

    /// Check if an executable is the legitimate owner of the accessed secret domain.
    pub fn is_secret_owner(exe_name: &str, path_str: &str) -> bool {
        let domain = Self::get_secret_domain_for_path(path_str);
        if domain == TaintFlags::NONE {
            return false;
        }
        let owner_domain = Self::get_owner_secret_domain(exe_name);
        (owner_domain & domain) != 0
    }

    /// Check whether a process is verified as a legitimate secret owner against binary spoofing:
    /// 1. Path matches recognized domain owner profile (e.g. /usr/bin/google-chrome, /opt/google/chrome/chrome)
    /// 2. Executable passes package/system integrity (is_trusted_system_pkg == true OR (inode_uid == 0 && (inode_mode & 0o022) == 0))
    /// 3. Process environment is uncompromised (no hostile memory mappings / unverified libs)
    pub fn is_verified_secret_owner(
        exe_path: &Path,
        _dev: u64,
        _ino: u64,
        secret_path: &Path,
        is_trusted_pkg: bool,
        inode_uid: u32,
        inode_mode: u32,
        has_untrusted_env: bool,
    ) -> bool {
        if has_untrusted_env {
            return false;
        }

        let exe_str = exe_path.to_string_lossy();
        let exe_name = exe_path.file_name().and_then(|n| n.to_str()).unwrap_or("");
        let secret_str = secret_path.to_string_lossy();

        // 1. Must match secret domain owner profile
        if !Self::is_secret_owner(exe_name, &secret_str) {
            return false;
        }

        // Must run from system location, NOT /tmp, /home, /dev/shm, etc.
        let is_system_path = exe_str.starts_with("/usr/")
            || exe_str.starts_with("/opt/")
            || exe_str.starts_with("/bin/")
            || exe_str.starts_with("/lib/");
        if !is_system_path {
            return false;
        }

        // 2. Binary must have integrity verified (trusted package or root-owned non-writable)
        let has_integrity = is_trusted_pkg || (inode_uid == 0 && (inode_mode & 0o022) == 0);
        if !has_integrity {
            return false;
        }

        true
    }

    /// Determines whether a process is an OS-level IPC broker or graphical compositor.
    /// Used to prevent "Taint Explosion" where messaging a system broker taints the entire OS.
    pub fn is_ipc_broker_name(exe_name: &str) -> bool {
        matches!(
            exe_name,
            "dbus-daemon"
                | "dbus-broker"
                | "systemd"
                | "pipewire"
                | "pipewire-pulse"
                | "wireplumber"
                | "xdg-desktop-portal"
                | "gnome-shell"
                | "kwin"
                | "kwin_wayland"
                | "kwin_x11"
                | "sway"
                | "hyprland"
                | "mutter"
                | "wayland"
        )
    }

    /// Recognizes legitimate JIT runtimes (browsers, Electron, JVM, Node.js)
    /// which legitimately allocate dynamic code pages in memory (V8, SpiderMonkey, HotSpot).
    pub fn is_known_jit_runtime(exe_name: &str) -> bool {
        matches!(
            exe_name,
            "chrome"
                | "google-chrome"
                | "firefox"
                | "firefox-bin"
                | "chromium"
                | "node"
                | "nodejs"
                | "java"
                | "code"
                | "discord"
                | "slack"
                | "electron"
        )
    }
}

/// Unified userspace manager and simulation mirror for Kernel Object Storages:
/// - BPF_MAP_TYPE_TASK_STORAGE (resolved through task->group_leader)
/// - BPF_MAP_TYPE_INODE_STORAGE
/// - BPF_MAP_TYPE_SK_STORAGE
/// - flow_mark_ctx (BPF_MAP_TYPE_HASH / LRU_HASH: mark -> FlowContext)
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
    /// Synchronous eBPF map `flow_mark_ctx` (mark -> FlowContext).
    flow_mark_ctx: Arc<RwLock<HashMap<u32, FlowContext>>>,
    /// Monotonic sequence generator for dynamic flow marks (up to 23 bits).
    flow_seq: Arc<AtomicU32>,
    /// PID of the verified sentinel-gui process for in-kernel ptrace protection.
    gui_pid: Arc<RwLock<Option<u32>>>,
    /// PID of the sentineld daemon process for self-defense.
    daemon_pid: Arc<RwLock<Option<u32>>>,
    /// Explicitly registered IPC broker TGIDs (anti-taint explosion).
    ipc_brokers: Arc<RwLock<HashSet<u32>>>,
    /// Sockets tracked in SK_STORAGE keyed by socket cookie.
    #[allow(dead_code)]
    sockets: Arc<RwLock<HashMap<u64, SkStorageEntry>>>,
    /// Inodes (dev, ino) of cryptographically verified GUI binary for BPF LSM attestation.
    gui_binary_inodes: Arc<RwLock<HashSet<(u64, u64)>>>,
    /// Last watchdog heartbeat from sentineld daemon in nanoseconds.
    last_heartbeat_ns: Arc<AtomicU64>,
}

impl TaintMapManager {
    pub fn new() -> Self {
        Self {
            tasks: Arc::new(RwLock::new(HashMap::new())),
            thread_to_group: Arc::new(RwLock::new(HashMap::new())),
            inodes: Arc::new(RwLock::new(HashMap::new())),
            allowed_tgids: Arc::new(RwLock::new(HashSet::new())),
            flow_mark_ctx: Arc::new(RwLock::new(HashMap::new())),
            flow_seq: Arc::new(AtomicU32::new(1)),
            gui_pid: Arc::new(RwLock::new(None)),
            daemon_pid: Arc::new(RwLock::new(None)),
            ipc_brokers: Arc::new(RwLock::new(HashSet::new())),
            sockets: Arc::new(RwLock::new(HashMap::new())),
            gui_binary_inodes: Arc::new(RwLock::new(HashSet::new())),
            last_heartbeat_ns: Arc::new(AtomicU64::new(0)),
        }
    }

    /// Register canonical GUI binary (dev, ino) for zero-userspace BPF LSM attestation.
    pub fn register_gui_binary(&self, dev: u64, ino: u64) {
        let mut map = self.gui_binary_inodes.write().unwrap();
        map.insert((dev, ino));
    }

    /// Check if an inode matches registered GUI binary.
    pub fn is_registered_gui_binary(&self, dev: u64, ino: u64) -> bool {
        let map = self.gui_binary_inodes.read().unwrap();
        map.contains(&(dev, ino))
    }

    /// Set verified GUI status for a process group leader in TASK_STORAGE.
    pub fn set_verified_gui(&self, tgid: u32, verified: bool) {
        let leader_tgid = self.resolve_group_leader(tgid);
        let mut map = self.tasks.write().unwrap();
        let entry = map.entry(leader_tgid).or_insert_with(|| TaskStorageEntry {
            tgid: leader_tgid,
            group_leader_tgid: leader_tgid,
            tid: tgid,
            taint_flags: TaintFlags::default(),
            baseline_profile: 0,
            is_leaf: true,
            parent_tgid: 0,
            is_verified_gui: verified,
            is_sealed: verified,
            ..Default::default()
        });
        entry.is_verified_gui = verified;
        if verified {
            entry.is_sealed = true;
        }
    }

    /// Check if a process group leader has verified GUI status in TASK_STORAGE.
    pub fn is_verified_gui(&self, tgid: u32) -> bool {
        let leader_tgid = self.resolve_group_leader(tgid);
        let map = self.tasks.read().unwrap();
        map.get(&leader_tgid).map(|e| e.is_verified_gui).unwrap_or(false)
    }

    /// Update the in-kernel watchdog heartbeat timestamp.
    pub fn update_heartbeat(&self, now_ns: u64) {
        self.last_heartbeat_ns.store(now_ns, Ordering::SeqCst);
    }

    /// Read the latest watchdog heartbeat timestamp.
    pub fn get_heartbeat(&self) -> u64 {
        self.last_heartbeat_ns.load(Ordering::SeqCst)
    }

    /// Check if daemon is currently responsive (within 2.0s watchdog limit).
    pub fn is_daemon_alive(&self, now_ns: u64) -> bool {
        let last = self.get_heartbeat();
        if last == 0 {
            return true; // Grace period during startup
        }
        now_ns.saturating_sub(last) <= 2_000_000_000
    }

    /// Mark an inode as a trusted system package in INODE_STORAGE with version validation and optional fs-verity digest.
    pub fn mark_inode_trusted_ext(&self, dev: u64, ino: u64, version: u64, fs_verity: Option<[u8; 32]>) {
        let mut inodes = self.inodes.write().unwrap();
        let entry = inodes.entry((dev, ino)).or_insert_with(|| InodeStorageEntry {
            taint_flags: TaintFlags::default(),
            source_tgid: 0,
            dev,
            ino,
            is_pipe: false,
            is_fifo: false,
            is_trusted_system_pkg: true,
            inode_version: version,
            fs_verity_hash: fs_verity,
        });
        entry.is_trusted_system_pkg = true;
        entry.inode_version = version;
        entry.fs_verity_hash = fs_verity;
    }

    /// Mark an inode as a trusted system package in INODE_STORAGE with version validation.
    pub fn mark_inode_trusted(&self, dev: u64, ino: u64, version: u64) {
        self.mark_inode_trusted_ext(dev, ino, version, None);
    }

    /// Check if an inode is verified in INODE_STORAGE and version has not drifted.
    pub fn is_inode_trusted(&self, dev: u64, ino: u64, current_version: u64) -> bool {
        let inodes = self.inodes.read().unwrap();
        if let Some(entry) = inodes.get(&(dev, ino)) {
            if entry.is_trusted_system_pkg {
                if current_version == 0 || entry.inode_version == current_version {
                    return true;
                }
            }
        }
        false
    }

    /// Retrieve the taint flags for a task ID.
    pub fn get_flags(&self, id: u32) -> TaintFlags {
        let leader_tgid = self.resolve_group_leader(id);
        let map = self.tasks.read().unwrap();
        map.get(&leader_tgid).map(|e| e.taint_flags).unwrap_or_default()
    }

    /// Register verified GUI process PID for in-kernel ptrace and memory protection.
    pub fn set_gui_pid(&self, pid: u32) {
        let mut g = self.gui_pid.write().unwrap();
        *g = Some(pid);
    }

    /// Get current registered GUI PID.
    pub fn get_gui_pid(&self) -> Option<u32> {
        *self.gui_pid.read().unwrap()
    }

    /// Register daemon PID for kernel self-defense.
    pub fn set_daemon_pid(&self, pid: u32) {
        let mut d = self.daemon_pid.write().unwrap();
        *d = Some(pid);
    }

    /// Register an IPC broker process to prevent transitive taint explosion.
    pub fn register_ipc_broker(&self, tgid: u32) {
        let leader = self.resolve_group_leader(tgid);
        let mut b = self.ipc_brokers.write().unwrap();
        b.insert(leader);
    }

    /// Check if a process is an active IPC broker.
    pub fn is_ipc_broker(&self, tgid: u32) -> bool {
        let leader = self.resolve_group_leader(tgid);
        let b = self.ipc_brokers.read().unwrap();
        b.contains(&leader)
    }

    /// Register a new flow context synchronously before setting mark on the socket/packet.
    ///
    /// # Synchronous eBPF Map Flow:
    /// In kernel eBPF, the program first inserts `FlowContext` into `flow_mark_ctx` by mark,
    /// and then applies the mark to the socket/packet. When sentineld receives the packet
    /// from NFQUEUE, it looks up `FlowContext` by `NFQA_MARK` immediately, eliminating any
    /// race condition with RingBuffer!
    pub fn register_flow_context(
        &self,
        tgid: u32,
        pid: u32,
        uid: u32,
        sock_cookie: u64,
        exe_inode: u64,
        requires_reval: bool,
    ) -> u32 {
        let leader_tgid = self.resolve_group_leader(tgid);
        let taint_flags = self
            .get_task_storage(leader_tgid)
            .map(|t| t.taint_flags.0)
            .unwrap_or(0);

        let seq = self.flow_seq.fetch_add(1, Ordering::SeqCst) & SENTINEL_MARK_FLOW_ID_MASK;
        let mark = encode_flow_mark(seq, requires_reval);

        let ctx = FlowContext {
            mark,
            tgid: leader_tgid,
            pid,
            uid,
            cgroup_id: 0,
            sock_cookie,
            taint_flags,
            exe_inode,
            exec_id: 0,
        };

        let mut map = self.flow_mark_ctx.write().unwrap();
        map.insert(seq, ctx);
        mark
    }

    /// Look up FlowContext by packet mark (instant synchronous retrieval upon NFQUEUE arrival).
    pub fn lookup_flow_context(&self, mark: u32) -> Option<FlowContext> {
        let (_, _, flow_id) = decode_flow_mark(mark);
        let map = self.flow_mark_ctx.read().unwrap();
        map.get(&flow_id).copied()
    }

    /// Direct insertion of flow context by mark/flow_id (for testing and direct eBPF simulation).
    pub fn insert_flow_context(&self, mark: u32, ctx: FlowContext) {
        let (_, _, flow_id) = decode_flow_mark(mark);
        let mut map = self.flow_mark_ctx.write().unwrap();
        map.insert(flow_id, ctx);
    }

    /// Retrieve flow context by mark (alias for lookup_flow_context).
    pub fn get_flow_context(&self, mark: u32) -> Option<FlowContext> {
        self.lookup_flow_context(mark)
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
            ..Default::default()
        });
        entry.taint_flags.0 |= flags.0;
    }

    /// Record a DNS query from a process, returning whether it exceeds the cumulative tunneling threshold.
    ///
    /// # Anti-Chunking DNS Exfiltration Defense:
    /// Tracks query counts and cumulative subdomain label lengths for tainted processes.
    /// If an attacker attempts to slice stolen data into short chunks (< 16 chars),
    /// sending >= 3 suspicious queries or accumulating >= 48 subdomain bytes triggers detection.
    pub fn record_dns_query(&self, tgid: u32, query_domain: &str) -> bool {
        let leader = self.resolve_group_leader(tgid);
        let is_tainted = self.is_tainted(leader);
        if !is_tainted {
            return false;
        }

        let clean = query_domain.trim_end_matches('.');
        let labels: Vec<&str> = clean.split('.').collect();
        let subdomain_bytes: u32 = if labels.len() > 2 {
            labels[..labels.len() - 2].iter().map(|l| l.len() as u32).sum()
        } else if let Some(first) = labels.first() {
            first.len() as u32
        } else {
            0
        };

        let mut tasks = self.tasks.write().unwrap();
        if let Some(entry) = tasks.get_mut(&leader) {
            entry.dns_query_count += 1;
            entry.cumulative_dns_subdomain_bytes += subdomain_bytes;
            if entry.dns_query_count >= 3 || entry.cumulative_dns_subdomain_bytes >= 48 {
                return true;
            }
        }
        false
    }

    /// Returns whether the task has exceeded cumulative DNS tunneling thresholds.
    pub fn is_cumulative_dns_tunnel_triggered(&self, tgid: u32) -> bool {
        let leader = self.resolve_group_leader(tgid);
        let tasks = self.tasks.read().unwrap();
        tasks.get(&leader)
            .map(|t| t.dns_query_count >= 3 || t.cumulative_dns_subdomain_bytes >= 48)
            .unwrap_or(false)
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
        let is_writing = (mask & MAY_WRITE) != 0;
        let is_reading = (mask & MAY_READ) != 0;

        // 2. Hot-Path Fast Exit:
        // Regular files accessed by untainted processes that are not tainted in INODE_STORAGE
        // and do not require cache invalidation exit immediately with zero writes and zero allocations.
        if !is_special && !self.is_tainted(leader_tgid) {
            let inode_needs_handling = {
                let inodes = self.inodes.read().unwrap();
                inodes
                    .get(&(dev, ino))
                    .map(|e| e.taint_flags.is_tainted() || (is_writing && e.is_trusted_system_pkg))
                    .unwrap_or(false)
            };
            if !inode_needs_handling {
                return None;
            }
        }

        // 3. Process Write Path:
        if is_writing {
            // Invalidate in-kernel cached package trust upon any file write
            {
                let mut inodes = self.inodes.write().unwrap();
                if let Some(entry) = inodes.get_mut(&(dev, ino)) {
                    entry.is_trusted_system_pkg = false;
                }
            }

            // Staging Attack Defense: Tainted task writes to ANY file (including user cache, temp files, intermediate logs)
            if self.is_tainted(leader_tgid) {
                let parent_flags = self
                    .get_task_storage(leader_tgid)
                    .map(|t| t.taint_flags)
                    .unwrap_or(TaintFlags(TaintFlags::BIT_TEMPFILE));

                let mut inodes = self.inodes.write().unwrap();
                let inode_entry = inodes.entry((dev, ino)).or_insert_with(|| InodeStorageEntry {
                    taint_flags: TaintFlags::default(),
                    source_tgid: leader_tgid,
                    dev,
                    ino,
                    is_pipe,
                    is_fifo,
                    is_trusted_system_pkg: false,
                    inode_version: 0,
                    fs_verity_hash: None,
                });

                inode_entry.taint_flags.0 |= parent_flags.0;
                if is_pipe || is_fifo {
                    inode_entry.taint_flags.insert(TaintFlags::BIT_PIPE);
                } else {
                    inode_entry.taint_flags.insert(TaintFlags::BIT_TEMPFILE);
                }
                inode_entry.is_trusted_system_pkg = false;

                return Some(inode_entry.taint_flags);
            }
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

    /// Process `lsm/mmap_file` hook with explicit inode attributes.
    ///
    /// # Zero-Userspace GUI Memory Sealing (Security Hardening):
    /// Rather than relying on fragile path blacklists (which can be bypassed via ~/.cache,
    /// ~/.config, /var/tmp, or /run/user/$UID), any executable mapping (`PROT_EXEC`) requested by a process
    /// with `is_verified_gui == 1` is strictly audited against an inode attribute whitelist:
    /// - File MUST belong to root (`inode_uid == 0`).
    /// - File MUST NOT have write permissions for group or others (`(inode_mode & 0o022) == 0`).
    /// - File system / path must NOT be temporary or user-writable.
    /// Violations immediately strip `is_verified_gui = 0` and deny execution (`-EPERM`).
    pub fn handle_mmap_file_attrs(
        &self,
        id: u32,
        dev: u64,
        ino: u64,
        path: &Path,
        prot: u32,
        flags: u32,
        inode_uid: u32,
        inode_mode: u32,
    ) -> MmapVerdict {
        let leader_tgid = self.resolve_group_leader(id);
        let path_str = path.to_string_lossy();

        if TaintHygiene::is_exempt_path(&path_str) {
            return MmapVerdict::Allow;
        }

        let is_write_shared = (prot & 0x2 != 0) && (flags & 0x1 != 0 /* MAP_SHARED */);
        let is_exec = (prot & 0x4) != 0;

        // 0. Zero-Userspace GUI Sealing:
        // Audited against Inode Attribute Whitelist:
        if is_exec && self.is_verified_gui(leader_tgid) {
            let is_root_owned = inode_uid == 0;
            let is_not_writable = (inode_mode & 0o022) == 0;
            let is_untrusted_loc = path_str.starts_with("/tmp")
                || path_str.starts_with("/dev/shm")
                || path_str.starts_with("/home")
                || path_str.starts_with("/var/tmp")
                || path_str.contains("/.local/")
                || path_str.contains("/.cache/")
                || path_str.contains("/.config/")
                || path_str.contains("/run/user/")
                || path_str.contains("/Downloads/")
                || path_str.contains("(deleted)");

            if !is_root_owned || !is_not_writable || is_untrusted_loc {
                self.set_verified_gui(leader_tgid, false);
                return MmapVerdict::DenyMmap;
            }
        }

        // 1. Tainted Execution Blocked:
        // A tainted process attempting to map an executable payload is blocked in kernel
        if is_exec && self.is_tainted(leader_tgid) {
            return MmapVerdict::TaintedExecutionBlocked;
        }

        // 2. Executable mapping on unlinked file or tmpfs / memfd -> FlagAnonExec
        if is_exec {
            let is_unlinked_or_tmpfs = path_str.contains("(deleted)")
                || path_str.starts_with("/dev/shm")
                || path_str.starts_with("/memfd:")
                || path_str.contains("/memfd:");
            if is_unlinked_or_tmpfs {
                return MmapVerdict::FlagAnonExec;
            }
        }

        // 3. Secret file mapped -> Taint reader process
        if TaintHygiene::is_strictly_private_secret(&path_str) {
            let domain = TaintHygiene::get_secret_domain_for_path(&path_str);
            let mut taint = TaintFlags::default();
            taint.insert(domain);
            taint.insert(TaintFlags::BIT_MMAP_SHARED);
            self.set_task_taint(leader_tgid, taint);
            return MmapVerdict::TaintTask;
        }

        // 4. Tainted process maps normal file with PROT_WRITE | MAP_SHARED -> Taint target inode
        if is_write_shared && self.is_tainted(leader_tgid) {
            let parent_flags = self
                .get_task_storage(leader_tgid)
                .map(|t| t.taint_flags)
                .unwrap_or(TaintFlags(TaintFlags::BIT_MMAP_SHARED));

            let mut inodes = self.inodes.write().unwrap();
            let inode_entry = inodes.entry((dev, ino)).or_insert_with(|| InodeStorageEntry {
                taint_flags: TaintFlags::default(),
                source_tgid: leader_tgid,
                dev,
                ino,
                is_pipe: false,
                is_fifo: false,
                is_trusted_system_pkg: false,
                inode_version: 0,
                fs_verity_hash: None,
            });

            inode_entry.taint_flags.0 |= parent_flags.0;
            inode_entry.taint_flags.insert(TaintFlags::BIT_MMAP_SHARED);
            return MmapVerdict::TaintInode;
        }

        // 5. Any process maps an already-tainted inode -> inherit taint
        let inode_tainted = {
            let inodes = self.inodes.read().unwrap();
            inodes.get(&(dev, ino)).map(|e| e.taint_flags)
        };

        if let Some(taint) = inode_tainted {
            if taint.is_tainted() {
                self.set_task_taint(leader_tgid, taint);
                return MmapVerdict::TaintTask;
            }
        }

        MmapVerdict::Allow
    }

    /// Process `lsm/mmap_file` hook with automatic inode attribute inference.
    pub fn handle_mmap_file(
        &self,
        id: u32,
        dev: u64,
        ino: u64,
        path: &Path,
        prot: u32,
        flags: u32,
    ) -> MmapVerdict {
        let path_str = path.to_string_lossy();
        let (default_uid, default_mode) = if path_str.starts_with("/usr")
            || path_str.starts_with("/lib")
            || path_str.starts_with("/bin")
            || path_str.starts_with("/opt")
        {
            (0, 0o755)
        } else {
            (1000, 0o777)
        };
        self.handle_mmap_file_attrs(id, dev, ino, path, prot, flags, default_uid, default_mode)
    }

    /// Process `lsm/file_mprotect` hook:
    /// Intercepts memory protection promotions (e.g. mprotect(PROT_EXEC), W^X transitions)
    /// to prevent two-step injection (mmap(RW) -> mprotect(RX)) into verified GUI or tainted processes.
    pub fn handle_file_mprotect(
        &self,
        id: u32,
        path: Option<&Path>,
        _reqprot: u32,
        prot: u32,
        inode_uid: u32,
        inode_mode: u32,
    ) -> MmapVerdict {
        let leader_tgid = self.resolve_group_leader(id);
        let is_exec = (prot & MAY_EXEC != 0) || ((prot & 0x4) != 0);

        if !is_exec {
            return MmapVerdict::Allow;
        }

        // 1. Zero-Userspace GUI Memory Sealing:
        if self.is_verified_gui(leader_tgid) {
            // Anonymous memory promotion (W^X violation) or file without root ownership / with write permissions
            let is_anonymous = path.is_none();
            let is_root_owned = inode_uid == 0;
            let is_not_writable = (inode_mode & 0o022) == 0;
            let is_untrusted_loc = if let Some(p) = path {
                let s = p.to_string_lossy();
                s.starts_with("/tmp")
                    || s.starts_with("/dev/shm")
                    || s.starts_with("/home")
                    || s.starts_with("/var/tmp")
                    || s.contains("/.local/")
                    || s.contains("/.cache/")
                    || s.contains("/.config/")
                    || s.contains("/run/user/")
                    || s.contains("/Downloads/")
                    || s.contains("(deleted)")
            } else {
                true
            };

            if is_anonymous || !is_root_owned || !is_not_writable || is_untrusted_loc {
                self.set_verified_gui(leader_tgid, false);
                return MmapVerdict::DenyMmap;
            }
        }

        // 2. Tainted Execution Blocked:
        if self.is_tainted(leader_tgid) {
            return MmapVerdict::TaintedExecutionBlocked;
        }

        MmapVerdict::Allow
    }

    /// Process `lsm/file_receive` hook: intercepts descriptor passing via SCM_RIGHTS over AF_UNIX.
    pub fn handle_file_receive(
        &self,
        receiver_id: u32,
        sender_id: u32,
        dev: u64,
        ino: u64,
        path: &Path,
    ) -> FileReceiveVerdict {
        let receiver_leader = self.resolve_group_leader(receiver_id);
        let sender_leader = self.resolve_group_leader(sender_id);
        let path_str = path.to_string_lossy();

        if TaintHygiene::is_exempt_path(&path_str) {
            return FileReceiveVerdict::Allow;
        }

        let is_secret = TaintHygiene::is_strictly_private_secret(&path_str);
        let inode_tainted = {
            let inodes = self.inodes.read().unwrap();
            inodes.get(&(dev, ino)).map(|e| e.taint_flags.is_tainted()).unwrap_or(false)
        };
        let sender_tainted = self.is_tainted(sender_leader);

        if is_secret || inode_tainted || (sender_tainted && !path_str.starts_with("/usr")) {
            let mut taint = self
                .get_task_storage(sender_leader)
                .map(|t| t.taint_flags)
                .unwrap_or(TaintFlags(TaintFlags::TAINT_SCM_RIGHTS));
            taint.insert(TaintFlags::TAINT_SCM_RIGHTS);
            self.set_task_taint(receiver_leader, taint);
            return FileReceiveVerdict::TaintReceiver;
        }

        FileReceiveVerdict::Allow
    }

    /// Process `lsm/unix_may_send` hook: prevents IPC taint laundering via AF_UNIX domain sockets
    /// and guards privileged /run/sentinel/sentinel.sock from unverified callers.
    pub fn handle_unix_may_send<P: AsRef<Path>>(
        &self,
        sender_id: u32,
        receiver_id: u32,
        sock_path: P,
    ) -> UnixSendVerdict {
        let path_ref = sock_path.as_ref();
        let path_str = path_ref.to_string_lossy();
        let sender_leader = self.resolve_group_leader(sender_id);
        let receiver_leader = self.resolve_group_leader(receiver_id);

        // 1. Zero-Userspace Trust Gate for Management Socket:
        // Intercepts connect() to /run/sentinel/sentinel.sock directly in kernel space:
        // Only root (UID 0) or cryptographically verified sentinel-gui are allowed!
        if path_str.ends_with("/sentinel.sock") || path_str == "/run/sentinel/sentinel.sock" {
            let is_root = sender_leader == 0;
            let is_gui = self.is_verified_gui(sender_leader);
            if !is_root && !is_gui {
                return UnixSendVerdict::Block;
            }
            return UnixSendVerdict::Allow;
        }

        // 2. Covert DNS Tunneling Protection:
        // Intercepts requests to systemd-resolved socket (/run/systemd/resolve/io.systemd.Resolve)
        if (path_str.contains("systemd/resolve") || path_str.contains("io.systemd.Resolve"))
            && self.is_tainted(sender_leader)
        {
            return UnixSendVerdict::InspectDns;
        }

        if !self.is_tainted(sender_leader) {
            return UnixSendVerdict::Allow;
        }

        // Exempt system display and desktop infrastructure sockets
        if TaintHygiene::is_exempt_path(&path_str) {
            return UnixSendVerdict::Allow;
        }

        // Anti-Taint Explosion: System IPC brokers (dbus-daemon, systemd, pipewire)
        // must not spread taint to all other clean clients across the session!
        if self.is_ipc_broker(receiver_leader) || TaintHygiene::is_ipc_broker_name(&path_str) {
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
    ///
    /// # Kernel Self-Defense for GUI & Daemon:
    /// Protects `sentinel-gui` and `sentineld` from memory tampering (`ptrace`, `process_vm_readv/writev`,
    /// `/proc/<pid>/mem`). Any unprivileged peer of the same UID attempting to attach is immediately
    /// denied (-EPERM), closing the P0 attack surface!
    pub fn handle_ptrace_access_check(
        &self,
        tracer_id: u32,
        tracee_id: u32,
        _mode: u32,
    ) -> PtraceVerdict {
        let tracer_leader = self.resolve_group_leader(tracer_id);
        let tracee_leader = self.resolve_group_leader(tracee_id);

        // 1. Nuclear GUI & Daemon Self-Defense:
        // Protected processes (sentinel-gui, sentineld) CANNOT be attached or snooped by unprivileged processes,
        // even if running under the same user UID!
        let gui_pid = self.get_gui_pid();
        let daemon_pid = *self.daemon_pid.read().unwrap();

        if Some(tracee_leader) == gui_pid || Some(tracee_leader) == daemon_pid {
            // Only root debugger (UID 0 / CAP_SYS_PTRACE) is permitted
            if tracer_leader != 0 {
                return PtraceVerdict::Deny;
            }
        }

        let tracer_tainted = self.is_tainted(tracer_leader);
        let tracee_tainted = self.is_tainted(tracee_leader);

        // 2. A tainted process must NOT attach to or snoop memory of clean processes
        if tracer_tainted && !tracee_tainted {
            return PtraceVerdict::Deny;
        }

        // 3. If a clean process attaches to a tainted process, it inherits the taint
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

    #[test]
    fn test_nuclear_gui_self_defense() {
        let manager = TaintMapManager::new();
        let gui_tgid = 8000;
        manager.set_gui_pid(gui_tgid);

        let unprivileged_stealer = 8050; // Same UID, not root

        // Stealer tries to attach / snoop sentinel-gui memory
        let verdict = manager.handle_ptrace_access_check(unprivileged_stealer, gui_tgid, 0);
        assert_eq!(verdict, PtraceVerdict::Deny, "Nuclear GUI self-defense failed!");

        // Root debugger (tgid 0) is allowed
        let root_verdict = manager.handle_ptrace_access_check(0, gui_tgid, 0);
        assert_eq!(root_verdict, PtraceVerdict::Allow);
    }

    #[test]
    fn test_flow_mark_context_synchronous() {
        let manager = TaintMapManager::new();
        let tgid = 9500;
        manager.mark_tainted(tgid);

        // Register flow synchronously in eBPF map
        let mark = manager.register_flow_context(tgid, 9500, 1000, 0x12345678, 9999, false);

        // Immediate lookup by mark returns exact FlowContext with no race
        let ctx = manager.lookup_flow_context(mark);
        assert!(ctx.is_some());
        let ctx = ctx.unwrap();
        assert_eq!(ctx.tgid, tgid);
        assert_eq!(ctx.mark, mark);
        assert_ne!(ctx.taint_flags, 0);
    }

    #[test]
    fn test_mmap_secret_and_shared_memory() {
        let manager = TaintMapManager::new();
        let reader_tgid = 4500;
        let writer_tgid = 4501;
        let shm_path = Path::new("/dev/shm/payload_shared");

        // 1. Reading secret via mmap (PROT_READ = 0x1)
        let res = manager.handle_mmap_file(reader_tgid, 1, 100, Path::new("/home/user/.ssh/id_rsa"), 0x1, 0);
        assert_eq!(res, MmapVerdict::TaintTask);
        assert!(manager.is_tainted(reader_tgid));

        // 2. Tainted writer maps /dev/shm with PROT_WRITE | MAP_SHARED (PROT_WRITE = 0x2, MAP_SHARED = 0x1)
        let res2 = manager.handle_mmap_file(reader_tgid, 2, 200, shm_path, 0x2, 1);
        assert_eq!(res2, MmapVerdict::TaintInode);

        // 3. Clean process maps the shared memory -> becomes tainted (PROT_READ = 0x1)
        let res3 = manager.handle_mmap_file(writer_tgid, 2, 200, shm_path, 0x1, 1);
        assert_eq!(res3, MmapVerdict::TaintTask);
        assert!(manager.is_tainted(writer_tgid));
    }

    #[test]
    fn test_anti_taint_explosion_dbus_broker() {
        let manager = TaintMapManager::new();
        let tainted_app = 3300;
        let dbus_broker = 105; // dbus-daemon system bus
        manager.mark_tainted(tainted_app);
        manager.register_ipc_broker(dbus_broker);

        let verdict = manager.handle_unix_may_send(tainted_app, dbus_broker, Path::new("/run/dbus/system_bus_socket"));
        assert_eq!(verdict, UnixSendVerdict::Allow);
        // DBus broker MUST NOT become tainted!
        assert!(!manager.is_tainted(dbus_broker));
    }
}
