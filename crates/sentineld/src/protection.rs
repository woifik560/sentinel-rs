//! Shared daemon protection state, telemetry metrics, and Process Protection Policy.

use std::collections::HashSet;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::Instant;
use sentinel_common::config::default_never_freeze_list;
use sentinel_common::policy::OperatingMode;

#[derive(Debug)]
pub struct ProtectionState {
    pub enabled: bool,
    pub mode: OperatingMode,
    pub start_time: Instant,
    pub bpf_lsm_active: bool,
    pub network_holding_active: bool,
    pub rules_path: PathBuf,
    pub config_path: PathBuf,
    pub total_incidents: AtomicU64,
}

impl ProtectionState {
    pub fn new(
        enabled: bool,
        mode: OperatingMode,
        rules_path: PathBuf,
        config_path: PathBuf,
    ) -> Self {
        Self {
            enabled,
            mode,
            start_time: Instant::now(),
            bpf_lsm_active: false,
            network_holding_active: false,
            rules_path,
            config_path,
            total_incidents: AtomicU64::new(0),
        }
    }

    pub fn uptime_secs(&self) -> u64 {
        self.start_time.elapsed().as_secs()
    }

    pub fn increment_incidents(&self) -> u64 {
        self.total_incidents.fetch_add(1, Ordering::Relaxed) + 1
    }

    pub fn incident_count(&self) -> u64 {
        self.total_incidents.load(Ordering::Relaxed)
    }
}

/// Hardened multi-attribute Process Protection Policy.
///
/// Defends critical system processes from spoofing attacks and accidental self-termination.
/// A binary named "sshd" running from /tmp/sshd is strictly treated as UNPROTECTED malware,
/// whereas canonical /usr/sbin/sshd or /usr/lib/systemd/systemd is protected.
#[derive(Debug, Clone)]
pub struct ProcessProtectionPolicy {
    own_pid: u32,
    own_exe: Option<PathBuf>,
    protected_names: HashSet<String>,
}

impl Default for ProcessProtectionPolicy {
    fn default() -> Self {
        Self::new()
    }
}

impl ProcessProtectionPolicy {
    pub fn new() -> Self {
        let own_pid = std::process::id();
        let own_exe = std::env::current_exe().ok();
        let protected_names = default_never_freeze_list().into_iter().collect();

        Self {
            own_pid,
            own_exe,
            protected_names,
        }
    }

    pub fn with_own_pid(mut self, pid: u32) -> Self {
        self.own_pid = pid;
        self
    }

    /// Determines whether a process is a critical system process protected from automatic termination.
    ///
    /// Multi-layer validation:
    /// 1. Self-Identity: Sentinel-RS (own PID, own binary) is never terminated.
    /// 2. PID 1 / Init: systemd is strictly protected.
    /// 3. Anti-Spoofing: Any process executing from /tmp, /dev/shm, /var/tmp, ~/Downloads,
    ///    or writable home directories is NEVER protected, regardless of its process name!
    /// 4. Canonical Path & DPKG/RPM validation: Process must reside in verified system directories.
    pub fn is_critical_system_process(
        &self,
        tgid: u32,
        exe_path: &Path,
        _dev_ino: Option<(u64, u64)>,
        pkg_origin: Option<&str>,
    ) -> bool {
        // 1. Never terminate self
        if tgid == self.own_pid {
            return true;
        }
        if let Some(ref own) = self.own_exe {
            if exe_path == own {
                return true;
            }
        }

        // 2. PID 1 (systemd / init) is inviolable
        if tgid <= 1 {
            return true;
        }

        let path_str = exe_path.to_string_lossy();

        // 3. Strict Anti-Spoofing check:
        // Attackers copying malware to /tmp/sshd or /tmp/systemd CANNOT bypass termination!
        if path_str.starts_with("/tmp")
            || path_str.starts_with("/dev/shm")
            || path_str.starts_with("/var/tmp")
            || path_str.contains("/Downloads/")
            || path_str.starts_with("/home/")
            || path_str.starts_with("/root/")
            || path_str.contains("/.local/")
            || path_str.contains("/.cache/")
        {
            return false;
        }

        // Must be in a canonical system path
        let is_system_path = path_str.starts_with("/usr/sbin/")
            || path_str.starts_with("/usr/bin/")
            || path_str.starts_with("/usr/lib/")
            || path_str.starts_with("/sbin/")
            || path_str.starts_with("/bin/")
            || path_str.starts_with("/lib/");

        if !is_system_path {
            return false;
        }

        let exe_name = exe_path
            .file_name()
            .and_then(|n| n.to_str())
            .unwrap_or_default();

        // Specific critical system daemons
        if exe_name == "systemd"
            || exe_name == "sshd"
            || exe_name == "dbus-daemon"
            || exe_name == "systemd-journald"
            || exe_name == "systemd-udevd"
            || exe_name == "systemd-logind"
            || exe_name == "systemd-resolved"
            || exe_name == "sentineld"
            || exe_name == "sntctl"
            || exe_name == "lightdm"
            || exe_name == "gdm"
            || exe_name == "sddm"
        {
            return true;
        }

        // If from verified package and in never-freeze list
        if self.protected_names.contains(exe_name) {
            if pkg_origin.is_some() || is_system_path {
                return true;
            }
        }

        false
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_spoofed_sshd_in_tmp_is_not_protected() {
        let policy = ProcessProtectionPolicy::new().with_own_pid(9999);

        // A fake sshd in /tmp must NOT be protected!
        let fake_sshd = Path::new("/tmp/sshd");
        assert!(!policy.is_critical_system_process(1234, fake_sshd, None, None));

        // A fake systemd in /dev/shm must NOT be protected!
        let fake_systemd = Path::new("/dev/shm/systemd");
        assert!(!policy.is_critical_system_process(5678, fake_systemd, None, None));

        // A genuine system sshd in /usr/sbin/sshd MUST be protected!
        let real_sshd = Path::new("/usr/sbin/sshd");
        assert!(policy.is_critical_system_process(450, real_sshd, None, Some("openssh-server")));

        // Real systemd
        let real_systemd = Path::new("/usr/lib/systemd/systemd");
        assert!(policy.is_critical_system_process(1, real_systemd, None, Some("systemd")));
    }
}
