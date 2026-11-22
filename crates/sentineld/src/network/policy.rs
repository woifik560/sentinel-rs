//! Network safety and policy checkers.

use sentinel_common::config::default_never_freeze_list;
use std::collections::HashSet;
use std::path::Path;

#[derive(Clone, Debug)]
pub struct NeverFreezeChecker {
    protected_names: HashSet<String>,
}

impl Default for NeverFreezeChecker {
    fn default() -> Self {
        Self {
            protected_names: default_never_freeze_list().into_iter().collect(),
        }
    }
}

impl NeverFreezeChecker {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn is_protected(&self, tgid: u32, exe_path: &Path, uid: u32) -> bool {
        if tgid <= 2 {
            return true;
        }

        let path_str = exe_path.to_string_lossy();
        if path_str.starts_with("/tmp")
            || path_str.starts_with("/dev/shm")
            || path_str.starts_with("/var/tmp")
            || path_str.contains("/Downloads/")
        {
            return false;
        }

        let is_system_dir = path_str.starts_with("/usr/bin/")
            || path_str.starts_with("/bin/")
            || path_str.starts_with("/usr/lib/")
            || path_str.starts_with("/lib/");

        if !is_system_dir {
            return false;
        }

        let exe_name = exe_path
            .file_name()
            .and_then(|n| n.to_str())
            .unwrap_or_default();

        if (exe_name.starts_with("systemd")
            || exe_name.starts_with("dbus")
            || exe_name.starts_with("udevd"))
            && (uid == 0 || uid < 1000)
        {
            return true;
        }

        if exe_name == "sntctl" || exe_name == "sentinelctl" || exe_name == "sentineld" {
            return true;
        }

        if self.protected_names.contains(exe_name) {
            return true;
        }

        if exe_name.starts_with("kwin")
            || exe_name.starts_with("pipewire")
            || exe_name.starts_with("lxpanel")
            || exe_name.starts_with("xfce4-")
            || exe_name.starts_with("mate-")
            || exe_name.starts_with("plasma")
            || exe_name.starts_with("lightdm")
            || exe_name.starts_with("gdm")
            || exe_name.starts_with("sddm")
            || exe_name.starts_with("steam")
        {
            return true;
        }

        false
    }
}
