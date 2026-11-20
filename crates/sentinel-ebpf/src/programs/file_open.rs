//! eBPF LSM hook: `lsm/file_open` (`security_file_open`)
//!
//! # Kernel Logic:
//! 1. Intercepts file open operations for `current->tgid`.
//! 2. Matches against strictly private credentials using Taint Hygiene rules:
//!    - Strictly private SSH keys: `~/.ssh/id_*` (excludes `*.pub`, `config`, `known_hosts`)
//!    - GPG private keys: `~/.gnupg/private-keys-v1.d/`, `secring.gpg`
//!    - Telegram desktop session data: `~/.local/share/TelegramDesktop/tdata/`
//!    - Browser login credentials and cookies: `Cookies`, `cookies.sqlite`, `Login Data`
//!    - Crypto wallets: `~/.electrum/wallets/`, `~/.bitcoin/wallets/`
//! 3. Checks if caller binary has legitimate App Scope ownership.
//! 4. If non-owner access is detected:
//!    - Marks the calling task in `BPF_MAP_TYPE_TASK_STORAGE` with the `TAINTED` bitflag.
//!    - Submits a `RawFileOpenEvent` to the eBPF `RingBuffer` for daemon analysis.

use crate::maps::TaintHygiene;
use sentinel_common::process::SecretCategory;

/// Description of the `lsm/file_open` eBPF hook configuration.
#[derive(Debug, Clone)]
pub struct FileOpenHookConfig {
    pub enabled: bool,
    pub max_path_len: usize,
}

impl Default for FileOpenHookConfig {
    fn default() -> Self {
        Self {
            enabled: true,
            max_path_len: 256,
        }
    }
}

/// Simulation helper for validating file_open events in user-space testing and runtime.
pub fn simulate_file_open_check(
    path_str: &str,
    current_exe: &str,
) -> Option<SecretCategory> {
    // 0. Cross-process /proc/<pid>/environ or /proc/<pid>/mem snooping
    if path_str.starts_with("/proc/") && (path_str.ends_with("/environ") || path_str.ends_with("/mem")) {
        return Some(SecretCategory::Other(format!("Cross-Process Secret Snoop: {}", path_str)));
    }

    // 1. Enforce Taint Hygiene: Ignore non-private files (.pub, config, known_hosts)
    if !TaintHygiene::is_strictly_private_secret(path_str) {
        return None;
    }

    // 2. SSH Keys App Scope validation
    if path_str.contains("/.ssh/") || (path_str.starts_with("/etc/ssh/ssh_host_") && path_str.ends_with("_key")) {
        if !current_exe.ends_with("/ssh")
            && !current_exe.ends_with("/ssh-add")
            && !current_exe.ends_with("/sftp")
            && !current_exe.ends_with("/sshd")
            && !current_exe.ends_with("/git")
        {
            return Some(SecretCategory::SshKey);
        }
    }

    // 2b. Developer & Cloud credentials App Scope validation
    if path_str.ends_with("/.git-credentials")
        || path_str.ends_with("/.netrc")
        || path_str.ends_with("/.authinfo")
        || path_str.ends_with("/.pgpass")
        || path_str.ends_with("/.my.cnf")
        || path_str.ends_with("/.npmrc")
        || path_str.ends_with("/.pypirc")
        || path_str.ends_with("/.docker/config.json")
        || path_str.contains("/.config/gh/hosts.yml")
        || path_str.contains("/.config/glab-cli/config.yml")
    {
        if path_str.ends_with("/.git-credentials") && current_exe.ends_with("/git") {
            return None;
        }
        if path_str.ends_with("/.docker/config.json") && current_exe.ends_with("/docker") {
            return None;
        }
        if path_str.contains("/gh/hosts.yml") && current_exe.ends_with("/gh") {
            return None;
        }
        return Some(SecretCategory::DeveloperCredentials);
    }

    // 2c. Shell history App Scope validation
    if path_str.ends_with("/.bash_history") || path_str.ends_with("/.zsh_history") || path_str.ends_with("/.histfile") {
        let exe_name = current_exe.rsplit('/').next().unwrap_or(current_exe);
        if exe_name != "bash" && exe_name != "zsh" {
            return Some(SecretCategory::Other("ShellHistory".to_string()));
        }
    }

    // 3. GPG Keys App Scope validation
    if path_str.contains("/.gnupg/") {
        if !current_exe.ends_with("/gpg")
            && !current_exe.ends_with("/gpg-agent")
            && !current_exe.ends_with("/gpg2")
        {
            return Some(SecretCategory::GpgKey);
        }
    }

    // 4. Telegram Desktop App Scope validation
    if path_str.contains("/TelegramDesktop/tdata") {
        if !current_exe.ends_with("/Telegram") && !current_exe.ends_with("/telegram-desktop") {
            return Some(SecretCategory::TelegramData);
        }
    }

    // 5. Browser Credentials App Scope validation
    if path_str.contains("cookies.sqlite") || path_str.contains("/Cookies") || path_str.contains("/Login Data") {
        if !current_exe.ends_with("/firefox")
            && !current_exe.ends_with("/chrome")
            && !current_exe.ends_with("/chromium")
            && !current_exe.ends_with("/brave")
        {
            return Some(SecretCategory::BrowserCookies);
        }
    }

    // 6. Crypto Wallets
    if path_str.contains("/.electrum/wallets") || path_str.contains("/.bitcoin/wallets") {
        return Some(SecretCategory::CryptoWallet);
    }

    // 7. Cloud Credentials App Scope validation
    if path_str.contains("/.aws/") || path_str.contains("/.kube/") || path_str.contains("/.config/gcloud/") {
        if !current_exe.ends_with("/aws") && !current_exe.ends_with("/kubectl") && !current_exe.ends_with("/gcloud") {
            return Some(SecretCategory::CloudCredentials);
        }
    }

    None
}
