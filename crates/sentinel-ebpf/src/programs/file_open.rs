//! eBPF LSM hook: `lsm/file_open` (`security_file_open`)
//!
//! # Kernel Logic:
//! 1. Inspects the file path opened by `current->tgid`.
//! 2. Matches against known sensitive paths:
//!    - SSH keys: `~/.ssh/id_*`, `~/.ssh/config`
//!    - GPG keys: `~/.gnupg/private-keys-v1.d/`, `secring.gpg`
//!    - Telegram: `~/.local/share/TelegramDesktop/tdata/`
//!    - Browsers: `~/.config/google-chrome/*/Cookies`, `~/.mozilla/firefox/*.default*/cookies.sqlite`
//!    - Crypto wallets: `~/.electrum/wallets/`, `~/.bitcoin/wallets/`
//! 3. Checks if the binary has legitimate App Scope ownership.
//! 4. If non-owner access is detected:
//!    - Sets the `TAINTED` flag for the current TGID in the `tainted_processes` eBPF map.
//!    - Submits a `RawFileOpenEvent` to the eBPF `RingBuffer` for daemon analysis.

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

/// Simulation helper for validating file_open events in user-space testing.
pub fn simulate_file_open_check(
    path_str: &str,
    current_exe: &str,
) -> Option<sentinel_common::process::SecretCategory> {
    use sentinel_common::process::SecretCategory;

    if path_str.contains("/.ssh/id_") || path_str.ends_with("/.ssh/id_rsa") || path_str.ends_with("/.ssh/id_ed25519") {
        if !current_exe.ends_with("/ssh") && !current_exe.ends_with("/ssh-add") && !current_exe.ends_with("/git") {
            return Some(SecretCategory::SshKey);
        }
    }

    if path_str.contains("/.gnupg/") {
        if !current_exe.ends_with("/gpg") && !current_exe.ends_with("/gpg-agent") {
            return Some(SecretCategory::GpgKey);
        }
    }

    if path_str.contains("/TelegramDesktop/tdata") {
        if !current_exe.ends_with("/Telegram") && !current_exe.ends_with("/telegram-desktop") {
            return Some(SecretCategory::TelegramData);
        }
    }

    if path_str.contains("cookies.sqlite") || path_str.contains("/Cookies") || path_str.contains("/Login Data") {
        if !current_exe.ends_with("/firefox") && !current_exe.ends_with("/chrome") && !current_exe.ends_with("/chromium") {
            return Some(SecretCategory::BrowserCookies);
        }
    }

    if path_str.contains("/.electrum/wallets") || path_str.contains("/.bitcoin/wallets") {
        return Some(SecretCategory::CryptoWallet);
    }

    None
}
