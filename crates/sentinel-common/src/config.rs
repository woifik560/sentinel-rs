//! Configuration models and loaders for Sentinel-RS.
//!
//! Loads `/etc/sentinel/config.toml` and `/etc/sentinel/rules.toml`.

use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::fs;
use std::path::{Path, PathBuf};

use crate::events::{SENTINEL_NFQUEUE_NUM, SENTINEL_SO_MARK};
use crate::risk::RiskThresholds;

/// General daemon configuration.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GeneralConfig {
    #[serde(default = "default_mode")]
    pub mode: String,
    #[serde(default = "default_prompt_timeout")]
    pub prompt_timeout_secs: u64,
    #[serde(default = "default_ring_buffer_size")]
    pub ring_buffer_size: usize,
    #[serde(default = "default_so_mark")]
    pub so_mark: u32,
    #[serde(default = "default_nfqueue_num")]
    pub nfqueue_num: u16,
    #[serde(default = "default_false")]
    pub audit_only: bool,
    #[serde(default = "default_never_freeze_list")]
    pub never_freeze_allowlist: Vec<String>,
}

fn default_mode() -> String {
    "balanced".to_string()
}

fn default_prompt_timeout() -> u64 {
    30
}

fn default_ring_buffer_size() -> usize {
    8192
}

fn default_so_mark() -> u32 {
    SENTINEL_SO_MARK
}

fn default_nfqueue_num() -> u16 {
    SENTINEL_NFQUEUE_NUM
}

fn default_false() -> bool {
    false
}

pub fn default_never_freeze_list() -> Vec<String> {
    vec![
        "systemd".into(),
        "systemd-journald".into(),
        "systemd-logind".into(),
        "systemd-resolved".into(),
        "systemd-udevd".into(),
        "dbus-daemon".into(),
        "dbus-broker".into(),
        "gnome-shell".into(),
        "kwin_x11".into(),
        "kwin_wayland".into(),
        "sway".into(),
        "hyprland".into(),
        "mutter".into(),
        "weston".into(),
        "Xwayland".into(),
        "Xorg".into(),
        "pipewire".into(),
        "pipewire-pulse".into(),
        "wireplumber".into(),
        "NetworkManager".into(),
        "wpa_supplicant".into(),
        "sentinel-gui".into(),
        "sentinelctl".into(),
        "gnome-terminal".into(),
        "kitty".into(),
        "alacritty".into(),
        "konsole".into(),
        "foot".into(),
        "wezterm".into(),
        "xterm".into(),
    ]
}

impl Default for GeneralConfig {
    fn default() -> Self {
        Self {
            mode: default_mode(),
            prompt_timeout_secs: default_prompt_timeout(),
            ring_buffer_size: default_ring_buffer_size(),
            so_mark: default_so_mark(),
            nfqueue_num: default_nfqueue_num(),
            audit_only: default_false(),
            never_freeze_allowlist: default_never_freeze_list(),
        }
    }
}

/// IPC socket configuration.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SocketConfig {
    #[serde(default = "default_socket_path")]
    pub path: PathBuf,
}

fn default_socket_path() -> PathBuf {
    PathBuf::from("/run/sentinel/sentinel.sock")
}

impl Default for SocketConfig {
    fn default() -> Self {
        Self {
            path: default_socket_path(),
        }
    }
}

/// Protected target categories.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TargetsConfig {
    #[serde(default = "default_true")]
    pub protect_telegram: bool,
    #[serde(default = "default_true")]
    pub protect_browsers: bool,
    #[serde(default = "default_true")]
    pub protect_ssh: bool,
    #[serde(default = "default_true")]
    pub protect_crypto: bool,
}

fn default_true() -> bool {
    true
}

impl Default for TargetsConfig {
    fn default() -> Self {
        Self {
            protect_telegram: true,
            protect_browsers: true,
            protect_ssh: true,
            protect_crypto: true,
        }
    }
}

/// Whitelist configuration.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct WhitelistConfig {
    #[serde(default)]
    pub binaries: Vec<PathBuf>,
}

/// Main Sentinel configuration matching `config.toml`.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct SentinelConfig {
    #[serde(default)]
    pub general: GeneralConfig,
    #[serde(default)]
    pub socket: SocketConfig,
    #[serde(default)]
    pub targets: TargetsConfig,
    #[serde(default)]
    pub whitelist: WhitelistConfig,
}

impl SentinelConfig {
    /// Load configuration from a TOML file.
    pub fn load_from_file<P: AsRef<Path>>(path: P) -> Result<Self, ConfigError> {
        let content = fs::read_to_string(path.as_ref())
            .map_err(|e| ConfigError::Io(e, path.as_ref().to_path_buf()))?;
        toml::from_str(&content)
            .map_err(|e| ConfigError::Parse(e, path.as_ref().to_path_buf()))
    }
}

/// Definition of a single rule in `rules.toml`.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RuleConfig {
    pub id: String,
    pub weight: i32,
    #[serde(default)]
    pub description: String,
}

/// Full rules configuration matching `rules.toml`.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RulesConfig {
    #[serde(default)]
    pub thresholds: RiskThresholds,
    #[serde(default)]
    pub rules: HashMap<String, RuleConfig>,
}

impl Default for RulesConfig {
    fn default() -> Self {
        Self {
            thresholds: RiskThresholds::default(),
            rules: HashMap::new(),
        }
    }
}

impl RulesConfig {
    /// Load rules configuration from a TOML file.
    pub fn load_from_file<P: AsRef<Path>>(path: P) -> Result<Self, ConfigError> {
        let content = fs::read_to_string(path.as_ref())
            .map_err(|e| ConfigError::Io(e, path.as_ref().to_path_buf()))?;
        toml::from_str(&content)
            .map_err(|e| ConfigError::Parse(e, path.as_ref().to_path_buf()))
    }
}

/// Errors occurring during configuration loading.
#[derive(Debug, thiserror::Error)]
pub enum ConfigError {
    #[error("Failed to read configuration file '{1}': {0}")]
    Io(std::io::Error, PathBuf),
    #[error("Failed to parse TOML configuration in '{1}': {0}")]
    Parse(toml::de::Error, PathBuf),
}
