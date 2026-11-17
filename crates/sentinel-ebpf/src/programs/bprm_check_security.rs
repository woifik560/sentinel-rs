//! eBPF LSM hook: `lsm/bprm_check_security` (`security_bprm_check_security`)
//!
//! # Kernel Logic:
//! Intercepts executable file verification before `execve` completes and before
//! any user-space instructions or network connections execute.
//!
//! 1. Inspects `file->f_path.dentry` for anonymous memory execution (`memfd_create`):
//!    - Checks if the file lacks a backing filesystem, or has name starting with `memfd:`,
//!      or is accessed via `/proc/self/fd/`.
//!    - If detected, immediately sets the `PROFILE_FILELESS_MEMFD` flag in `BPF_MAP_TYPE_TASK_STORAGE`.
//!
//! 2. Pre-calculates the baseline trust profile in kernel space:
//!    - Pre-sets `PROFILE_TRUSTED_PKG`, `PROFILE_UNTRUSTED_ORIGIN`, `PROFILE_INTERPRETER`,
//!      or `PROFILE_NEVER_FREEZE` in `TASK_STORAGE`.
//!    - Allows the subsequent Fast-Path in `lsm/socket_connect` to verify the process in nanoseconds.
//!
//! 3. Submits `RawBprmCheckSecurityEvent` to the RingBuffer.

use std::path::Path;
use sentinel_common::events::{RawBprmCheckSecurityEvent, MAX_PATH_LEN};
use sentinel_common::process::{
    PROFILE_FILELESS_MEMFD, PROFILE_INTERPRETER, PROFILE_TRUSTED_PKG, PROFILE_UNTRUSTED_ORIGIN,
};
use crate::maps::TaintMapManager;

/// Evaluates bprm execution check with kernel INODE_STORAGE cache and baseline profile.
pub fn evaluate_bprm_security(
    manager: &TaintMapManager,
    _tgid: u32,
    dev: u64,
    ino: u64,
    exe_path: &Path,
    inode_version: u64,
) -> u32 {
    let mut profile = compute_baseline_profile(exe_path);

    // Kernel INODE_STORAGE Cached Verification:
    // If sentineld previously verified this binary, reuse TRUSTED_SYSTEM_PKG directly in kernel!
    if manager.is_inode_trusted(dev, ino, inode_version) {
        profile |= PROFILE_TRUSTED_PKG;
    }

    profile
}

/// Simulation helper for Linux 6.x kfunc bpf_get_file_hash() / bpf_ima_file_hash()
pub fn bpf_get_file_hash_simulated(path: &Path) -> Option<[u8; 32]> {
    use sha2::{Digest, Sha256};
    let content = std::fs::read(path).ok()?;
    let hash = Sha256::digest(&content);
    let mut out = [0u8; 32];
    out.copy_from_slice(&hash);
    Some(out)
}

/// Check if a binary path or dentry represents anonymous memory execution.
pub fn is_memfd_or_fileless(path_str: &str) -> bool {
    path_str.starts_with("/memfd:")
        || path_str.starts_with("memfd:")
        || path_str.contains("/memfd:")
        || path_str.contains("anon_inode:[memfd]")
        || (path_str.starts_with("/proc/") && path_str.contains("/fd/"))
        || path_str.contains("(deleted)") && path_str.starts_with("/dev/shm")
}

/// Kernel-level check at execve time: prevents launching sentineld or sntctl with malicious LD_PRELOAD or LD_AUDIT.
pub fn check_daemon_secure_bprm(exe_path: &Path, envp_entries: &[&str]) -> Result<(), &'static str> {
    let path_str = exe_path.to_string_lossy();
    if path_str.ends_with("/sentineld") || path_str == "sentineld" || path_str.ends_with("/sntctl") || path_str == "sntctl" {
        for entry in envp_entries {
            if entry.starts_with("LD_PRELOAD=") && entry.len() > "LD_PRELOAD=".len() {
                return Err("-EPERM: LD_PRELOAD forbidden on sentinel binaries");
            }
            if entry.starts_with("LD_AUDIT=") && entry.len() > "LD_AUDIT=".len() {
                return Err("-EPERM: LD_AUDIT forbidden on sentinel binaries");
            }
        }
    }
    Ok(())
}

// Deprecated alias for backward compatibility with existing tests
pub fn check_gui_secure_bprm(exe_path: &Path, envp_entries: &[&str]) -> Result<(), &'static str> {
    check_daemon_secure_bprm(exe_path, envp_entries)
}

/// Compute initial baseline trust profile bits for `TASK_STORAGE`.
pub fn compute_baseline_profile(path: &Path) -> u32 {
    let path_str = path.to_string_lossy();
    let mut profile = 0;

    if is_memfd_or_fileless(&path_str) {
        profile |= PROFILE_FILELESS_MEMFD;
    }

    if path_str.starts_with("/tmp")
        || path_str.starts_with("/dev/shm")
        || path_str.contains("/Downloads/")
        || path_str.starts_with("/var/tmp")
    {
        profile |= PROFILE_UNTRUSTED_ORIGIN;
    }

    if let Some(name) = path.file_name().and_then(|n| n.to_str()) {
        if matches!(
            name,
            "python3" | "python" | "bash" | "sh" | "zsh" | "node" | "perl" | "ruby"
        ) {
            profile |= PROFILE_INTERPRETER;
        }
    }

    profile
}

/// Helper to create raw event for testing and RingBuffer simulation.
pub fn create_raw_bprm_event(
    tgid: u32,
    uid: u32,
    exe_path: &str,
    dev: u64,
    ino: u64,
) -> RawBprmCheckSecurityEvent {
    let mut exe_buf = [0u8; MAX_PATH_LEN];
    let bytes = exe_path.as_bytes();
    let len = bytes.len().min(MAX_PATH_LEN);
    exe_buf[..len].copy_from_slice(&bytes[..len]);

    let is_memfd = if is_memfd_or_fileless(exe_path) { 1 } else { 0 };

    RawBprmCheckSecurityEvent {
        tgid,
        uid,
        exe_path: exe_buf,
        exe_path_len: len as u32,
        dev,
        ino,
        is_memfd,
        _pad: [0; 7],
    }
}
