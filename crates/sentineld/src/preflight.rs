//! Preflight validation checks before starting daemon or loading eBPF maps.
//!
//! Enforces:
//! 1. BPF LSM presence in `/sys/kernel/security/lsm`.
//!    CVE-2026-64192 arises when `bpf` is absent from the LSM stack on unpatched older kernels
//!    (resolved upstream in updates like 6.1.184+ and newer releases in July 2026).
//!    The primary defense is the preflight verification of `/sys/kernel/security/lsm` for `bpf`.
//! 2. Safe kernel version baseline (Linux 6.1.184+ / 6.6+).
//! 3. Netfilter / nftables userspace availability.

use std::fs;
use std::process::Command;
use tracing::{info, warn};

#[derive(Debug, Clone)]
pub struct PreflightReport {
    pub lsm_active: bool,
    pub kernel_version: String,
    pub is_kernel_safe: bool,
    pub nftables_available: bool,
}

/// Perform kernel and environment preflight verification.
pub fn run_preflight_checks(strict: bool, min_version: &str) -> anyhow::Result<PreflightReport> {
    info!("Executing kernel and LSM preflight checks...");

    // 1. Check BPF LSM in /sys/kernel/security/lsm
    let lsm_content = fs::read_to_string("/sys/kernel/security/lsm").unwrap_or_default();
    let lsm_active = lsm_content.contains("bpf");

    // 2. Check kernel release
    let kernel_version = fs::read_to_string("/proc/sys/kernel/osrelease")
        .unwrap_or_default()
        .trim()
        .to_string();

    let is_kernel_safe = sentinel_ebpf::loader::verify_kernel_version_safe(&kernel_version, min_version);

    // 3. Check nftables CLI tool
    let nftables_available = Command::new("nft")
        .arg("--version")
        .output()
        .map(|o| o.status.success())
        .unwrap_or(false);

    let report = PreflightReport {
        lsm_active,
        kernel_version: kernel_version.clone(),
        is_kernel_safe,
        nftables_available,
    };

    info!(
        "Preflight report: LSM bpf active: {}, Kernel: '{}' (safe: {}), nftables: {}",
        report.lsm_active, report.kernel_version, report.is_kernel_safe, report.nftables_available
    );

    if strict {
        if !report.lsm_active {
            anyhow::bail!(
                "PREFLIGHT ERROR: BPF LSM is not active in the current kernel!\n\
                 Current /sys/kernel/security/lsm contents: '{}'\n\
                 CVE-2026-64192 mitigation requires 'bpf' to be active in the LSM stack.\n\
                 Fix (Ubuntu/Debian): Append 'lsm=...,bpf' to GRUB_CMDLINE_LINUX in /etc/default/grub \
                 and execute 'sudo update-grub && sudo reboot'.",
                lsm_content.trim()
            );
        }

        if !report.is_kernel_safe {
            anyhow::bail!(
                "PREFLIGHT ERROR: Kernel version '{}' is below required safe threshold '{}'!\n\
                 Unpatched older kernels without BPF in the LSM stack risk kernel panics (CVE-2026-64192).\n\
                 Please update to Linux kernel 6.1.184+ or 6.6+.",
                kernel_version,
                min_version
            );
        }
    } else {
        if !report.lsm_active {
            warn!("BPF LSM is not active in /sys/kernel/security/lsm. Running in simulated fallback mode.");
        }
        if !report.is_kernel_safe {
            warn!("Kernel version check skipped or warning issued.");
        }
    }

    Ok(report)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_preflight_checks_non_strict() {
        let res = run_preflight_checks(false, "6.1");
        assert!(res.is_ok());
    }
}
