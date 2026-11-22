//! Preflight validation checks and kernel compatibility tier discovery.
//!
//! Evaluates kernel capabilities before starting the daemon or loading eBPF maps:
//! - BPF LSM presence in `/sys/kernel/security/lsm`
//! - Kernel BTF availability in `/sys/kernel/btf/vmlinux`
//! - RingBuffer support (Linux >= 5.8)
//! - `bpf_task_storage` support (Linux >= 5.11)
//! - Discovers Kernel Compatibility Tier: Tier 1 (6.1+), Tier 2 (5.15-6.0), Tier 3 (5.10-5.14).

use serde::{Deserialize, Serialize};
use std::fs;
use std::path::Path;
use std::process::Command;
use tracing::{info, warn};

/// Kernel compatibility tier profile.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum KernelCompatibilityTier {
    /// Linux 6.1+: Full functionality (BPF LSM, RingBuffer, BPF timers, task_storage, pidfd).
    Tier1Full,
    /// Linux 5.15–6.0: Verified compatibility (RingBuffer, BPF LSM, task_storage).
    Tier2Verified,
    /// Linux 5.10–5.14: Limited compatibility (No BPF LSM, tracepoints + NFQUEUE packet triage only).
    Tier3Limited,
    /// Kernel < 5.10 or missing mandatory prerequisites.
    Unsupported,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PreflightReport {
    pub lsm_active: bool,
    pub btf_available: bool,
    pub ringbuffer_supported: bool,
    pub task_storage_supported: bool,
    pub kernel_version: String,
    pub compatibility_tier: KernelCompatibilityTier,
    pub is_kernel_safe: bool,
    pub nftables_available: bool,
    pub recommendations: Vec<String>,
}

/// Parse kernel major.minor from version string.
pub fn parse_kernel_version(version: &str) -> (u32, u32) {
    let clean = version.trim_start_matches("Linux ").trim();
    let parts: Vec<&str> = clean.split('.').collect();
    let major = parts.first().and_then(|s| s.parse().ok()).unwrap_or(0);
    let minor = parts
        .get(1)
        .and_then(|s| {
            s.split(|c: char| !c.is_ascii_digit())
                .next()
                .and_then(|digits| digits.parse().ok())
        })
        .unwrap_or(0);
    (major, minor)
}

/// Perform kernel and environment preflight verification.
pub fn run_preflight_checks(strict: bool, min_version: &str) -> anyhow::Result<PreflightReport> {
    info!("Executing kernel and LSM preflight compatibility checks...");

    // 1. Check BPF LSM in /sys/kernel/security/lsm
    let lsm_content = fs::read_to_string("/sys/kernel/security/lsm").unwrap_or_default();
    let lsm_active = lsm_content.contains("bpf");

    // 2. Check kernel release
    let kernel_version = fs::read_to_string("/proc/sys/kernel/osrelease")
        .unwrap_or_default()
        .trim()
        .to_string();

    let (major, minor) = parse_kernel_version(&kernel_version);

    // 3. Check BTF in /sys/kernel/btf/vmlinux
    let btf_available = Path::new("/sys/kernel/btf/vmlinux").exists();

    // 4. Feature support baselines
    let ringbuffer_supported = (major > 5) || (major == 5 && minor >= 8);
    let task_storage_supported = (major > 5) || (major == 5 && minor >= 11);

    // 5. Determine Compatibility Tier
    let mut recommendations = Vec::new();
    let compatibility_tier = if (major > 6) || (major == 6 && minor >= 1) {
        if lsm_active && btf_available {
            KernelCompatibilityTier::Tier1Full
        } else {
            if !lsm_active {
                recommendations.push(
                    "Enable BPF in LSM stack: add 'lsm=...,bpf' to kernel command line".into(),
                );
            }
            if !btf_available {
                recommendations.push(
                    "Kernel compiled without CONFIG_DEBUG_INFO_BTF=y; BTF required for full CO-RE"
                        .into(),
                );
            }
            KernelCompatibilityTier::Tier2Verified
        }
    } else if major == 5 && minor >= 15 {
        if !lsm_active {
            recommendations.push(
                "Tier 2 kernel: BPF LSM recommended; fallback to tracepoints if disabled".into(),
            );
        }
        KernelCompatibilityTier::Tier2Verified
    } else if major == 5 && minor >= 10 {
        recommendations.push(
            "Tier 3 kernel: Operating in limited mode without BPF LSM (tracepoints + NFQUEUE only)"
                .into(),
        );
        KernelCompatibilityTier::Tier3Limited
    } else {
        recommendations.push(
            "Kernel version is below minimum supported baseline (5.10). Please upgrade Linux."
                .into(),
        );
        KernelCompatibilityTier::Unsupported
    };

    let is_kernel_safe =
        sentinel_ebpf::loader::verify_kernel_version_safe(&kernel_version, min_version);

    // 6. Check nftables CLI tool
    let nftables_available = Command::new("nft")
        .arg("--version")
        .output()
        .map(|o| o.status.success())
        .unwrap_or(false);

    let report = PreflightReport {
        lsm_active,
        btf_available,
        ringbuffer_supported,
        task_storage_supported,
        kernel_version: kernel_version.clone(),
        compatibility_tier,
        is_kernel_safe,
        nftables_available,
        recommendations,
    };

    info!(
        "Preflight report: Tier {:?}, LSM bpf: {}, BTF: {}, Kernel: '{}' (safe: {}), nftables: {}",
        report.compatibility_tier,
        report.lsm_active,
        report.btf_available,
        report.kernel_version,
        report.is_kernel_safe,
        report.nftables_available
    );

    if strict {
        if compatibility_tier == KernelCompatibilityTier::Unsupported {
            anyhow::bail!(
                "PREFLIGHT FATAL: Kernel '{}' is unsupported by Sentinel-RS! Minimum required: Linux 5.10+.",
                kernel_version
            );
        }

        if !report.lsm_active && compatibility_tier == KernelCompatibilityTier::Tier1Full {
            anyhow::bail!(
                "PREFLIGHT ERROR: BPF LSM is not active in the current kernel!\n\
                 Current /sys/kernel/security/lsm contents: '{}'\n\
                 Fix (Ubuntu/Debian): Append 'lsm=...,bpf' to GRUB_CMDLINE_LINUX in /etc/default/grub \
                 and execute 'sudo update-grub && sudo reboot'.",
                lsm_content.trim()
            );
        }
    } else {
        if !report.lsm_active {
            warn!("BPF LSM is not active in /sys/kernel/security/lsm. Running in compatibility fallback mode.");
        }
    }

    Ok(report)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_kernel_version_parsing() {
        assert_eq!(
            parse_kernel_version("6.6.87.2-microsoft-standard-WSL2"),
            (6, 6)
        );
        assert_eq!(parse_kernel_version("6.1.0-21-amd64"), (6, 1));
        assert_eq!(parse_kernel_version("5.15.0-107-generic"), (5, 15));
        assert_eq!(parse_kernel_version("5.10.120"), (5, 10));
        assert_eq!(parse_kernel_version("4.19.0-6"), (4, 19));
    }
}
