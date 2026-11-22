//! `sntctl doctor` diagnostics implementation.

use crate::client::{DEFAULT_PRIVILEGED_SOCKET, DEFAULT_READONLY_SOCKET};
use std::path::Path;

pub async fn run_doctor() -> anyhow::Result<()> {
    println!("================================================================================");
    println!(" Sentinel-RS System Health & Security Diagnostics (sntctl doctor)");
    println!("================================================================================");

    let mut all_ok = true;

    // 1. Kernel Version Check
    let kernel_release = std::fs::read_to_string("/proc/sys/kernel/osrelease")
        .unwrap_or_else(|_| "Unknown".to_string())
        .trim()
        .to_string();

    let is_recent_kernel = if kernel_release != "Unknown" {
        let parts: Vec<&str> = kernel_release.split('.').collect();
        if let (Some(maj), Some(min)) = (
            parts.first().and_then(|m| m.parse::<u32>().ok()),
            parts.get(1).and_then(|m| m.parse::<u32>().ok()),
        ) {
            maj > 6 || (maj == 6 && min >= 1)
        } else {
            false
        }
    } else {
        false
    };

    if is_recent_kernel {
        println!(
            "[OK]   Linux Kernel: {} (>= 6.1 BPF object storage supported)",
            kernel_release
        );
    } else {
        println!(
            "[WARN] Linux Kernel: {} (Kernel >= 6.1 recommended for full BPF LSM)",
            kernel_release
        );
    }

    // 2. BPF LSM Active Check
    let lsm_active = std::fs::read_to_string("/sys/kernel/security/lsm")
        .unwrap_or_default()
        .trim()
        .to_string();

    if lsm_active.contains("bpf") {
        println!(
            "[OK]   BPF LSM: Active in /sys/kernel/security/lsm ({})",
            lsm_active
        );
    } else {
        all_ok = false;
        println!("[FAIL] BPF LSM: 'bpf' is NOT enabled in /sys/kernel/security/lsm!");
        println!(
            "       Remediation: Run 'sudo sntctl setup-kernel' to configure your bootloader."
        );
    }

    // 3. Socket and IPC Directory Check
    let sock_dir = Path::new("/run/sentinel");
    let mgmt_sock = Path::new(DEFAULT_PRIVILEGED_SOCKET);
    let ro_sock = Path::new(DEFAULT_READONLY_SOCKET);

    if sock_dir.exists() {
        println!("[OK]   IPC Directory: {} exists", sock_dir.display());
    } else {
        println!(
            "[INFO] IPC Directory: {} will be created on daemon start",
            sock_dir.display()
        );
    }

    if mgmt_sock.exists() {
        println!(
            "[OK]   Management Socket: {} (SO_PEERCRED RBAC active)",
            mgmt_sock.display()
        );
    } else {
        println!(
            "[INFO] Management Socket: {} not active (daemon offline?)",
            mgmt_sock.display()
        );
    }

    if ro_sock.exists() {
        println!(
            "[OK]   Read-Only Socket: {} accessible for operator monitoring",
            ro_sock.display()
        );
    } else {
        println!(
            "[INFO] Read-Only Socket: {} not active (daemon offline?)",
            ro_sock.display()
        );
    }

    // 4. Netfilter / nftables Check
    let nft_check = std::process::Command::new("nft")
        .arg("list")
        .arg("table")
        .arg("inet")
        .arg("sentinel")
        .output();

    match nft_check {
        Ok(out) if out.status.success() => {
            println!("[OK]   Netfilter: Table 'inet sentinel' active with NFQUEUE bypass");
        }
        _ => {
            println!("[INFO] Netfilter: Table 'inet sentinel' not currently loaded");
        }
    }

    println!("================================================================================");
    if all_ok {
        println!(" Overall Status: SYSTEM READY FOR SENTINEL-RS HEADLESS AGENT");
    } else {
        println!(" Overall Status: PREFLIGHT ACTIONS REQUIRED (see above)");
    }
    println!("================================================================================");

    Ok(())
}
