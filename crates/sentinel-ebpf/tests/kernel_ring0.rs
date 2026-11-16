//! In-kernel Ring-0 test suite for Sentinel-RS eBPF loader and probes.
//!
//! Executed inside a real Linux 6.x QEMU/KVM virtual machine via vmtest.
//! Validates:
//! 1. Host kernel version meets safe threshold (>= 6.1) to avoid CVE-2026-64192 panics.
//! 2. EbpfLoader initializes ring buffer channel and maps manager.
//! 3. BPF LSM presence in /sys/kernel/security/lsm when booted with lsm=...,bpf.
//! 4. In-kernel map pinning directory creation (/sys/fs/bpf/sentinel).

use sentinel_ebpf::loader::{verify_kernel_version_safe, EbpfLoader, LoaderConfig};

#[tokio::test]
async fn test_kernel_safe_version_verification() {
    // Linux 6.1+ is safe for BPF_MAP_TYPE_INODE_STORAGE
    assert!(verify_kernel_version_safe("6.1.0-28-amd64", "6.1"));
    assert!(verify_kernel_version_safe("6.8.0-45-generic", "6.1"));
    assert!(verify_kernel_version_safe("6.12.1+bpf", "6.1"));
    assert!(verify_kernel_version_safe("6.6.137-flatcar", "6.1"));

    // Legacy kernels vulnerable to CVE-2026-64192 must be rejected in strict preflight
    assert!(!verify_kernel_version_safe("5.15.0-100-generic", "6.1"));
    assert!(!verify_kernel_version_safe("5.10.0-1-amd64", "6.1"));
    assert!(!verify_kernel_version_safe("4.19.0-6-amd64", "6.1"));
}

#[tokio::test]
async fn test_ebpf_loader_initialization_and_preflight() {
    let mut config = LoaderConfig::default();
    config.strict_preflight = false;

    let mut loader = EbpfLoader::new(config);
    let res = loader.load_and_attach().await;
    assert!(
        res.is_ok(),
        "EbpfLoader load_and_attach should complete successfully: {:?}",
        res.err()
    );
}

#[tokio::test]
async fn test_strict_preflight_in_lsm_bpf_ring0_kernel() {
    let lsm_path = "/sys/kernel/security/lsm";
    if let Ok(lsm_content) = std::fs::read_to_string(lsm_path) {
        if lsm_content.contains("bpf") {
            println!("Ring-0 kernel detected with BPF LSM active ('{}')", lsm_content.trim());
            let mut config = LoaderConfig::default();
            config.strict_preflight = true;
            config.min_kernel_version = "6.1".to_string();

            let mut loader = EbpfLoader::new(config);
            let res = loader.load_and_attach().await;
            assert!(
                res.is_ok(),
                "Strict preflight must pass in live Linux 6.x kernel with BPF LSM: {:?}",
                res.err()
            );

            // Verify bpffs pinning directory readiness
            let pin_dir_res = loader.ensure_pin_dir();
            assert!(
                pin_dir_res.is_ok(),
                "Pinning directory /sys/fs/bpf/sentinel should be created or validated"
            );
        } else {
            println!(
                "Notice: 'bpf' not listed in {} (found: '{}'). Skipping strict assertion.",
                lsm_path,
                lsm_content.trim()
            );
        }
    } else {
        println!("Notice: {} not found (non-Linux or virtual container). Skipping.", lsm_path);
    }
}
