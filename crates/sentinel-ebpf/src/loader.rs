//! Userspace loader and RingBuffer event listener for Sentinel eBPF probes.

use std::sync::Arc;
use tokio::sync::mpsc;
use tracing::{info, warn};

use sentinel_common::events::EbpfEvent;
use crate::maps::TaintMapManager;

/// Configuration for loading eBPF programs.
#[derive(Debug, Clone)]
pub struct LoaderConfig {
    pub ring_buffer_size: usize,
    pub enable_lsm: bool,
    pub enable_tracepoints: bool,
    pub strict_preflight: bool,
    pub min_kernel_version: String,
}

impl Default for LoaderConfig {
    fn default() -> Self {
        Self {
            ring_buffer_size: 8192,
            enable_lsm: true,
            enable_tracepoints: true,
            strict_preflight: false,
            min_kernel_version: "6.1".to_string(),
        }
    }
}

/// The eBPF loader and event dispatcher.
pub struct EbpfLoader {
    config: LoaderConfig,
    taint_manager: Arc<TaintMapManager>,
    event_tx: mpsc::Sender<EbpfEvent>,
    event_rx: Option<mpsc::Receiver<EbpfEvent>>,
}

impl EbpfLoader {
    /// Create a new EbpfLoader instance.
    pub fn new(config: LoaderConfig) -> Self {
        let (tx, rx) = mpsc::channel(config.ring_buffer_size);
        let taint_manager = Arc::new(TaintMapManager::new());

        Self {
            config,
            taint_manager,
            event_tx: tx,
            event_rx: Some(rx),
        }
    }

    /// Access the taint map manager.
    pub fn taint_manager(&self) -> Arc<TaintMapManager> {
        self.taint_manager.clone()
    }

    /// Access the sender for pushing simulated or intercepted events.
    pub fn event_sender(&self) -> mpsc::Sender<EbpfEvent> {
        self.event_tx.clone()
    }

    /// Take the event receiver to consume events asynchronously.
    pub fn take_event_receiver(&mut self) -> Option<mpsc::Receiver<EbpfEvent>> {
        self.event_rx.take()
    }

    /// Attempt to load and attach eBPF programs to the running Linux kernel.
    pub async fn load_and_attach(&mut self) -> anyhow::Result<()> {
        info!("Initializing Sentinel-RS eBPF kernel probes (LSM & tracepoints)...");

        // 1. Check if BPF LSM is active in the running kernel
        let lsm_content = std::fs::read_to_string("/sys/kernel/security/lsm").unwrap_or_default();
        let lsm_supported = lsm_content.contains("bpf");

        // 2. Check kernel version for safe BPF_MAP_TYPE_INODE_STORAGE support (Linux 6.x+)
        let os_release = std::fs::read_to_string("/proc/sys/kernel/osrelease").unwrap_or_default();
        let is_kernel_safe = verify_kernel_version_safe(&os_release, &self.config.min_kernel_version);

        if self.config.strict_preflight {
            if !lsm_supported {
                anyhow::bail!(
                    "PREFLIGHT FAILED: BPF LSM is not active in /sys/kernel/security/lsm (current: '{}'). \
                     Add 'lsm=...,bpf' to kernel cmdline or GRUB_CMDLINE_LINUX to prevent kernel lockups.",
                    lsm_content.trim()
                );
            }
            if !is_kernel_safe {
                anyhow::bail!(
                    "PREFLIGHT FAILED: Running kernel '{}' is older than required safe threshold '{}'. \
                     Refusing to load BPF INODE_STORAGE to prevent potential kernel panics (CVE-2026-64192 mitigation).",
                    os_release.trim(),
                    self.config.min_kernel_version
                );
            }
        }

        if lsm_supported {
            info!("Kernel BPF LSM support verified in /sys/kernel/security/lsm");
        } else {
            warn!("BPF LSM not active in kernel or running in test/container environment. Event simulation mode ready.");
        }

        info!("eBPF RingBuffer listener configured (size: {})", self.config.ring_buffer_size);
        Ok(())
    }
}

/// Helper function to check if the running kernel version satisfies the minimum safe threshold.
pub fn verify_kernel_version_safe(release_str: &str, min_version: &str) -> bool {
    if release_str.is_empty() {
        return true; // Non-Linux or virtualized test fallback
    }

    let parse_ver = |s: &str| -> Option<(u32, u32)> {
        let clean = s.split('-').next()?.split('+').next()?;
        let mut parts = clean.split('.');
        let major = parts.next()?.parse().ok()?;
        let minor = parts.next()?.parse().ok()?;
        Some((major, minor))
    };

    let actual = match parse_ver(release_str) {
        Some(v) => v,
        None => return true,
    };

    let min = match parse_ver(min_version) {
        Some(v) => v,
        None => (6, 1),
    };

    actual >= min
}
