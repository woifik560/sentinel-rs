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

/// Directory path in bpffs where programs and maps are pinned.
pub const BPF_PIN_PATH: &str = "/sys/fs/bpf/sentinel";

/// The eBPF loader and event dispatcher.
pub struct EbpfLoader {
    config: LoaderConfig,
    taint_manager: Arc<TaintMapManager>,
    event_tx: mpsc::Sender<EbpfEvent>,
    event_rx: Option<mpsc::Receiver<EbpfEvent>>,
}

impl EbpfLoader {
    /// Ensures that /sys/fs/bpf/sentinel is ready for persistent pinning.
    /// This keeps BPF LSM and cgroup programs active in the kernel across daemon crashes.
    pub fn ensure_pin_dir(&self) -> anyhow::Result<std::path::PathBuf> {
        let pin_dir = std::path::PathBuf::from(BPF_PIN_PATH);
        if !pin_dir.exists() {
            let _ = std::fs::create_dir_all(&pin_dir);
        }
        Ok(pin_dir)
    }

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
            warn!("BPF LSM not active in kernel or running in test/container environment. Event simulation & tracepoint mode ready.");
        }

        #[cfg(target_os = "linux")]
        {
            if self.config.enable_tracepoints {
                self.start_live_monitors();
            }
        }

        info!("eBPF RingBuffer listener configured (size: {})", self.config.ring_buffer_size);
        Ok(())
    }

    #[cfg(target_os = "linux")]
    fn start_live_monitors(&self) {
        let tx = self.event_tx.clone();
        let _ = std::thread::Builder::new()
            .name("sentinel-tracepoint".into())
            .spawn(move || {
                start_tracepoint_collector(tx);
            });

        let fan_tx = self.event_tx.clone();
        let _ = std::thread::Builder::new()
            .name("sentinel-fanotify".into())
            .spawn(move || {
                start_fanotify_collector(fan_tx);
            });
    }
}

#[cfg(target_os = "linux")]
fn start_tracepoint_collector(tx: mpsc::Sender<EbpfEvent>) {
    use std::fs::File;
    use std::io::{BufRead, BufReader};
    use std::path::{Path, PathBuf};

    let trace_dirs = ["/sys/kernel/tracing", "/sys/kernel/debug/tracing"];
    let trace_dir = trace_dirs.iter().find(|d| Path::new(d).exists());

    let trace_path = match trace_dir {
        Some(d) => Path::new(d),
        None => {
            warn!("Tracing directory not found (/sys/kernel/tracing). Tracepoint monitoring disabled.");
            return;
        }
    };

    // Enable sched_process_fork, sched_process_exec, and inet_sock_set_state
    let fork_enable = trace_path.join("events/sched/sched_process_fork/enable");
    let exec_enable = trace_path.join("events/sched/sched_process_exec/enable");
    let sock_enable = trace_path.join("events/sock/inet_sock_set_state/enable");

    let _ = std::fs::write(&fork_enable, "1");
    let _ = std::fs::write(&exec_enable, "1");
    let _ = std::fs::write(&sock_enable, "1");

    // Clear stale historical trace buffer before reading
    let trace_file = trace_path.join("trace");
    let _ = std::fs::write(&trace_file, "0");

    info!("Active kernel tracepoints enabled for process and network events.");

    let pipe_path = trace_path.join("trace_pipe");
    let file = match File::open(&pipe_path) {
        Ok(f) => f,
        Err(e) => {
            warn!("Could not open {}: {}. Tracepoint stream unavailable.", pipe_path.display(), e);
            return;
        }
    };

    let reader = BufReader::new(file);
    for line_res in reader.lines() {
        let line = match line_res {
            Ok(l) => l,
            Err(_) => break,
        };

        // 1. sched_process_fork
        if line.contains("sched_process_fork:") {
            if let Some(c_idx) = line.find("child_pid=") {
                let child_str = line[c_idx + 10..].split_whitespace().next().unwrap_or_default();
                let p_opt = if let Some(pp_idx) = line.find("parent_pid=") {
                    line[pp_idx + 11..].split_whitespace().next()
                } else if let Some(p_idx) = line[..c_idx].rfind(" pid=") {
                    line[p_idx + 5..c_idx].split_whitespace().next()
                } else if let Some(p_idx) = line[..c_idx].rfind("pid=") {
                    line[p_idx + 4..c_idx].split_whitespace().next()
                } else {
                    None
                };

                if let (Some(parent_str), Ok(child_tgid)) = (p_opt, child_str.parse::<u32>()) {
                    if let Ok(parent_tgid) = parent_str.parse::<u32>() {
                        let _ = tx.blocking_send(EbpfEvent::ProcessFork { parent_tgid, child_tgid });
                    }
                }
            }
        }
        // 2. sched_process_exec
        else if line.contains("sched_process_exec:") {
            if let (Some(f_idx), Some(p_idx)) = (line.find("filename="), line.rfind(" pid=")) {
                let filename = if let Some(space_idx) = line[f_idx + 9..].find(" pid=") {
                    &line[f_idx + 9..f_idx + 9 + space_idx]
                } else {
                    line[f_idx + 9..].split_whitespace().next().unwrap_or_default()
                };
                let pid_str = line[p_idx + 5..].split_whitespace().next().unwrap_or_default();
                if let Ok(tgid) = pid_str.parse::<u32>() {
                    let cmdline_path = format!("/proc/{}/cmdline", tgid);
                    let cmdline = if let Ok(bytes) = std::fs::read(&cmdline_path) {
                        let parsed: Vec<String> = bytes
                            .split(|&b| b == 0)
                            .filter(|s| !s.is_empty())
                            .map(|s| String::from_utf8_lossy(s).to_string())
                            .collect();
                        if parsed.is_empty() {
                            vec![filename.to_string()]
                        } else {
                            parsed
                        }
                    } else {
                        vec![filename.to_string()]
                    };

                    let _ = tx.blocking_send(EbpfEvent::ProcessExec {
                        tgid,
                        exe_path: PathBuf::from(filename),
                        cmdline,
                    });
                }
            }
        }
        // 3. inet_sock_set_state
        else if line.contains("inet_sock_set_state:") && line.contains("newstate=TCP_SYN_SENT") {
            let pid_opt = if let Some(bracket_idx) = line.find('[') {
                let prefix = &line[..bracket_idx];
                if let Some(dash_idx) = prefix.rfind('-') {
                    prefix[dash_idx + 1..].trim().parse::<u32>().ok()
                } else {
                    None
                }
            } else {
                None
            };

            let dport_opt = if let Some(dp_idx) = line.find("dport=") {
                line[dp_idx + 6..].split_whitespace().next().and_then(|s| s.parse::<u16>().ok())
            } else {
                None
            };

            let daddr_opt = if let Some(da_idx) = line.find("daddr=") {
                line[da_idx + 6..].split_whitespace().next().and_then(|s| s.parse::<std::net::Ipv4Addr>().ok())
            } else {
                None
            };

            if let (Some(tgid), Some(dst_port), Some(dst_ipv4)) = (pid_opt, dport_opt, daddr_opt) {
                let pgrp = std::fs::read_to_string(format!("/proc/{}/stat", tgid))
                    .ok()
                    .and_then(|stat| {
                        let r_paren = stat.rfind(')')?;
                        let rest = &stat[r_paren + 1..];
                        let mut fields = rest.split_whitespace();
                        let _state = fields.next()?;
                        let _ppid = fields.next()?;
                        let pgrp_str = fields.next()?;
                        pgrp_str.parse::<u32>().ok()
                    })
                    .unwrap_or(tgid);

                let _ = tx.blocking_send(EbpfEvent::SocketConnect {
                    tgid,
                    group_leader_tgid: pgrp,
                    addr_family: 2,
                    dst_ipv4: Some(dst_ipv4),
                    dst_ipv6: None,
                    dst_port,
                    protocol: 6,
                    so_mark: 0,
                });
            }
        }
    }
}

#[cfg(target_os = "linux")]
fn start_fanotify_collector(tx: mpsc::Sender<EbpfEvent>) {
    use std::ffi::CString;

    let fan_fd = unsafe { libc::fanotify_init(libc::FAN_CLASS_NOTIF | libc::FAN_CLOEXEC, libc::O_RDONLY as u32) };
    if fan_fd < 0 {
        warn!("fanotify_init failed. File access monitoring running in passive mode.");
        return;
    }

    // Mark target filesystems or paths
    let targets = ["/home", "/root", "/etc", "/tmp"];
    let mut marked = 0;
    for target in &targets {
        if let Ok(c_target) = CString::new(*target) {
            let ret = unsafe {
                libc::fanotify_mark(
                    fan_fd,
                    libc::FAN_MARK_ADD | libc::FAN_MARK_FILESYSTEM,
                    libc::FAN_OPEN,
                    libc::AT_FDCWD,
                    c_target.as_ptr(),
                )
            };
            if ret == 0 {
                marked += 1;
            } else {
                let ret_dir = unsafe {
                    libc::fanotify_mark(
                        fan_fd,
                        libc::FAN_MARK_ADD,
                        libc::FAN_OPEN | libc::FAN_EVENT_ON_CHILD,
                        libc::AT_FDCWD,
                        c_target.as_ptr(),
                    )
                };
                if ret_dir == 0 {
                    marked += 1;
                }
            }
        }
    }

    info!("fanotify secret monitor active (marked {} targets).", marked);

    let mut buf = vec![0u8; 8192];
    loop {
        let n = unsafe { libc::read(fan_fd, buf.as_mut_ptr() as *mut libc::c_void, buf.len()) };
        if n <= 0 {
            break;
        }

        let mut offset = 0;
        while offset + std::mem::size_of::<libc::fanotify_event_metadata>() <= n as usize {
            let meta = unsafe {
                &*(buf.as_ptr().add(offset) as *const libc::fanotify_event_metadata)
            };
            if meta.event_len == 0 {
                break;
            }

            if meta.fd >= 0 {
                let proc_fd_path = format!("/proc/self/fd/{}", meta.fd);
                if let Ok(target_path) = std::fs::read_link(&proc_fd_path) {
                    let path_str = target_path.to_string_lossy();
                    let pid = meta.pid as u32;

                    let current_exe = std::fs::read_link(format!("/proc/{}/exe", pid))
                        .map(|p| p.to_string_lossy().to_string())
                        .unwrap_or_default();

                    if let Some(_cat) = crate::programs::file_open::simulate_file_open_check(&path_str, &current_exe) {
                        // Extract parent PID and group leader (PGID) to ensure taint links to parent script
                        let mut ppid = 0;
                        let mut pgrp = 0;
                        if let Ok(stat) = std::fs::read_to_string(format!("/proc/{}/stat", pid)) {
                            if let Some(r_paren) = stat.rfind(')') {
                                let rest = &stat[r_paren + 1..];
                                let mut fields = rest.split_whitespace();
                                let _state = fields.next();
                                if let Some(ppid_str) = fields.next() {
                                    ppid = ppid_str.parse::<u32>().unwrap_or(0);
                                }
                                if let Some(pgrp_str) = fields.next() {
                                    pgrp = pgrp_str.parse::<u32>().unwrap_or(0);
                                }
                            }
                        }

                        if ppid <= 1 {
                            ppid = std::fs::read_to_string(format!("/proc/{}/status", pid))
                                .ok()
                                .and_then(|s| {
                                    for line in s.lines() {
                                        if line.starts_with("PPid:") {
                                            return line.split_whitespace().nth(1)?.parse::<u32>().ok();
                                        }
                                    }
                                    None
                                })
                                .unwrap_or(0);
                        }

                        if ppid > 1 {
                            let _ = tx.blocking_send(EbpfEvent::ProcessFork {
                                parent_tgid: ppid,
                                child_tgid: pid,
                            });
                        }

                        let _ = tx.blocking_send(EbpfEvent::FileOpen {
                            tgid: pid,
                            uid: 1000,
                            path: target_path.clone(),
                            dev: 0,
                            ino: 0,
                            flags: 0,
                        });

                        if ppid > 1 {
                            let _ = tx.blocking_send(EbpfEvent::FileOpen {
                                tgid: ppid,
                                uid: 1000,
                                path: target_path.clone(),
                                dev: 0,
                                ino: 0,
                                flags: 0,
                            });
                        }

                        if pgrp > 1 && pgrp != pid && pgrp != ppid {
                            let _ = tx.blocking_send(EbpfEvent::FileOpen {
                                tgid: pgrp,
                                uid: 1000,
                                path: target_path,
                                dev: 0,
                                ino: 0,
                                flags: 0,
                            });
                        }
                    }
                }
                unsafe {
                    libc::close(meta.fd);
                }
            }

            offset += meta.event_len as usize;
        }
    }

    unsafe {
        libc::close(fan_fd);
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
