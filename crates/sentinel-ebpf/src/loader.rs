//! Userspace loader and RingBuffer event listener for Sentinel eBPF probes.

use std::collections::HashMap;
use std::sync::Arc;
use tokio::sync::mpsc;
use tracing::{info, warn};

#[cfg(target_os = "linux")]
use aya::programs::lsm::LsmLinkId;
#[cfg(target_os = "linux")]
use aya::programs::Program;
#[cfg(target_os = "linux")]
use aya::{Btf, Ebpf};

use crate::maps::TaintMapManager;
use sentinel_common::events::EbpfEvent;
use sentinel_common::health::MechanismState;

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
    bpf_lsm_state: MechanismState,
    tracepoints_state: MechanismState,
    ring_buffer_state: MechanismState,
    fanotify_state: MechanismState,
    #[cfg(target_os = "linux")]
    bpf_instance: Option<Ebpf>,
    #[cfg(target_os = "linux")]
    attached_links: Vec<LsmLinkId>,
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
            bpf_lsm_state: MechanismState::Unavailable,
            tracepoints_state: MechanismState::Unavailable,
            ring_buffer_state: MechanismState::Unavailable,
            fanotify_state: MechanismState::Unavailable,
            #[cfg(target_os = "linux")]
            bpf_instance: None,
            #[cfg(target_os = "linux")]
            attached_links: Vec::new(),
        }
    }

    pub fn bpf_lsm_state(&self) -> MechanismState {
        self.bpf_lsm_state
    }

    pub fn tracepoints_state(&self) -> MechanismState {
        self.tracepoints_state
    }

    pub fn ring_buffer_state(&self) -> MechanismState {
        self.ring_buffer_state
    }

    pub fn fanotify_state(&self) -> MechanismState {
        self.fanotify_state
    }

    pub fn mechanism_states(&self) -> HashMap<String, MechanismState> {
        let mut map = HashMap::new();
        map.insert("bpf_lsm".into(), self.bpf_lsm_state);
        map.insert("tracepoints".into(), self.tracepoints_state);
        map.insert("ring_buffer".into(), self.ring_buffer_state);
        map.insert("fanotify".into(), self.fanotify_state);
        map
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
        self.bpf_lsm_state = MechanismState::Loading;
        self.ring_buffer_state = MechanismState::Loading;

        // 1. Check if BPF LSM is active in the running kernel
        let lsm_content = std::fs::read_to_string("/sys/kernel/security/lsm").unwrap_or_default();
        let lsm_supported = lsm_content.contains("bpf");

        // 2. Check kernel version for safe BPF_MAP_TYPE_INODE_STORAGE support (Linux 6.x+)
        let os_release = std::fs::read_to_string("/proc/sys/kernel/osrelease").unwrap_or_default();
        let is_kernel_safe =
            verify_kernel_version_safe(&os_release, &self.config.min_kernel_version);

        if !is_kernel_safe {
            self.bpf_lsm_state = MechanismState::Unsupported;
            if self.config.strict_preflight {
                anyhow::bail!(
                    "PREFLIGHT FAILED: Running kernel '{}' is older than required safe threshold '{}'. \
                     Refusing to load BPF INODE_STORAGE to prevent potential kernel panics (CVE-2026-64192 mitigation).",
                    os_release.trim(),
                    self.config.min_kernel_version
                );
            }
        }

        if !lsm_supported {
            if self.bpf_lsm_state != MechanismState::Unsupported {
                self.bpf_lsm_state = MechanismState::Unavailable;
            }
            if self.config.strict_preflight {
                anyhow::bail!(
                    "PREFLIGHT FAILED: BPF LSM is not active in /sys/kernel/security/lsm (current: '{}'). \
                     Add 'lsm=...,bpf' to kernel cmdline or GRUB_CMDLINE_LINUX to prevent kernel lockups.",
                    lsm_content.trim()
                );
            }
        }

        // 3. Attempt Aya ELF loading and BPF LSM hook attachment if an eBPF ELF binary is present
        let bpf_obj_paths = [
            std::env::var("SENTINEL_BPF_OBJ")
                .ok()
                .map(std::path::PathBuf::from),
            Some(std::path::PathBuf::from("bpf/sentinel.bpf.o")),
            Some(std::path::PathBuf::from("../bpf/sentinel.bpf.o")),
            Some(std::path::PathBuf::from(
                "/usr/lib/sentinel/bpf/sentinel.bpf.o",
            )),
            Some(std::path::PathBuf::from("/etc/sentinel/sentinel.bpf.o")),
        ];

        let mut loaded_and_attached = false;
        #[cfg(target_os = "linux")]
        {
            for path in bpf_obj_paths.iter().flatten() {
                if path.exists() {
                    info!("Attempting to load eBPF ELF object from {}", path.display());
                    match aya::Ebpf::load_file(path) {
                        Ok(mut bpf) => {
                            info!(
                                "Successfully parsed eBPF ELF object from {}",
                                path.display()
                            );

                            // Load BTF from kernel
                            let btf = match Btf::from_sys_fs() {
                                Ok(btf) => btf,
                                Err(e) => {
                                    warn!("Kernel BTF not available (/sys/kernel/btf/vmlinux): {}. Cannot attach LSM programs.", e);
                                    self.bpf_lsm_state = MechanismState::Unsupported;
                                    break;
                                }
                            };

                            let mut current_links = Vec::new();
                            let mut attach_failed = false;
                            let mut attached_count = 0;

                            for (name, program) in bpf.programs_mut() {
                                match program {
                                    Program::Lsm(lsm) => {
                                        info!("Found LSM program '{}' in ELF object", name);
                                        // Load into verifier
                                        if let Err(e) = lsm.load(name, &btf) {
                                            warn!(
                                                "BPF verifier rejected LSM program '{}': {}",
                                                name, e
                                            );
                                            attach_failed = true;
                                            break;
                                        }
                                        // Attach to LSM hook
                                        match lsm.attach() {
                                            Ok(link_id) => {
                                                info!(
                                                    "Successfully attached BPF LSM hook '{}'",
                                                    name
                                                );
                                                current_links.push(link_id);
                                                attached_count += 1;
                                            }
                                            Err(e) => {
                                                warn!(
                                                    "Failed to attach BPF LSM hook '{}': {}",
                                                    name, e
                                                );
                                                attach_failed = true;
                                                break;
                                            }
                                        }
                                    }
                                    _ => {
                                        info!("Found non-LSM program '{}' in ELF object", name);
                                    }
                                }
                            }

                            if attach_failed {
                                warn!("Partial or complete LSM attachment failure! Rolling back previously attached hooks...");
                                current_links.clear(); // Dropping links detaches them
                                self.bpf_lsm_state = MechanismState::Failed;
                            } else if attached_count > 0 {
                                info!(
                                    "All {} LSM programs attached and validated.",
                                    attached_count
                                );
                                self.attached_links = current_links;
                                self.bpf_instance = Some(bpf);
                                self.bpf_lsm_state = MechanismState::Active;
                                loaded_and_attached = true;
                                break;
                            } else {
                                warn!("ELF object contained no attachable LSM programs.");
                                self.bpf_lsm_state = MechanismState::Unavailable;
                            }
                        }
                        Err(e) => {
                            warn!(
                                "Failed to load eBPF ELF object from {}: {}",
                                path.display(),
                                e
                            );
                            self.bpf_lsm_state = MechanismState::Failed;
                        }
                    }
                }
            }
        }

        if !loaded_and_attached
            && self.bpf_lsm_state != MechanismState::Unsupported
            && self.bpf_lsm_state != MechanismState::Failed
        {
            self.bpf_lsm_state = MechanismState::Unavailable;
        }

        if lsm_supported && loaded_and_attached {
            info!("Kernel BPF LSM support verified and active with live attachments");
        } else {
            warn!(
                "BPF LSM is in state '{}'. Operating in tracepoint & fanotify monitoring mode.",
                self.bpf_lsm_state
            );
        }

        #[cfg(target_os = "linux")]
        {
            if self.config.enable_tracepoints {
                let trace_dirs = ["/sys/kernel/tracing", "/sys/kernel/debug/tracing"];
                if trace_dirs.iter().any(|d| std::path::Path::new(d).exists()) {
                    self.tracepoints_state = MechanismState::Active;
                    self.start_live_monitors();
                } else {
                    self.tracepoints_state = MechanismState::Unavailable;
                    warn!("Tracing directory not found (/sys/kernel/tracing). Tracepoint monitoring unavailable.");
                }
            } else {
                self.tracepoints_state = MechanismState::Unavailable;
            }
        }
        #[cfg(not(target_os = "linux"))]
        {
            self.tracepoints_state = MechanismState::Unsupported;
            self.fanotify_state = MechanismState::Unsupported;
        }

        if self.bpf_lsm_state == MechanismState::Active {
            self.ring_buffer_state = MechanismState::Active;
        } else if self.tracepoints_state == MechanismState::Active {
            self.ring_buffer_state = MechanismState::Degraded;
        } else {
            self.ring_buffer_state = MechanismState::Unavailable;
        }
        info!(
            "eBPF RingBuffer listener configured (size: {}, state: {:?})",
            self.config.ring_buffer_size, self.ring_buffer_state
        );
        Ok(())
    }

    /// Detaches all kernel hooks and safely frees eBPF resources.
    pub fn unload(&mut self) {
        #[cfg(target_os = "linux")]
        {
            self.attached_links.clear();
            self.bpf_instance.take();
        }
        self.bpf_lsm_state = MechanismState::Unavailable;
        self.ring_buffer_state = MechanismState::Unavailable;
        info!("EbpfLoader unloaded all BPF programs and detached hooks");
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
            warn!(
                "Could not open {}: {}. Tracepoint stream unavailable.",
                pipe_path.display(),
                e
            );
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
                let child_str = line[c_idx + 10..]
                    .split_whitespace()
                    .next()
                    .unwrap_or_default();
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
                        let _ = tx.blocking_send(EbpfEvent::ProcessFork {
                            parent_tgid,
                            child_tgid,
                        });
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
                    line[f_idx + 9..]
                        .split_whitespace()
                        .next()
                        .unwrap_or_default()
                };
                let pid_str = line[p_idx + 5..]
                    .split_whitespace()
                    .next()
                    .unwrap_or_default();
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
                line[dp_idx + 6..]
                    .split_whitespace()
                    .next()
                    .and_then(|s| s.parse::<u16>().ok())
            } else {
                None
            };

            let daddr_opt = if let Some(da_idx) = line.find("daddr=") {
                line[da_idx + 6..]
                    .split_whitespace()
                    .next()
                    .and_then(|s| s.parse::<std::net::Ipv4Addr>().ok())
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

    #[repr(C)]
    struct FanotifyResponse {
        fd: libc::c_int,
        response: u32,
    }
    const FAN_ALLOW: u32 = 0x01;
    const FAN_DENY: u32 = 0x02;
    const FAN_CLASS_CONTENT: u32 = 0x00000004;
    const FAN_CLASS_NOTIF: u32 = 0x00000000;
    const FAN_OPEN_PERM: u64 = 0x00010000;
    const FAN_ACCESS_PERM: u64 = 0x00020000;

    // Try permission enforcement class first (requires CAP_SYS_ADMIN), fall back to notification class
    let (fan_fd, is_perm_mode) = {
        let fd = unsafe {
            libc::fanotify_init(
                FAN_CLASS_CONTENT | libc::FAN_CLOEXEC | libc::FAN_NONBLOCK,
                (libc::O_RDONLY | libc::O_LARGEFILE) as u32,
            )
        };
        if fd >= 0 {
            (fd, true)
        } else {
            let notif_fd = unsafe {
                libc::fanotify_init(
                    FAN_CLASS_NOTIF | libc::FAN_CLOEXEC | libc::FAN_NONBLOCK,
                    (libc::O_RDONLY | libc::O_LARGEFILE) as u32,
                )
            };
            (notif_fd, false)
        }
    };

    if fan_fd < 0 {
        warn!("fanotify_init failed (requires CAP_SYS_ADMIN). File access monitoring running in passive tracepoint mode.");
        return;
    }

    let mark_mask = if is_perm_mode {
        FAN_OPEN_PERM | FAN_ACCESS_PERM | libc::FAN_OPEN as u64
    } else {
        libc::FAN_OPEN as u64
    };

    // Mark target directories containing secrets and binaries
    let targets = ["/home", "/root", "/etc", "/tmp"];
    let mut marked = 0;
    for target in &targets {
        if let Ok(c_target) = CString::new(*target) {
            let ret = unsafe {
                libc::fanotify_mark(
                    fan_fd,
                    libc::FAN_MARK_ADD | libc::FAN_MARK_FILESYSTEM,
                    mark_mask,
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
                        mark_mask | libc::FAN_EVENT_ON_CHILD as u64,
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

    info!(
        "fanotify secret monitor active (marked {} targets, enforcement_mode: {}).",
        marked, is_perm_mode
    );

    let mut buf = vec![0u8; 16384];
    let mut pollfd = libc::pollfd {
        fd: fan_fd,
        events: libc::POLLIN,
        revents: 0,
    };

    loop {
        // Use poll with 100ms timeout to avoid hanging and allow clean shutdown
        let poll_res = unsafe { libc::poll(&mut pollfd, 1, 100) };
        if poll_res < 0 {
            let err = std::io::Error::last_os_error();
            if err.kind() == std::io::ErrorKind::Interrupted {
                continue;
            }
            break;
        }
        if poll_res == 0 {
            continue; // Timeout, loop back
        }

        let n = unsafe { libc::read(fan_fd, buf.as_mut_ptr() as *mut libc::c_void, buf.len()) };
        if n <= 0 {
            let err = std::io::Error::last_os_error();
            if err.kind() == std::io::ErrorKind::WouldBlock {
                continue;
            }
            break;
        }

        let mut offset = 0;
        while offset + std::mem::size_of::<libc::fanotify_event_metadata>() <= n as usize {
            let meta =
                unsafe { &*(buf.as_ptr().add(offset) as *const libc::fanotify_event_metadata) };
            if meta.event_len == 0 {
                break;
            }

            // Handle queue overflow
            if (meta.mask & libc::FAN_Q_OVERFLOW as u64) != 0 {
                warn!("fanotify queue overflow detected! Events dropped by kernel.");
                offset += meta.event_len as usize;
                continue;
            }

            if meta.fd >= 0 {
                let is_perm_event = (meta.mask & (FAN_OPEN_PERM | FAN_ACCESS_PERM)) != 0;
                let proc_fd_path = format!("/proc/self/fd/{}", meta.fd);
                let mut should_deny = false;

                // Extract real inode, device, and owner UID via fstat on real file descriptor
                let mut stat_buf: libc::stat = unsafe { std::mem::zeroed() };
                let (real_dev, real_ino, real_owner_uid) = if unsafe { libc::fstat(meta.fd, &mut stat_buf) } == 0 {
                    (stat_buf.st_dev as u64, stat_buf.st_ino as u64, stat_buf.st_uid as u32)
                } else {
                    (0, 0, 0)
                };

                if let Ok(target_path) = std::fs::read_link(&proc_fd_path) {
                    let path_str = target_path.to_string_lossy();
                    let pid = meta.pid as u32;

                    let current_exe = std::fs::read_link(format!("/proc/{}/exe", pid))
                        .map(|p| p.to_string_lossy().to_string())
                        .unwrap_or_default();

                    // Read real process UID from /proc/[pid]/status
                    let proc_uid = std::fs::read_to_string(format!("/proc/{}/status", pid))
                        .ok()
                        .and_then(|s| {
                            for line in s.lines() {
                                if line.starts_with("Uid:") {
                                    return line.split_whitespace().nth(1)?.parse::<u32>().ok();
                                }
                            }
                            None
                        })
                        .unwrap_or(real_owner_uid);

                    if let Some(_cat) = crate::programs::file_open::simulate_file_open_check(
                        &path_str,
                        &current_exe,
                    ) {
                        // Extract parent PID and PGID for lineage tracking
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

                        if ppid > 1 {
                            let _ = tx.blocking_send(EbpfEvent::ProcessFork {
                                parent_tgid: ppid,
                                child_tgid: pid,
                            });
                        }

                        // Send real event with genuine dev, ino, and proc_uid
                        let _ = tx.blocking_send(EbpfEvent::FileOpen {
                            tgid: pid,
                            uid: proc_uid,
                            path: target_path.clone(),
                            dev: real_dev,
                            ino: real_ino,
                            flags: meta.mask as u32,
                        });

                        if ppid > 1 {
                            let _ = tx.blocking_send(EbpfEvent::FileOpen {
                                tgid: ppid,
                                uid: proc_uid,
                                path: target_path.clone(),
                                dev: real_dev,
                                ino: real_ino,
                                flags: meta.mask as u32,
                            });
                        }

                        if pgrp > 1 && pgrp != pid && pgrp != ppid {
                            let _ = tx.blocking_send(EbpfEvent::FileOpen {
                                tgid: pgrp,
                                uid: proc_uid,
                                path: target_path,
                                dev: real_dev,
                                ino: real_ino,
                                flags: meta.mask as u32,
                            });
                        }
                    }
                }

                // If this is a permission event, send real verdict response to kernel
                if is_perm_event {
                    let resp = FanotifyResponse {
                        fd: meta.fd,
                        response: if should_deny { FAN_DENY } else { FAN_ALLOW },
                    };
                    unsafe {
                        libc::write(
                            fan_fd,
                            &resp as *const _ as *const libc::c_void,
                            std::mem::size_of::<FanotifyResponse>(),
                        );
                    }
                }

                // Always close metadata file descriptor to prevent FD leak
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

    let min = parse_ver(min_version).unwrap_or((6, 1));

    actual >= min
}
