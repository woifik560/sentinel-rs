//! sentineld — Root security daemon for Sentinel-RS.
//!
//! Integrates eBPF kernel object storages (TASK_STORAGE, INODE_STORAGE, SK_STORAGE),
//! Causal Lineage DAG, LoLBin-hardened Risk Engine, Zero-Drop NFQUEUE network holding,
//! and Never-Freeze interactive prompt over Unix IPC.

#![allow(dead_code)]
#![allow(unused_variables)]
#![allow(unused_mut)]
#![allow(warnings)]

use clap::Parser;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::{Duration, SystemTime, UNIX_EPOCH};
use tracing::{error, info, warn, Level};
use tracing_subscriber::FmtSubscriber;
use uuid::Uuid;

use sentinel_common::config::{RulesConfig, SentinelConfig};
use sentinel_common::events::{EbpfEvent, MAY_READ};
use sentinel_common::incident::IncidentReport;
use sentinel_common::ipc::{IpcMessage, PromptRequest};
use sentinel_common::process::SecretCategory;
use sentinel_common::risk::Verdict;
use sentinel_ebpf::loader::{EbpfLoader, LoaderConfig};
use sentinel_ebpf::programs::file_open::simulate_file_open_check;

use sentineld::context_policy::ContextPolicyEngine;
use sentineld::freeze::{FreezeInspectOrchestrator, HoldResult, NfqueueHoldManager};
use sentineld::ipc_server::IpcServer;
use sentineld::lineage::LineageTracker;
use sentineld::pkg_check::DpkgChecker;
use sentineld::preflight::run_preflight_checks;
use sentineld::protection::ProtectionState;
use sentineld::risk::{NetworkContext, RiskEngine};
use sentineld::sha_cache::ShaCache;
use sentineld::storage::StorageManager;
use sentineld::tofu::{TofuCheckResult, TofuManager};
use sentineld::verdict::VerdictRouter;
use sentineld::verdict_cache::VerdictDecisionCache;

#[derive(Parser, Debug)]
#[command(name = "sentineld", author = "woifik560", version = "0.2.0")]
#[command(about = "Deterministic eBPF host firewall and integrity daemon for Linux Desktop")]
struct Cli {
    /// Path to configuration file
    #[arg(short, long, default_value = "/etc/sentinel/config.toml")]
    config: PathBuf,

    /// Path to rules configuration file
    #[arg(short, long, default_value = "/etc/sentinel/rules.toml")]
    rules: PathBuf,

    /// Run in silent observer / soak audit mode (Milestone 1)
    #[arg(long)]
    audit_only: bool,

    /// Enable verbose debug logging
    #[arg(short, long)]
    verbose: bool,
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    let cli = Cli::parse();

    let log_level = if cli.verbose { Level::DEBUG } else { Level::INFO };
    let subscriber = FmtSubscriber::builder()
        .with_max_level(log_level)
        .with_target(false)
        .finish();
    tracing::subscriber::set_global_default(subscriber)
        .expect("Failed to initialize tracing subscriber");

    info!("Starting Sentinel-RS Daemon (sentineld v0.2.0)...");
    info!("Target RAM usage budget: < 25-30 MB RAM (Zero LLM / Pure Deterministic)");

    // 1. Load Configurations (with local fallback if running from repo)
    let config_path = resolve_config_path(&cli.config, "config/config.toml");
    let rules_path = resolve_config_path(&cli.rules, "config/rules.toml");

    let mut config = if config_path.exists() {
        SentinelConfig::load_from_file(&config_path)
            .map_err(|e| anyhow::anyhow!("Configuration parsing error in {}: {}", config_path.display(), e))?
    } else {
        info!("Configuration not found at {}. Using defaults.", config_path.display());
        SentinelConfig::default()
    };

    if cli.audit_only {
        config.general.audit_only = true;
    }

    let rules = if rules_path.exists() {
        RulesConfig::load_from_file(&rules_path)
            .map_err(|e| anyhow::anyhow!("Rules configuration parsing error in {}: {}", rules_path.display(), e))?
    } else {
        info!("Rules configuration not found at {}. Using defaults.", rules_path.display());
        RulesConfig::default()
    };

    info!("Loaded configuration from {}", config_path.display());
    info!("Loaded rules from {}", rules_path.display());
    if config.general.audit_only {
        info!("RUNNING IN AUDIT-ONLY / SOAK MODE (Milestone 1): Actions will be logged without blocking.");
    }

    // 2. Run Preflight Checks (BPF LSM & Kernel Safety)
    let _preflight = run_preflight_checks(false, &config.general.min_kernel_version)?;

    // 3. Initialize Core Engine Modules
    let dpkg_checker = DpkgChecker::new();
    let _sha_cache = ShaCache::new(2048);
    let lineage_tracker = LineageTracker::new(config.general.ring_buffer_size);
    let risk_engine = Arc::new(tokio::sync::RwLock::new(RiskEngine::new(rules.clone(), dpkg_checker)));
    let verdict_router = Arc::new(VerdictRouter::new(rules));
    let tofu_mgr = Arc::new(TofuManager::new(&config.tofu.db_path));
    let context_policy = Arc::new(ContextPolicyEngine::new(config.context_rules.clone()).with_default_rules());
    let _verdict_cache = Arc::new(VerdictDecisionCache::new());

    // Initialize Persistent SQLite Storage (Audit 3.3)
    let storage_db_path = config.tofu.db_path.parent()
        .map(|p| p.join("sentinel.db"))
        .unwrap_or_else(|| PathBuf::from("/var/lib/sentinel/sentinel.db"));
    let storage_manager = match StorageManager::new(storage_db_path.clone(), 1024) {
        Ok(mgr) => {
            info!("Persistent SQLite database initialized at {}", storage_db_path.display());
            Some(mgr)
        }
        Err(e) => {
            warn!("Failed to initialize primary SQLite storage at {}: {}. Falling back to /run/sentinel/sentinel.db", storage_db_path.display(), e);
            StorageManager::new(PathBuf::from("/run/sentinel/sentinel.db"), 1024).ok()
        }
    };

    let freeze_orchestrator = FreezeInspectOrchestrator::new(
        config.general.prompt_timeout_secs,
        config.general.pending_queue_size,
        config.general.aggregate_window_ms,
    );

    // Initialize nftables holding rule for NFQUEUE (Audit 1.5)
    let holding_res = freeze_orchestrator.init_network_holding();
    let network_holding_active = holding_res.is_ok();
    if let Err(ref e) = holding_res {
        warn!("Failed to initialize nftables holding: {}. Running in degraded network holding mode.", e);
    }

    // Shared Protection State (Audit 1.3)
    let op_mode = std::str::FromStr::from_str(&config.general.mode.to_uppercase())
        .unwrap_or(sentinel_common::policy::OperatingMode::Balanced);
    let protection_state = Arc::new(tokio::sync::RwLock::new(ProtectionState::new(
        !config.general.audit_only,
        op_mode,
        rules_path.clone(),
        config_path.clone(),
    )));
    {
        let mut st = protection_state.write().await;
        st.network_holding_active = network_holding_active;
    }

    // Network Protection Manager for nftables isolation & anti-lockout
    let block_mgr = Arc::new(sentineld::response::NetworkBlockManager::new());
    let network_manager = Arc::new(
        sentineld::network::NetworkProtectionManager::new(
            block_mgr,
            config.general.aggregate_window_ms,
        ),
    );

    // Graceful Shutdown Signal Handler: Restore nftables rules on SIGINT/SIGTERM (Audit 3.1)
    tokio::spawn(run_shutdown_listener());

    // 4. Initialize eBPF Loader
    let mut ebpf_loader = EbpfLoader::new(LoaderConfig {
        ring_buffer_size: config.general.ring_buffer_size,
        enable_lsm: true,
        enable_tracepoints: true,
        strict_preflight: false,
        min_kernel_version: config.general.min_kernel_version.clone(),
    });
    ebpf_loader.load_and_attach().await?;
    let raw_event_rx = ebpf_loader.take_event_receiver().expect("Receiver must be present");
    let taint_mgr = ebpf_loader.taint_manager();

    {
        let mut st = protection_state.write().await;
        st.bpf_lsm_active = (ebpf_loader.bpf_lsm_state() == sentinel_common::health::MechanismState::Active);
    }

    // Bounded RingBuffer Consumer with DoS rate-limiting
    let event_metrics = Arc::new(sentineld::collector::EventMetrics::default());
    let consumer = sentineld::collector::RingBufferConsumer::new(
        event_metrics.clone(),
        config.general.ring_buffer_size,
    );
    let mut event_rx = consumer.start_consumer(raw_event_rx);

    // Register daemon PID for kernel self-defense and systemd as IPC broker
    taint_mgr.set_daemon_pid(std::process::id());
    taint_mgr.register_ipc_broker(1);

    // Start in-kernel Watchdog Heartbeat (updates BPF array map every 500ms)
    let heartbeat_taint = taint_mgr.clone();
    tokio::spawn(async move {
        loop {
            let now_ns = SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .map(|d| d.as_nanos() as u64)
                .unwrap_or(0);
            heartbeat_taint.update_heartbeat(now_ns);
            tokio::time::sleep(Duration::from_millis(500)).await;
        }
    });

    // 5. Initialize and Start IPC Server (Management & Read-Only Monitor)
    let ipc_server = Arc::new(
        IpcServer::new(
            config.socket.path.clone(),
            config.socket.readonly_path.clone(),
            freeze_orchestrator.clone(),
            lineage_tracker.clone(),
            taint_mgr.clone(),
        )
        .with_state_and_storage(
            protection_state.clone(),
            risk_engine.clone(),
            storage_manager.clone(),
        )
        .with_network_manager(network_manager.clone()),
    );

    let ipc_runner = ipc_server.clone();
    tokio::spawn(async move {
        if let Err(e) = ipc_runner.run().await {
            error!("IPC server encountered error: {}", e);
        }
    });

    // 6. Start Fail-Closed Background Timeout Reaper
    let freeze_reaper = freeze_orchestrator.clone();
    tokio::spawn(async move {
        let mut interval = tokio::time::interval(Duration::from_secs(1));
        loop {
            interval.tick().await;
            let expired = freeze_reaper.check_timeouts();
            if !expired.is_empty() {
                warn!("Fail-Closed reaper dropped held packets for expired TGIDs: {:?}", expired);
            }
        }
    });

    // 7. Periodic Lineage & Taint Memory Pruner (Audit 2.5)
    let pruner_lineage = lineage_tracker.clone();
    let pruner_taint = taint_mgr.clone();
    tokio::spawn(async move {
        let mut interval = tokio::time::interval(Duration::from_secs(300));
        loop {
            interval.tick().await;
            let count_lineage = pruner_lineage.prune_dead();
            let count_taint = pruner_taint.prune_dead();
            if count_lineage > 0 || count_taint > 0 {
                tracing::debug!("Memory pruner cleaned {} lineage nodes, {} taint records", count_lineage, count_taint);
            }
        }
    });

    // Systemd Ready & Health-Aware Watchdog Notification (TASK-P0-07)
    notify_systemd("READY=1");
    if let Ok(usec_str) = std::env::var("WATCHDOG_USEC") {
        if let Ok(usec) = usec_str.parse::<u64>() {
            let interval = Duration::from_micros(usec / 2);
            let degraded_mgr = std::sync::Arc::new(sentineld::health::DegradedStateManager::new());
            let failure_policy = std::sync::Arc::new(sentineld::health::FailurePolicyManager::new());
            let health_monitor = std::sync::Arc::new(sentineld::health::HealthMonitor::with_failure_policy(
                degraded_mgr,
                failure_policy,
            ));
            let sub_metrics = std::sync::Arc::new(sentineld::health::SubsystemMetrics::default());
            let wd = sentineld::health::Watchdog::with_monitor(interval, health_monitor, sub_metrics);
            wd.start();
        }
    }

    info!("Sentinel-RS daemon fully initialized and operational.");

    // 7. Main RingBuffer Event Dispatch Loop
    while let Some(event) = event_rx.recv().await {
        match event {
            EbpfEvent::FileOpen { tgid, uid: _, ref path, dev: _, ino: _, flags: _ } => {
                let path_str = path.to_string_lossy();
                let current_exe = lineage_tracker
                    .get(tgid)
                    .map(|n| n.exe_path.to_string_lossy().to_string())
                    .unwrap_or_default();

                if let Some(category) = simulate_file_open_check(&path_str, &current_exe) {
                    warn!(
                        "Secret access detected: TGID {} accessed {:?} ({})",
                        tgid, category, path_str
                    );
                    taint_mgr.mark_tainted(tgid);
                    let now_ns = SystemTime::now()
                        .duration_since(UNIX_EPOCH)
                        .unwrap_or_default()
                        .as_nanos() as u64;
                    lineage_tracker.record_secret_access(tgid, path.clone(), category, now_ns);
                }
            }

            EbpfEvent::FilePermission { tgid, uid: _, ref path, dev, ino, mask, is_pipe, is_fifo } => {
                if let Some(_taint) = taint_mgr.handle_file_permission(tgid, dev, ino, path, mask, is_pipe, is_fifo) {
                    let is_read = (mask & MAY_READ) != 0;
                    if is_read {
                        warn!(
                            "Data-flow taint propagation: TGID {} inherited taint via pipe/file {}",
                            tgid, path.display()
                        );
                        let now_ns = SystemTime::now()
                            .duration_since(UNIX_EPOCH)
                            .unwrap_or_default()
                            .as_nanos() as u64;
                        lineage_tracker.record_secret_access(
                            tgid,
                            path.clone(),
                            SecretCategory::Other(format!("Pipe/FIFO Taint: {}", path.display())),
                            now_ns,
                        );
                    }
                }
            }

            EbpfEvent::UnixMaySend { sender_tgid, receiver_tgid, ref sock_path, is_blocked: _ } => {
                let verdict = taint_mgr.handle_unix_may_send(sender_tgid, receiver_tgid, sock_path);
                if verdict == sentinel_ebpf::UnixSendVerdict::TaintReceiver {
                    warn!(
                        "IPC Taint Laundering Prevention: TGID {} inherited taint from TGID {} via AF_UNIX {}",
                        receiver_tgid, sender_tgid, sock_path.display()
                    );
                    let now_ns = SystemTime::now()
                        .duration_since(UNIX_EPOCH)
                        .unwrap_or_default()
                        .as_nanos() as u64;
                    lineage_tracker.record_secret_access(
                        receiver_tgid,
                        sock_path.clone(),
                        SecretCategory::Other(format!("AF_UNIX Taint: {}", sock_path.display())),
                        now_ns,
                    );
                }
            }

            EbpfEvent::PtraceAccessCheck { tracer_tgid, tracee_tgid, mode, is_blocked: _ } => {
                let verdict = taint_mgr.handle_ptrace_access_check(tracer_tgid, tracee_tgid, mode);
                if verdict == sentinel_ebpf::PtraceVerdict::Deny {
                    warn!(
                        "Memory Snooping Prevention: Denied ptrace/process_vm_readv from tainted TGID {} to TGID {}",
                        tracer_tgid, tracee_tgid
                    );
                }
            }

            EbpfEvent::ProcEnvironAccess { reader_tgid, target_tgid, ref path, is_blocked: _ } => {
                warn!(
                    "Cross-Process Credential Snoop: TGID {} attempted to read environ/mem of TGID {} ({})",
                    reader_tgid, target_tgid, path.display()
                );
                taint_mgr.mark_tainted(reader_tgid);
            }

            EbpfEvent::MmapFile { tgid, uid: _, ref path, dev, ino, prot, flags, is_secret: _, is_write_shared: _, is_exec: _ } => {
                let verdict = taint_mgr.handle_mmap_file(tgid, dev, ino, path, prot, flags);
                match verdict {
                    sentinel_ebpf::MmapVerdict::TaintTask => {
                        warn!("mmap Secret Access: TGID {} mapped secret {}", tgid, path.display());
                        let now_ns = SystemTime::now()
                            .duration_since(UNIX_EPOCH)
                            .unwrap_or_default()
                            .as_nanos() as u64;
                        lineage_tracker.record_secret_access(
                            tgid,
                            path.clone(),
                            SecretCategory::Other(format!("mmap Secret: {}", path.display())),
                            now_ns,
                        );
                    }
                    sentinel_ebpf::MmapVerdict::TaintInode => {
                        warn!("mmap Shared Memory Taint: Tainted TGID {} mapped {} with PROT_WRITE | MAP_SHARED", tgid, path.display());
                    }
                    sentinel_ebpf::MmapVerdict::FlagAnonExec
                    | sentinel_ebpf::MmapVerdict::TaintedExecutionBlocked
                    | sentinel_ebpf::MmapVerdict::DenyMmap => {
                        warn!("mmap Blocked / Fileless Execution: TGID {} attempted unauthorized executable mapping on {}", tgid, path.display());
                        if let Some(mut node) = lineage_tracker.get(tgid) {
                            node.is_anon_exec = true;
                            lineage_tracker.insert(node.clone());
                            if node.has_secret_access() {
                                warn!("Immediate enforcement: terminating tainted TGID {} attempting unauthorized executable mmap", tgid);
                                let _ = freeze_orchestrator.terminate_process(tgid, &node.exe_name(), node.uid);
                            }
                        }
                    }
                    sentinel_ebpf::MmapVerdict::Allow => {}
                }
            }

            EbpfEvent::FileReceive { receiver_tgid, sender_tgid, ref path, dev, ino, is_tainted: _ } => {
                let verdict = taint_mgr.handle_file_receive(receiver_tgid, sender_tgid, dev, ino, path);
                if verdict == sentinel_ebpf::FileReceiveVerdict::TaintReceiver {
                    warn!(
                        "SCM_RIGHTS Taint Propagation: TGID {} inherited descriptor to {} from TGID {}",
                        receiver_tgid, path.display(), sender_tgid
                    );
                    let now_ns = SystemTime::now()
                        .duration_since(UNIX_EPOCH)
                        .unwrap_or_default()
                        .as_nanos() as u64;
                    lineage_tracker.record_secret_access(
                        receiver_tgid,
                        path.clone(),
                        SecretCategory::Other(format!("SCM_RIGHTS: {}", path.display())),
                        now_ns,
                    );
                }
            }

            EbpfEvent::BprmCheckSecurity { tgid, uid: _, exe_path: _, dev: _, ino: _, is_memfd } => {
                if is_memfd {
                    warn!("LSM bprm_check_security: anonymous memfd_create execution detected for TGID {}", tgid);
                    if let Some(mut node) = lineage_tracker.get(tgid) {
                        node.is_memfd = true;
                        lineage_tracker.insert(node.clone());
                        if node.has_secret_access() {
                            warn!("Immediate enforcement: terminating tainted TGID {} attempting memfd_create execution", tgid);
                            let _ = freeze_orchestrator.terminate_process(tgid, &node.exe_name(), node.uid);
                        }
                    }
                }
            }

            EbpfEvent::ProcessFork { parent_tgid, child_tgid } => {
                taint_mgr.register_thread(child_tgid, parent_tgid);
                taint_mgr.inherit_fork(parent_tgid, child_tgid);
                lineage_tracker.handle_fork(parent_tgid, child_tgid);
            }

            EbpfEvent::ProcessExec { tgid, exe_path, cmdline } => {
                lineage_tracker.handle_exec(tgid, exe_path, cmdline);
            }

            EbpfEvent::SocketConnect { tgid, group_leader_tgid, addr_family: _, dst_ipv4, dst_ipv6, dst_port, protocol: _, so_mark }
            | EbpfEvent::SocketSendmsg { tgid, group_leader_tgid, addr_family: _, dst_ipv4, dst_ipv6, dst_port, so_mark, is_preopened: _ } => {
                // Synchronous FlowContext lookup from flow_mark_ctx eBPF map:
                let _flow_ctx = taint_mgr.lookup_flow_context(so_mark);
                let is_reval = (so_mark & sentinel_common::events::SENTINEL_MARK_REVAL_BIT) != 0;
                if is_reval {
                    warn!("Established Socket Re-evaluation: intercepted established flow with mark 0x{:08X} for TGID {}", so_mark, tgid);
                }

                let dest_ip = dst_ipv4
                    .map(|ip| ip.to_string())
                    .or_else(|| dst_ipv6.map(|ip| ip.to_string()));

                let effective_tgid = tgid;

                let is_first_seen_ip = dest_ip
                    .as_ref()
                    .map(|ip| lineage_tracker.record_ip_contact(effective_tgid, ip))
                    .unwrap_or(false);

                let now_ns = SystemTime::now()
                    .duration_since(UNIX_EPOCH)
                    .unwrap_or_default()
                    .as_nanos() as u64;

                let mut node = lineage_tracker.get(effective_tgid).or_else(|| {
                    if let Some(discovered) = LineageTracker::discover_from_procfs(effective_tgid) {
                        let mut disc = discovered;
                        if let Some(parent) = lineage_tracker.get(disc.ppid) {
                            disc.ancestor_script = parent.script_path.clone().or_else(|| parent.ancestor_script.clone());
                            if parent.has_secret_access() {
                                disc.secret_accesses = parent.secret_accesses.clone();
                            }
                        }
                        lineage_tracker.insert(disc.clone());
                        Some(disc)
                    } else {
                        None
                    }
                }).unwrap_or_else(|| {
                    sentinel_common::process::ProcessNode::new(
                        effective_tgid,
                        1,
                        1000,
                        PathBuf::from("/proc/unknown"),
                    )
                });

                // If cmdline has 1 or fewer elements or script_path is none, re-check /proc/<effective_tgid>/cmdline
                if node.cmdline.len() <= 1 || node.script_path.is_none() {
                    if let Ok(bytes) = std::fs::read(format!("/proc/{}/cmdline", effective_tgid)) {
                        let cmd: Vec<String> = bytes
                            .split(|&b| b == 0)
                            .filter(|s| !s.is_empty())
                            .map(|s| String::from_utf8_lossy(s).to_string())
                            .collect();
                        if !cmd.is_empty() {
                            let script_info = sentineld::lineage::tracker::inspect_interpreter(&node.exe_path, &cmd);
                            if let Some(info) = script_info {
                                if let Some(sp) = info.script_path {
                                    node.script_path = Some(sp);
                                    node.is_interactive_shell = false;
                                }
                            }
                            if cmd.iter().any(|a| a.ends_with(".sh") || a.starts_with("/tmp/") || a == "-c") {
                                node.is_interactive_shell = false;
                            }
                            node.cmdline = cmd;
                        }
                    }
                }

                // Dual-defense: If this process itself has no recorded secrets, but its ancestors in the lineage
                // tree or group leader accessed secrets (e.g. bash or scp spawned ssh), inherit ancestor secrets and script!
                let mut effective_node = node.clone();
                let effective_group_leader = if group_leader_tgid != 0 && group_leader_tgid != effective_tgid {
                    group_leader_tgid
                } else {
                    effective_node.group_leader_tgid
                };

                // 1. Check group leader first!
                if effective_group_leader != 0 && effective_group_leader != effective_tgid {
                    if let Some(leader) = lineage_tracker.get(effective_group_leader) {
                        if effective_node.ancestor_script.is_none() {
                            effective_node.ancestor_script = leader.script_path.clone().or_else(|| leader.ancestor_script.clone());
                        }
                        if effective_node.secret_accesses.is_empty() && leader.has_secret_access() {
                            effective_node.secret_accesses.extend(leader.secret_accesses.clone());
                        }
                    }
                }

                // 2. Upward ancestor traversal
                if effective_node.secret_accesses.is_empty() || effective_node.ancestor_script.is_none() {
                    let mut curr_ppid = effective_node.ppid;
                    let mut visited = std::collections::HashSet::new();
                    visited.insert(effective_tgid);
                    while curr_ppid > 1 && visited.insert(curr_ppid) {
                        let ancestor_opt = lineage_tracker.get(curr_ppid)
                            .or_else(|| LineageTracker::discover_from_procfs(curr_ppid));

                        if let Some(mut ancestor) = ancestor_opt {
                            if ancestor.cmdline.len() <= 1 || ancestor.script_path.is_none() {
                                if let Ok(bytes) = std::fs::read(format!("/proc/{}/cmdline", curr_ppid)) {
                                    let cmd: Vec<String> = bytes
                                        .split(|&b| b == 0)
                                        .filter(|s| !s.is_empty())
                                        .map(|s| String::from_utf8_lossy(s).to_string())
                                        .collect();
                                    if !cmd.is_empty() {
                                        if let Some(info) = sentineld::lineage::tracker::inspect_interpreter(&ancestor.exe_path, &cmd) {
                                            if let Some(sp) = info.script_path {
                                                ancestor.script_path = Some(sp);
                                                ancestor.is_interactive_shell = false;
                                            }
                                        }
                                        if cmd.iter().any(|a| a.ends_with(".sh") || a.starts_with("/tmp/") || a == "-c") {
                                            ancestor.is_interactive_shell = false;
                                        }
                                        ancestor.cmdline = cmd;
                                    }
                                }
                            }

                            if effective_node.ancestor_script.is_none() {
                                effective_node.ancestor_script = ancestor.script_path.clone().or_else(|| ancestor.ancestor_script.clone());
                            }
                            if !ancestor.secret_accesses.is_empty() {
                                effective_node.secret_accesses.extend(ancestor.secret_accesses.clone());
                                break;
                            }
                            if ancestor.is_interactive_shell && ancestor.secret_accesses.is_empty() {
                                break;
                            }
                            curr_ppid = ancestor.ppid;
                        } else {
                            break;
                        }
                    }
                }

                // 3. Dual-domain / cross-namespace fallback: If still no secrets recorded, check for recent taint
                if effective_node.secret_accesses.is_empty() {
                    if let Some(tainted) = lineage_tracker.find_recent_tainted(now_ns, 30_000_000_000) {
                        warn!(
                            "Cross-namespace taint correlation: associating network connect from TGID {} with recent tainted process TGID {} ({})",
                            effective_tgid, tainted.tgid, tainted.display_name()
                        );
                        if effective_node.ancestor_script.is_none() {
                            effective_node.ancestor_script = tainted.script_path.clone().or_else(|| tainted.ancestor_script.clone());
                        }
                        effective_node.secret_accesses.extend(tainted.secret_accesses.clone());
                        if effective_node.group_leader_tgid <= 1 {
                            effective_node.group_leader_tgid = tainted.group_leader_tgid;
                        }
                    }
                }

                // Contextual Policy Pre-Approval Check: ("who + what secret + where to connect")
                let last_secret = effective_node.secret_accesses.last();
                if let Some(rule) = context_policy.is_allowed(
                    &effective_node.exe_path,
                    effective_node.exe_sha256.as_deref(),
                    last_secret.map(|s| &s.category),
                    dest_ip.as_deref(),
                    dst_port,
                    None,
                ) {
                    info!(
                        "CONTEXT POLICY PRE-APPROVED: Flow allowed by rule '{}' for TGID {} ({}) -> {}:{}",
                        rule.id, tgid, effective_node.display_name(), dest_ip.as_deref().unwrap_or("?"), dst_port
                    );
                    ipc_server.broadcast_event(IpcMessage::Event {
                        timestamp: chrono::Utc::now().to_rfc3339(),
                        summary: format!("Pre-approved contextual flow ({}) for {}", rule.id, effective_node.display_name()),
                        risk_score: Some(0),
                    });
                    continue;
                }

                // TOFU Check for software outside dpkg
                let is_tofu_target = TofuManager::is_non_dpkg_target(&effective_node.exe_path);
                let mut is_tofu_tampered = false;
                if is_tofu_target {
                    if let Some(ref sha) = effective_node.exe_sha256 {
                        match tofu_mgr.check_or_register(&effective_node.exe_path, sha) {
                            TofuCheckResult::Tampered { expected, actual } => {
                                warn!(
                                    "TOFU TAMPER ALERT: Binary {} hash mismatch! Expected {}, got {}",
                                    effective_node.exe_path.display(), expected, actual
                                );
                                is_tofu_tampered = true;
                            }
                            _ => {}
                        }
                    }
                }

                let is_ipc_laundered = effective_node.secret_accesses.iter().any(|s| {
                    matches!(s.category, SecretCategory::Other(ref tag) if tag.contains("AF_UNIX") || tag.contains("SCM_RIGHTS") || tag.contains("ptrace"))
                });

                let is_dns_port = dst_port == 53;
                let has_dns_record = is_dns_port || !sentineld::risk::is_numeric_ip(dest_ip.as_deref().unwrap_or(""));

                let net_ctx = NetworkContext {
                    dest_ip: dest_ip.clone(),
                    dest_port: dst_port,
                    has_dns_record,
                    is_first_seen_ip,
                    current_time_ns: now_ns,
                    is_tofu_tampered,
                    is_ipc_laundered,
                    dest_domain: None,
                };

                // Check if protection is enabled (Audit 1.3)
                let is_prot_active = protection_state.read().await.enabled;
                if !is_prot_active {
                    info!("[PROTECTION DISABLED] Allowing flow for TGID {} -> {}:{}", tgid, dest_ip.as_deref().unwrap_or("?"), dst_port);
                    continue;
                }

                let score = risk_engine.read().await.evaluate(&effective_node, &net_ctx);
                let verdict = verdict_router.route(&score);
                let chain = lineage_tracker.get_ancestor_chain(tgid);

                let incident_id = Uuid::new_v4().to_string();
                let secret_path = last_secret.map(|s| s.path.to_string_lossy().to_string());
                let time_delta_ms = last_secret.map(|s| {
                    now_ns.saturating_sub(s.timestamp_ns) / 1_000_000
                });

                let reasons: Vec<String> = score.firings.iter().map(|f| f.reason.clone()).collect();

                let report = IncidentReport::new(
                    incident_id.clone(),
                    chrono::Utc::now(),
                    score.total,
                    verdict.clone(),
                    chain.clone(),
                    secret_path.clone(),
                    time_delta_ms,
                    dest_ip.clone(),
                    Some(dst_port),
                    None,
                    score.firings.clone(),
                );

                if verdict != Verdict::Low {
                    protection_state.read().await.increment_incidents();
                    if let Ok(json) = serde_json::to_string_pretty(&report) {
                        ipc_server.store_incident_json(incident_id.clone(), json).await;
                    }
                    if let Some(ref s) = storage_manager {
                        let stored_rec = sentineld::storage::schema::StoredIncidentRecord {
                            incident_id: incident_id.clone(),
                            created_at: chrono::Utc::now(),
                            updated_at: chrono::Utc::now(),
                            severity: format!("{:?}", verdict),
                            risk_score: report.risk_score,
                            process_key: format!("{}:0", tgid),
                            status: "Active".to_string(),
                            verdict: format!("{:?}", verdict),
                            human_summary: report.human_summary.clone(),
                            details_json: serde_json::to_string(&report).unwrap_or_default(),
                        };
                        s.queue_incident(stored_rec);
                    }
                }

                if config.general.audit_only {
                    info!("[AUDIT ONLY] Verdict {:?} for TGID {} (score: {})", verdict, tgid, score.total);
                    ipc_server.broadcast_event(IpcMessage::Event {
                        timestamp: chrono::Utc::now().to_rfc3339(),
                        summary: format!("[AUDIT] {}", report.human_summary),
                        risk_score: Some(score.total),
                    });
                    continue;
                }

                match verdict {
                    Verdict::Low => {
                        ipc_server.broadcast_event(IpcMessage::Event {
                            timestamp: chrono::Utc::now().to_rfc3339(),
                            summary: report.human_summary,
                            risk_score: Some(score.total),
                        });
                    }
                    Verdict::Grey => {
                        let exe_name = effective_node
                            .exe_path
                            .file_name()
                            .map(|n| n.to_string_lossy().to_string())
                            .unwrap_or_default();

                        let dest_tuple = dest_ip.clone().map(|ip| (ip, dst_port));
                        let hold_res = freeze_orchestrator.hold_network(
                            incident_id.clone(),
                            tgid,
                            exe_name,
                            None,
                            dest_tuple,
                        );

                        match hold_res {
                            HoldResult::NewPrompt(inc_id) => {
                                let expires_at = SystemTime::now()
                                    .checked_add(Duration::from_secs(config.general.prompt_timeout_secs))
                                    .unwrap_or(SystemTime::now())
                                    .duration_since(UNIX_EPOCH)
                                    .unwrap_or_default()
                                    .as_secs();

                                let prompt = PromptRequest {
                                    incident_id: inc_id,
                                    risk_score: score.total,
                                    lineage: chain,
                                    secret_path,
                                    time_delta_ms,
                                    dest_ip,
                                    dest_port: Some(dst_port),
                                    dest_domain: None,
                                    reasons,
                                    expires_at_unix: expires_at,
                                };

                                ipc_server.broadcast_prompt(prompt).await;
                            }
                            HoldResult::Aggregated(existing_id) => {
                                info!("Request aggregated into active prompt {}", existing_id);
                            }
                            HoldResult::PreApproved => {
                                info!("TGID {} connection was pre-approved by active duration/host policy", tgid);
                            }
                            HoldResult::QueueFull => {
                                warn!("Connection dropped immediately due to queue saturation DoS defense.");
                            }
                        }
                    }
                    Verdict::High => {
                        // Immediate freeze and block (respecting Never-Freeze Allowlist)
                        let _ = freeze_orchestrator.freeze_process(effective_tgid, &effective_node.exe_path, effective_node.uid);
                        if let Some(ref ip) = dest_ip {
                            if ip != "0.0.0.0" && ip != "127.0.0.1" && !ip.starts_with("127.") && !ip.is_empty() {
                                sentineld::network::nftables::NftablesManager::block_ip(ip);
                            }
                        }
                        let _ = freeze_orchestrator.terminate_process(effective_tgid, &effective_node.exe_name(), effective_node.uid);
                        if effective_node.ppid > 1 {
                            // Only terminate parent if it is executing an untrusted script or payload, never interactive shell or desktop manager
                            let parent_node = lineage_tracker.get(effective_node.ppid)
                                .or_else(|| LineageTracker::discover_from_procfs(effective_node.ppid));
                            if let Some(parent) = parent_node {
                                if !parent.is_interactive_shell && (parent.script_path.is_some() || parent.ancestor_script.is_some()) {
                                    let _ = freeze_orchestrator.terminate_process(effective_node.ppid, &parent.exe_name(), parent.uid);
                                }
                            }
                        }
                        if effective_tgid != tgid {
                            let host_exe = lineage_tracker.get(tgid)
                                .map(|n| n.exe_name())
                                .unwrap_or_else(|| "stealer_host_pid".to_string());
                            let _ = freeze_orchestrator.terminate_process(tgid, &host_exe, effective_node.uid);
                        }
                        ipc_server.broadcast_event(IpcMessage::Event {
                            timestamp: chrono::Utc::now().to_rfc3339(),
                            summary: report.human_summary,
                            risk_score: Some(score.total),
                        });
                    }
                }
            }
        }
    }

    Ok(())
}

fn notify_systemd(state: &str) {
    #[cfg(unix)]
    {
        if let Some(path) = std::env::var_os("NOTIFY_SOCKET") {
            if let Ok(sock) = std::os::unix::net::UnixDatagram::unbound() {
                let _ = sock.send_to(state.as_bytes(), path);
            }
        }
    }
}

fn resolve_config_path(primary: &Path, fallback: &str) -> PathBuf {
    if primary.exists() {
        primary.to_path_buf()
    } else if Path::new(fallback).exists() {
        PathBuf::from(fallback)
    } else {
        primary.to_path_buf()
    }
}

async fn run_shutdown_listener() {
    #[cfg(unix)]
    {
        use tokio::signal::unix::{signal, SignalKind};
        let sigterm = signal(SignalKind::terminate());
        let sigint = signal(SignalKind::interrupt());
        match (sigterm, sigint) {
            (Ok(mut term), Ok(mut int)) => {
                tokio::select! {
                    _ = term.recv() => {
                        info!("SIGTERM received. Initiating graceful shutdown...");
                    }
                    _ = int.recv() => {
                        info!("SIGINT received. Initiating graceful shutdown...");
                    }
                }
            }
            _ => {
                let _ = tokio::signal::ctrl_c().await;
            }
        }
    }
    #[cfg(not(unix))]
    {
        let _ = tokio::signal::ctrl_c().await;
    }

    notify_systemd("STOPPING=1");
    info!("Termination signal received. Cleaning up Netfilter rules and sockets...");
    NfqueueHoldManager::clean_nftables_rules();
    sentineld::network::nftables::NftablesManager::cleanup_rules();
    let _ = tokio::fs::remove_file("/run/sentinel/sentinel.sock").await;
    let _ = tokio::fs::remove_file("/run/sentinel/sentinel-ro.sock").await;
    std::process::exit(0);
}
