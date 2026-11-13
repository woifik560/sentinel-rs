//! sentineld — Root security daemon for Sentinel-RS.
//!
//! Integrates eBPF kernel probes, Causal Lineage DAG, Transparent Risk Engine,
//! and Freeze & Inspect Interactive Prompt over Unix IPC.

#![allow(dead_code)]

use clap::Parser;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::{Duration, SystemTime, UNIX_EPOCH};
use tracing::{error, info, warn, Level};
use tracing_subscriber::FmtSubscriber;
use uuid::Uuid;

use sentinel_common::config::{RulesConfig, SentinelConfig};
use sentinel_common::events::EbpfEvent;
use sentinel_common::incident::IncidentReport;
use sentinel_common::ipc::{IpcMessage, PromptRequest};
use sentinel_common::risk::Verdict;
use sentinel_ebpf::loader::{EbpfLoader, LoaderConfig};
use sentinel_ebpf::programs::file_open::simulate_file_open_check;

mod freeze;
mod ipc_server;
mod lineage;
mod pkg_check;
mod risk_engine;
mod sha_cache;
mod verdict;

use freeze::FreezeInspectOrchestrator;
use ipc_server::IpcServer;
use lineage::LineageTracker;
use pkg_check::DpkgChecker;
use risk_engine::{NetworkContext, RiskEngine};
use sha_cache::ShaCache;
use verdict::VerdictRouter;

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

    let config = SentinelConfig::load_from_file(&config_path).unwrap_or_else(|e| {
        warn!("Could not load config from {}: {}. Using defaults.", config_path.display(), e);
        SentinelConfig::default()
    });

    let rules = RulesConfig::load_from_file(&rules_path).unwrap_or_else(|e| {
        warn!("Could not load rules from {}: {}. Using defaults.", rules_path.display(), e);
        RulesConfig::default()
    });

    info!("Loaded configuration from {}", config_path.display());
    info!("Loaded rules from {}", rules_path.display());

    // 2. Initialize Core Engine Modules
    let dpkg_checker = DpkgChecker::new();
    let _sha_cache = ShaCache::new(2048);
    let lineage_tracker = LineageTracker::new(config.general.ring_buffer_size);
    let risk_engine = Arc::new(RiskEngine::new(rules.clone(), dpkg_checker));
    let verdict_router = Arc::new(VerdictRouter::new(rules));
    let freeze_orchestrator = FreezeInspectOrchestrator::new(config.general.prompt_timeout_secs);

    // 3. Initialize and Start IPC Server
    let ipc_server = Arc::new(IpcServer::new(
        config.socket.path.clone(),
        freeze_orchestrator.clone(),
        lineage_tracker.clone(),
    ));

    let ipc_runner = ipc_server.clone();
    tokio::spawn(async move {
        if let Err(e) = ipc_runner.run().await {
            error!("IPC server encountered error: {}", e);
        }
    });

    // 4. Start Fail-Closed Background Timeout Reaper
    let freeze_reaper = freeze_orchestrator.clone();
    tokio::spawn(async move {
        let mut interval = tokio::time::interval(Duration::from_secs(1));
        loop {
            interval.tick().await;
            let expired = freeze_reaper.check_timeouts();
            if !expired.is_empty() {
                warn!("Fail-Closed reaper terminated expired TGIDs: {:?}", expired);
            }
        }
    });

    // 5. Initialize eBPF Loader
    let mut ebpf_loader = EbpfLoader::new(LoaderConfig {
        ring_buffer_size: config.general.ring_buffer_size,
        enable_lsm: true,
        enable_tracepoints: true,
    });
    ebpf_loader.load_and_attach().await?;
    let mut event_rx = ebpf_loader.take_event_receiver().expect("Receiver must be present");
    let taint_mgr = ebpf_loader.taint_manager();

    info!("Sentinel-RS daemon fully initialized and operational.");

    // 6. Main RingBuffer Event Dispatch Loop
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

            EbpfEvent::ProcessFork { parent_tgid, child_tgid } => {
                taint_mgr.inherit_fork(parent_tgid, child_tgid);
                lineage_tracker.handle_fork(parent_tgid, child_tgid);
            }

            EbpfEvent::ProcessExec { tgid, exe_path, cmdline } => {
                lineage_tracker.handle_exec(tgid, exe_path, cmdline);
            }

            EbpfEvent::SocketConnect { tgid, addr_family: _, dst_ipv4, dst_ipv6, dst_port, protocol: _ } => {
                let dest_ip = dst_ipv4
                    .map(|ip| ip.to_string())
                    .or_else(|| dst_ipv6.map(|ip| ip.to_string()));

                let now_ns = SystemTime::now()
                    .duration_since(UNIX_EPOCH)
                    .unwrap_or_default()
                    .as_nanos() as u64;

                let net_ctx = NetworkContext {
                    dest_ip: dest_ip.clone(),
                    dest_port: dst_port,
                    has_dns_record: false,
                    current_time_ns: now_ns,
                };

                let node = lineage_tracker.get(tgid).unwrap_or_else(|| {
                    sentinel_common::process::ProcessNode::new(
                        tgid,
                        1,
                        1000,
                        PathBuf::from("/proc/unknown"),
                    )
                });

                let score = risk_engine.evaluate(&node, &net_ctx);
                let verdict = verdict_router.route(&score);
                let chain = lineage_tracker.get_ancestor_chain(tgid);

                let incident_id = Uuid::new_v4().to_string();
                let last_secret = node.secret_accesses.last();
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

                if let Ok(json) = serde_json::to_string_pretty(&report) {
                    ipc_server.store_incident_json(incident_id.clone(), json).await;
                }

                match verdict {
                    Verdict::Low => {
                        // Allow and broadcast event
                        ipc_server.broadcast_event(IpcMessage::Event {
                            timestamp: chrono::Utc::now().to_rfc3339(),
                            summary: report.human_summary,
                            risk_score: Some(score.total),
                        });
                    }
                    Verdict::Grey => {
                        // Freeze process and present prompt
                        let _ = freeze_orchestrator.freeze(tgid);
                        freeze_orchestrator.register_prompt(incident_id.clone(), tgid);

                        let expires_at = SystemTime::now()
                            .checked_add(Duration::from_secs(config.general.prompt_timeout_secs))
                            .unwrap_or(SystemTime::now())
                            .duration_since(UNIX_EPOCH)
                            .unwrap_or_default()
                            .as_secs();

                        let prompt = PromptRequest {
                            incident_id,
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

                        ipc_server.broadcast_prompt(prompt);
                    }
                    Verdict::High => {
                        // Immediate freeze and block
                        let _ = freeze_orchestrator.freeze(tgid);
                        ipc_server.broadcast_event(IpcMessage::Event {
                            timestamp: chrono::Utc::now().to_rfc3339(),
                            summary: report.human_summary,
                            risk_score: Some(score.total),
                        });
                    }
                }
            }

            EbpfEvent::SocketSendmsg { tgid, addr_family: _, dst_ipv4: _, dst_ipv6: _, dst_port } => {
                // Similar handling for connectionless UDP
                warn!("Intercepted UDP sendmsg for TGID {} -> port {}", tgid, dst_port);
            }
        }
    }

    Ok(())
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
