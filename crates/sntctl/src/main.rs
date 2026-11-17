//! sntctl — Command-line interface management and triage tool for Sentinel-RS.

use clap::{Parser, Subcommand};
use std::path::{Path, PathBuf};
use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader};

use sentinel_common::ipc::IpcMessage;

mod client;
mod commands;
mod output;

use client::{connect_socket, DEFAULT_PRIVILEGED_SOCKET, DEFAULT_READONLY_SOCKET};
use commands::{
    config::{run_config, ConfigAction},
    diagnostics::run_diagnostics,
    doctor::run_doctor,
    events::{run_events, EventsAction},
    health::run_health,
    incidents::{run_incidents, IncidentsAction},
    network::{run_network, NetworkAction},
    policy::{run_policy, PolicyActionCmd},
    process::{run_process, ProcessAction},
    protection::{run_protection, ProtectionAction},
    rules::{run_rules, RulesAction},
    setup_kernel::run_setup_kernel,
    status::run_status,
};

#[derive(Parser, Debug)]
#[command(name = "sntctl", author = "woifik560", version = "0.2.1")]
#[command(about = "CLI management and triage tool for Sentinel-RS headless HIPS/EDR agent")]
struct Cli {
    /// Path to Sentinel Unix Domain Socket
    #[arg(short, long)]
    socket: Option<PathBuf>,

    /// Emit machine-readable JSON output
    #[arg(long, global = true)]
    json: bool,

    #[command(subcommand)]
    command: Commands,
}

#[derive(Subcommand, Debug)]
enum Commands {
    /// Query daemon status and summary statistics [Read-Only]
    Status,

    /// Query subsystem health and watchdog diagnostics [Read-Only]
    Health,

    /// Run full system diagnostics and security preflight checks
    Doctor,

    /// Manage autonomous prevention and defensive protections
    Protection {
        #[command(subcommand)]
        action: ProtectionAction,
    },

    /// Query and export normalized security events
    Events {
        #[command(subcommand)]
        action: EventsAction,
    },

    /// Manage and inspect security incidents and forensic reports
    Incidents {
        #[command(subcommand)]
        action: IncidentsAction,
    },

    /// Inspect and manage security policy rules and operating modes
    Policy {
        #[command(subcommand)]
        action: PolicyActionCmd,
    },

    /// List active behavior detection heuristics and rules
    Rules {
        #[command(subcommand)]
        action: RulesAction,
    },

    /// Inspect process DAG, attributes, and lineage ancestry
    Process {
        #[command(subcommand)]
        action: ProcessAction,
    },

    /// Inspect Netfilter status and network containment blocks
    Network {
        #[command(subcommand)]
        action: NetworkAction,
    },

    /// Validate configuration file syntax
    Config {
        #[command(subcommand)]
        action: ConfigAction,
    },

    /// Deep internal telemetry diagnostics
    Diagnostics,

    /// Unfreeze a suspended process TGID [Requires Root]
    Unfreeze {
        /// Process Thread Group ID (PID)
        tgid: u32,
    },

    /// Live stream of security events and detections [Read-Only]
    Monitor,

    /// Universal Linux kernel and bootloader auto-configuration for BPF LSM [Requires Root]
    SetupKernel {
        /// Force re-configuration even if BPF is already present in /sys/kernel/security/lsm
        #[arg(long)]
        force: bool,
    },
}

fn is_root() -> bool {
    #[cfg(unix)]
    {
        extern "C" {
            fn geteuid() -> u32;
        }
        unsafe { geteuid() == 0 }
    }
    #[cfg(not(unix))]
    {
        false
    }
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    let cli = Cli::parse();
    let json = cli.json;

    let is_root = is_root();

    match cli.command {
        Commands::Status => {
            let default_sock = if is_root {
                DEFAULT_PRIVILEGED_SOCKET
            } else {
                DEFAULT_READONLY_SOCKET
            };
            let sock = cli.socket.unwrap_or_else(|| PathBuf::from(default_sock));
            run_status(&sock, json).await?
        }
        Commands::Health => {
            let default_sock = if is_root {
                DEFAULT_PRIVILEGED_SOCKET
            } else {
                DEFAULT_READONLY_SOCKET
            };
            let sock = cli.socket.unwrap_or_else(|| PathBuf::from(default_sock));
            run_health(&sock, json).await?
        }
        Commands::Doctor => run_doctor().await?,
        Commands::Protection { action } => {
            let sock = cli.socket.unwrap_or_else(|| PathBuf::from(DEFAULT_PRIVILEGED_SOCKET));
            run_protection(&sock, action, json).await?
        }
        Commands::Events { action } => {
            let sock = cli.socket.unwrap_or_else(|| PathBuf::from(DEFAULT_READONLY_SOCKET));
            run_events(&sock, action, json).await?
        }
        Commands::Incidents { action } => {
            let sock = cli.socket.unwrap_or_else(|| PathBuf::from(DEFAULT_READONLY_SOCKET));
            run_incidents(&sock, action, json).await?
        }
        Commands::Policy { action } => {
            let sock = cli.socket.unwrap_or_else(|| PathBuf::from(DEFAULT_PRIVILEGED_SOCKET));
            run_policy(&sock, action, json).await?
        }
        Commands::Rules { action } => {
            let sock = cli.socket.unwrap_or_else(|| PathBuf::from(DEFAULT_READONLY_SOCKET));
            run_rules(&sock, action, json).await?
        }
        Commands::Process { action } => {
            let default_sock = match action {
                ProcessAction::Kill { .. } | ProcessAction::Suspend { .. } => DEFAULT_PRIVILEGED_SOCKET,
                _ => DEFAULT_READONLY_SOCKET,
            };
            let sock = cli.socket.unwrap_or_else(|| PathBuf::from(default_sock));
            run_process(&sock, action, json).await?
        }
        Commands::Network { action } => {
            let default_sock = match action {
                NetworkAction::Isolate | NetworkAction::Unisolate => DEFAULT_PRIVILEGED_SOCKET,
                _ => DEFAULT_READONLY_SOCKET,
            };
            let sock = cli.socket.unwrap_or_else(|| PathBuf::from(default_sock));
            run_network(&sock, action, json).await?
        }
        Commands::Config { action } => run_config(action).await?,
        Commands::Diagnostics => {
            let sock = cli.socket.unwrap_or_else(|| PathBuf::from(DEFAULT_READONLY_SOCKET));
            run_diagnostics(&sock, json).await?
        }
        Commands::Unfreeze { tgid } => {
            let sock = cli.socket.unwrap_or_else(|| PathBuf::from(DEFAULT_PRIVILEGED_SOCKET));
            run_unfreeze(&sock, tgid).await?
        }
        Commands::Monitor => {
            let sock = cli.socket.unwrap_or_else(|| PathBuf::from(DEFAULT_READONLY_SOCKET));
            run_monitor(&sock).await?
        }
        Commands::SetupKernel { force } => run_setup_kernel(force).await?,
    }

    Ok(())
}

async fn run_unfreeze(socket_path: &Path, tgid: u32) -> anyhow::Result<()> {
    let stream = connect_socket(socket_path).await?;
    let (_, mut writer) = stream.into_split();

    let msg = IpcMessage::Unfreeze { tgid };
    let payload = serde_json::to_string(&msg)? + "\n";
    writer.write_all(payload.as_bytes()).await?;
    println!("Unfreeze request sent for TGID {}", tgid);
    Ok(())
}

async fn run_monitor(socket_path: &Path) -> anyhow::Result<()> {
    let stream = connect_socket(socket_path).await?;
    let (reader, mut writer) = stream.into_split();
    let mut reader = BufReader::new(reader);

    let sub = IpcMessage::Subscribe;
    let payload = serde_json::to_string(&sub)? + "\n";
    writer.write_all(payload.as_bytes()).await?;

    println!("Streaming Sentinel-RS firewall events from {} (Ctrl+C to quit)...", socket_path.display());
    let mut line = String::new();
    while reader.read_line(&mut line).await? > 0 {
        let trimmed = line.trim();
        if let Ok(msg) = serde_json::from_str::<IpcMessage>(trimmed) {
            match msg {
                IpcMessage::Event { timestamp, summary, risk_score } => {
                    let score_str = risk_score
                        .map(|s| format!(" [Risk: {}]", s))
                        .unwrap_or_default();
                    println!("[{}] {}{}", timestamp, summary, score_str);
                }
                IpcMessage::Prompt(p) => {
                    println!("[ALERT] Incident {} (Risk: {}/100)", p.incident_id, p.risk_score);
                }
                _ => {}
            }
        }
        line.clear();
    }
    Ok(())
}
