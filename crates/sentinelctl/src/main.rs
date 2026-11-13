//! sentinelctl — Command-line interface client for Sentinel-RS.
//!
//! Provides interactive watch mode, live event monitoring, process unfreezing,
//! forensic report export, and whitelist management over Unix domain IPC.

use clap::{Parser, Subcommand};
use std::io::{self, Write};
use std::path::{Path, PathBuf};
use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader};
use tokio::net::UnixStream;

use sentinel_common::config::SentinelConfig;
use sentinel_common::ipc::{IpcMessage, PromptAction, PromptRequest, PromptVerdict};

#[derive(Parser, Debug)]
#[command(name = "sentinelctl", author = "woifik560", version = "0.2.0")]
#[command(about = "CLI management and triage tool for Sentinel-RS firewall")]
struct Cli {
    /// Path to Sentinel Unix Domain Socket
    #[arg(short, long, default_value = "/run/sentinel/sentinel.sock")]
    socket: PathBuf,

    #[command(subcommand)]
    command: Commands,
}

#[derive(Subcommand, Debug)]
enum Commands {
    /// Interactive real-time prompt triage (for SSH and terminals)
    Watch,

    /// Live stream of firewall events and security accesses
    Monitor,

    /// Unfreeze a mistakenly blocked process TGID
    Unfreeze {
        /// Process Thread Group ID (PID)
        tgid: u32,
    },

    /// Query daemon status and statistics
    Status,

    /// Export forensic incident report in JSON format
    Export {
        /// Incident ID to export
        incident_id: String,
        /// Output format (default: json)
        #[arg(short, long, default_value = "json")]
        format: String,
    },

    /// Manage trusted application whitelists
    Whitelist {
        #[command(subcommand)]
        action: WhitelistAction,
    },
}

#[derive(Subcommand, Debug)]
enum WhitelistAction {
    /// List whitelisted binaries
    List,
    /// Add a binary path to whitelist
    Add {
        /// Path to the executable binary
        path: PathBuf,
    },
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    let cli = Cli::parse();

    match cli.command {
        Commands::Watch => run_watch(&cli.socket).await?,
        Commands::Monitor => run_monitor(&cli.socket).await?,
        Commands::Unfreeze { tgid } => run_unfreeze(&cli.socket, tgid).await?,
        Commands::Status => run_status(&cli.socket).await?,
        Commands::Export { incident_id, format: _ } => run_export(&cli.socket, incident_id).await?,
        Commands::Whitelist { action } => run_whitelist(action).await?,
    }

    Ok(())
}

/// Connects to sentineld socket with fallback error guidance.
async fn connect_socket(socket_path: &Path) -> anyhow::Result<UnixStream> {
    UnixStream::connect(socket_path).await.map_err(|e| {
        anyhow::anyhow!(
            "Failed to connect to sentineld IPC socket at {}: {}\nIs 'sentineld' running with sudo/root?",
            socket_path.display(),
            e
        )
    })
}

/// `sentinelctl watch`: interactive prompt loop for triage.
async fn run_watch(socket_path: &Path) -> anyhow::Result<()> {
    println!("Connecting to Sentinel-RS daemon at {}...", socket_path.display());
    let stream = connect_socket(socket_path).await?;
    let (reader, mut writer) = stream.into_split();
    let mut reader = BufReader::new(reader);

    println!("================================================================================");
    println!(" Sentinel-RS Interactive Watch Mode (Terminal Freeze & Inspect)");
    println!(" Waiting for security prompts from daemon... (Press Ctrl+C to exit)");
    println!("================================================================================");

    let mut line = String::new();
    loop {
        line.clear();
        let bytes_read = reader.read_line(&mut line).await?;
        if bytes_read == 0 {
            println!("Disconnected from sentineld.");
            break;
        }

        let trimmed = line.trim();
        if let Ok(IpcMessage::Prompt(prompt)) = serde_json::from_str::<IpcMessage>(trimmed) {
            display_prompt(&prompt);

            let action = prompt_user_action();
            let verdict = PromptVerdict {
                incident_id: prompt.incident_id,
                action,
            };

            let msg = IpcMessage::Verdict(verdict);
            let payload = serde_json::to_string(&msg)? + "\n";
            writer.write_all(payload.as_bytes()).await?;
            println!("Verdict submitted successfully.\n");
        }
    }

    Ok(())
}

fn display_prompt(p: &PromptRequest) {
    println!("\n========================== ПОДОЗРИТЕЛЬНАЯ АКТИВНОСТЬ ==========================");
    println!("Инцидент ID:  {}", p.incident_id);
    println!("Оценка риска: {} / 100", p.risk_score);

    // Lineage breadcrumb
    let chain_str = p
        .lineage
        .iter()
        .map(|s| s.to_string())
        .collect::<Vec<_>>()
        .join(" -> ");
    println!("Цепочка:      {}", chain_str);

    if let Some(ref sec) = p.secret_path {
        let delta_str = p
            .time_delta_ms
            .map(|ms| format!(" ({:.2}s назад)", ms as f64 / 1000.0))
            .unwrap_or_default();
        println!("Секрет:       {}{}", sec, delta_str);
    }

    if let Some(ref ip) = p.dest_ip {
        let port_str = p.dest_port.map(|p| format!(":{}", p)).unwrap_or_default();
        println!("Назначение:   {}{}", ip, port_str);
    }

    println!("\nСработавшие правила риска:");
    for r in &p.reasons {
        println!("  • {}", r);
    }
    println!("================================================================================");
}

fn prompt_user_action() -> PromptAction {
    loop {
        println!("Выберите действие:");
        println!("  [1] Убить процесс (SIGKILL)");
        println!("  [2] Заблокировать разово (DenyOnce)");
        println!("  [3] Разрешить разово (AllowOnce)");
        println!("  [4] Разрешить для этого экземпляра (AllowProcess)");
        println!("  [5] Добавить в постоянный App Scope");
        print!("Ваш выбор [1-5]: ");
        io::stdout().flush().unwrap();

        let mut input = String::new();
        if io::stdin().read_line(&mut input).is_ok() {
            match input.trim() {
                "1" => return PromptAction::Kill,
                "2" => return PromptAction::DenyOnce,
                "3" => return PromptAction::AllowOnce,
                "4" => return PromptAction::AllowProcess,
                "5" => return PromptAction::AllowAppScope,
                _ => println!("Неверный ввод, введите число от 1 до 5."),
            }
        }
    }
}

/// `sentinelctl monitor`: live streaming log of events.
async fn run_monitor(socket_path: &Path) -> anyhow::Result<()> {
    let stream = connect_socket(socket_path).await?;
    let (reader, mut writer) = stream.into_split();
    let mut reader = BufReader::new(reader);

    // Send subscribe message
    let sub = IpcMessage::Subscribe;
    let payload = serde_json::to_string(&sub)? + "\n";
    writer.write_all(payload.as_bytes()).await?;

    println!("Streaming Sentinel-RS firewall events (Ctrl+C to quit)...");
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
                    println!("[PROMPT] Incident {} (Risk: {}/100)", p.incident_id, p.risk_score);
                }
                _ => {}
            }
        }
        line.clear();
    }
    Ok(())
}

/// `sentinelctl unfreeze <tgid>`: unfreeze process.
async fn run_unfreeze(socket_path: &Path, tgid: u32) -> anyhow::Result<()> {
    let stream = connect_socket(socket_path).await?;
    let (_, mut writer) = stream.into_split();

    let msg = IpcMessage::Unfreeze { tgid };
    let payload = serde_json::to_string(&msg)? + "\n";
    writer.write_all(payload.as_bytes()).await?;
    println!("Unfreeze request sent for TGID {}", tgid);
    Ok(())
}

/// `sentinelctl status`: query daemon status.
async fn run_status(socket_path: &Path) -> anyhow::Result<()> {
    let stream = connect_socket(socket_path).await?;
    let (reader, mut writer) = stream.into_split();
    let mut reader = BufReader::new(reader);

    let msg = IpcMessage::StatusRequest;
    let payload = serde_json::to_string(&msg)? + "\n";
    writer.write_all(payload.as_bytes()).await?;

    let mut response = String::new();
    reader.read_line(&mut response).await?;

    if let Ok(IpcMessage::StatusResponse { uptime_secs, tracked_processes, total_incidents, frozen_count }) =
        serde_json::from_str::<IpcMessage>(response.trim())
    {
        println!("Sentinel-RS Daemon Status:");
        println!("  Uptime:             {} seconds", uptime_secs);
        println!("  Tracked Processes:  {}", tracked_processes);
        println!("  Total Incidents:    {}", total_incidents);
        println!("  Frozen Processes:   {}", frozen_count);
    } else {
        println!("Received response: {}", response.trim());
    }
    Ok(())
}

/// `sentinelctl export <incident_id>`: export forensic report.
async fn run_export(socket_path: &Path, incident_id: String) -> anyhow::Result<()> {
    let stream = connect_socket(socket_path).await?;
    let (reader, mut writer) = stream.into_split();
    let mut reader = BufReader::new(reader);

    let msg = IpcMessage::ExportRequest { incident_id };
    let payload = serde_json::to_string(&msg)? + "\n";
    writer.write_all(payload.as_bytes()).await?;

    let mut response = String::new();
    reader.read_line(&mut response).await?;

    if let Ok(IpcMessage::ExportResponse { report_json }) =
        serde_json::from_str::<IpcMessage>(response.trim())
    {
        println!("{}", report_json);
    } else {
        println!("Export response: {}", response.trim());
    }
    Ok(())
}

/// `sentinelctl whitelist`: view/update config whitelist.
async fn run_whitelist(action: WhitelistAction) -> anyhow::Result<()> {
    let config_path = Path::new("config/config.toml");
    let mut config = SentinelConfig::load_from_file(config_path).unwrap_or_default();

    match action {
        WhitelistAction::List => {
            println!("Whitelisted Binaries:");
            for b in &config.whitelist.binaries {
                println!("  • {}", b.display());
            }
        }
        WhitelistAction::Add { path } => {
            if !config.whitelist.binaries.contains(&path) {
                config.whitelist.binaries.push(path.clone());
                let content = toml::to_string_pretty(&config)?;
                tokio::fs::write(config_path, content).await?;
                println!("Added {} to whitelist in {}", path.display(), config_path.display());
            } else {
                println!("{} is already whitelisted.", path.display());
            }
        }
    }
    Ok(())
}
