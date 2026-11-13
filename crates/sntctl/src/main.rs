//! sntctl — Command-line interface client for Sentinel-RS.
//!
//! Provides interactive watch mode, live event monitoring, process unfreezing,
//! forensic report export, and whitelist management over Unix domain IPC.
//! Renamed from sentinelctl to avoid namespace conflict with SentinelOne.

use clap::{Parser, Subcommand};
use std::io::{self, Write};
use std::path::{Path, PathBuf};
use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader};
use tokio::net::UnixStream;

use sentinel_common::config::SentinelConfig;
use sentinel_common::ipc::{IpcMessage, PromptAction, PromptRequest, PromptVerdict};

const DEFAULT_PRIVILEGED_SOCKET: &str = "/run/sentinel/sentinel.sock";
const DEFAULT_READONLY_SOCKET: &str = "/run/sentinel/sentinel-ro.sock";

#[derive(Parser, Debug)]
#[command(name = "sntctl", author = "woifik560", version = "0.2.0")]
#[command(about = "CLI management and triage tool for Sentinel-RS firewall")]
struct Cli {
    /// Path to Sentinel Unix Domain Socket (defaults to /run/sentinel/sentinel-ro.sock for read-only, sentinel.sock for privileged)
    #[arg(short, long)]
    socket: Option<PathBuf>,

    #[command(subcommand)]
    command: Commands,
}

#[derive(Subcommand, Debug)]
enum Commands {
    /// Interactive real-time prompt triage (for SSH and terminals) [Requires Root]
    Watch,

    /// Live stream of firewall events and security accesses [Read-Only]
    Monitor,

    /// Unfreeze a mistakenly blocked process TGID [Requires Root]
    Unfreeze {
        /// Process Thread Group ID (PID)
        tgid: u32,
    },

    /// Query daemon status and statistics [Read-Only]
    Status,

    /// Export forensic incident report in JSON format [Read-Only]
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
        Commands::Watch => {
            let sock = cli.socket.unwrap_or_else(|| PathBuf::from(DEFAULT_PRIVILEGED_SOCKET));
            run_watch(&sock).await?
        }
        Commands::Monitor => {
            let sock = cli.socket.unwrap_or_else(|| PathBuf::from(DEFAULT_READONLY_SOCKET));
            run_monitor(&sock).await?
        }
        Commands::Unfreeze { tgid } => {
            let sock = cli.socket.unwrap_or_else(|| PathBuf::from(DEFAULT_PRIVILEGED_SOCKET));
            run_unfreeze(&sock, tgid).await?
        }
        Commands::Status => {
            let sock = cli.socket.unwrap_or_else(|| PathBuf::from(DEFAULT_READONLY_SOCKET));
            run_status(&sock).await?
        }
        Commands::Export { incident_id, format: _ } => {
            let sock = cli.socket.unwrap_or_else(|| PathBuf::from(DEFAULT_READONLY_SOCKET));
            run_export(&sock, incident_id).await?
        }
        Commands::Whitelist { action } => run_whitelist(action).await?,
    }

    Ok(())
}

/// Connects to sentineld socket with fallback error guidance.
async fn connect_socket(socket_path: &Path) -> anyhow::Result<UnixStream> {
    UnixStream::connect(socket_path).await.map_err(|e| {
        anyhow::anyhow!(
            "Failed to connect to sentineld IPC socket at {}: {}\nIs 'sentineld' running? For management commands (watch/unfreeze), ensure you have root/sudo privileges.",
            socket_path.display(),
            e
        )
    })
}

/// `sntctl watch`: interactive prompt loop for triage.
async fn run_watch(socket_path: &Path) -> anyhow::Result<()> {
    println!("Connecting to Sentinel-RS daemon at {}...", socket_path.display());
    let stream = connect_socket(socket_path).await?;
    let (reader, mut writer) = stream.into_split();
    let mut reader = BufReader::new(reader);

    println!("================================================================================");
    println!(" Sentinel-RS Interactive Watch Mode (Terminal Freeze & Inspect)");
    println!(" Connected to privileged management socket: {}", socket_path.display());
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

            let (action, auth_pin) = prompt_user_action(&prompt);
            let verdict = PromptVerdict {
                incident_id: prompt.incident_id,
                action,
                auth_pin,
            };

            let msg = IpcMessage::Verdict(verdict);
            let payload = serde_json::to_string(&msg)? + "\n";
            writer.write_all(payload.as_bytes()).await?;
            println!("Verdict submitted successfully.\n");
        } else if let Ok(IpcMessage::AuthError(err)) = serde_json::from_str::<IpcMessage>(trimmed) {
            eprintln!("Authentication error from daemon: {}", err);
            break;
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

    if p.is_x11_session {
        println!("\n[ПРЕДУПРЕЖДЕНИЕ БЕЗОПАСНОСТИ: X11 СЕССИЯ]");
        println!("Обнаружена среда X11, подверженная инъекции синтетических кликов.");
        if let Some(ref pin) = p.auth_pin {
            println!("Для подтверждения чувствительного вердикта потребуется ввести разовый PIN: {}", pin);
        }
    }
    println!("================================================================================");
}

fn prompt_user_action(p: &PromptRequest) -> (PromptAction, Option<String>) {
    let host_target = p.dest_domain.clone().or_else(|| p.dest_ip.clone()).unwrap_or_else(|| "current-target".into());

    loop {
        println!("Выберите действие:");
        println!("  [1] Убить процесс (SIGKILL)");
        println!("  [2] Заблокировать разово (DenyOnce / TCP RST)");
        println!("  [3] Разрешить разово (AllowOnce)");
        println!("  [4] Разрешить на 5 минут (AllowForDuration 300s)");
        println!("  [5] Разрешить только для хоста {} (AllowHost)", host_target);
        println!("  [6] Разрешить для этого экземпляра процесса (AllowProcess)");
        println!("  [7] Добавить в постоянный App Scope whitelist");
        print!("Ваш выбор [1-7]: ");
        io::stdout().flush().unwrap();

        let mut input = String::new();
        if io::stdin().read_line(&mut input).is_ok() {
            let action = match input.trim() {
                "1" => PromptAction::Kill,
                "2" => PromptAction::DenyOnce,
                "3" => PromptAction::AllowOnce,
                "4" => PromptAction::AllowForDuration { seconds: 300 },
                "5" => PromptAction::AllowHost { host: host_target.clone() },
                "6" => PromptAction::AllowProcess,
                "7" => PromptAction::AllowAppScope,
                _ => {
                    println!("Неверный ввод, введите число от 1 до 7.");
                    continue;
                }
            };

            let mut entered_pin = None;
            if p.is_x11_session && p.auth_pin.is_some() {
                loop {
                    print!("Введите 4-значный PIN подтверждения X11: ");
                    io::stdout().flush().unwrap();
                    let mut pin_input = String::new();
                    if io::stdin().read_line(&mut pin_input).is_ok() {
                        entered_pin = Some(pin_input.trim().to_string());
                        break;
                    }
                }
            }

            return (action, entered_pin);
        }
    }
}

/// `sntctl monitor`: live streaming log of events.
async fn run_monitor(socket_path: &Path) -> anyhow::Result<()> {
    let stream = connect_socket(socket_path).await?;
    let (reader, mut writer) = stream.into_split();
    let mut reader = BufReader::new(reader);

    // Send subscribe message
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
                    println!("[PROMPT] Incident {} (Risk: {}/100)", p.incident_id, p.risk_score);
                }
                _ => {}
            }
        }
        line.clear();
    }
    Ok(())
}

/// `sntctl unfreeze <tgid>`: unfreeze process.
async fn run_unfreeze(socket_path: &Path, tgid: u32) -> anyhow::Result<()> {
    let stream = connect_socket(socket_path).await?;
    let (_, mut writer) = stream.into_split();

    let msg = IpcMessage::Unfreeze { tgid };
    let payload = serde_json::to_string(&msg)? + "\n";
    writer.write_all(payload.as_bytes()).await?;
    println!("Unfreeze request sent for TGID {}", tgid);
    Ok(())
}

/// `sntctl status`: query daemon status.
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
        println!("Sentinel-RS Daemon Status (from {}):", socket_path.display());
        println!("  Uptime:             {} seconds", uptime_secs);
        println!("  Tracked Processes:  {}", tracked_processes);
        println!("  Total Incidents:    {}", total_incidents);
        println!("  Frozen Processes:   {}", frozen_count);
    } else {
        println!("Received response: {}", response.trim());
    }
    Ok(())
}

/// `sntctl export <incident_id>`: export forensic report.
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

/// `sntctl whitelist`: view/update config whitelist.
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
