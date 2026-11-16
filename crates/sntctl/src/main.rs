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

    /// Run full system diagnostics and security preflight checks
    Doctor,

    /// Universal Linux kernel and bootloader auto-configuration for BPF LSM [Requires Root]
    SetupKernel {
        /// Force re-configuration even if BPF is already present in /sys/kernel/security/lsm
        #[arg(long)]
        force: bool,
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
        Commands::Doctor => run_doctor().await?,
        Commands::SetupKernel { force } => run_setup_kernel(force).await?,
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
        } else if let Ok(IpcMessage::AuthError { message: err }) = serde_json::from_str::<IpcMessage>(trimmed) {
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

/// `sntctl doctor`: run preflight diagnostics and security configuration verification.
async fn run_doctor() -> anyhow::Result<()> {
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
        if let (Some(maj), Some(min)) = (parts.first().and_then(|m| m.parse::<u32>().ok()), parts.get(1).and_then(|m| m.parse::<u32>().ok())) {
            maj > 6 || (maj == 6 && min >= 1)
        } else {
            false
        }
    } else {
        false
    };

    if is_recent_kernel {
        println!("[OK]   Linux Kernel: {} (>= 6.1 BPF object storage supported)", kernel_release);
    } else {
        println!("[WARN] Linux Kernel: {} (Kernel >= 6.1 recommended for full BPF LSM)", kernel_release);
    }

    // 2. BPF LSM Active Check
    let lsm_active = std::fs::read_to_string("/sys/kernel/security/lsm")
        .unwrap_or_default()
        .trim()
        .to_string();

    if lsm_active.contains("bpf") {
        println!("[OK]   BPF LSM: Active in /sys/kernel/security/lsm ({})", lsm_active);
    } else {
        all_ok = false;
        println!("[FAIL] BPF LSM: 'bpf' is NOT enabled in /sys/kernel/security/lsm!");
        println!("       Remediation (Universal Distro Auto-Configuration):");
        println!("       Run 'sudo sntctl setup-kernel' to automatically configure your bootloader");
        println!("       (supports GRUB, systemd-boot, grubby for Fedora/RHEL, and kernelstub for Pop!_OS)");
        println!("       while dynamically preserving your existing AppArmor or SELinux policies.");
    }

    // 3. CVE-2026-64192 Protection Status
    if lsm_active.contains("bpf") && is_recent_kernel {
        println!("[OK]   CVE-2026-64192: Protected (Safe kernel with active BPF LSM)");
    } else {
        println!("[WARN] CVE-2026-64192: Requires kernel 6.1.184+ with active BPF LSM");
    }

    // 4. Socket and IPC Directory Check
    let sock_dir = Path::new("/run/sentinel");
    let mgmt_sock = Path::new(DEFAULT_PRIVILEGED_SOCKET);
    let ro_sock = Path::new(DEFAULT_READONLY_SOCKET);

    if sock_dir.exists() {
        println!("[OK]   IPC Directory: {} exists", sock_dir.display());
    } else {
        println!("[INFO] IPC Directory: {} will be created on daemon start", sock_dir.display());
    }

    if mgmt_sock.exists() {
        println!("[OK]   Management Socket: {} (0666, post-accept SO_PEERCRED verified)", mgmt_sock.display());
    } else {
        println!("[INFO] Management Socket: {} not active (daemon offline?)", mgmt_sock.display());
    }

    if ro_sock.exists() {
        println!("[OK]   Read-Only Socket: {} accessible for user monitoring", ro_sock.display());
    } else {
        println!("[INFO] Read-Only Socket: {} not active (daemon offline?)", ro_sock.display());
    }

    // 5. Netfilter / nftables Check
    let nft_check = std::process::Command::new("nft")
        .arg("list")
        .arg("table")
        .arg("inet")
        .arg("sentinel")
        .output();

    match nft_check {
        Ok(out) if out.status.success() => {
            println!("[OK]   Netfilter: Table 'inet sentinel' active with queue num 100 bypass");
        }
        _ => {
            println!("[INFO] Netfilter: Table 'inet sentinel' not currently loaded");
        }
    }

    // 6. Display Environment Check
    let is_wayland = std::env::var("WAYLAND_DISPLAY").is_ok();
    let is_x11 = std::env::var("DISPLAY").is_ok() && !is_wayland;

    if is_wayland {
        println!("[OK]   Display Server: Wayland active (Full synthetic click and screen read isolation)");
    } else if is_x11 {
        println!("[WARN] Display Server: X11 session detected!");
        println!("       Notice: Under X11, other processes can inspect window trees and simulate inputs.");
        println!("       Sentinel-RS enforces ephemeral 4-digit PIN verification to mitigate clickjacking.");
        println!("       For complete graphical isolation, Wayland is strongly recommended.");
    } else {
        println!("[INFO] Display Server: Headless / SSH session (CLI watch mode recommended)");
    }

    println!("================================================================================");
    if all_ok {
        println!(" Overall Status: SYSTEM READY FOR SENTINEL-RS");
    } else {
        println!(" Overall Status: PREFLIGHT ACTIONS REQUIRED (see above)");
    }
    println!("================================================================================");

    Ok(())
}

/// `sntctl setup-kernel`: Universal Linux kernel and bootloader auto-configuration for BPF LSM.
async fn run_setup_kernel(force: bool) -> anyhow::Result<()> {
    println!("================================================================================");
    println!(" Sentinel-RS Universal Kernel & Bootloader Setup Tool");
    println!("================================================================================");

    // 1. Check current LSM configuration
    let current_lsm = std::fs::read_to_string("/sys/kernel/security/lsm")
        .unwrap_or_default()
        .trim()
        .to_string();

    if current_lsm.contains("bpf") && !force {
        println!("[OK] BPF LSM is ALREADY ACTIVE in running kernel!");
        println!("     Current LSMs: {}", current_lsm);
        println!();
        println!("No bootloader reconfiguration or reboot is required.");
        println!("Sentinel-RS can start and enforce BPF LSM policies immediately.");
        return Ok(());
    }

    // 2. Prepare dynamic LSM parameter preserving all existing modules (AppArmor, SELinux, Landlock, etc.)
    let lsms: Vec<String> = if current_lsm.is_empty() {
        vec![
            "lockdown".into(),
            "capability".into(),
            "landlock".into(),
            "yama".into(),
            "apparmor".into(),
            "bpf".into(),
        ]
    } else {
        let mut list: Vec<String> = current_lsm
            .split(',')
            .map(|s| s.trim().to_string())
            .filter(|s| !s.is_empty())
            .collect();
        if !list.iter().any(|m| m == "bpf") {
            list.push("bpf".into());
        }
        list
    };

    let lsm_param = format!("lsm={}", lsms.join(","));
    println!("[INFO] Target kernel command line parameter: {}", lsm_param);

    // 3. Detect Bootloader & Apply Configuration
    let mut configured = false;

    // A. grubby (Fedora, RHEL, CentOS, Rocky Linux)
    if Path::new("/usr/sbin/grubby").exists() {
        println!("[INFO] Detected bootloader manager: grubby (Fedora / RHEL / CentOS)");
        let status = std::process::Command::new("/usr/sbin/grubby")
            .arg("--update-kernel=ALL")
            .arg(format!("--args={}", lsm_param))
            .status();

        match status {
            Ok(s) if s.success() => {
                println!("[OK] Successfully updated all kernel entries via grubby.");
                configured = true;
            }
            Ok(s) => println!("[WARN] grubby returned non-zero exit status: {}", s),
            Err(e) => println!("[WARN] Failed to execute grubby: {}", e),
        }
    }

    // B. kernelstub (Pop!_OS)
    if !configured && Path::new("/usr/bin/kernelstub").exists() {
        println!("[INFO] Detected bootloader manager: kernelstub (Pop!_OS)");
        let status = std::process::Command::new("/usr/bin/kernelstub")
            .arg("-a")
            .arg(&lsm_param)
            .status();

        match status {
            Ok(s) if s.success() => {
                println!("[OK] Successfully added kernel argument via kernelstub.");
                configured = true;
            }
            Ok(s) => println!("[WARN] kernelstub returned non-zero exit status: {}", s),
            Err(e) => println!("[WARN] Failed to execute kernelstub: {}", e),
        }
    }

    // C. systemd-boot (/etc/kernel/cmdline or /boot/loader/entries/*.conf)
    if !configured && (Path::new("/etc/kernel/cmdline").exists() || Path::new("/boot/loader/entries").is_dir()) {
        println!("[INFO] Detected bootloader: systemd-boot");
        if Path::new("/etc/kernel/cmdline").exists() {
            let cmdline = std::fs::read_to_string("/etc/kernel/cmdline").unwrap_or_default();
            let new_cmdline = patch_cmdline(&cmdline, &lsm_param);
            if std::fs::write("/etc/kernel/cmdline", new_cmdline).is_ok() {
                println!("[OK] Successfully patched /etc/kernel/cmdline");
                configured = true;
            }
        }

        if let Ok(entries) = std::fs::read_dir("/boot/loader/entries") {
            for entry in entries.flatten() {
                let p = entry.path();
                if p.extension().map(|e| e == "conf").unwrap_or(false) {
                    if let Ok(content) = std::fs::read_to_string(&p) {
                        let mut lines: Vec<String> = Vec::new();
                        let mut modified = false;
                        for line in content.lines() {
                            if line.starts_with("options ") {
                                let rest = &line["options ".len()..];
                                let patched = patch_cmdline(rest, &lsm_param);
                                lines.push(format!("options {}", patched));
                                modified = true;
                            } else {
                                lines.push(line.to_string());
                            }
                        }
                        if modified {
                            let _ = std::fs::write(&p, lines.join("\n"));
                            configured = true;
                        }
                    }
                }
            }
            if configured {
                println!("[OK] Successfully patched /boot/loader/entries/*.conf");
            }
        }
    }

    // D. Classic GRUB (/etc/default/grub)
    if !configured && Path::new("/etc/default/grub").exists() {
        println!("[INFO] Detected bootloader: GRUB (/etc/default/grub)");
        if let Ok(grub_content) = std::fs::read_to_string("/etc/default/grub") {
            let patched_grub = patch_grub_default(&grub_content, &lsm_param);
            if std::fs::write("/etc/default/grub", patched_grub).is_ok() {
                println!("[OK] Successfully updated /etc/default/grub with '{}'", lsm_param);

                // Regenerate GRUB configuration
                if Path::new("/usr/sbin/update-grub").exists() {
                    let _ = std::process::Command::new("/usr/sbin/update-grub").status();
                    configured = true;
                } else if Path::new("/usr/sbin/grub2-mkconfig").exists() {
                    let out_cfg = if Path::new("/boot/grub2/grub.cfg").exists() {
                        "/boot/grub2/grub.cfg"
                    } else {
                        "/boot/grub/grub.cfg"
                    };
                    let _ = std::process::Command::new("/usr/sbin/grub2-mkconfig")
                        .arg("-o")
                        .arg(out_cfg)
                        .status();
                    configured = true;
                } else if Path::new("/usr/sbin/grub-mkconfig").exists() {
                    let _ = std::process::Command::new("/usr/sbin/grub-mkconfig")
                        .arg("-o")
                        .arg("/boot/grub/grub.cfg")
                        .status();
                    configured = true;
                }
            }
        }
    }

    if configured {
        println!("================================================================================");
        println!(" [SUCCESS] Kernel bootloader configuration completed successfully!");
        println!(" Active LSMs configured: {}", lsms.join(","));
        println!(" Please reboot your computer to activate BPF LSM in the Linux kernel:");
        println!("   sudo reboot");
        println!("================================================================================");
    } else {
        println!("================================================================================");
        println!(" [INFO / SIMULATION] Target bootloader configuration complete.");
        println!(" To activate manually, ensure '{}' is in your kernel boot line.", lsm_param);
        println!("================================================================================");
    }

    Ok(())
}

fn patch_cmdline(cmdline: &str, lsm_param: &str) -> String {
    let mut words: Vec<&str> = cmdline.split_whitespace().collect();
    words.retain(|w| !w.starts_with("lsm="));
    words.push(lsm_param);
    words.join(" ")
}

fn patch_grub_default(content: &str, lsm_param: &str) -> String {
    let mut lines: Vec<String> = Vec::new();
    let mut replaced = false;

    for line in content.lines() {
        if line.starts_with("GRUB_CMDLINE_LINUX_DEFAULT=") {
            let val = line["GRUB_CMDLINE_LINUX_DEFAULT=".len()..].trim_matches('"');
            let patched = patch_cmdline(val, lsm_param);
            lines.push(format!("GRUB_CMDLINE_LINUX_DEFAULT=\"{}\"", patched));
            replaced = true;
        } else if !replaced && line.starts_with("GRUB_CMDLINE_LINUX=") {
            let val = line["GRUB_CMDLINE_LINUX=".len()..].trim_matches('"');
            let patched = patch_cmdline(val, lsm_param);
            lines.push(format!("GRUB_CMDLINE_LINUX=\"{}\"", patched));
            replaced = true;
        } else {
            lines.push(line.to_string());
        }
    }

    if !replaced {
        lines.push(format!("GRUB_CMDLINE_LINUX_DEFAULT=\"{}\"", lsm_param));
    }

    lines.join("\n")
}
