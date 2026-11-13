#![allow(dead_code)]
//! sentinel-gui — Native Slint desktop UI for Sentinel-RS.
//!
//! Provides interactive incident alerts with process lineage breadcrumbs,
//! risk score gauges, and Fail-Closed countdown timers (< 30 MB RAM).

use std::path::PathBuf;
use std::sync::Arc;
use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader};
use tokio::net::UnixStream;
use tokio::sync::Mutex;
use tracing::{info, warn};

use sentinel_common::ipc::{IpcMessage, PromptAction, PromptRequest, PromptVerdict};

slint::slint! {
    import { Button } from "std-widgets.slint";

    export component IncidentPromptWindow inherits Window {
        in-out property <string> incident_id: "inc-000";
        in-out property <int> risk_score: 85;
        in-out property <string> lineage_text: "bash -> npm -> python3 (/tmp/install.py)";
        in-out property <string> secret_text: "~/.ssh/id_ed25519 (0.14s назад)";
        in-out property <string> target_text: "185.220.101.5:443 (Без DNS)";
        in-out property <string> reasons_text: "• Чтение SSH ключей\n• Скрипт из /tmp\n• Прямой IP";
        in-out property <int> remaining_seconds: 30;

        callback kill_clicked();
        callback deny_clicked();
        callback allow_once_clicked();
        callback allow_scope_clicked();

        title: "Sentinel-RS — Инцидент Безопасности";
        min_width: 620px;
        min_height: 480px;

        VerticalLayout {
            padding: 24px;
            spacing: 14px;

            Text {
                text: "ПОДОЗРИТЕЛЬНАЯ АКТИВНОСТЬ (FREEZE & INSPECT)";
                font_size: 16px;
                font_weight: 700;
                color: #d32f2f;
            }

            Rectangle {
                background: #f8f9fa;
                border_radius: 6px;
                border_width: 1px;
                border_color: #e9ecef;

                VerticalLayout {
                    padding: 12px;
                    spacing: 8px;

                    Text {
                        text: "Оценка риска: " + root.risk_score + " / 100 (" + (root.risk_score >= 75 ? "КРИТИЧЕСКИЙ" : "ПОДОЗРИТЕЛЬНЫЙ") + ")";
                        font_size: 14px;
                        font_weight: 700;
                        color: root.risk_score >= 75 ? #b71c1c : #e65100;
                    }
                    Text {
                        text: "Цепочка предков: " + root.lineage_text;
                        font_size: 13px;
                    }
                    Text {
                        text: "Секрет: " + root.secret_text;
                        font_size: 13px;
                    }
                    Text {
                        text: "Назначение: " + root.target_text;
                        font_size: 13px;
                    }
                }
            }

            Text {
                text: "Сработавшие правила детерминированного анализа:";
                font_size: 13px;
                font_weight: 600;
            }

            Rectangle {
                background: #fdfdfe;
                border_radius: 4px;
                border_width: 1px;
                border_color: #dee2e6;

                VerticalLayout {
                    padding: 10px;
                    Text {
                        text: root.reasons_text;
                        font_size: 12px;
                    }
                }
            }

            Text {
                text: "Автоматическая блокировка (Fail-Closed) через " + root.remaining_seconds + " сек...";
                color: #6c757d;
                font_size: 12px;
            }

            HorizontalLayout {
                spacing: 12px;

                Button {
                    text: "Убить (SIGKILL)";
                    clicked => { root.kill_clicked(); }
                }
                Button {
                    text: "Блокировать";
                    clicked => { root.deny_clicked(); }
                }
                Button {
                    text: "Разрешить разово";
                    clicked => { root.allow_once_clicked(); }
                }
                Button {
                    text: "Добавить в Scope";
                    clicked => { root.allow_scope_clicked(); }
                }
            }
        }
    }
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    tracing_subscriber::fmt::init();
    info!("Starting Sentinel-RS Desktop GUI (Slint UI)...");

    let args: Vec<String> = std::env::args().collect();
    if args.iter().any(|a| a == "--help" || a == "-h") {
        println!("Sentinel-RS Desktop GUI Alert Dialog");
        println!("\nUsage: sentinel-gui [OPTIONS]");
        println!("\nOptions:");
        println!("  --demo       Display mock incident alert for preview and testing");
        println!("  -s, --socket Path to sentinel.sock [default: /run/sentinel/sentinel.sock]");
        println!("  -h, --help   Print help");
        return Ok(());
    }

    let is_demo = args.iter().any(|a| a == "--demo");
    let mut socket_path = PathBuf::from("/run/sentinel/sentinel.sock");
    if let Some(pos) = args.iter().position(|a| a == "-s" || a == "--socket") {
        if let Some(val) = args.get(pos + 1) {
            socket_path = PathBuf::from(val);
        }
    }

    let window = IncidentPromptWindow::new()?;

    if is_demo {
        info!("Running in GUI demo mode");
        window.set_incident_id("demo-8842".into());
        window.set_risk_score(85);
        window.set_lineage_text("bash (PID 1204) -> npm (PID 1420) -> python3 (/tmp/install.py)".into());
        window.set_secret_text("~/.ssh/id_ed25519 (0.14s назад)".into());
        window.set_target_text("185.220.101.5:443 (Без DNS)".into());
        window.set_reasons_text(
            "• Доступ к SSH-ключам неуполномоченным процессом (+40)\n• Скрипт запущен из /tmp (+25)\n• Попытка эксфильтрации в течение 5 секунд (+15)\n• Прямое подключение по IP-адресу (+10)".into()
        );

        window.on_kill_clicked(|| {
            info!("User clicked Kill in demo");
        });
        window.on_deny_clicked(|| {
            info!("User clicked Deny in demo");
        });
        window.on_allow_once_clicked(|| {
            info!("User clicked Allow Once in demo");
        });
        window.on_allow_scope_clicked(|| {
            info!("User clicked Allow Scope in demo");
        });

        window.run()?;
        return Ok(());
    }

    // Connect to Unix Domain Socket
    let stream = match UnixStream::connect(&socket_path).await {
        Ok(s) => s,
        Err(e) => {
            warn!(
                "Could not connect to sentineld at {}: {}. Launching demo window.",
                socket_path.display(),
                e
            );
            window.run()?;
            return Ok(());
        }
    };

    let (reader, writer) = stream.into_split();
    let writer = Arc::new(Mutex::new(writer));
    let mut reader = BufReader::new(reader);

    let window_handle = window.as_weak();
    let writer_clone = writer.clone();

    // Wire action callbacks
    let w_kill = window_handle.clone();
    let wr_kill = writer_clone.clone();
    window.on_kill_clicked(move || {
        if let Some(w) = w_kill.upgrade() {
            let id = w.get_incident_id().to_string();
            let wr = wr_kill.clone();
            tokio::spawn(async move {
                send_verdict(wr, id, PromptAction::Kill).await;
            });
        }
    });

    let w_deny = window_handle.clone();
    let wr_deny = writer_clone.clone();
    window.on_deny_clicked(move || {
        if let Some(w) = w_deny.upgrade() {
            let id = w.get_incident_id().to_string();
            let wr = wr_deny.clone();
            tokio::spawn(async move {
                send_verdict(wr, id, PromptAction::DenyOnce).await;
            });
        }
    });

    let w_allow = window_handle.clone();
    let wr_allow = writer_clone.clone();
    window.on_allow_once_clicked(move || {
        if let Some(w) = w_allow.upgrade() {
            let id = w.get_incident_id().to_string();
            let wr = wr_allow.clone();
            tokio::spawn(async move {
                send_verdict(wr, id, PromptAction::AllowOnce).await;
            });
        }
    });

    let w_scope = window_handle.clone();
    let wr_scope = writer_clone.clone();
    window.on_allow_scope_clicked(move || {
        if let Some(w) = w_scope.upgrade() {
            let id = w.get_incident_id().to_string();
            let wr = wr_scope.clone();
            tokio::spawn(async move {
                send_verdict(wr, id, PromptAction::AllowAppScope).await;
            });
        }
    });

    // Background task to read incoming prompt requests from sentineld
    let w_incoming = window_handle.clone();
    tokio::spawn(async move {
        let mut line = String::new();
        while reader.read_line(&mut line).await.unwrap_or(0) > 0 {
            let trimmed = line.trim();
            if let Ok(IpcMessage::Prompt(prompt)) = serde_json::from_str::<IpcMessage>(trimmed) {
                let weak = w_incoming.clone();
                let _ = slint::invoke_from_event_loop(move || {
                    if let Some(w) = weak.upgrade() {
                        populate_prompt(&w, prompt);
                    }
                });
            }
            line.clear();
        }
    });

    window.run()?;
    Ok(())
}

/// Sanitize untrusted input strings to prevent UI injection, ANSI control spoofing, or script injection.
fn sanitize_display_string(input: &str) -> String {
    input
        .chars()
        .filter(|c| !c.is_control() || *c == '\n' || *c == '\t')
        .take(512)
        .collect()
}

fn populate_prompt(w: &IncidentPromptWindow, p: PromptRequest) {
    let clean_incident_id = sanitize_display_string(&p.incident_id);
    w.set_incident_id(clean_incident_id.into());
    w.set_risk_score((p.risk_score as i32).clamp(0, 100));

    let lineage_str = p
        .lineage
        .iter()
        .map(|s| sanitize_display_string(&s.to_string()))
        .collect::<Vec<_>>()
        .join(" -> ");
    w.set_lineage_text(lineage_str.into());

    if let Some(sec) = p.secret_path {
        let clean_sec = sanitize_display_string(&sec);
        let delta = p
            .time_delta_ms
            .map(|ms| format!(" ({:.2}s назад)", ms as f64 / 1000.0))
            .unwrap_or_default();
        w.set_secret_text(format!("{}{}", clean_sec, delta).into());
    }

    if let Some(ip) = p.dest_ip {
        let clean_ip = sanitize_display_string(&ip);
        let port_str = p.dest_port.map(|port| format!(":{}", port)).unwrap_or_default();
        w.set_target_text(format!("{}{}", clean_ip, port_str).into());
    }

    let reasons = p
        .reasons
        .iter()
        .map(|r| format!("• {}", sanitize_display_string(r)))
        .collect::<Vec<_>>()
        .join("\n");
    w.set_reasons_text(reasons.into());
}

async fn send_verdict(
    writer: Arc<Mutex<tokio::net::unix::OwnedWriteHalf>>,
    incident_id: String,
    action: PromptAction,
) {
    let msg = IpcMessage::Verdict(PromptVerdict { incident_id, action });
    if let Ok(json) = serde_json::to_string(&msg) {
        let payload = json + "\n";
        let mut w = writer.lock().await;
        let _ = w.write_all(payload.as_bytes()).await;
    }
}
