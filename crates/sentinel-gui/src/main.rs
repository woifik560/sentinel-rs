#![allow(dead_code)]
//! sentinel-gui — Native Slint desktop UI for Sentinel-RS.
//!
//! Provides interactive incident alerts with process lineage breadcrumbs,
//! risk score gauges, X11 anti-clickjacking PIN confirmation, and
//! Fail-Closed countdown timers (< 30 MB RAM).

use std::path::PathBuf;
use std::sync::Arc;
use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader};
use tokio::net::UnixStream;
use tokio::sync::Mutex;
use tracing::{info, warn};

use sentinel_common::ipc::{IpcMessage, PromptAction, PromptRequest, PromptVerdict};

slint::slint! {
    import { Button, LineEdit } from "std-widgets.slint";

    export component IncidentPromptWindow inherits Window {
        in-out property <string> incident_id: "inc-000";
        in-out property <int> risk_score: 85;
        in-out property <string> lineage_text: "bash -> npm -> python3 (/tmp/install.py)";
        in-out property <string> secret_text: "~/.ssh/id_ed25519 (0.14s назад)";
        in-out property <string> target_text: "185.220.101.5:443 (Без DNS)";
        in-out property <string> reasons_text: "• Чтение SSH ключей\n• Скрипт из /tmp\n• Прямой IP";
        in-out property <int> remaining_seconds: 30;
        in-out property <bool> is_x11: false;
        in-out property <string> auth_pin_expected: "";
        in-out property <string> auth_pin_input: "";

        callback kill_clicked();
        callback deny_clicked();
        callback allow_once_clicked();
        callback allow_duration_clicked();
        callback allow_host_clicked();
        callback allow_scope_clicked();

        title: "Sentinel-RS — Инцидент Безопасности";
        min_width: 680px;
        min_height: 540px;

        VerticalLayout {
            padding: 24px;
            spacing: 12px;

            Text {
                text: "ПОДОЗРИТЕЛЬНАЯ АКТИВНОСТЬ (FREEZE & INSPECT)";
                font_size: 16px;
                font_weight: 700;
                color: #d32f2f;
            }

            if root.is_x11: Rectangle {
                background: #fff3cd;
                border_radius: 6px;
                border_width: 1px;
                border_color: #ffeeba;
                height: 48px;

                HorizontalLayout {
                    padding: 8px;
                    spacing: 12px;

                    Text {
                        text: "⚠️ X11 СЕССИЯ: Возможно фальшивое нажатие! Введите PIN [" + root.auth_pin_expected + "]:";
                        color: #856404;
                        font_weight: 600;
                        vertical_alignment: center;
                    }

                    LineEdit {
                        width: 100px;
                        text <=> root.auth_pin_input;
                        placeholder_text: "PIN";
                    }
                }
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
                spacing: 8px;

                Button {
                    text: "Убить (SIGKILL)";
                    clicked => { root.kill_clicked(); }
                }
                Button {
                    text: "Блок (TCP RST)";
                    clicked => { root.deny_clicked(); }
                }
                Button {
                    text: "Разрешить разово";
                    clicked => { root.allow_once_clicked(); }
                }
                Button {
                    text: "На 5 минут";
                    clicked => { root.allow_duration_clicked(); }
                }
                Button {
                    text: "Для хоста";
                    clicked => { root.allow_host_clicked(); }
                }
                Button {
                    text: "В Scope";
                    clicked => { root.allow_scope_clicked(); }
                }
            }
        }
    }
}

/// Detects if the current desktop session is running on X11 instead of Wayland.
fn detect_x11_session() -> bool {
    if std::env::var("WAYLAND_DISPLAY").is_ok() {
        return false;
    }
    if let Ok(session_type) = std::env::var("XDG_SESSION_TYPE") {
        if session_type.to_lowercase() == "x11" {
            return true;
        }
    }
    std::env::var("DISPLAY").is_ok()
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    tracing_subscriber::fmt::init();
    info!("Starting Sentinel-RS Desktop GUI (Slint UI)...");

    let is_x11 = detect_x11_session();
    if is_x11 {
        warn!("Running under X11 desktop environment. Synthetic input protection (one-time PIN) will be enforced.");
    }

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
    window.set_is_x11(is_x11);

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
        window.set_auth_pin_expected("7491".into());

        window.on_kill_clicked(|| info!("User clicked Kill in demo"));
        window.on_deny_clicked(|| info!("User clicked Deny in demo"));
        window.on_allow_once_clicked(|| info!("User clicked Allow Once in demo"));
        window.on_allow_duration_clicked(|| info!("User clicked Allow Duration in demo"));
        window.on_allow_host_clicked(|| info!("User clicked Allow Host in demo"));
        window.on_allow_scope_clicked(|| info!("User clicked Allow Scope in demo"));

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

    // Helper macro/closure for verdict submission
    let wire_action = |w_weak: slint::Weak<IncidentPromptWindow>, wr: Arc<Mutex<tokio::net::unix::OwnedWriteHalf>>, act_factory: Box<dyn Fn(&IncidentPromptWindow) -> PromptAction + Send + 'static>| {
        move || {
            if let Some(w) = w_weak.upgrade() {
                let id = w.get_incident_id().to_string();
                let pin = if w.get_is_x11() {
                    Some(w.get_auth_pin_input().to_string())
                } else {
                    None
                };
                let action = act_factory(&w);
                let wr = wr.clone();
                tokio::spawn(async move {
                    send_verdict(wr, id, action, pin).await;
                });
            }
        }
    };

    window.on_kill_clicked(wire_action(window_handle.clone(), writer_clone.clone(), Box::new(|_| PromptAction::Kill)));
    window.on_deny_clicked(wire_action(window_handle.clone(), writer_clone.clone(), Box::new(|_| PromptAction::DenyOnce)));
    window.on_allow_once_clicked(wire_action(window_handle.clone(), writer_clone.clone(), Box::new(|_| PromptAction::AllowOnce)));
    window.on_allow_duration_clicked(wire_action(window_handle.clone(), writer_clone.clone(), Box::new(|_| PromptAction::AllowForDuration { seconds: 300 })));
    window.on_allow_host_clicked(wire_action(window_handle.clone(), writer_clone.clone(), Box::new(|w| {
        let tgt = w.get_target_text().to_string();
        let host = tgt.split(':').next().unwrap_or("").trim().to_string();
        PromptAction::AllowHost { host }
    })));
    window.on_allow_scope_clicked(wire_action(window_handle.clone(), writer_clone.clone(), Box::new(|_| PromptAction::AllowAppScope)));

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

    w.set_is_x11(p.is_x11_session);
    if let Some(pin) = p.auth_pin {
        w.set_auth_pin_expected(pin.into());
    }
}

async fn send_verdict(
    writer: Arc<Mutex<tokio::net::unix::OwnedWriteHalf>>,
    incident_id: String,
    action: PromptAction,
    auth_pin: Option<String>,
) {
    let msg = IpcMessage::Verdict(PromptVerdict { incident_id, action, auth_pin });
    if let Ok(json) = serde_json::to_string(&msg) {
        let payload = json + "\n";
        let mut w = writer.lock().await;
        let _ = w.write_all(payload.as_bytes()).await;
    }
}
