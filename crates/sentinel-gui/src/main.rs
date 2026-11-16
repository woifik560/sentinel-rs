#![allow(dead_code)]
//! sentinel-gui — Minimalist Dark Desktop UI for Sentinel-RS.
//!
//! Provides an ultra-minimalist dark dashboard in idle mode and clean,
//! human-readable incident alert cards during active security freezes.

use std::path::PathBuf;
use std::sync::Arc;
use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader};
use tokio::net::unix::OwnedWriteHalf;
use tokio::net::UnixStream;
use tokio::sync::Mutex;
use tracing::{info, warn};

use sentinel_common::ipc::{IpcMessage, PromptAction, PromptVerdict};

slint::slint! {
    component StatusPill inherits Rectangle {
        in property <string> text;
        in property <color> dot_color: #10b981;
        in property <color> pill_bg: #141820;
        in property <color> border_col: #1e2432;

        background: root.pill_bg;
        border_radius: 14px;
        border_width: 1px;
        border_color: root.border_col;
        height: 28px;

        HorizontalLayout {
            padding_left: 12px;
            padding_right: 12px;
            spacing: 8px;
            alignment: center;

            Rectangle {
                width: 7px;
                height: 7px;
                border_radius: 3.5px;
                background: root.dot_color;
                y: (parent.height - self.height) / 2;
            }

            Text {
                text: root.text;
                color: #e2e8f0;
                font_size: 11px;
                font_weight: 600;
                vertical_alignment: center;
            }
        }
    }

    component MetricCard inherits Rectangle {
        in property <string> label;
        in property <string> val;
        in property <color> val_color: #f8fafc;

        background: #141820;
        border_radius: 10px;
        border_width: 1px;
        border_color: #1e2533;
        padding: 12px;

        VerticalLayout {
            spacing: 4px;
            alignment: center;

            Text {
                text: root.label;
                color: #64748b;
                font_size: 11px;
                font_weight: 500;
                horizontal_alignment: center;
            }
            Text {
                text: root.val;
                color: root.val_color;
                font_size: 14px;
                font_weight: 700;
                horizontal_alignment: center;
            }
        }
    }

    component ActionButton inherits Rectangle {
        in property <string> text;
        in property <color> bg_color: #dc2626;
        in property <color> hover_color: #ef4444;
        in property <color> text_color: #ffffff;
        in property <length> font_size: 13px;
        in property <int> font_weight: 600;
        callback clicked();

        border_radius: 8px;
        background: ta.has-hover ? root.hover_color : root.bg_color;
        animate background { duration: 120ms; }

        ta := TouchArea {
            clicked => { root.clicked(); }
            mouse_cursor: pointer;
        }

        Text {
            text: root.text;
            color: root.text_color;
            font_size: root.font_size;
            font_weight: root.font_weight;
            horizontal_alignment: center;
            vertical_alignment: center;
        }
    }

    export component MainWindow inherits Window {
        title: "Sentinel-RS";
        min_width: 620px;
        min_height: 460px;
        background: #0d0f14;

        in-out property <bool> is_connected: true;
        in-out property <bool> has_incident: false;

        // Idle properties
        in-out property <string> lsm_status: "LSM: Активен";
        in-out property <string> tracked_count_text: "142 процесса";
        in-out property <string> threat_count_text: "0 угроз";
        in-out property <string> last_event_text: "Все сетевые вызовы контролируются ядром Linux";

        // Incident properties
        in-out property <string> incident_id: "";
        in-out property <string> process_name: "curl";
        in-out property <string> process_pid: "1420";
        in-out property <string> process_path: "/usr/bin/curl";
        in-out property <string> target_address: "185.220.101.5:443";
        in-out property <string> reasons_text: "Прямое подключение по IP • Нестандартный порт";
        in-out property <int> risk_score: 75;
        in-out property <int> countdown_seconds: 30;

        callback block_clicked();
        callback allow_clicked();
        callback kill_clicked();
        callback reconnect_clicked();
        callback test_alert_clicked();

        VerticalLayout {
            padding: 24px;
            spacing: 16px;

            // Top bar
            HorizontalLayout {
                alignment: space_between;
                VerticalLayout {
                    spacing: 2px;
                    alignment: center;
                    Text {
                        text: "SENTINEL-RS";
                        font_size: 15px;
                        font_weight: 800;
                        color: #ffffff;
                    }
                    Text {
                        text: "Автономный BPF LSM фаервол";
                        font_size: 11px;
                        color: #64748b;
                    }
                }

                StatusPill {
                    text: root.is_connected ? "Защита активна" : "Служба отключена";
                    dot_color: root.is_connected ? #10b981 : #ef4444;
                    pill_bg: root.is_connected ? #0d281e : #281114;
                    border_col: root.is_connected ? #134e38 : #4a191e;
                }
            }

            // Central view: IDLE
            if !root.has_incident : VerticalLayout {
                spacing: 16px;

                if root.is_connected : Rectangle {
                    background: #141820;
                    border_radius: 12px;
                    border_width: 1px;
                    border_color: #1e2533;
                    height: 180px;

                    VerticalLayout {
                        alignment: center;
                        spacing: 10px;

                        Rectangle {
                            width: 52px;
                            height: 52px;
                            border_radius: 26px;
                            background: #064e3b;
                            border_width: 1px;
                            border_color: #059669;

                            Text {
                                text: "✓";
                                color: #34d399;
                                font_size: 24px;
                                font_weight: 700;
                                horizontal_alignment: center;
                                vertical_alignment: center;
                            }
                        }

                        Text {
                            text: "Система в безопасности";
                            font_size: 17px;
                            font_weight: 700;
                            color: #f8fafc;
                            horizontal_alignment: center;
                        }

                        Text {
                            text: "Сетевые вызовы и процессы контролируются ядром. Угроз не обнаружено.";
                            font_size: 12px;
                            color: #94a3b8;
                            horizontal_alignment: center;
                        }
                    }
                }

                if !root.is_connected : Rectangle {
                    background: #181416;
                    border_radius: 12px;
                    border_width: 1px;
                    border_color: #381a1e;
                    height: 180px;

                    VerticalLayout {
                        alignment: center;
                        spacing: 12px;

                        Text {
                            text: "Служба sentineld не подключена";
                            font_size: 16px;
                            font_weight: 700;
                            color: #fca5a5;
                            horizontal_alignment: center;
                        }

                        Text {
                            text: "Запустите демон в терминале: sudo systemctl start sentineld";
                            font_size: 12px;
                            color: #94a3b8;
                            horizontal_alignment: center;
                        }

                        HorizontalLayout {
                            alignment: center;
                            ActionButton {
                                width: 200px;
                                height: 38px;
                                text: "Повторить подключение";
                                bg_color: #1e2533;
                                hover_color: #2b3548;
                                text_color: #e2e8f0;
                                clicked => { root.reconnect_clicked(); }
                            }
                        }
                    }
                }

                // Stats row
                HorizontalLayout {
                    spacing: 12px;
                    height: 70px;

                    MetricCard {
                        label: "ЯДРО EBPF";
                        val: root.lsm_status;
                        val_color: #10b981;
                    }
                    MetricCard {
                        label: "МОНИТОРИНГ";
                        val: root.tracked_count_text;
                        val_color: #38bdf8;
                    }
                    MetricCard {
                        label: "БЛОКИРОВКИ";
                        val: root.threat_count_text;
                        val_color: #a78bfa;
                    }
                }

                // Footer
                HorizontalLayout {
                    alignment: space_between;
                    Text {
                        text: root.last_event_text;
                        font_size: 11px;
                        color: #64748b;
                        vertical_alignment: center;
                    }
                    ActionButton {
                        width: 120px;
                        height: 28px;
                        font_size: 11px;
                        text: "Тест тревоги";
                        bg_color: #181d26;
                        hover_color: #232a38;
                        text_color: #94a3b8;
                        clicked => { root.test_alert_clicked(); }
                    }
                }
            }

            // Central view: INCIDENT ALERT
            if root.has_incident : VerticalLayout {
                spacing: 14px;

                HorizontalLayout {
                    alignment: space_between;
                    StatusPill {
                        text: "ПОДОЗРИТЕЛЬНОЕ СОЕДИНЕНИЕ";
                        dot_color: #ef4444;
                        pill_bg: #2d1215;
                        border_col: #5c1d24;
                    }

                    Text {
                        text: "Блокировка через " + root.countdown_seconds + "с";
                        color: #94a3b8;
                        font_size: 12px;
                        vertical_alignment: center;
                    }
                }

                Rectangle {
                    background: #141820;
                    border_radius: 12px;
                    border_width: 1px;
                    border_color: #272f3d;

                    VerticalLayout {
                        padding: 18px;
                        spacing: 12px;

                        // Process details
                        HorizontalLayout {
                            alignment: space_between;
                            VerticalLayout {
                                spacing: 2px;
                                Text {
                                    text: root.process_name;
                                    font_size: 18px;
                                    font_weight: 700;
                                    color: #ffffff;
                                }
                                Text {
                                    text: "PID " + root.process_pid + " • " + root.process_path;
                                    font_size: 12px;
                                    color: #94a3b8;
                                }
                            }

                            Rectangle {
                                background: #221c16;
                                border_radius: 6px;
                                border_width: 1px;
                                border_color: #5c3818;
                                height: 26px;
                                HorizontalLayout {
                                    padding_left: 8px;
                                    padding_right: 8px;
                                    Text {
                                        text: "РИСК " + root.risk_score + "/100";
                                        font_size: 11px;
                                        font_weight: 700;
                                        color: #fb923c;
                                        vertical_alignment: center;
                                    }
                                }
                            }
                        }

                        // Divider
                        Rectangle {
                            height: 1px;
                            background: #1e2533;
                        }

                        // Target
                        VerticalLayout {
                            spacing: 3px;
                            Text {
                                text: "КУДА ОБРАЩАЕТСЯ";
                                font_size: 10px;
                                font_weight: 700;
                                color: #64748b;
                            }
                            Text {
                                text: root.target_address;
                                font_size: 15px;
                                font_weight: 600;
                                color: #38bdf8;
                            }
                        }

                        // Reasons
                        VerticalLayout {
                            spacing: 3px;
                            Text {
                                text: "ОБНАРУЖЕННЫЕ АНОМАЛИИ";
                                font_size: 10px;
                                font_weight: 700;
                                color: #64748b;
                            }
                            Text {
                                text: root.reasons_text;
                                font_size: 12px;
                                color: #fbbf24;
                            }
                        }
                    }
                }

                // 2 Clean buttons + 1 ghost link
                HorizontalLayout {
                    spacing: 12px;
                    alignment: center;

                    ActionButton {
                        width: 170px;
                        height: 42px;
                        text: "Заблокировать";
                        bg_color: #dc2626;
                        hover_color: #ef4444;
                        text_color: #ffffff;
                        clicked => { root.block_clicked(); }
                    }

                    ActionButton {
                        width: 150px;
                        height: 42px;
                        text: "Разрешить";
                        bg_color: #1e2533;
                        hover_color: #2b3548;
                        text_color: #e2e8f0;
                        clicked => { root.allow_clicked(); }
                    }

                    ActionButton {
                        width: 180px;
                        height: 42px;
                        text: "Завершить процесс";
                        bg_color: transparent;
                        hover_color: #281216;
                        text_color: #f87171;
                        font_size: 12px;
                        clicked => { root.kill_clicked(); }
                    }
                }
            }
        }
    }
}

struct ActiveIncident {
    id: String,
    auth_pin: Option<String>,
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    tracing_subscriber::fmt::init();
    info!("Starting Sentinel-RS Desktop UI...");

    let args: Vec<String> = std::env::args().collect();
    if args.iter().any(|a| a == "--help" || a == "-h") {
        println!("Sentinel-RS Desktop GUI");
        println!("\nUsage: sentinel-gui [OPTIONS]");
        println!("\nOptions:");
        println!("  --demo       Display preview with sample data");
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

    let window = MainWindow::new()?;
    let window_handle = window.as_weak();

    let writer_slot: Arc<Mutex<Option<OwnedWriteHalf>>> = Arc::new(Mutex::new(None));
    let active_incident: Arc<Mutex<Option<ActiveIncident>>> = Arc::new(Mutex::new(None));

    // Countdown timer background task
    let w_timer = window_handle.clone();
    tokio::spawn(async move {
        loop {
            tokio::time::sleep(std::time::Duration::from_secs(1)).await;
            let w_h = w_timer.clone();
            let _ = slint::invoke_from_event_loop(move || {
                if let Some(w) = w_h.upgrade() {
                    if w.get_has_incident() {
                        let s = w.get_countdown_seconds();
                        if s > 0 {
                            w.set_countdown_seconds(s - 1);
                        } else {
                            w.set_has_incident(false);
                        }
                    }
                }
            });
        }
    });

    // Wire actions
    let active_inc = active_incident.clone();
    let wr = writer_slot.clone();
    let w_h = window_handle.clone();
    window.on_block_clicked(move || {
        let active_inc = active_inc.clone();
        let wr = wr.clone();
        let w_h = w_h.clone();
        tokio::spawn(async move {
            if let Some(inc) = active_inc.lock().await.take() {
                send_verdict(&wr, inc.id, PromptAction::DenyOnce, inc.auth_pin).await;
            }
            let _ = slint::invoke_from_event_loop(move || {
                if let Some(w) = w_h.upgrade() {
                    w.set_has_incident(false);
                }
            });
        });
    });

    let active_inc = active_incident.clone();
    let wr = writer_slot.clone();
    let w_h = window_handle.clone();
    window.on_allow_clicked(move || {
        let active_inc = active_inc.clone();
        let wr = wr.clone();
        let w_h = w_h.clone();
        tokio::spawn(async move {
            if let Some(inc) = active_inc.lock().await.take() {
                send_verdict(&wr, inc.id, PromptAction::AllowOnce, inc.auth_pin).await;
            }
            let _ = slint::invoke_from_event_loop(move || {
                if let Some(w) = w_h.upgrade() {
                    w.set_has_incident(false);
                }
            });
        });
    });

    let active_inc = active_incident.clone();
    let wr = writer_slot.clone();
    let w_h = window_handle.clone();
    window.on_kill_clicked(move || {
        let active_inc = active_inc.clone();
        let wr = wr.clone();
        let w_h = w_h.clone();
        tokio::spawn(async move {
            if let Some(inc) = active_inc.lock().await.take() {
                send_verdict(&wr, inc.id, PromptAction::Kill, inc.auth_pin).await;
            }
            let _ = slint::invoke_from_event_loop(move || {
                if let Some(w) = w_h.upgrade() {
                    w.set_has_incident(false);
                }
            });
        });
    });

    let w_h = window_handle.clone();
    window.on_test_alert_clicked(move || {
        if let Some(w) = w_h.upgrade() {
            w.set_incident_id("demo-8842".into());
            w.set_process_name("curl".into());
            w.set_process_pid("3812".into());
            w.set_process_path("/usr/bin/curl".into());
            w.set_target_address("185.220.101.5:443".into());
            w.set_reasons_text("Чтение ключа ~/.ssh/id_ed25519 • Прямое IP-подключение".into());
            w.set_risk_score(85);
            w.set_countdown_seconds(30);
            w.set_has_incident(true);
        }
    });

    let reconnect_notify = Arc::new(tokio::sync::Notify::new());

    let w_h = window_handle.clone();
    let notify_clone = reconnect_notify.clone();
    window.on_reconnect_clicked(move || {
        notify_clone.notify_one();
    });

    if is_demo {
        info!("Running in demo preview mode");
        window.set_is_connected(true);
        window.set_lsm_status("LSM: Активен".into());
        window.set_tracked_count_text("142 процесса".into());
        window.set_threat_count_text("0 угроз".into());
        window.set_last_event_text("Демонстрационный режим Sentinel-RS".into());
        window.run()?;
        return Ok(());
    }

    // Spawn single background connection loop with instant reconnect notification
    let w_h = window_handle.clone();
    let notify_loop = reconnect_notify.clone();
    tokio::spawn(async move {
        connect_and_listen(socket_path, writer_slot, active_incident, w_h, notify_loop).await;
    });

    window.run()?;
    Ok(())
}

async fn connect_and_listen(
    socket_path: PathBuf,
    writer_slot: Arc<Mutex<Option<OwnedWriteHalf>>>,
    active_incident: Arc<Mutex<Option<ActiveIncident>>>,
    window_handle: slint::Weak<MainWindow>,
    reconnect_notify: Arc<tokio::sync::Notify>,
) {
    loop {
        match UnixStream::connect(&socket_path).await {
            Ok(stream) => {
                info!("Connected to sentineld at {}", socket_path.display());
                let (reader, mut writer) = stream.into_split();

                // Send Subscribe and StatusRequest
                let sub = serde_json::to_string(&IpcMessage::Subscribe).unwrap_or_default() + "\n";
                let _ = writer.write_all(sub.as_bytes()).await;
                let stat = serde_json::to_string(&IpcMessage::StatusRequest).unwrap_or_default() + "\n";
                let _ = writer.write_all(stat.as_bytes()).await;

                {
                    let mut lock = writer_slot.lock().await;
                    *lock = Some(writer);
                }

                let w_h = window_handle.clone();
                let _ = slint::invoke_from_event_loop(move || {
                    if let Some(w) = w_h.upgrade() {
                        w.set_is_connected(true);
                        w.set_last_event_text("Подключено к службе sentineld".into());
                    }
                });

                let mut reader = BufReader::new(reader);
                let mut line = String::new();
                while reader.read_line(&mut line).await.unwrap_or(0) > 0 {
                    let trimmed = line.trim();
                    if let Ok(msg) = serde_json::from_str::<IpcMessage>(trimmed) {
                        match msg {
                            IpcMessage::Prompt(prompt) => {
                                let inc_data = ActiveIncident {
                                    id: prompt.incident_id.clone(),
                                    auth_pin: prompt.auth_pin.clone(),
                                };
                                {
                                    let mut lock = active_incident.lock().await;
                                    *lock = Some(inc_data);
                                }

                                let (exe, pid, path) = if let Some(last) = prompt.lineage.last() {
                                    (
                                        last.exe_name.clone(),
                                        last.tgid.to_string(),
                                        last.script_path
                                            .as_ref()
                                            .map(|p| p.display().to_string())
                                            .unwrap_or_else(|| last.exe_name.clone()),
                                    )
                                } else {
                                    ("Неизвестный процесс".into(), "—".into(), "".into())
                                };

                                let target = match (&prompt.dest_ip, prompt.dest_port) {
                                    (Some(ip), Some(port)) => format!("{}:{}", ip, port),
                                    (Some(ip), None) => ip.clone(),
                                    _ => "Внешний узел".into(),
                                };

                                let reasons = if prompt.reasons.is_empty() {
                                    "Подозрительная активность".to_string()
                                } else {
                                    prompt.reasons.join(" • ")
                                };

                                let score = prompt.risk_score as i32;
                                let inc_id = prompt.incident_id;
                                let w_h = window_handle.clone();
                                let _ = slint::invoke_from_event_loop(move || {
                                    if let Some(w) = w_h.upgrade() {
                                        w.set_incident_id(inc_id.into());
                                        w.set_process_name(exe.into());
                                        w.set_process_pid(pid.into());
                                        w.set_process_path(path.into());
                                        w.set_target_address(target.into());
                                        w.set_reasons_text(reasons.into());
                                        w.set_risk_score(score);
                                        w.set_countdown_seconds(30);
                                        w.set_has_incident(true);
                                    }
                                });
                            }
                            IpcMessage::StatusResponse {
                                uptime_secs: _,
                                tracked_processes,
                                total_incidents,
                                frozen_count: _,
                            } => {
                                let w_h = window_handle.clone();
                                let _ = slint::invoke_from_event_loop(move || {
                                    if let Some(w) = w_h.upgrade() {
                                        w.set_tracked_count_text(format!("{} процессов", tracked_processes).into());
                                        w.set_threat_count_text(format!("{} угроз", total_incidents).into());
                                    }
                                });
                            }
                            IpcMessage::Event { timestamp: _, summary, risk_score: _ } => {
                                let w_h = window_handle.clone();
                                let _ = slint::invoke_from_event_loop(move || {
                                    if let Some(w) = w_h.upgrade() {
                                        w.set_last_event_text(summary.into());
                                    }
                                });
                            }
                            _ => {}
                        }
                    }
                    line.clear();
                }

                // Disconnected
                warn!("Connection to sentineld lost");
                {
                    let mut lock = writer_slot.lock().await;
                    *lock = None;
                }
                let w_h = window_handle.clone();
                let _ = slint::invoke_from_event_loop(move || {
                    if let Some(w) = w_h.upgrade() {
                        w.set_is_connected(false);
                        w.set_last_event_text("Связь с демоном потеряна".into());
                    }
                });
            }
            Err(e) => {
                warn!("Cannot connect to sentineld: {}. Retrying in 3s...", e);
                let w_h = window_handle.clone();
                let _ = slint::invoke_from_event_loop(move || {
                    if let Some(w) = w_h.upgrade() {
                        w.set_is_connected(false);
                    }
                });
            }
        }
        tokio::select! {
            _ = tokio::time::sleep(std::time::Duration::from_secs(3)) => {}
            _ = reconnect_notify.notified() => {
                info!("Manual reconnection triggered via UI");
            }
        }
    }
}

async fn send_verdict(
    writer_slot: &Arc<Mutex<Option<OwnedWriteHalf>>>,
    incident_id: String,
    action: PromptAction,
    auth_pin: Option<String>,
) {
    let msg = IpcMessage::Verdict(PromptVerdict {
        incident_id,
        action,
        auth_pin,
    });
    if let Ok(json) = serde_json::to_string(&msg) {
        let payload = json + "\n";
        let mut lock = writer_slot.lock().await;
        if let Some(ref mut w) = *lock {
            let _ = w.write_all(payload.as_bytes()).await;
        }
    }
}
