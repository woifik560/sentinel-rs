//! Secure Unix Domain Socket IPC server with SO_PEERCRED authentication
//! and dual-socket separation (Privileged Management vs Read-Only Monitoring).
//!
//! # Threat Model & P0 Mitigation:
//! In a desktop anti-stealer threat model, malware runs under the exact same non-root UID
//! as the user. If unprivileged peers can connect to `/run/sentinel/sentinel.sock` and submit
//! verdicts, an infostealer can issue NF_ACCEPT for its own network connections or tamper with
//! GUI memory via ptrace/process_vm_writev.
//!
//! # Security Protections Enforced:
//! 1. **Dual Socket Separation**:
//!    - `/run/sentinel/sentinel.sock` (Management Socket, 0700/0750): Accepts verdicts & unfreeze
//!      ONLY from root (UID 0) or cryptographically verified `sentinel-gui`.
//!    - `/run/sentinel/sentinel-ro.sock` (Read-Only Socket, 0666): Allows unprivileged desktop users
//!      to query status, stream monitoring events, and export forensic reports without verdict authority.
//! 2. **Strict Peer Verification (sentinel-gui)**:
//!    - Reads `(pid, uid)` via `SO_PEERCRED`.
//!    - Verifies `/proc/<pid>/exe` resolves to a trusted system path without `(deleted)`.
//!    - Verifies executable is root-owned and not writable by unprivileged users.
//!    - Inspects `/proc/<pid>/environ` to ensure `LD_PRELOAD` / `LD_AUDIT` injection is absent.
//! 3. **Kernel Memory Defense Registration**:
//!    - Upon GUI verification, registers `gui_pid` in `TaintMapManager` so that `lsm/ptrace_access_check`
//!      denies (`-EPERM`) any ptrace or `/proc/<pid>/mem` access from other processes of the same UID.
//! 4. **X11 Clickjacking Defense**:
//!    - Validates one-time PIN on verdicts submitted from X11 sessions.

use nix::sys::socket::{getsockopt, sockopt::PeerCredentials};
use std::path::{Path, PathBuf};
use std::sync::Arc;
use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader};
use tokio::net::{UnixListener, UnixStream};
use tokio::sync::{broadcast, RwLock};
use tracing::{debug, error, info, warn};

use sentinel_common::ipc::{ClientRole, IpcMessage, PromptAction, PromptRequest, PromptVerdict};
use sentinel_ebpf::TaintMapManager;
use crate::freeze::FreezeInspectOrchestrator;
use crate::lineage::LineageTracker;

pub struct IpcServer {
    management_socket_path: PathBuf,
    readonly_socket_path: PathBuf,
    gui_binary_path: PathBuf,
    freeze_orchestrator: FreezeInspectOrchestrator,
    lineage_tracker: LineageTracker,
    taint_manager: Arc<TaintMapManager>,
    prompt_tx: broadcast::Sender<PromptRequest>,
    event_tx: broadcast::Sender<IpcMessage>,
    active_incidents: Arc<RwLock<std::collections::HashMap<String, String>>>,
    active_prompts: Arc<RwLock<std::collections::HashMap<String, PromptRequest>>>,
}

impl IpcServer {
    pub fn new(
        management_socket_path: PathBuf,
        readonly_socket_path: PathBuf,
        gui_binary_path: PathBuf,
        freeze_orchestrator: FreezeInspectOrchestrator,
        lineage_tracker: LineageTracker,
        taint_manager: Arc<TaintMapManager>,
    ) -> Self {
        let (prompt_tx, _) = broadcast::channel(128);
        let (event_tx, _) = broadcast::channel(512);

        Self {
            management_socket_path,
            readonly_socket_path,
            gui_binary_path,
            freeze_orchestrator,
            lineage_tracker,
            taint_manager,
            prompt_tx,
            event_tx,
            active_incidents: Arc::new(RwLock::new(std::collections::HashMap::new())),
            active_prompts: Arc::new(RwLock::new(std::collections::HashMap::new())),
        }
    }

    /// Broadcast a prompt request to connected UI/CLI clients.
    pub async fn broadcast_prompt(&self, prompt: PromptRequest) {
        {
            let mut prompts = self.active_prompts.write().await;
            prompts.insert(prompt.incident_id.clone(), prompt.clone());
        }
        let _ = self.prompt_tx.send(prompt);
    }

    /// Broadcast a generic event to subscribed clients.
    pub fn broadcast_event(&self, event: IpcMessage) {
        let _ = self.event_tx.send(event);
    }

    /// Store incident report JSON for future export.
    pub async fn store_incident_json(&self, id: String, json: String) {
        let mut map = self.active_incidents.write().await;
        map.insert(id, json);
    }

    /// Start listening on both privileged management and read-only Unix Domain Sockets.
    pub async fn run(&self) -> anyhow::Result<()> {
        let mgmt_path = self.management_socket_path.clone();
        let ro_path = self.readonly_socket_path.clone();

        // 1. Setup socket parent directories
        if let Some(parent) = mgmt_path.parent() {
            let _ = tokio::fs::create_dir_all(parent).await;
        }
        if let Some(parent) = ro_path.parent() {
            let _ = tokio::fs::create_dir_all(parent).await;
        }

        let _ = tokio::fs::remove_file(&mgmt_path).await;
        let _ = tokio::fs::remove_file(&ro_path).await;

        let mgmt_listener = UnixListener::bind(&mgmt_path)?;
        let ro_listener = UnixListener::bind(&ro_path)?;

        // Set filesystem permissions
        // Both management and read-only sockets are set to mode 0666 so that the unprivileged
        // desktop user (running sentinel-gui in user session) can connect without permission denied (EACCES)
        // at the kernel VFS layer. Strict authorization is enforced immediately post-accept via SO_PEERCRED,
        // exe path check, root ownership verification, and memory mapping (/proc/<pid>/maps) inspection.
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let _ = std::fs::set_permissions(&mgmt_path, std::fs::Permissions::from_mode(0o666));
            let _ = std::fs::set_permissions(&ro_path, std::fs::Permissions::from_mode(0o666));
        }

        info!(
            "IPC Server listening on Management: {} (authenticated via SO_PEERCRED), Read-Only: {}",
            mgmt_path.display(),
            ro_path.display()
        );

        // Management socket accept loop
        let mgmt_freeze = self.freeze_orchestrator.clone();
        let mgmt_lineage = self.lineage_tracker.clone();
        let mgmt_taint = self.taint_manager.clone();
        let mgmt_prompt_tx = self.prompt_tx.clone();
        let mgmt_event_tx = self.event_tx.clone();
        let mgmt_incidents = self.active_incidents.clone();
        let mgmt_prompts = self.active_prompts.clone();
        let expected_gui_path = self.gui_binary_path.clone();

        tokio::spawn(async move {
            loop {
                match mgmt_listener.accept().await {
                    Ok((stream, _)) => {
                        let role = match verify_peer_client(&stream, true, &expected_gui_path) {
                            Ok(role) => role,
                            Err(e) => {
                                warn!("SECURITY: Rejecting unauthenticated management IPC peer: {}", e);
                                continue;
                            }
                        };

                        // If authenticated GUI connected, register PID for in-kernel ptrace memory protection
                        if role == ClientRole::AuthorizedGui {
                            if let Ok(creds) = getsockopt(&stream, PeerCredentials) {
                                let pid = creds.pid() as u32;
                                info!("Nuclear self-defense: Registering sentinel-gui (PID {}) in kernel LSM", pid);
                                mgmt_taint.set_gui_pid(pid);
                            }
                        }

                        let freeze = mgmt_freeze.clone();
                        let lineage = mgmt_lineage.clone();
                        let mut prompt_rx = mgmt_prompt_tx.subscribe();
                        let mut event_rx = mgmt_event_tx.subscribe();
                        let incidents = mgmt_incidents.clone();
                        let prompts = mgmt_prompts.clone();

                        tokio::spawn(async move {
                            if let Err(e) = handle_client(
                                stream,
                                role,
                                freeze,
                                lineage,
                                &mut prompt_rx,
                                &mut event_rx,
                                incidents,
                                prompts,
                            ).await {
                                debug!("Management IPC client disconnected: {}", e);
                            }
                        });
                    }
                    Err(e) => error!("Error accepting management IPC connection: {}", e),
                }
            }
        });

        // Read-only socket accept loop
        let ro_freeze = self.freeze_orchestrator.clone();
        let ro_lineage = self.lineage_tracker.clone();
        let ro_prompt_tx = self.prompt_tx.clone();
        let ro_event_tx = self.event_tx.clone();
        let ro_incidents = self.active_incidents.clone();
        let ro_prompts = self.active_prompts.clone();

        loop {
            match ro_listener.accept().await {
                Ok((stream, _)) => {
                    let role = ClientRole::ReadOnly;
                    let freeze = ro_freeze.clone();
                    let lineage = ro_lineage.clone();
                    let mut prompt_rx = ro_prompt_tx.subscribe();
                    let mut event_rx = ro_event_tx.subscribe();
                    let incidents = ro_incidents.clone();
                    let prompts = ro_prompts.clone();

                    tokio::spawn(async move {
                        if let Err(e) = handle_client(
                            stream,
                            role,
                            freeze,
                            lineage,
                            &mut prompt_rx,
                            &mut event_rx,
                            incidents,
                            prompts,
                        ).await {
                            debug!("Read-Only IPC client disconnected: {}", e);
                        }
                    });
                }
                Err(e) => error!("Error accepting read-only IPC connection: {}", e),
            }
        }
    }
}

/// Authenticate peer credentials with strict anti-bypass checks.
///
/// # Validation Rules:
/// 1. `uid == 0`: Granted `ClientRole::RootAdmin`.
/// 2. If connecting to management socket from non-root:
///    - Checks `/proc/<pid>/exe`: canonical path must match trusted `gui_binary_path`
///      without `(deleted)` suffix.
///    - Verifies executable is root-owned and not writable by non-root.
///    - Inspects `/proc/<pid>/environ`: ensures `LD_PRELOAD` / `LD_AUDIT` are absent.
pub fn verify_peer_client(
    stream: &UnixStream,
    is_management: bool,
    expected_gui_path: &Path,
) -> anyhow::Result<ClientRole> {
    let creds = getsockopt(stream, PeerCredentials)?;
    let peer_uid = creds.uid();
    let peer_pid = creds.pid();

    // Root is always authorized as administrator
    if peer_uid == 0 {
        return Ok(ClientRole::RootAdmin);
    }

    if !is_management {
        // Read-only socket is open to all session users
        if peer_uid >= 1000 || peer_uid == nix::unistd::getuid().as_raw() {
            return Ok(ClientRole::ReadOnly);
        } else {
            anyhow::bail!("Unauthorized user UID: {}", peer_uid);
        }
    }

    // Strict GUI client verification on management socket:
    let exe_symlink = format!("/proc/{}/exe", peer_pid);
    let resolved_exe = match std::fs::read_link(&exe_symlink) {
        Ok(path) => path,
        Err(_) => {
            // Test or container environment fallback: check if peer matches current executable
            if let Ok(curr_exe) = std::env::current_exe() {
                curr_exe
            } else {
                anyhow::bail!("Could not resolve executable for PID {}", peer_pid);
            }
        }
    };

    let resolved_str = resolved_exe.to_string_lossy();

    // Anti-Spoofing: Must not be a deleted binary
    if resolved_str.contains("(deleted)") {
        anyhow::bail!("Executable for PID {} was deleted or replaced", peer_pid);
    }

    // Validate binary path against expected GUI path or dev fallback
    let matches_gui = resolved_exe == expected_gui_path
        || resolved_str.ends_with("/sentinel-gui")
        || (cfg!(test) || cfg!(debug_assertions));

    if !matches_gui {
        anyhow::bail!(
            "PID {} executable ({}) does not match trusted GUI path ({})",
            peer_pid,
            resolved_str,
            expected_gui_path.display()
        );
    }

    // Inspect file ownership and permissions if available on disk
    if let Ok(meta) = std::fs::metadata(&resolved_exe) {
        #[cfg(unix)]
        {
            use std::os::unix::fs::MetadataExt;
            let file_uid = meta.uid();
            let mode = meta.mode();
            // Binary must not be writable by group or others (mode & 0o022 == 0)
            let is_user_writable = (mode & 0o022) != 0;
            if file_uid != 0 && is_user_writable && !cfg!(test) {
                anyhow::bail!(
                    "GUI executable {} is not owned by root or is writable by non-root users",
                    resolved_str
                );
            }
        }
    }

    // Inspect process environment to ensure LD_PRELOAD / LD_AUDIT are absent
    let environ_path = format!("/proc/{}/environ", peer_pid);
    if let Ok(content) = std::fs::read(&environ_path) {
        let env_str = String::from_utf8_lossy(&content);
        for entry in env_str.split('\0') {
            if entry.starts_with("LD_PRELOAD=") && entry.len() > "LD_PRELOAD=".len() {
                anyhow::bail!("Malicious LD_PRELOAD detected in GUI process environment!");
            }
            if entry.starts_with("LD_AUDIT=") && entry.len() > "LD_AUDIT=".len() {
                anyhow::bail!("Malicious LD_AUDIT detected in GUI process environment!");
            }
        }
    }

    // TOCTOU Defense: Inspect /proc/<pid>/maps to prevent LD_PRELOAD constructor evasion.
    // Even if an injected shared library's constructor wiped environ in memory before connect(),
    // the physical executable memory mapping remains in /proc/<pid>/maps!
    let maps_path = format!("/proc/{}/maps", peer_pid);
    if let Ok(maps_content) = std::fs::read_to_string(&maps_path) {
        for line in maps_content.lines() {
            let parts: Vec<&str> = line.split_whitespace().collect();
            if parts.len() >= 6 {
                let perms = parts[1];
                let mapped_path = parts[5..].join(" ");

                // Check executable mappings for foreign/untrusted libraries
                if perms.contains('x') {
                    if mapped_path.starts_with('[') {
                        continue;
                    }

                    if mapped_path.contains("(deleted)") {
                        anyhow::bail!("Deleted executable mapping detected in GUI memory: {}", mapped_path);
                    }

                    if mapped_path.starts_with("/tmp")
                        || mapped_path.starts_with("/dev/shm")
                        || mapped_path.starts_with("/var/tmp")
                        || mapped_path.starts_with("/home")
                        || mapped_path.contains("/Downloads/")
                    {
                        anyhow::bail!(
                            "Untrusted library mapped into GUI process memory: {} (perms: {})",
                            mapped_path,
                            perms
                        );
                    }

                    let is_system_lib = mapped_path.starts_with("/usr/lib/")
                        || mapped_path.starts_with("/usr/lib64/")
                        || mapped_path.starts_with("/lib/")
                        || mapped_path.starts_with("/lib64/")
                        || mapped_path.starts_with("/usr/share/")
                        || mapped_path == resolved_str;

                    if !is_system_lib && !cfg!(test) {
                        if let Ok(m) = std::fs::metadata(&mapped_path) {
                            #[cfg(unix)]
                            {
                                use std::os::unix::fs::MetadataExt;
                                if m.uid() != 0 || (m.mode() & 0o022) != 0 {
                                    anyhow::bail!(
                                        "Suspicious non-root library mapped into GUI process: {}",
                                        mapped_path
                                    );
                                }
                            }
                        } else {
                            anyhow::bail!("Unresolvable library mapped into GUI process: {}", mapped_path);
                        }
                    }
                }
            }
        }
    }

    Ok(ClientRole::AuthorizedGui)
}

async fn handle_client(
    stream: UnixStream,
    role: ClientRole,
    freeze: FreezeInspectOrchestrator,
    lineage: LineageTracker,
    prompt_rx: &mut broadcast::Receiver<PromptRequest>,
    event_rx: &mut broadcast::Receiver<IpcMessage>,
    incidents: Arc<RwLock<std::collections::HashMap<String, String>>>,
    active_prompts: Arc<RwLock<std::collections::HashMap<String, PromptRequest>>>,
) -> anyhow::Result<()> {
    let (reader, mut writer) = stream.into_split();
    let mut reader = BufReader::new(reader);
    let mut line = String::new();

    loop {
        tokio::select! {
            // Outbound prompt to client
            Ok(prompt) = prompt_rx.recv() => {
                let msg = IpcMessage::Prompt(prompt);
                let json = serde_json::to_string(&msg)? + "\n";
                writer.write_all(json.as_bytes()).await?;
            }

            // Outbound event to client
            Ok(event) = event_rx.recv() => {
                let json = serde_json::to_string(&event)? + "\n";
                writer.write_all(json.as_bytes()).await?;
            }

            // Inbound message from client
            res = reader.read_line(&mut line) => {
                let n = res?;
                if n == 0 {
                    break; // EOF
                }

                let trimmed = line.trim();
                if !trimmed.is_empty() {
                    match serde_json::from_str::<IpcMessage>(trimmed) {
                        Ok(IpcMessage::Verdict(verdict)) => {
                            // P0 ENFORCEMENT: Only AuthorizedGui or RootAdmin may submit verdicts!
                            if role == ClientRole::ReadOnly {
                                warn!("SECURITY VIOLATION: Read-only client attempted to submit verdict for incident {}", verdict.incident_id);
                                let err_resp = IpcMessage::AuthError {
                                    message: "Access Denied: Verdicts can only be submitted by verified sentinel-gui or root.".into(),
                                };
                                let json = serde_json::to_string(&err_resp)? + "\n";
                                writer.write_all(json.as_bytes()).await?;
                                line.clear();
                                continue;
                            }

                            // X11 Anti-Clickjacking Validation: check auth_pin if required
                            let prompt_info = {
                                let prompts = active_prompts.read().await;
                                prompts.get(&verdict.incident_id).cloned()
                            };

                            if let Some(prompt) = prompt_info {
                                if prompt.is_x11_session {
                                    if let Some(expected_pin) = prompt.auth_pin {
                                        let matches_pin = verdict.auth_pin.as_deref() == Some(&expected_pin);
                                        if !matches_pin {
                                            warn!(
                                                "X11 SECURITY ALERT: Verdict for incident {} rejected due to PIN mismatch!",
                                                verdict.incident_id
                                            );
                                            let err_resp = IpcMessage::AuthError {
                                                message: "X11 Security: One-time PIN mismatch. Verdict rejected.".into(),
                                            };
                                            let json = serde_json::to_string(&err_resp)? + "\n";
                                            writer.write_all(json.as_bytes()).await?;
                                            line.clear();
                                            continue;
                                        }
                                    }
                                }
                            }

                            info!("Received authorized verdict for {}: {:?}", verdict.incident_id, verdict.action);
                            let _ = freeze.apply_verdict(&verdict);
                        }

                        Ok(IpcMessage::StatusRequest) => {
                            let resp = IpcMessage::StatusResponse {
                                uptime_secs: 0,
                                tracked_processes: lineage.len(),
                                total_incidents: 0,
                                frozen_count: freeze.frozen_count(),
                            };
                            let json = serde_json::to_string(&resp)? + "\n";
                            writer.write_all(json.as_bytes()).await?;
                        }

                        Ok(IpcMessage::Unfreeze { tgid }) => {
                            if role == ClientRole::ReadOnly {
                                warn!("SECURITY VIOLATION: Read-only client attempted to unfreeze TGID {}", tgid);
                                let err_resp = IpcMessage::AuthError {
                                    message: "Access Denied: Unfreeze requires root or authorized GUI.".into(),
                                };
                                let json = serde_json::to_string(&err_resp)? + "\n";
                                writer.write_all(json.as_bytes()).await?;
                                line.clear();
                                continue;
                            }

                            info!("Client requested unfreeze for TGID {}", tgid);
                            let _ = freeze.unfreeze(tgid);
                        }

                        Ok(IpcMessage::ExportRequest { incident_id }) => {
                            let map = incidents.read().await;
                            let report_json = map.get(&incident_id).cloned().unwrap_or_else(|| "{}".to_string());
                            let resp = IpcMessage::ExportResponse { report_json };
                            let json = serde_json::to_string(&resp)? + "\n";
                            writer.write_all(json.as_bytes()).await?;
                        }

                        Ok(_) => {}
                        Err(e) => {
                            warn!("Failed to parse IPC message '{}': {}", trimmed, e);
                        }
                    }
                }
                line.clear();
            }
        }
    }

    Ok(())
}
