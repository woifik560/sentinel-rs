//! Secure Unix Domain Socket IPC server with SO_PEERCRED authentication
//! and role-based access control (RBAC).
//!
//! # Headless Security Model (Part 14):
//! In a headless HIPS/EDR agent, management is conducted via CLI (`sntctl`) over
//! `/run/sentinel/sentinel.sock` using kernel-authenticated peer credentials (`SO_PEERCRED`).
//!
//! # Roles Enforced:
//! 1. **ROOT_ADMIN (UID 0)**:
//!    - Policy management, protection enable/disable, configuration reload,
//!      exception management, incident export, manual response/unfreeze.
//! 2. **OPERATOR (GID 0 / operator group)**:
//!    - Status, health, events, incidents, diagnostics.
//! 3. **READ_ONLY**:
//!    - Read-only queries and live event monitoring on `/run/sentinel/sentinel-ro.sock`.

use nix::sys::socket::{getsockopt, sockopt::PeerCredentials};
use std::path::{Path, PathBuf};
use std::sync::Arc;
use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader};
use tokio::net::{UnixListener, UnixStream};
use tokio::sync::{broadcast, RwLock};
use tracing::{debug, error, info, warn};

use sentinel_common::ipc::{ClientRole, IpcCommand, IpcMessage, IpcResponse, PromptRequest};
use sentinel_ebpf::TaintMapManager;
use crate::freeze::FreezeInspectOrchestrator;
use crate::lineage::LineageTracker;
use crate::protection::ProtectionState;
use crate::risk::RiskEngine;
use crate::storage::StorageManager;

pub struct IpcServer {
    management_socket_path: PathBuf,
    readonly_socket_path: PathBuf,
    freeze_orchestrator: FreezeInspectOrchestrator,
    lineage_tracker: LineageTracker,
    #[allow(dead_code)]
    taint_manager: Arc<TaintMapManager>,
    prompt_tx: broadcast::Sender<PromptRequest>,
    event_tx: broadcast::Sender<IpcMessage>,
    active_incidents: Arc<RwLock<std::collections::HashMap<String, String>>>,
    active_prompts: Arc<RwLock<std::collections::HashMap<String, PromptRequest>>>,
    pub protection_state: Arc<RwLock<ProtectionState>>,
    pub risk_engine: Option<Arc<RwLock<RiskEngine>>>,
    pub storage: Option<StorageManager>,
}

impl IpcServer {
    pub fn new(
        management_socket_path: PathBuf,
        readonly_socket_path: PathBuf,
        freeze_orchestrator: FreezeInspectOrchestrator,
        lineage_tracker: LineageTracker,
        taint_manager: Arc<TaintMapManager>,
    ) -> Self {
        let (prompt_tx, _) = broadcast::channel(128);
        let (event_tx, _) = broadcast::channel(512);

        let protection_state = Arc::new(RwLock::new(ProtectionState::new(
            true,
            sentinel_common::policy::OperatingMode::Balanced,
            PathBuf::from("/etc/sentinel/rules.toml"),
            PathBuf::from("/etc/sentinel/config.toml"),
        )));

        Self {
            management_socket_path,
            readonly_socket_path,
            freeze_orchestrator,
            lineage_tracker,
            taint_manager,
            prompt_tx,
            event_tx,
            active_incidents: Arc::new(RwLock::new(std::collections::HashMap::new())),
            active_prompts: Arc::new(RwLock::new(std::collections::HashMap::new())),
            protection_state,
            risk_engine: None,
            storage: None,
        }
    }

    /// Builder method to configure state, risk engine, and persistent storage.
    pub fn with_state_and_storage(
        mut self,
        protection_state: Arc<RwLock<ProtectionState>>,
        risk_engine: Arc<RwLock<RiskEngine>>,
        storage: Option<StorageManager>,
    ) -> Self {
        self.protection_state = protection_state;
        self.risk_engine = Some(risk_engine);
        self.storage = storage;
        self
    }

    /// Backward-compatible constructor for existing tests
    pub fn new_with_gui(
        management_socket_path: PathBuf,
        readonly_socket_path: PathBuf,
        _gui_binary_path: PathBuf,
        freeze_orchestrator: FreezeInspectOrchestrator,
        lineage_tracker: LineageTracker,
        taint_manager: Arc<TaintMapManager>,
    ) -> Self {
        Self::new(
            management_socket_path,
            readonly_socket_path,
            freeze_orchestrator,
            lineage_tracker,
            taint_manager,
        )
    }

    /// Broadcast a prompt/telemetry record to connected monitoring clients.
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

    /// Start listening on both management and read-only Unix Domain Sockets.
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
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            // Management socket restricted to root / operator group
            let _ = std::fs::set_permissions(&mgmt_path, std::fs::Permissions::from_mode(0o660));
            // Read-only socket open to local users
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
        let mgmt_prompt_tx = self.prompt_tx.clone();
        let mgmt_event_tx = self.event_tx.clone();
        let mgmt_incidents = self.active_incidents.clone();
        let mgmt_protection_state = self.protection_state.clone();
        let mgmt_risk_engine = self.risk_engine.clone();
        let mgmt_storage = self.storage.clone();

        tokio::spawn(async move {
            loop {
                match mgmt_listener.accept().await {
                    Ok((stream, _)) => {
                        let role = match verify_peer_client(&stream, true) {
                            Ok(role) => role,
                            Err(e) => {
                                warn!("SECURITY: Rejecting unauthenticated management IPC peer: {}", e);
                                continue;
                            }
                        };

                        let freeze = mgmt_freeze.clone();
                        let lineage = mgmt_lineage.clone();
                        let mut prompt_rx = mgmt_prompt_tx.subscribe();
                        let mut event_rx = mgmt_event_tx.subscribe();
                        let incidents = mgmt_incidents.clone();
                        let protection_state = mgmt_protection_state.clone();
                        let risk_engine = mgmt_risk_engine.clone();
                        let storage = mgmt_storage.clone();

                        tokio::spawn(async move {
                            if let Err(e) = handle_client(
                                stream,
                                role,
                                freeze,
                                lineage,
                                &mut prompt_rx,
                                &mut event_rx,
                                incidents,
                                protection_state,
                                risk_engine,
                                storage,
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
        let ro_protection_state = self.protection_state.clone();
        let ro_risk_engine = self.risk_engine.clone();
        let ro_storage = self.storage.clone();

        loop {
            match ro_listener.accept().await {
                Ok((stream, _)) => {
                    let role = match verify_peer_client(&stream, false) {
                        Ok(role) => role,
                        Err(e) => {
                            warn!("SECURITY: Rejecting unauthorized read-only IPC peer: {}", e);
                            continue;
                        }
                    };
                    let freeze = ro_freeze.clone();
                    let lineage = ro_lineage.clone();
                    let mut prompt_rx = ro_prompt_tx.subscribe();
                    let mut event_rx = ro_event_tx.subscribe();
                    let incidents = ro_incidents.clone();
                    let protection_state = ro_protection_state.clone();
                    let risk_engine = ro_risk_engine.clone();
                    let storage = ro_storage.clone();

                    tokio::spawn(async move {
                        if let Err(e) = handle_client(
                            stream,
                            role,
                            freeze,
                            lineage,
                            &mut prompt_rx,
                            &mut event_rx,
                            incidents,
                            protection_state,
                            risk_engine,
                            storage,
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

/// Authenticate peer credentials with SO_PEERCRED RBAC validation.
pub fn verify_peer_client(
    stream: &UnixStream,
    is_management: bool,
) -> anyhow::Result<ClientRole> {
    let creds = getsockopt(stream, PeerCredentials)?;
    let peer_uid = creds.uid();
    let peer_gid = creds.gid();
    let peer_pid = creds.pid();

    // 1. Root UID is always RootAdmin
    if peer_uid == 0 {
        return Ok(ClientRole::RootAdmin);
    }

    // 2. Management socket requires privileged access
    if is_management {
        // If connecting to management socket from non-root:
        // Must belong to operator group (GID 0 or root group)
        if peer_gid == 0 {
            return Ok(ClientRole::Operator);
        }
        anyhow::bail!(
            "Access Denied: Management socket requires root (UID 0) or operator group (GID 0). Peer UID: {}, GID: {}, PID: {}",
            peer_uid, peer_gid, peer_pid
        );
    }

    // 3. Read-only socket is open to local users
    if peer_uid >= 1000 || peer_uid == nix::unistd::getuid().as_raw() || peer_gid == 0 {
        Ok(ClientRole::ReadOnly)
    } else {
        anyhow::bail!("Unauthorized user UID: {}", peer_uid);
    }
}

/// Backward compatibility helper for existing tests
pub fn verify_peer_client_with_manager(
    stream: &UnixStream,
    is_management: bool,
    _expected_gui_path: &Path,
    _taint_manager: Option<&TaintMapManager>,
) -> anyhow::Result<ClientRole> {
    verify_peer_client(stream, is_management)
}

#[doc(hidden)]
pub async fn handle_ipc_command_for_test(
    cmd: IpcCommand,
    role: ClientRole,
    freeze: &FreezeInspectOrchestrator,
    lineage: &LineageTracker,
    incidents: &Arc<RwLock<std::collections::HashMap<String, String>>>,
    protection_state: &Arc<RwLock<ProtectionState>>,
    risk_engine: Option<&Arc<RwLock<RiskEngine>>>,
    storage: Option<&StorageManager>,
) -> IpcResponse {
    handle_ipc_command(
        cmd,
        role,
        freeze,
        lineage,
        incidents,
        protection_state,
        risk_engine,
        storage,
    ).await
}

async fn handle_client(
    stream: UnixStream,
    role: ClientRole,
    freeze: FreezeInspectOrchestrator,
    lineage: LineageTracker,
    prompt_rx: &mut broadcast::Receiver<PromptRequest>,
    event_rx: &mut broadcast::Receiver<IpcMessage>,
    incidents: Arc<RwLock<std::collections::HashMap<String, String>>>,
    protection_state: Arc<RwLock<ProtectionState>>,
    risk_engine: Option<Arc<RwLock<RiskEngine>>>,
    storage: Option<StorageManager>,
) -> anyhow::Result<()> {
    let (reader, mut writer) = stream.into_split();
    let mut reader = BufReader::new(reader);
    let max_msg_size: u64 = 65536; // 64 KB limit (TASK-P1-18 DoS protection)

    loop {
        let mut line = String::new();
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

            // Inbound message from client with 64KB bounded reader and 5s read timeout
            res = tokio::time::timeout(
                std::time::Duration::from_secs(5),
                reader.read_line(&mut line)
            ) => {
                let n = match res {
                    Ok(Ok(bytes_read)) => bytes_read,
                    Ok(Err(e)) => return Err(e.into()),
                    Err(_) => {
                        debug!("IPC client read timed out (5s limit). Closing connection.");
                        break;
                    }
                };

                if n == 0 {
                    break; // EOF
                }

                if n as u64 >= max_msg_size && !line.ends_with('\n') {
                    warn!("SECURITY: IPC client exceeded maximum 64KB message limit! Terminating connection.");
                    let err_resp = IpcResponse::Error {
                        code: "EMSGSIZE".into(),
                        message: "Message exceeds 64KB buffer limit".into(),
                    };
                    let json = serde_json::to_string(&err_resp)? + "\n";
                    let _ = writer.write_all(json.as_bytes()).await;
                    break;
                }

                let trimmed = line.trim();
                if !trimmed.is_empty() {
                    // Try parsing typed command or legacy message
                    if let Ok(cmd) = serde_json::from_str::<IpcCommand>(trimmed) {
                        let response = handle_ipc_command(
                            cmd,
                            role,
                            &freeze,
                            &lineage,
                            &incidents,
                            &protection_state,
                            risk_engine.as_ref(),
                            storage.as_ref(),
                        ).await;
                        let json = serde_json::to_string(&response)? + "\n";
                        writer.write_all(json.as_bytes()).await?;
                    } else if let Ok(msg) = serde_json::from_str::<IpcMessage>(trimmed) {
                        match msg {
                            IpcMessage::Verdict(verdict) => {
                                if role != ClientRole::RootAdmin {
                                    warn!("SECURITY VIOLATION: Non-root client attempted to submit override verdict for {}", verdict.incident_id);
                                    let err_resp = IpcMessage::AuthError {
                                        message: "Access Denied: Manual verdicts require root administrator authority.".into(),
                                    };
                                    let json = serde_json::to_string(&err_resp)? + "\n";
                                    writer.write_all(json.as_bytes()).await?;
                                    line.clear();
                                    continue;
                                }

                                info!("Received authorized admin override for {}: {:?}", verdict.incident_id, verdict.action);
                                let _ = freeze.apply_verdict(&verdict);
                            }

                            IpcMessage::StatusRequest => {
                                let state = protection_state.read().await;
                                let resp = IpcMessage::StatusResponse {
                                    uptime_secs: state.uptime_secs(),
                                    tracked_processes: lineage.len(),
                                    total_incidents: state.incident_count(),
                                    frozen_count: freeze.frozen_count(),
                                    mode: state.mode.to_string(),
                                };
                                let json = serde_json::to_string(&resp)? + "\n";
                                writer.write_all(json.as_bytes()).await?;
                            }

                            IpcMessage::Unfreeze { tgid } => {
                                if role != ClientRole::RootAdmin {
                                    warn!("SECURITY VIOLATION: Non-root client attempted to unfreeze TGID {}", tgid);
                                    let err_resp = IpcMessage::AuthError {
                                        message: "Access Denied: Unfreeze requires root administrator authority.".into(),
                                    };
                                    let json = serde_json::to_string(&err_resp)? + "\n";
                                    writer.write_all(json.as_bytes()).await?;
                                    line.clear();
                                    continue;
                                }

                                info!("Root admin requested unfreeze for TGID {}", tgid);
                                let _ = freeze.unfreeze(tgid);
                            }

                            IpcMessage::ExportRequest { incident_id } => {
                                let map = incidents.read().await;
                                let report_json = if let Some(mem_json) = map.get(&incident_id) {
                                    mem_json.clone()
                                } else if let Some(ref s) = storage {
                                    s.get_incident(&incident_id)
                                        .ok()
                                        .flatten()
                                        .map(|r| r.details_json)
                                        .unwrap_or_else(|| "{}".to_string())
                                } else {
                                    "{}".to_string()
                                };
                                let resp = IpcMessage::ExportResponse { report_json };
                                let json = serde_json::to_string(&resp)? + "\n";
                                writer.write_all(json.as_bytes()).await?;
                            }

                            _ => {}
                        }
                    } else {
                        warn!("Failed to parse IPC message '{}'", trimmed);
                    }
                }
                line.clear();
            }
        }
    }

    Ok(())
}

async fn handle_ipc_command(
    cmd: IpcCommand,
    role: ClientRole,
    freeze: &FreezeInspectOrchestrator,
    lineage: &LineageTracker,
    incidents: &Arc<RwLock<std::collections::HashMap<String, String>>>,
    protection_state: &Arc<RwLock<ProtectionState>>,
    risk_engine: Option<&Arc<RwLock<RiskEngine>>>,
    storage: Option<&StorageManager>,
) -> IpcResponse {
    match cmd {
        IpcCommand::Status => {
            let state = protection_state.read().await;
            let data = serde_json::json!({
                "uptime_secs": state.uptime_secs(),
                "tracked_processes": lineage.len(),
                "total_incidents": state.incident_count(),
                "frozen_processes": freeze.frozen_count(),
                "protection_active": state.enabled,
                "mode": state.mode.to_string(),
                "role": format!("{:?}", role),
            });
            IpcResponse::Ok(data)
        }
        IpcCommand::Health | IpcCommand::Diagnostics | IpcCommand::Doctor => {
            let state = protection_state.read().await;
            let data = serde_json::json!({
                "status": if state.enabled { "healthy" } else { "degraded" },
                "uptime_secs": state.uptime_secs(),
                "bpf_lsm_active": state.bpf_lsm_active,
                "network_holding_active": state.network_holding_active,
                "protection_active": state.enabled,
                "mode": state.mode.to_string(),
                "tracked_processes": lineage.len(),
                "frozen_processes": freeze.frozen_count(),
            });
            IpcResponse::Ok(data)
        }
        IpcCommand::ProtectionStatus => {
            let state = protection_state.read().await;
            let data = serde_json::json!({
                "protection_active": state.enabled,
                "bpf_lsm": state.bpf_lsm_active,
                "network_holding": state.network_holding_active,
                "mode": state.mode.to_string(),
            });
            IpcResponse::Ok(data)
        }
        IpcCommand::ProtectionEnable => {
            if role != ClientRole::RootAdmin {
                return IpcResponse::Error {
                    code: "EACCES".into(),
                    message: "Root administrator permission required to enable protection".into(),
                };
            }
            let mut state = protection_state.write().await;
            state.enabled = true;
            info!("Protection enabled by admin");
            IpcResponse::Ok(serde_json::json!({ "enabled": true, "mode": state.mode.to_string() }))
        }
        IpcCommand::ProtectionDisable => {
            if role != ClientRole::RootAdmin {
                return IpcResponse::Error {
                    code: "EACCES".into(),
                    message: "Root administrator permission required to disable protection".into(),
                };
            }
            let mut state = protection_state.write().await;
            state.enabled = false;
            warn!("SECURITY WARNING: Protection disabled by admin");
            IpcResponse::Ok(serde_json::json!({ "enabled": false, "mode": state.mode.to_string() }))
        }
        IpcCommand::Unfreeze { tgid } => {
            if role != ClientRole::RootAdmin {
                return IpcResponse::Error {
                    code: "EACCES".into(),
                    message: "Root administrator permission required to unfreeze processes".into(),
                };
            }
            let _ = freeze.unfreeze(tgid);
            IpcResponse::Ok(serde_json::json!({ "unfrozen_tgid": tgid }))
        }
        IpcCommand::IncidentsList { limit, offset } => {
            let mut list: Vec<serde_json::Value> = Vec::new();
            if let Some(s) = storage {
                if let Ok(records) = s.list_incidents(limit.unwrap_or(50), offset.unwrap_or(0)) {
                    for r in records {
                        list.push(serde_json::json!({
                            "incident_id": r.incident_id,
                            "created_at": r.created_at.to_rfc3339(),
                            "severity": r.severity,
                            "risk_score": r.risk_score,
                            "verdict": r.verdict,
                            "summary": r.human_summary,
                        }));
                    }
                }
            }
            if list.is_empty() {
                let map = incidents.read().await;
                for k in map.keys() {
                    list.push(serde_json::json!({ "incident_id": k }));
                }
            }
            IpcResponse::Ok(serde_json::json!({ "incidents": list }))
        }
        IpcCommand::IncidentsClear => {
            if role != ClientRole::RootAdmin {
                return IpcResponse::Error {
                    code: "EACCES".into(),
                    message: "Root administrator permission required to clear incidents".into(),
                };
            }
            let mut map = incidents.write().await;
            let mem_count = map.len();
            map.clear();
            let db_cleared = storage.and_then(|s| s.clear_all_incidents().ok()).unwrap_or(0);
            IpcResponse::Ok(serde_json::json!({
                "status": "cleared",
                "cleared_memory": mem_count,
                "cleared_database": db_cleared,
            }))
        }
        IpcCommand::IncidentsShow { incident_id } => {
            let map = incidents.read().await;
            if let Some(data) = map.get(&incident_id) {
                let parsed: serde_json::Value = serde_json::from_str(data).unwrap_or(serde_json::Value::Null);
                return IpcResponse::Ok(parsed);
            }
            if let Some(s) = storage {
                if let Ok(Some(record)) = s.get_incident(&incident_id) {
                    let parsed: serde_json::Value = serde_json::from_str(&record.details_json)
                        .unwrap_or_else(|_| serde_json::json!({
                            "incident_id": record.incident_id,
                            "created_at": record.created_at.to_rfc3339(),
                            "severity": record.severity,
                            "risk_score": record.risk_score,
                            "verdict": record.verdict,
                            "human_summary": record.human_summary,
                        }));
                    return IpcResponse::Ok(parsed);
                }
            }
            IpcResponse::Error {
                code: "ENOENT".into(),
                message: format!("Incident {} not found", incident_id),
            }
        }
        IpcCommand::IncidentsExport { incident_id, format } => {
            let map = incidents.read().await;
            if let Some(data) = map.get(&incident_id) {
                return IpcResponse::Ok(serde_json::json!({
                    "incident_id": incident_id,
                    "format": format,
                    "data": data,
                }));
            }
            if let Some(s) = storage {
                if let Ok(Some(record)) = s.get_incident(&incident_id) {
                    return IpcResponse::Ok(serde_json::json!({
                        "incident_id": incident_id,
                        "format": format,
                        "data": record.details_json,
                    }));
                }
            }
            IpcResponse::Error {
                code: "ENOENT".into(),
                message: format!("Incident {} not found", incident_id),
            }
        }
        IpcCommand::ProcessInspect { tgid } => {
            if let Some(node) = lineage.get(tgid) {
                IpcResponse::Ok(serde_json::to_value(node).unwrap_or_default())
            } else {
                IpcResponse::Error {
                    code: "ESRCH".into(),
                    message: format!("Process {} not found in lineage graph", tgid),
                }
            }
        }
        IpcCommand::ProcessLineage { tgid } => {
            let chain = lineage.get_ancestor_chain(tgid);
            IpcResponse::Ok(serde_json::to_value(chain).unwrap_or_default())
        }
        IpcCommand::ProcessKill { tgid, reason } => {
            if role != ClientRole::RootAdmin {
                return IpcResponse::Error {
                    code: "EACCES".into(),
                    message: "Root administrator permission required to terminate processes".into(),
                };
            }
            if tgid <= 2 || tgid == std::process::id() {
                return IpcResponse::Error {
                    code: "EPERM".into(),
                    message: format!("Cannot terminate protected system/daemon process {}", tgid),
                };
            }
            let proc_node = lineage.get(tgid).or_else(|| LineageTracker::discover_from_procfs(tgid));
            let (start_time, exe_path) = if let Some(ref n) = proc_node {
                (n.start_time_ns, Some(n.exe_path.clone()))
            } else {
                (0, None)
            };
            let key = crate::lineage::ProcessKey::new(tgid, start_time);
            match crate::response::safe_terminate_process(&key, exe_path.as_deref(), std::time::Duration::from_millis(100)) {
                Ok(_) => {
                    info!("Process {} terminated by admin (reason: {:?})", tgid, reason);
                    IpcResponse::Ok(serde_json::json!({ "terminated_tgid": tgid, "status": "Terminated" }))
                }
                Err(e) => {
                    IpcResponse::Error {
                        code: "ESRCH".into(),
                        message: format!("Failed to terminate process {}: {}", tgid, e),
                    }
                }
            }
        }
        IpcCommand::ProcessSuspend { tgid } => {
            if role != ClientRole::RootAdmin {
                return IpcResponse::Error {
                    code: "EACCES".into(),
                    message: "Root administrator permission required to suspend processes".into(),
                };
            }
            if tgid <= 2 || tgid == std::process::id() {
                return IpcResponse::Error {
                    code: "EPERM".into(),
                    message: format!("Cannot suspend protected system/daemon process {}", tgid),
                };
            }
            let proc_node = lineage.get(tgid).or_else(|| LineageTracker::discover_from_procfs(tgid));
            let (start_time, exe_path) = if let Some(ref n) = proc_node {
                (n.start_time_ns, Some(n.exe_path.clone()))
            } else {
                (0, None)
            };
            let key = crate::lineage::ProcessKey::new(tgid, start_time);
            match crate::response::suspend_process(&key, exe_path.as_deref()) {
                Ok(_) => {
                    info!("Process {} suspended by admin", tgid);
                    IpcResponse::Ok(serde_json::json!({ "suspended_tgid": tgid, "status": "Suspended" }))
                }
                Err(e) => {
                    IpcResponse::Error {
                        code: "ESRCH".into(),
                        message: format!("Failed to suspend process {}: {}", tgid, e),
                    }
                }
            }
        }
        IpcCommand::NetworkIsolate => {
            if role != ClientRole::RootAdmin {
                return IpcResponse::Error {
                    code: "EACCES".into(),
                    message: "Root administrator permission required for network containment".into(),
                };
            }
            let net_block = crate::response::NetworkBlockManager::new();
            let containment = crate::response::HostContainment::new(std::sync::Arc::new(net_block));
            containment.isolate_host();
            IpcResponse::Ok(serde_json::json!({ "containment": "active", "status": "Isolated", "anti_lockout_secs": 300 }))
        }
        IpcCommand::NetworkIsolateTimed { tier, timeout_secs, trusted_ssh_ips } => {
            if role != ClientRole::RootAdmin {
                return IpcResponse::Error {
                    code: "EACCES".into(),
                    message: "Root administrator permission required for network containment".into(),
                };
            }
            let iso_tier = match tier.to_lowercase().as_str() {
                "selective" => crate::network::nftables::IsolationTier::Selective,
                "restricted" => crate::network::nftables::IsolationTier::Restricted,
                _ => crate::network::nftables::IsolationTier::FullIsolation,
            };
            if let Err(e) = crate::network::nftables::NftablesManager::apply_isolation_tier(iso_tier, &trusted_ssh_ips) {
                return IpcResponse::Error {
                    code: "ENETRESET".into(),
                    message: format!("Failed to apply isolation tier: {}", e),
                };
            }
            IpcResponse::Ok(serde_json::json!({
                "containment": "active",
                "tier": format!("{:?}", iso_tier),
                "timeout_secs": timeout_secs,
                "trusted_ssh_ips": trusted_ssh_ips,
            }))
        }
        IpcCommand::NetworkConfirmIsolation => {
            if role != ClientRole::RootAdmin {
                return IpcResponse::Error {
                    code: "EACCES".into(),
                    message: "Root administrator permission required for network containment".into(),
                };
            }
            IpcResponse::Ok(serde_json::json!({ "status": "confirmed", "anti_lockout_disarmed": true }))
        }
        IpcCommand::NetworkUnisolate => {
            if role != ClientRole::RootAdmin {
                return IpcResponse::Error {
                    code: "EACCES".into(),
                    message: "Root administrator permission required for network containment".into(),
                };
            }
            let net_block = crate::response::NetworkBlockManager::new();
            let containment = crate::response::HostContainment::new(std::sync::Arc::new(net_block));
            containment.release_host();
            IpcResponse::Ok(serde_json::json!({ "containment": "released", "status": "Normal" }))
        }
        IpcCommand::PolicyReload => {
            if role != ClientRole::RootAdmin {
                return IpcResponse::Error {
                    code: "EACCES".into(),
                    message: "Root administrator permission required for policy operations".into(),
                };
            }
            let state = protection_state.read().await;
            match sentinel_common::config::RulesConfig::load_from_file(&state.rules_path) {
                Ok(new_rules) => {
                    let count = new_rules.rules.len();
                    if let Some(engine) = risk_engine {
                        let mut eng = engine.write().await;
                        eng.set_rules_config(new_rules);
                    }
                    info!("Rules reloaded successfully from {}: {} active rules", state.rules_path.display(), count);
                    IpcResponse::Ok(serde_json::json!({ "reloaded": true, "rules_count": count }))
                }
                Err(e) => {
                    error!("Failed to reload rules from {}: {}", state.rules_path.display(), e);
                    IpcResponse::Error {
                        code: "EINVAL".into(),
                        message: format!("Failed to reload rules: {}", e),
                    }
                }
            }
        }
        IpcCommand::PolicyList | IpcCommand::RulesList => {
            if let Some(engine) = risk_engine {
                let eng = engine.read().await;
                let rules = eng.rules_config();
                IpcResponse::Ok(serde_json::to_value(&rules.rules).unwrap_or_default())
            } else {
                IpcResponse::Ok(serde_json::json!([]))
            }
        }
        IpcCommand::PolicyShow { policy_id } | IpcCommand::RulesShow { rule_id: policy_id } => {
            if let Some(engine) = risk_engine {
                let eng = engine.read().await;
                if let Some(rule) = eng.rules_config().rules.get(&policy_id) {
                    return IpcResponse::Ok(serde_json::to_value(rule).unwrap_or_default());
                }
            }
            IpcResponse::Error {
                code: "ENOENT".into(),
                message: format!("Rule/Policy {} not found", policy_id),
            }
        }
        IpcCommand::PolicyValidate { policy_content } => {
            match toml::from_str::<sentinel_common::config::RulesConfig>(&policy_content) {
                Ok(cfg) => IpcResponse::Ok(serde_json::json!({ "valid": true, "rules_count": cfg.rules.len() })),
                Err(e) => IpcResponse::Error {
                    code: "EINVAL".into(),
                    message: format!("Policy validation error: {}", e),
                },
            }
        }
        IpcCommand::NetworkStatus => {
            let state = protection_state.read().await;
            IpcResponse::Ok(serde_json::json!({
                "network_holding_active": state.network_holding_active,
                "mode": state.mode.to_string(),
            }))
        }
        IpcCommand::NetworkBlocked => {
            IpcResponse::Ok(serde_json::json!({ "blocked_ips": [] }))
        }
        IpcCommand::ConfigValidate => {
            let state = protection_state.read().await;
            match sentinel_common::config::SentinelConfig::load_from_file(&state.config_path) {
                Ok(_) => IpcResponse::Ok(serde_json::json!({ "valid": true, "path": state.config_path.display().to_string() })),
                Err(e) => IpcResponse::Error {
                    code: "EINVAL".into(),
                    message: format!("Config validation error: {}", e),
                },
            }
        }
        IpcCommand::EventsList { .. } | IpcCommand::EventsShow { .. } | IpcCommand::EventsExport { .. } => {
            IpcResponse::Error {
                code: "ENOTSUP".into(),
                message: "Event queries are not supported on this endpoint".into(),
            }
        }
    }
}
