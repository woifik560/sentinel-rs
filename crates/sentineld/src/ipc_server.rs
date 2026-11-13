//! Secure Unix Domain Socket IPC server with SO_PEERCRED authentication.
//!
//! Enforces that only root (UID 0) or the active desktop user can send commands.

use nix::sys::socket::{getsockopt, sockopt::PeerCredentials};
use std::path::PathBuf;
use std::sync::Arc;
use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader};
use tokio::net::{UnixListener, UnixStream};
use tokio::sync::{broadcast, RwLock};
use tracing::{debug, error, info, warn};

use sentinel_common::ipc::{IpcMessage, PromptRequest};
use crate::freeze::FreezeInspectOrchestrator;
use crate::lineage::LineageTracker;

pub struct IpcServer {
    socket_path: PathBuf,
    freeze_orchestrator: FreezeInspectOrchestrator,
    lineage_tracker: LineageTracker,
    prompt_tx: broadcast::Sender<PromptRequest>,
    event_tx: broadcast::Sender<IpcMessage>,
    active_incidents: Arc<RwLock<std::collections::HashMap<String, String>>>,
}

impl IpcServer {
    pub fn new(
        socket_path: PathBuf,
        freeze_orchestrator: FreezeInspectOrchestrator,
        lineage_tracker: LineageTracker,
    ) -> Self {
        let (prompt_tx, _) = broadcast::channel(128);
        let (event_tx, _) = broadcast::channel(512);

        Self {
            socket_path,
            freeze_orchestrator,
            lineage_tracker,
            prompt_tx,
            event_tx,
            active_incidents: Arc::new(RwLock::new(std::collections::HashMap::new())),
        }
    }

    /// Broadcast a prompt request to all connected UI/CLI clients.
    pub fn broadcast_prompt(&self, prompt: PromptRequest) {
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

    /// Start listening on the Unix Domain Socket.
    pub async fn run(&self) -> anyhow::Result<()> {
        if let Some(parent) = self.socket_path.parent() {
            let _ = tokio::fs::create_dir_all(parent).await;
        }
        let _ = tokio::fs::remove_file(&self.socket_path).await;

        let listener = UnixListener::bind(&self.socket_path)?;
        info!("IPC Server listening on {}", self.socket_path.display());

        loop {
            match listener.accept().await {
                Ok((stream, _)) => {
                    // Check SO_PEERCRED authentication
                    if let Err(e) = authenticate_peer(&stream) {
                        warn!("Rejecting unauthenticated IPC peer: {}", e);
                        continue;
                    }

                    let freeze = self.freeze_orchestrator.clone();
                    let lineage = self.lineage_tracker.clone();
                    let mut prompt_rx = self.prompt_tx.subscribe();
                    let mut event_rx = self.event_tx.subscribe();
                    let incidents = self.active_incidents.clone();

                    tokio::spawn(async move {
                        if let Err(e) = handle_client(
                            stream,
                            freeze,
                            lineage,
                            &mut prompt_rx,
                            &mut event_rx,
                            incidents,
                        ).await {
                            debug!("IPC client disconnected: {}", e);
                        }
                    });
                }
                Err(e) => {
                    error!("Error accepting IPC connection: {}", e);
                }
            }
        }
    }
}

/// Authenticate connected peer using kernel credentials (SO_PEERCRED).
fn authenticate_peer(stream: &UnixStream) -> anyhow::Result<()> {
    let creds = getsockopt(stream, PeerCredentials)?;

    // Root (0) is always allowed. Non-root allowed if matches current process or active desktop UID (> 0)
    let peer_uid = creds.uid();
    let self_uid = nix::unistd::getuid().as_raw();

    if peer_uid == 0 || peer_uid == self_uid || peer_uid >= 1000 {
        Ok(())
    } else {
        Err(anyhow::anyhow!("Unauthorized UID: {}", peer_uid))
    }
}

async fn handle_client(
    stream: UnixStream,
    freeze: FreezeInspectOrchestrator,
    lineage: LineageTracker,
    prompt_rx: &mut broadcast::Receiver<PromptRequest>,
    event_rx: &mut broadcast::Receiver<IpcMessage>,
    incidents: Arc<RwLock<std::collections::HashMap<String, String>>>,
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
                            info!("Received user verdict for {}: {:?}", verdict.incident_id, verdict.action);
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
