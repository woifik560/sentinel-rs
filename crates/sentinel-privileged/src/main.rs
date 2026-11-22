//! Minimal privileged helper daemon for Sentinel-RS.
//! Runs with bounded capabilities (CAP_NET_ADMIN, CAP_KILL, CAP_BPF)
//! and executes strictly verified system operations over /run/sentinel/privileged.sock.

use nix::sys::socket::{getsockopt, sockopt::PeerCredentials};
use std::path::PathBuf;
use std::sync::Arc;
use tokio::io::{AsyncBufReadExt, AsyncReadExt, AsyncWriteExt, BufReader};
use tokio::net::UnixListener;
use tokio::sync::Semaphore;
use tracing::{error, info, warn};

use sentinel_privileged::server::PrivilegedExecutor;
use sentinel_privileged::{PrivilegedOp, PrivilegedResult};

const MAX_PAYLOAD_BYTES: u64 = 65536;
const MAX_CONCURRENT_CLIENTS: usize = 16;

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    tracing_subscriber::fmt().with_target(false).init();

    info!("Starting Sentinel Privileged Helper daemon (sentinel-privileged)...");

    // Check and recover leftover or expired anti-lockout state from a previous run/crash
    PrivilegedExecutor::check_and_recover_lockout_state();

    let socket_path = PathBuf::from("/run/sentinel/privileged.sock");
    if let Some(parent) = socket_path.parent() {
        tokio::fs::create_dir_all(parent).await?;
    }
    let _ = tokio::fs::remove_file(&socket_path).await;

    let listener = UnixListener::bind(&socket_path)?;

    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(&socket_path, std::fs::Permissions::from_mode(0o600)).map_err(
            |e| {
                anyhow::anyhow!(
                    "CRITICAL: Failed to enforce 0600 permissions on {}: {}",
                    socket_path.display(),
                    e
                )
            },
        )?;
    }

    info!("Privileged helper listening on {}", socket_path.display());

    let semaphore = Arc::new(Semaphore::new(MAX_CONCURRENT_CLIENTS));
    let shutdown_socket_path = socket_path.clone();

    tokio::select! {
        res = run_server(listener, semaphore) => {
            if let Err(e) = res {
                error!("Privileged server terminated with error: {}", e);
            }
        }
        _ = tokio::signal::ctrl_c() => {
            info!("Received shutdown signal (Ctrl+C), cleaning up privileged socket...");
        }
    }

    let _ = tokio::fs::remove_file(&shutdown_socket_path).await;
    info!("Privileged helper stopped cleanly.");
    Ok(())
}

async fn run_server(listener: UnixListener, semaphore: Arc<Semaphore>) -> anyhow::Result<()> {
    loop {
        match listener.accept().await {
            Ok((stream, _)) => {
                // Verify peer credentials: only root (UID 0) allowed
                #[cfg(unix)]
                {
                    match getsockopt(&stream, PeerCredentials) {
                        Ok(creds) => {
                            let uid = creds.uid();
                            if uid != 0 {
                                warn!("SECURITY: Rejecting non-root connection to privileged socket (UID: {})", uid);
                                continue;
                            }
                        }
                        Err(e) => {
                            warn!(
                                "Failed to query peer credentials: {}. Rejecting connection.",
                                e
                            );
                            continue;
                        }
                    }
                }

                let permit = match semaphore.clone().try_acquire_owned() {
                    Ok(p) => p,
                    Err(_) => {
                        warn!(
                            "Privileged helper saturated: max connections ({}) reached. Rejecting.",
                            MAX_CONCURRENT_CLIENTS
                        );
                        let (_, mut writer) = stream.into_split();
                        let res = PrivilegedResult::Error {
                            code: "EBUSY".into(),
                            message: "Privileged helper connection limit exceeded".into(),
                        };
                        if let Ok(json) = serde_json::to_string(&res) {
                            let _ = writer.write_all(json.as_bytes()).await;
                            let _ = writer.write_all(b"\n").await;
                        }
                        continue;
                    }
                };

                tokio::spawn(async move {
                    let _permit = permit;
                    let (reader, mut writer) = stream.into_split();
                    let mut limited_reader = BufReader::new(reader.take(MAX_PAYLOAD_BYTES + 1));
                    let mut buf = Vec::new();

                    match limited_reader.read_until(b'\n', &mut buf).await {
                        Ok(n) => {
                            if n as u64 > MAX_PAYLOAD_BYTES {
                                let res = PrivilegedResult::Error {
                                    code: "EMSGSIZE".into(),
                                    message: format!(
                                        "Payload exceeds maximum allowed size of {} bytes",
                                        MAX_PAYLOAD_BYTES
                                    ),
                                };
                                if let Ok(json) = serde_json::to_string(&res) {
                                    let _ = writer.write_all(json.as_bytes()).await;
                                    let _ = writer.write_all(b"\n").await;
                                }
                                return;
                            }

                            if n == 0 || !buf.ends_with(b"\n") {
                                let res = PrivilegedResult::Error {
                                    code: "EINVAL".into(),
                                    message: "Malformed or truncated request".into(),
                                };
                                if let Ok(json) = serde_json::to_string(&res) {
                                    let _ = writer.write_all(json.as_bytes()).await;
                                    let _ = writer.write_all(b"\n").await;
                                }
                                return;
                            }

                            let line = match std::str::from_utf8(&buf[..buf.len() - 1]) {
                                Ok(s) => s.trim(),
                                Err(_) => {
                                    let res = PrivilegedResult::Error {
                                        code: "EINVAL".into(),
                                        message: "Invalid UTF-8 payload".into(),
                                    };
                                    if let Ok(json) = serde_json::to_string(&res) {
                                        let _ = writer.write_all(json.as_bytes()).await;
                                        let _ = writer.write_all(b"\n").await;
                                    }
                                    return;
                                }
                            };

                            let result = match serde_json::from_str::<PrivilegedOp>(line) {
                                Ok(op) => PrivilegedExecutor::dispatch(op),
                                Err(e) => PrivilegedResult::Error {
                                    code: "EINVAL".into(),
                                    message: format!("Malformed command: {}", e),
                                },
                            };

                            if let Ok(json) = serde_json::to_string(&result) {
                                let _ = writer.write_all(json.as_bytes()).await;
                                let _ = writer.write_all(b"\n").await;
                            }
                        }
                        Err(e) => {
                            warn!("Error reading from privileged client: {}", e);
                        }
                    }
                });
            }
            Err(e) => error!("Error accepting connection on privileged socket: {}", e),
        }
    }
}
