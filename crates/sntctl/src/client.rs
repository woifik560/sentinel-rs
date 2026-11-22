//! IPC socket client for sntctl.

use sentinel_common::ipc::{IpcCommand, IpcResponse};
use std::path::Path;
use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader};
use tokio::net::UnixStream;

pub const DEFAULT_PRIVILEGED_SOCKET: &str = "/run/sentinel/sentinel.sock";
pub const DEFAULT_READONLY_SOCKET: &str = "/run/sentinel/sentinel-ro.sock";

pub async fn connect_socket(socket_path: &Path) -> anyhow::Result<UnixStream> {
    UnixStream::connect(socket_path).await.map_err(|e| {
        anyhow::anyhow!(
            "Failed to connect to sentineld IPC socket at {}: {}\nIs 'sentineld' running? Privileged commands require root/sudo.",
            socket_path.display(),
            e
        )
    })
}

pub async fn send_command(socket_path: &Path, cmd: IpcCommand) -> anyhow::Result<IpcResponse> {
    let stream = connect_socket(socket_path).await?;
    let (reader, mut writer) = stream.into_split();
    let mut reader = BufReader::new(reader);

    let payload = serde_json::to_string(&cmd)? + "\n";
    writer.write_all(payload.as_bytes()).await?;

    let mut response_line = String::new();
    let bytes = reader.read_line(&mut response_line).await?;
    if bytes == 0 {
        anyhow::bail!("Server closed connection without responding");
    }

    let response: IpcResponse = serde_json::from_str(response_line.trim())?;
    Ok(response)
}
