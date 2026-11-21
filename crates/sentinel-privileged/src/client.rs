//! IPC Client for sending requests to the privileged helper daemon.

use std::path::PathBuf;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::UnixStream;
use super::{PrivilegedOp, PrivilegedResult};

pub struct PrivilegedClient {
    socket_path: PathBuf,
}

impl Default for PrivilegedClient {
    fn default() -> Self {
        Self {
            socket_path: PathBuf::from("/run/sentinel/privileged.sock"),
        }
    }
}

impl PrivilegedClient {
    pub fn new(socket_path: PathBuf) -> Self {
        Self { socket_path }
    }

    pub fn is_available(&self) -> bool {
        self.socket_path.exists()
    }

    pub async fn execute(&self, op: PrivilegedOp) -> anyhow::Result<PrivilegedResult> {
        let mut stream = UnixStream::connect(&self.socket_path).await?;
        let payload = serde_json::to_string(&op)?;
        stream.write_all(payload.as_bytes()).await?;
        stream.write_all(b"\n").await?;
        stream.flush().await?;

        let mut buffer = Vec::new();
        let mut take_stream = stream.take(65536);
        take_stream.read_to_end(&mut buffer).await?;

        let resp: PrivilegedResult = serde_json::from_slice(&buffer)?;
        Ok(resp)
    }
}
