//! IPC Client for sending requests to the privileged helper daemon.

use super::{PrivilegedOp, PrivilegedResult};
use std::path::PathBuf;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::UnixStream;

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

    #[cfg(unix)]
    pub fn execute_sync(&self, op: &PrivilegedOp) -> anyhow::Result<PrivilegedResult> {
        use std::io::{BufRead, BufReader, Write};
        use std::os::unix::net::UnixStream as StdUnixStream;

        let mut stream = StdUnixStream::connect(&self.socket_path)?;
        stream.set_read_timeout(Some(std::time::Duration::from_secs(5)))?;
        stream.set_write_timeout(Some(std::time::Duration::from_secs(5)))?;

        let payload = serde_json::to_string(op)?;
        stream.write_all(payload.as_bytes())?;
        stream.write_all(b"\n")?;
        stream.flush()?;

        let mut reader = BufReader::new(stream);
        let mut response_line = String::new();
        reader.read_line(&mut response_line)?;
        let resp: PrivilegedResult = serde_json::from_str(&response_line)?;
        Ok(resp)
    }

    #[cfg(not(unix))]
    pub fn execute_sync(&self, _op: &PrivilegedOp) -> anyhow::Result<PrivilegedResult> {
        anyhow::bail!("Unix Domain Sockets not supported on this platform")
    }
}
