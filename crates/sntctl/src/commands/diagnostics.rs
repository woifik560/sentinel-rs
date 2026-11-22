//! `sntctl diagnostics` command implementation.

use crate::client::send_command;
use crate::output::{print_header, print_json};
use sentinel_common::ipc::{IpcCommand, IpcResponse};
use std::path::Path;

pub async fn run_diagnostics(socket_path: &Path, json_output: bool) -> anyhow::Result<()> {
    let resp = send_command(socket_path, IpcCommand::Diagnostics).await?;
    match resp {
        IpcResponse::Ok(data) => {
            if json_output {
                print_json(&data)?;
            } else {
                print_header("Agent Diagnostics");
                print_json(&data)?;
            }
        }
        IpcResponse::Error { code, message } => {
            eprintln!("Error querying diagnostics [{}]: {}", code, message);
        }
        _ => {
            println!("Unexpected response: {:?}", resp);
        }
    }
    Ok(())
}
