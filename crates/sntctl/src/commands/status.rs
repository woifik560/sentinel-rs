//! `sntctl status` command implementation.

use std::path::Path;
use sentinel_common::ipc::{IpcCommand, IpcResponse};
use crate::client::send_command;
use crate::output::{print_header, print_json, print_row};

pub async fn run_status(socket_path: &Path, json_output: bool) -> anyhow::Result<()> {
    let resp = send_command(socket_path, IpcCommand::Status).await?;
    match resp {
        IpcResponse::Ok(data) => {
            if json_output {
                print_json(&data)?;
            } else {
                print_header("Sentinel-RS Agent Status");
                if let Some(obj) = data.as_object() {
                    for (k, v) in obj {
                        let val_str = v.as_str().map(|s| s.to_string()).unwrap_or_else(|| v.to_string());
                        print_row(k, &val_str);
                    }
                }
            }
        }
        IpcResponse::Error { code, message } => {
            eprintln!("Error querying status [{}]: {}", code, message);
        }
        _ => {
            println!("Unexpected response: {:?}", resp);
        }
    }
    Ok(())
}
