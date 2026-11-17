//! `sntctl protection` subcommands.

use clap::Subcommand;
use std::path::Path;
use sentinel_common::ipc::{IpcCommand, IpcResponse};
use crate::client::send_command;
use crate::output::{print_header, print_json, print_row};

#[derive(Subcommand, Debug)]
pub enum ProtectionAction {
    /// Show active protection status
    Status,
    /// Enable all defensive protections [Requires Root]
    Enable,
    /// Disable defensive protections (switch to audit mode) [Requires Root]
    Disable,
}

pub async fn run_protection(socket_path: &Path, action: ProtectionAction, json_output: bool) -> anyhow::Result<()> {
    let cmd = match action {
        ProtectionAction::Status => IpcCommand::ProtectionStatus,
        ProtectionAction::Enable => IpcCommand::ProtectionEnable,
        ProtectionAction::Disable => IpcCommand::ProtectionDisable,
    };

    let resp = send_command(socket_path, cmd).await?;
    match resp {
        IpcResponse::Ok(data) => {
            if json_output {
                print_json(&data)?;
            } else {
                print_header("Protection Status");
                if let Some(obj) = data.as_object() {
                    for (k, v) in obj {
                        let val_str = v.as_str().map(|s| s.to_string()).unwrap_or_else(|| v.to_string());
                        print_row(k, &val_str);
                    }
                }
            }
        }
        IpcResponse::Error { code, message } => {
            eprintln!("Error executing protection command [{}]: {}", code, message);
        }
        _ => {
            println!("Unexpected response: {:?}", resp);
        }
    }
    Ok(())
}
