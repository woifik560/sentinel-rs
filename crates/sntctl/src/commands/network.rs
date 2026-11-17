//! `sntctl network` subcommands.

use clap::Subcommand;
use std::path::Path;
use sentinel_common::ipc::{IpcCommand, IpcResponse};
use crate::client::send_command;
use crate::output::{print_header, print_json};

#[derive(Subcommand, Debug)]
pub enum NetworkAction {
    /// Show Netfilter and NFQUEUE protection status
    Status,
    /// List currently isolated or blocked processes and destinations
    Blocked,
    /// Engage emergency host network containment
    Isolate,
    /// Release emergency host network containment
    Unisolate,
}

pub async fn run_network(socket_path: &Path, action: NetworkAction, json_output: bool) -> anyhow::Result<()> {
    let cmd = match action {
        NetworkAction::Status => IpcCommand::NetworkStatus,
        NetworkAction::Blocked => IpcCommand::NetworkBlocked,
        NetworkAction::Isolate => IpcCommand::NetworkIsolate,
        NetworkAction::Unisolate => IpcCommand::NetworkUnisolate,
    };

    let resp = send_command(socket_path, cmd).await?;
    match resp {
        IpcResponse::Ok(data) => {
            if json_output {
                print_json(&data)?;
            } else {
                match action {
                    NetworkAction::Isolate => println!("Host network containment successfully activated"),
                    NetworkAction::Unisolate => println!("Host network containment successfully released"),
                    _ => {
                        print_header("Network Protection Status");
                        print_json(&data)?;
                    }
                }
            }
        }
        IpcResponse::Error { code, message } => {
            eprintln!("Error querying network status [{}]: {}", code, message);
        }
        _ => {
            println!("Unexpected response: {:?}", resp);
        }
    }
    Ok(())
}
