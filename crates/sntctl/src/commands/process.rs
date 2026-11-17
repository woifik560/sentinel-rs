//! `sntctl process` subcommands.

use clap::Subcommand;
use std::path::Path;
use sentinel_common::ipc::{IpcCommand, IpcResponse};
use crate::client::send_command;
use crate::output::{print_header, print_json};

#[derive(Subcommand, Debug)]
pub enum ProcessAction {
    /// Inspect details and attributes of a tracked process
    Inspect {
        tgid: u32,
    },
    /// Show full ancestor lineage tree for a process
    Lineage {
        tgid: u32,
    },
}

pub async fn run_process(socket_path: &Path, action: ProcessAction, json_output: bool) -> anyhow::Result<()> {
    let cmd = match action {
        ProcessAction::Inspect { tgid } => IpcCommand::ProcessInspect { tgid },
        ProcessAction::Lineage { tgid } => IpcCommand::ProcessLineage { tgid },
    };

    let resp = send_command(socket_path, cmd).await?;
    match resp {
        IpcResponse::Ok(data) => {
            if json_output {
                print_json(&data)?;
            } else {
                print_header("Process Inspection");
                print_json(&data)?;
            }
        }
        IpcResponse::Error { code, message } => {
            eprintln!("Error inspecting process [{}]: {}", code, message);
        }
        _ => {
            println!("Unexpected response: {:?}", resp);
        }
    }
    Ok(())
}
