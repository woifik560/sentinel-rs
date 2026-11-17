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
    /// Safely terminate a process with anti-PID-reuse verification
    Kill {
        tgid: u32,
        #[arg(short, long)]
        reason: Option<String>,
    },
    /// Suspend a process for forensic inspection
    Suspend {
        tgid: u32,
    },
}

pub async fn run_process(socket_path: &Path, action: ProcessAction, json_output: bool) -> anyhow::Result<()> {
    let cmd = match &action {
        ProcessAction::Inspect { tgid } => IpcCommand::ProcessInspect { tgid: *tgid },
        ProcessAction::Lineage { tgid } => IpcCommand::ProcessLineage { tgid: *tgid },
        ProcessAction::Kill { tgid, reason } => IpcCommand::ProcessKill { tgid: *tgid, reason: reason.clone() },
        ProcessAction::Suspend { tgid } => IpcCommand::ProcessSuspend { tgid: *tgid },
    };

    let resp = send_command(socket_path, cmd).await?;
    match resp {
        IpcResponse::Ok(data) => {
            if json_output {
                print_json(&data)?;
            } else {
                match action {
                    ProcessAction::Kill { tgid, .. } => println!("Process {} successfully terminated", tgid),
                    ProcessAction::Suspend { tgid } => println!("Process {} successfully suspended", tgid),
                    _ => {
                        print_header("Process Inspection");
                        print_json(&data)?;
                    }
                }
            }
        }
        IpcResponse::Error { code, message } => {
            eprintln!("Error executing process action [{}]: {}", code, message);
        }
        _ => {
            println!("Unexpected response: {:?}", resp);
        }
    }
    Ok(())
}
