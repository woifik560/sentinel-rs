//! `sntctl incidents` subcommands.

use crate::client::send_command;
use crate::output::{print_header, print_json};
use clap::Subcommand;
use sentinel_common::ipc::{IpcCommand, IpcResponse};
use std::path::Path;

#[derive(Subcommand, Debug)]
pub enum IncidentsAction {
    /// List detected security incidents
    List {
        #[arg(short, long, default_value = "20")]
        limit: usize,
    },
    /// Show full forensic incident report by incident ID
    Show { incident_id: String },
    /// Export incident report in JSON format
    Export { incident_id: String },
    /// Clear all security incidents
    Clear,
}

pub async fn run_incidents(
    socket_path: &Path,
    action: IncidentsAction,
    json_output: bool,
) -> anyhow::Result<()> {
    let cmd = match action {
        IncidentsAction::List { limit } => IpcCommand::IncidentsList {
            limit: Some(limit),
            offset: Some(0),
        },
        IncidentsAction::Show { incident_id } => IpcCommand::IncidentsShow { incident_id },
        IncidentsAction::Export { incident_id } => IpcCommand::IncidentsShow { incident_id },
        IncidentsAction::Clear => IpcCommand::IncidentsClear,
    };

    let resp = send_command(socket_path, cmd).await?;
    match resp {
        IpcResponse::Ok(data) => {
            if json_output {
                print_json(&data)?;
            } else {
                print_header("Security Incidents");
                print_json(&data)?;
            }
        }
        IpcResponse::Error { code, message } => {
            eprintln!("Error querying incidents [{}]: {}", code, message);
        }
        _ => {
            println!("Unexpected response: {:?}", resp);
        }
    }
    Ok(())
}
