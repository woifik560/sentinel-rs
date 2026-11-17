//! `sntctl events` subcommands.

use clap::Subcommand;
use std::path::Path;
use sentinel_common::ipc::{IpcCommand, IpcResponse};
use crate::client::send_command;
use crate::output::{print_header, print_json};

#[derive(Subcommand, Debug)]
pub enum EventsAction {
    /// List recent collected events
    List {
        #[arg(short, long, default_value = "50")]
        limit: usize,
    },
    /// Show details for a specific event ID
    Show {
        event_id: String,
    },
    /// Export events in JSON format
    Export {
        #[arg(short, long, default_value = "1000")]
        limit: usize,
    },
}

pub async fn run_events(socket_path: &Path, action: EventsAction, json_output: bool) -> anyhow::Result<()> {
    let cmd = match action {
        EventsAction::List { limit } => IpcCommand::EventsList { limit: Some(limit), offset: Some(0) },
        EventsAction::Show { event_id } => IpcCommand::EventsShow { event_id },
        EventsAction::Export { limit } => IpcCommand::EventsList { limit: Some(limit), offset: Some(0) },
    };

    let resp = send_command(socket_path, cmd).await?;
    match resp {
        IpcResponse::Ok(data) => {
            if json_output {
                print_json(&data)?;
            } else {
                print_header("Security Events");
                print_json(&data)?;
            }
        }
        IpcResponse::Error { code, message } => {
            eprintln!("Error querying events [{}]: {}", code, message);
        }
        _ => {
            println!("Unexpected response: {:?}", resp);
        }
    }
    Ok(())
}
