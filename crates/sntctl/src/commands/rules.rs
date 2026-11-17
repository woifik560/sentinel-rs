//! `sntctl rules` subcommands.

use clap::Subcommand;
use std::path::Path;
use sentinel_common::ipc::{IpcCommand, IpcResponse};
use crate::client::send_command;
use crate::output::{print_header, print_json};

#[derive(Subcommand, Debug)]
pub enum RulesAction {
    /// List all active behavior and detection rules
    List,
    /// Show details of a specific rule
    Show {
        rule_id: String,
    },
}

pub async fn run_rules(socket_path: &Path, action: RulesAction, json_output: bool) -> anyhow::Result<()> {
    let cmd = match action {
        RulesAction::List => IpcCommand::RulesList,
        RulesAction::Show { rule_id } => IpcCommand::RulesShow { rule_id },
    };

    let resp = send_command(socket_path, cmd).await?;
    match resp {
        IpcResponse::Ok(data) => {
            if json_output {
                print_json(&data)?;
            } else {
                print_header("Detection Rules");
                print_json(&data)?;
            }
        }
        IpcResponse::Error { code, message } => {
            eprintln!("Error querying rules [{}]: {}", code, message);
        }
        _ => {
            println!("Unexpected response: {:?}", resp);
        }
    }
    Ok(())
}
