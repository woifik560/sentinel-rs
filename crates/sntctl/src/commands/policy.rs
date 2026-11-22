//! `sntctl policy` subcommands.

use crate::client::send_command;
use crate::output::{print_header, print_json};
use clap::Subcommand;
use sentinel_common::ipc::{IpcCommand, IpcResponse};
use std::path::{Path, PathBuf};

#[derive(Subcommand, Debug)]
pub enum PolicyActionCmd {
    /// List configured security policy rules
    List,
    /// Validate policy configuration file
    Validate {
        #[arg(short, long, default_value = "/etc/sentinel/rules.toml")]
        file: PathBuf,
    },
    /// Hot-reload policy rules without restarting daemon [Requires Root]
    Reload,
}

pub async fn run_policy(
    socket_path: &Path,
    action: PolicyActionCmd,
    json_output: bool,
) -> anyhow::Result<()> {
    match action {
        PolicyActionCmd::List => {
            let resp = send_command(socket_path, IpcCommand::PolicyList).await?;
            match resp {
                IpcResponse::Ok(data) => {
                    if json_output {
                        print_json(&data)?;
                    } else {
                        print_header("Configured Security Policies");
                        print_json(&data)?;
                    }
                }
                IpcResponse::Error { code, message } => eprintln!("Error [{}]: {}", code, message),
                _ => println!("Unexpected response: {:?}", resp),
            }
        }
        PolicyActionCmd::Validate { file } => {
            println!("Validating policy file: {}...", file.display());
            match sentinel_common::config::RulesConfig::load_from_file(&file) {
                Ok(rules) => {
                    println!(
                        "[OK] Policy file is valid. Loaded {} rules successfully.",
                        rules.rules.len()
                    );
                }
                Err(e) => {
                    eprintln!("[FAIL] Policy validation failed: {}", e);
                }
            }
        }
        PolicyActionCmd::Reload => {
            let resp = send_command(socket_path, IpcCommand::PolicyReload).await?;
            match resp {
                IpcResponse::Ok(_) => println!("[OK] Security policy reloaded successfully."),
                IpcResponse::Error { code, message } => {
                    eprintln!("Failed to reload policy [{}]: {}", code, message)
                }
                _ => println!("Unexpected response: {:?}", resp),
            }
        }
    }
    Ok(())
}
