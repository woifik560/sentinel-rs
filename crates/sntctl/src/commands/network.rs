//! `sntctl network` subcommands.

use clap::Subcommand;
use std::path::Path;
use sentinel_common::ipc::{IpcCommand, IpcResponse};
use crate::client::send_command;
use crate::output::{print_header, print_json};

#[derive(Subcommand, Debug)]
pub enum NetworkAction {
    /// Show Netfilter, NFQUEUE, and isolation status
    Status,
    /// List currently isolated or blocked processes and destinations
    Blocked,
    /// Engage emergency host network containment (with Anti-Lockout safety timer)
    Isolate {
        /// Isolation tier: selective, restricted, full
        #[arg(short, long, default_value = "full")]
        tier: String,
        /// Anti-lockout timeout in seconds (auto-rollback if not confirmed; 0 = permanent)
        #[arg(short, long, default_value_t = 300)]
        timeout: u64,
        /// Trusted SSH IP addresses exempted from isolation
        #[arg(long)]
        trusted_ssh_ip: Vec<String>,
    },
    /// Confirm network isolation and disarm the Anti-Lockout auto-rollback timer
    ConfirmIsolation,
    /// Release emergency host network containment
    Unisolate,
}

pub async fn run_network(socket_path: &Path, action: NetworkAction, json_output: bool) -> anyhow::Result<()> {
    let cmd = match &action {
        NetworkAction::Status => IpcCommand::NetworkStatus,
        NetworkAction::Blocked => IpcCommand::NetworkBlocked,
        NetworkAction::Isolate { tier, timeout, trusted_ssh_ip } => {
            IpcCommand::NetworkIsolateTimed {
                tier: tier.clone(),
                timeout_secs: *timeout,
                trusted_ssh_ips: trusted_ssh_ip.clone(),
            }
        }
        NetworkAction::ConfirmIsolation => IpcCommand::NetworkConfirmIsolation,
        NetworkAction::Unisolate => IpcCommand::NetworkUnisolate,
    };

    let resp = send_command(socket_path, cmd).await?;
    match resp {
        IpcResponse::Ok(data) => {
            if json_output {
                print_json(&data)?;
            } else {
                match action {
                    NetworkAction::Isolate { timeout, .. } => {
                        println!("Host network containment successfully activated.");
                        if timeout > 0 {
                            println!(
                                "ANTI-LOCKOUT TIMER: {} seconds remaining. Run 'sntctl network confirm-isolation' to keep isolation active.",
                                timeout
                            );
                        }
                    }
                    NetworkAction::ConfirmIsolation => {
                        println!("Network isolation confirmed! Anti-Lockout timer disarmed.");
                    }
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
