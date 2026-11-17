//! `sntctl health` command implementation.

use std::path::Path;
use sentinel_common::ipc::{IpcCommand, IpcResponse};
use crate::client::send_command;
use crate::output::{print_header, print_json, print_row};

pub async fn run_health(socket_path: &Path, json_output: bool) -> anyhow::Result<()> {
    let resp = send_command(socket_path, IpcCommand::Health).await?;
    match resp {
        IpcResponse::Health(report) => {
            if json_output {
                print_json(&report)?;
            } else {
                print_header("Sentinel-RS Health Status");
                print_row("Overall Status", &format!("{}", report.overall_status));
                print_row("Uptime", &format!("{}s", report.uptime_secs));
                println!("\nSubsystem Status:");
                for sub in &report.subsystems {
                    println!("  • {:<22} [{}] - {}", sub.id, sub.status, sub.message);
                }
            }
        }
        IpcResponse::Ok(data) => {
            if json_output {
                print_json(&data)?;
            } else {
                print_header("Sentinel-RS Health Status");
                if let Some(obj) = data.as_object() {
                    for (k, v) in obj {
                        let val_str = v.as_str().map(|s| s.to_string()).unwrap_or_else(|| v.to_string());
                        print_row(k, &val_str);
                    }
                }
            }
        }
        IpcResponse::Error { code, message } => {
            eprintln!("Error querying health [{}]: {}", code, message);
        }
        _ => {
            println!("Unexpected response: {:?}", resp);
        }
    }
    Ok(())
}
