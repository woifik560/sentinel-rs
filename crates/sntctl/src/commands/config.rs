//! `sntctl config` subcommands.

use clap::Subcommand;
use std::path::{Path, PathBuf};

#[derive(Subcommand, Debug)]
pub enum ConfigAction {
    /// Validate configuration file syntax and semantics
    Validate {
        #[arg(short, long, default_value = "/etc/sentinel/config.toml")]
        file: PathBuf,
    },
}

pub async fn run_config(action: ConfigAction) -> anyhow::Result<()> {
    match action {
        ConfigAction::Validate { file } => {
            let target_path = if file.exists() {
                file
            } else if Path::new("config/config.toml").exists() {
                PathBuf::from("config/config.toml")
            } else {
                file
            };

            println!("Validating configuration file: {}...", target_path.display());
            match sentinel_common::config::SentinelConfig::load_from_file(&target_path) {
                Ok(_) => {
                    println!("[OK] Configuration file is valid.");
                }
                Err(e) => {
                    eprintln!("[FAIL] Configuration syntax error: {}", e);
                }
            }
        }
    }
    Ok(())
}
