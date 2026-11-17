//! Process suspension (SIGSTOP) and resumption (SIGCONT) controls.

use nix::sys::signal::{kill, Signal};
use nix::unistd::Pid;
use std::path::Path;
use tracing::info;
use crate::lineage::ProcessKey;
use super::process_term::{verify_process_identity, TerminationError};

pub fn suspend_process(key: &ProcessKey, expected_exe: Option<&Path>) -> Result<(), TerminationError> {
    let pid = key.pid;
    let nix_pid = Pid::from_raw(pid as i32);

    verify_process_identity(key, expected_exe)?;

    info!("Freezing process PID {} with SIGSTOP", pid);
    kill(nix_pid, Signal::SIGSTOP).map_err(|e| TerminationError::SignalFailed(pid, e))?;
    Ok(())
}

pub fn resume_process(key: &ProcessKey, expected_exe: Option<&Path>) -> Result<(), TerminationError> {
    let pid = key.pid;
    let nix_pid = Pid::from_raw(pid as i32);

    verify_process_identity(key, expected_exe)?;

    info!("Resuming process PID {} with SIGCONT", pid);
    kill(nix_pid, Signal::SIGCONT).map_err(|e| TerminationError::SignalFailed(pid, e))?;
    Ok(())
}
