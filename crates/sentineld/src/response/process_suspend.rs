//! Process suspension (SIGSTOP) and resumption (SIGCONT) controls.

use super::process_term::{
    verify_process_identity, verify_process_identity_internal, PidFd, TerminationError,
};
use crate::lineage::ProcessKey;
use nix::sys::signal::{kill, Signal};
use nix::unistd::Pid;
use std::path::Path;
use tracing::info;

pub fn suspend_process(
    key: &ProcessKey,
    expected_exe: Option<&Path>,
) -> Result<(), TerminationError> {
    let pid = key.pid;

    if let Ok(pidfd) = PidFd::open(pid) {
        verify_process_identity_internal(key, expected_exe, Some(pidfd.fd))?;
        info!("Freezing process PID {} with SIGSTOP via pidfd", pid);
        pidfd.send_signal(Signal::SIGSTOP)?;
        return Ok(());
    }

    // Fallback: verify identity BEFORE sending SIGSTOP!
    verify_process_identity(key, expected_exe)?;

    let nix_pid = Pid::from_raw(pid as i32);
    info!("Freezing process PID {} with SIGSTOP", pid);
    kill(nix_pid, Signal::SIGSTOP).map_err(|e| TerminationError::SignalFailed(pid, e))?;
    Ok(())
}

pub fn resume_process(
    key: &ProcessKey,
    expected_exe: Option<&Path>,
) -> Result<(), TerminationError> {
    let pid = key.pid;

    if let Ok(pidfd) = PidFd::open(pid) {
        verify_process_identity_internal(key, expected_exe, Some(pidfd.fd))?;
        info!("Resuming process PID {} with SIGCONT via pidfd", pid);
        pidfd.send_signal(Signal::SIGCONT)?;
        return Ok(());
    }

    verify_process_identity(key, expected_exe)?;

    let nix_pid = Pid::from_raw(pid as i32);
    info!("Resuming process PID {} with SIGCONT", pid);
    kill(nix_pid, Signal::SIGCONT).map_err(|e| TerminationError::SignalFailed(pid, e))?;
    Ok(())
}
