//! Safe process termination with anti-PID-reuse verification.

use std::fs;
use std::path::Path;
use std::time::Duration;
use nix::sys::signal::{kill, Signal};
use nix::unistd::Pid;
use tracing::{error, info, warn};
use crate::lineage::ProcessKey;

#[derive(Debug, thiserror::Error)]
pub enum TerminationError {
    #[error("PID reuse detected: target PID {0} belongs to a different process! Aborting termination.")]
    PidReuseDetected(u32),
    #[error("Process {0} not found")]
    NotFound(u32),
    #[error("System error signaling process {0}: {1}")]
    SignalFailed(u32, nix::Error),
    #[error("Permission denied terminating process {0}")]
    PermissionDenied(u32),
}

/// Verifies that the process currently running at `pid` matches the expected `ProcessKey` and `expected_exe`.
/// Protects against race conditions where the target process died and the kernel reused the PID.
pub fn verify_process_identity(key: &ProcessKey, expected_exe: Option<&Path>) -> Result<(), TerminationError> {
    let pid = key.pid;
    let proc_path = format!("/proc/{}", pid);
    if !Path::new(&proc_path).exists() {
        return Err(TerminationError::NotFound(pid));
    }

    // 1. Verify start time from /proc/<pid>/stat if key has start_time_ns
    if key.start_time_ns > 0 {
        let stat_path = format!("/proc/{}/stat", pid);
        if let Ok(content) = fs::read_to_string(&stat_path) {
            if let Some(rparen) = content.rfind(')') {
                let rest = &content[rparen + 1..];
                let fields: Vec<&str> = rest.split_whitespace().collect();
                if let Some(starttime_str) = fields.get(19) {
                    if let Ok(curr_start_time) = starttime_str.parse::<u64>() {
                        // If start time ticks is recorded, verify against key if matching precision
                        if curr_start_time > 0 && key.start_time_ns > 0 && curr_start_time != key.start_time_ns {
                            // Only warn if significantly divergent (e.g. reused PID)
                            let diff = (curr_start_time as i64 - key.start_time_ns as i64).abs();
                            if diff > 1000 {
                                warn!(
                                    "PID reuse detected for PID {}! Expected start_time {}, found {}",
                                    pid, key.start_time_ns, curr_start_time
                                );
                                return Err(TerminationError::PidReuseDetected(pid));
                            }
                        }
                    }
                }
            }
        }
    }

    // 2. Verify exe symlink if provided
    if let Some(expected) = expected_exe {
        let exe_link = format!("/proc/{}/exe", pid);
        if let Ok(actual_target) = fs::read_link(&exe_link) {
            let actual_str = actual_target.to_string_lossy();
            let exp_str = expected.to_string_lossy();
            let actual_clean = actual_str.trim_end_matches(" (deleted)");
            let exp_clean = exp_str.trim_end_matches(" (deleted)");
            if actual_clean != exp_clean && !actual_clean.ends_with(exp_clean) {
                warn!(
                    "PID reuse binary mismatch for PID {}! Expected {:?}, found {:?}",
                    pid, expected, actual_target
                );
                return Err(TerminationError::PidReuseDetected(pid));
            }
        }
    }

    Ok(())
}

/// Executes safe multi-stage process termination:
/// 1. SIGSTOP to prevent further malicious activity immediately
/// 2. Verify process identity (PID reuse protection)
/// 3. SIGTERM for clean resource release
/// 4. Verify exit; if still running after timeout, SIGKILL
pub fn safe_terminate_process(
    key: &ProcessKey,
    expected_exe: Option<&Path>,
    grace_period: Duration,
) -> Result<bool, TerminationError> {
    let pid = key.pid;
    let nix_pid = Pid::from_raw(pid as i32);

    // 1. Immediate freeze to halt malicious actions
    if let Err(e) = kill(nix_pid, Signal::SIGSTOP) {
        if e == nix::errno::Errno::ESRCH {
            return Ok(true); // Process already dead
        }
        return Err(TerminationError::SignalFailed(pid, e));
    }

    // 2. Identity verification under freeze
    if let Err(e) = verify_process_identity(key, expected_exe) {
        // If identity mismatch, RESUME process to not kill innocents
        let _ = kill(nix_pid, Signal::SIGCONT);
        return Err(e);
    }

    // 3. Graceful termination
    info!("Sending SIGTERM to process {}", pid);
    let _ = kill(nix_pid, Signal::SIGTERM);
    let _ = kill(nix_pid, Signal::SIGCONT);

    // Check if exited within grace period
    let start = std::time::Instant::now();
    let poll_interval = Duration::from_millis(50);
    while start.elapsed() < grace_period {
        let proc_path = format!("/proc/{}", pid);
        if !Path::new(&proc_path).exists() {
            info!("Process {} terminated gracefully with SIGTERM", pid);
            return Ok(true);
        }
        std::thread::sleep(poll_interval);
    }

    // 4. Forceful kill if still alive
    warn!("Process {} did not exit within grace period, sending SIGKILL", pid);
    if let Err(e) = kill(nix_pid, Signal::SIGKILL) {
        if e == nix::errno::Errno::ESRCH {
            return Ok(true);
        }
        error!("Failed to send SIGKILL to PID {}: {}", pid, e);
        return Err(TerminationError::SignalFailed(pid, e));
    }

    info!("Process {} forcibly terminated with SIGKILL", pid);
    Ok(true)
}
