//! Safe process termination with anti-PID-reuse verification and Linux pidfd support.

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
    #[error("pidfd operation failed for PID {0}: {1}")]
    PidFdFailed(u32, String),
}

/// Safe wrapper for a Linux process file descriptor (pidfd).
pub struct PidFd {
    pub pid: u32,
    pub fd: libc::c_int,
}

impl PidFd {
    /// Attempts to open a pidfd for the given PID using Linux syscall SYS_pidfd_open (available since Linux 5.3).
    pub fn open(pid: u32) -> Result<Self, TerminationError> {
        #[cfg(target_os = "linux")]
        {
            let fd = unsafe {
                libc::syscall(libc::SYS_pidfd_open, pid as libc::pid_t, 0)
            } as libc::c_int;

            if fd >= 0 {
                return Ok(Self { pid, fd });
            }

            let err = std::io::Error::last_os_error();
            if err.raw_os_error() == Some(libc::ESRCH) {
                return Err(TerminationError::NotFound(pid));
            }
            if err.raw_os_error() == Some(libc::EPERM) {
                return Err(TerminationError::PermissionDenied(pid));
            }
            Err(TerminationError::PidFdFailed(pid, err.to_string()))
        }
        #[cfg(not(target_os = "linux"))]
        {
            Err(TerminationError::PidFdFailed(pid, "Not supported on non-linux OS".into()))
        }
    }

    /// Sends a signal to the process pinned by this pidfd via SYS_pidfd_send_signal.
    /// This is strictly atomic and immune to TOCTOU PID recycling.
    pub fn send_signal(&self, sig: Signal) -> Result<(), TerminationError> {
        #[cfg(target_os = "linux")]
        {
            let res = unsafe {
                libc::syscall(
                    libc::SYS_pidfd_send_signal,
                    self.fd,
                    sig as libc::c_int,
                    std::ptr::null::<libc::siginfo_t>(),
                    0,
                )
            };

            if res == 0 {
                Ok(())
            } else {
                let err = nix::Error::last();
                if err == nix::errno::Errno::ESRCH {
                    return Ok(()); // Process already terminated
                }
                Err(TerminationError::SignalFailed(self.pid, err))
            }
        }
        #[cfg(not(target_os = "linux"))]
        {
            let nix_pid = Pid::from_raw(self.pid as i32);
            kill(nix_pid, sig).map_err(|e| TerminationError::SignalFailed(self.pid, e))
        }
    }

    /// Checks if the process instance pinned by this pidfd is still alive.
    pub fn is_alive(&self) -> bool {
        let fd_stat = format!("/proc/self/fd/{}/stat", self.fd);
        if Path::new(&fd_stat).exists() {
            return true;
        }
        let proc_path = format!("/proc/{}", self.pid);
        Path::new(&proc_path).exists()
    }
}

impl Drop for PidFd {
    fn drop(&mut self) {
        if self.fd >= 0 {
            unsafe {
                libc::close(self.fd);
            }
        }
    }
}

/// Verifies that the process currently running at `pid` matches the expected `ProcessKey` and `expected_exe`.
/// Supports reading from direct /proc/<pid> or via /proc/self/fd/<pidfd> if a pidfd is provided.
pub fn verify_process_identity(key: &ProcessKey, expected_exe: Option<&Path>) -> Result<(), TerminationError> {
    verify_process_identity_internal(key, expected_exe, None)
}

/// Internal identity verification with optional pidfd path resolution.
pub fn verify_process_identity_internal(
    key: &ProcessKey,
    expected_exe: Option<&Path>,
    pidfd_fd: Option<libc::c_int>,
) -> Result<(), TerminationError> {
    let pid = key.pid;
    let proc_path = if let Some(fd) = pidfd_fd {
        format!("/proc/self/fd/{}", fd)
    } else {
        format!("/proc/{}", pid)
    };

    if !Path::new(&proc_path).exists() {
        return Err(TerminationError::NotFound(pid));
    }

    // 1. Verify start time from stat if key has start_time_ns (clock ticks)
    if key.start_time_ns > 0 {
        let stat_path = format!("{}/stat", proc_path);
        let stat_fallback = format!("/proc/{}/stat", pid);
        let content_opt = fs::read_to_string(&stat_path).or_else(|_| fs::read_to_string(&stat_fallback));

        if let Ok(content) = content_opt {
            if let Some(rparen) = content.rfind(')') {
                let rest = &content[rparen + 1..];
                let fields: Vec<&str> = rest.split_whitespace().collect();
                if let Some(starttime_str) = fields.get(19) {
                    if let Ok(curr_start_time) = starttime_str.parse::<u64>() {
                        if curr_start_time != key.start_time_ns {
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

    // 2. Verify exe symlink if provided
    if let Some(expected) = expected_exe {
        let exe_link = format!("{}/exe", proc_path);
        let exe_fallback = format!("/proc/{}/exe", pid);
        let actual_target_opt = fs::read_link(&exe_link).or_else(|_| fs::read_link(&exe_fallback));

        if let Ok(actual_target) = actual_target_opt {
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

/// Executes safe multi-stage process termination without TOCTOU races:
///
/// Order of operations:
/// 1. pidfd_open -> pins the exact process instance, preventing kernel PID recycling
/// 2. verify_process_identity(pidfd) -> pre-signal validation; if mismatch, abort immediately!
/// 3. pidfd_send_signal(SIGSTOP) -> freeze target process
/// 4. verify_process_identity_post_freeze -> post-freeze re-validation
/// 5. pidfd_send_signal(SIGTERM) -> graceful exit
/// 6. wait for exit up to grace_period; if still alive, pidfd_send_signal(SIGKILL)
pub fn safe_terminate_process(
    key: &ProcessKey,
    expected_exe: Option<&Path>,
    grace_period: Duration,
) -> Result<bool, TerminationError> {
    let pid = key.pid;

    // Attempt pidfd-based termination if available on Linux >= 5.3
    if let Ok(pidfd) = PidFd::open(pid) {
        // 1. Pre-freeze identity verification using pidfd
        verify_process_identity_internal(key, expected_exe, Some(pidfd.fd))?;

        // 2. Freeze pinned process instance
        pidfd.send_signal(Signal::SIGSTOP)?;

        // 3. Post-freeze identity re-verification
        if let Err(e) = verify_process_identity_internal(key, expected_exe, Some(pidfd.fd)) {
            // If identity check fails under freeze, immediately unfreeze and abort!
            let _ = pidfd.send_signal(Signal::SIGCONT);
            return Err(e);
        }

        // 4. Send SIGTERM for graceful exit
        info!("Sending SIGTERM via pidfd to PID {}", pid);
        let _ = pidfd.send_signal(Signal::SIGTERM);
        let _ = pidfd.send_signal(Signal::SIGCONT);

        // Check if exited within grace period
        let start = std::time::Instant::now();
        let poll_interval = Duration::from_millis(50);
        while start.elapsed() < grace_period {
            if !pidfd.is_alive() {
                info!("Process {} terminated gracefully with SIGTERM", pid);
                return Ok(true);
            }
            std::thread::sleep(poll_interval);
        }

        // 5. Forceful kill if still alive
        warn!("Process {} did not exit within grace period, sending SIGKILL via pidfd", pid);
        pidfd.send_signal(Signal::SIGKILL)?;
        info!("Process {} forcibly terminated with SIGKILL via pidfd", pid);
        return Ok(true);
    }

    // Fallback path for older kernels (< 5.3):
    // CRITICAL FIX: Verify identity BEFORE sending ANY signal to avoid freezing innocent reused PID!
    verify_process_identity(key, expected_exe)?;

    let nix_pid = Pid::from_raw(pid as i32);

    // 1. Freeze process
    if let Err(e) = kill(nix_pid, Signal::SIGSTOP) {
        if e == nix::errno::Errno::ESRCH {
            return Ok(true);
        }
        return Err(TerminationError::SignalFailed(pid, e));
    }

    // 2. Re-verify identity under freeze
    if let Err(e) = verify_process_identity(key, expected_exe) {
        let _ = kill(nix_pid, Signal::SIGCONT);
        return Err(e);
    }

    // 3. Send SIGTERM
    info!("Sending SIGTERM to process {}", pid);
    let _ = kill(nix_pid, Signal::SIGTERM);
    let _ = kill(nix_pid, Signal::SIGCONT);

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

    // 4. Forceful kill
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
