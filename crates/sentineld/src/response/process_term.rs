//! Safe process termination with anti-PID-reuse verification and Linux pidfd support.

use crate::lineage::ProcessKey;
use nix::sys::signal::{kill, Signal};
use nix::unistd::Pid;
use std::fs;
use std::path::Path;
use std::time::Duration;
use tracing::{error, info, warn};

#[derive(Debug, thiserror::Error)]
pub enum TerminationError {
    #[error(
        "PID reuse detected: target PID {0} belongs to a different process! Aborting termination."
    )]
    PidReuseDetected(u32),
    #[error("Process {0} not found")]
    NotFound(u32),
    #[error("Process verification failed for PID {0}: {1}")]
    VerificationFailed(u32, String),
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
            let fd = unsafe { libc::syscall(libc::SYS_pidfd_open, pid as libc::pid_t, 0) }
                as libc::c_int;

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
            Err(TerminationError::PidFdFailed(
                pid,
                "Not supported on non-linux OS".into(),
            ))
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
    /// On Linux, poll on a pidfd returns POLLIN when the process exits.
    /// Strictly inspects the pidfd itself without relying on racily re-inspecting /proc.
    pub fn is_alive(&self) -> bool {
        #[cfg(target_os = "linux")]
        {
            let mut pfd = libc::pollfd {
                fd: self.fd,
                events: libc::POLLIN,
                revents: 0,
            };
            loop {
                let ret = unsafe { libc::poll(&mut pfd, 1, 0) };
                if ret < 0 {
                    let err = std::io::Error::last_os_error();
                    if err.raw_os_error() == Some(libc::EINTR) {
                        continue;
                    }
                    // Descriptor invalid or polling failure
                    return false;
                } else if ret > 0 {
                    // When the pinned process exits, pidfd becomes readable (POLLIN).
                    // POLLHUP/POLLERR may also accompany exit.
                    if (pfd.revents & (libc::POLLIN | libc::POLLHUP | libc::POLLERR)) != 0 {
                        return false;
                    }
                }
                // ret == 0 (timeout) means no event -> process is still running
                return true;
            }
        }
        #[cfg(not(target_os = "linux"))]
        {
            let proc_path = format!("/proc/{}", self.pid);
            Path::new(&proc_path).exists()
        }
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
pub fn verify_process_identity(
    key: &ProcessKey,
    expected_exe: Option<&Path>,
) -> Result<(), TerminationError> {
    verify_process_identity_internal(key, expected_exe, None)
}

/// Internal identity verification with strict fail-closed validation.
pub fn verify_process_identity_internal(
    key: &ProcessKey,
    expected_exe: Option<&Path>,
    pidfd_fd: Option<libc::c_int>,
) -> Result<(), TerminationError> {
    let pid = key.pid;
    let proc_path = format!("/proc/{}", pid);

    if !Path::new(&proc_path).exists() {
        return Err(TerminationError::NotFound(pid));
    }

    // Fail closed: If start_time_ns is 0 and no strong alternative identity (pidfd or expected_exe) is provided, reject!
    if key.start_time_ns == 0 && expected_exe.is_none() && pidfd_fd.is_none() {
        return Err(TerminationError::VerificationFailed(
            pid,
            "Process start time is 0/missing without strong alternative identity (fail-closed)"
                .into(),
        ));
    }

    // 1. Verify start time from /proc/<pid>/stat
    let stat_path = format!("{}/stat", proc_path);
    let content = fs::read_to_string(&stat_path).map_err(|e| match e.raw_os_error() {
        Some(libc::ENOENT) => TerminationError::NotFound(pid),
        Some(libc::EACCES) | Some(libc::EPERM) => TerminationError::PermissionDenied(pid),
        _ => TerminationError::VerificationFailed(pid, format!("Cannot read {}: {}", stat_path, e)),
    })?;

    let rparen = content.rfind(')').ok_or_else(|| {
        TerminationError::VerificationFailed(pid, format!("Malformed stat file for PID {}", pid))
    })?;
    let rest = &content[rparen + 1..];
    let fields: Vec<&str> = rest.split_whitespace().collect();
    let starttime_str = fields.get(19).ok_or_else(|| {
        TerminationError::VerificationFailed(
            pid,
            format!("Missing starttime field in stat for PID {}", pid),
        )
    })?;
    let curr_start_time = starttime_str.parse::<u64>().map_err(|e| {
        TerminationError::VerificationFailed(
            pid,
            format!("Failed to parse starttime in stat for PID {}: {}", pid, e),
        )
    })?;

    if key.start_time_ns > 0 && curr_start_time != key.start_time_ns {
        warn!(
            "PID reuse detected for PID {}! Expected start_time {}, found {}",
            pid, key.start_time_ns, curr_start_time
        );
        return Err(TerminationError::PidReuseDetected(pid));
    }

    // 2. Verify exe symlink if provided
    if let Some(expected) = expected_exe {
        let exe_link = format!("{}/exe", proc_path);
        let actual_target = fs::read_link(&exe_link).map_err(|e| match e.raw_os_error() {
            Some(libc::ENOENT) => TerminationError::NotFound(pid),
            Some(libc::EACCES) | Some(libc::EPERM) => TerminationError::PermissionDenied(pid),
            _ => TerminationError::VerificationFailed(
                pid,
                format!("Cannot read link {}: {}", exe_link, e),
            ),
        })?;

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
        // 1. Pre-freeze identity verification
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
        pidfd.send_signal(Signal::SIGTERM)?;
        let _ = pidfd.send_signal(Signal::SIGCONT);

        // Check if exited within grace period
        let start = std::time::Instant::now();
        let poll_interval = Duration::from_millis(10);
        while start.elapsed() < grace_period {
            if !pidfd.is_alive() {
                info!("Process {} terminated gracefully with SIGTERM", pid);
                return Ok(true);
            }
            std::thread::sleep(poll_interval);
        }

        // 5. Forceful kill if still alive
        warn!(
            "Process {} did not exit within grace period, sending SIGKILL via pidfd",
            pid
        );
        pidfd.send_signal(Signal::SIGKILL)?;
        info!("Process {} forcibly terminated with SIGKILL via pidfd", pid);
        return Ok(true);
    }

    // Privilege separation fallback: if pidfd open failed (e.g. unprivileged daemon),
    // delegate process signaling to the sentinel-privileged helper.
    let priv_client = sentinel_privileged::client::PrivilegedClient::default();
    if priv_client.is_available() {
        info!(
            "Privilege separation: delegating signal to sentinel-privileged helper for PID {}",
            pid
        );
        verify_process_identity(key, expected_exe)?;
        match priv_client.execute_sync(&sentinel_privileged::PrivilegedOp::SignalProcess {
            pid,
            signal: libc::SIGTERM,
            expected_start_time: Some(key.start_time_ns),
            expected_exe: expected_exe.map(|p| p.to_string_lossy().to_string()),
        }) {
            Ok(sentinel_privileged::PrivilegedResult::Ok(_)) => {
                info!("Privileged helper signaled process {}", pid);
                return Ok(true);
            }
            Ok(sentinel_privileged::PrivilegedResult::Error { code, message }) => {
                warn!("Privileged helper error signaling {pid} ({code}): {message}");
                if message.contains("PID reuse detected") {
                    return Err(TerminationError::PidReuseDetected(pid));
                }
                if code == "ESRCH" {
                    return Err(TerminationError::NotFound(pid));
                }
            }
            Err(e) => {
                warn!("Failed to communicate with privileged helper for PID {pid}: {e}");
            }
        }
    }

    // Fallback path for older kernels (< 5.3) or direct unprivileged execution:
    // WEAKER GUARANTEE NOTICE: Without pidfd, there exists a fundamental kernel TOCTOU window
    // between /proc validation and signal delivery. This fallback is NOT fully race-free.
    // To minimize the race window, we strictly verify identity, freeze immediately with SIGSTOP,
    // re-validate identity while frozen, and fail-closed if any check fails.
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
    kill(nix_pid, Signal::SIGTERM).map_err(|e| TerminationError::SignalFailed(pid, e))?;
    let _ = kill(nix_pid, Signal::SIGCONT);

    let start = std::time::Instant::now();
    let poll_interval = Duration::from_millis(10);
    while start.elapsed() < grace_period {
        let proc_path = format!("/proc/{}", pid);
        if !Path::new(&proc_path).exists() {
            info!("Process {} terminated gracefully with SIGTERM", pid);
            return Ok(true);
        }
        std::thread::sleep(poll_interval);
    }

    // 4. Forceful kill
    warn!(
        "Process {} did not exit within grace period, sending SIGKILL",
        pid
    );
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
