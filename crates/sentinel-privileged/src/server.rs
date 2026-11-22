//! Privileged helper server executing verified system actions.

use std::path::Path;
use std::process::Command;
use tracing::warn;
use super::{PrivilegedOp, PrivilegedResult};

pub struct PrivilegedExecutor;

impl PrivilegedExecutor {
    /// Validates and executes an nftables batch script.
    ///
    /// CRITICAL SECURITY GUARD: Rejects any script that:
    /// 1. Flushes foreign rulesets (`flush ruleset`)
    /// 2. Targets tables other than `table inet sentinel`
    pub fn execute_nft_batch(batch: &str) -> PrivilegedResult {
        if batch.contains("flush ruleset") {
            warn!("Rejected illegal privileged batch: contains 'flush ruleset'!");
            return PrivilegedResult::Error {
                code: "EPERM".into(),
                message: "Security policy prohibits 'flush ruleset'".into(),
            };
        }

        // Must only reference table inet sentinel
        for line in batch.lines() {
            let trimmed = line.trim();
            if trimmed.is_empty() || trimmed.starts_with('#') {
                continue;
            }
            if trimmed.contains("table") && !trimmed.contains("table inet sentinel") {
                warn!("Rejected illegal privileged batch: references foreign table '{}'", trimmed);
                return PrivilegedResult::Error {
                    code: "EPERM".into(),
                    message: "Operations strictly restricted to 'table inet sentinel'".into(),
                };
            }
        }

        let nft_bin = if Path::new("/usr/sbin/nft").exists() {
            "/usr/sbin/nft"
        } else if Path::new("/sbin/nft").exists() {
            "/sbin/nft"
        } else {
            "nft"
        };

        // Step 1: Pre-validate syntax before applying (`nft -c -f -`)
        if let Ok(mut check_child) = Command::new(nft_bin)
            .arg("-c")
            .arg("-f")
            .arg("-")
            .stdin(std::process::Stdio::piped())
            .stdout(std::process::Stdio::piped())
            .stderr(std::process::Stdio::piped())
            .spawn()
        {
            if let Some(mut stdin) = check_child.stdin.take() {
                use std::io::Write;
                let _ = stdin.write_all(batch.as_bytes());
            }
            if let Ok(out) = check_child.wait_with_output() {
                if !out.status.success() {
                    let err = String::from_utf8_lossy(&out.stderr);
                    return PrivilegedResult::Error {
                        code: "EBADSYNTAX".into(),
                        message: format!("Syntax error: {}", err.trim()),
                    };
                }
            }
        }

        let mut child = match Command::new(nft_bin)
            .arg("-f")
            .arg("-")
            .stdin(std::process::Stdio::piped())
            .stdout(std::process::Stdio::piped())
            .stderr(std::process::Stdio::piped())
            .spawn()
        {
            Ok(c) => c,
            Err(e) => {
                return PrivilegedResult::Error {
                    code: "EIO".into(),
                    message: format!("Failed to spawn nft: {}", e),
                };
            }
        };

        if let Some(mut stdin) = child.stdin.take() {
            use std::io::Write;
            let _ = stdin.write_all(batch.as_bytes());
        }

        match child.wait_with_output() {
            Ok(out) => {
                if out.status.success() {
                    PrivilegedResult::Ok(serde_json::json!({ "status": "applied" }))
                } else {
                    let err = String::from_utf8_lossy(&out.stderr);
                    PrivilegedResult::Error {
                        code: "EBADCMD".into(),
                        message: err.trim().to_string(),
                    }
                }
            }
            Err(e) => PrivilegedResult::Error {
                code: "EIO".into(),
                message: e.to_string(),
            },
        }
    }

    /// Signals a process using pidfd (or kill) after verifying it is not PID 1.
    pub fn signal_process(pid: u32, signal: i32) -> PrivilegedResult {
        if pid <= 1 {
            return PrivilegedResult::Error {
                code: "EPERM".into(),
                message: "Targeting init / PID 1 is forbidden".into(),
            };
        }

        #[cfg(target_os = "linux")]
        {
            let fd = unsafe { libc::syscall(libc::SYS_pidfd_open, pid as libc::pid_t, 0) } as libc::c_int;
            if fd >= 0 {
                let res = unsafe {
                    libc::syscall(
                        libc::SYS_pidfd_send_signal,
                        fd,
                        signal,
                        std::ptr::null::<libc::siginfo_t>(),
                        0,
                    )
                };
                unsafe { libc::close(fd) };
                if res == 0 {
                    return PrivilegedResult::Ok(serde_json::json!({ "signaled": true, "pid": pid }));
                } else {
                    let err = nix::Error::last();
                    return PrivilegedResult::Error {
                        code: "ESRCH".into(),
                        message: err.to_string(),
                    };
                }
            }
        }

        // Fallback
        let nix_pid = nix::unistd::Pid::from_raw(pid as i32);
        let sig = match nix::sys::signal::Signal::try_from(signal) {
            Ok(s) => s,
            Err(_) => {
                return PrivilegedResult::Error {
                    code: "EINVAL".into(),
                    message: format!("Invalid signal number {}", signal),
                };
            }
        };

        match nix::sys::signal::kill(nix_pid, sig) {
            Ok(_) => PrivilegedResult::Ok(serde_json::json!({ "signaled": true, "pid": pid })),
            Err(e) => PrivilegedResult::Error {
                code: "ESRCH".into(),
                message: e.to_string(),
            },
        }
    }

    /// Dispatches a privileged operation request.
    pub fn dispatch(op: PrivilegedOp) -> PrivilegedResult {
        match op {
            PrivilegedOp::Ping => PrivilegedResult::Ok(serde_json::json!({ "status": "pong" })),
            PrivilegedOp::ApplyNftablesBatch { batch } => Self::execute_nft_batch(&batch),
            PrivilegedOp::SignalProcess { pid, signal } => Self::signal_process(pid, signal),
        }
    }
}
