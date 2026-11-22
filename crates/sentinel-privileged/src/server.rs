//! Privileged helper server executing verified system actions.

use super::{PrivilegedOp, PrivilegedResult};
use std::path::Path;
use std::process::Command;
use tracing::warn;

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
                warn!(
                    "Rejected illegal privileged batch: references foreign table '{}'",
                    trimmed
                );
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

    /// Signals a process using pidfd (or kill) after verifying it is not PID 1
    /// and performing anti-PID-reuse checks on start_time and exe identity.
    pub fn signal_process(
        pid: u32,
        signal: i32,
        expected_start_time: Option<u64>,
        expected_exe: Option<&str>,
    ) -> PrivilegedResult {
        if pid <= 1 {
            return PrivilegedResult::Error {
                code: "EPERM".into(),
                message: "Targeting init / PID 1 is forbidden".into(),
            };
        }

        // Anti-PID-reuse verification: validates that the target process instance matches expected attributes.
        let verify_identity = || -> Result<(), (String, String)> {
            if let Some(exp_start) = expected_start_time {
                if exp_start > 0 {
                    let stat_path = format!("/proc/{}/stat", pid);
                    let content = std::fs::read_to_string(&stat_path).map_err(|e| {
                        (
                            "ESRCH".to_string(),
                            format!("Cannot read {}: {}", stat_path, e),
                        )
                    })?;
                    let rparen = content.rfind(')').ok_or_else(|| {
                        (
                            "EBADF".to_string(),
                            format!("Malformed stat for PID {}", pid),
                        )
                    })?;
                    let rest = &content[rparen + 1..];
                    let fields: Vec<&str> = rest.split_whitespace().collect();
                    let starttime_str = fields.get(19).ok_or_else(|| {
                        (
                            "EBADF".to_string(),
                            format!("Missing starttime field in stat for PID {}", pid),
                        )
                    })?;
                    let curr_start = starttime_str.parse::<u64>().map_err(|e| {
                        (
                            "EBADF".to_string(),
                            format!("Failed to parse starttime for PID {}: {}", pid, e),
                        )
                    })?;
                    if curr_start != exp_start {
                        return Err((
                            "ESRCH".to_string(),
                            format!(
                                "PID reuse detected: expected start_time {}, found {}",
                                exp_start, curr_start
                            ),
                        ));
                    }
                }
            }

            if let Some(exp_exe) = expected_exe {
                let exe_link = format!("/proc/{}/exe", pid);
                let actual = std::fs::read_link(&exe_link).map_err(|e| {
                    (
                        "ESRCH".to_string(),
                        format!("Cannot readlink {}: {}", exe_link, e),
                    )
                })?;
                let actual_str = actual.to_string_lossy();
                let actual_clean = actual_str.trim_end_matches(" (deleted)");
                let exp_clean = exp_exe.trim_end_matches(" (deleted)");
                if actual_clean != exp_clean && !actual_clean.ends_with(exp_clean) {
                    return Err((
                        "ESRCH".to_string(),
                        format!(
                            "PID reuse detected: expected exe '{}', found '{}'",
                            exp_exe, actual_clean
                        ),
                    ));
                }
            }
            Ok(())
        };

        #[cfg(target_os = "linux")]
        {
            let fd = unsafe { libc::syscall(libc::SYS_pidfd_open, pid as libc::pid_t, 0) }
                as libc::c_int;
            if fd >= 0 {
                if let Err((code, message)) = verify_identity() {
                    unsafe { libc::close(fd) };
                    warn!(
                        "Privileged helper rejected signal to PID {}: {}",
                        pid, message
                    );
                    return PrivilegedResult::Error { code, message };
                }

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
                    return PrivilegedResult::Ok(
                        serde_json::json!({ "signaled": true, "pid": pid }),
                    );
                } else {
                    let err = nix::Error::last();
                    return PrivilegedResult::Error {
                        code: "ESRCH".into(),
                        message: err.to_string(),
                    };
                }
            }
        }

        // If pidfd_open is unavailable (e.g. Linux < 5.3 or sandbox), verify before kill fallback
        if let Err((code, message)) = verify_identity() {
            warn!(
                "Privileged helper fallback rejected signal to PID {}: {}",
                pid, message
            );
            return PrivilegedResult::Error { code, message };
        }

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
            PrivilegedOp::SignalProcess {
                pid,
                signal,
                expected_start_time,
                expected_exe,
            } => Self::signal_process(pid, signal, expected_start_time, expected_exe.as_deref()),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_privileged_signal_rejects_pid_1() {
        let res = PrivilegedExecutor::signal_process(1, libc::SIGTERM, None, None);
        match res {
            PrivilegedResult::Error { code, message } => {
                assert_eq!(code, "EPERM");
                assert!(message.contains("forbidden"));
            }
            _ => panic!("Expected rejection for PID 1"),
        }
    }

    #[test]
    fn test_privileged_signal_rejects_mismatched_start_time() {
        let current_pid = std::process::id();
        let res = PrivilegedExecutor::signal_process(
            current_pid,
            libc::SIGCONT,
            Some(999_999_999_999),
            None,
        );
        match res {
            PrivilegedResult::Error { code, message } => {
                assert_eq!(code, "ESRCH");
                assert!(message.contains("PID reuse detected"));
            }
            _ => panic!("Expected rejection on mismatched start_time"),
        }
    }

    #[test]
    fn test_privileged_signal_rejects_mismatched_exe() {
        let current_pid = std::process::id();
        let res = PrivilegedExecutor::signal_process(
            current_pid,
            libc::SIGCONT,
            None,
            Some("/tmp/fake_binary_never_exists"),
        );
        match res {
            PrivilegedResult::Error { code, message } => {
                assert_eq!(code, "ESRCH");
                assert!(message.contains("PID reuse detected"));
            }
            _ => panic!("Expected rejection on mismatched binary name"),
        }
    }

    #[test]
    fn test_privileged_nft_rejects_flush_ruleset() {
        let res = PrivilegedExecutor::execute_nft_batch("flush ruleset\n");
        match res {
            PrivilegedResult::Error { code, message } => {
                assert_eq!(code, "EPERM");
                assert!(message.contains("prohibits 'flush ruleset'"));
            }
            _ => panic!("Expected rejection of flush ruleset"),
        }
    }

    #[test]
    fn test_privileged_nft_rejects_foreign_tables() {
        let res = PrivilegedExecutor::execute_nft_batch("flush table ip filter\n");
        match res {
            PrivilegedResult::Error { code, message } => {
                assert_eq!(code, "EPERM");
                assert!(message.contains("strictly restricted to 'table inet sentinel'"));
            }
            _ => panic!("Expected rejection of foreign table"),
        }
    }
}
