//! Privileged helper server executing verified system actions.

use super::{FirewallOperation, PrivilegedOp, PrivilegedResult};
use std::net::IpAddr;
use std::path::{Path, PathBuf};
use std::process::Command;
use std::sync::atomic::{AtomicU64, Ordering};
use tracing::{info, warn};

static WATCHDOG_GENERATION: AtomicU64 = AtomicU64::new(0);

fn lockout_state_path() -> PathBuf {
    let p = Path::new("/run/sentinel");
    let usable = if p.exists() {
        let probe = p.join(".probe_write");
        if std::fs::write(&probe, b"").is_ok() {
            let _ = std::fs::remove_file(&probe);
            true
        } else {
            false
        }
    } else if std::fs::create_dir_all(p).is_ok() {
        let probe = p.join(".probe_write");
        if std::fs::write(&probe, b"").is_ok() {
            let _ = std::fs::remove_file(&probe);
            true
        } else {
            false
        }
    } else {
        false
    };

    if usable {
        p.join("isolation_lockout.state")
    } else {
        std::env::temp_dir().join("sentinel_isolation_lockout.state")
    }
}

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

    /// Builds a verified atomic nftables isolation batch script with strict type and IP validation.
    pub fn build_isolation_batch(
        tier: &str,
        trusted_ssh_ips: &[String],
        blocked_ips: &[String],
        blocked_ports: &[u16],
    ) -> Result<String, (String, String)> {
        let mut parsed_ssh = Vec::new();
        for ip in trusted_ssh_ips {
            let parsed = ip.parse::<IpAddr>().map_err(|e| {
                (
                    "EINVAL".into(),
                    format!("Invalid trusted SSH IP '{}': {}", ip, e),
                )
            })?;
            parsed_ssh.push(parsed);
        }

        let mut parsed_blocked = Vec::new();
        for ip in blocked_ips {
            let parsed = ip.parse::<IpAddr>().map_err(|e| {
                (
                    "EINVAL".into(),
                    format!("Invalid blocked IP '{}': {}", ip, e),
                )
            })?;
            parsed_blocked.push(parsed);
        }

        match tier {
            "None" => {
                let bypass_flag = " bypass";
                Ok(format!(
                    "add table inet sentinel\n\
                     delete table inet sentinel\n\
                     add table inet sentinel\n\
                     add set inet sentinel blocked_v4 {{ type ipv4_addr; }}\n\
                     add set inet sentinel blocked_v6 {{ type ipv6_addr; }}\n\
                     add chain inet sentinel input {{ type filter hook input priority 0; policy accept; }}\n\
                     add chain inet sentinel output {{ type filter hook output priority 0; policy accept; }}\n\
                     add rule inet sentinel output oif lo accept\n\
                     add rule inet sentinel output ip daddr @blocked_v4 counter drop\n\
                     add rule inet sentinel output ip6 daddr @blocked_v6 counter drop\n\
                     add rule inet sentinel output ct state established,related accept\n\
                     add rule inet sentinel output meta mark & 0xff800000 == 0x5e800000 counter queue num 100{}\n\
                     add rule inet sentinel output ct state new meta mark & 0xff800000 == 0x5e000000 counter queue num 100{}\n",
                    bypass_flag, bypass_flag
                ))
            }
            "Selective" => {
                let mut set_elements = String::new();
                for ip in &parsed_blocked {
                    match ip {
                        IpAddr::V4(v4) => set_elements.push_str(&format!(
                            "add element inet sentinel blocked_v4 {{ {} }}\n",
                            v4
                        )),
                        IpAddr::V6(v6) => set_elements.push_str(&format!(
                            "add element inet sentinel blocked_v6 {{ {} }}\n",
                            v6
                        )),
                    }
                }
                let mut port_rules = String::new();
                for port in blocked_ports {
                    port_rules.push_str(&format!(
                        "add rule inet sentinel output tcp dport {} counter drop\n\
                         add rule inet sentinel output udp dport {} counter drop\n",
                        port, port
                    ));
                }

                Ok(format!(
                    "add table inet sentinel\n\
                     delete table inet sentinel\n\
                     add table inet sentinel\n\
                     add set inet sentinel blocked_v4 {{ type ipv4_addr; }}\n\
                     add set inet sentinel blocked_v6 {{ type ipv6_addr; }}\n\
                     {}\
                     add chain inet sentinel input {{ type filter hook input priority 0; policy accept; }}\n\
                     add chain inet sentinel output {{ type filter hook output priority 0; policy accept; }}\n\
                     add rule inet sentinel output oif lo accept\n\
                     add rule inet sentinel output ip daddr @blocked_v4 counter drop\n\
                     add rule inet sentinel output ip6 daddr @blocked_v6 counter drop\n\
                     {}\
                     add rule inet sentinel output ct state established,related accept\n\
                     add rule inet sentinel output meta mark & 0xff800000 == 0x5e800000 counter queue num 100 bypass\n\
                     add rule inet sentinel output ct state new meta mark & 0xff800000 == 0x5e000000 counter queue num 100 bypass\n",
                    set_elements, port_rules
                ))
            }
            "Restricted" => {
                let mut ssh_accept_rules = String::new();
                for ip in &parsed_ssh {
                    match ip {
                        IpAddr::V4(v4) => {
                            ssh_accept_rules.push_str(&format!(
                                "add rule inet sentinel output ip daddr {} tcp dport 22 accept\n\
                                 add rule inet sentinel output ip daddr {} tcp sport 22 ct state established,related accept\n",
                                v4, v4
                            ));
                        }
                        IpAddr::V6(v6) => {
                            ssh_accept_rules.push_str(&format!(
                                "add rule inet sentinel output ip6 daddr {} tcp dport 22 accept\n\
                                 add rule inet sentinel output ip6 daddr {} tcp sport 22 ct state established,related accept\n",
                                v6, v6
                            ));
                        }
                    }
                }
                Ok(format!(
                    "add table inet sentinel\n\
                     delete table inet sentinel\n\
                     add table inet sentinel\n\
                     add chain inet sentinel input {{ type filter hook input priority 0; policy accept; }}\n\
                     add chain inet sentinel output {{ type filter hook output priority 0; policy drop; }}\n\
                     add rule inet sentinel output oif lo accept\n\
                     add rule inet sentinel output udp dport 53 accept\n\
                     add rule inet sentinel output tcp dport 53 accept\n\
                     add rule inet sentinel output tcp sport 22 ct state established,related accept\n\
                     {}",
                    ssh_accept_rules
                ))
            }
            "FullIsolation" => {
                let mut trusted_rules = String::new();
                for ip in &parsed_ssh {
                    match ip {
                        IpAddr::V4(v4) => {
                            trusted_rules.push_str(&format!(
                                "add rule inet sentinel input ip saddr {} tcp dport 22 accept\n\
                                 add rule inet sentinel output ip daddr {} tcp sport 22 ct state established,related accept\n",
                                v4, v4
                            ));
                        }
                        IpAddr::V6(v6) => {
                            trusted_rules.push_str(&format!(
                                "add rule inet sentinel input ip6 saddr {} tcp dport 22 accept\n\
                                 add rule inet sentinel output ip6 daddr {} tcp sport 22 ct state established,related accept\n",
                                v6, v6
                            ));
                        }
                    }
                }
                Ok(format!(
                    "add table inet sentinel\n\
                     delete table inet sentinel\n\
                     add table inet sentinel\n\
                     add chain inet sentinel input {{ type filter hook input priority 0; policy drop; }}\n\
                     add chain inet sentinel output {{ type filter hook output priority 0; policy drop; }}\n\
                     add rule inet sentinel input iif lo accept\n\
                     add rule inet sentinel output oif lo accept\n\
                     add rule inet sentinel input tcp dport 22 ct state established,related accept\n\
                     add rule inet sentinel output tcp sport 22 ct state established,related accept\n\
                     {}",
                    trusted_rules
                ))
            }
            other => Err((
                "EINVAL".into(),
                format!("Unknown isolation tier '{}'", other),
            )),
        }
    }

    /// Arms the Anti-Lockout safety watchdog timer and persists state to disk.
    pub fn arm_anti_lockout(timeout_secs: u64, trusted_ssh_ips: Vec<String>) -> PrivilegedResult {
        if timeout_secs == 0 {
            return PrivilegedResult::Error {
                code: "EINVAL".into(),
                message: "timeout_secs must be greater than 0".into(),
            };
        }
        let now = match std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH) {
            Ok(d) => d.as_secs(),
            Err(_) => 0,
        };
        let expires_at = now + timeout_secs;
        let state_content = serde_json::json!({
            "expires_at": expires_at,
            "trusted_ssh_ips": trusted_ssh_ips,
        });

        let state_path = lockout_state_path();
        if let Err(e) = std::fs::write(&state_path, state_content.to_string()) {
            warn!(
                "Failed to persist anti-lockout state to {}: {}",
                state_path.display(),
                e
            );
        }

        let gen = WATCHDOG_GENERATION.fetch_add(1, Ordering::SeqCst) + 1;
        let dur = std::time::Duration::from_secs(timeout_secs);
        std::thread::Builder::new()
            .name("snt-lockout-watchdog".into())
            .spawn(move || {
                std::thread::sleep(dur);
                if WATCHDOG_GENERATION.load(Ordering::SeqCst) == gen {
                    let path = lockout_state_path();
                    if path.exists() {
                        warn!(
                            "ANTI-LOCKOUT WATCHDOG EXPIRED! Operator failed to confirm within {}s. Rolling back isolation!",
                            timeout_secs
                        );
                        let _ = PrivilegedExecutor::rollback_isolation();
                    }
                }
            })
            .ok();

        PrivilegedResult::Ok(serde_json::json!({ "armed": true, "expires_at": expires_at }))
    }

    /// Confirms network isolation and disarms the Anti-Lockout watchdog timer.
    pub fn confirm_anti_lockout() -> PrivilegedResult {
        WATCHDOG_GENERATION.fetch_add(1, Ordering::SeqCst);
        let path = lockout_state_path();
        let _ = std::fs::remove_file(&path);
        PrivilegedResult::Ok(serde_json::json!({ "confirmed": true }))
    }

    /// Rolls back network isolation to Tier::None and removes state.
    pub fn rollback_isolation() -> PrivilegedResult {
        WATCHDOG_GENERATION.fetch_add(1, Ordering::SeqCst);
        let path = lockout_state_path();
        let _ = std::fs::remove_file(&path);
        match Self::build_isolation_batch("None", &[], &[], &[]) {
            Ok(batch) => Self::execute_nft_batch(&batch),
            Err((code, message)) => PrivilegedResult::Error { code, message },
        }
    }

    /// Checks for leftover or expired anti-lockout state upon helper startup.
    pub fn check_and_recover_lockout_state() {
        let path = lockout_state_path();
        if !path.exists() {
            return;
        }
        if let Ok(data) = std::fs::read_to_string(&path) {
            if let Ok(val) = serde_json::from_str::<serde_json::Value>(&data) {
                if let Some(expires_at) = val.get("expires_at").and_then(|v| v.as_u64()) {
                    let now = std::time::SystemTime::now()
                        .duration_since(std::time::UNIX_EPOCH)
                        .map(|d| d.as_secs())
                        .unwrap_or(0);
                    if now >= expires_at {
                        warn!(
                            "CRASH RECOVERY: Found expired anti-lockout state (expired at {}). Rolling back network isolation immediately!",
                            expires_at
                        );
                        let _ = Self::rollback_isolation();
                    } else {
                        let remaining = expires_at - now;
                        info!(
                            "CRASH RECOVERY: Found active anti-lockout state (remaining: {}s). Resuming watchdog timer.",
                            remaining
                        );
                        let trusted = val
                            .get("trusted_ssh_ips")
                            .and_then(|v| v.as_array())
                            .map(|arr| {
                                arr.iter()
                                    .filter_map(|x| x.as_str().map(String::from))
                                    .collect()
                            })
                            .unwrap_or_default();
                        let _ = Self::arm_anti_lockout(remaining, trusted);
                    }
                }
            }
        }
    }

    /// Executes a strongly-typed firewall operation.
    pub fn execute_firewall_op(op: FirewallOperation) -> PrivilegedResult {
        match op {
            FirewallOperation::SetupHolding { use_bypass } => {
                let bypass_flag = if use_bypass { " bypass" } else { "" };
                let batch = format!(
                    "add table inet sentinel\n\
                     delete table inet sentinel\n\
                     add table inet sentinel\n\
                     add chain inet sentinel input {{ type filter hook input priority 0; policy accept; }}\n\
                     add chain inet sentinel output {{ type filter hook output priority 0; policy accept; }}\n\
                     add rule inet sentinel output meta mark & 0xff800000 == 0x5e800000 counter queue num 100{}\n\
                     add rule inet sentinel output ct state established,related accept\n\
                     add rule inet sentinel output ct state new meta mark & 0xff800000 == 0x5e000000 counter queue num 100{}\n",
                    bypass_flag, bypass_flag
                );
                Self::execute_nft_batch(&batch)
            }
            FirewallOperation::ApplyIsolation {
                tier,
                trusted_ssh_ips,
                blocked_ips,
                blocked_ports,
            } => {
                match Self::build_isolation_batch(
                    &tier,
                    &trusted_ssh_ips,
                    &blocked_ips,
                    &blocked_ports,
                ) {
                    Ok(batch) => Self::execute_nft_batch(&batch),
                    Err((code, message)) => PrivilegedResult::Error { code, message },
                }
            }
            FirewallOperation::BlockIp { ip } => {
                let parsed = match ip.parse::<IpAddr>() {
                    Ok(p) => p,
                    Err(e) => {
                        return PrivilegedResult::Error {
                            code: "EINVAL".into(),
                            message: format!("Invalid IP address '{}': {}", ip, e),
                        };
                    }
                };
                let rule = match parsed {
                    IpAddr::V4(v4) => {
                        format!("insert rule inet sentinel output ip daddr {} drop\n", v4)
                    }
                    IpAddr::V6(v6) => {
                        format!("insert rule inet sentinel output ip6 daddr {} drop\n", v6)
                    }
                };
                let batch = format!(
                    "add table inet sentinel\n\
                     add chain inet sentinel output {{ type filter hook output priority 0; policy accept; }}\n\
                     {}",
                    rule
                );
                Self::execute_nft_batch(&batch)
            }
            FirewallOperation::CleanupRules => {
                let nft_bin = if Path::new("/usr/sbin/nft").exists() {
                    "/usr/sbin/nft"
                } else if Path::new("/sbin/nft").exists() {
                    "/sbin/nft"
                } else {
                    "nft"
                };
                let _ = Command::new(nft_bin)
                    .args(["delete", "table", "inet", "sentinel"])
                    .output();
                PrivilegedResult::Ok(serde_json::json!({ "status": "cleaned" }))
            }
            FirewallOperation::ArmAntiLockout {
                timeout_secs,
                trusted_ssh_ips,
            } => Self::arm_anti_lockout(timeout_secs, trusted_ssh_ips),
            FirewallOperation::ConfirmAntiLockout => Self::confirm_anti_lockout(),
            FirewallOperation::Rollback => Self::rollback_isolation(),
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
            PrivilegedOp::Firewall(fw_op) => Self::execute_firewall_op(fw_op),
            #[allow(deprecated)]
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

    #[test]
    fn test_build_isolation_batch_validation() {
        // Valid None
        let res = PrivilegedExecutor::build_isolation_batch("None", &[], &[], &[]);
        assert!(res.is_ok());
        let batch = res.unwrap();
        assert!(batch.contains("table inet sentinel"));

        // Invalid trusted IP
        let res = PrivilegedExecutor::build_isolation_batch(
            "Restricted",
            &["192.168.1.300".to_string()],
            &[],
            &[],
        );
        assert!(res.is_err());
        assert_eq!(res.unwrap_err().0, "EINVAL");

        // Invalid blocked IP
        let res = PrivilegedExecutor::build_isolation_batch(
            "Selective",
            &[],
            &["not-an-ip".to_string()],
            &[8080],
        );
        assert!(res.is_err());
        assert_eq!(res.unwrap_err().0, "EINVAL");

        // Unknown tier
        let res = PrivilegedExecutor::build_isolation_batch("SuperIsolation", &[], &[], &[]);
        assert!(res.is_err());
        assert_eq!(res.unwrap_err().0, "EINVAL");
    }

    #[test]
    fn test_anti_lockout_arm_and_confirm() {
        let res = PrivilegedExecutor::arm_anti_lockout(60, vec!["10.0.0.1".into()]);
        match res {
            PrivilegedResult::Ok(val) => {
                assert_eq!(val["armed"], true);
                assert!(lockout_state_path().exists());
            }
            _ => panic!("Expected arm_anti_lockout to succeed"),
        }

        let res = PrivilegedExecutor::confirm_anti_lockout();
        match res {
            PrivilegedResult::Ok(val) => {
                assert_eq!(val["confirmed"], true);
                assert!(!lockout_state_path().exists());
            }
            _ => panic!("Expected confirm_anti_lockout to succeed"),
        }
    }
}
