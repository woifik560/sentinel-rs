//! Red-Team Integration Test Suite for Sentinel-RS (Milestone 1 & Beyond).
//!
//! Validates:
//! 1. `cat secret | curl` pipe taint tracking via INODE_STORAGE & `lsm/file_permission`.
//! 2. Exfiltration via tempfile `/tmp/key` and inode taint inheritance.
//! 3. LoLBin protection: `/usr/bin/curl` and `/usr/bin/git` cannot use dpkg trust discount when accessing secrets.
//! 4. `memfd_create` fileless execution detection via `lsm/bprm_check_security`.
//! 5. Taint Hygiene: `/dev/pts/*`, `/dev/null`, `~/.ssh/config`, `~/.ssh/*.pub` are exempt.
//! 6. Never-Freeze Allowlist: `gnome-shell`, `dbus-daemon`, `systemd` are strictly protected from SIGSTOP.

use std::path::{Path, PathBuf};
use sentinel_common::config::RulesConfig;
use sentinel_common::events::{MAY_READ, MAY_WRITE, SENTINEL_SO_MARK};
use sentinel_common::process::{ProcessNode, SecretCategory};
use sentinel_common::risk::{RiskThresholds, RuleId, Verdict};
use sentinel_ebpf::maps::{TaintFlags, TaintHygiene, TaintMapManager};
use sentinel_ebpf::programs::bprm_check_security::is_memfd_or_fileless;
use sentinel_ebpf::programs::file_open::simulate_file_open_check;
use sentinel_ebpf::programs::file_permission::evaluate_file_permission;
use sentinel_ebpf::programs::socket_connect::{evaluate_socket_connect, SocketConnectVerdict};

// Mock DpkgChecker for standalone testing
#[derive(Clone, Default)]
struct MockDpkgChecker;
impl MockDpkgChecker {
    fn check_package(&self, path: &Path) -> Option<sentineld_mock_pkg::DpkgInfo> {
        if path.starts_with("/usr/bin/") || path.starts_with("/bin/") {
            Some(sentineld_mock_pkg::DpkgInfo {
                package_name: path.file_name().unwrap().to_string_lossy().to_string(),
                is_integrity_verified: true,
            })
        } else {
            None
        }
    }
}

mod sentineld_mock_pkg {
    #[derive(Clone, Debug)]
    pub struct DpkgInfo {
        pub package_name: String,
        pub is_integrity_verified: bool,
    }
}

#[test]
fn test_scenario_1_cat_secret_pipe_curl() {
    let taint_mgr = TaintMapManager::new();
    let cat_tgid = 4100;
    let curl_tgid = 4101;
    let pipe_ino = 554433;
    let pipe_dev = 0;
    let pipe_path = Path::new("pipe:[554433]");

    // 1. cat reads ~/.ssh/id_rsa
    let secret = simulate_file_open_check("/home/user/.ssh/id_rsa", "/bin/cat");
    assert_eq!(secret, Some(SecretCategory::SshKey));
    taint_mgr.mark_tainted(cat_tgid);
    assert!(taint_mgr.is_tainted(cat_tgid));
    assert!(!taint_mgr.is_tainted(curl_tgid));

    // 2. cat writes to stdout (pipe) -> INODE_STORAGE marked tainted
    let write_res = evaluate_file_permission(&taint_mgr, cat_tgid, pipe_dev, pipe_ino, pipe_path, MAY_WRITE, true, false);
    assert!(write_res.is_some());

    // 3. curl reads from stdin (same pipe) -> TASK_STORAGE inherits taint!
    let read_res = evaluate_file_permission(&taint_mgr, curl_tgid, pipe_dev, pipe_ino, pipe_path, MAY_READ, true, false);
    assert!(read_res.is_some());
    assert!(taint_mgr.is_tainted(curl_tgid));

    // 4. curl attempts outbound connection to evil.tld
    // Slow-Path evaluates: is_tainted = true -> HoldPending via SO_MARK
    let verdict = evaluate_socket_connect(
        taint_mgr.is_tainted(curl_tgid),
        false, // not allowed
        true,  // curl is dpkg package
        true,  // use NFQUEUE
    );

    assert_eq!(
        verdict,
        SocketConnectVerdict::SlowPathHoldNfqueue {
            so_mark: SENTINEL_SO_MARK,
        }
    );
}

#[test]
fn test_scenario_2_tempfile_exfiltration() {
    let taint_mgr = TaintMapManager::new();
    let bash_tgid = 5001;
    let curl_tgid = 5002;
    let file_ino = 887766;
    let file_dev = 1;
    let file_path = Path::new("/tmp/stolen_key.txt");

    // Process is tainted from reading secret
    taint_mgr.mark_tainted(bash_tgid);

    // Writes to /tmp/stolen_key.txt
    evaluate_file_permission(&taint_mgr, bash_tgid, file_dev, file_ino, file_path, MAY_WRITE, false, false);

    // Another process reads /tmp/stolen_key.txt
    evaluate_file_permission(&taint_mgr, curl_tgid, file_dev, file_ino, file_path, MAY_READ, false, false);

    // curl must now be tainted
    assert!(taint_mgr.is_tainted(curl_tgid));
}

#[test]
fn test_scenario_3_lolbin_discount_prevention() {
    // Verified that curl reading a secret CANNOT get TRUSTED_PACKAGE_CONTEXT discount
    let firings = vec![
        sentinel_common::risk::RuleFiring {
            rule_id: RuleId::SecretNonOwner,
            weight: 40,
            reason: "Чтение защищенного секрета".into(),
        },
        sentinel_common::risk::RuleFiring {
            rule_id: RuleId::TrustedPackageContext,
            weight: -35,
            reason: "Системный пакет curl".into(),
        },
    ];

    let score = sentinel_common::risk::RiskScore::compute(firings);

    // Discount must be stripped, minimum floor 40 (GREY)
    assert_eq!(score.total, 40);
    assert!(!score.firings.iter().any(|f| f.rule_id == RuleId::TrustedPackageContext));
    assert_eq!(score.classify(&RiskThresholds::default()), Verdict::Grey);
}

#[test]
fn test_scenario_4_memfd_fileless_detection() {
    assert!(is_memfd_or_fileless("/memfd:payload (deleted)"));
    assert!(is_memfd_or_fileless("memfd:dropper"));
    assert!(is_memfd_or_fileless("/proc/self/fd/4"));
    assert!(!is_memfd_or_fileless("/usr/bin/curl"));
}

#[test]
fn test_scenario_5_taint_hygiene() {
    // Exempt devices and sessions
    assert!(TaintHygiene::is_exempt_path("/dev/pts/2"));
    assert!(TaintHygiene::is_exempt_path("/dev/null"));
    assert!(TaintHygiene::is_exempt_path("/tmp/.X11-unix/X0"));

    // Public keys and config must NOT taint
    assert!(!TaintHygiene::is_strictly_private_secret("/home/user/.ssh/id_ed25519.pub"));
    assert!(!TaintHygiene::is_strictly_private_secret("/home/user/.ssh/config"));
    assert!(!TaintHygiene::is_strictly_private_secret("/home/user/.ssh/known_hosts"));

    // Private keys DO taint
    assert!(TaintHygiene::is_strictly_private_secret("/home/user/.ssh/id_ed25519"));
    assert!(TaintHygiene::is_strictly_private_secret("/home/user/.ssh/id_rsa"));
}

#[test]
fn test_scenario_6_multithreaded_stealer_group_leader_taint() {
    let taint_mgr = TaintMapManager::new();
    let process_tgid = 6000;
    let thread_a_tid = 6001; // reads ~/.ssh/id_ed25519
    let thread_b_tid = 6002; // attempts network exfiltration

    // Register sibling threads under the same process group leader
    taint_mgr.register_thread(thread_a_tid, process_tgid);
    taint_mgr.register_thread(thread_b_tid, process_tgid);

    // Initial state: clean
    assert!(!taint_mgr.is_tainted(process_tgid));
    assert!(!taint_mgr.is_tainted(thread_a_tid));
    assert!(!taint_mgr.is_tainted(thread_b_tid));

    // Thread A reads secret -> taints its group leader in TASK_STORAGE
    let secret = simulate_file_open_check("/home/user/.ssh/id_ed25519", "/tmp/stealer");
    assert_eq!(secret, Some(SecretCategory::SshKey));
    taint_mgr.mark_tainted(thread_a_tid);

    // Verification: Thread B MUST immediately be recognized as tainted!
    assert!(taint_mgr.is_tainted(thread_b_tid), "Multi-threading bypass failed: Thread B is not tainted!");
    assert!(taint_mgr.is_tainted(process_tgid));

    // When Thread B connects to socket, Slow-Path hold MUST trigger:
    let verdict = evaluate_socket_connect(
        taint_mgr.is_tainted(thread_b_tid),
        false,
        false,
        true,
    );
    assert_eq!(
        verdict,
        SocketConnectVerdict::SlowPathHoldNfqueue {
            so_mark: SENTINEL_SO_MARK
        }
    );
}

#[test]
fn test_scenario_7_udp_quic_dns_connectionless_exfiltration() {
    let taint_mgr = TaintMapManager::new();
    let tgid = 6200;

    // Process is tainted
    taint_mgr.mark_tainted(tgid);

    // Sends raw UDP packet via socket_sendmsg (e.g. DNS tunnel or curl --http3 QUIC)
    let verdict = sentinel_ebpf::programs::socket_sendmsg::evaluate_socket_sendmsg(
        taint_mgr.is_tainted(tgid),
        false,
        false,
        true,
        false,
    );

    assert_eq!(
        verdict,
        SocketConnectVerdict::SlowPathHoldNfqueue {
            so_mark: SENTINEL_SO_MARK
        }
    );
}

#[test]
fn test_scenario_8_preopened_socket_exfiltration() {
    let taint_mgr = TaintMapManager::new();
    let tgid = 6300;

    // 1. Process starts clean and opens a TCP socket
    let initial_verdict = evaluate_socket_connect(
        taint_mgr.is_tainted(tgid),
        false,
        true,
        true,
    );
    assert_eq!(initial_verdict, SocketConnectVerdict::FastPathAllow);

    // 2. Later, process reads secret -> becomes tainted!
    taint_mgr.mark_tainted(tgid);

    // 3. Process tries to send data over the ALREADY OPENED socket!
    // lsm/socket_sendmsg & cgroup_skb/egress check must intercept it:
    let send_verdict = sentinel_ebpf::programs::socket_sendmsg::evaluate_socket_sendmsg(
        taint_mgr.is_tainted(tgid),
        false,
        true,
        true,
        true, // is_preopened
    );

    assert_eq!(
        send_verdict,
        SocketConnectVerdict::SlowPathHoldNfqueue {
            so_mark: SENTINEL_SO_MARK
        }
    );
}

#[test]
fn test_scenario_9_ipc_taint_laundering_af_unix() {
    let taint_mgr = TaintMapManager::new();
    let infected_tgid = 6400;
    let clean_helper_tgid = 6401;
    let ipc_socket = Path::new("/tmp/clean_worker.sock");

    taint_mgr.mark_tainted(infected_tgid);
    assert!(!taint_mgr.is_tainted(clean_helper_tgid));

    // Infected process attempts to send stolen secret to clean helper via AF_UNIX
    let verdict = sentinel_ebpf::programs::unix_may_send::evaluate_unix_may_send(
        &taint_mgr,
        infected_tgid,
        clean_helper_tgid,
        ipc_socket,
    );

    assert_eq!(verdict, sentinel_ebpf::UnixSendVerdict::TaintReceiver);
    // Clean helper must now be marked as tainted in TASK_STORAGE!
    assert!(taint_mgr.is_tainted(clean_helper_tgid));
}

#[test]
fn test_scenario_10_ptrace_memory_snooping_denied() {
    let taint_mgr = TaintMapManager::new();
    let tainted_stealer = 6500;
    let clean_target = 6501;

    taint_mgr.mark_tainted(tainted_stealer);

    // Tainted process attempts to attach to or inject into clean process
    let verdict = sentinel_ebpf::programs::ptrace_access_check::evaluate_ptrace_access_check(
        &taint_mgr,
        tainted_stealer,
        clean_target,
        0,
    );

    assert_eq!(verdict, sentinel_ebpf::PtraceVerdict::Deny);
}

#[test]
fn test_scenario_11_cross_process_environ_snooping() {
    // Attempting to read another process's environment variables
    assert!(TaintMapManager::is_proc_environ_or_mem_snoop(1000, "/proc/2000/environ"));
    assert!(TaintMapManager::is_proc_environ_or_mem_snoop(1000, "/proc/2000/mem"));

    // Reading own environ is permitted
    assert!(!TaintMapManager::is_proc_environ_or_mem_snoop(1000, "/proc/1000/environ"));
}

#[test]
fn test_scenario_12_anti_spoofing_never_freeze() {
    // Test that NeverFreezeChecker prevents spoofing comm via prctl(PR_SET_NAME)
    let checker = sentineld_mock_never_freeze::NeverFreezeChecker::new();

    // Legitimate systemd and gnome-shell
    assert!(checker.is_protected(1, Path::new("/usr/lib/systemd/systemd"), 0));
    assert!(checker.is_protected(500, Path::new("/usr/bin/gnome-shell"), 1000));

    // Malicious fake binaries trying to spoof names
    assert!(!checker.is_protected(7000, Path::new("/tmp/gnome-shell"), 1000));
    assert!(!checker.is_protected(7001, Path::new("/tmp/systemd"), 0));
    assert!(!checker.is_protected(7002, Path::new("/dev/shm/pipewire"), 1000));
    assert!(!checker.is_protected(7003, Path::new("/home/user/Downloads/kwin_wayland"), 1000));
}

#[test]
fn test_scenario_13_dos_protection_and_flow_aggregation() {
    let orchestrator = sentineld_mock_never_freeze::MockOrchestrator::new(2);

    let tgid = 9999;
    let dest = ("192.0.2.1".to_string(), 443);

    // First attempt: Accepted into pending queue
    assert!(orchestrator.hold(tgid, &dest));

    // Rapid duplicate to same destination: Aggregated, no duplicate queue slot
    assert!(orchestrator.hold(tgid, &dest));

    // Different destination: fills capacity
    let dest2 = ("192.0.2.2".to_string(), 80);
    assert!(orchestrator.hold(tgid, &dest2));

    // Third unique destination: Queue full! Packet dropped to prevent DoS!
    let dest3 = ("192.0.2.3".to_string(), 53);
    assert!(!orchestrator.hold(tgid, &dest3), "DoS protection failed to drop on overflow!");
}

#[test]
fn test_scenario_14_tofu_tampered_binary_detection() {
    let temp_db = std::env::temp_dir().join(format!("tofu_rt_{}.json", uuid::Uuid::new_v4()));
    let tofu = sentineld_mock_tofu::TofuManager::new(&temp_db);

    let binary = Path::new("/home/user/.cargo/bin/custom_agent");
    let sha_v1 = "1111222233334444555566667777888811112222333344445555666677778888";
    let sha_tampered = "9999888877776666555544443333222299998888777766665555444433332222";

    // 1. Initial registration
    let res1 = tofu.check_or_register(binary, sha_v1);
    assert_eq!(res1, sentineld_mock_tofu::TofuCheckResult::NewRegistered);

    // 2. Legitimate run
    let res2 = tofu.check_or_register(binary, sha_v1);
    assert_eq!(res2, sentineld_mock_tofu::TofuCheckResult::Verified);

    // 3. Binary modified on disk
    let res3 = tofu.check_or_register(binary, sha_tampered);
    assert_eq!(res3, sentineld_mock_tofu::TofuCheckResult::Tampered);

    let _ = std::fs::remove_file(temp_db);
}

#[test]
fn test_scenario_15_contextual_policy_ssh_rules() {
    let engine = sentineld_mock_policy::ContextPolicyEngine::default();

    // SSH key access for git/ssh to github.com:22 -> Pre-Approved!
    let allowed = engine.is_allowed(
        Path::new("/usr/bin/ssh"),
        Some(&SecretCategory::SshKey),
        Some("140.82.112.3"),
        22,
        Some("github.com"),
    );
    assert!(allowed, "Legitimate SSH connection to GitHub should be allowed by context policy");

    // Same SSH key accessed by ssh going to unknown rogue port 4444 -> Prompt / Block!
    let denied = engine.is_allowed(
        Path::new("/usr/bin/ssh"),
        Some(&SecretCategory::SshKey),
        Some("185.220.101.5"),
        4444,
        None,
    );
    assert!(!denied, "SSH connecting to arbitrary rogue port must not be pre-approved");
}

#[test]
fn test_scenario_16_hotpath_microbenchmark_clean_file_permission() {
    let taint_mgr = TaintMapManager::new();
    let clean_tgid = 1200;
    let dev = 5;
    let ino = 10001;
    let path = Path::new("/usr/lib/x86_64-linux-gnu/libc.so.6");

    let start = std::time::Instant::now();
    for _ in 0..10_000 {
        let res = taint_mgr.handle_file_permission(
            clean_tgid,
            dev,
            ino,
            path,
            MAY_READ,
            false,
            false,
        );
        assert!(res.is_none());
    }
    let elapsed = start.elapsed();
    // 10,000 checks should execute in just a few milliseconds on modern CPUs
    assert!(elapsed.as_millis() < 50, "Hot-path is too slow: {:?}", elapsed);
}

mod sentineld_mock_never_freeze {
    use super::*;

    pub struct NeverFreezeChecker {
        names: std::collections::HashSet<String>,
    }

    impl NeverFreezeChecker {
        pub fn new() -> Self {
            let mut names = std::collections::HashSet::new();
            names.insert("gnome-shell".into());
            names.insert("kwin_wayland".into());
            names.insert("dbus-daemon".into());
            names.insert("pipewire".into());
            Self { names }
        }

        pub fn is_protected(&self, tgid: u32, path: &Path, uid: u32) -> bool {
            if tgid == 1 {
                return true;
            }
            let s = path.to_string_lossy();
            if s.starts_with("/tmp") || s.starts_with("/dev/shm") || s.contains("/Downloads/") {
                return false;
            }
            if !s.starts_with("/usr/bin/") && !s.starts_with("/usr/lib/") && !s.starts_with("/bin/") {
                return false;
            }
            let name = path.file_name().unwrap().to_string_lossy();
            if name.starts_with("systemd") && (uid == 0 || uid < 1000) {
                return true;
            }
            self.names.contains(&name.to_string())
        }
    }

    pub struct MockOrchestrator {
        limit: usize,
        held: std::sync::Mutex<std::collections::HashMap<(u32, String, u16), u32>>,
    }

    impl MockOrchestrator {
        pub fn new(limit: usize) -> Self {
            Self {
                limit,
                held: std::sync::Mutex::new(std::collections::HashMap::new()),
            }
        }

        pub fn hold(&self, tgid: u32, dest: &(String, u16)) -> bool {
            let mut map = self.held.lock().unwrap();
            let key = (tgid, dest.0.clone(), dest.1);
            if let Some(count) = map.get_mut(&key) {
                *count += 1;
                return true; // Aggregated
            }
            if map.len() >= self.limit {
                return false; // Queue full -> dropped!
            }
            map.insert(key, 1);
            true
        }
    }
}

mod sentineld_mock_tofu {
    use std::path::{Path, PathBuf};
    use std::collections::HashMap;

    #[derive(Debug, PartialEq, Eq)]
    pub enum TofuCheckResult {
        NewRegistered,
        Verified,
        Tampered,
    }

    pub struct TofuManager {
        map: std::sync::Mutex<HashMap<PathBuf, String>>,
    }

    impl TofuManager {
        pub fn new(_db: &Path) -> Self {
            Self {
                map: std::sync::Mutex::new(HashMap::new()),
            }
        }

        pub fn check_or_register(&self, path: &Path, hash: &str) -> TofuCheckResult {
            let mut map = self.map.lock().unwrap();
            if let Some(existing) = map.get(path) {
                if existing == hash {
                    TofuCheckResult::Verified
                } else {
                    TofuCheckResult::Tampered
                }
            } else {
                map.insert(path.to_path_buf(), hash.to_string());
                TofuCheckResult::NewRegistered
            }
        }
    }
}

mod sentineld_mock_policy {
    use super::*;

    #[derive(Default)]
    pub struct ContextPolicyEngine;

    impl ContextPolicyEngine {
        pub fn is_allowed(
            &self,
            path: &Path,
            _cat: Option<&SecretCategory>,
            dest_ip: Option<&str>,
            dest_port: u16,
            dest_domain: Option<&str>,
        ) -> bool {
            let s = path.to_string_lossy();
            if s.ends_with("/ssh") {
                if dest_port == 22 && (dest_domain == Some("github.com") || dest_ip == Some("140.82.112.3")) {
                    return true;
                }
            }
            false
        }
    }
}

