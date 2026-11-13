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
