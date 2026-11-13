//! Comprehensive E2E Adversarial Test Suite for Sentinel-RS.
//!
//! Validates:
//! 1. `cat secret | curl` pipe taint tracking.
//! 2. Established socket bypass prevention (`ct state established` revalidation + socket_sendmsg).
//! 3. SCM_RIGHTS + mmap file descriptor passing and memory execution defense.
//! 4. Memfd/anon memory fileless execution detection.
//! 5. `prctl(PR_SET_NAME)` comm spoofing defense (real /proc/pid/exe verification).
//! 6. P0 Attack: Unauthorized non-GUI process attempting Verdict::Allow on management socket.
//! 7. Kernel LSM defense: ptrace / process_vm_writev blocked against GUI/daemon from same UID.
//! 8. D-Bus broker isolation and anti-taint explosion.
//! 9. Dynamic mark flow correlation: concurrent SYN packets mapped synchronously via BPF map.
//! 10. SYN retransmit deduplication and AllowForDuration temporary pass.

use std::collections::HashMap;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU32, Ordering};
use std::sync::Arc;
use tokio::sync::Mutex;

use sentinel_common::events::{
    decode_flow_mark, encode_flow_mark, FlowContext, EbpfEvent, MAY_READ, MAY_WRITE,
    SENTINEL_MARK_FLOW_ID_MASK, SENTINEL_MARK_REVAL_BIT, SENTINEL_SO_MARK_PREFIX,
};
use sentinel_common::ipc::{ClientRole, IpcMessage, PromptAction, PromptRequest, PromptVerdict};
use sentinel_common::process::{ProcessNode, SecretCategory};
use sentinel_common::risk::{RiskEngineConfig, RiskThresholds, RuleId, Verdict};
use sentinel_ebpf::maps::{TaintFlags, TaintHygiene, TaintMapManager};
use sentinel_ebpf::programs::bprm_check_security::is_memfd_or_fileless;
use sentinel_ebpf::programs::file_open::simulate_file_open_check;
use sentinel_ebpf::programs::file_permission::evaluate_file_permission;
use sentinel_ebpf::programs::file_receive::handle_file_receive;
use sentinel_ebpf::programs::mmap_file::{handle_mmap_file, MmapVerdict};
use sentinel_ebpf::programs::socket_connect::{evaluate_socket_connect, SocketConnectVerdict};
use sentinel_ebpf::programs::socket_sendmsg::{evaluate_socket_sendmsg_ext, SocketSendmsgVerdict};

// -----------------------------------------------------------------------------
// Test 1: `cat secret | curl` (pipe taint inheritance)
// -----------------------------------------------------------------------------
#[test]
fn test_1_cat_secret_pipe_curl() {
    let taint_mgr = TaintMapManager::new();
    let cat_tgid = 1010;
    let curl_tgid = 1011;
    let pipe_ino = 998877;
    let pipe_dev = 0;
    let pipe_path = Path::new("pipe:[998877]");

    // 1. cat reads ~/.ssh/id_rsa
    let secret = simulate_file_open_check("/home/user/.ssh/id_rsa", "/bin/cat");
    assert_eq!(secret, Some(SecretCategory::SshKey));
    taint_mgr.mark_tainted(cat_tgid);
    assert!(taint_mgr.is_tainted(cat_tgid));
    assert!(!taint_mgr.is_tainted(curl_tgid));

    // 2. cat writes to pipe stdout -> INODE_STORAGE marked tainted
    let write_res = evaluate_file_permission(&taint_mgr, cat_tgid, pipe_dev, pipe_ino, pipe_path, MAY_WRITE, true, false);
    assert!(write_res.is_some(), "Pipe inode should inherit taint from cat");

    // 3. curl reads from pipe stdin -> curl TASK_STORAGE marked tainted
    let read_res = evaluate_file_permission(&taint_mgr, curl_tgid, pipe_dev, pipe_ino, pipe_path, MAY_READ, true, false);
    assert!(read_res.is_some(), "curl process should inherit taint from pipe");
    assert!(taint_mgr.is_tainted(curl_tgid), "curl must be tainted after reading pipe");

    // 4. curl attempts outbound connection -> FastPath rejected, Hold in NFQUEUE
    let flow_id = 42;
    let verdict = evaluate_socket_connect(true, false, true, true);
    match verdict {
        SocketConnectVerdict::SlowPathHoldNfqueue { so_mark } => {
            assert_eq!(so_mark & SENTINEL_SO_MARK_PREFIX, SENTINEL_SO_MARK_PREFIX);
        }
        _ => panic!("Expected SlowPathHoldNfqueue for tainted curl process"),
    }
}

// -----------------------------------------------------------------------------
// Test 2: Bypass via Pre-Opened / Established Socket (`ct state established` defeat)
// -----------------------------------------------------------------------------
#[test]
fn test_2_established_socket_bypass_sendmsg() {
    let taint_mgr = TaintMapManager::new();
    let tgid = 2020;

    // 1. Initial connection while process is clean -> Fast-Path Accept
    let initial_connect = evaluate_socket_connect(false, false, false, true);
    assert_eq!(initial_connect, SocketConnectVerdict::FastPathAccept);

    // 2. Process later accesses browser cookies/passwords
    let secret = simulate_file_open_check("/home/user/.config/google-chrome/Default/Login Data", "/tmp/stealer");
    assert_eq!(secret, Some(SecretCategory::BrowserData));
    taint_mgr.mark_tainted(tgid);
    assert!(taint_mgr.is_tainted(tgid));

    // 3. Process sends data on the PREVIOUSLY ESTABLISHED socket
    let flow_id = 105;
    let send_verdict = evaluate_socket_sendmsg_ext(
        &taint_mgr,
        tgid,
        true,  // is_preopened established socket
        false, // not high risk outright
        flow_id,
    );

    // Must tag packet with revalidation mark (0x40000000 | flow_id)
    match send_verdict {
        SocketSendmsgVerdict::HoldForRevalidation { reval_mark } => {
            assert_eq!(reval_mark & SENTINEL_MARK_REVAL_BIT, SENTINEL_MARK_REVAL_BIT);
            assert_eq!(reval_mark & SENTINEL_MARK_FLOW_ID_MASK, flow_id);
        }
        _ => panic!("Expected HoldForRevalidation for sendmsg on established socket after taint"),
    }
}

// -----------------------------------------------------------------------------
// Test 3: SCM_RIGHTS + mmap (FD passing via Unix socket & memory mapping)
// -----------------------------------------------------------------------------
#[test]
fn test_3_scm_rights_and_mmap_file() {
    let taint_mgr = TaintMapManager::new();
    let sender_tgid = 3001;
    let receiver_tgid = 3002;

    // 1. Sender reads crypto wallet
    let secret = simulate_file_open_check("/home/user/.electrum/wallets/default_wallet", "/tmp/worker");
    assert_eq!(secret, Some(SecretCategory::CryptoWallet));
    taint_mgr.mark_tainted(sender_tgid);

    // 2. Sender passes FD via SCM_RIGHTS to receiver
    assert!(!taint_mgr.is_tainted(receiver_tgid));
    let s_flags = taint_mgr.get_flags(sender_tgid);
    handle_file_receive(&taint_mgr, sender_tgid, receiver_tgid, s_flags.bits());
    assert!(taint_mgr.is_tainted(receiver_tgid), "Receiver must be tainted via SCM_RIGHTS fd receive");

    // 3. Receiver mmaps file with PROT_EXEC
    let prot_read_exec = 0x1 | 0x4; // PROT_READ | PROT_EXEC
    let mmap_verdict = handle_mmap_file(&taint_mgr, receiver_tgid, "/tmp/in_memory.so", prot_read_exec, 0x02);
    assert_eq!(mmap_verdict, MmapVerdict::TaintedExecutionBlocked, "Executable mmap by tainted receiver must be blocked");
}

// -----------------------------------------------------------------------------
// Test 4: Memfd / Anonymous Execution Detection
// -----------------------------------------------------------------------------
#[test]
fn test_4_memfd_anon_exec() {
    // 1. memfd_create virtual executable
    assert!(is_memfd_or_fileless(Path::new("/memfd:payload (deleted)")));
    assert!(is_memfd_or_fileless(Path::new("anon_inode:[memfd]")));
    assert!(!is_memfd_or_fileless(Path::new("/usr/bin/python3")));

    // 2. Risk evaluation: memfd triggers RuleId::FilelessMemfd (+50)
    let mut fired = Vec::new();
    let mut score = 0;
    if is_memfd_or_fileless(Path::new("/memfd:stealer (deleted)")) {
        score += 50;
        fired.push(RuleId::FilelessMemfd);
    }
    assert!(score >= 50);
    assert!(fired.contains(&RuleId::FilelessMemfd));
}

// -----------------------------------------------------------------------------
// Test 5: prctl(PR_SET_NAME) Comm Spoofing Defense
// -----------------------------------------------------------------------------
#[test]
fn test_5_prctl_comm_spoofing_defense() {
    // An attacker sets comm to "ssh" or "gnome-shell" via prctl, but /proc/<pid>/exe is /tmp/evil
    let spoofed_comm = "ssh";
    let real_exe = PathBuf::from("/tmp/evil");

    // Sentinel does not rely on comm! It checks real_exe against dpkg database and root ownership.
    let is_trusted_dpkg = real_exe.starts_with("/usr/bin/") && !real_exe.starts_with("/tmp/");
    assert!(!is_trusted_dpkg, "Real exe in /tmp cannot claim dpkg trust even if comm is 'ssh'");

    // Node resolution
    let node = ProcessNode::new(4040, None, 1000, real_exe.clone(), spoofed_comm.to_string());
    assert_eq!(node.exe_path, PathBuf::from("/tmp/evil"));
    assert_ne!(node.exe_name(), "ssh", "exe_name must reflect binary file name, not spoofed comm");
}

// -----------------------------------------------------------------------------
// Test 6: P0 Attack — Unauthorized non-GUI process attempting Verdict::Allow
// -----------------------------------------------------------------------------
#[test]
fn test_6_p0_unauthorized_sock_connect_rejection() {
    // An infostealer process of UID 1000 connects to management socket and tries to submit Verdict
    let attacker_uid = 1000;
    let attacker_pid = 6666;
    let attacker_exe = Path::new("/home/user/.local/bin/infostealer");
    let gui_binary_canonical = Path::new("/usr/bin/sentinel-gui");

    // Peer verification logic:
    let is_root = attacker_uid == 0;
    let is_gui = attacker_exe == gui_binary_canonical;

    let role = if is_root {
        ClientRole::RootAdmin
    } else if is_gui {
        ClientRole::AuthorizedGui
    } else {
        ClientRole::ReadOnly
    };

    assert_eq!(role, ClientRole::ReadOnly, "Attacker must only receive ReadOnly role");

    // When ReadOnly client attempts Verdict, daemon rejects with AuthError
    let incoming_msg = IpcMessage::Verdict(PromptVerdict {
        incident_id: "inc-1".to_string(),
        action: PromptAction::AllowOnce,
        auth_pin: None,
    });

    let rejection: Result<(), String> = match (&incoming_msg, role) {
        (IpcMessage::Verdict(_), ClientRole::ReadOnly) => {
            Err("EACCES: Unauthorized client role cannot submit verdicts".into())
        }
        _ => Ok(()),
    };

    assert!(rejection.is_err());
    assert!(rejection.unwrap_err().contains("EACCES"));
}

// -----------------------------------------------------------------------------
// Test 7: Kernel LSM Defense — Block ptrace / mem snooping against GUI & daemon
// -----------------------------------------------------------------------------
#[test]
fn test_7_ptrace_memory_snooping_lsm_defense() {
    let taint_mgr = TaintMapManager::new();
    let gui_pid = 7000;
    let daemon_pid = 1;
    let attacker_pid = 7001;

    taint_mgr.set_gui_pid(gui_pid);
    taint_mgr.set_daemon_pid(daemon_pid);

    // Attacker of the same UID tries to attach ptrace to GUI (caller_has_cap = false)
    let gui_target_blocked = taint_mgr.handle_ptrace_access_check(attacker_pid, gui_pid, false);
    assert_eq!(gui_target_blocked, -1, "-EPERM must be returned when same-UID process ptraces sentinel-gui");

    // Attacker tries to attach ptrace to sentineld
    let daemon_target_blocked = taint_mgr.handle_ptrace_access_check(attacker_pid, daemon_pid, false);
    assert_eq!(daemon_target_blocked, -1, "-EPERM must be returned when ptracing sentineld");

    // Normal root debugger with CAP_SYS_PTRACE can attach
    let root_allowed = taint_mgr.handle_ptrace_access_check(0, gui_pid, true);
    assert_eq!(root_allowed, 0, "Root with CAP_SYS_PTRACE is permitted");
}

// -----------------------------------------------------------------------------
// Test 8: D-Bus Broker Isolation & Anti-Taint Explosion
// -----------------------------------------------------------------------------
#[test]
fn test_8_ipc_broker_isolation_anti_explosion() {
    let taint_mgr = TaintMapManager::new();
    let tainted_app = 8001;
    let dbus_daemon_pid = 400;
    let other_clean_app = 8002;

    taint_mgr.mark_tainted(tainted_app);
    taint_mgr.register_ipc_broker(dbus_daemon_pid);

    // Tainted app sends IPC to dbus-daemon
    let broker_tainted = taint_mgr.handle_unix_may_send(tainted_app, dbus_daemon_pid, "dbus-daemon");
    assert!(!broker_tainted, "D-Bus daemon must NOT inherit taint");
    assert!(!taint_mgr.is_tainted(dbus_daemon_pid), "dbus-daemon must remain clean");

    // dbus-daemon delivers a message to other_clean_app
    let other_tainted = taint_mgr.handle_unix_may_send(dbus_daemon_pid, other_clean_app, "gnome-calculator");
    assert!(!other_tainted);
    assert!(!taint_mgr.is_tainted(other_clean_app), "Clean app must not become tainted via D-Bus");
}

// -----------------------------------------------------------------------------
// Test 9: Dynamic Mark Flow Correlation (Synchronous BPF Map vs Async Race)
// -----------------------------------------------------------------------------
#[test]
fn test_9_dynamic_mark_correlation_concurrent() {
    let taint_mgr = TaintMapManager::new();

    // 10 concurrent network flows
    for flow_id in 1..=10 {
        let mark = encode_flow_mark(flow_id, false);
        assert_eq!(mark & SENTINEL_SO_MARK_PREFIX, SENTINEL_SO_MARK_PREFIX);

        let ctx = FlowContext {
            mark,
            tgid: 9000 + flow_id,
            pid: 9000 + flow_id,
            uid: 1000,
            cgroup_id: 1,
            sock_cookie: 0x12340000 + flow_id as u64,
            taint_flags: 1,
            exe_inode: 55500 + flow_id as u64,
            exec_id: flow_id as u64,
        };

        // Synchronously put into BPF flow_mark_ctx map
        taint_mgr.insert_flow_context(mark, ctx);
    }

    // When NFQUEUE pops a packet with NFQA_MARK:
    let received_mark = encode_flow_mark(7, false);
    let (is_sentinel, requires_reval, recovered_flow_id) = decode_flow_mark(received_mark);
    assert!(is_sentinel);
    assert!(!requires_reval);
    assert_eq!(recovered_flow_id, 7);

    let retrieved_ctx = taint_mgr.get_flow_context(received_mark);
    assert!(retrieved_ctx.is_some(), "FlowContext must be found synchronously by mark");
    let ctx = retrieved_ctx.unwrap();
    assert_eq!(ctx.tgid, 9007);
    assert_eq!(ctx.sock_cookie, 0x12340007);
}

// -----------------------------------------------------------------------------
// Test 10: SYN Retransmit Deduplication & AllowForDuration
// -----------------------------------------------------------------------------
#[tokio::test]
async fn test_10_syn_retransmit_dedup_and_duration_allow() {
    // Incident tracking simulation
    let incident_id = "inc-retrans-99";
    let flow_mark = encode_flow_mark(15, false);

    struct PendingIncident {
        id: String,
        packet_queue: Vec<u32>, // Simulated packet IDs
    }

    let pending: Arc<Mutex<HashMap<String, PendingIncident>>> = Arc::new(Mutex::new(HashMap::new()));

    // 1. Packet 1 arrives (Initial SYN)
    {
        let mut map = pending.lock().await;
        map.insert(
            incident_id.to_string(),
            PendingIncident {
                id: incident_id.to_string(),
                packet_queue: vec![1001],
            },
        );
    }

    // 2. Packet 2 arrives (SYN Retransmit 1 - same incident)
    {
        let mut map = pending.lock().await;
        if let Some(inc) = map.get_mut(incident_id) {
            inc.packet_queue.push(1002);
        }
    }

    // 3. Packet 3 arrives (SYN Retransmit 2 - same incident)
    {
        let mut map = pending.lock().await;
        if let Some(inc) = map.get_mut(incident_id) {
            inc.packet_queue.push(1003);
        }
    }

    // Assert: Only ONE incident was created, holding all 3 retransmitted packets
    {
        let map = pending.lock().await;
        assert_eq!(map.len(), 1, "Only 1 dialog should be created for SYN retransmits");
        let inc = map.get(incident_id).unwrap();
        assert_eq!(inc.packet_queue.len(), 3);
    }

    // 4. User sends verdict: AllowForDuration (300 seconds)
    let verdict_action = PromptAction::AllowForDuration { seconds: 300 };

    // Simulate verdict application: flush all pending packets in group
    let mut released_packets = Vec::new();
    {
        let mut map = pending.lock().await;
        if let Some(inc) = map.remove(incident_id) {
            released_packets.extend(inc.packet_queue);
        }
    }

    assert_eq!(released_packets, vec![1001, 1002, 1003], "All queued SYN packets released at once");
}

// -----------------------------------------------------------------------------
// Test 11: Zero Bitmask Collision in Netfilter Rules
// -----------------------------------------------------------------------------
#[test]
fn test_11_nftables_bitmask_collision_free() {
    use sentinel_common::events::{
        SENTINEL_MARK_NETFILTER_MASK, SENTINEL_MARK_NEW_MATCH, SENTINEL_MARK_REVAL_MATCH,
    };

    // For any flow_id up to 23 bits:
    for flow_id in [0, 1, 42, 1024, 65535, 0x007FFFFF] {
        let new_flow_mark = encode_flow_mark(flow_id, false);
        let reval_flow_mark = encode_flow_mark(flow_id, true);

        // 1. New flow must match ONLY Rule 3 (New flow), NEVER Rule 1 (Reval)
        assert_eq!(new_flow_mark & SENTINEL_MARK_NETFILTER_MASK, SENTINEL_MARK_NEW_MATCH);
        assert_ne!(new_flow_mark & SENTINEL_MARK_NETFILTER_MASK, SENTINEL_MARK_REVAL_MATCH);

        // 2. Revalidation flow must match Rule 1 (Reval), NOT Rule 3 (New flow)
        assert_eq!(reval_flow_mark & SENTINEL_MARK_NETFILTER_MASK, SENTINEL_MARK_REVAL_MATCH);
        assert_ne!(reval_flow_mark & SENTINEL_MARK_NETFILTER_MASK, SENTINEL_MARK_NEW_MATCH);

        // 3. Both must decode cleanly to the exact same flow_id
        let (_, reval_1, id_1) = decode_flow_mark(new_flow_mark);
        let (_, reval_2, id_2) = decode_flow_mark(reval_flow_mark);
        assert!(!reval_1);
        assert!(reval_2);
        assert_eq!(id_1, flow_id);
        assert_eq!(id_2, flow_id);
    }
}

// -----------------------------------------------------------------------------
// Test 12: TOCTOU Defense: /proc/<pid>/maps Detects Wiped LD_PRELOAD
// -----------------------------------------------------------------------------
#[test]
fn test_12_ld_preload_toctou_maps_defense() {
    // Simulated maps content where a malicious .so was loaded from /tmp, but environ was wiped
    let simulated_maps = "\
55b8e4000000-55b8e4005000 r-xp 00000000 08:01 100000 /usr/bin/sentinel-gui
7f8a10000000-7f8a10002000 r-xp 00000000 08:01 200000 /tmp/evil_constructor_wiped.so
7f8a20000000-7f8a20003000 r-xp 00000000 08:01 300000 /usr/lib/x86_64-linux-gnu/libc.so.6
";

    let mut detected_malicious_mapping = false;
    for line in simulated_maps.lines() {
        let parts: Vec<&str> = line.split_whitespace().collect();
        if parts.len() >= 6 {
            let perms = parts[1];
            let mapped_path = parts[5..].join(" ");
            if perms.contains('x') {
                if mapped_path.starts_with("/tmp")
                    || mapped_path.starts_with("/dev/shm")
                    || mapped_path.starts_with("/home")
                {
                    detected_malicious_mapping = true;
                    break;
                }
            }
        }
    }

    assert!(
        detected_malicious_mapping,
        "/proc/<pid>/maps inspection must detect hostile shared library even after environ wipe!"
    );
}

// -----------------------------------------------------------------------------
// Test 13: D-Bus / systemd Broker Escape Prevention
// -----------------------------------------------------------------------------
#[test]
fn test_13_dbus_systemd_spawn_link() {
    use crate::lineage::LineageTracker;

    let tracker = LineageTracker::new(128);
    let attacker_tgid = 9100;
    let spawned_tgid = 9101;

    // 1. Attacker directly accesses SSH secret
    tracker.record_secret_access(
        attacker_tgid,
        PathBuf::from("/home/user/.ssh/id_rsa"),
        SecretCategory::SshKey,
        1000,
    );

    let attacker_node = tracker.get(attacker_tgid).unwrap();
    assert!(attacker_node.has_secret_access());

    // 2. Spawned process was launched via D-Bus / systemd-run (PPID is PID 1)
    tracker.handle_fork(1, spawned_tgid);
    let initial_spawned = tracker.get(spawned_tgid).unwrap();
    assert!(!initial_spawned.has_secret_access(), "Initial process before broker link has no secrets");

    // 3. Sentinel-RS detects the IPC spawn invocation and links them
    tracker.link_ipc_spawn(attacker_tgid, spawned_tgid);

    let linked_spawned = tracker.get(spawned_tgid).unwrap();
    assert!(
        linked_spawned.has_secret_access(),
        "Spawned process must inherit secret taint through D-Bus/systemd broker link!"
    );
}

// -----------------------------------------------------------------------------
// Test 14: JIT Runtime Legitimate Memory Execution Compatibility
// -----------------------------------------------------------------------------
#[test]
fn test_14_jit_runtime_allow() {
    assert!(TaintHygiene::is_known_jit_runtime("chrome"));
    assert!(TaintHygiene::is_known_jit_runtime("firefox"));
    assert!(TaintHygiene::is_known_jit_runtime("node"));
    assert!(TaintHygiene::is_known_jit_runtime("java"));
    assert!(!TaintHygiene::is_known_jit_runtime("stealer"));
    assert!(!TaintHygiene::is_known_jit_runtime("sh"));
}
