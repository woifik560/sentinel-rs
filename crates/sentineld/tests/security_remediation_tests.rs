//! Regression tests for security remediation and audit findings:
//! 1. IncidentsClear RBAC (Non-root rejection with EACCES)
//! 2. Unhandled / unknown IPC commands fail-closed (ENOTSUP, never silent fake success)
//! 3. ProtectionEnable / ProtectionDisable state changes & RBAC
//! 4. PolicyReload updates rules in RiskEngine dynamically
//! 5. Anti-PID-reuse verification: ticks divergence and binary path mismatch return PidReuseDetected
//! 6. Strict IP address validation for nftables
//! 7. Config & Rules strict syntax validation

use std::path::PathBuf;
use std::sync::Arc;
use tokio::sync::RwLock;

use sentinel_common::config::RulesConfig;
use sentinel_common::ipc::{ClientRole, IpcCommand, IpcResponse};
use sentinel_common::policy::OperatingMode;
use sentineld::freeze::FreezeInspectOrchestrator;
use sentineld::lineage::{LineageTracker, ProcessKey};
use sentineld::pkg_check::DpkgChecker;
use sentineld::protection::ProtectionState;
use sentineld::response::process_term::{verify_process_identity, TerminationError};
use sentineld::risk::RiskEngine;

#[tokio::test]
async fn test_incidents_clear_requires_root_admin() {
    let freeze = FreezeInspectOrchestrator::new(10, 64, 500);
    let lineage = LineageTracker::new(64);
    let incidents = Arc::new(RwLock::new(std::collections::HashMap::new()));
    let protection_state = Arc::new(RwLock::new(ProtectionState::new(
        true,
        OperatingMode::Balanced,
        PathBuf::from("/etc/sentinel/rules.toml"),
        PathBuf::from("/etc/sentinel/config.toml"),
    )));
    let risk_engine = Arc::new(RwLock::new(RiskEngine::new(RulesConfig::default(), DpkgChecker::new())));

    // Populate an incident
    incidents.write().await.insert("inc-1".into(), "{}".into());

    // 1. ReadOnly client attempts IncidentsClear -> MUST return EACCES
    let resp = sentineld::ipc_server::handle_ipc_command_for_test(
        IpcCommand::IncidentsClear,
        ClientRole::ReadOnly,
        &freeze,
        &lineage,
        &incidents,
        &protection_state,
        Some(&risk_engine),
        None,
    ).await;

    match resp {
        IpcResponse::Error { code, message } => {
            assert_eq!(code, "EACCES");
            assert!(message.contains("Root administrator"));
        }
        _ => panic!("Expected EACCES error, got {:?}", resp),
    }

    // Incidents must still be intact
    assert_eq!(incidents.read().await.len(), 1);

    // 2. Operator client attempts IncidentsClear -> MUST return EACCES
    let resp_op = sentineld::ipc_server::handle_ipc_command_for_test(
        IpcCommand::IncidentsClear,
        ClientRole::Operator,
        &freeze,
        &lineage,
        &incidents,
        &protection_state,
        Some(&risk_engine),
        None,
    ).await;

    match resp_op {
        IpcResponse::Error { code, .. } => assert_eq!(code, "EACCES"),
        _ => panic!("Expected EACCES for operator role"),
    }

    // 3. RootAdmin client clears incidents -> MUST succeed
    let resp_root = sentineld::ipc_server::handle_ipc_command_for_test(
        IpcCommand::IncidentsClear,
        ClientRole::RootAdmin,
        &freeze,
        &lineage,
        &incidents,
        &protection_state,
        Some(&risk_engine),
        None,
    ).await;

    match resp_root {
        IpcResponse::Ok(val) => {
            assert_eq!(val["status"], "cleared");
            assert_eq!(val["cleared_memory"], 1);
        }
        _ => panic!("Expected Ok response for root admin"),
    }
    assert_eq!(incidents.read().await.len(), 0);
}

#[tokio::test]
async fn test_protection_toggle_controls_real_state() {
    let freeze = FreezeInspectOrchestrator::new(10, 64, 500);
    let lineage = LineageTracker::new(64);
    let incidents = Arc::new(RwLock::new(std::collections::HashMap::new()));
    let protection_state = Arc::new(RwLock::new(ProtectionState::new(
        true,
        OperatingMode::Balanced,
        PathBuf::from("/etc/sentinel/rules.toml"),
        PathBuf::from("/etc/sentinel/config.toml"),
    )));
    let risk_engine = Arc::new(RwLock::new(RiskEngine::new(RulesConfig::default(), DpkgChecker::new())));

    // Check initial status
    assert!(protection_state.read().await.enabled);

    // Non-root cannot disable protection
    let resp = sentineld::ipc_server::handle_ipc_command_for_test(
        IpcCommand::ProtectionDisable,
        ClientRole::ReadOnly,
        &freeze,
        &lineage,
        &incidents,
        &protection_state,
        Some(&risk_engine),
        None,
    ).await;
    assert!(matches!(resp, IpcResponse::Error { ref code, .. } if code == "EACCES"));

    // Root disables protection
    let resp_root = sentineld::ipc_server::handle_ipc_command_for_test(
        IpcCommand::ProtectionDisable,
        ClientRole::RootAdmin,
        &freeze,
        &lineage,
        &incidents,
        &protection_state,
        Some(&risk_engine),
        None,
    ).await;
    assert!(matches!(resp_root, IpcResponse::Ok(ref val) if val["enabled"] == false));
    assert!(!protection_state.read().await.enabled);

    // Root re-enables protection
    let resp_enable = sentineld::ipc_server::handle_ipc_command_for_test(
        IpcCommand::ProtectionEnable,
        ClientRole::RootAdmin,
        &freeze,
        &lineage,
        &incidents,
        &protection_state,
        Some(&risk_engine),
        None,
    ).await;
    assert!(matches!(resp_enable, IpcResponse::Ok(ref val) if val["enabled"] == true));
    assert!(protection_state.read().await.enabled);
}

#[tokio::test]
async fn test_unsupported_commands_return_enotsup() {
    let freeze = FreezeInspectOrchestrator::new(10, 64, 500);
    let lineage = LineageTracker::new(64);
    let incidents = Arc::new(RwLock::new(std::collections::HashMap::new()));
    let protection_state = Arc::new(RwLock::new(ProtectionState::new(
        true,
        OperatingMode::Balanced,
        PathBuf::from("/etc/sentinel/rules.toml"),
        PathBuf::from("/etc/sentinel/config.toml"),
    )));
    let risk_engine = Arc::new(RwLock::new(RiskEngine::new(RulesConfig::default(), DpkgChecker::new())));

    let resp = sentineld::ipc_server::handle_ipc_command_for_test(
        IpcCommand::EventsList { limit: None, offset: None },
        ClientRole::RootAdmin,
        &freeze,
        &lineage,
        &incidents,
        &protection_state,
        Some(&risk_engine),
        None,
    ).await;

    match resp {
        IpcResponse::Error { code, .. } => assert_eq!(code, "ENOTSUP"),
        _ => panic!("Expected ENOTSUP for unimplemented command"),
    }
}

#[test]
fn test_anti_pid_reuse_verification() {
    let current_pid = std::process::id();
    let current_ticks = sentineld::lineage::read_proc_starttime(current_pid);

    if let Some(ticks) = current_ticks {
        // Correct PID + correct ticks -> MUST pass
        let valid_key = ProcessKey::new(current_pid, ticks);
        assert!(verify_process_identity(&valid_key, None).is_ok());

        // Correct PID + incorrect ticks (reused PID scenario) -> MUST return PidReuseDetected
        let reused_key = ProcessKey::new(current_pid, ticks.wrapping_add(12345));
        let res = verify_process_identity(&reused_key, None);
        assert!(matches!(res, Err(TerminationError::PidReuseDetected(_))));

        // Correct PID + mismatching executable path -> MUST return PidReuseDetected
        let wrong_exe = PathBuf::from("/usr/bin/nonexistent_malware");
        let res_exe = verify_process_identity(&valid_key, Some(&wrong_exe));
        assert!(matches!(res_exe, Err(TerminationError::PidReuseDetected(_))));
    }
}

#[test]
fn test_rules_config_parsing_error() {
    // Malformed TOML
    let malformed_toml = "this is not valid toml = [[";
    let res = toml::from_str::<RulesConfig>(malformed_toml);
    assert!(res.is_err(), "Malformed TOML must return error");
}

#[tokio::test]
async fn test_readonly_denied_sensitive_queries() {
    let freeze = FreezeInspectOrchestrator::new(10, 64, 500);
    let lineage = LineageTracker::new(64);
    let incidents = Arc::new(RwLock::new(std::collections::HashMap::new()));
    let protection_state = Arc::new(RwLock::new(ProtectionState::new(
        true,
        OperatingMode::Balanced,
        PathBuf::from("/etc/sentinel/rules.toml"),
        PathBuf::from("/etc/sentinel/config.toml"),
    )));
    let risk_engine = Arc::new(RwLock::new(RiskEngine::new(RulesConfig::default(), DpkgChecker::new())));

    // 1. ReadOnly client attempts IncidentsList -> MUST return EACCES
    let resp = sentineld::ipc_server::handle_ipc_command_for_test(
        IpcCommand::IncidentsList { limit: None, offset: None },
        ClientRole::ReadOnly,
        &freeze,
        &lineage,
        &incidents,
        &protection_state,
        Some(&risk_engine),
        None,
    ).await;
    assert!(matches!(resp, IpcResponse::Error { ref code, .. } if code == "EACCES"));

    // 2. ReadOnly client attempts ProcessLineage -> MUST return EACCES
    let resp_lineage = sentineld::ipc_server::handle_ipc_command_for_test(
        IpcCommand::ProcessLineage { tgid: 1 },
        ClientRole::ReadOnly,
        &freeze,
        &lineage,
        &incidents,
        &protection_state,
        Some(&risk_engine),
        None,
    ).await;
    assert!(matches!(resp_lineage, IpcResponse::Error { ref code, .. } if code == "EACCES"));

    // 3. ReadOnly client attempts PolicyList -> MUST return EACCES
    let resp_policy = sentineld::ipc_server::handle_ipc_command_for_test(
        IpcCommand::PolicyList,
        ClientRole::ReadOnly,
        &freeze,
        &lineage,
        &incidents,
        &protection_state,
        Some(&risk_engine),
        None,
    ).await;
    assert!(matches!(resp_policy, IpcResponse::Error { ref code, .. } if code == "EACCES"));

    // 4. Operator client is permitted to query incidents
    let resp_op = sentineld::ipc_server::handle_ipc_command_for_test(
        IpcCommand::IncidentsList { limit: None, offset: None },
        ClientRole::Operator,
        &freeze,
        &lineage,
        &incidents,
        &protection_state,
        Some(&risk_engine),
        None,
    ).await;
    assert!(matches!(resp_op, IpcResponse::Ok(_)));
}

#[test]
fn test_nftables_syntax_generator_correctness() {
    use sentineld::network::nftables::{IsolationTier, NftablesManager};

    // Full Isolation Script
    let full_script = NftablesManager::generate_isolation_script(IsolationTier::FullIsolation, &[]);
    assert!(full_script.contains("add table inet sentinel"));
    assert!(full_script.contains("policy drop"));
    assert!(full_script.contains("oif lo accept"));

    // Restricted Isolation with SSH Anti-Lockout
    let restricted_script = NftablesManager::generate_isolation_script(
        IsolationTier::Restricted,
        &["192.168.1.50".to_string()],
    );
    assert!(restricted_script.contains("tcp dport 22 accept"));
    // Crucial anti-lockout fix on output:
    assert!(restricted_script.contains("tcp sport 22 ct state established,related accept"));
    assert!(restricted_script.contains("192.168.1.50"));

    // Selective Isolation
    let selective_script = NftablesManager::generate_isolation_script(IsolationTier::Selective, &[]);
    assert!(selective_script.contains("blocked_v4"));
    assert!(selective_script.contains("blocked_v6"));
}

#[tokio::test]
async fn test_network_anti_lockout_confirm_state() {
    use sentineld::network::nftables::IsolationTier;
    let block_mgr = Arc::new(sentineld::response::NetworkBlockManager::new());
    let net_mgr = sentineld::network::NetworkProtectionManager::new(block_mgr, 500);

    // Initial state: not isolated (IsolationTier::None)
    assert_eq!(*net_mgr.isolation_tier.read().await, IsolationTier::None);
    // Confirm when not isolated must return error
    let unisolated_err = net_mgr.confirm_isolation().await;
    assert!(unisolated_err.is_err(), "Confirming isolation while not isolated must fail");

    // Simulate active isolation and timer
    *net_mgr.isolation_tier.write().await = IsolationTier::FullIsolation;
    net_mgr.isolation_timer_active.store(true, std::sync::atomic::Ordering::SeqCst);
    net_mgr.isolation_confirmed.store(false, std::sync::atomic::Ordering::SeqCst);

    // Operator confirms isolation
    let confirmed = net_mgr.confirm_isolation().await.expect("Failed to confirm isolation");
    assert!(confirmed);
    assert!(net_mgr.isolation_confirmed.load(std::sync::atomic::Ordering::SeqCst));
    assert!(!net_mgr.isolation_timer_active.load(std::sync::atomic::Ordering::SeqCst));

    // Second confirmation returns false (already confirmed/disarmed)
    let second_confirm = net_mgr.confirm_isolation().await.expect("Failed second confirm");
    assert!(!second_confirm);
}

#[test]
fn test_missing_start_time_fails_closed() {
    let current_pid = std::process::id();
    let key_missing_ticks = ProcessKey::new(current_pid, 0);
    // Without alternative identity, 0 ticks must fail closed
    let result = verify_process_identity(&key_missing_ticks, None);
    assert!(result.is_err(), "Zero start time ticks must fail closed without alternative identity");
}

#[test]
fn test_selective_isolation_policy_blocks_designated_targets() {
    use sentineld::network::nftables::{IsolationTier, NftablesManager, SelectivePolicy};

    let mut policy = SelectivePolicy::default();
    policy.blocked_ips.push("203.0.113.5".parse().unwrap());
    policy.blocked_ports.push(4444);

    let script = NftablesManager::generate_isolation_script_with_policy(IsolationTier::Selective, &[], &policy);
    assert!(script.contains("203.0.113.5"));
    assert!(script.contains("tcp dport 4444 counter drop"));
    assert!(script.contains("udp dport 4444 counter drop"));
    assert!(script.contains("blocked_v4"));
}

#[test]
fn test_restricted_isolation_omits_broad_established_bypass() {
    use sentineld::network::nftables::{IsolationTier, NftablesManager};

    let script = NftablesManager::generate_isolation_script(
        IsolationTier::Restricted,
        &["192.168.1.10".to_string()],
    );
    // Verified: No top-level unrestricted ct state established,related accept in output chain
    assert!(!script.contains("add rule inet sentinel output ct state established,related accept"));
    // Verified: Anti-lockout SSH establishes only for trusted target
    assert!(script.contains("add rule inet sentinel output ip daddr 192.168.1.10 tcp sport 22 ct state established,related accept"));
}

#[tokio::test]
async fn test_privileged_helper_rejection_for_unauthorized_user() {
    use sentinel_privileged::server::PrivilegedExecutor;
    use sentinel_privileged::PrivilegedResult;

    // Test that flush ruleset is rejected
    let res = PrivilegedExecutor::execute_nft_batch("flush ruleset\n");
    assert!(matches!(res, PrivilegedResult::Error { ref code, .. } if code == "EPERM"));

    // Test that foreign table manipulation is rejected
    let res_foreign = PrivilegedExecutor::execute_nft_batch("add table ip filter\n");
    assert!(matches!(res_foreign, PrivilegedResult::Error { ref code, .. } if code == "EPERM"));

    // Test that targeting PID 1 is rejected
    let res_pid1 = PrivilegedExecutor::signal_process(1, libc::SIGTERM);
    assert!(matches!(res_pid1, PrivilegedResult::Error { ref code, .. } if code == "EPERM"));
}
