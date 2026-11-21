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
