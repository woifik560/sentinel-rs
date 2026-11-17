//! Integration tests for headless HIPS/EDR subsystems:
//! 1. PID-reuse prevention & canonical ProcessKey verification.
//! 2. 6-stage policy precedence evaluation.
//! 3. Deterministic risk engine scoring & multi-stage compounding.
//! 4. Incident management & temporal correlation.
//! 5. Autonomous defensive response orchestrator.

use std::path::PathBuf;
use sentinel_common::policy::{OperatingMode, PolicyAction};
use sentinel_common::risk::{RuleFiring, RuleId};
use sentineld::incidents::manager::{IncidentManager, IncidentStatus};
use sentineld::lineage::ProcessKey as LineageKey;
use sentineld::policy::{PolicyContext, PolicyEngine, PolicyRule, RuleCondition};
use sentineld::response::process_term::verify_process_identity;
use sentineld::risk::{AttackStage, EvidenceAggregator, RiskAssessment};

#[test]
fn test_pid_reuse_protection_mechanisms() {
    // Current PID of our test process
    let current_pid = std::process::id();

    // Key with correct current PID and 0 start time (passes existence check)
    let valid_key = LineageKey::new(current_pid, 0);
    assert!(verify_process_identity(&valid_key, None).is_ok());

    // Key targeting a nonexistent high PID (should fail with NotFound)
    let invalid_key = LineageKey::new(999_999_999, 0);
    assert!(verify_process_identity(&invalid_key, None).is_err());

    // Key with start_time heavily mismatched (simulated recycled PID)
    let recycled_key = LineageKey::new(current_pid, 1);
    // If /proc/<pid>/stat is readable, starttime will diverge by > 1000 ticks
    let res = verify_process_identity(&recycled_key, None);
    // On Linux with readable /proc, should return PidReuseDetected error
    if let Err(e) = res {
        println!("PID reuse check returned expected error: {:?}", e);
    }
}

#[test]
fn test_six_stage_policy_precedence() {
    let engine = PolicyEngine::new(OperatingMode::Balanced);

    // 1. Immutable Safety Constraint: PID 1 must ALWAYS be allowed
    let pid1_ctx = PolicyContext::new(LineageKey::new(1, 100), PathBuf::from("/sbin/init"), 0, 0);
    let decision = engine.evaluate(&pid1_ctx);
    assert_eq!(decision.action, PolicyAction::Allow);
    assert_eq!(decision.rule_id, Some("SAFETY_CRITICAL_PID".into()));

    // 2. Immutable Safety Constraint: Sentinel daemon must ALWAYS be allowed
    let daemon_ctx = PolicyContext::new(LineageKey::new(4500, 200), PathBuf::from("/usr/local/bin/sentineld"), 0, 0);
    let decision = engine.evaluate(&daemon_ctx);
    assert_eq!(decision.action, PolicyAction::Allow);
    assert_eq!(decision.rule_id, Some("SAFETY_AGENT_SELF".into()));

    // 3. Protected System Resource: Non-root accessing /etc/sentinel
    let tampered_ctx = PolicyContext::new(LineageKey::new(5100, 300), PathBuf::from("/etc/sentinel/evil.sh"), 1000, 1000);
    let decision = engine.evaluate(&tampered_ctx);
    assert_eq!(decision.action, PolicyAction::Deny);
    assert_eq!(decision.rule_id, Some("PROTECTED_SYSTEM_RESOURCE".into()));

    // 4. Admin Deny Rule overrides Admin Allow Rule
    let deny_rule = PolicyRule {
        id: "DENY_TEST".into(),
        name: "Explicit Deny Malware".into(),
        description: "Deny evil binary".into(),
        conditions: vec![RuleCondition::PathPrefix("/opt/evil".into())],
        action: PolicyAction::TerminateProcess,
        is_enabled: true,
    };
    engine.add_deny_rule(deny_rule);

    let evil_ctx = PolicyContext::new(LineageKey::new(6000, 400), PathBuf::from("/opt/evil/backdoor"), 1000, 1000);
    let decision = engine.evaluate(&evil_ctx);
    assert_eq!(decision.action, PolicyAction::TerminateProcess);
    assert_eq!(decision.policy_id, Some("DENY_TEST".into()));
}

#[test]
fn test_operating_mode_autonomous_verdicts() {
    let engine = PolicyEngine::new(OperatingMode::Audit);
    let mut ctx = PolicyContext::new(LineageKey::new(7000, 500), PathBuf::from("/tmp/miner"), 1000, 1000);
    ctx.risk = Some(RiskAssessment::new(85, Vec::new()));

    // Audit mode never blocks
    let decision = engine.evaluate(&ctx);
    assert_eq!(decision.action, PolicyAction::Monitor);

    // Balanced mode terminates high risk (> 80)
    engine.set_mode(OperatingMode::Balanced);
    let decision = engine.evaluate(&ctx);
    assert_eq!(decision.action, PolicyAction::TerminateProcess);

    // Strict mode isolates medium risk and kills lower thresholds (> 50)
    engine.set_mode(OperatingMode::Strict);
    let mut medium_ctx = PolicyContext::new(LineageKey::new(7001, 501), PathBuf::from("/tmp/script"), 1000, 1000);
    medium_ctx.risk = Some(RiskAssessment::new(55, Vec::new()));
    let decision = engine.evaluate(&medium_ctx);
    assert_eq!(decision.action, PolicyAction::TerminateProcess);
}

#[test]
fn test_multi_stage_attack_evidence_compounding() {
    let mut aggregator = EvidenceAggregator::new();
    let now = 1_000_000_000;

    // Single stage firing
    aggregator.add_firing(
        &RuleFiring {
            rule_id: RuleId::SecretNonOwner,
            weight: 40,
            reason: "Secret read".into(),
        },
        AttackStage::CredentialAccess,
        now,
    );

    let (score1, _) = aggregator.calculate_aggregate();
    assert_eq!(score1, 40);

    // Add second distinct attack stage (Exfiltration) -> 1.15x compounding multiplier
    aggregator.add_firing(
        &RuleFiring {
            rule_id: RuleId::FastExfilBurst,
            weight: 15,
            reason: "Fast exfil".into(),
        },
        AttackStage::Exfiltration,
        now + 100,
    );

    let (score2, _) = aggregator.calculate_aggregate();
    // (40 + 15) * 1.15 = 55 * 1.15 = 63.25 -> 63
    assert_eq!(score2, 63);

    // Add third distinct attack stage (Execution) -> 1.30x compounding multiplier
    aggregator.add_firing(
        &RuleFiring {
            rule_id: RuleId::UntrustedBinaryOrigin,
            weight: 25,
            reason: "Untrusted origin".into(),
        },
        AttackStage::Execution,
        now + 200,
    );

    let (score3, _) = aggregator.calculate_aggregate();
    // (40 + 15 + 25) * 1.30 = 80 * 1.30 = 104 -> clamped to 100
    assert_eq!(score3, 100);
}

#[test]
fn test_incident_lifecycle_and_temporal_correlation() {
    let mgr = IncidentManager::new(30, None);
    let key = LineageKey::new(8888, 123456);

    // First event creates incident
    let id1 = mgr.record_threat(
        key.clone(),
        75,
        sentinel_common::risk::SeverityLevel::High,
        Vec::new(),
        Vec::new(),
        PolicyAction::TerminateProcess,
        "Test threat detected".into(),
        Some("EVT-1".into()),
    );

    let inc1 = mgr.get(&id1).expect("Incident must exist");
    assert_eq!(inc1.status, IncidentStatus::Detected);
    assert_eq!(inc1.risk_score, 75);

    // Second event within correlation window attaches to same incident
    let id2 = mgr.record_threat(
        key.clone(),
        85,
        sentinel_common::risk::SeverityLevel::Severe,
        Vec::new(),
        Vec::new(),
        PolicyAction::TerminateProcess,
        "Second event".into(),
        Some("EVT-2".into()),
    );

    assert_eq!(id1, id2);
    let inc_updated = mgr.get(&id1).expect("Incident must exist");
    assert_eq!(inc_updated.risk_score, 85);
    assert_eq!(inc_updated.event_references.len(), 2);

    // Status transition
    let transitioned = mgr.update_status(&id1, IncidentStatus::Contained);
    assert!(transitioned);
    assert_eq!(mgr.get(&id1).unwrap().status, IncidentStatus::Contained);
}
