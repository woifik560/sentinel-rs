//! Evaluation context for security policy decisions.

use crate::behavior::DetectionMatch;
use crate::lineage::ProcessKey;
use crate::risk::RiskAssessment;
use sentinel_common::process::SecretCategory;
use std::path::PathBuf;

/// Contextual data provided to the policy engine for verdict determination.
#[derive(Debug, Clone)]
pub struct PolicyContext {
    pub process_key: ProcessKey,
    pub exe_path: PathBuf,
    pub cmdline: Vec<String>,
    pub uid: u32,
    pub gid: u32,
    pub parent_key: Option<ProcessKey>,
    pub exe_sha256: Option<String>,
    pub secret_category: Option<SecretCategory>,
    pub dest_ip: Option<String>,
    pub dest_port: Option<u16>,
    pub dest_domain: Option<String>,
    pub risk: Option<RiskAssessment>,
    pub behavior_matches: Vec<DetectionMatch>,
}

impl PolicyContext {
    pub fn new(process_key: ProcessKey, exe_path: PathBuf, uid: u32, gid: u32) -> Self {
        Self {
            process_key,
            exe_path,
            cmdline: Vec::new(),
            uid,
            gid,
            parent_key: None,
            exe_sha256: None,
            secret_category: None,
            dest_ip: None,
            dest_port: None,
            dest_domain: None,
            risk: None,
            behavior_matches: Vec::new(),
        }
    }
}
