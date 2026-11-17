//! Risk scoring, evidence aggregation, decay and explanation subsystem.

pub mod decay;
pub mod engine;
pub mod evidence;
pub mod explanation;

pub use decay::RiskDecay;
pub use engine::{is_numeric_ip, is_private_or_loopback_ip, NetworkContext, RiskEngine};
pub use evidence::{AttackStage, EvidenceAggregator, RiskEvidence};
pub use explanation::RiskAssessment;
