//! Automated Response and Defensive Action subsystem.

pub mod containment;
pub mod network_block;
pub mod orchestrator;
pub mod process_suspend;
pub mod process_term;

pub use containment::HostContainment;
pub use network_block::NetworkBlockManager;
pub use orchestrator::ResponseOrchestrator;
pub use process_suspend::{resume_process, suspend_process};
pub use process_term::{safe_terminate_process, verify_process_identity, TerminationError};
