//! Incident management subsystem for EDR.

pub mod correlator;
pub mod manager;

pub use correlator::IncidentCorrelator;
pub use manager::{Incident, IncidentManager, IncidentStatus};
