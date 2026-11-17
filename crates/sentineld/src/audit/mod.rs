//! Security Audit Logging subsystem.

pub mod events;
pub mod logger;

pub use events::{AuditCategory, AuditRecord};
pub use logger::AuditLogger;
