//! SQLite persistent storage subsystem.

pub mod database;
pub mod migrations;
pub mod schema;

pub use database::StorageManager;
pub use schema::{StoredEventRecord, StoredIncidentRecord, StoredResponseRecord};
