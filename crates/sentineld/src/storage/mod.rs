//! SQLite persistent storage subsystem.

pub mod database;
pub mod migrations;
pub mod schema;

pub use database::StorageManager;
pub use migrations::{check_database_integrity, initialize_database};
pub use schema::{StoredEventRecord, StoredIncidentRecord, StoredResponseRecord};
