//! Versioned database migrations and SQLite schema management for Sentinel-RS.

use rusqlite::{Connection, Result};
use tracing::info;

pub fn initialize_database(conn: &mut Connection) -> Result<()> {
    // 1. Enable WAL mode and performance pragmas
    conn.execute_batch(
        "PRAGMA journal_mode = WAL;
         PRAGMA synchronous = NORMAL;
         PRAGMA foreign_keys = ON;
         PRAGMA busy_timeout = 5000;",
    )?;

    // 2. Migration version tracking table
    conn.execute(
        "CREATE TABLE IF NOT EXISTS schema_migrations (
            version INTEGER PRIMARY KEY,
            applied_at TEXT NOT NULL
        )",
        [],
    )?;

    let current_version: i64 = conn
        .query_row(
            "SELECT COALESCE(MAX(version), 0) FROM schema_migrations",
            [],
            |row| row.get(0),
        )
        .unwrap_or(0);

    info!("Current database schema version: {}", current_version);

    if current_version < 1 {
        apply_v1_migration(conn)?;
    }

    Ok(())
}

fn apply_v1_migration(conn: &mut Connection) -> Result<()> {
    let tx = conn.transaction()?;

    tx.execute_batch(
        "
        -- 1. Events table
        CREATE TABLE IF NOT EXISTS events (
            event_id TEXT PRIMARY KEY,
            timestamp TEXT NOT NULL,
            event_type TEXT NOT NULL,
            source TEXT NOT NULL,
            process_key TEXT NOT NULL,
            pid INTEGER NOT NULL,
            tgid INTEGER NOT NULL,
            uid INTEGER NOT NULL,
            gid INTEGER NOT NULL,
            exe_path TEXT,
            details_json TEXT NOT NULL
        );

        CREATE INDEX IF NOT EXISTS idx_events_timestamp ON events(timestamp);
        CREATE INDEX IF NOT EXISTS idx_events_process_key ON events(process_key);
        CREATE INDEX IF NOT EXISTS idx_events_type ON events(event_type);

        -- 2. Incidents table
        CREATE TABLE IF NOT EXISTS incidents (
            incident_id TEXT PRIMARY KEY,
            created_at TEXT NOT NULL,
            updated_at TEXT NOT NULL,
            severity TEXT NOT NULL,
            risk_score INTEGER NOT NULL,
            process_key TEXT NOT NULL,
            status TEXT NOT NULL,
            verdict TEXT NOT NULL,
            human_summary TEXT NOT NULL,
            details_json TEXT NOT NULL
        );

        CREATE INDEX IF NOT EXISTS idx_incidents_created_at ON incidents(created_at);
        CREATE INDEX IF NOT EXISTS idx_incidents_severity ON incidents(severity);
        CREATE INDEX IF NOT EXISTS idx_incidents_process_key ON incidents(process_key);
        CREATE INDEX IF NOT EXISTS idx_incidents_status ON incidents(status);

        -- 3. Incident to events correlation link table
        CREATE TABLE IF NOT EXISTS incident_events (
            incident_id TEXT NOT NULL REFERENCES incidents(incident_id) ON DELETE CASCADE,
            event_id TEXT NOT NULL REFERENCES events(event_id) ON DELETE CASCADE,
            PRIMARY KEY (incident_id, event_id)
        );

        -- 4. Processes table
        CREATE TABLE IF NOT EXISTS processes (
            process_key TEXT PRIMARY KEY,
            pid INTEGER NOT NULL,
            ppid INTEGER NOT NULL,
            uid INTEGER NOT NULL,
            start_time_ns INTEGER NOT NULL,
            exe_path TEXT NOT NULL,
            exe_sha256 TEXT,
            cmdline TEXT NOT NULL,
            is_memfd INTEGER NOT NULL DEFAULT 0,
            first_seen TEXT NOT NULL,
            last_seen TEXT NOT NULL
        );

        CREATE INDEX IF NOT EXISTS idx_processes_pid ON processes(pid);
        CREATE INDEX IF NOT EXISTS idx_processes_sha256 ON processes(exe_sha256);

        -- 5. Response Actions table
        CREATE TABLE IF NOT EXISTS response_actions (
            action_id TEXT PRIMARY KEY,
            timestamp TEXT NOT NULL,
            incident_id TEXT REFERENCES incidents(incident_id),
            process_key TEXT NOT NULL,
            action_type TEXT NOT NULL,
            status TEXT NOT NULL,
            details_json TEXT NOT NULL
        );

        CREATE INDEX IF NOT EXISTS idx_response_timestamp ON response_actions(timestamp);

        -- 6. Policy Audit table
        CREATE TABLE IF NOT EXISTS policy_audit (
            audit_id TEXT PRIMARY KEY,
            timestamp TEXT NOT NULL,
            decision_id TEXT NOT NULL,
            policy_id TEXT,
            rule_id TEXT,
            process_key TEXT NOT NULL,
            action TEXT NOT NULL,
            risk_score INTEGER NOT NULL,
            reason TEXT NOT NULL
        );

        CREATE INDEX IF NOT EXISTS idx_policy_audit_timestamp ON policy_audit(timestamp);

        -- 7. Configuration History table
        CREATE TABLE IF NOT EXISTS configuration_history (
            version_id TEXT PRIMARY KEY,
            timestamp TEXT NOT NULL,
            changed_by TEXT NOT NULL,
            config_json TEXT NOT NULL,
            success INTEGER NOT NULL
        );

        -- 8. Health History table
        CREATE TABLE IF NOT EXISTS health_history (
            check_id TEXT PRIMARY KEY,
            timestamp TEXT NOT NULL,
            overall_status TEXT NOT NULL,
            subsystems_json TEXT NOT NULL
        );

        CREATE INDEX IF NOT EXISTS idx_health_timestamp ON health_history(timestamp);

        -- Record migration
        INSERT INTO schema_migrations (version, applied_at)
        VALUES (1, datetime('now'));
        ",
    )?;

    tx.commit()?;
    info!("Applied database migration v1 successfully");
    Ok(())
}

/// Run an integrity check on the SQLite database file.
pub fn check_database_integrity(conn: &Connection) -> Result<bool> {
    let mut stmt = conn.prepare("PRAGMA integrity_check")?;
    let mut rows = stmt.query([])?;

    if let Some(row) = rows.next()? {
        let status: String = row.get(0)?;
        Ok(status == "ok")
    } else {
        Ok(false)
    }
}
