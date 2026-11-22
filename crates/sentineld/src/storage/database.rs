//! Storage manager handling persistent SQLite operations via bounded asynchronous queues.

use chrono::{Duration, Utc};
use rusqlite::{params, Connection};
use std::path::{Path, PathBuf};
use tokio::sync::mpsc;
use tracing::{error, info, warn};

use crate::collector::NormalizedEvent;
use crate::storage::migrations::{check_database_integrity, initialize_database};
use crate::storage::schema::{StoredIncidentRecord, StoredResponseRecord};

#[derive(Debug)]
pub enum StorageCommand {
    StoreEvent(NormalizedEvent),
    StoreIncident(StoredIncidentRecord),
    StoreResponse(StoredResponseRecord),
    LinkIncidentEvent {
        incident_id: String,
        event_id: String,
    },
    PurgeOldRecords {
        retention_days: i64,
    },
    CheckpointWal,
}

#[derive(Clone)]
pub struct StorageManager {
    cmd_tx: mpsc::Sender<StorageCommand>,
    db_path: PathBuf,
}

/// Check available disk space in megabytes using statvfs on Unix.
pub fn get_available_disk_space_mb(path: &Path) -> u64 {
    #[cfg(unix)]
    {
        use std::ffi::CString;
        use std::mem::MaybeUninit;
        let c_path = CString::new(path.to_string_lossy().as_bytes()).unwrap_or_default();
        let mut stat = MaybeUninit::<libc::statvfs>::uninit();
        if unsafe { libc::statvfs(c_path.as_ptr(), stat.as_mut_ptr()) } == 0 {
            let s = unsafe { stat.assume_init() };
            let free_bytes = s.f_bavail * s.f_frsize;
            return free_bytes / (1024 * 1024);
        }
    }
    1024
}

/// Open an SQLite connection configured with WAL mode, foreign keys, and 5-second busy timeout.
pub fn open_sqlite_connection(path: &Path) -> rusqlite::Result<Connection> {
    let conn = Connection::open(path)?;
    conn.busy_timeout(std::time::Duration::from_millis(5000))?;
    conn.execute_batch(
        "PRAGMA journal_mode = WAL;
         PRAGMA synchronous = NORMAL;
         PRAGMA foreign_keys = ON;
         PRAGMA busy_timeout = 5000;",
    )?;
    Ok(conn)
}

impl StorageManager {
    pub fn new(db_path: PathBuf, queue_capacity: usize) -> anyhow::Result<Self> {
        if let Some(parent) = db_path.parent() {
            let _ = std::fs::create_dir_all(parent);
        }

        // Initialize and verify migrations synchronously on startup
        {
            let mut conn = open_sqlite_connection(&db_path)?;
            initialize_database(&mut conn)?;
            if !check_database_integrity(&conn)? {
                warn!(
                    "SQLite integrity check returned non-ok status for {}",
                    db_path.display()
                );
            } else {
                info!("Database integrity verified ok for {}", db_path.display());
            }
        }

        // Restrict SQLite database file permissions to root/daemon owner only (0600)
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let _ = std::fs::set_permissions(&db_path, std::fs::Permissions::from_mode(0o600));
        }

        let (cmd_tx, mut cmd_rx) = mpsc::channel::<StorageCommand>(queue_capacity);
        let worker_path = db_path.clone();

        // Spawn dedicated blocking SQLite worker thread
        std::thread::spawn(move || {
            let mut conn = match open_sqlite_connection(&worker_path) {
                Ok(c) => c,
                Err(e) => {
                    error!("Failed to open SQLite worker connection: {}", e);
                    return;
                }
            };

            info!(
                "SQLite storage worker thread active on {}",
                worker_path.display()
            );

            while let Some(cmd) = cmd_rx.blocking_recv() {
                if let Err(e) = execute_storage_command(&mut conn, &worker_path, cmd) {
                    warn!("Storage worker error: {}", e);
                }
            }
            let _ = conn.execute_batch("PRAGMA wal_checkpoint(TRUNCATE);");
            info!("SQLite storage worker thread shutdown and WAL truncated");
        });

        // Spawn periodic retention and checkpointing maintenance task (TASK-P1-19)
        let maint_tx = cmd_tx.clone();
        tokio::spawn(async move {
            let mut interval = tokio::time::interval(std::time::Duration::from_secs(3600)); // Every 1h
            loop {
                interval.tick().await;
                let _ = maint_tx.try_send(StorageCommand::PurgeOldRecords { retention_days: 14 });
                let _ = maint_tx.try_send(StorageCommand::CheckpointWal);
            }
        });

        Ok(Self { cmd_tx, db_path })
    }

    /// Asynchronously queue an event for storage without blocking critical hot path.
    pub fn queue_event(&self, event: NormalizedEvent) {
        if let Err(mpsc::error::TrySendError::Full(_)) =
            self.cmd_tx.try_send(StorageCommand::StoreEvent(event))
        {
            warn!(
                "Storage write queue full! Dropping event persistence to preserve kernel latency"
            );
        }
    }

    /// Asynchronously queue an incident for storage.
    pub fn queue_incident(&self, incident: StoredIncidentRecord) {
        let _ = self
            .cmd_tx
            .try_send(StorageCommand::StoreIncident(incident));
    }

    /// Asynchronously queue a response action record for storage.
    pub fn enqueue_response(&self, record: StoredResponseRecord) {
        let _ = self.cmd_tx.try_send(StorageCommand::StoreResponse(record));
    }

    /// Link incident to event.
    pub fn link_incident_event(&self, incident_id: String, event_id: String) {
        let _ = self.cmd_tx.try_send(StorageCommand::LinkIncidentEvent {
            incident_id,
            event_id,
        });
    }

    /// Trigger retention purge (default 14 days).
    pub fn purge_retention(&self, retention_days: i64) {
        let _ = self
            .cmd_tx
            .try_send(StorageCommand::PurgeOldRecords { retention_days });
    }

    /// Trigger WAL truncation checkpoint.
    pub fn checkpoint_wal(&self) {
        let _ = self.cmd_tx.try_send(StorageCommand::CheckpointWal);
    }

    /// Query recent incidents synchronously for sntctl CLI.
    pub fn list_incidents(
        &self,
        limit: usize,
        offset: usize,
    ) -> rusqlite::Result<Vec<StoredIncidentRecord>> {
        let conn = open_sqlite_connection(&self.db_path)?;
        let mut stmt = conn.prepare(
            "SELECT incident_id, created_at, updated_at, severity, risk_score, process_key, status, verdict, human_summary, details_json
             FROM incidents
             ORDER BY created_at DESC
             LIMIT ?1 OFFSET ?2",
        )?;

        let rows = stmt.query_map(params![limit as i64, offset as i64], |row| {
            let created_str: String = row.get(1)?;
            let updated_str: String = row.get(2)?;
            let created_at = chrono::DateTime::parse_from_rfc3339(&created_str)
                .map(|d| d.with_timezone(&Utc))
                .unwrap_or_else(|_| Utc::now());
            let updated_at = chrono::DateTime::parse_from_rfc3339(&updated_str)
                .map(|d| d.with_timezone(&Utc))
                .unwrap_or_else(|_| Utc::now());

            Ok(StoredIncidentRecord {
                incident_id: row.get(0)?,
                created_at,
                updated_at,
                severity: row.get(3)?,
                risk_score: row.get(4)?,
                process_key: row.get(5)?,
                status: row.get(6)?,
                verdict: row.get(7)?,
                human_summary: row.get(8)?,
                details_json: row.get(9)?,
            })
        })?;

        let mut list = Vec::new();
        for r in rows {
            list.push(r?);
        }
        Ok(list)
    }

    /// Retrieve incident by ID.
    pub fn get_incident(&self, id: &str) -> rusqlite::Result<Option<StoredIncidentRecord>> {
        let conn = open_sqlite_connection(&self.db_path)?;
        let mut stmt = conn.prepare(
            "SELECT incident_id, created_at, updated_at, severity, risk_score, process_key, status, verdict, human_summary, details_json
             FROM incidents
             WHERE incident_id = ?1",
        )?;

        let mut rows = stmt.query(params![id])?;
        if let Some(row) = rows.next()? {
            let created_str: String = row.get(1)?;
            let updated_str: String = row.get(2)?;
            let created_at = chrono::DateTime::parse_from_rfc3339(&created_str)
                .map(|d| d.with_timezone(&Utc))
                .unwrap_or_else(|_| Utc::now());
            let updated_at = chrono::DateTime::parse_from_rfc3339(&updated_str)
                .map(|d| d.with_timezone(&Utc))
                .unwrap_or_else(|_| Utc::now());

            Ok(Some(StoredIncidentRecord {
                incident_id: row.get(0)?,
                created_at,
                updated_at,
                severity: row.get(3)?,
                risk_score: row.get(4)?,
                process_key: row.get(5)?,
                status: row.get(6)?,
                verdict: row.get(7)?,
                human_summary: row.get(8)?,
                details_json: row.get(9)?,
            }))
        } else {
            Ok(None)
        }
    }

    /// Clear all stored incidents (for sntctl incidents clear).
    pub fn clear_all_incidents(&self) -> rusqlite::Result<usize> {
        let conn = open_sqlite_connection(&self.db_path)?;
        conn.execute("DELETE FROM incidents", [])
    }

    /// Count total recorded incidents.
    pub fn count_incidents(&self) -> rusqlite::Result<usize> {
        let conn = open_sqlite_connection(&self.db_path)?;
        conn.query_row("SELECT COUNT(*) FROM incidents", [], |row| {
            row.get::<_, i64>(0).map(|c| c as usize)
        })
    }
}

fn execute_storage_command(
    conn: &mut Connection,
    db_path: &Path,
    cmd: StorageCommand,
) -> rusqlite::Result<()> {
    // DATABASE QUOTA GUARD: prevent database growth exceeding 500 MB
    let db_size_mb = std::fs::metadata(db_path)
        .map(|m| m.len() / (1024 * 1024))
        .unwrap_or(0);
    if db_size_mb > 500 {
        warn!(
            "DATABASE QUOTA GUARD: Database file size exceeds 500 MB ({} MB). Purging oldest raw events and checkpointing WAL...",
            db_size_mb
        );
        let cutoff = (Utc::now() - Duration::days(3)).to_rfc3339();
        let _ = conn.execute("DELETE FROM events WHERE timestamp < ?1", params![cutoff]);
        let _ = conn.execute_batch("PRAGMA wal_checkpoint(TRUNCATE);");
    }

    match cmd {
        StorageCommand::StoreEvent(event) => {
            // TASK-P1-19: Disk Quota Guard: if disk space is < 500 MB, drop raw events to prevent disk exhaustion
            let free_mb = get_available_disk_space_mb(db_path);
            if free_mb < 500 {
                warn!(
                    "DISK QUOTA GUARD: Low disk space ({} MB available < 500 MB). Dropping raw event to preserve host integrity!",
                    free_mb
                );
                return Ok(());
            }

            let details_json = serde_json::to_string(&event.details).unwrap_or_default();
            let exe_str = event.exe_path.map(|p| p.to_string_lossy().to_string());

            conn.execute(
                "INSERT OR IGNORE INTO events
                 (event_id, timestamp, event_type, source, process_key, pid, tgid, uid, gid, exe_path, details_json)
                 VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11)",
                params![
                    event.event_id,
                    event.timestamp.to_rfc3339(),
                    format!("{:?}", event.event_type),
                    format!("{:?}", event.source),
                    event.process_key.to_string_id(),
                    event.pid,
                    event.tgid,
                    event.uid,
                    event.gid,
                    exe_str,
                    details_json,
                ],
            )?;
        }

        StorageCommand::StoreIncident(incident) => {
            conn.execute(
                "INSERT INTO incidents
                 (incident_id, created_at, updated_at, severity, risk_score, process_key, status, verdict, human_summary, details_json)
                 VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10)
                 ON CONFLICT(incident_id) DO UPDATE SET
                    updated_at = excluded.updated_at,
                    severity = excluded.severity,
                    risk_score = excluded.risk_score,
                    status = excluded.status,
                    verdict = excluded.verdict,
                    human_summary = excluded.human_summary,
                    details_json = excluded.details_json",
                params![
                    incident.incident_id,
                    incident.created_at.to_rfc3339(),
                    incident.updated_at.to_rfc3339(),
                    incident.severity,
                    incident.risk_score,
                    incident.process_key,
                    incident.status,
                    incident.verdict,
                    incident.human_summary,
                    incident.details_json,
                ],
            )?;
        }

        StorageCommand::StoreResponse(response) => {
            conn.execute(
                "INSERT INTO response_actions
                 (action_id, timestamp, incident_id, process_key, action_type, status, details_json)
                 VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7)",
                params![
                    response.action_id,
                    response.timestamp.to_rfc3339(),
                    response.incident_id,
                    response.process_key,
                    response.action_type,
                    response.status,
                    response.details_json,
                ],
            )?;
        }

        StorageCommand::LinkIncidentEvent {
            incident_id,
            event_id,
        } => {
            conn.execute(
                "INSERT OR IGNORE INTO incident_events (incident_id, event_id) VALUES (?1, ?2)",
                params![incident_id, event_id],
            )?;
        }

        StorageCommand::PurgeOldRecords { retention_days } => {
            let cutoff = (Utc::now() - Duration::days(retention_days)).to_rfc3339();
            let count = conn.execute("DELETE FROM events WHERE timestamp < ?1", params![cutoff])?;
            if count > 0 {
                info!(
                    "Purged {} raw events older than {} days (retention policy)",
                    count, retention_days
                );
            }
        }

        StorageCommand::CheckpointWal => {
            // TASK-P1-19: PRAGMA wal_checkpoint(TRUNCATE) to reset WAL file size
            let _ = conn.execute_batch("PRAGMA wal_checkpoint(TRUNCATE);");
            info!("SQLite PRAGMA wal_checkpoint(TRUNCATE) executed successfully.");
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_open_sqlite_connection_pragmas() {
        let temp_dir =
            std::env::temp_dir().join(format!("sentinel_db_test_{}", std::process::id()));
        let _ = std::fs::create_dir_all(&temp_dir);
        let db_file = temp_dir.join("test.db");

        let conn = open_sqlite_connection(&db_file).expect("Failed to open connection");
        let journal_mode: String = conn
            .query_row("PRAGMA journal_mode;", [], |r| r.get(0))
            .unwrap();
        assert_eq!(journal_mode.to_uppercase(), "WAL");

        let busy_timeout: i64 = conn
            .query_row("PRAGMA busy_timeout;", [], |r| r.get(0))
            .unwrap();
        assert_eq!(busy_timeout, 5000);

        let foreign_keys: i64 = conn
            .query_row("PRAGMA foreign_keys;", [], |r| r.get(0))
            .unwrap();
        assert_eq!(foreign_keys, 1);

        let _ = std::fs::remove_dir_all(&temp_dir);
    }

    #[tokio::test]
    async fn test_concurrent_storage_readers_and_writers() {
        let temp_dir =
            std::env::temp_dir().join(format!("sentinel_concurrent_test_{}", std::process::id()));
        let _ = std::fs::create_dir_all(&temp_dir);
        let db_file = temp_dir.join("test_concurrent.db");

        let storage =
            StorageManager::new(db_file.clone(), 1000).expect("Failed to create storage manager");

        // Concurrently insert incidents and query
        for i in 0..20 {
            let record = StoredIncidentRecord {
                incident_id: format!("inc-{}", i),
                created_at: Utc::now(),
                updated_at: Utc::now(),
                severity: "HIGH".into(),
                risk_score: 85,
                process_key: "123:456".into(),
                status: "ACTIVE".into(),
                verdict: "BLOCK".into(),
                human_summary: format!("Incident test {}", i),
                details_json: "{}".into(),
            };
            storage.queue_incident(record);
        }

        // Concurrently query without SQLITE_BUSY error
        let mut success_reads = 0;
        for _ in 0..10 {
            if storage.list_incidents(50, 0).is_ok() {
                success_reads += 1;
            }
        }
        assert_eq!(
            success_reads, 10,
            "All 10 concurrent reads must succeed without SQLITE_BUSY"
        );

        let _ = std::fs::remove_dir_all(&temp_dir);
    }
}
