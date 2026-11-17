//! Storage manager handling persistent SQLite operations via bounded asynchronous queues.

use chrono::{Duration, Utc};
use rusqlite::{params, Connection};
use std::path::PathBuf;
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
    LinkIncidentEvent { incident_id: String, event_id: String },
    PurgeOldRecords { retention_days: i64 },
}

#[derive(Clone)]
pub struct StorageManager {
    cmd_tx: mpsc::Sender<StorageCommand>,
    db_path: PathBuf,
}

impl StorageManager {
    pub fn new(db_path: PathBuf, queue_capacity: usize) -> anyhow::Result<Self> {
        if let Some(parent) = db_path.parent() {
            let _ = std::fs::create_dir_all(parent);
        }

        // Initialize and verify migrations synchronously on startup
        {
            let mut conn = Connection::open(&db_path)?;
            initialize_database(&mut conn)?;
            if !check_database_integrity(&conn)? {
                warn!("SQLite integrity check returned non-ok status for {}", db_path.display());
            } else {
                info!("Database integrity verified ok for {}", db_path.display());
            }
        }

        let (cmd_tx, mut cmd_rx) = mpsc::channel::<StorageCommand>(queue_capacity);
        let worker_path = db_path.clone();

        // Spawn dedicated blocking SQLite worker thread
        std::thread::spawn(move || {
            let mut conn = match Connection::open(&worker_path) {
                Ok(c) => c,
                Err(e) => {
                    error!("Failed to open SQLite worker connection: {}", e);
                    return;
                }
            };

            info!("SQLite storage worker thread active on {}", worker_path.display());

            while let Some(cmd) = cmd_rx.blocking_recv() {
                if let Err(e) = execute_storage_command(&mut conn, cmd) {
                    warn!("Storage worker error: {}", e);
                }
            }
            info!("SQLite storage worker thread shutdown");
        });

        Ok(Self { cmd_tx, db_path })
    }

    /// Asynchronously queue an event for storage without blocking critical hot path.
    pub fn queue_event(&self, event: NormalizedEvent) {
        if let Err(mpsc::error::TrySendError::Full(_)) = self.cmd_tx.try_send(StorageCommand::StoreEvent(event)) {
            warn!("Storage write queue full! Dropping event persistence to preserve kernel latency");
        }
    }

    /// Asynchronously queue an incident for storage.
    pub fn queue_incident(&self, incident: StoredIncidentRecord) {
        let _ = self.cmd_tx.try_send(StorageCommand::StoreIncident(incident));
    }

    /// Asynchronously queue a response action record for storage.
    pub fn enqueue_response(&self, record: StoredResponseRecord) {
        let _ = self.cmd_tx.try_send(StorageCommand::StoreResponse(record));
    }

    /// Link incident to event.
    pub fn link_incident_event(&self, incident_id: String, event_id: String) {
        let _ = self.cmd_tx.try_send(StorageCommand::LinkIncidentEvent { incident_id, event_id });
    }

    /// Trigger retention purge.
    pub fn purge_retention(&self, retention_days: i64) {
        let _ = self.cmd_tx.try_send(StorageCommand::PurgeOldRecords { retention_days });
    }

    /// Query recent incidents synchronously for sntctl CLI.
    pub fn list_incidents(&self, limit: usize, offset: usize) -> rusqlite::Result<Vec<StoredIncidentRecord>> {
        let conn = Connection::open(&self.db_path)?;
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
        let conn = Connection::open(&self.db_path)?;
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
}

fn execute_storage_command(conn: &mut Connection, cmd: StorageCommand) -> rusqlite::Result<()> {
    match cmd {
        StorageCommand::StoreEvent(event) => {
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

        StorageCommand::LinkIncidentEvent { incident_id, event_id } => {
            conn.execute(
                "INSERT OR IGNORE INTO incident_events (incident_id, event_id) VALUES (?1, ?2)",
                params![incident_id, event_id],
            )?;
        }

        StorageCommand::PurgeOldRecords { retention_days } => {
            let cutoff = (Utc::now() - Duration::days(retention_days)).to_rfc3339();
            let count = conn.execute("DELETE FROM events WHERE timestamp < ?1", params![cutoff])?;
            if count > 0 {
                info!("Purged {} events older than {} days", count, retention_days);
            }
        }
    }
    Ok(())
}
