//! Event correlation and incident deduplication engine.

use chrono::{DateTime, Duration, Utc};
use std::collections::HashMap;
use std::sync::{Arc, RwLock};

use crate::collector::ProcessKey;

#[derive(Debug, Clone)]
pub struct CorrelationWindow {
    pub process_key: ProcessKey,
    pub incident_id: String,
    pub last_event_at: DateTime<Utc>,
    pub event_count: usize,
}

pub struct IncidentCorrelator {
    window_duration: Duration,
    active_windows: Arc<RwLock<HashMap<String, CorrelationWindow>>>,
}

impl IncidentCorrelator {
    pub fn new(window_secs: i64) -> Self {
        Self {
            window_duration: Duration::seconds(window_secs),
            active_windows: Arc::new(RwLock::new(HashMap::new())),
        }
    }

    /// Check if an event for the given process key correlates with an existing open incident.
    pub fn correlate_or_create<F>(&self, process_key: &ProcessKey, new_incident_id_fn: F) -> (String, bool)
    where
        F: FnOnce() -> String,
    {
        let key_str = process_key.to_string_id();
        let now = Utc::now();
        let mut windows = self.active_windows.write().unwrap();

        // Expire old windows
        windows.retain(|_, win| (now - win.last_event_at) <= self.window_duration);

        if let Some(win) = windows.get_mut(&key_str) {
            win.last_event_at = now;
            win.event_count += 1;
            (win.incident_id.clone(), false)
        } else {
            let id = new_incident_id_fn();
            windows.insert(
                key_str,
                CorrelationWindow {
                    process_key: process_key.clone(),
                    incident_id: id.clone(),
                    last_event_at: now,
                    event_count: 1,
                },
            );
            (id, true)
        }
    }
}
