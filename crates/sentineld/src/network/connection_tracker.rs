//! Network connection tracking and flow state.

use std::collections::{HashMap, HashSet};
use std::sync::{Arc, RwLock};
use std::time::{Duration, Instant};

#[derive(Clone)]
pub struct ConnectionTracker {
    aggregate_window: Duration,
    aggregated_flows: Arc<RwLock<HashMap<(u32, String, u16), (String, Instant)>>>,
    duration_allowlist: Arc<RwLock<HashMap<u32, Instant>>>,
    host_allowlist: Arc<RwLock<HashMap<u32, HashSet<String>>>>,
}

impl ConnectionTracker {
    pub fn new(aggregate_window: Duration) -> Self {
        Self {
            aggregate_window,
            aggregated_flows: Arc::new(RwLock::new(HashMap::new())),
            duration_allowlist: Arc::new(RwLock::new(HashMap::new())),
            host_allowlist: Arc::new(RwLock::new(HashMap::new())),
        }
    }

    pub fn is_temporarily_allowed(&self, tgid: u32, host: Option<&str>) -> bool {
        let now = Instant::now();
        if let Some(&expiry) = self.duration_allowlist.read().unwrap().get(&tgid) {
            if now < expiry {
                return true;
            }
        }

        if let Some(h) = host {
            if let Some(allowed_hosts) = self.host_allowlist.read().unwrap().get(&tgid) {
                if allowed_hosts.contains(h) {
                    return true;
                }
            }
        }

        false
    }

    pub fn add_temporary_allow(&self, tgid: u32, duration: Duration) {
        self.duration_allowlist
            .write()
            .unwrap()
            .insert(tgid, Instant::now() + duration);
    }

    pub fn add_host_allow(&self, tgid: u32, host: String) {
        self.host_allowlist
            .write()
            .unwrap()
            .entry(tgid)
            .or_default()
            .insert(host);
    }

    pub fn check_or_record_flow(
        &self,
        tgid: u32,
        ip: &str,
        port: u16,
        incident_id: &str,
    ) -> Option<String> {
        let key = (tgid, ip.to_string(), port);
        let now = Instant::now();
        let mut flows = self.aggregated_flows.write().unwrap();

        if let Some((existing_id, timestamp)) = flows.get(&key) {
            if now.duration_since(*timestamp) < self.aggregate_window {
                return Some(existing_id.clone());
            }
        }

        flows.insert(key, (incident_id.to_string(), now));
        None
    }
}
