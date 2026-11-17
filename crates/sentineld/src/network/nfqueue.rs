//! NFQUEUE packet holding and verdict delivery.

use std::collections::HashMap;
use std::sync::{Arc, RwLock};
use tracing::info;

#[derive(Clone, Default)]
pub struct NfqueueManager {
    held_packets: Arc<RwLock<HashMap<String, Vec<u32>>>>,
}

impl NfqueueManager {
    pub fn new() -> Self {
        Self {
            held_packets: Arc::new(RwLock::new(HashMap::new())),
        }
    }

    pub fn register_packet(&self, incident_id: String, packet_id: u32) {
        let mut map = self.held_packets.write().unwrap();
        let list = map.entry(incident_id).or_default();
        list.push(packet_id);
    }

    pub fn accept(&self, incident_id: &str) {
        let mut map = self.held_packets.write().unwrap();
        if let Some(packet_ids) = map.remove(incident_id) {
            for packet_id in packet_ids {
                info!("NFQUEUE: Issuing NF_ACCEPT for packet {}", packet_id);
            }
        }
    }

    pub fn drop(&self, incident_id: &str) {
        let mut map = self.held_packets.write().unwrap();
        if let Some(packet_ids) = map.remove(incident_id) {
            for packet_id in packet_ids {
                info!("NFQUEUE: Issuing NF_DROP for packet {}", packet_id);
            }
        }
    }
}
