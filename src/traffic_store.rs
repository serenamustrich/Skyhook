use std::fs;
use std::path::{Path, PathBuf};
use std::sync::RwLock;

use serde::{Deserialize, Serialize};

const CURRENT_SCHEMA_VERSION: u32 = 2;

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct TrafficSnapshot {
    pub schema_version: u32,
    pub global_upload: u64,
    pub global_download: u64,
    pub per_outbound: std::collections::HashMap<String, OutboundTraffic>,
    pub per_subscription: std::collections::HashMap<String, SubscriptionTraffic>,
    pub per_domain: std::collections::HashMap<String, DomainTraffic>,
    pub per_app: std::collections::HashMap<String, AppTraffic>,
    pub per_protocol: std::collections::HashMap<String, ProtocolTraffic>,
    pub saved_at: Option<String>,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct OutboundTraffic {
    pub upload: u64,
    pub download: u64,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct SubscriptionTraffic {
    pub upload: u64,
    pub download: u64,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct DomainTraffic {
    pub upload: u64,
    pub download: u64,
    pub visits: u64,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct AppTraffic {
    pub upload: u64,
    pub download: u64,
    pub connections: u64,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct ProtocolTraffic {
    pub upload: u64,
    pub download: u64,
    pub connections: u64,
}

pub struct TrafficStore {
    path: PathBuf,
    state: RwLock<TrafficSnapshot>,
}

impl TrafficStore {
    pub fn new(path: impl AsRef<Path>) -> Self {
        let state = load_traffic(path.as_ref());
        Self {
            path: path.as_ref().to_path_buf(),
            state: RwLock::new(state),
        }
    }

    pub fn get(&self) -> TrafficSnapshot {
        self.state.read().unwrap_or_else(|e| e.into_inner()).clone()
    }

    pub fn add_global_traffic(&self, upload: u64, download: u64) {
        if let Ok(mut state) = self.state.write() {
            state.global_upload += upload;
            state.global_download += download;
        }
    }

    pub fn add_outbound_traffic(&self, outbound: &str, upload: u64, download: u64) {
        if let Ok(mut state) = self.state.write() {
            let entry = state.per_outbound.entry(outbound.to_string()).or_default();
            entry.upload += upload;
            entry.download += download;
        }
    }

    pub fn add_subscription_traffic(&self, subscription_id: &str, upload: u64, download: u64) {
        if let Ok(mut state) = self.state.write() {
            let entry = state
                .per_subscription
                .entry(subscription_id.to_string())
                .or_default();
            entry.upload += upload;
            entry.download += download;
        }
    }

    pub fn add_domain_traffic(&self, domain: &str, upload: u64, download: u64) {
        if let Ok(mut state) = self.state.write() {
            let entry = state.per_domain.entry(domain.to_string()).or_default();
            entry.upload += upload;
            entry.download += download;
            entry.visits += 1;
        }
    }

    pub fn add_app_traffic(&self, app_name: &str, upload: u64, download: u64) {
        if let Ok(mut state) = self.state.write() {
            let entry = state.per_app.entry(app_name.to_string()).or_default();
            entry.upload += upload;
            entry.download += download;
            entry.connections += 1;
        }
    }

    pub fn add_protocol_traffic(&self, protocol: &str, upload: u64, download: u64) {
        if let Ok(mut state) = self.state.write() {
            let entry = state.per_protocol.entry(protocol.to_string()).or_default();
            entry.upload += upload;
            entry.download += download;
            entry.connections += 1;
        }
    }

    pub fn persist(&self) -> anyhow::Result<()> {
        let state = self.state.read().map_err(|e| anyhow::anyhow!("{}", e))?;
        let mut snapshot = state.clone();
        snapshot.schema_version = CURRENT_SCHEMA_VERSION;
        snapshot.saved_at = Some(chrono::Utc::now().to_rfc3339());

        if let Some(parent) = self.path.parent() {
            fs::create_dir_all(parent)?;
        }

        let temp_path = self.path.with_extension("tmp");
        let content = serde_json::to_string_pretty(&snapshot)?;
        fs::write(&temp_path, &content)?;
        fs::rename(&temp_path, &self.path)?;
        Ok(())
    }
}

fn load_traffic(path: &Path) -> TrafficSnapshot {
    fs::read_to_string(path)
        .ok()
        .and_then(|content| {
            let mut snapshot: TrafficSnapshot = serde_json::from_str(&content).ok()?;
            if snapshot.schema_version < CURRENT_SCHEMA_VERSION {
                snapshot = migrate_traffic(snapshot);
            }
            Some(snapshot)
        })
        .unwrap_or_default()
}

fn migrate_traffic(mut snapshot: TrafficSnapshot) -> TrafficSnapshot {
    if snapshot.schema_version < 2 {
        snapshot.per_domain = std::collections::HashMap::new();
        snapshot.per_app = std::collections::HashMap::new();
        snapshot.per_protocol = std::collections::HashMap::new();
    }
    snapshot.schema_version = CURRENT_SCHEMA_VERSION;
    snapshot
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::NamedTempFile;

    #[test]
    fn default_traffic() {
        let traffic = TrafficSnapshot::default();
        assert_eq!(traffic.global_upload, 0);
        assert_eq!(traffic.global_download, 0);
    }

    #[test]
    fn persist_and_load() {
        let file = NamedTempFile::new().unwrap();
        let path = file.path();

        let store = TrafficStore::new(path);
        store.add_global_traffic(100, 200);
        store.add_outbound_traffic("proxy-1", 50, 100);
        store.persist().unwrap();

        let loaded = TrafficStore::new(path);
        let state = loaded.get();
        assert_eq!(state.global_upload, 100);
        assert_eq!(state.global_download, 200);
        assert_eq!(state.per_outbound.get("proxy-1").unwrap().upload, 50);
    }
}
