use std::fs;
use std::path::{Path, PathBuf};
use std::sync::RwLock;

use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct RuntimeState {
    pub last_selected_outbound: Option<String>,
    pub last_successful_outbound: Option<String>,
    pub last_selected_by_group: std::collections::HashMap<String, String>,
    pub last_selected_by_country: std::collections::HashMap<String, String>,
}

pub struct RuntimeStateStore {
    path: PathBuf,
    state: RwLock<RuntimeState>,
}

impl RuntimeStateStore {
    pub fn new(path: impl AsRef<Path>) -> Self {
        let state = load_state(path.as_ref());
        Self {
            path: path.as_ref().to_path_buf(),
            state: RwLock::new(state),
        }
    }

    pub fn get(&self) -> RuntimeState {
        self.state.read().unwrap_or_else(|e| e.into_inner()).clone()
    }

    pub fn set_last_selected(&self, outbound: String) {
        if let Ok(mut state) = self.state.write() {
            state.last_selected_outbound = Some(outbound);
            let _ = save_state(&self.path, &state);
        }
    }

    pub fn set_last_successful(&self, outbound: String) {
        if let Ok(mut state) = self.state.write() {
            state.last_successful_outbound = Some(outbound);
            let _ = save_state(&self.path, &state);
        }
    }

    pub fn set_last_selected_for_group(&self, group: String, outbound: String) {
        if let Ok(mut state) = self.state.write() {
            state.last_selected_by_group.insert(group, outbound);
            let _ = save_state(&self.path, &state);
        }
    }

    pub fn set_last_selected_for_country(&self, code: String, outbound: String) {
        if let Ok(mut state) = self.state.write() {
            state.last_selected_by_country.insert(code, outbound);
            let _ = save_state(&self.path, &state);
        }
    }
}

fn load_state(path: &Path) -> RuntimeState {
    fs::read_to_string(path)
        .ok()
        .and_then(|content| serde_json::from_str(&content).ok())
        .unwrap_or_default()
}

fn save_state(path: &Path, state: &RuntimeState) -> anyhow::Result<()> {
    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent)?;
    }
    let content = serde_json::to_string_pretty(state)?;
    fs::write(path, content)?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::NamedTempFile;

    #[test]
    fn default_state() {
        let state = RuntimeState::default();
        assert!(state.last_selected_outbound.is_none());
        assert!(state.last_successful_outbound.is_none());
        assert!(state.last_selected_by_group.is_empty());
        assert!(state.last_selected_by_country.is_empty());
    }

    #[test]
    fn persist_and_load() {
        let file = NamedTempFile::new().unwrap();
        let path = file.path();

        let store = RuntimeStateStore::new(path);
        store.set_last_selected("proxy-1".to_string());
        store.set_last_successful("proxy-2".to_string());
        store.set_last_selected_for_group("auto".to_string(), "proxy-3".to_string());

        let loaded = RuntimeStateStore::new(path);
        let state = loaded.get();
        assert_eq!(state.last_selected_outbound, Some("proxy-1".to_string()));
        assert_eq!(state.last_successful_outbound, Some("proxy-2".to_string()));
        assert_eq!(
            state.last_selected_by_group.get("auto"),
            Some(&"proxy-3".to_string())
        );
    }
}
