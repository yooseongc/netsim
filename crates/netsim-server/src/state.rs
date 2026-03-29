use std::collections::HashMap;
use std::path::PathBuf;
use std::sync::Mutex;

use netsim_core::trace::SimulationResult;

use crate::storage::ProjectStorage;

pub struct AppState {
    pub storage: ProjectStorage,
    /// In-memory cache for quick simulation result lookup by ID
    pub sim_cache: Mutex<HashMap<String, SimulationResult>>,
}

impl AppState {
    pub fn new() -> Self {
        let data_dir = std::env::var("NETSIM_DATA_DIR")
            .map(PathBuf::from)
            .unwrap_or_else(|_| PathBuf::from("./data/projects"));

        Self {
            storage: ProjectStorage::new(data_dir),
            sim_cache: Mutex::new(HashMap::new()),
        }
    }

    pub fn cache_simulation(&self, result: &SimulationResult) {
        if let Ok(mut cache) = self.sim_cache.lock() {
            cache.insert(result.id.clone(), result.clone());
        }
    }

    pub fn get_cached_simulation(&self, id: &str) -> Option<SimulationResult> {
        self.sim_cache.lock().ok()?.get(id).cloned()
    }
}
