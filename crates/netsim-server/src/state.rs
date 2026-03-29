use std::path::PathBuf;

use crate::storage::ProjectStorage;

pub struct AppState {
    pub storage: ProjectStorage,
}

impl AppState {
    pub fn new() -> Self {
        let data_dir = std::env::var("NETSIM_DATA_DIR")
            .map(PathBuf::from)
            .unwrap_or_else(|_| PathBuf::from("./data/projects"));

        Self {
            storage: ProjectStorage::new(data_dir),
        }
    }
}
