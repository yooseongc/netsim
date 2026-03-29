use std::path::PathBuf;

pub struct ProjectStorage {
    pub data_dir: PathBuf,
}

impl ProjectStorage {
    pub fn new(data_dir: PathBuf) -> Self {
        std::fs::create_dir_all(&data_dir).ok();
        Self { data_dir }
    }
}

// 파일 기반 프로젝트 저장소 — 추후 구현
