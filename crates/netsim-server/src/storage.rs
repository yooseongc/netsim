use std::path::PathBuf;

use chrono::Utc;
use serde::{Deserialize, Serialize};

use netsim_core::model::scenario::Scenario;
use netsim_core::trace::SimulationResult;

use crate::error::ApiError;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ProjectMeta {
    pub name: String,
    #[serde(default)]
    pub description: Option<String>,
    pub created_at: String,
    pub updated_at: String,
}

pub struct ProjectStorage {
    pub data_dir: PathBuf,
}

impl ProjectStorage {
    pub fn new(data_dir: PathBuf) -> Self {
        std::fs::create_dir_all(&data_dir).ok();
        Self { data_dir }
    }

    fn project_dir(&self, name: &str) -> PathBuf {
        self.data_dir.join(name)
    }

    fn meta_path(&self, name: &str) -> PathBuf {
        self.project_dir(name).join("project.yaml")
    }

    fn scenario_path(&self, name: &str) -> PathBuf {
        self.project_dir(name).join("scenario.json")
    }

    fn simulations_dir(&self, name: &str) -> PathBuf {
        self.project_dir(name).join("simulations")
    }

    fn simulation_path(&self, project_name: &str, id: &str) -> PathBuf {
        self.simulations_dir(project_name).join(format!("{}.json", id))
    }

    fn read_meta(&self, name: &str) -> Result<ProjectMeta, ApiError> {
        let path = self.meta_path(name);
        let content = std::fs::read_to_string(&path)
            .map_err(|_| ApiError::NotFound(format!("Project '{}' not found", name)))?;
        serde_yaml::from_str(&content)
            .map_err(|e| ApiError::Internal(format!("Failed to read project metadata: {}", e)))
    }

    fn write_meta(&self, meta: &ProjectMeta) -> Result<(), ApiError> {
        let path = self.meta_path(&meta.name);
        let content = serde_yaml::to_string(meta)
            .map_err(|e| ApiError::Internal(format!("Failed to serialize project metadata: {}", e)))?;
        std::fs::write(&path, content)
            .map_err(|e| ApiError::Internal(format!("Failed to write project metadata: {}", e)))
    }

    pub fn list_projects(&self) -> Result<Vec<ProjectMeta>, ApiError> {
        let mut projects = Vec::new();
        let entries = std::fs::read_dir(&self.data_dir)
            .map_err(|e| ApiError::Internal(format!("Failed to read data directory: {}", e)))?;
        for entry in entries {
            let entry = entry
                .map_err(|e| ApiError::Internal(format!("Failed to read directory entry: {}", e)))?;
            if entry.path().is_dir() {
                let name = entry.file_name().to_string_lossy().to_string();
                if let Ok(meta) = self.read_meta(&name) {
                    projects.push(meta);
                }
            }
        }
        projects.sort_by(|a, b| a.name.cmp(&b.name));
        Ok(projects)
    }

    pub fn create_project(&self, name: &str, description: Option<&str>) -> Result<ProjectMeta, ApiError> {
        let dir = self.project_dir(name);
        if dir.exists() {
            return Err(ApiError::Conflict(format!("Project '{}' already exists", name)));
        }
        std::fs::create_dir_all(&dir)
            .map_err(|e| ApiError::Internal(format!("Failed to create project directory: {}", e)))?;

        let now = Utc::now().to_rfc3339();
        let meta = ProjectMeta {
            name: name.to_string(),
            description: description.map(|s| s.to_string()),
            created_at: now.clone(),
            updated_at: now,
        };
        self.write_meta(&meta)?;
        Ok(meta)
    }

    pub fn get_project(&self, name: &str) -> Result<ProjectMeta, ApiError> {
        if !self.project_dir(name).exists() {
            return Err(ApiError::NotFound(format!("Project '{}' not found", name)));
        }
        self.read_meta(name)
    }

    pub fn update_project(&self, name: &str, description: Option<&str>) -> Result<ProjectMeta, ApiError> {
        let mut meta = self.get_project(name)?;
        if let Some(desc) = description {
            meta.description = Some(desc.to_string());
        }
        meta.updated_at = Utc::now().to_rfc3339();
        self.write_meta(&meta)?;
        Ok(meta)
    }

    pub fn delete_project(&self, name: &str) -> Result<(), ApiError> {
        let dir = self.project_dir(name);
        if !dir.exists() {
            return Err(ApiError::NotFound(format!("Project '{}' not found", name)));
        }
        std::fs::remove_dir_all(&dir)
            .map_err(|e| ApiError::Internal(format!("Failed to delete project: {}", e)))
    }

    pub fn clone_project(&self, name: &str, new_name: &str) -> Result<ProjectMeta, ApiError> {
        let src_dir = self.project_dir(name);
        if !src_dir.exists() {
            return Err(ApiError::NotFound(format!("Project '{}' not found", name)));
        }
        let dst_dir = self.project_dir(new_name);
        if dst_dir.exists() {
            return Err(ApiError::Conflict(format!("Project '{}' already exists", new_name)));
        }

        // Copy directory recursively
        copy_dir_recursive(&src_dir, &dst_dir)
            .map_err(|e| ApiError::Internal(format!("Failed to clone project: {}", e)))?;

        // Update metadata in the cloned project
        let now = Utc::now().to_rfc3339();
        let mut meta = self.read_meta(new_name)?;
        meta.name = new_name.to_string();
        meta.created_at = now.clone();
        meta.updated_at = now;
        self.write_meta(&meta)?;
        Ok(meta)
    }

    pub fn has_scenario(&self, name: &str) -> bool {
        self.scenario_path(name).exists()
    }

    pub fn get_scenario(&self, name: &str) -> Result<Scenario, ApiError> {
        let path = self.scenario_path(name);
        let content = std::fs::read_to_string(&path)
            .map_err(|_| ApiError::NotFound(format!("Scenario not found for project '{}'", name)))?;
        serde_json::from_str(&content)
            .map_err(|e| ApiError::Internal(format!("Failed to parse scenario: {}", e)))
    }

    pub fn save_scenario(&self, name: &str, scenario: &Scenario) -> Result<(), ApiError> {
        if !self.project_dir(name).exists() {
            return Err(ApiError::NotFound(format!("Project '{}' not found", name)));
        }
        let path = self.scenario_path(name);
        let content = serde_json::to_string_pretty(scenario)
            .map_err(|e| ApiError::Internal(format!("Failed to serialize scenario: {}", e)))?;
        std::fs::write(&path, content)
            .map_err(|e| ApiError::Internal(format!("Failed to write scenario: {}", e)))?;

        // Update project metadata timestamp
        if let Ok(mut meta) = self.read_meta(name) {
            meta.updated_at = Utc::now().to_rfc3339();
            self.write_meta(&meta).ok();
        }
        Ok(())
    }

    pub fn save_simulation_result(&self, project_name: &str, result: &SimulationResult) -> Result<(), ApiError> {
        let sim_dir = self.simulations_dir(project_name);
        std::fs::create_dir_all(&sim_dir)
            .map_err(|e| ApiError::Internal(format!("Failed to create simulations directory: {}", e)))?;
        let path = self.simulation_path(project_name, &result.id);
        let content = serde_json::to_string_pretty(result)
            .map_err(|e| ApiError::Internal(format!("Failed to serialize simulation result: {}", e)))?;
        std::fs::write(&path, content)
            .map_err(|e| ApiError::Internal(format!("Failed to write simulation result: {}", e)))
    }

    pub fn get_simulation_result(&self, project_name: &str, id: &str) -> Result<SimulationResult, ApiError> {
        let path = self.simulation_path(project_name, id);
        let content = std::fs::read_to_string(&path)
            .map_err(|_| ApiError::NotFound(format!("Simulation result '{}' not found", id)))?;
        serde_json::from_str(&content)
            .map_err(|e| ApiError::Internal(format!("Failed to parse simulation result: {}", e)))
    }

    /// Search for a simulation result by ID across all projects
    pub fn find_simulation_result(&self, id: &str) -> Result<SimulationResult, ApiError> {
        let entries = std::fs::read_dir(&self.data_dir)
            .map_err(|e| ApiError::Internal(format!("Failed to read data directory: {}", e)))?;
        for entry in entries {
            let entry = entry
                .map_err(|e| ApiError::Internal(format!("Failed to read directory entry: {}", e)))?;
            if entry.path().is_dir() {
                let name = entry.file_name().to_string_lossy().to_string();
                if let Ok(result) = self.get_simulation_result(&name, id) {
                    return Ok(result);
                }
            }
        }
        Err(ApiError::NotFound(format!("Simulation result '{}' not found", id)))
    }
}

fn copy_dir_recursive(src: &std::path::Path, dst: &std::path::Path) -> std::io::Result<()> {
    std::fs::create_dir_all(dst)?;
    for entry in std::fs::read_dir(src)? {
        let entry = entry?;
        let src_path = entry.path();
        let dst_path = dst.join(entry.file_name());
        if src_path.is_dir() {
            copy_dir_recursive(&src_path, &dst_path)?;
        } else {
            std::fs::copy(&src_path, &dst_path)?;
        }
    }
    Ok(())
}
