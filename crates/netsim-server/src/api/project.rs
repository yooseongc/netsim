use std::sync::Arc;

use axum::extract::{Path, State};
use axum::http::StatusCode;
use axum::response::IntoResponse;
use axum::routing::{get, post};
use axum::{Json, Router};
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};

use crate::error::ApiError;
use crate::state::AppState;

#[derive(Debug, Deserialize)]
pub struct CreateProjectRequest {
    pub name: String,
    #[serde(default)]
    pub description: Option<String>,
}

#[derive(Debug, Deserialize)]
pub struct UpdateProjectRequest {
    #[serde(default)]
    pub description: Option<String>,
}

#[derive(Debug, Deserialize)]
pub struct CloneProjectRequest {
    pub new_name: String,
}

#[derive(Debug, Serialize)]
pub struct ProjectDetailResponse {
    pub name: String,
    pub description: Option<String>,
    pub created_at: String,
    pub updated_at: String,
    pub has_scenario: bool,
    pub has_imported_config: bool,
}

pub fn routes(state: Arc<AppState>) -> Router {
    Router::new()
        .route("/projects", get(list_projects).post(create_project))
        .route(
            "/projects/{name}",
            get(get_project).put(update_project).delete(delete_project),
        )
        .route("/projects/{name}/clone", post(clone_project))
        .with_state(state)
}

async fn list_projects(
    State(state): State<Arc<AppState>>,
) -> Result<Json<Value>, ApiError> {
    let projects = state.storage.list_projects()?;
    Ok(Json(json!({ "projects": projects })))
}

async fn create_project(
    State(state): State<Arc<AppState>>,
    Json(req): Json<CreateProjectRequest>,
) -> Result<(StatusCode, Json<Value>), ApiError> {
    let meta = state.storage.create_project(&req.name, req.description.as_deref())?;
    Ok((StatusCode::CREATED, Json(serde_json::to_value(meta).unwrap())))
}

async fn get_project(
    State(state): State<Arc<AppState>>,
    Path(name): Path<String>,
) -> Result<Json<Value>, ApiError> {
    let meta = state.storage.get_project(&name)?;
    let has_scenario = state.storage.has_scenario(&name);
    let resp = ProjectDetailResponse {
        name: meta.name,
        description: meta.description,
        created_at: meta.created_at,
        updated_at: meta.updated_at,
        has_scenario,
        has_imported_config: false,
    };
    Ok(Json(serde_json::to_value(resp).unwrap()))
}

async fn update_project(
    State(state): State<Arc<AppState>>,
    Path(name): Path<String>,
    Json(req): Json<UpdateProjectRequest>,
) -> Result<Json<Value>, ApiError> {
    let meta = state.storage.update_project(&name, req.description.as_deref())?;
    Ok(Json(serde_json::to_value(meta).unwrap()))
}

async fn delete_project(
    State(state): State<Arc<AppState>>,
    Path(name): Path<String>,
) -> Result<impl IntoResponse, ApiError> {
    state.storage.delete_project(&name)?;
    Ok(StatusCode::NO_CONTENT)
}

async fn clone_project(
    State(state): State<Arc<AppState>>,
    Path(name): Path<String>,
    Json(req): Json<CloneProjectRequest>,
) -> Result<(StatusCode, Json<Value>), ApiError> {
    let meta = state.storage.clone_project(&name, &req.new_name)?;
    Ok((StatusCode::CREATED, Json(serde_json::to_value(meta).unwrap())))
}
