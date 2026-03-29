use std::sync::Arc;

use axum::extract::{Path, State};
use axum::routing::{get, post};
use axum::{Json, Router};
use serde::Deserialize;
use serde_json::{json, Value};

use netsim_core::engine;
use netsim_core::model::scenario::Scenario;

use crate::error::ApiError;
use crate::state::AppState;

#[derive(Debug, Deserialize)]
pub struct SimulateRequest {
    #[serde(default)]
    pub scenario_override: Option<Scenario>,
}

pub fn routes(state: Arc<AppState>) -> Router {
    Router::new()
        .route("/projects/{name}/scenario", get(get_scenario).put(save_scenario))
        .route("/projects/{name}/scenario/validate", post(validate_scenario))
        .route("/projects/{name}/simulate", post(simulate))
        .route("/simulations/{id}", get(get_simulation_result))
        .route("/simulations/{id}/trace", get(get_simulation_trace))
        .with_state(state)
}

async fn get_scenario(
    State(state): State<Arc<AppState>>,
    Path(name): Path<String>,
) -> Result<Json<Value>, ApiError> {
    // Verify project exists
    state.storage.get_project(&name)?;
    let scenario = state.storage.get_scenario(&name)?;
    Ok(Json(serde_json::to_value(scenario).unwrap()))
}

async fn save_scenario(
    State(state): State<Arc<AppState>>,
    Path(name): Path<String>,
    Json(scenario): Json<Scenario>,
) -> Result<Json<Value>, ApiError> {
    // Verify project exists
    state.storage.get_project(&name)?;
    state.storage.save_scenario(&name, &scenario)?;
    Ok(Json(serde_json::to_value(scenario).unwrap()))
}

async fn validate_scenario(
    State(state): State<Arc<AppState>>,
    Path(name): Path<String>,
    Json(scenario): Json<Scenario>,
) -> Result<Json<Value>, ApiError> {
    // Verify project exists
    state.storage.get_project(&name)?;

    let mut errors = Vec::new();
    let mut warnings = Vec::new();

    // Basic validations
    if scenario.interfaces.is_empty() {
        errors.push("No interfaces defined".to_string());
    }

    // Check that ingress interface exists
    let ingress = &scenario.packet.ingress_interface;
    if !scenario.interfaces.iter().any(|i| i.name == *ingress) {
        errors.push(format!(
            "Ingress interface '{}' not found in defined interfaces",
            ingress
        ));
    }

    // Check for unreferenced interfaces
    for iface in &scenario.interfaces {
        let name = &iface.name;
        let referenced_in_routes = scenario.routing_tables.iter().any(|rt| {
            rt.routes.iter().any(|r| r.dev.as_deref() == Some(name.as_str()))
        });
        if !referenced_in_routes && *name != *ingress {
            warnings.push(format!(
                "Interface '{}' is defined but not referenced in any route",
                name
            ));
        }
    }

    let valid = errors.is_empty();
    Ok(Json(json!({
        "valid": valid,
        "errors": errors,
        "warnings": warnings,
    })))
}

async fn simulate(
    State(state): State<Arc<AppState>>,
    Path(name): Path<String>,
    Json(req): Json<SimulateRequest>,
) -> Result<Json<Value>, ApiError> {
    // Verify project exists
    state.storage.get_project(&name)?;

    let scenario = match req.scenario_override {
        Some(s) => s,
        None => state.storage.get_scenario(&name)?,
    };

    let result = engine::run(&scenario);

    // Save to storage
    state.storage.save_simulation_result(&name, &result)?;
    // Cache for quick lookup
    state.cache_simulation(&result);

    Ok(Json(json!({
        "simulation_id": result.id,
        "status": "completed",
        "result": result,
    })))
}

async fn get_simulation_result(
    State(state): State<Arc<AppState>>,
    Path(id): Path<String>,
) -> Result<Json<Value>, ApiError> {
    // Try cache first
    if let Some(result) = state.get_cached_simulation(&id) {
        return Ok(Json(serde_json::to_value(result).unwrap()));
    }

    // Fall back to searching storage
    let result = state.storage.find_simulation_result(&id)?;
    state.cache_simulation(&result);
    Ok(Json(serde_json::to_value(result).unwrap()))
}

async fn get_simulation_trace(
    State(state): State<Arc<AppState>>,
    Path(id): Path<String>,
) -> Result<Json<Value>, ApiError> {
    // Try cache first
    let result = if let Some(r) = state.get_cached_simulation(&id) {
        r
    } else {
        let r = state.storage.find_simulation_result(&id)?;
        state.cache_simulation(&r);
        r
    };

    Ok(Json(json!({ "trace": result.trace })))
}
