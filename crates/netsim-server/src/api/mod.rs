use std::sync::Arc;

use axum::Router;

use crate::state::AppState;

pub mod health;
pub mod project;
pub mod simulation;
pub mod import;

pub fn routes(state: Arc<AppState>) -> Router {
    Router::new()
        .merge(health::routes())
        .merge(project::routes(state.clone()))
        .merge(simulation::routes(state.clone()))
        .merge(import::routes(state))
        .merge(crate::samples::routes())
}
