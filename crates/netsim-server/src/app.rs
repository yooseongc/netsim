use std::sync::Arc;

use axum::Router;
use tower_http::cors::CorsLayer;
use tower_http::trace::TraceLayer;

use crate::api;
use crate::state::AppState;

pub async fn create_app() -> Router {
    let state = Arc::new(AppState::new());

    let api_routes = api::routes(state.clone());

    Router::new()
        .nest("/api/v1", api_routes)
        .layer(CorsLayer::permissive())
        .layer(TraceLayer::new_for_http())
}
