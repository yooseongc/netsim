use std::sync::Arc;

use axum::Router;
use tower_http::cors::CorsLayer;
use tower_http::services::{ServeDir, ServeFile};
use tower_http::trace::TraceLayer;

use crate::api;
use crate::state::AppState;

pub async fn create_app() -> Router {
    let state = Arc::new(AppState::new());

    let api_routes = api::routes(state.clone());

    let mut app = Router::new()
        .nest("/api/v1", api_routes)
        .layer(CorsLayer::permissive())
        .layer(TraceLayer::new_for_http());

    // Serve frontend static files if NETSIM_STATIC_DIR is set
    if let Ok(static_dir) = std::env::var("NETSIM_STATIC_DIR") {
        let index_path = format!("{}/index.html", static_dir);
        let serve_dir = ServeDir::new(&static_dir)
            .not_found_service(ServeFile::new(&index_path));
        app = app.fallback_service(serve_dir);
    }

    app
}
