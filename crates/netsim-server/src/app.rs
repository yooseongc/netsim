use std::sync::Arc;

use axum::Router;
use axum::response::IntoResponse;
use tower_http::cors::CorsLayer;
use tower_http::services::ServeDir;
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
    // SPA fallback: non-API, non-asset routes return index.html with 200
    if let Ok(static_dir) = std::env::var("NETSIM_STATIC_DIR") {
        let index_path = format!("{}/index.html", static_dir);
        let index_contents = std::fs::read_to_string(&index_path)
            .unwrap_or_else(|_| "<html><body>netsim</body></html>".to_string());

        let serve_dir = ServeDir::new(&static_dir)
            .fallback(axum::routing::get(move || {
                let html = index_contents.clone();
                async move {
                    (
                        [(axum::http::header::CONTENT_TYPE, "text/html")],
                        html,
                    ).into_response()
                }
            }));
        app = app.fallback_service(serve_dir);
    }

    app
}
