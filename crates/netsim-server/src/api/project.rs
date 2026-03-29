use std::sync::Arc;

use axum::Router;

use crate::state::AppState;

pub fn routes(_state: Arc<AppState>) -> Router {
    Router::new()
    // 프로젝트 CRUD API — 추후 구현
}
