use std::sync::Arc;

use axum::Router;

use crate::state::AppState;

pub fn routes(_state: Arc<AppState>) -> Router {
    Router::new()
    // 시뮬레이션 API — 추후 구현
}
