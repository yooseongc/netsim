use tracing_subscriber::EnvFilter;

mod app;
mod api;
mod storage;
mod state;
mod error;
mod samples;

#[tokio::main]
async fn main() {
    tracing_subscriber::fmt()
        .with_env_filter(EnvFilter::from_default_env().add_directive("netsim=info".parse().unwrap()))
        .init();

    let port = std::env::var("NETSIM_PORT")
        .ok()
        .and_then(|p| p.parse::<u16>().ok())
        .unwrap_or(8080);

    let app = app::create_app().await;

    let listener = tokio::net::TcpListener::bind(format!("0.0.0.0:{}", port))
        .await
        .expect("Failed to bind to port");

    tracing::info!("netsim server listening on port {}", port);

    axum::serve(listener, app)
        .await
        .expect("Server failed");
}
