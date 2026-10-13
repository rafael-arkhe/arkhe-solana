use anyhow::Context;
use arkhe_provenance_mcp::{ArkheMcp, ArkheMcpConfig};
use axum::{routing::get, Router};
use rmcp::transport::streamable_http_server::{
    session::local::LocalSessionManager, StreamableHttpServerConfig, StreamableHttpService,
};
use sqlx::postgres::PgPoolOptions;
use std::net::SocketAddr;
use tokio_util::sync::CancellationToken;

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| "info,arkhe_provenance_mcp=info".into()),
        )
        .init();

    let database_url = std::env::var("DATABASE_URL").context("DATABASE_URL is required")?;
    let preflight_url =
        std::env::var("ARKHE_PREFLIGHT_URL").context("ARKHE_PREFLIGHT_URL is required")?;
    let price_book_version =
        std::env::var("ARKHE_PRICE_BOOK_VERSION").unwrap_or_else(|_| "phase-a-free-v1".into());
    let port: u16 = std::env::var("PORT")
        .unwrap_or_else(|_| "8080".into())
        .parse()
        .context("PORT must be u16")?;

    let pool = PgPoolOptions::new()
        .max_connections(10)
        .connect(&database_url)
        .await
        .context("failed to connect to PostgreSQL")?;

    // Startup invariant: metering schema must exist before accepting tool calls.
    sqlx::query("SELECT 1 FROM usage_events LIMIT 1")
        .fetch_optional(&pool)
        .await
        .context("usage_events missing; run database migrations first")?;

    let shared = ArkheMcp::new(
        pool,
        preflight_url,
        price_book_version,
        ArkheMcpConfig::from_env(),
    )?;

    let cancellation = CancellationToken::new();
    let config = StreamableHttpServerConfig::default()
        .with_legacy_session_mode(false)
        .with_json_response(true)
        .with_cancellation_token(cancellation.child_token());

    let service = StreamableHttpService::new(
        move || Ok(shared.clone()),
        LocalSessionManager::default().into(),
        config,
    );

    let app = Router::new()
        .route("/health", get(|| async { "ok" }))
        .nest_service("/mcp", service);

    let addr = SocketAddr::from(([0, 0, 0, 0], port));
    let listener = tokio::net::TcpListener::bind(addr).await?;
    tracing::info!(%addr, "Arkhe metered MCP server listening");

    axum::serve(listener, app)
        .with_graceful_shutdown(async move {
            let _ = tokio::signal::ctrl_c().await;
            cancellation.cancel();
        })
        .await?;

    Ok(())
}
