//! Azure Functions Custom Handler for MISP → Microsoft Sentinel sync.
//!
//! Implements the [Azure Functions Custom Handler] protocol: an HTTP server
//! that the Functions host calls for each function invocation. The binary
//! must be named `handler` (configured in `host.json`).
//!
//! [Azure Functions Custom Handler]: https://learn.microsoft.com/azure/azure-functions/functions-custom-handlers
//!
//! # Function
//! - `sync-timer`: Timer-triggered sync. Schedule is set in `sync-timer/function.json`.
//!
//! # Environment variables
//!
//! All configuration is read from env vars — see `Config::from_env` in
//! `misp2sentinel-core`. Required:
//!   - `MISP_URL`
//!   - `MISP_API_KEY` (or sourced from Key Vault)
//!   - `AZURE_TENANT_ID`
//!   - `AZURE_CLIENT_ID`
//!   - `AZURE_CLIENT_SECRET` (or sourced from Key Vault)
//!   - `SENTINEL_WORKSPACE_ID`
//!
//! The Functions host injects `FUNCTIONS_CUSTOMHANDLER_PORT` automatically.

use axum::{Json, Router, extract::State, routing::post};
use misp2sentinel_core::{Config, Syncer};
use serde::Serialize;
use std::sync::Arc;
use tracing::{error, info};

#[derive(Debug, Serialize, Clone)]
struct SyncResponse {
    events_processed: usize,
    indicators_created: usize,
    indicators_uploaded: usize,
    indicators_failed: usize,
}

/// Shared application state (unused for now, placeholder for future caching).
#[derive(Clone)]
struct AppState;

#[tokio::main]
async fn main() {
    tracing_subscriber::fmt()
        .json()
        .without_time()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| tracing_subscriber::EnvFilter::new("info")),
        )
        .init();

    let port = std::env::var("FUNCTIONS_CUSTOMHANDLER_PORT")
        .unwrap_or_else(|_| "8080".to_string())
        .parse::<u16>()
        .expect("FUNCTIONS_CUSTOMHANDLER_PORT must be a valid port number");

    let state = Arc::new(AppState);

    let app = Router::new()
        .route("/sync-timer", post(timer_handler))
        .with_state(state);

    let listener = tokio::net::TcpListener::bind(format!("127.0.0.1:{port}"))
        .await
        .expect("Failed to bind listener");

    info!(port, "Azure Functions custom handler listening");

    axum::serve(listener, app).await.expect("Server error");
}

/// Handler for the `sync-timer` timer-triggered function.
///
/// Azure Functions sends a POST to `/{functionName}` on each invocation.
/// The response body is not used by timer triggers, but must be a 200 OK.
async fn timer_handler(State(_state): State<Arc<AppState>>) -> Json<SyncResponse> {
    match run_sync().await {
        Ok(response) => {
            info!(
                events = response.events_processed,
                indicators = response.indicators_created,
                uploaded = response.indicators_uploaded,
                failed = response.indicators_failed,
                "Sync completed"
            );
            Json(response)
        }
        Err(e) => {
            error!(error = %e, "Sync failed");
            Json(SyncResponse {
                events_processed: 0,
                indicators_created: 0,
                indicators_uploaded: 0,
                indicators_failed: 0,
            })
        }
    }
}

async fn run_sync() -> anyhow::Result<SyncResponse> {
    let mut config = Config::from_env()?;
    config.validate()?;
    config.load_keyvault_secrets().await?;

    let mut syncer = Syncer::with_progress(config, false)?;
    let result = syncer.run().await?;

    let (uploaded, failed) = result
        .upload_stats
        .map(|s| (s.successful, s.failed))
        .unwrap_or((0, 0));

    Ok(SyncResponse {
        events_processed: result.events_processed,
        indicators_created: result.indicators_created,
        indicators_uploaded: uploaded,
        indicators_failed: failed,
    })
}
