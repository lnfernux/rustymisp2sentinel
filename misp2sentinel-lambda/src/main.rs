//! AWS Lambda handler for MISP → Microsoft Sentinel sync.
//!
//! Deployed as a Lambda custom runtime. The binary must be named `bootstrap`.
//! Triggered via EventBridge Scheduler (or any invocation source).
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
//! # Invocation payload (optional)
//!
//! ```json
//! { "dry_run": true }
//! ```
//! Setting `dry_run` here overrides the `SYNC_DRY_RUN` env var.

use lambda_runtime::{service_fn, Error, LambdaEvent};
use misp2sentinel_core::{Config, Syncer};
use serde::{Deserialize, Serialize};
use tracing::info;

#[derive(Debug, Deserialize, Default)]
struct SyncRequest {
    dry_run: Option<bool>,
}

#[derive(Debug, Serialize)]
struct SyncResponse {
    events_processed: usize,
    indicators_created: usize,
    indicators_uploaded: usize,
    indicators_failed: usize,
}

#[tokio::main]
async fn main() -> Result<(), Error> {
    tracing_subscriber::fmt()
        .json()
        .without_time()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| tracing_subscriber::EnvFilter::new("info")),
        )
        .init();

    lambda_runtime::run(service_fn(handler)).await
}

async fn handler(event: LambdaEvent<SyncRequest>) -> Result<SyncResponse, Error> {
    let mut config = Config::from_env().map_err(|e| format!("Config error: {e}"))?;

    // Allow the invocation payload to override dry_run
    if let Some(dry_run) = event.payload.dry_run {
        config.sync.dry_run = dry_run;
    }

    config.validate().map_err(|e| format!("Config validation error: {e}"))?;
    config.load_keyvault_secrets().await.map_err(|e| format!("Key Vault error: {e}"))?;

    let mut syncer =
        Syncer::with_progress(config, false).map_err(|e| format!("Syncer init error: {e}"))?;

    let result = syncer.run().await.map_err(|e| format!("Sync error: {e}"))?;

    let (uploaded, failed) = result
        .upload_stats
        .map(|s| (s.successful, s.failed))
        .unwrap_or((0, 0));

    info!(
        events = result.events_processed,
        indicators = result.indicators_created,
        uploaded,
        failed,
        "Sync completed"
    );

    Ok(SyncResponse {
        events_processed: result.events_processed,
        indicators_created: result.indicators_created,
        indicators_uploaded: uploaded,
        indicators_failed: failed,
    })
}
