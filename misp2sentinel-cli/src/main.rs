//! MISP2Sentinel CLI
//!
//! Command-line tool for synchronizing threat intelligence from MISP to Microsoft Sentinel.

use anyhow::Result;
use clap::Parser;
use misp2sentinel_core::{Config, Syncer};
use tracing::{error, info, Level};
use tracing_subscriber::{fmt, EnvFilter};

/// MISP to Microsoft Sentinel Threat Intelligence Sync
#[derive(Parser, Debug)]
#[command(name = "misp2sentinel")]
#[command(author, version, about, long_about = None)]
struct Args {
    /// Path to configuration file
    #[arg(short, long, env = "CONFIG_PATH")]
    config: Option<String>,

    /// Run in dry-run mode (don't upload to Sentinel)
    #[arg(long, env = "SYNC_DRY_RUN")]
    dry_run: bool,

    /// Enable verbose logging
    #[arg(short, long, env = "VERBOSE")]
    verbose: bool,

    /// Output logs as JSON
    #[arg(long, env = "LOG_JSON")]
    json_logs: bool,

    /// MISP server URL
    #[arg(long, env = "MISP_URL")]
    misp_url: Option<String>,

    /// Azure Tenant ID
    #[arg(long, env = "AZURE_TENANT_ID")]
    tenant_id: Option<String>,

    /// Azure Client ID
    #[arg(long, env = "AZURE_CLIENT_ID")]
    client_id: Option<String>,

    /// Sentinel Workspace ID
    #[arg(long, env = "SENTINEL_WORKSPACE_ID")]
    workspace_id: Option<String>,

    /// Azure Key Vault URL for secrets
    #[arg(long, env = "AZURE_KEYVAULT_URL")]
    keyvault_url: Option<String>,

    /// Check configuration without running
    #[arg(long)]
    check_config: bool,
}

#[tokio::main]
async fn main() -> Result<()> {
    // Load .env file if present
    let _ = dotenvy::dotenv();

    // Parse CLI arguments
    let args = Args::parse();

    // Initialize logging
    init_logging(args.verbose, args.json_logs);

    info!("MISP2Sentinel starting up");

    // Load configuration
    let mut config = load_config(&args)?;

    // Load secrets from Key Vault if configured
    if config.keyvault.is_some() {
        info!("Loading secrets from Azure Key Vault");
        config.load_keyvault_secrets().await?;
    }

    // Apply CLI overrides
    if args.dry_run {
        config.sync.dry_run = true;
    }

    // Validate configuration
    if let Err(e) = config.validate() {
        error!("Configuration validation failed: {}", e);
        std::process::exit(1);
    }

    if args.check_config {
        info!("Configuration check passed");
        println!("  Configuration is valid");
        println!("  MISP URL: {}", config.misp.url);
        println!("  Tenant ID: {}", config.sentinel.tenant_id);
        println!("  Workspace ID: {}", config.sentinel.workspace_id);
        println!("  Dry run: {}", config.sync.dry_run);
        return Ok(());
    }

    // Run sync
    info!("Starting synchronization");
    let mut syncer = Syncer::new(config)?;

    match syncer.run().await {
        Ok(result) => {
            info!("{}", result.summary());

            if result.is_success() {
                println!("Sync completed successfully");
                println!("  {}", result.summary());
            } else {
                println!("Sync completed with errors");
                println!("  {}", result.summary());
                std::process::exit(1);
            }
        }
        Err(e) => {
            error!("Sync failed: {}", e);
            println!("Sync failed: {}", e);
            std::process::exit(1);
        }
    }

    Ok(())
}

fn init_logging(verbose: bool, json: bool) {
    let level = if verbose { Level::DEBUG } else { Level::INFO };

    let filter = EnvFilter::builder()
        .with_default_directive(level.into())
        .from_env_lossy();

    if json {
        fmt().with_env_filter(filter).json().init();
    } else {
        fmt().with_env_filter(filter).with_target(false).init();
    }
}

fn load_config(args: &Args) -> Result<Config> {
    let mut config = if let Some(ref path) = args.config {
        info!("Loading configuration from: {}", path);
        Config::from_file(path)?
    } else {
        info!("Loading configuration from environment variables");
        Config::load()?
    };

    // Apply CLI overrides
    if let Some(ref url) = args.misp_url {
        config.misp.url = url.clone();
    }
    if let Some(ref tenant_id) = args.tenant_id {
        config.sentinel.tenant_id = tenant_id.clone();
    }
    if let Some(ref client_id) = args.client_id {
        config.sentinel.client_id = client_id.clone();
    }
    if let Some(ref workspace_id) = args.workspace_id {
        config.sentinel.workspace_id = workspace_id.clone();
    }
    if let Some(ref keyvault_url) = args.keyvault_url {
        config.keyvault = Some(misp2sentinel_core::KeyVaultConfig {
            vault_url: keyvault_url.clone(),
            misp_api_key_secret: Some("misp-api-key".to_string()),
            sentinel_client_secret: Some("sentinel-client-secret".to_string()),
        });
    }

    Ok(config)
}
