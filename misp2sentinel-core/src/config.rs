//! Configuration management for MISP2Sentinel
//!
//! Configuration can be loaded from:
//! 1. Environment variables (highest priority)
//! 2. Configuration file (config.toml)
//! 3. Azure Key Vault (for secrets)
//! 4. Default values (lowest priority)

use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::env;
use std::path::Path;
use tracing::info;

use crate::error::{Error, Result};

/// Main configuration struct
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Config {
    /// MISP configuration
    pub misp: MispConfig,

    /// Microsoft Sentinel configuration
    pub sentinel: SentinelConfig,

    /// Sync behavior configuration
    pub sync: SyncConfig,

    /// Optional Key Vault configuration for secrets
    #[serde(default)]
    pub keyvault: Option<KeyVaultConfig>,
}

/// MISP server configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MispConfig {
    /// MISP server URL (e.g., https://misp.example.com)
    pub url: String,

    /// MISP API key (can be loaded from Key Vault)
    pub api_key: String,

    /// Verify TLS certificates (default: true)
    #[serde(default = "default_true")]
    pub verify_tls: bool,

    /// Event filters in MISP query format
    #[serde(default)]
    pub filters: MispFilters,

    /// Number of events per page (default: 100)
    #[serde(default = "default_page_limit")]
    pub page_limit: u32,

    /// Maximum number of events to fetch (None = unlimited)
    #[serde(default)]
    pub max_events: Option<u32>,
}

/// MISP event filters
/// These align with the MISP restSearch API parameters
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct MispFilters {
    /// Only published events (default: true)
    #[serde(default = "default_true")]
    pub published: bool,

    /// Filter by tags to INCLUDE (OR logic) - e.g., ["tlp:white", "type:malware"]
    #[serde(default)]
    pub tags: Vec<String>,

    /// Tags to EXCLUDE (NOT logic) - e.g., ["tlp:red", "false-positive"]
    #[serde(default)]
    pub not_tags: Vec<String>,

    /// Organizations to INCLUDE (by name or UUID)
    #[serde(default)]
    pub orgs: Vec<String>,

    /// Organizations to EXCLUDE (by name or UUID)
    #[serde(default)]
    pub not_orgs: Vec<String>,

    /// Publish timestamp filter - events published AFTER this time
    /// Formats: "14d", "30d", "90d", "2024-01-01", Unix timestamp
    /// Default: "14d" (matches Python misp2sentinel)
    #[serde(default = "default_publish_timestamp")]
    pub publish_timestamp: Option<String>,

    /// Event timestamp filter - events modified AFTER this time
    /// Default: None (no filtering by modification time, matches Python behavior)
    #[serde(default)]
    pub timestamp: Option<String>,

    /// From date filter (YYYY-MM-DD) - events with date >= from
    #[serde(default)]
    pub from: Option<String>,

    /// To date filter (YYYY-MM-DD) - events with date <= to
    #[serde(default)]
    pub to: Option<String>,

    /// Last N time period - events published in the last X time
    /// Examples: "1d", "7d", "24h", "30m"
    #[serde(default)]
    pub last: Option<String>,

    /// Event info search - search in event info/description
    #[serde(default)]
    pub event_info: Option<String>,

    /// Threat level filter (1=High, 2=Medium, 3=Low, 4=Undefined)
    #[serde(default)]
    pub threat_level_id: Option<Vec<u8>>,

    /// Only events with IDS-flagged attributes (default: true)
    #[serde(default = "default_true")]
    pub to_ids: bool,

    /// Enforce warninglist filtering on MISP side (default: false, matches Python)
    #[serde(default)]
    pub enforce_warninglist: bool,

    /// Include event tags in response (default: true, matches Python)
    #[serde(default = "default_true")]
    pub include_event_tags: bool,

    /// Additional custom filters (passed directly to MISP API)
    #[serde(default)]
    pub custom: HashMap<String, serde_json::Value>,
}

/// Microsoft Sentinel configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SentinelConfig {
    /// Azure tenant ID
    pub tenant_id: String,

    /// Azure AD application (client) ID
    pub client_id: String,

    /// Azure AD application client secret (can be loaded from Key Vault)
    pub client_secret: String,

    /// Log Analytics workspace ID where Sentinel is deployed
    pub workspace_id: String,

    /// Source system name for uploaded indicators
    #[serde(default = "default_source_system")]
    pub source_system: String,

    /// API version (default: 2024-02-01-preview)
    #[serde(default = "default_api_version")]
    pub api_version: String,
}

/// Sync behavior configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SyncConfig {
    /// Days until indicators expire (default: 50, matches Python)
    #[serde(default = "default_days_to_expire")]
    pub days_to_expire: u32,

    /// Start counting expiration from "current_date" or "valid_from" (default: "current_date")
    #[serde(default = "default_days_to_expire_start")]
    pub days_to_expire_start: String,

    /// Per-type expiration overrides (days)
    /// Example: {"ipv4-addr": 180, "domain-name": 365}
    #[serde(default)]
    pub type_expiration: HashMap<String, u32>,

    /// Default confidence level (0-100, default: 50)
    #[serde(default = "default_confidence")]
    pub default_confidence: u8,

    /// Indicator types to include (empty = all supported)
    #[serde(default)]
    pub include_types: Vec<String>,

    /// Indicator types to exclude
    #[serde(default)]
    pub exclude_types: Vec<String>,

    /// Dry run mode - parse without uploading
    #[serde(default)]
    pub dry_run: bool,

    /// Maximum indicators per batch (max 100)
    #[serde(default = "default_batch_size")]
    pub batch_size: usize,

    /// Requests per minute limit (max 100)
    #[serde(default = "default_rate_limit")]
    pub requests_per_minute: u32,

    // === Performance Tuning ===
    /// Number of concurrent MISP page fetches (default: 4)
    #[serde(default = "default_concurrent_page_fetches")]
    pub concurrent_page_fetches: usize,

    /// Number of concurrent Sentinel upload batches (default: 4)
    #[serde(default = "default_concurrent_uploads")]
    pub concurrent_uploads: usize,

    /// Enable parallel conversion of events to STIX (default: true)
    #[serde(default = "default_true")]
    pub parallel_conversion: bool,

    /// Enable verbose logging
    #[serde(default)]
    pub verbose: bool,

    /// Flatten MISP object attributes to atomic attributes (default: true, matches Python)
    /// Helps when attributes are not "mapped" in misp-stix converter
    #[serde(default = "default_true")]
    pub flatten_attributes: bool,

    /// Ignore local tags (org-specific) when processing (default: true, matches Python)
    #[serde(default = "default_true")]
    pub ignore_local_tags: bool,

    /// Write parsed indicators to file for debugging (default: false)
    #[serde(default)]
    pub write_parsed_indicators: bool,

    /// Write event IDs to file for debugging (default: false)
    #[serde(default)]
    pub write_parsed_event_ids: bool,
}

/// Azure Key Vault configuration for secret management
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct KeyVaultConfig {
    /// Key Vault URL (e.g., https://myvault.vault.azure.net/)
    pub vault_url: String,

    /// Secret name for MISP API key
    pub misp_api_key_secret: Option<String>,

    /// Secret name for Sentinel client secret
    pub sentinel_client_secret: Option<String>,
}

// Default value functions
fn default_true() -> bool {
    true
}
fn default_page_limit() -> u32 {
    100
}
fn default_source_system() -> String {
    "MISP".to_string()
}
fn default_api_version() -> String {
    "2024-02-01-preview".to_string()
} // Latest Sentinel TI API
fn default_days_to_expire() -> u32 {
    50
} // Match Python default
fn default_days_to_expire_start() -> String {
    "current_date".to_string()
} // Match Python default
fn default_confidence() -> u8 {
    50
}
fn default_batch_size() -> usize {
    100
}
fn default_rate_limit() -> u32 {
    100
}
fn default_concurrent_page_fetches() -> usize {
    4
}
fn default_concurrent_uploads() -> usize {
    4
}
fn default_publish_timestamp() -> Option<String> {
    Some("14d".to_string())
} // Match Python default

#[allow(clippy::derivable_impls)] // Explicit impl is clearer for nested structs
impl Default for Config {
    fn default() -> Self {
        Config {
            misp: MispConfig::default(),
            sentinel: SentinelConfig::default(),
            sync: SyncConfig::default(),
            keyvault: None,
        }
    }
}

impl Default for MispConfig {
    fn default() -> Self {
        MispConfig {
            url: String::new(),
            api_key: String::new(),
            verify_tls: true,
            filters: MispFilters::default(),
            page_limit: default_page_limit(),
            max_events: None,
        }
    }
}

impl Default for SentinelConfig {
    fn default() -> Self {
        SentinelConfig {
            tenant_id: String::new(),
            client_id: String::new(),
            client_secret: String::new(),
            workspace_id: String::new(),
            source_system: default_source_system(),
            api_version: default_api_version(),
        }
    }
}

impl Default for SyncConfig {
    fn default() -> Self {
        SyncConfig {
            days_to_expire: default_days_to_expire(),
            days_to_expire_start: default_days_to_expire_start(),
            type_expiration: HashMap::new(),
            default_confidence: default_confidence(),
            include_types: Vec::new(),
            exclude_types: Vec::new(),
            dry_run: false,
            batch_size: default_batch_size(),
            requests_per_minute: default_rate_limit(),
            concurrent_page_fetches: default_concurrent_page_fetches(),
            concurrent_uploads: default_concurrent_uploads(),
            parallel_conversion: true,
            verbose: false,
            flatten_attributes: true,
            ignore_local_tags: true,
            write_parsed_indicators: false,
            write_parsed_event_ids: false,
        }
    }
}

impl Config {
    /// Load configuration from environment variables
    pub fn from_env() -> Result<Self> {
        Ok(Config {
            misp: MispConfig {
                url: env::var("MISP_URL").map_err(|_| Error::Config("MISP_URL not set".into()))?,
                api_key: env::var("MISP_API_KEY").unwrap_or_default(), // Can be loaded from Key Vault
                verify_tls: env::var("MISP_VERIFY_TLS")
                    .map(|v| v.parse().unwrap_or(true))
                    .unwrap_or(true),
                filters: MispFilters {
                    published: env::var("MISP_FILTER_PUBLISHED")
                        .map(|v| v.parse().unwrap_or(true))
                        .unwrap_or(true),
                    tags: env::var("MISP_FILTER_TAGS")
                        .map(|v| {
                            v.split(',')
                                .map(|s| s.trim().to_string())
                                .filter(|s| !s.is_empty())
                                .collect()
                        })
                        .unwrap_or_default(),
                    not_tags: env::var("MISP_FILTER_NOT_TAGS")
                        .map(|v| {
                            v.split(',')
                                .map(|s| s.trim().to_string())
                                .filter(|s| !s.is_empty())
                                .collect()
                        })
                        .unwrap_or_default(),
                    orgs: env::var("MISP_FILTER_ORGS")
                        .map(|v| {
                            v.split(',')
                                .map(|s| s.trim().to_string())
                                .filter(|s| !s.is_empty())
                                .collect()
                        })
                        .unwrap_or_default(),
                    not_orgs: env::var("MISP_FILTER_NOT_ORGS")
                        .map(|v| {
                            v.split(',')
                                .map(|s| s.trim().to_string())
                                .filter(|s| !s.is_empty())
                                .collect()
                        })
                        .unwrap_or_default(),
                    publish_timestamp: env::var("MISP_FILTER_PUBLISH_TIMESTAMP")
                        .ok()
                        .or(default_publish_timestamp()),
                    timestamp: env::var("MISP_FILTER_TIMESTAMP").ok(),
                    from: env::var("MISP_FILTER_FROM").ok(),
                    to: env::var("MISP_FILTER_TO").ok(),
                    last: env::var("MISP_FILTER_LAST").ok(),
                    event_info: env::var("MISP_FILTER_EVENT_INFO").ok(),
                    threat_level_id: env::var("MISP_FILTER_THREAT_LEVEL")
                        .map(|v| {
                            v.split(',')
                                .filter_map(|s| s.trim().parse::<u8>().ok())
                                .collect::<Vec<u8>>()
                        })
                        .ok(),
                    to_ids: env::var("MISP_FILTER_TO_IDS")
                        .map(|v| v.parse().unwrap_or(true))
                        .unwrap_or(true),
                    enforce_warninglist: env::var("MISP_FILTER_ENFORCE_WARNINGLIST")
                        .map(|v| v.parse().unwrap_or(false))
                        .unwrap_or(false),
                    include_event_tags: env::var("MISP_FILTER_INCLUDE_EVENT_TAGS")
                        .map(|v| v.parse().unwrap_or(true))
                        .unwrap_or(true),
                    custom: HashMap::new(),
                },
                page_limit: env::var("MISP_PAGE_LIMIT")
                    .map(|v| v.parse().unwrap_or(100))
                    .unwrap_or(100),
                max_events: env::var("MISP_MAX_EVENTS")
                    .map(|v| v.parse().ok())
                    .ok()
                    .flatten(),
            },
            sentinel: SentinelConfig {
                tenant_id: env::var("AZURE_TENANT_ID")
                    .map_err(|_| Error::Config("AZURE_TENANT_ID not set".into()))?,
                client_id: env::var("AZURE_CLIENT_ID")
                    .map_err(|_| Error::Config("AZURE_CLIENT_ID not set".into()))?,
                client_secret: env::var("AZURE_CLIENT_SECRET").unwrap_or_default(), // Can be loaded from Key Vault
                workspace_id: env::var("SENTINEL_WORKSPACE_ID")
                    .map_err(|_| Error::Config("SENTINEL_WORKSPACE_ID not set".into()))?,
                source_system: env::var("SENTINEL_SOURCE_SYSTEM")
                    .unwrap_or_else(|_| "MISP".to_string()),
                api_version: env::var("SENTINEL_API_VERSION")
                    .unwrap_or_else(|_| default_api_version()),
            },
            sync: SyncConfig {
                days_to_expire: env::var("SYNC_DAYS_TO_EXPIRE")
                    .map(|v| v.parse().unwrap_or(default_days_to_expire()))
                    .unwrap_or_else(|_| default_days_to_expire()),
                days_to_expire_start: env::var("SYNC_DAYS_TO_EXPIRE_START")
                    .unwrap_or_else(|_| default_days_to_expire_start()),
                type_expiration: env::var("SYNC_TYPE_EXPIRATION")
                    .map(|v| parse_type_expiration(&v))
                    .unwrap_or_default(),
                default_confidence: env::var("SYNC_DEFAULT_CONFIDENCE")
                    .map(|v| v.parse().unwrap_or(50))
                    .unwrap_or(50),
                include_types: env::var("SYNC_INCLUDE_TYPES")
                    .map(|v| v.split(',').map(|s| s.trim().to_string()).collect())
                    .unwrap_or_default(),
                exclude_types: env::var("SYNC_EXCLUDE_TYPES")
                    .map(|v| v.split(',').map(|s| s.trim().to_string()).collect())
                    .unwrap_or_default(),
                dry_run: env::var("SYNC_DRY_RUN")
                    .map(|v| v.parse().unwrap_or(false))
                    .unwrap_or(false),
                batch_size: env::var("SYNC_BATCH_SIZE")
                    .map(|v| v.parse().unwrap_or(100).min(100))
                    .unwrap_or(100),
                requests_per_minute: env::var("SYNC_REQUESTS_PER_MINUTE")
                    .map(|v| v.parse().unwrap_or(100).min(100))
                    .unwrap_or(100),
                concurrent_page_fetches: env::var("SYNC_CONCURRENT_PAGE_FETCHES")
                    .map(|v| v.parse().unwrap_or(4))
                    .unwrap_or(4),
                concurrent_uploads: env::var("SYNC_CONCURRENT_UPLOADS")
                    .map(|v| v.parse().unwrap_or(4))
                    .unwrap_or(4),
                parallel_conversion: env::var("SYNC_PARALLEL_CONVERSION")
                    .map(|v| v.parse().unwrap_or(true))
                    .unwrap_or(true),
                verbose: env::var("SYNC_VERBOSE")
                    .map(|v| v.parse().unwrap_or(false))
                    .unwrap_or(false),
                flatten_attributes: env::var("SYNC_FLATTEN_ATTRIBUTES")
                    .map(|v| v.parse().unwrap_or(false))
                    .unwrap_or(false),
                ignore_local_tags: env::var("SYNC_IGNORE_LOCAL_TAGS")
                    .map(|v| v.parse().unwrap_or(true))
                    .unwrap_or(true),
                write_parsed_indicators: env::var("SYNC_WRITE_PARSED_INDICATORS")
                    .map(|v| v.parse().unwrap_or(false))
                    .unwrap_or(false),
                write_parsed_event_ids: env::var("SYNC_WRITE_PARSED_EVENT_IDS")
                    .map(|v| v.parse().unwrap_or(false))
                    .unwrap_or(false),
            },
            keyvault: env::var("AZURE_KEYVAULT_URL")
                .ok()
                .map(|vault_url| KeyVaultConfig {
                    vault_url,
                    misp_api_key_secret: env::var("KEYVAULT_MISP_API_KEY_SECRET").ok(),
                    sentinel_client_secret: env::var("KEYVAULT_SENTINEL_CLIENT_SECRET").ok(),
                }),
        })
    }

    /// Load configuration from a TOML file
    pub fn from_file<P: AsRef<Path>>(path: P) -> Result<Self> {
        let content = std::fs::read_to_string(path)
            .map_err(|e| Error::Config(format!("Failed to read config file: {}", e)))?;
        toml::from_str(&content)
            .map_err(|e| Error::Config(format!("Failed to parse config file: {}", e)))
    }

    /// Load configuration with environment variable overrides
    pub fn load() -> Result<Self> {
        // Try loading from file first, then override with env vars
        let config_path = env::var("CONFIG_PATH").unwrap_or_else(|_| "config.toml".to_string());

        let mut config = if Path::new(&config_path).exists() {
            info!("Loading configuration from {}", config_path);
            Self::from_file(&config_path)?
        } else {
            // Try env vars, but fall back to defaults if not set
            info!("Loading configuration from environment variables");
            Self::from_env().unwrap_or_else(|_| Self::default())
        };

        // Override core settings with environment variables if set
        if let Ok(val) = env::var("MISP_URL") {
            config.misp.url = val;
        }
        if let Ok(val) = env::var("MISP_API_KEY") {
            config.misp.api_key = val;
        }
        if let Ok(val) = env::var("MISP_VERIFY_TLS") {
            config.misp.verify_tls = val.parse().unwrap_or(true);
        }
        if let Ok(val) = env::var("MISP_PAGE_LIMIT") {
            config.misp.page_limit = val.parse().unwrap_or(100);
        }

        // Override MISP filters with environment variables
        if let Ok(val) = env::var("MISP_FILTER_PUBLISHED") {
            config.misp.filters.published = val.parse().unwrap_or(true);
        }
        if let Ok(val) = env::var("MISP_FILTER_TAGS") {
            config.misp.filters.tags = val
                .split(',')
                .map(|s| s.trim().to_string())
                .filter(|s| !s.is_empty())
                .collect();
        }
        if let Ok(val) = env::var("MISP_FILTER_NOT_TAGS") {
            config.misp.filters.not_tags = val
                .split(',')
                .map(|s| s.trim().to_string())
                .filter(|s| !s.is_empty())
                .collect();
        }
        if let Ok(val) = env::var("MISP_FILTER_ORGS") {
            config.misp.filters.orgs = val
                .split(',')
                .map(|s| s.trim().to_string())
                .filter(|s| !s.is_empty())
                .collect();
        }
        if let Ok(val) = env::var("MISP_FILTER_NOT_ORGS") {
            config.misp.filters.not_orgs = val
                .split(',')
                .map(|s| s.trim().to_string())
                .filter(|s| !s.is_empty())
                .collect();
        }
        if let Ok(val) = env::var("MISP_FILTER_PUBLISH_TIMESTAMP") {
            config.misp.filters.publish_timestamp = Some(val);
        }
        if let Ok(val) = env::var("MISP_FILTER_TIMESTAMP") {
            config.misp.filters.timestamp = Some(val);
        }
        if let Ok(val) = env::var("MISP_FILTER_FROM") {
            config.misp.filters.from = Some(val);
        }
        if let Ok(val) = env::var("MISP_FILTER_TO") {
            config.misp.filters.to = Some(val);
        }
        if let Ok(val) = env::var("MISP_FILTER_LAST") {
            config.misp.filters.last = Some(val);
        }
        if let Ok(val) = env::var("MISP_FILTER_EVENT_INFO") {
            config.misp.filters.event_info = Some(val);
        }
        if let Ok(val) = env::var("MISP_FILTER_THREAT_LEVEL") {
            config.misp.filters.threat_level_id = Some(
                val.split(',')
                    .filter_map(|s| s.trim().parse::<u8>().ok())
                    .collect(),
            );
        }
        if let Ok(val) = env::var("MISP_FILTER_TO_IDS") {
            config.misp.filters.to_ids = val.parse().unwrap_or(true);
        }
        if let Ok(val) = env::var("MISP_FILTER_ENFORCE_WARNINGLIST") {
            config.misp.filters.enforce_warninglist = val.parse().unwrap_or(true);
        }
        if let Ok(val) = env::var("MISP_MAX_EVENTS") {
            config.misp.max_events = val.parse().ok();
        }

        // Override Sentinel settings
        if let Ok(val) = env::var("AZURE_TENANT_ID") {
            config.sentinel.tenant_id = val;
        }
        if let Ok(val) = env::var("AZURE_CLIENT_ID") {
            config.sentinel.client_id = val;
        }
        if let Ok(val) = env::var("AZURE_CLIENT_SECRET") {
            config.sentinel.client_secret = val;
        }
        if let Ok(val) = env::var("SENTINEL_WORKSPACE_ID") {
            config.sentinel.workspace_id = val;
        }

        // Override sync settings
        if let Ok(val) = env::var("SYNC_DRY_RUN") {
            config.sync.dry_run = val.parse().unwrap_or(false);
        }
        if let Ok(val) = env::var("SYNC_BATCH_SIZE") {
            config.sync.batch_size = val.parse().unwrap_or(100);
        }
        if let Ok(val) = env::var("SYNC_REQUESTS_PER_MINUTE") {
            config.sync.requests_per_minute = val.parse().unwrap_or(100);
        }
        if let Ok(val) = env::var("SYNC_CONCURRENT_PAGE_FETCHES") {
            config.sync.concurrent_page_fetches = val.parse().unwrap_or(4);
        }
        if let Ok(val) = env::var("SYNC_CONCURRENT_UPLOADS") {
            config.sync.concurrent_uploads = val.parse().unwrap_or(4);
        }
        if let Ok(val) = env::var("SYNC_PARALLEL_CONVERSION") {
            config.sync.parallel_conversion = val.parse().unwrap_or(true);
        }

        Ok(config)
    }

    /// Load secrets from Azure Key Vault
    pub async fn load_keyvault_secrets(&mut self) -> Result<()> {
        use azure_security_keyvault_secrets::models::Secret;

        let kv_config = match &self.keyvault {
            Some(kv) => kv.clone(),
            None => return Ok(()),
        };

        info!(
            "Loading secrets from Azure Key Vault: {}",
            kv_config.vault_url
        );

        let credential = azure_identity::DeveloperToolsCredential::new(None)
            .map_err(|e| Error::KeyVault(format!("Failed to create credential: {}", e)))?;
        let client = azure_security_keyvault_secrets::SecretClient::new(
            &kv_config.vault_url,
            credential,
            None, // default options
        )
        .map_err(|e| Error::KeyVault(format!("Failed to create Key Vault client: {}", e)))?;

        // Load MISP API key if configured
        if let Some(secret_name) = &kv_config.misp_api_key_secret {
            if self.misp.api_key.is_empty() {
                match client.get_secret(secret_name, None).await {
                    Ok(response) => {
                        let secret: Secret = response.into_model().map_err(|e| {
                            Error::KeyVault(format!("Failed to parse secret: {}", e))
                        })?;
                        self.misp.api_key = secret.value.clone().unwrap_or_default();
                        info!("Loaded MISP API key from Key Vault");
                    }
                    Err(e) => {
                        return Err(Error::KeyVault(format!(
                            "Failed to load MISP API key: {}",
                            e
                        )));
                    }
                }
            }
        }

        // Load Sentinel client secret if configured
        if let Some(secret_name) = &kv_config.sentinel_client_secret {
            if self.sentinel.client_secret.is_empty() {
                match client.get_secret(secret_name, None).await {
                    Ok(response) => {
                        let secret: Secret = response.into_model().map_err(|e| {
                            Error::KeyVault(format!("Failed to parse secret: {}", e))
                        })?;
                        self.sentinel.client_secret = secret.value.clone().unwrap_or_default();
                        info!("Loaded Sentinel client secret from Key Vault");
                    }
                    Err(e) => {
                        return Err(Error::KeyVault(format!(
                            "Failed to load Sentinel client secret: {}",
                            e
                        )));
                    }
                }
            }
        }

        Ok(())
    }

    /// Validate the configuration
    pub fn validate(&self) -> Result<()> {
        if self.misp.url.is_empty() {
            return Err(Error::Config("MISP URL is required".into()));
        }
        if self.misp.api_key.is_empty() {
            return Err(Error::Config("MISP API key is required".into()));
        }
        if self.sentinel.tenant_id.is_empty() {
            return Err(Error::Config("Azure tenant ID is required".into()));
        }
        if self.sentinel.client_id.is_empty() {
            return Err(Error::Config("Azure client ID is required".into()));
        }
        if self.sentinel.client_secret.is_empty() {
            return Err(Error::Config("Azure client secret is required".into()));
        }
        if self.sentinel.workspace_id.is_empty() {
            return Err(Error::Config("Sentinel workspace ID is required".into()));
        }
        Ok(())
    }
}

/// Parse type expiration from string format: "ipv4-addr:180,domain-name:365"
fn parse_type_expiration(s: &str) -> HashMap<String, u32> {
    s.split(',')
        .filter_map(|pair| {
            let parts: Vec<&str> = pair.split(':').collect();
            if parts.len() == 2 {
                Some((parts[0].trim().to_string(), parts[1].trim().parse().ok()?))
            } else {
                None
            }
        })
        .collect()
}
