//! Error types for the MISP2Sentinel library

use thiserror::Error;

/// Main error type for the library
#[derive(Error, Debug)]
pub enum Error {
    #[error("Configuration error: {0}")]
    Config(String),

    #[error("MISP API error: {0}")]
    MispApi(String),

    #[error("Sentinel API error: {0}")]
    SentinelApi(String),

    #[error("Authentication error: {0}")]
    Auth(String),

    #[error("Rate limit exceeded, retry after {0} seconds")]
    RateLimit(u64),

    #[error("STIX conversion error: {0}")]
    StixConversion(String),

    #[error("Key Vault error: {0}")]
    KeyVault(String),

    #[error("HTTP error: {0}")]
    Http(#[from] reqwest::Error),

    #[error("JSON error: {0}")]
    Json(#[from] serde_json::Error),

    #[error("IO error: {0}")]
    Io(#[from] std::io::Error),
}

pub type Result<T> = std::result::Result<T, Error>;
