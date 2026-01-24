//! Core library for MISP to Microsoft Sentinel threat intelligence synchronization
//!
//! This crate provides the shared functionality for syncing threat indicators
//! from MISP to Microsoft Sentinel using the Upload Indicators API.

pub mod config;
pub mod error;
pub mod misp;
pub mod progress;
pub mod sentinel;
pub mod stix;
pub mod sync;

pub use config::{Config, KeyVaultConfig};
pub use error::Error;
pub use progress::ProgressTracker;
pub use sync::Syncer;

// Re-export commonly used types for convenience
pub use misp::{MispAttribute, MispClient, MispEvent};
pub use stix::{
    create_file_hash_pattern, create_pattern, ObservableType, StixAttackPattern, StixIdentity,
    StixIndicator, StixObject, StixRelationship, StixThreatActor,
};
