//! STIX 2.1 data structures for threat intelligence
//!
//! This module defines the STIX objects supported by the Microsoft Sentinel
//! Upload Indicators API.

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use uuid::Uuid;

/// STIX indicator object for threat intelligence
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct StixIndicator {
    /// Object type - always "indicator"
    #[serde(rename = "type")]
    pub object_type: String,

    /// STIX specification version
    #[serde(default = "default_spec_version")]
    pub spec_version: String,

    /// Unique identifier (format: indicator--UUID)
    pub id: String,

    /// When the indicator was created
    pub created: DateTime<Utc>,

    /// When the indicator was last modified
    pub modified: DateTime<Utc>,

    /// Human-readable name
    #[serde(skip_serializing_if = "Option::is_none")]
    pub name: Option<String>,

    /// Detailed description
    #[serde(skip_serializing_if = "Option::is_none")]
    pub description: Option<String>,

    /// The detection pattern (STIX patterning language)
    pub pattern: String,

    /// Pattern language type (usually "stix")
    pub pattern_type: String,

    /// Pattern language version
    #[serde(skip_serializing_if = "Option::is_none")]
    pub pattern_version: Option<String>,

    /// When this indicator becomes valid
    pub valid_from: DateTime<Utc>,

    /// When this indicator expires
    #[serde(skip_serializing_if = "Option::is_none")]
    pub valid_until: Option<DateTime<Utc>>,

    /// Indicator categories
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub indicator_types: Vec<String>,

    /// Kill chain phases
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub kill_chain_phases: Vec<KillChainPhase>,

    /// Confidence level (0-100)
    #[serde(skip_serializing_if = "Option::is_none")]
    pub confidence: Option<u8>,

    /// Language of text content
    #[serde(skip_serializing_if = "Option::is_none")]
    pub lang: Option<String>,

    /// External references (URLs, reports, etc.)
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub external_references: Vec<ExternalReference>,

    /// Object marking references (TLP, etc.)
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub object_marking_refs: Vec<String>,

    /// Labels/tags
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub labels: Vec<String>,

    /// Creator reference
    #[serde(skip_serializing_if = "Option::is_none")]
    pub created_by_ref: Option<String>,

    /// Whether the indicator is revoked
    #[serde(default)]
    pub revoked: bool,

    /// Granular markings for specific fields
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub granular_markings: Vec<GranularMarking>,
}

/// Kill chain phase reference
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct KillChainPhase {
    pub kill_chain_name: String,
    pub phase_name: String,
}

/// External reference (URL, report, etc.)
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ExternalReference {
    pub source_name: String,

    #[serde(skip_serializing_if = "Option::is_none")]
    pub description: Option<String>,

    #[serde(skip_serializing_if = "Option::is_none")]
    pub url: Option<String>,

    #[serde(skip_serializing_if = "Option::is_none")]
    pub external_id: Option<String>,

    #[serde(default, skip_serializing_if = "HashMap::is_empty")]
    pub hashes: HashMap<String, String>,
}

/// Granular marking for specific fields
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GranularMarking {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub marking_ref: Option<String>,

    #[serde(default)]
    pub selectors: Vec<String>,

    #[serde(skip_serializing_if = "Option::is_none")]
    pub lang: Option<String>,
}

/// STIX Attack Pattern object
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct StixAttackPattern {
    #[serde(rename = "type")]
    pub object_type: String,

    #[serde(default = "default_spec_version")]
    pub spec_version: String,

    pub id: String,

    pub created: DateTime<Utc>,

    pub modified: DateTime<Utc>,

    pub name: String,

    #[serde(skip_serializing_if = "Option::is_none")]
    pub description: Option<String>,

    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub aliases: Vec<String>,

    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub kill_chain_phases: Vec<KillChainPhase>,

    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub external_references: Vec<ExternalReference>,

    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub object_marking_refs: Vec<String>,

    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub labels: Vec<String>,
}

impl StixAttackPattern {
    pub fn new(name: String) -> Self {
        let now = Utc::now();
        Self {
            object_type: "attack-pattern".to_string(),
            spec_version: "2.1".to_string(),
            id: format!("attack-pattern--{}", Uuid::new_v4()),
            created: now,
            modified: now,
            name,
            description: None,
            aliases: vec![],
            kill_chain_phases: vec![],
            external_references: vec![],
            object_marking_refs: vec![],
            labels: vec![],
        }
    }

    pub fn new_with_deterministic_id(source_uuid: &str, name: String) -> Self {
        let now = Utc::now();
        let namespace = Uuid::NAMESPACE_URL;
        let deterministic_uuid = Uuid::new_v5(&namespace, source_uuid.as_bytes());
        Self {
            object_type: "attack-pattern".to_string(),
            spec_version: "2.1".to_string(),
            id: format!("attack-pattern--{}", deterministic_uuid),
            created: now,
            modified: now,
            name,
            description: None,
            aliases: vec![],
            kill_chain_phases: vec![],
            external_references: vec![],
            object_marking_refs: vec![],
            labels: vec![],
        }
    }

    pub fn with_description(mut self, description: impl Into<String>) -> Self {
        self.description = Some(description.into());
        self
    }

    pub fn with_external_reference(mut self, reference: ExternalReference) -> Self {
        self.external_references.push(reference);
        self
    }

    pub fn with_tlp(mut self, tlp_marking: &str) -> Self {
        if !self.object_marking_refs.contains(&tlp_marking.to_string()) {
            self.object_marking_refs.push(tlp_marking.to_string());
        }
        self
    }
}

/// STIX Threat Actor object
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct StixThreatActor {
    #[serde(rename = "type")]
    pub object_type: String,

    #[serde(default = "default_spec_version")]
    pub spec_version: String,

    pub id: String,

    pub created: DateTime<Utc>,

    pub modified: DateTime<Utc>,

    pub name: String,

    #[serde(skip_serializing_if = "Option::is_none")]
    pub description: Option<String>,

    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub aliases: Vec<String>,

    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub threat_actor_types: Vec<String>,

    #[serde(skip_serializing_if = "Option::is_none")]
    pub first_seen: Option<DateTime<Utc>>,

    #[serde(skip_serializing_if = "Option::is_none")]
    pub last_seen: Option<DateTime<Utc>>,

    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub roles: Vec<String>,

    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub goals: Vec<String>,

    #[serde(skip_serializing_if = "Option::is_none")]
    pub sophistication: Option<String>,

    #[serde(skip_serializing_if = "Option::is_none")]
    pub resource_level: Option<String>,

    #[serde(skip_serializing_if = "Option::is_none")]
    pub primary_motivation: Option<String>,

    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub external_references: Vec<ExternalReference>,

    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub object_marking_refs: Vec<String>,

    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub labels: Vec<String>,
}

impl StixThreatActor {
    pub fn new(name: String) -> Self {
        let now = Utc::now();
        Self {
            object_type: "threat-actor".to_string(),
            spec_version: "2.1".to_string(),
            id: format!("threat-actor--{}", Uuid::new_v4()),
            created: now,
            modified: now,
            name,
            description: None,
            aliases: vec![],
            threat_actor_types: vec![],
            first_seen: None,
            last_seen: None,
            roles: vec![],
            goals: vec![],
            sophistication: None,
            resource_level: None,
            primary_motivation: None,
            external_references: vec![],
            object_marking_refs: vec![],
            labels: vec![],
        }
    }

    pub fn new_with_deterministic_id(source_uuid: &str, name: String) -> Self {
        let now = Utc::now();
        let namespace = Uuid::NAMESPACE_URL;
        let deterministic_uuid = Uuid::new_v5(&namespace, source_uuid.as_bytes());
        Self {
            object_type: "threat-actor".to_string(),
            spec_version: "2.1".to_string(),
            id: format!("threat-actor--{}", deterministic_uuid),
            created: now,
            modified: now,
            name,
            description: None,
            aliases: vec![],
            threat_actor_types: vec![],
            first_seen: None,
            last_seen: None,
            roles: vec![],
            goals: vec![],
            sophistication: None,
            resource_level: None,
            primary_motivation: None,
            external_references: vec![],
            object_marking_refs: vec![],
            labels: vec![],
        }
    }

    pub fn with_description(mut self, description: impl Into<String>) -> Self {
        self.description = Some(description.into());
        self
    }

    pub fn with_external_reference(mut self, reference: ExternalReference) -> Self {
        self.external_references.push(reference);
        self
    }

    pub fn with_tlp(mut self, tlp_marking: &str) -> Self {
        if !self.object_marking_refs.contains(&tlp_marking.to_string()) {
            self.object_marking_refs.push(tlp_marking.to_string());
        }
        self
    }
}

/// STIX Identity object
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct StixIdentity {
    #[serde(rename = "type")]
    pub object_type: String,

    #[serde(default = "default_spec_version")]
    pub spec_version: String,

    pub id: String,

    pub created: DateTime<Utc>,

    pub modified: DateTime<Utc>,

    pub name: String,

    #[serde(skip_serializing_if = "Option::is_none")]
    pub description: Option<String>,

    #[serde(skip_serializing_if = "Option::is_none")]
    pub identity_class: Option<String>,

    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub sectors: Vec<String>,

    #[serde(skip_serializing_if = "Option::is_none")]
    pub contact_information: Option<String>,

    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub external_references: Vec<ExternalReference>,

    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub object_marking_refs: Vec<String>,

    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub labels: Vec<String>,
}

impl StixIdentity {
    pub fn new(name: String) -> Self {
        let now = Utc::now();
        Self {
            object_type: "identity".to_string(),
            spec_version: "2.1".to_string(),
            id: format!("identity--{}", Uuid::new_v4()),
            created: now,
            modified: now,
            name,
            description: None,
            identity_class: None,
            sectors: vec![],
            contact_information: None,
            external_references: vec![],
            object_marking_refs: vec![],
            labels: vec![],
        }
    }

    pub fn new_with_deterministic_id(source_uuid: &str, name: String) -> Self {
        let now = Utc::now();
        let namespace = Uuid::NAMESPACE_URL;
        let deterministic_uuid = Uuid::new_v5(&namespace, source_uuid.as_bytes());
        Self {
            object_type: "identity".to_string(),
            spec_version: "2.1".to_string(),
            id: format!("identity--{}", deterministic_uuid),
            created: now,
            modified: now,
            name,
            description: None,
            identity_class: None,
            sectors: vec![],
            contact_information: None,
            external_references: vec![],
            object_marking_refs: vec![],
            labels: vec![],
        }
    }

    pub fn with_description(mut self, description: impl Into<String>) -> Self {
        self.description = Some(description.into());
        self
    }

    pub fn with_identity_class(mut self, class: impl Into<String>) -> Self {
        self.identity_class = Some(class.into());
        self
    }

    pub fn with_external_reference(mut self, reference: ExternalReference) -> Self {
        self.external_references.push(reference);
        self
    }

    pub fn with_tlp(mut self, tlp_marking: &str) -> Self {
        if !self.object_marking_refs.contains(&tlp_marking.to_string()) {
            self.object_marking_refs.push(tlp_marking.to_string());
        }
        self
    }
}

/// STIX Relationship object
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct StixRelationship {
    #[serde(rename = "type")]
    pub object_type: String,

    #[serde(default = "default_spec_version")]
    pub spec_version: String,

    pub id: String,

    pub created: DateTime<Utc>,

    pub modified: DateTime<Utc>,

    pub relationship_type: String,

    pub source_ref: String,

    pub target_ref: String,

    #[serde(skip_serializing_if = "Option::is_none")]
    pub description: Option<String>,

    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub external_references: Vec<ExternalReference>,

    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub object_marking_refs: Vec<String>,
}

impl StixRelationship {
    pub fn new(relationship_type: String, source_ref: String, target_ref: String) -> Self {
        let now = Utc::now();
        Self {
            object_type: "relationship".to_string(),
            spec_version: "2.1".to_string(),
            id: format!("relationship--{}", Uuid::new_v4()),
            created: now,
            modified: now,
            relationship_type,
            source_ref,
            target_ref,
            description: None,
            external_references: vec![],
            object_marking_refs: vec![],
        }
    }

    pub fn new_with_deterministic_id(
        source_uuid: &str,
        relationship_type: String,
        source_ref: String,
        target_ref: String,
    ) -> Self {
        let now = Utc::now();
        let namespace = Uuid::NAMESPACE_URL;
        let deterministic_uuid = Uuid::new_v5(&namespace, source_uuid.as_bytes());
        Self {
            object_type: "relationship".to_string(),
            spec_version: "2.1".to_string(),
            id: format!("relationship--{}", deterministic_uuid),
            created: now,
            modified: now,
            relationship_type,
            source_ref,
            target_ref,
            description: None,
            external_references: vec![],
            object_marking_refs: vec![],
        }
    }

    pub fn with_tlp(mut self, tlp_marking: &str) -> Self {
        if !self.object_marking_refs.contains(&tlp_marking.to_string()) {
            self.object_marking_refs.push(tlp_marking.to_string());
        }
        self
    }
}

/// Enum wrapper for all supported STIX domain objects
#[derive(Debug, Clone, Serialize)]
#[serde(untagged)]
pub enum StixObject {
    Indicator(StixIndicator),
    AttackPattern(StixAttackPattern),
    ThreatActor(StixThreatActor),
    Identity(StixIdentity),
    Relationship(StixRelationship),
}

/// TLP (Traffic Light Protocol) marking definitions
pub mod tlp {
    /// TLP:WHITE / TLP:CLEAR
    pub const WHITE: &str = "marking-definition--613f2e26-407d-48c7-9eca-b8e91df99dc9";
    /// TLP:GREEN
    pub const GREEN: &str = "marking-definition--34098fce-860f-48ae-8e50-ebd3cc5e41da";
    /// TLP:AMBER
    pub const AMBER: &str = "marking-definition--f88d31f6-486f-44da-b317-01333bde0b82";
    /// TLP:RED
    pub const RED: &str = "marking-definition--5e57c739-391a-4eb3-b6be-7d15ca92d5ed";

    /// Get TLP marking definition from tag
    pub fn from_tag(tag: &str) -> Option<&'static str> {
        let tag_lower = tag.to_lowercase();
        if tag_lower.contains("tlp:white") || tag_lower.contains("tlp:clear") {
            Some(WHITE)
        } else if tag_lower.contains("tlp:green") {
            Some(GREEN)
        } else if tag_lower.contains("tlp:amber") {
            Some(AMBER)
        } else if tag_lower.contains("tlp:red") {
            Some(RED)
        } else {
            None
        }
    }
}

fn default_spec_version() -> String {
    "2.1".to_string()
}

impl StixIndicator {
    /// Create a new STIX indicator with required fields
    pub fn new(pattern: String, pattern_type: String, valid_from: DateTime<Utc>) -> Self {
        let now = Utc::now();
        Self {
            object_type: "indicator".to_string(),
            spec_version: "2.1".to_string(),
            id: format!("indicator--{}", Uuid::new_v4()),
            created: now,
            modified: now,
            name: None,
            description: None,
            pattern,
            pattern_type,
            pattern_version: Some("2.1".to_string()),
            valid_from,
            valid_until: None,
            indicator_types: vec![],
            kill_chain_phases: vec![],
            confidence: None,
            lang: None,
            external_references: vec![],
            object_marking_refs: vec![],
            labels: vec![],
            created_by_ref: None,
            revoked: false,
            granular_markings: vec![],
        }
    }

    /// Create a new STIX indicator with a deterministic ID based on a source UUID
    /// This ensures the same MISP attribute always produces the same STIX indicator ID,
    /// enabling proper deduplication in Sentinel (updates instead of duplicates)
    pub fn new_with_deterministic_id(
        source_uuid: &str,
        pattern: String,
        pattern_type: String,
        valid_from: DateTime<Utc>,
    ) -> Self {
        let now = Utc::now();

        // Create a deterministic UUID v5 based on the source UUID
        // Using the URL namespace as a stable base
        let namespace = Uuid::NAMESPACE_URL;
        let deterministic_uuid = Uuid::new_v5(&namespace, source_uuid.as_bytes());

        Self {
            object_type: "indicator".to_string(),
            spec_version: "2.1".to_string(),
            id: format!("indicator--{}", deterministic_uuid),
            created: now,
            modified: now,
            name: None,
            description: None,
            pattern,
            pattern_type,
            pattern_version: Some("2.1".to_string()),
            valid_from,
            valid_until: None,
            indicator_types: vec![],
            kill_chain_phases: vec![],
            confidence: None,
            lang: None,
            external_references: vec![],
            object_marking_refs: vec![],
            labels: vec![],
            created_by_ref: None,
            revoked: false,
            granular_markings: vec![],
        }
    }

    /// Set the indicator name
    pub fn with_name(mut self, name: impl Into<String>) -> Self {
        self.name = Some(name.into());
        self
    }

    /// Set the description
    pub fn with_description(mut self, description: impl Into<String>) -> Self {
        self.description = Some(description.into());
        self
    }

    /// Set the valid_until timestamp
    pub fn with_valid_until(mut self, valid_until: DateTime<Utc>) -> Self {
        self.valid_until = Some(valid_until);
        self
    }

    /// Set confidence level
    pub fn with_confidence(mut self, confidence: u8) -> Self {
        self.confidence = Some(confidence.min(100));
        self
    }

    /// Add a TLP marking
    pub fn with_tlp(mut self, tlp_marking: &str) -> Self {
        if !self.object_marking_refs.contains(&tlp_marking.to_string()) {
            self.object_marking_refs.push(tlp_marking.to_string());
        }
        self
    }

    /// Add labels/tags
    pub fn with_labels(mut self, labels: Vec<String>) -> Self {
        self.labels.extend(labels);
        self
    }

    /// Add an external reference
    pub fn with_external_reference(mut self, reference: ExternalReference) -> Self {
        self.external_references.push(reference);
        self
    }

    /// Add indicator types
    pub fn with_indicator_types(mut self, types: Vec<String>) -> Self {
        self.indicator_types.extend(types);
        self
    }

    /// Add a kill chain phase
    pub fn with_kill_chain_phase(mut self, chain_name: String, phase_name: String) -> Self {
        self.kill_chain_phases.push(KillChainPhase {
            kill_chain_name: chain_name,
            phase_name,
        });
        self
    }
}

/// Supported indicator observable types
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ObservableType {
    IPv4Addr,
    IPv6Addr,
    DomainName,
    Url,
    File,
    EmailAddr,
    UserAccount,
    WindowsRegistryKey,
}

impl ObservableType {
    /// Get the STIX pattern prefix for this type
    pub fn pattern_prefix(&self) -> &'static str {
        match self {
            Self::IPv4Addr => "ipv4-addr:value",
            Self::IPv6Addr => "ipv6-addr:value",
            Self::DomainName => "domain-name:value",
            Self::Url => "url:value",
            Self::File => "file:hashes",
            Self::EmailAddr => "email-addr:value",
            Self::UserAccount => "user-account:account_login",
            Self::WindowsRegistryKey => "windows-registry-key:key",
        }
    }

    /// Get the type name for expiration mapping
    pub fn type_name(&self) -> &'static str {
        match self {
            Self::IPv4Addr => "ipv4-addr",
            Self::IPv6Addr => "ipv6-addr",
            Self::DomainName => "domain-name",
            Self::Url => "url",
            Self::File => "file",
            Self::EmailAddr => "email-addr",
            Self::UserAccount => "user-account",
            Self::WindowsRegistryKey => "windows-registry-key",
        }
    }
}

/// Create a STIX pattern from a value and type
pub fn create_pattern(observable_type: ObservableType, value: &str) -> String {
    format!(
        "[{} = '{}']",
        observable_type.pattern_prefix(),
        escape_pattern_value(value)
    )
}

/// Create a file hash pattern
pub fn create_file_hash_pattern(hash_type: &str, hash_value: &str) -> String {
    let hash_upper = hash_type.to_uppercase();
    let stix_hash_type = match hash_upper.as_str() {
        "MD5" => "MD5",
        "SHA1" | "SHA-1" => "SHA-1",
        "SHA256" | "SHA-256" => "SHA-256",
        "SHA512" | "SHA-512" => "SHA-512",
        "SSDEEP" => "SSDEEP",
        _ => &hash_upper,
    };
    format!("[file:hashes.'{}' = '{}']", stix_hash_type, hash_value)
}

/// Escape special characters in STIX pattern values
pub fn escape_pattern_value(value: &str) -> String {
    value.replace('\\', "\\\\").replace('\'', "\\'")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_create_ipv4_pattern() {
        let pattern = create_pattern(ObservableType::IPv4Addr, "192.168.1.1");
        assert_eq!(pattern, "[ipv4-addr:value = '192.168.1.1']");
    }

    #[test]
    fn test_create_domain_pattern() {
        let pattern = create_pattern(ObservableType::DomainName, "evil.example.com");
        assert_eq!(pattern, "[domain-name:value = 'evil.example.com']");
    }

    #[test]
    fn test_create_file_hash_pattern() {
        let pattern = create_file_hash_pattern("SHA256", "abc123");
        assert_eq!(pattern, "[file:hashes.'SHA-256' = 'abc123']");
    }

    #[test]
    fn test_tlp_from_tag() {
        assert_eq!(tlp::from_tag("tlp:white"), Some(tlp::WHITE));
        assert_eq!(tlp::from_tag("TLP:AMBER"), Some(tlp::AMBER));
        assert_eq!(tlp::from_tag("tlp:clear"), Some(tlp::WHITE));
    }
}
