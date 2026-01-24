//! MISP API client
//!
//! This module provides a client for interacting with the MISP REST API
//! to fetch threat intelligence events and attributes.
//!
//! Optimized for high throughput with:
//! - Connection pooling
//! - Concurrent page fetching
//! - Streaming response processing

use futures::stream::{self, StreamExt};
use reqwest::Client;
use serde::{Deserialize, Serialize};
use tracing::{debug, info, warn};

use crate::config::MispConfig;
use crate::error::{Error, Result};

/// MISP API client with connection pooling
pub struct MispClient {
    client: Client,
    base_url: String,
    api_key: String,
}

impl MispClient {
    /// Create a new MISP client with optimized connection pool
    pub fn new(config: &MispConfig) -> Result<Self> {
        let client = Client::builder()
            .danger_accept_invalid_certs(!config.verify_tls)
            .timeout(std::time::Duration::from_secs(300))
            // Connection pool optimization for high throughput
            .pool_max_idle_per_host(10)
            .pool_idle_timeout(std::time::Duration::from_secs(90))
            .tcp_keepalive(std::time::Duration::from_secs(60))
            .tcp_nodelay(true)
            .build()
            .map_err(|e| Error::MispApi(format!("Failed to create HTTP client: {}", e)))?;

        Ok(Self {
            client,
            base_url: config.url.trim_end_matches('/').to_string(),
            api_key: config.api_key.clone(),
        })
    }

    /// Fetch events from MISP with concurrent page fetching
    ///
    /// This method first determines the total number of pages, then fetches
    /// them concurrently for maximum throughput.
    pub async fn fetch_events(&self, config: &MispConfig) -> Result<Vec<MispEvent>> {
        let limit = config.page_limit;
        let concurrent_fetches = 4; // Default, can be configured

        // First, get page 1 to determine if we need more pages
        info!("Fetching initial MISP events page (limit: {})", limit);
        let first_page = self.fetch_page(config, 1, limit).await?;
        let first_count = first_page.len();

        info!("First page returned {} events", first_count);

        if first_count < limit as usize {
            // All events fit in first page
            return Ok(first_page);
        }

        // We need to fetch more pages concurrently
        info!(
            "Fetching remaining pages concurrently (concurrency: {})",
            concurrent_fetches
        );

        let mut all_events = first_page;
        let mut page = 2u32;

        loop {
            // Create a batch of page numbers to fetch
            let pages_to_fetch: Vec<u32> = (page..page + concurrent_fetches as u32).collect();

            // Fetch pages concurrently
            let results: Vec<Result<Vec<MispEvent>>> = stream::iter(pages_to_fetch.clone())
                .map(|p| self.fetch_page(config, p, limit))
                .buffer_unordered(concurrent_fetches)
                .collect()
                .await;

            let mut any_page_had_results = false;
            let mut all_pages_full = true;

            for (i, result) in results.into_iter().enumerate() {
                match result {
                    Ok(events) => {
                        let count = events.len();
                        info!("Page {} returned {} events", pages_to_fetch[i], count);

                        if count > 0 {
                            any_page_had_results = true;
                            all_events.extend(events);
                        }

                        if count < limit as usize {
                            all_pages_full = false;
                        }
                    }
                    Err(e) => {
                        warn!("Error fetching page {}: {}", pages_to_fetch[i], e);
                        all_pages_full = false;
                    }
                }
            }

            if !any_page_had_results || !all_pages_full {
                break;
            }

            page += concurrent_fetches as u32;
        }

        info!("Total events fetched: {}", all_events.len());
        Ok(all_events)
    }

    /// Fetch events concurrently with configurable concurrency
    pub async fn fetch_events_concurrent(
        &self,
        config: &MispConfig,
        concurrent_fetches: usize,
    ) -> Result<Vec<MispEvent>> {
        let limit = config.page_limit;
        let max_events = config.max_events;

        // First, get page 1 to determine if we need more pages
        info!("Fetching initial MISP events page (limit: {})", limit);
        let first_page = self.fetch_page(config, 1, limit).await?;
        let first_count = first_page.len();

        info!("First page returned {} events", first_count);

        // If max_events is set and we have enough, return early
        if let Some(max) = max_events {
            if first_count >= max as usize {
                info!("Limiting to {} events (max_events setting)", max);
                return Ok(first_page.into_iter().take(max as usize).collect());
            }
        }

        if first_count < limit as usize {
            return Ok(first_page);
        }

        let mut all_events = first_page;
        let mut page = 2u32;

        loop {
            // Check if we've reached max_events limit
            if let Some(max) = max_events {
                if all_events.len() >= max as usize {
                    info!("Reached max_events limit ({}), stopping fetch", max);
                    all_events.truncate(max as usize);
                    break;
                }
            }

            let pages_to_fetch: Vec<u32> = (page..page + concurrent_fetches as u32).collect();

            let results: Vec<Result<Vec<MispEvent>>> = stream::iter(pages_to_fetch.clone())
                .map(|p| self.fetch_page(config, p, limit))
                .buffer_unordered(concurrent_fetches)
                .collect()
                .await;

            let mut any_page_had_results = false;
            let mut all_pages_full = true;

            for (i, result) in results.into_iter().enumerate() {
                match result {
                    Ok(events) => {
                        let count = events.len();
                        if count > 0 {
                            any_page_had_results = true;
                            all_events.extend(events);
                        }
                        if count < limit as usize {
                            all_pages_full = false;
                        }
                    }
                    Err(e) => {
                        warn!("Error fetching page {}: {}", pages_to_fetch[i], e);
                        all_pages_full = false;
                    }
                }
            }

            if !any_page_had_results || !all_pages_full {
                break;
            }

            page += concurrent_fetches as u32;
        }

        // Final truncation in case we went over
        if let Some(max) = max_events {
            if all_events.len() > max as usize {
                all_events.truncate(max as usize);
            }
        }

        info!("Total events fetched: {}", all_events.len());
        Ok(all_events)
    }

    /// Fetch a single page of events
    async fn fetch_page(
        &self,
        config: &MispConfig,
        page: u32,
        limit: u32,
    ) -> Result<Vec<MispEvent>> {
        debug!("Fetching MISP events page {} (limit: {})", page, limit);

        let request_body = self.build_search_request(&config.filters, page, limit);

        let response = self
            .client
            .post(format!("{}/events/restSearch", self.base_url))
            .header("Authorization", &self.api_key)
            .header("Accept", "application/json")
            .header("Content-Type", "application/json")
            .json(&request_body)
            .send()
            .await
            .map_err(|e| Error::MispApi(format!("Request failed: {}", e)))?;

        if !response.status().is_success() {
            let status = response.status();
            let text = response.text().await.unwrap_or_default();
            return Err(Error::MispApi(format!(
                "MISP API error ({}): {}",
                status, text
            )));
        }

        let result: MispSearchResponse = response
            .json()
            .await
            .map_err(|e| Error::MispApi(format!("Failed to parse response: {}", e)))?;

        Ok(result.response.into_iter().map(|w| w.event).collect())
    }

    /// Build the search request body
    fn build_search_request(
        &self,
        filters: &crate::config::MispFilters,
        page: u32,
        limit: u32,
    ) -> serde_json::Value {
        let mut request = serde_json::json!({
            "returnFormat": "json",
            "page": page,
            "limit": limit,
        });

        if let Some(obj) = request.as_object_mut() {
            // Include event tags (matches Python default: always true)
            if filters.include_event_tags {
                obj.insert("includeEventTags".to_string(), serde_json::json!(true));
            }

            if filters.published {
                obj.insert("published".to_string(), serde_json::json!(1));
            }

            // Tags to include (OR logic)
            if !filters.tags.is_empty() {
                obj.insert("tags".to_string(), serde_json::json!(filters.tags));
            }

            // Tags to exclude (NOT logic) - prefix with ! in the same array if needed
            // MISP supports both separate NOT filter and ! prefix
            if !filters.not_tags.is_empty() {
                // MISP supports "!" prefix for NOT tags in the same array
                // We'll use a separate NOT parameter when available
                let not_tags: Vec<String> =
                    filters.not_tags.iter().map(|t| format!("!{}", t)).collect();

                // If we have both include and exclude tags, merge them
                if let Some(existing) = obj.get_mut("tags") {
                    if let Some(arr) = existing.as_array_mut() {
                        for tag in not_tags {
                            arr.push(serde_json::json!(tag));
                        }
                    }
                } else {
                    obj.insert("tags".to_string(), serde_json::json!(not_tags));
                }
            }

            // Organizations to include
            if !filters.orgs.is_empty() {
                obj.insert("org".to_string(), serde_json::json!(filters.orgs));
            }

            // Organizations to exclude - use NOT parameter
            if !filters.not_orgs.is_empty() {
                let not_orgs: Vec<String> =
                    filters.not_orgs.iter().map(|o| format!("!{}", o)).collect();
                if let Some(existing) = obj.get_mut("org") {
                    if let Some(arr) = existing.as_array_mut() {
                        for org in not_orgs {
                            arr.push(serde_json::json!(org));
                        }
                    }
                } else {
                    obj.insert("org".to_string(), serde_json::json!(not_orgs));
                }
            }

            // Publish timestamp filter (when event was published)
            if let Some(ref timestamp) = filters.publish_timestamp {
                obj.insert(
                    "publish_timestamp".to_string(),
                    serde_json::json!(timestamp),
                );
            }

            // Timestamp filter (when event was last modified)
            if let Some(ref timestamp) = filters.timestamp {
                obj.insert("timestamp".to_string(), serde_json::json!(timestamp));
            }

            // Date range filters
            if let Some(ref from) = filters.from {
                obj.insert("from".to_string(), serde_json::json!(from));
            }
            if let Some(ref to) = filters.to {
                obj.insert("to".to_string(), serde_json::json!(to));
            }

            // Last N days/hours filter (e.g., "7d", "24h", or seconds)
            if let Some(ref last) = filters.last {
                obj.insert("last".to_string(), serde_json::json!(last));
            }

            // Event info text search
            if let Some(ref event_info) = filters.event_info {
                obj.insert("eventinfo".to_string(), serde_json::json!(event_info));
            }

            // Threat level filter (1=High, 2=Medium, 3=Low, 4=Undefined)
            if let Some(ref levels) = filters.threat_level_id {
                if !levels.is_empty() {
                    obj.insert("threat_level_id".to_string(), serde_json::json!(levels));
                }
            }

            if filters.enforce_warninglist {
                obj.insert("enforceWarninglist".to_string(), serde_json::json!(true));
            }

            // Only include attributes with to_ids flag set
            if filters.to_ids {
                obj.insert("to_ids".to_string(), serde_json::json!(1));
            }

            // Add custom filters
            for (key, value) in &filters.custom {
                obj.insert(key.clone(), value.clone());
            }
        }

        debug!(
            "MISP search request: {}",
            serde_json::to_string_pretty(&request).unwrap_or_default()
        );
        request
    }
}

/// MISP API search response wrapper
#[derive(Debug, Deserialize)]
pub struct MispSearchResponse {
    pub response: Vec<MispEventWrapper>,
}

/// Wrapper for MISP event in response
#[derive(Debug, Deserialize)]
pub struct MispEventWrapper {
    #[serde(rename = "Event")]
    pub event: MispEvent,
}

/// MISP Event structure
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MispEvent {
    pub id: String,
    pub uuid: String,
    pub info: String,

    #[serde(default)]
    pub date: Option<String>,

    pub timestamp: String,

    #[serde(default)]
    pub publish_timestamp: Option<String>,

    #[serde(default)]
    pub published: bool,

    #[serde(default)]
    pub threat_level_id: Option<String>,

    #[serde(default)]
    pub analysis: Option<String>,

    #[serde(rename = "Attribute", default)]
    pub attributes: Vec<MispAttribute>,

    #[serde(rename = "Object", default)]
    pub objects: Vec<MispObject>,

    #[serde(rename = "Tag", default)]
    pub tags: Vec<MispTag>,

    #[serde(rename = "Org", default)]
    pub org: Option<MispOrg>,

    #[serde(rename = "Orgc", default)]
    pub orgc: Option<MispOrg>,
}

/// MISP Attribute
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MispAttribute {
    pub id: String,
    pub uuid: String,

    #[serde(rename = "type")]
    pub attr_type: String,

    pub category: String,
    pub value: String,

    #[serde(default)]
    pub to_ids: bool,

    pub timestamp: String,

    #[serde(default)]
    pub comment: Option<String>,

    #[serde(rename = "Tag", default)]
    pub tags: Vec<MispTag>,

    #[serde(default)]
    pub first_seen: Option<String>,

    #[serde(default)]
    pub last_seen: Option<String>,
}

/// MISP Object (container for related attributes)
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MispObject {
    pub id: String,
    pub uuid: String,
    pub name: String,

    #[serde(rename = "Attribute", default)]
    pub attributes: Vec<MispAttribute>,

    #[serde(default)]
    pub comment: Option<String>,

    pub timestamp: String,
}

/// MISP Tag
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MispTag {
    #[serde(default)]
    pub id: Option<String>,
    pub name: String,

    #[serde(default)]
    pub colour: Option<String>,

    /// Local tag indicator - MISP returns this as either bool or int
    #[serde(default, deserialize_with = "deserialize_local_field")]
    pub local: Option<i32>,
}

/// Deserialize the 'local' field which can be bool, int, or string
fn deserialize_local_field<'de, D>(deserializer: D) -> std::result::Result<Option<i32>, D::Error>
where
    D: serde::Deserializer<'de>,
{
    use serde::de::Error;

    let value: Option<serde_json::Value> = Option::deserialize(deserializer)?;

    match value {
        None => Ok(None),
        Some(serde_json::Value::Bool(b)) => Ok(Some(if b { 1 } else { 0 })),
        Some(serde_json::Value::Number(n)) => Ok(Some(n.as_i64().unwrap_or(0) as i32)),
        Some(serde_json::Value::String(s)) => Ok(Some(s.parse().unwrap_or(0))),
        Some(_) => Err(D::Error::custom("unexpected type for local field")),
    }
}

/// MISP Organization
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MispOrg {
    pub id: String,
    pub name: String,

    #[serde(default)]
    pub uuid: Option<String>,
}

/// Supported MISP attribute types that can be converted to STIX indicators
///
/// This list covers the most common and actionable threat intelligence types
/// that can be represented as STIX 2.1 indicator patterns for Microsoft Sentinel.
pub const ACTIONABLE_TYPES: &[&str] = &[
    // Network indicators - IPv4/IPv6 addresses
    "ip-src",
    "ip-dst",
    "ip-src|port",
    "ip-dst|port",
    // Network indicators - Domains and hostnames
    "domain",
    "domain|ip",
    "hostname",
    "hostname|port",
    "url",
    // Network indicators - Autonomous Systems
    "AS",
    // Network indicators - MAC addresses
    "mac-address",
    "mac-eui-64",
    // Network fingerprinting
    "ja3-fingerprint-md5",
    "jarm-fingerprint",
    "hassh-md5",
    "hasshserver-md5",
    "community-id",
    // HTTP indicators
    "user-agent",
    // Email indicators
    "email-src",
    "email-dst",
    "email-subject",
    "email-src-display-name",
    "email-x-mailer",
    // File hashes - Common
    "md5",
    "sha1",
    "sha256",
    "sha512",
    "ssdeep",
    "imphash",
    "authentihash",
    "pehash",
    "vhash",
    "tlsh",
    "cdhash",
    "telfhash",
    "impfuzzy",
    // File hashes - Extended SHA variants
    "sha224",
    "sha384",
    "sha512/224",
    "sha512/256",
    "sha3-224",
    "sha3-256",
    "sha3-384",
    "sha3-512",
    // Composite file hashes (filename|hash)
    "filename|md5",
    "filename|sha1",
    "filename|sha256",
    "filename|sha512",
    "filename|ssdeep",
    "filename|imphash",
    "filename|authentihash",
    "filename|pehash",
    "filename|vhash",
    "filename|tlsh",
    "filename|sha224",
    "filename|sha384",
    "filename|sha512/224",
    "filename|sha512/256",
    "filename|sha3-224",
    "filename|sha3-256",
    "filename|sha3-384",
    "filename|sha3-512",
    "filename|impfuzzy",
    // File attributes
    "filename",
    // X.509 Certificate fingerprints
    "x509-fingerprint-md5",
    "x509-fingerprint-sha1",
    "x509-fingerprint-sha256",
    // Windows-specific
    "mutex",
    "regkey",
    "regkey|value",
    "windows-scheduled-task",
    "windows-service-name",
    "windows-service-displayname",
    // Metadata types (for Graph API parity)
    "malware-type",
    "port",
    "size-in-bytes",
];

impl MispAttribute {
    /// Check if this attribute type is actionable for threat intelligence
    pub fn is_actionable(&self) -> bool {
        self.to_ids && ACTIONABLE_TYPES.contains(&self.attr_type.as_str())
    }

    /// Get the observable type for STIX pattern generation
    pub fn get_observable_type(&self) -> Option<crate::stix::ObservableType> {
        use crate::stix::ObservableType;

        match self.attr_type.as_str() {
            "ip-src" | "ip-dst" => Some(ObservableType::IPv4Addr), // Simplified
            "domain" | "hostname" => Some(ObservableType::DomainName),
            "url" => Some(ObservableType::Url),
            "email-src" | "email-dst" => Some(ObservableType::EmailAddr),
            "md5" | "sha1" | "sha256" | "sha512" | "ssdeep" | "imphash" | "filename|md5"
            | "filename|sha1" | "filename|sha256" | "filename|sha512" | "filename|ssdeep"
            | "filename|imphash" => Some(ObservableType::File),
            "regkey" | "regkey|value" => Some(ObservableType::WindowsRegistryKey),
            _ => None,
        }
    }

    /// Extract hash type from attribute type
    pub fn get_hash_type(&self) -> Option<&str> {
        match self.attr_type.as_str() {
            // Common hashes
            "md5" | "filename|md5" => Some("MD5"),
            "sha1" | "filename|sha1" => Some("SHA-1"),
            "sha256" | "filename|sha256" => Some("SHA-256"),
            "sha512" | "filename|sha512" => Some("SHA-512"),
            "ssdeep" | "filename|ssdeep" => Some("SSDEEP"),
            "imphash" | "filename|imphash" => Some("IMPHASH"),
            "authentihash" | "filename|authentihash" => Some("AUTHENTIHASH"),
            "pehash" | "filename|pehash" => Some("PEHASH"),
            "vhash" | "filename|vhash" => Some("VHASH"),
            "tlsh" | "filename|tlsh" => Some("TLSH"),
            "cdhash" => Some("CDHASH"),
            "telfhash" => Some("TELFHASH"),
            "impfuzzy" | "filename|impfuzzy" => Some("IMPFUZZY"),
            // Extended SHA variants
            "sha224" | "filename|sha224" => Some("SHA-224"),
            "sha384" | "filename|sha384" => Some("SHA-384"),
            "sha512/224" | "filename|sha512/224" => Some("SHA-512/224"),
            "sha512/256" | "filename|sha512/256" => Some("SHA-512/256"),
            "sha3-224" | "filename|sha3-224" => Some("SHA3-224"),
            "sha3-256" | "filename|sha3-256" => Some("SHA3-256"),
            "sha3-384" | "filename|sha3-384" => Some("SHA3-384"),
            "sha3-512" | "filename|sha3-512" => Some("SHA3-512"),
            // X.509 fingerprints
            "x509-fingerprint-md5" => Some("MD5"),
            "x509-fingerprint-sha1" => Some("SHA-1"),
            "x509-fingerprint-sha256" => Some("SHA-256"),
            // JA3/JARM/HASSH fingerprints (treated as hash-like values)
            "ja3-fingerprint-md5" => Some("JA3"),
            "jarm-fingerprint" => Some("JARM"),
            "hassh-md5" => Some("HASSH"),
            "hasshserver-md5" => Some("HASSHSERVER"),
            _ => None,
        }
    }

    /// Extract the hash value from composite types
    pub fn get_hash_value(&self) -> &str {
        if self.attr_type.contains('|') {
            self.value.split('|').next_back().unwrap_or(&self.value)
        } else {
            &self.value
        }
    }
}

impl MispEvent {
    /// Get all actionable attributes from the event (including from objects)
    pub fn get_actionable_attributes(&self) -> Vec<&MispAttribute> {
        let mut attributes: Vec<&MispAttribute> = self
            .attributes
            .iter()
            .filter(|a| a.is_actionable())
            .collect();

        for obj in &self.objects {
            for attr in &obj.attributes {
                if attr.is_actionable() {
                    attributes.push(attr);
                }
            }
        }

        attributes
    }

    /// Extract TLP level from event tags
    pub fn get_tlp(&self) -> Option<&str> {
        for tag in &self.tags {
            let name_lower = tag.name.to_lowercase();
            if name_lower.starts_with("tlp:") {
                return Some(&tag.name);
            }
        }
        None
    }

    /// Extract threat type from sentinel-threattype tag
    pub fn get_threat_type(&self) -> Option<String> {
        for tag in &self.tags {
            if tag.name.to_lowercase().starts_with("sentinel-threattype:") {
                return tag.name.split(':').nth(1).map(|s| s.to_string());
            }
        }
        None
    }

    /// Get filtered labels (excluding internal MISP tags)
    pub fn get_labels(&self, ignore_local: bool) -> Vec<String> {
        self.tags
            .iter()
            .filter(|tag| {
                // Skip local tags if configured
                if ignore_local && tag.local == Some(1) {
                    return false;
                }

                // Skip internal MISP tags
                let name = &tag.name;
                !name.starts_with("misp-galaxy:")
                    && !name.starts_with("misp:")
                    && !name.contains("Threat-Report")
                    && !name.starts_with("tlp:")
                    && !name.starts_with("sentinel-")
            })
            .map(|tag| tag.name.clone())
            .collect()
    }
}
