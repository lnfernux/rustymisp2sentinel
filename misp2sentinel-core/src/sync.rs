//! Synchronization logic between MISP and Sentinel
//!
//! This module orchestrates the fetching of events from MISP,
//! conversion to STIX format, and upload to Microsoft Sentinel.
//!
//! Optimized for high throughput with:
//! - Parallel event-to-STIX conversion using Rayon
//! - Concurrent Sentinel batch uploads
//! - Efficient deduplication

use chrono::{Duration, Utc};
use rayon::prelude::*;
use serde::Serialize;
use std::collections::HashSet;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Arc;
use std::time::Instant;
use tracing::{debug, info, warn};

use crate::config::Config;
use crate::error::{Error, Result};
use crate::misp::{MispAttribute, MispClient, MispEvent};
use crate::progress::ProgressTracker;
use crate::sentinel::{SentinelClient, UploadStats};
use crate::stix::{
    create_file_hash_pattern, create_pattern, escape_pattern_value, tlp, ExternalReference,
    ObservableType, StixIndicator,
};

/// Main synchronization orchestrator
pub struct Syncer {
    config: Config,
    misp_client: MispClient,
    sentinel_client: Option<SentinelClient>,
    progress: ProgressTracker,
}

impl Syncer {
    /// Create a new syncer with the given configuration
    pub fn new(config: Config) -> Result<Self> {
        Self::with_progress(config, true)
    }

    /// Create a new syncer with optional progress tracking
    pub fn with_progress(config: Config, show_progress: bool) -> Result<Self> {
        let misp_client = MispClient::new(&config.misp)?;

        let sentinel_client = if config.sync.dry_run {
            None
        } else {
            Some(SentinelClient::new(config.sentinel.clone())?)
        };

        Ok(Self {
            config,
            misp_client,
            sentinel_client,
            progress: ProgressTracker::new(show_progress),
        })
    }

    /// Run the synchronization process
    pub async fn run(&mut self) -> Result<SyncResult> {
        let total_start = Instant::now();
        info!("Starting MISP to Sentinel synchronization");

        // Phase 1: Fetch events from MISP (with concurrent page fetching)
        let fetch_spinner = self.progress.create_spinner("Fetching events from MISP...");
        let fetch_start = Instant::now();
        let events = self
            .misp_client
            .fetch_events_concurrent(&self.config.misp, self.config.sync.concurrent_page_fetches)
            .await?;
        let fetch_duration = fetch_start.elapsed();
        fetch_spinner.finish_and_clear();

        self.progress.println(&format!(
            "✓ Fetched {} events from MISP in {:.2}s",
            events.len(),
            fetch_duration.as_secs_f64()
        ));
        info!(
            "Fetched {} events from MISP in {:.2}s",
            events.len(),
            fetch_duration.as_secs_f64()
        );

        // Phase 2: Convert to STIX indicators (parallel or sequential based on config)
        let convert_pb = self
            .progress
            .create_conversion_progress(events.len() as u64);
        let convert_start = Instant::now();
        let indicators = if self.config.sync.parallel_conversion {
            self.convert_events_to_indicators_parallel_with_progress(&events, &convert_pb)?
        } else {
            self.convert_events_to_indicators(&events)?
        };
        let convert_duration = convert_start.elapsed();
        convert_pb.finish_and_clear();

        let conversion_rate = indicators.len() as f64 / convert_duration.as_secs_f64().max(0.001);
        self.progress.println(&format!(
            "✓ Converted to {} STIX indicators in {:.2}s ({:.0} ind/sec)",
            indicators.len(),
            convert_duration.as_secs_f64(),
            conversion_rate
        ));
        info!(
            "Converted to {} STIX indicators in {:.2}s ({:.0} indicators/sec)",
            indicators.len(),
            convert_duration.as_secs_f64(),
            conversion_rate
        );

        if self.config.sync.dry_run {
            let total_duration = total_start.elapsed();
            info!(
                "Dry run mode - skipping upload. Total time: {:.2}s",
                total_duration.as_secs_f64()
            );
            self.progress.print_dry_run_summary(
                events.len(),
                indicators.len(),
                total_duration.as_secs_f64(),
            );

            // Print estimated upload time
            let num_batches =
                (indicators.len() as f64 / self.config.sync.batch_size as f64).ceil() as usize;
            let seconds_per_batch = 60.0 / self.config.sync.requests_per_minute as f64;
            let estimated_seconds =
                num_batches as f64 * seconds_per_batch / self.config.sync.concurrent_uploads as f64;
            let estimated_msg = format!(
                "  → Estimated upload time: {:.0}s ({} batches @ {:.2}s each, {} concurrent)",
                estimated_seconds,
                num_batches,
                seconds_per_batch,
                self.config.sync.concurrent_uploads
            );
            self.progress.println(&estimated_msg);
            info!("{}", estimated_msg);

            return Ok(SyncResult {
                events_processed: events.len(),
                indicators_created: indicators.len(),
                upload_stats: None,
            });
        }

        // Phase 3: Upload to Sentinel (with concurrent batch uploads)
        let sentinel_client = self
            .sentinel_client
            .as_mut()
            .ok_or_else(|| Error::Config("Sentinel client not initialized".into()))?;

        // Calculate and show estimated time
        let num_batches =
            (indicators.len() as f64 / self.config.sync.batch_size as f64).ceil() as usize;
        let estimated_seconds = num_batches as f64
            * (60.0 / self.config.sync.requests_per_minute as f64)
            / self.config.sync.concurrent_uploads as f64;
        self.progress.println(&format!(
            "→ Starting upload: {} indicators in {} batches (~{:.0}s estimated)",
            indicators.len(),
            num_batches,
            estimated_seconds
        ));

        let upload_pb = self
            .progress
            .create_upload_progress(indicators.len() as u64);
        let batch_pb = self.progress.create_batch_progress(
            (indicators.len() as f64 / self.config.sync.batch_size as f64).ceil() as u64,
        );

        let upload_start = Instant::now();
        let upload_stats = sentinel_client
            .upload_indicators_concurrent_with_progress(
                indicators,
                self.config.sync.batch_size,
                self.config.sync.requests_per_minute,
                self.config.sync.concurrent_uploads,
                upload_pb.clone(),
                batch_pb.clone(),
            )
            .await?;
        let upload_duration = upload_start.elapsed();
        upload_pb.finish_and_clear();
        batch_pb.finish_and_clear();

        let total_duration = total_start.elapsed();
        info!(
            "Upload completed in {:.2}s. Total sync time: {:.2}s",
            upload_duration.as_secs_f64(),
            total_duration.as_secs_f64()
        );

        self.progress.print_summary(
            events.len(),
            upload_stats.total_indicators,
            upload_stats.successful,
            upload_stats.failed,
            total_duration.as_secs_f64(),
        );

        Ok(SyncResult {
            events_processed: events.len(),
            indicators_created: upload_stats.total_indicators,
            upload_stats: Some(upload_stats),
        })
    }

    /// Convert MISP events to STIX indicators (sequential)
    fn convert_events_to_indicators(&self, events: &[MispEvent]) -> Result<Vec<StixIndicator>> {
        let mut indicators = Vec::new();
        let mut seen_patterns: HashSet<String> = HashSet::new();

        for event in events {
            let event_indicators = self.convert_event(event, &mut seen_patterns)?;
            indicators.extend(event_indicators);
        }

        Ok(indicators)
    }

    /// Convert MISP events to STIX indicators with progress tracking
    fn convert_events_to_indicators_parallel_with_progress(
        &self,
        events: &[MispEvent],
        progress: &indicatif::ProgressBar,
    ) -> Result<Vec<StixIndicator>> {
        let counter = Arc::new(AtomicUsize::new(0));
        let total = events.len();

        // Process events in parallel and collect indicators
        let all_indicators: Vec<Vec<StixIndicator>> = events
            .par_iter()
            .filter_map(|event| {
                // Each thread converts its events
                let indicators = self.convert_event_for_parallel(event);

                // Update progress
                let count = counter.fetch_add(1, Ordering::Relaxed) + 1;
                progress.set_position(count as u64);

                match indicators {
                    Ok(ind) if !ind.is_empty() => Some(ind),
                    Ok(_) => None,
                    Err(e) => {
                        warn!("Error converting event {}: {}", event.uuid, e);
                        None
                    }
                }
            })
            .collect();

        progress.set_position(total as u64);

        // Flatten and deduplicate (patterns may overlap between events)
        let mut final_indicators = Vec::with_capacity(all_indicators.iter().map(|v| v.len()).sum());
        let mut final_patterns: HashSet<String> = HashSet::new();

        for indicators in all_indicators {
            for indicator in indicators {
                if !final_patterns.contains(&indicator.pattern) {
                    final_patterns.insert(indicator.pattern.clone());
                    final_indicators.push(indicator);
                }
            }
        }

        Ok(final_indicators)
    }

    /// Convert a single event for parallel processing (no shared mutable state)
    fn convert_event_for_parallel(&self, event: &MispEvent) -> Result<Vec<StixIndicator>> {
        let mut indicators = Vec::new();
        let mut local_patterns: HashSet<String> = HashSet::new();

        // Get event-level metadata
        let event_tlp = event
            .get_tlp()
            .and_then(tlp::from_tag)
            .unwrap_or(tlp::WHITE);
        let event_threat_type = event.get_threat_type();
        let event_labels = event.get_labels(true);

        // Process all actionable attributes
        for attr in event.get_actionable_attributes() {
            if !self.should_include_type(&attr.attr_type) {
                continue;
            }

            let pattern = match self.create_pattern_for_attribute(attr) {
                Some(p) => p,
                None => continue,
            };

            // Local deduplication within event
            if local_patterns.contains(&pattern) {
                continue;
            }
            local_patterns.insert(pattern.clone());

            let indicator = self.create_indicator(
                event,
                attr,
                pattern,
                event_tlp,
                &event_threat_type,
                &event_labels,
            )?;

            if self.validate_indicator(&indicator).is_ok() {
                indicators.push(indicator);
            }
        }

        Ok(indicators)
    }

    /// Convert a single MISP event to STIX indicators
    fn convert_event(
        &self,
        event: &MispEvent,
        seen_patterns: &mut HashSet<String>,
    ) -> Result<Vec<StixIndicator>> {
        let mut indicators = Vec::new();

        // Get event-level metadata
        let event_tlp = event
            .get_tlp()
            .and_then(tlp::from_tag)
            .unwrap_or(tlp::WHITE);
        let event_threat_type = event.get_threat_type();
        let event_labels = event.get_labels(true); // Ignore local tags

        // Process all actionable attributes
        for attr in event.get_actionable_attributes() {
            // Apply include/exclude filters
            if !self.should_include_type(&attr.attr_type) {
                continue;
            }

            // Create STIX pattern
            let pattern = match self.create_pattern_for_attribute(attr) {
                Some(p) => p,
                None => {
                    debug!("Skipping unsupported attribute type: {}", attr.attr_type);
                    continue;
                }
            };

            // Deduplicate by pattern
            if seen_patterns.contains(&pattern) {
                debug!("Skipping duplicate pattern: {}", pattern);
                continue;
            }
            seen_patterns.insert(pattern.clone());

            // Create the indicator
            let indicator = self.create_indicator(
                event,
                attr,
                pattern,
                event_tlp,
                &event_threat_type,
                &event_labels,
            )?;

            // Validate the indicator
            if let Err(e) = self.validate_indicator(&indicator) {
                warn!("Skipping invalid indicator: {}", e);
                continue;
            }

            indicators.push(indicator);
        }

        Ok(indicators)
    }

    /// Create a STIX pattern for a MISP attribute
    fn create_pattern_for_attribute(&self, attr: &MispAttribute) -> Option<String> {
        match attr.attr_type.as_str() {
            // Network indicators - IP addresses
            "ip-src" | "ip-dst" => {
                if attr.value.contains(':') {
                    Some(create_pattern(ObservableType::IPv6Addr, &attr.value))
                } else {
                    Some(create_pattern(ObservableType::IPv4Addr, &attr.value))
                }
            }
            "ip-src|port" | "ip-dst|port" => {
                let ip = attr.value.split('|').next()?;
                if ip.contains(':') {
                    Some(create_pattern(ObservableType::IPv6Addr, ip))
                } else {
                    Some(create_pattern(ObservableType::IPv4Addr, ip))
                }
            }

            // Domain and hostname
            "domain" | "hostname" => {
                Some(create_pattern(ObservableType::DomainName, &attr.value))
            }
            "domain|ip" => {
                let domain = attr.value.split('|').next()?;
                Some(create_pattern(ObservableType::DomainName, domain))
            }
            "hostname|port" => {
                let hostname = attr.value.split('|').next()?;
                Some(create_pattern(ObservableType::DomainName, hostname))
            }

            // URL
            "url" => {
                Some(create_pattern(ObservableType::Url, &attr.value))
            }
            "uri" => {
                // URI is essentially a URL
                Some(create_pattern(ObservableType::Url, &attr.value))
            }

            // Autonomous System Number
            "AS" => {
                // STIX pattern for autonomous-system
                Some(format!("[autonomous-system:number = {}]", attr.value.trim_start_matches("AS")))
            }

            // MAC addresses
            "mac-address" | "mac-eui-64" => {
                // STIX pattern for mac-addr
                Some(format!("[mac-addr:value = '{}']", escape_pattern_value(&attr.value)))
            }

            // Email indicators
            "email-src" | "email-dst" => {
                Some(create_pattern(ObservableType::EmailAddr, &attr.value))
            }
            "email-subject" => {
                Some(format!("[email-message:subject = '{}']", escape_pattern_value(&attr.value)))
            }
            "email-body" => {
                Some(format!("[email-message:body = '{}']", escape_pattern_value(&attr.value)))
            }
            "email-header" => {
                Some(format!("[email-message:raw_email = '{}']", escape_pattern_value(&attr.value)))
            }
            "email-reply-to" => {
                Some(format!("[email-message:additional_header_fields.Reply-To = '{}']", escape_pattern_value(&attr.value)))
            }
            "email-x-mailer" => {
                Some(format!("[email-message:additional_header_fields.X-Mailer = '{}']", escape_pattern_value(&attr.value)))
            }
            "email-message-id" => {
                Some(format!("[email-message:message_id = '{}']", escape_pattern_value(&attr.value)))
            }
            "email-mime-boundary" => {
                Some(format!("[email-message:additional_header_fields.MIME-Boundary = '{}']", escape_pattern_value(&attr.value)))
            }
            "email-thread-index" => {
                Some(format!("[email-message:additional_header_fields.Thread-Index = '{}']", escape_pattern_value(&attr.value)))
            }

            // File name
            "filename" => {
                Some(format!("[file:name = '{}']", escape_pattern_value(&attr.value)))
            }

            // User agent
            "user-agent" => {
                Some(format!("[network-traffic:extensions.'http-request-ext'.request_header.'User-Agent' = '{}']", escape_pattern_value(&attr.value)))
            }

            // JA3/JARM/HASSH fingerprints (network traffic extensions)
            "ja3-fingerprint-md5" => {
                Some(format!("[network-traffic:extensions.'ja3-ext'.ja3_hash = '{}']", escape_pattern_value(&attr.value)))
            }
            "jarm-fingerprint" => {
                Some(format!("[network-traffic:extensions.'jarm-ext'.jarm_hash = '{}']", escape_pattern_value(&attr.value)))
            }
            "hassh-md5" => {
                Some(format!("[network-traffic:extensions.'ssh-ext'.hassh = '{}']", escape_pattern_value(&attr.value)))
            }
            "hasshserver-md5" => {
                Some(format!("[network-traffic:extensions.'ssh-ext'.hassh_server = '{}']", escape_pattern_value(&attr.value)))
            }
            "community-id" => {
                // Community ID is a flow hash
                Some(format!("[network-traffic:extensions.'community-id-ext'.community_id = '{}']", escape_pattern_value(&attr.value)))
            }

            // Mutex
            "mutex" => {
                Some(format!("[mutex:name = '{}']", escape_pattern_value(&attr.value)))
            }

            // X.509 certificate fingerprints - convert to x509-certificate STIX object
            "x509-fingerprint-md5" => {
                Some(format!("[x509-certificate:hashes.MD5 = '{}']", escape_pattern_value(&attr.value)))
            }
            "x509-fingerprint-sha1" => {
                Some(format!("[x509-certificate:hashes.'SHA-1' = '{}']", escape_pattern_value(&attr.value)))
            }
            "x509-fingerprint-sha256" => {
                Some(format!("[x509-certificate:hashes.'SHA-256' = '{}']", escape_pattern_value(&attr.value)))
            }

            // Windows-specific indicators
            "windows-scheduled-task" => {
                Some(format!("[process:extensions.'windows-process-ext'.scheduled_task = '{}']", escape_pattern_value(&attr.value)))
            }
            "windows-service-name" => {
                Some(format!("[process:extensions.'windows-service-ext'.service_name = '{}']", escape_pattern_value(&attr.value)))
            }
            "windows-service-displayname" => {
                Some(format!("[process:extensions.'windows-service-ext'.display_name = '{}']", escape_pattern_value(&attr.value)))
            }

            // File hashes (all hash types handled by get_hash_type)
            _ if attr.get_hash_type().is_some() => {
                let hash_type = attr.get_hash_type()?;
                let hash_value = attr.get_hash_value();
                Some(create_file_hash_pattern(hash_type, hash_value))
            }

            // Registry keys
            "regkey" => {
                Some(create_pattern(ObservableType::WindowsRegistryKey, &attr.value))
            }
            "regkey|value" => {
                let key = attr.value.split('|').next()?;
                Some(create_pattern(ObservableType::WindowsRegistryKey, key))
            }

            _ => None,
        }
    }

    /// Create a STIX indicator from MISP attribute
    fn create_indicator(
        &self,
        event: &MispEvent,
        attr: &MispAttribute,
        pattern: String,
        tlp: &str,
        threat_type: &Option<String>,
        event_labels: &[String],
    ) -> Result<StixIndicator> {
        let now = Utc::now();

        // Determine valid_from from attribute or event timestamp
        let valid_from = attr
            .first_seen
            .as_ref()
            .and_then(|s| chrono::DateTime::parse_from_rfc3339(s).ok())
            .map(|dt| dt.with_timezone(&Utc))
            .unwrap_or(now);

        // Determine valid_until based on type-specific expiration
        let days_to_expire = self.get_expiration_days(attr);
        let valid_until = now + Duration::days(days_to_expire as i64);

        // Build indicator with deterministic ID based on MISP attribute UUID
        // This ensures the same attribute always produces the same STIX indicator ID,
        // enabling proper deduplication in Sentinel (updates instead of duplicates)
        let mut indicator = StixIndicator::new_with_deterministic_id(
            &attr.uuid,
            pattern,
            "stix".to_string(),
            valid_from,
        )
        .with_valid_until(valid_until)
        .with_confidence(self.config.sync.default_confidence)
        .with_tlp(tlp);

        // Set name and description
        indicator.name = Some(format!("{} - {}", event.info, attr.attr_type));
        indicator.description = Some(format!(
            "MISP Event: {} (UUID: {}). Attribute type: {}",
            event.info, event.uuid, attr.attr_type
        ));

        // Add indicator types
        if let Some(ref tt) = threat_type {
            indicator.indicator_types.push(tt.clone());
        } else {
            indicator.indicator_types.push("unknown".to_string());
        }

        // Add labels from event and attribute
        let mut labels = event_labels.to_vec();
        for tag in &attr.tags {
            if !labels.contains(&tag.name) {
                labels.push(tag.name.clone());
            }
        }
        indicator.labels = labels;

        // Add external reference to MISP
        indicator.external_references.push(ExternalReference {
            source_name: "MISP".to_string(),
            description: Some(format!("MISP Event: {}", event.info)),
            url: Some(format!(
                "{}/events/view/{}",
                self.config.misp.url, event.uuid
            )),
            external_id: Some(event.uuid.clone()),
            hashes: Default::default(),
        });

        Ok(indicator)
    }

    /// Get expiration days for an attribute type
    fn get_expiration_days(&self, attr: &MispAttribute) -> u32 {
        // Check type-specific expiration
        if let Some(observable_type) = attr.get_observable_type() {
            if let Some(&days) = self
                .config
                .sync
                .type_expiration
                .get(observable_type.type_name())
            {
                return days;
            }
        }

        // Default expiration
        self.config.sync.days_to_expire
    }

    /// Check if an attribute type should be included
    fn should_include_type(&self, attr_type: &str) -> bool {
        // If include list is specified, only include those
        if !self.config.sync.include_types.is_empty() {
            return self
                .config
                .sync
                .include_types
                .iter()
                .any(|t| t == attr_type);
        }

        // Otherwise, exclude from exclude list
        !self
            .config
            .sync
            .exclude_types
            .iter()
            .any(|t| t == attr_type)
    }

    /// Validate an indicator before upload
    fn validate_indicator(&self, indicator: &StixIndicator) -> Result<()> {
        // Check required fields
        if indicator.pattern.is_empty() {
            return Err(Error::StixConversion("Pattern is empty".into()));
        }

        if indicator.pattern_type.is_empty() {
            return Err(Error::StixConversion("Pattern type is empty".into()));
        }

        // Check valid_until is in the future
        if let Some(valid_until) = indicator.valid_until {
            if valid_until <= Utc::now() {
                return Err(Error::StixConversion(format!(
                    "Indicator expired: valid_until {} is in the past",
                    valid_until
                )));
            }
        }

        Ok(())
    }
}

/// Result of a synchronization run
#[derive(Debug, Serialize)]
pub struct SyncResult {
    pub events_processed: usize,
    pub indicators_created: usize,
    pub upload_stats: Option<UploadStats>,
}

impl SyncResult {
    /// Check if the sync was successful
    pub fn is_success(&self) -> bool {
        match &self.upload_stats {
            Some(stats) => stats.failed == 0,
            None => true, // Dry run is always "successful"
        }
    }

    /// Get a summary string
    pub fn summary(&self) -> String {
        match &self.upload_stats {
            Some(stats) => {
                format!(
                    "Processed {} events, created {} indicators. Upload: {} successful, {} failed ({} requests)",
                    self.events_processed,
                    self.indicators_created,
                    stats.successful,
                    stats.failed,
                    stats.requests_made
                )
            }
            None => {
                format!(
                    "Dry run: processed {} events, created {} indicators (not uploaded)",
                    self.events_processed, self.indicators_created
                )
            }
        }
    }
}
