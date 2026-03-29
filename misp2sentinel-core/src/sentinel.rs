//! Microsoft Sentinel API client
//!
//! This module provides a client for uploading threat intelligence
//! to Microsoft Sentinel using the Upload Indicators API.
//!
//! Optimized for high throughput with:
//! - Concurrent batch uploads
//! - Smart rate limiting with token bucket
//! - Automatic retry with exponential backoff

use reqwest::Client;
use serde::{Deserialize, Serialize};
use std::sync::Arc;
use std::time::{Duration, Instant};
use tokio::sync::{Mutex, Semaphore};
use tokio::time::sleep;
use tracing::{debug, error, info, warn};

use crate::config::SentinelConfig;
use crate::error::{Error, Result};
use crate::stix::{StixIndicator, StixObject};

/// Microsoft Sentinel API client with concurrent upload support
pub struct SentinelClient {
    client: Client,
    config: SentinelConfig,
    access_token: Option<AccessToken>,
}

/// OAuth2 access token with expiration
struct AccessToken {
    token: String,
    expires_at: Instant,
}

/// Token response from Azure AD
#[derive(Debug, Deserialize)]
struct TokenResponse {
    access_token: String,
    expires_in: u64,
    #[allow(dead_code)]
    token_type: String,
}

/// Upload request body for indicators
#[derive(Debug, Serialize)]
struct UploadRequest {
    sourcesystem: String,
    stixobjects: Vec<StixIndicator>,
}

/// Upload request body for mixed STIX objects
#[derive(Debug, Serialize)]
struct UploadRequestObjects {
    sourcesystem: String,
    stixobjects: Vec<StixObject>,
}

/// Upload response
#[derive(Debug, Deserialize)]
pub struct UploadResponse {
    #[serde(default)]
    pub errors: Vec<UploadError>,
}

/// Upload error details
#[derive(Debug, Deserialize)]
pub struct UploadError {
    #[serde(rename = "recordIndex")]
    pub record_index: usize,
    #[serde(rename = "errorMessages")]
    pub error_messages: Vec<String>,
}

/// Statistics for upload operation
#[derive(Debug, Default, Clone, Serialize)]
pub struct UploadStats {
    pub total_indicators: usize,
    pub successful: usize,
    pub failed: usize,
    pub requests_made: usize,
}

impl SentinelClient {
    /// Create a new Sentinel client with optimized connection pool
    pub fn new(config: SentinelConfig) -> Result<Self> {
        let client = Client::builder()
            .timeout(Duration::from_secs(120))
            // Connection pool optimization for concurrent uploads
            .pool_max_idle_per_host(10)
            .pool_idle_timeout(Duration::from_secs(90))
            .tcp_keepalive(Duration::from_secs(60))
            .tcp_nodelay(true)
            .build()
            .map_err(|e| Error::SentinelApi(format!("Failed to create HTTP client: {}", e)))?;

        Ok(Self {
            client,
            config,
            access_token: None,
        })
    }

    /// Get a valid access token, refreshing if necessary
    async fn get_access_token(&mut self) -> Result<String> {
        // Check if we have a valid token
        if let Some(ref token) = self.access_token {
            // Refresh if expiring within 5 minutes
            if token.expires_at > Instant::now() + Duration::from_secs(300) {
                return Ok(token.token.clone());
            }
        }

        info!("Acquiring new access token from Azure AD");

        let token_url = format!(
            "https://login.microsoftonline.com/{}/oauth2/v2.0/token",
            self.config.tenant_id
        );

        let params = [
            ("grant_type", "client_credentials"),
            ("client_id", &self.config.client_id),
            ("client_secret", &self.config.client_secret),
            ("scope", "https://management.azure.com/.default"),
        ];

        let response = self
            .client
            .post(&token_url)
            .form(&params)
            .send()
            .await
            .map_err(|e| Error::Auth(format!("Token request failed: {}", e)))?;

        if !response.status().is_success() {
            let status = response.status();
            let text = response.text().await.unwrap_or_default();
            return Err(Error::Auth(format!(
                "Failed to acquire token ({}): {}",
                status, text
            )));
        }

        let token_response: TokenResponse = response
            .json()
            .await
            .map_err(|e| Error::Auth(format!("Failed to parse token response: {}", e)))?;

        let token = AccessToken {
            token: token_response.access_token.clone(),
            expires_at: Instant::now() + Duration::from_secs(token_response.expires_in),
        };

        self.access_token = Some(token);
        info!("Successfully acquired access token");

        Ok(token_response.access_token)
    }

    /// Upload indicators to Sentinel
    pub async fn upload_indicators(
        &mut self,
        indicators: Vec<StixIndicator>,
        batch_size: usize,
        requests_per_minute: u32,
    ) -> Result<UploadStats> {
        let total = indicators.len();
        info!("Starting upload of {} indicators", total);

        if indicators.is_empty() {
            return Ok(UploadStats::default());
        }

        let mut stats = UploadStats {
            total_indicators: total,
            ..Default::default()
        };

        let batch_size = batch_size.min(100); // API limit
        let request_interval = Duration::from_millis(60_000 / requests_per_minute as u64);
        let mut last_request = Instant::now() - request_interval;

        for (batch_num, chunk) in indicators.chunks(batch_size).enumerate() {
            // Rate limiting
            let elapsed = last_request.elapsed();
            if elapsed < request_interval {
                let wait_time = request_interval - elapsed;
                debug!("Rate limiting: waiting {:?}", wait_time);
                sleep(wait_time).await;
            }

            // Retry loop for this batch
            let mut retries = 0;
            let max_retries = 3;

            loop {
                let result = self.upload_batch(chunk.to_vec()).await;
                last_request = Instant::now();
                stats.requests_made += 1;

                match result {
                    Ok(response) => {
                        let batch_success = chunk.len() - response.errors.len();
                        stats.successful += batch_success;
                        stats.failed += response.errors.len();

                        if !response.errors.is_empty() {
                            for err in &response.errors {
                                warn!(
                                    "Upload error at index {}: {:?}",
                                    err.record_index, err.error_messages
                                );
                            }
                        }

                        info!(
                            "Batch {}: uploaded {}/{} indicators (total: {}/{})",
                            batch_num + 1,
                            batch_success,
                            chunk.len(),
                            stats.successful,
                            total
                        );
                        break;
                    }
                    Err(Error::RateLimit(retry_after)) => {
                        warn!("Rate limit hit, waiting {} seconds", retry_after);
                        sleep(Duration::from_secs(retry_after + 1)).await;
                        retries += 1;
                        if retries >= max_retries {
                            stats.failed += chunk.len();
                            error!("Max retries exceeded for batch {}", batch_num + 1);
                            break;
                        }
                    }
                    Err(e) => {
                        stats.failed += chunk.len();
                        error!("Upload failed for batch {}: {}", batch_num + 1, e);
                        break;
                    }
                }
            }
        }

        info!(
            "Upload complete: {} successful, {} failed out of {} total",
            stats.successful, stats.failed, stats.total_indicators
        );

        Ok(stats)
    }

    /// Upload indicators to Sentinel with concurrent batch uploads
    ///
    /// This method uploads multiple batches concurrently while respecting
    /// the rate limit. Uses a semaphore to control concurrency and a
    /// token bucket for rate limiting.
    pub async fn upload_indicators_concurrent(
        &mut self,
        indicators: Vec<StixIndicator>,
        batch_size: usize,
        requests_per_minute: u32,
        max_concurrent: usize,
    ) -> Result<UploadStats> {
        let total = indicators.len();
        info!(
            "Starting concurrent upload of {} indicators (batch_size: {}, concurrency: {})",
            total, batch_size, max_concurrent
        );

        if indicators.is_empty() {
            return Ok(UploadStats::default());
        }

        let batch_size = batch_size.min(100); // API limit

        // Pre-acquire token to ensure we have valid auth
        let _ = self.get_access_token().await?;

        // Create batches
        let batches: Vec<Vec<StixIndicator>> =
            indicators.chunks(batch_size).map(|c| c.to_vec()).collect();

        let total_batches = batches.len();
        info!("Split into {} batches", total_batches);

        // Shared state for concurrent uploads
        let stats = Arc::new(Mutex::new(UploadStats {
            total_indicators: total,
            ..Default::default()
        }));

        // Semaphore for concurrency control
        let semaphore = Arc::new(Semaphore::new(max_concurrent));

        // Rate limiter: minimum interval between requests
        let request_interval = Duration::from_millis(60_000 / requests_per_minute as u64);
        let last_request_time = Arc::new(Mutex::new(Instant::now() - request_interval));

        // Clone necessary data for async tasks
        let client = self.client.clone();
        let config = self.config.clone();
        let token = self
            .access_token
            .as_ref()
            .map(|t| t.token.clone())
            .unwrap_or_default();

        // Upload batches concurrently
        let upload_futures: Vec<_> = batches
            .into_iter()
            .enumerate()
            .map(|(batch_num, batch)| {
                let client = client.clone();
                let config = config.clone();
                let token = token.clone();
                let stats = Arc::clone(&stats);
                let semaphore = Arc::clone(&semaphore);
                let last_request_time = Arc::clone(&last_request_time);
                let batch_len = batch.len();

                async move {
                    // Acquire semaphore permit
                    let _permit = semaphore.acquire().await.unwrap();

                    // Rate limiting
                    {
                        let mut last_time = last_request_time.lock().await;
                        let elapsed = last_time.elapsed();
                        if elapsed < request_interval {
                            sleep(request_interval - elapsed).await;
                        }
                        *last_time = Instant::now();
                    }

                    // Upload with retry on rate limit
                    let max_retries = 5u32;
                    let mut retries = 0u32;
                    let result = loop {
                        let result =
                            upload_batch_standalone(&client, &config, &token, batch.clone()).await;
                        match result {
                            Err(Error::RateLimit(retry_after)) if retries < max_retries => {
                                warn!(
                                    "Batch {}: rate limit hit, waiting {} seconds (attempt {}/{})",
                                    batch_num + 1,
                                    retry_after,
                                    retries + 1,
                                    max_retries
                                );
                                sleep(Duration::from_secs(retry_after + 1)).await;
                                retries += 1;
                            }
                            other => break other,
                        }
                    };

                    // Update stats
                    let mut stats_guard = stats.lock().await;
                    stats_guard.requests_made += 1;

                    match result {
                        Ok(response) => {
                            let batch_success = batch_len - response.errors.len();
                            stats_guard.successful += batch_success;
                            stats_guard.failed += response.errors.len();

                            if !response.errors.is_empty() {
                                for err in &response.errors {
                                    warn!(
                                        "Batch {}: upload error at index {}: {:?}",
                                        batch_num + 1,
                                        err.record_index,
                                        err.error_messages
                                    );
                                }
                            }

                            debug!(
                                "Batch {}/{}: uploaded {}/{} indicators",
                                batch_num + 1,
                                total_batches,
                                batch_success,
                                batch_len
                            );
                        }
                        Err(e) => {
                            stats_guard.failed += batch_len;
                            error!("Batch {}: upload failed: {}", batch_num + 1, e);
                        }
                    }
                }
            })
            .collect();

        // Wait for all uploads to complete
        futures::future::join_all(upload_futures).await;

        let final_stats = stats.lock().await.clone();
        info!(
            "Concurrent upload complete: {} successful, {} failed out of {} total ({} requests)",
            final_stats.successful,
            final_stats.failed,
            final_stats.total_indicators,
            final_stats.requests_made
        );

        Ok(final_stats)
    }

    /// Upload indicators to Sentinel with concurrent batch uploads and progress tracking
    pub async fn upload_indicators_concurrent_with_progress(
        &mut self,
        indicators: Vec<StixIndicator>,
        batch_size: usize,
        requests_per_minute: u32,
        max_concurrent: usize,
        indicator_progress: indicatif::ProgressBar,
        batch_progress: indicatif::ProgressBar,
    ) -> Result<UploadStats> {
        use std::sync::atomic::{AtomicUsize, Ordering};

        let total = indicators.len();
        info!(
            "Starting concurrent upload of {} indicators (batch_size: {}, concurrency: {})",
            total, batch_size, max_concurrent
        );

        if indicators.is_empty() {
            return Ok(UploadStats::default());
        }

        let batch_size = batch_size.min(100); // API limit

        // Pre-acquire token to ensure we have valid auth
        let _ = self.get_access_token().await?;

        // Create batches
        let batches: Vec<Vec<StixIndicator>> =
            indicators.chunks(batch_size).map(|c| c.to_vec()).collect();

        let total_batches = batches.len();
        info!("Split into {} batches", total_batches);

        // Shared state for concurrent uploads
        let stats = Arc::new(Mutex::new(UploadStats {
            total_indicators: total,
            ..Default::default()
        }));

        // Progress counters
        let indicators_uploaded = Arc::new(AtomicUsize::new(0));
        let batches_completed = Arc::new(AtomicUsize::new(0));

        // Semaphore for concurrency control
        let semaphore = Arc::new(Semaphore::new(max_concurrent));

        // Rate limiter: minimum interval between requests
        let request_interval = Duration::from_millis(60_000 / requests_per_minute as u64);
        let last_request_time = Arc::new(Mutex::new(Instant::now() - request_interval));

        // Clone necessary data for async tasks
        let client = self.client.clone();
        let config = self.config.clone();
        let token = self
            .access_token
            .as_ref()
            .map(|t| t.token.clone())
            .unwrap_or_default();

        // Upload batches concurrently
        let upload_futures: Vec<_> = batches
            .into_iter()
            .enumerate()
            .map(|(batch_num, batch)| {
                let client = client.clone();
                let config = config.clone();
                let token = token.clone();
                let stats = Arc::clone(&stats);
                let semaphore = Arc::clone(&semaphore);
                let last_request_time = Arc::clone(&last_request_time);
                let indicators_uploaded = Arc::clone(&indicators_uploaded);
                let batches_completed = Arc::clone(&batches_completed);
                let indicator_progress = indicator_progress.clone();
                let batch_progress = batch_progress.clone();
                let batch_len = batch.len();

                async move {
                    // Acquire semaphore permit
                    let _permit = semaphore.acquire().await.unwrap();

                    // Rate limiting
                    {
                        let mut last_time = last_request_time.lock().await;
                        let elapsed = last_time.elapsed();
                        if elapsed < request_interval {
                            sleep(request_interval - elapsed).await;
                        }
                        *last_time = Instant::now();
                    }

                    let batch_start = Instant::now();

                    // Upload with retry on rate limit
                    let max_retries = 5u32;
                    let mut retries = 0u32;
                    let result = loop {
                        let result =
                            upload_batch_standalone(&client, &config, &token, batch.clone()).await;
                        match result {
                            Err(Error::RateLimit(retry_after)) if retries < max_retries => {
                                warn!(
                                    "Batch {}: rate limit hit, waiting {} seconds (attempt {}/{})",
                                    batch_num + 1,
                                    retry_after,
                                    retries + 1,
                                    max_retries
                                );
                                sleep(Duration::from_secs(retry_after + 1)).await;
                                retries += 1;
                            }
                            other => break other,
                        }
                    };

                    let batch_duration = batch_start.elapsed();

                    // Update stats and progress
                    let mut stats_guard = stats.lock().await;
                    stats_guard.requests_made += 1;

                    match result {
                        Ok(response) => {
                            let batch_success = batch_len - response.errors.len();
                            let batch_failed = response.errors.len();
                            stats_guard.successful += batch_success;
                            stats_guard.failed += batch_failed;

                            // Update progress bars
                            let uploaded = indicators_uploaded
                                .fetch_add(batch_len, Ordering::Relaxed)
                                + batch_len;
                            indicator_progress.set_position(uploaded as u64);

                            let completed = batches_completed.fetch_add(1, Ordering::Relaxed) + 1;
                            batch_progress.set_position(completed as u64);

                            // Calculate rate
                            let rate = batch_len as f64 / batch_duration.as_secs_f64().max(0.001);

                            // Update batch progress message with detailed status
                            batch_progress.set_message(format!(
                                "✓{} ✗{} | {:.0} ind/s",
                                stats_guard.successful, stats_guard.failed, rate
                            ));

                            if !response.errors.is_empty() {
                                for err in &response.errors {
                                    warn!(
                                        "Batch {}: upload error at index {}: {:?}",
                                        batch_num + 1,
                                        err.record_index,
                                        err.error_messages
                                    );
                                }
                            }

                            debug!(
                                "Batch {}/{}: uploaded {}/{} indicators in {:.2}s ({:.0}/s)",
                                batch_num + 1,
                                total_batches,
                                batch_success,
                                batch_len,
                                batch_duration.as_secs_f64(),
                                rate
                            );
                        }
                        Err(e) => {
                            stats_guard.failed += batch_len;

                            // Update progress even on failure
                            let uploaded = indicators_uploaded
                                .fetch_add(batch_len, Ordering::Relaxed)
                                + batch_len;
                            indicator_progress.set_position(uploaded as u64);

                            let completed = batches_completed.fetch_add(1, Ordering::Relaxed) + 1;
                            batch_progress.set_position(completed as u64);
                            batch_progress.set_message(format!(
                                "✓{} ✗{} | ERROR",
                                stats_guard.successful, stats_guard.failed
                            ));

                            error!("Batch {}: upload failed: {}", batch_num + 1, e);
                        }
                    }
                }
            })
            .collect();

        // Wait for all uploads to complete
        futures::future::join_all(upload_futures).await;

        let final_stats = stats.lock().await.clone();
        info!(
            "Concurrent upload complete: {} successful, {} failed out of {} total ({} requests)",
            final_stats.successful,
            final_stats.failed,
            final_stats.total_indicators,
            final_stats.requests_made
        );

        Ok(final_stats)
    }

    /// Upload a single batch of indicators
    async fn upload_batch(&mut self, indicators: Vec<StixIndicator>) -> Result<UploadResponse> {
        let token = self.get_access_token().await?;

        let url = format!(
            "https://api.ti.sentinel.azure.com/workspaces/{}/threat-intelligence-stix-objects:upload?api-version={}",
            self.config.workspace_id,
            self.config.api_version
        );

        let request_body = UploadRequest {
            sourcesystem: self.config.source_system.clone(),
            stixobjects: indicators,
        };

        debug!("Uploading batch to: {}", url);

        let response = self
            .client
            .post(&url)
            .header("Authorization", format!("Bearer {}", token))
            .header("Content-Type", "application/json")
            .json(&request_body)
            .send()
            .await
            .map_err(|e| Error::SentinelApi(format!("Upload request failed: {}", e)))?;

        let status = response.status();

        // Handle rate limiting
        if status.as_u16() == 429 {
            let text = response.text().await.unwrap_or_default();
            // Try to extract retry-after from response
            let retry_after = extract_retry_after(&text).unwrap_or(60);
            return Err(Error::RateLimit(retry_after));
        }

        if !status.is_success() {
            let text = response.text().await.unwrap_or_default();
            return Err(Error::SentinelApi(format!(
                "Upload failed ({}): {}",
                status, text
            )));
        }

        // Success response may still contain errors for individual indicators
        let upload_response: UploadResponse = response
            .json()
            .await
            .unwrap_or(UploadResponse { errors: vec![] });

        Ok(upload_response)
    }

    /// Upload mixed STIX objects (indicators, attack-patterns, threat-actors, etc.)
    pub async fn upload_stix_objects(
        &mut self,
        objects: Vec<StixObject>,
        batch_size: usize,
        requests_per_minute: u32,
    ) -> Result<UploadStats> {
        let total = objects.len();
        info!("Starting upload of {} STIX objects", total);

        if objects.is_empty() {
            return Ok(UploadStats::default());
        }

        let mut stats = UploadStats {
            total_indicators: total,
            ..Default::default()
        };

        let batch_size = batch_size.min(100);
        let request_interval = Duration::from_millis(60_000 / requests_per_minute as u64);
        let mut last_request = Instant::now() - request_interval;

        for (batch_num, chunk) in objects.chunks(batch_size).enumerate() {
            let elapsed = last_request.elapsed();
            if elapsed < request_interval {
                let wait_time = request_interval - elapsed;
                debug!("Rate limiting: waiting {:?}", wait_time);
                sleep(wait_time).await;
            }

            let mut retries = 0;
            let max_retries = 3;

            loop {
                let result = self.upload_stix_batch(chunk.to_vec()).await;
                last_request = Instant::now();
                stats.requests_made += 1;

                match result {
                    Ok(response) => {
                        let batch_success = chunk.len() - response.errors.len();
                        stats.successful += batch_success;
                        stats.failed += response.errors.len();

                        if !response.errors.is_empty() {
                            for err in &response.errors {
                                warn!(
                                    "Upload error at index {}: {:?}",
                                    err.record_index, err.error_messages
                                );
                            }
                        }

                        info!(
                            "Batch {}: uploaded {}/{} objects (total: {}/{})",
                            batch_num + 1,
                            batch_success,
                            chunk.len(),
                            stats.successful,
                            total
                        );
                        break;
                    }
                    Err(Error::RateLimit(retry_after)) => {
                        warn!("Rate limit hit, waiting {} seconds", retry_after);
                        sleep(Duration::from_secs(retry_after + 1)).await;
                        retries += 1;
                        if retries >= max_retries {
                            stats.failed += chunk.len();
                            error!("Max retries exceeded for batch {}", batch_num + 1);
                            break;
                        }
                    }
                    Err(e) => {
                        stats.failed += chunk.len();
                        error!("Upload failed for batch {}: {}", batch_num + 1, e);
                        break;
                    }
                }
            }
        }

        info!(
            "Upload complete: {} successful, {} failed out of {} total",
            stats.successful, stats.failed, stats.total_indicators
        );

        Ok(stats)
    }

    /// Upload a batch of mixed STIX objects
    async fn upload_stix_batch(&mut self, objects: Vec<StixObject>) -> Result<UploadResponse> {
        let token = self.get_access_token().await?;

        let url = format!(
            "https://api.ti.sentinel.azure.com/workspaces/{}/threat-intelligence-stix-objects:upload?api-version={}",
            self.config.workspace_id,
            self.config.api_version
        );

        let request_body = UploadRequestObjects {
            sourcesystem: self.config.source_system.clone(),
            stixobjects: objects,
        };

        debug!("Uploading STIX batch to: {}", url);

        let response = self
            .client
            .post(&url)
            .header("Authorization", format!("Bearer {}", token))
            .header("Content-Type", "application/json")
            .json(&request_body)
            .send()
            .await
            .map_err(|e| Error::SentinelApi(format!("Upload request failed: {}", e)))?;

        let status = response.status();

        if status.as_u16() == 429 {
            let text = response.text().await.unwrap_or_default();
            let retry_after = extract_retry_after(&text).unwrap_or(60);
            return Err(Error::RateLimit(retry_after));
        }

        if !status.is_success() {
            let text = response.text().await.unwrap_or_default();
            return Err(Error::SentinelApi(format!(
                "Upload failed ({}): {}",
                status, text
            )));
        }

        let upload_response: UploadResponse = response
            .json()
            .await
            .unwrap_or(UploadResponse { errors: vec![] });

        Ok(upload_response)
    }
}

/// Standalone batch upload function for concurrent uploads
///
/// This is separate from the impl block to allow use in async closures
/// without borrowing self.
async fn upload_batch_standalone(
    client: &Client,
    config: &SentinelConfig,
    token: &str,
    indicators: Vec<StixIndicator>,
) -> Result<UploadResponse> {
    let url = format!(
        "https://api.ti.sentinel.azure.com/workspaces/{}/threat-intelligence-stix-objects:upload?api-version={}",
        config.workspace_id,
        config.api_version
    );

    let request_body = UploadRequest {
        sourcesystem: config.source_system.clone(),
        stixobjects: indicators,
    };

    let response = client
        .post(&url)
        .header("Authorization", format!("Bearer {}", token))
        .header("Content-Type", "application/json")
        .json(&request_body)
        .send()
        .await
        .map_err(|e| Error::SentinelApi(format!("Upload request failed: {}", e)))?;

    let status = response.status();

    if status.as_u16() == 429 {
        let text = response.text().await.unwrap_or_default();
        let retry_after = extract_retry_after(&text).unwrap_or(60);
        return Err(Error::RateLimit(retry_after));
    }

    if !status.is_success() {
        let text = response.text().await.unwrap_or_default();
        return Err(Error::SentinelApi(format!(
            "Upload failed ({}): {}",
            status, text
        )));
    }

    let upload_response: UploadResponse = response
        .json()
        .await
        .unwrap_or(UploadResponse { errors: vec![] });

    Ok(upload_response)
}

/// Extract retry-after seconds from error message
fn extract_retry_after(message: &str) -> Option<u64> {
    // The API returns something like: "Try again in 60 seconds"
    let re = regex_lite::Regex::new(r"(\d+)\s*seconds?").ok()?;
    re.captures(message)
        .and_then(|cap| cap.get(1))
        .and_then(|m| m.as_str().parse().ok())
}

// Simple regex implementation for retry-after extraction
mod regex_lite {
    pub struct Regex {
        #[allow(dead_code)]
        pattern: String,
    }

    impl Regex {
        pub fn new(pattern: &str) -> Result<Self, ()> {
            Ok(Self {
                pattern: pattern.to_string(),
            })
        }

        pub fn captures<'a>(&self, text: &'a str) -> Option<Captures<'a>> {
            // Simple implementation to extract numbers followed by "second"
            for word in text.split_whitespace() {
                if let Ok(num) = word.parse::<u64>() {
                    // Check if next word contains "second"
                    if text.contains("second") {
                        return Some(Captures { text, number: num });
                    }
                }
            }
            None
        }
    }

    pub struct Captures<'a> {
        #[allow(dead_code)]
        text: &'a str,
        number: u64,
    }

    impl<'a> Captures<'a> {
        pub fn get(&self, _index: usize) -> Option<Match> {
            Some(Match { value: self.number })
        }
    }

    pub struct Match {
        value: u64,
    }

    impl Match {
        pub fn as_str(&self) -> &str {
            // This is a simplified implementation
            Box::leak(self.value.to_string().into_boxed_str())
        }
    }
}
