//! Progress tracking for long-running operations
//!
//! Provides configurable progress bars and status indicators
//! for MISP fetching, STIX conversion, and Sentinel uploads.

use console::{style, Term};
use indicatif::{MultiProgress, ProgressBar, ProgressStyle};
use std::sync::Arc;
use std::time::Duration;

/// Progress tracking manager for sync operations
#[derive(Clone)]
pub struct ProgressTracker {
    multi: Arc<MultiProgress>,
    enabled: bool,
}

impl ProgressTracker {
    /// Create a new progress tracker
    pub fn new(enabled: bool) -> Self {
        Self {
            multi: Arc::new(MultiProgress::new()),
            enabled,
        }
    }

    /// Create a spinner for indeterminate operations
    pub fn create_spinner(&self, message: &str) -> ProgressBar {
        if !self.enabled {
            return ProgressBar::hidden();
        }

        let spinner = self.multi.add(ProgressBar::new_spinner());
        spinner.set_style(
            ProgressStyle::default_spinner()
                .tick_chars("⠋⠙⠹⠸⠼⠴⠦⠧⠇⠏")
                .template("{spinner:.cyan} {msg}")
                .unwrap(),
        );
        spinner.set_message(message.to_string());
        spinner.enable_steady_tick(Duration::from_millis(100));
        spinner
    }

    /// Create a progress bar for fetch operations (page-based)
    pub fn create_fetch_progress(&self, message: &str) -> ProgressBar {
        if !self.enabled {
            return ProgressBar::hidden();
        }

        let pb = self.multi.add(ProgressBar::new(0));
        pb.set_style(
            ProgressStyle::default_bar()
                .template(
                    "{spinner:.cyan} {msg} [{elapsed_precise}] {wide_bar:.cyan/blue} {pos} events",
                )
                .unwrap()
                .progress_chars("█▓▒░"),
        );
        pb.set_message(message.to_string());
        pb.enable_steady_tick(Duration::from_millis(100));
        pb
    }

    /// Create a progress bar for conversion operations
    pub fn create_conversion_progress(&self, total: u64) -> ProgressBar {
        if !self.enabled {
            return ProgressBar::hidden();
        }

        let pb = self.multi.add(ProgressBar::new(total));
        pb.set_style(
            ProgressStyle::default_bar()
                .template("{spinner:.green} Converting events [{elapsed_precise}] {wide_bar:.green/white} {pos}/{len} ({percent}%) | {per_sec} events/sec")
                .unwrap()
                .progress_chars("█▓▒░"),
        );
        pb
    }

    /// Create a progress bar for upload operations
    pub fn create_upload_progress(&self, total: u64) -> ProgressBar {
        if !self.enabled {
            return ProgressBar::hidden();
        }

        let pb = self.multi.add(ProgressBar::new(total));
        pb.set_style(
            ProgressStyle::default_bar()
                .template("{spinner:.yellow} Uploading [{elapsed_precise}] {wide_bar:.yellow/white} {pos}/{len} indicators ({percent}%) | {per_sec}/s | ETA: {eta}")
                .unwrap()
                .progress_chars("█▓▒░"),
        );
        pb.enable_steady_tick(Duration::from_millis(100));
        pb
    }

    /// Create a progress bar for batch uploads with detailed status
    pub fn create_batch_progress(&self, total_batches: u64) -> ProgressBar {
        if !self.enabled {
            return ProgressBar::hidden();
        }

        let pb = self.multi.add(ProgressBar::new(total_batches));
        pb.set_style(
            ProgressStyle::default_bar()
                .template("{spinner:.magenta} Batches [{elapsed_precise}] {wide_bar:.magenta/white} {pos}/{len} | {msg}")
                .unwrap()
                .progress_chars("█▓▒░"),
        );
        pb.enable_steady_tick(Duration::from_millis(100));
        pb
    }

    /// Create a status line for real-time batch reporting
    pub fn create_status_line(&self) -> ProgressBar {
        if !self.enabled {
            return ProgressBar::hidden();
        }

        let pb = self.multi.add(ProgressBar::new_spinner());
        pb.set_style(
            ProgressStyle::default_spinner()
                .tick_chars("⠋⠙⠹⠸⠼⠴⠦⠧⠇⠏")
                .template("{spinner:.blue} {msg}")
                .unwrap(),
        );
        pb.enable_steady_tick(Duration::from_millis(100));
        pb
    }

    /// Print a status message (works even with progress bars)
    pub fn println(&self, msg: &str) {
        if self.enabled {
            let _ = self.multi.println(msg);
        }
    }

    /// Print a batch completion message
    #[allow(clippy::too_many_arguments)]
    pub fn print_batch_status(
        &self,
        batch_num: usize,
        total_batches: usize,
        batch_success: usize,
        batch_failed: usize,
        total_success: usize,
        total_failed: usize,
        rate_per_sec: f64,
    ) {
        if !self.enabled {
            return;
        }

        let status = if batch_failed == 0 {
            style("✓").green()
        } else {
            style("⚠").yellow()
        };

        let _ = self.multi.println(format!(
            "  {} Batch {}/{}: {} ok, {} err | Total: {} ok, {} err | {:.0} ind/s",
            status,
            batch_num,
            total_batches,
            style(batch_success).green(),
            if batch_failed > 0 {
                style(batch_failed).red().to_string()
            } else {
                "0".to_string()
            },
            total_success,
            total_failed,
            rate_per_sec
        ));
    }

    /// Print a success summary
    pub fn print_summary(
        &self,
        events: usize,
        indicators: usize,
        successful: usize,
        failed: usize,
        duration_secs: f64,
    ) {
        let term = Term::stdout();
        let _ = term.write_line("");
        let _ = term.write_line(&format!(
            "{} Sync completed in {:.2}s",
            style("✓").green().bold(),
            duration_secs
        ));
        let _ = term.write_line(&format!(
            "  {} Events processed: {}",
            style("→").cyan(),
            events
        ));
        let _ = term.write_line(&format!(
            "  {} Indicators created: {}",
            style("→").cyan(),
            indicators
        ));
        if successful > 0 || failed > 0 {
            let _ = term.write_line(&format!(
                "  {} Uploaded: {} successful, {} failed",
                style("→").cyan(),
                style(successful).green(),
                if failed > 0 {
                    style(failed).red()
                } else {
                    style(failed).dim()
                }
            ));
        }
    }

    /// Print a dry-run summary
    pub fn print_dry_run_summary(&self, events: usize, indicators: usize, duration_secs: f64) {
        let term = Term::stdout();
        let _ = term.write_line("");
        let _ = term.write_line(&format!(
            "{} Dry run completed in {:.2}s",
            style("✓").yellow().bold(),
            duration_secs
        ));
        let _ = term.write_line(&format!(
            "  {} Events processed: {}",
            style("→").cyan(),
            events
        ));
        let _ = term.write_line(&format!(
            "  {} Indicators that would be created: {}",
            style("→").cyan(),
            indicators
        ));
        let _ = term.write_line(&format!(
            "  {} Mode: {} (no upload)",
            style("→").cyan(),
            style("DRY RUN").yellow()
        ));
    }
}

/// Phase status for progress reporting
pub enum Phase {
    Fetching,
    Converting,
    Uploading,
    Complete,
}

impl std::fmt::Display for Phase {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Phase::Fetching => write!(f, "Fetching"),
            Phase::Converting => write!(f, "Converting"),
            Phase::Uploading => write!(f, "Uploading"),
            Phase::Complete => write!(f, "Complete"),
        }
    }
}
