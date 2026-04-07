//! Progress tracking via callbacks.
//!
//! Provides traits for reporting transfer progress. The calling crate
//! brings its own UI (indicatif, ratatui, etc.) -- this module only
//! defines the callback interface.

use anyhow;

/// Callback trait for tracking progress of a single transfer.
pub trait ProgressHandler: Send + Sync {
    /// Called when a transfer begins.
    fn on_start(&self, url: &str, total_bytes: Option<u64>);

    /// Called on each chunk received/sent.
    fn on_progress(&self, url: &str, bytes: u64, total: Option<u64>);

    /// Called when a transfer completes successfully.
    fn on_complete(&self, url: &str, bytes: u64);

    /// Called when a transfer fails.
    fn on_error(&self, url: &str, error: &anyhow::Error);
}

/// Callback trait for tracking progress of a batch of transfers.
pub trait BatchProgressHandler: Send + Sync {
    /// Called when an individual transfer in the batch starts.
    fn on_transfer_start(&self, index: usize, url: &str, total_bytes: Option<u64>);

    /// Called on each chunk received/sent for an individual transfer.
    fn on_transfer_progress(&self, index: usize, bytes: u64, total: Option<u64>);

    /// Called when an individual transfer completes.
    fn on_transfer_complete(&self, index: usize, bytes: u64);

    /// Called when an individual transfer fails.
    fn on_transfer_error(&self, index: usize, error: &anyhow::Error);

    /// Called periodically with overall batch progress.
    fn on_batch_progress(&self, completed: usize, total: usize, bytes: u64);
}

/// A no-op progress handler that discards all progress events.
pub struct NoopProgress;

impl ProgressHandler for NoopProgress {
    fn on_start(&self, _url: &str, _total_bytes: Option<u64>) {}
    fn on_progress(&self, _url: &str, _bytes: u64, _total: Option<u64>) {}
    fn on_complete(&self, _url: &str, _bytes: u64) {}
    fn on_error(&self, _url: &str, _error: &anyhow::Error) {}
}

impl BatchProgressHandler for NoopProgress {
    fn on_transfer_start(&self, _index: usize, _url: &str, _total_bytes: Option<u64>) {}
    fn on_transfer_progress(&self, _index: usize, _bytes: u64, _total: Option<u64>) {}
    fn on_transfer_complete(&self, _index: usize, _bytes: u64) {}
    fn on_transfer_error(&self, _index: usize, _error: &anyhow::Error) {}
    fn on_batch_progress(&self, _completed: usize, _total: usize, _bytes: u64) {}
}

/// A progress handler that logs events via tracing.
pub struct TracingProgress;

impl ProgressHandler for TracingProgress {
    fn on_start(&self, url: &str, total_bytes: Option<u64>) {
        tracing::info!(url, total_bytes, "transfer started");
    }

    fn on_progress(&self, url: &str, bytes: u64, total: Option<u64>) {
        tracing::trace!(url, bytes, total, "transfer progress");
    }

    fn on_complete(&self, url: &str, bytes: u64) {
        tracing::info!(url, bytes, "transfer complete");
    }

    fn on_error(&self, url: &str, error: &anyhow::Error) {
        tracing::error!(url, %error, "transfer failed");
    }
}

impl BatchProgressHandler for TracingProgress {
    fn on_transfer_start(&self, index: usize, url: &str, total_bytes: Option<u64>) {
        tracing::info!(index, url, total_bytes, "batch transfer started");
    }

    fn on_transfer_progress(&self, index: usize, bytes: u64, total: Option<u64>) {
        tracing::trace!(index, bytes, total, "batch transfer progress");
    }

    fn on_transfer_complete(&self, index: usize, bytes: u64) {
        tracing::info!(index, bytes, "batch transfer complete");
    }

    fn on_transfer_error(&self, index: usize, error: &anyhow::Error) {
        tracing::error!(index, %error, "batch transfer failed");
    }

    fn on_batch_progress(&self, completed: usize, total: usize, bytes: u64) {
        tracing::info!(completed, total, bytes, "batch progress");
    }
}
