//! Progress tracking via callbacks.
//!
//! Provides traits for reporting transfer progress. The calling crate
//! brings its own UI (indicatif, ratatui, etc.) -- this module only
//! defines the callback interface.

use anyhow;
use std::time::Duration;

/// A structured lifecycle event emitted by one transfer.
///
/// Events are intentionally transport-neutral. Interactive callers can render
/// them as progress bars, machine-readable callers can serialize an equivalent
/// representation, and batch callers can aggregate them without changing the
/// transfer implementation.
#[derive(Debug, Clone, Copy)]
pub enum TransferEvent<'a> {
    /// The transfer has started.
    Started {
        /// Source or destination URL.
        url: &'a str,
        /// Complete object size when known.
        total_bytes: Option<u64>,
        /// Bytes already present in a validated partial transfer.
        resumed_bytes: u64,
    },
    /// More bytes have been committed to the transfer destination.
    Progress {
        /// Source or destination URL.
        url: &'a str,
        /// Complete bytes committed, including a resumed prefix.
        transferred_bytes: u64,
        /// Complete object size when known.
        total_bytes: Option<u64>,
    },
    /// A transient failure will be retried.
    Retrying {
        /// Source or destination URL.
        url: &'a str,
        /// One-based attempt about to start.
        attempt: u32,
        /// Delay before the next attempt.
        delay: Duration,
        /// Failure that caused the retry.
        error: &'a anyhow::Error,
    },
    /// The transferred bytes are being verified.
    Verifying {
        /// Source or destination URL.
        url: &'a str,
    },
    /// The transfer completed successfully.
    Completed {
        /// Source or destination URL.
        url: &'a str,
        /// Complete transferred byte count.
        transferred_bytes: u64,
    },
    /// The transfer failed permanently.
    Failed {
        /// Source or destination URL.
        url: &'a str,
        /// Terminal failure.
        error: &'a anyhow::Error,
    },
}

/// Receives structured events for one or more transfers.
///
/// Observers are supplied per operation rather than installed globally on a
/// manager. This lets concurrent CLI commands attach independent progress UIs
/// while sharing the same connection pools and policy engine.
pub trait TransferObserver: Send + Sync {
    /// Observes one transfer lifecycle event.
    fn observe(&self, event: TransferEvent<'_>);
}

/// An observer that discards every event.
#[derive(Debug, Default, Clone, Copy)]
pub struct NoopObserver;

impl TransferObserver for NoopObserver {
    fn observe(&self, _event: TransferEvent<'_>) {}
}

/// Callback trait for tracking progress of a single transfer.
///
/// Implementations are installed on the engine via
/// [`TransferEngine::set_progress`](crate::transfer::TransferEngine::set_progress).
/// Callbacks are invoked from the async transfer task, so they should
/// return quickly and must not block.
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
///
/// Passed to
/// [`TransferEngine::execute_batch`](crate::transfer::TransferEngine::execute_batch).
/// The `index` parameter identifies the transfer by its position in
/// the submitted request list. Per-transfer callbacks may be invoked
/// concurrently from multiple tasks.
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
///
/// This is the default handler used by the transfer engine when no
/// custom handler is installed. It implements both [`ProgressHandler`]
/// and [`BatchProgressHandler`].
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

/// A progress handler that logs events via [`tracing`].
///
/// Start/complete/error events are logged at `info`/`error` level;
/// per-chunk progress events are logged at `trace` level to avoid
/// flooding logs during large transfers.
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
