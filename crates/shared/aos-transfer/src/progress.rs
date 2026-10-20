//! Progress tracking via callbacks.
//!
//! Provides traits for reporting transfer progress. The calling crate
//! brings its own UI (indicatif, ratatui, etc.) -- this module only
//! defines the callback interface.

use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;
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
    fn observe(&self, _event: TransferEvent<'_>) {}

    /// Reports an informational diagnostic associated with a transfer.
    fn info(&self, _message: &str) {}

    /// Reports a recoverable transfer failure or other warning.
    fn warning(&self, _message: &str) {}

    /// Creates a shared progress handle for a transfer or preparatory phase.
    ///
    /// A zero total denotes an unknown size. The default handle tracks byte
    /// counts without producing output or reading a clock.
    fn transfer(&self, _label: &str, _total_bytes: u64) -> TransferProgress {
        TransferProgress::default()
    }
}

/// An observer that discards every event.
#[derive(Debug, Default, Clone, Copy)]
pub struct NoopObserver;

impl TransferObserver for NoopObserver {
    fn observe(&self, _event: TransferEvent<'_>) {}
}

/// Receives updates from a caller-owned transfer progress handle.
///
/// Implementations choose how to render updates. Methods must return promptly;
/// concurrent clones of a handle may call them from different tasks.
pub trait ProgressSink: Send + Sync {
    /// Selects a transfer phase while retaining the current byte count.
    fn phase(&self, _label: &str) {}

    /// Selects a preparatory phase with no meaningful byte total.
    fn activity_phase(&self, _label: &str) {}

    /// Sets the known transfer size, or zero when it is unknown.
    fn set_total(&self, _total_bytes: u64) {}

    /// Sets the absolute transferred byte count.
    fn set_position(&self, _bytes: u64) {}

    /// Adds bytes to the transferred byte count.
    fn inc(&self, _bytes: u64) {}

    /// Reports a warning without interrupting the transfer.
    fn warning(&self, _message: &str) {}

    /// Marks the transfer complete and releases its displayed progress.
    fn finish(&self) {}

    /// Stops the transfer and reports why it was abandoned.
    fn abandon(&self, _message: &str) {}

    /// Returns the adapter's elapsed time, or zero when it is not tracked.
    fn elapsed(&self) -> Duration {
        Duration::ZERO
    }

    /// Returns the current transferred byte count.
    fn position(&self) -> u64 {
        0
    }
}

/// Shares progress updates between a transfer and its presentation adapter.
///
/// Clones reference the same sink. Dropping the last handle drops that sink;
/// adapters may use this to clear unfinished presentation. A default handle
/// records position without any terminal, clock, or runtime dependency.
///
/// # Examples
///
/// ```rust
/// use aos_transfer::progress::{NoopObserver, TransferObserver};
///
/// let progress = NoopObserver.transfer("Downloading metadata", 1024);
/// let worker = progress.clone();
/// worker.inc(256);
/// assert_eq!(progress.position(), 256);
/// ```
#[derive(Clone)]
pub struct TransferProgress {
    sink: Arc<dyn ProgressSink>,
}

impl TransferProgress {
    /// Creates a progress handle backed by a caller's presentation adapter.
    pub fn new(sink: impl ProgressSink + 'static) -> Self {
        Self {
            sink: Arc::new(sink),
        }
    }

    /// Selects a transfer phase while retaining the current byte count.
    pub fn phase(&self, label: &str) {
        self.sink.phase(label);
    }

    /// Selects a preparatory phase with no meaningful byte total.
    pub fn activity_phase(&self, label: &str) {
        self.sink.activity_phase(label);
    }

    /// Sets the known transfer size, or zero when it is unknown.
    pub fn set_total(&self, total_bytes: u64) {
        self.sink.set_total(total_bytes);
    }

    /// Sets the absolute transferred byte count.
    pub fn set_position(&self, bytes: u64) {
        self.sink.set_position(bytes);
    }

    /// Adds bytes to the transferred byte count.
    pub fn inc(&self, bytes: u64) {
        self.sink.inc(bytes);
    }

    /// Reports a warning without interrupting the transfer.
    pub fn warning(&self, message: &str) {
        self.sink.warning(message);
    }

    /// Marks the transfer complete and releases its displayed progress.
    pub fn finish(&self) {
        self.sink.finish();
    }

    /// Stops the transfer and reports why it was abandoned.
    pub fn abandon(&self, message: &str) {
        self.sink.abandon(message);
    }

    /// Returns the adapter's elapsed time, or zero when it is not tracked.
    pub fn elapsed(&self) -> Duration {
        self.sink.elapsed()
    }

    /// Returns the current transferred byte count.
    pub fn position(&self) -> u64 {
        self.sink.position()
    }
}

impl Default for TransferProgress {
    fn default() -> Self {
        Self::new(SilentProgress {
            position: AtomicU64::new(0),
        })
    }
}

struct SilentProgress {
    position: AtomicU64,
}

impl ProgressSink for SilentProgress {
    fn set_position(&self, bytes: u64) {
        self.position.store(bytes, Ordering::Relaxed);
    }

    fn inc(&self, bytes: u64) {
        self.position.fetch_add(bytes, Ordering::Relaxed);
    }

    fn position(&self) -> u64 {
        self.position.load(Ordering::Relaxed)
    }
}

/// Callback trait for tracking progress of a single transfer.
///
/// Implementations are installed through the transfer engine's `set_progress`
/// method.
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
/// Passed to the transfer engine's `execute_batch` method.
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
#[cfg(feature = "transfer")]
pub struct TracingProgress;

#[cfg(feature = "transfer")]
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

#[cfg(feature = "transfer")]
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

#[cfg(test)]
#[allow(
    clippy::unwrap_used,
    reason = "thread panic is an intentional test failure"
)]
mod tests {
    use super::{NoopObserver, TransferObserver};

    #[test]
    fn silent_progress_shares_position_between_concurrent_clones() {
        let progress = NoopObserver.transfer("download", 100);
        progress.set_position(10);
        let clone = progress.clone();
        std::thread::spawn(move || clone.inc(20)).join().unwrap();

        assert_eq!(progress.position(), 30);
        progress.finish();
        assert_eq!(progress.position(), 30);
    }
}
