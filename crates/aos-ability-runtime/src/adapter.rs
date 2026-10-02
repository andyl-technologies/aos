//! Cancellation and bounded process execution controls for native handlers.

use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};

/// A cancellation signal shared with an in-flight trusted adapter.
#[derive(Clone, Debug, Default)]
pub struct CancellationToken {
    cancelled: Arc<AtomicBool>,
}

impl CancellationToken {
    /// Requests bounded cancellation of the current execution.
    pub fn cancel(&self) {
        self.cancelled.store(true, Ordering::Release);
    }

    /// Reports whether cancellation has been requested.
    #[must_use]
    pub fn is_cancelled(&self) -> bool {
        self.cancelled.load(Ordering::Acquire)
    }
}

/// Exposes the bounded attempt controls available to a trusted adapter.
pub trait RuntimeControl {
    /// Reports whether the controller has requested cancellation.
    fn is_cancelled(&self) -> bool;

    /// Returns the elapsed transaction budget in milliseconds.
    fn elapsed_millis(&self) -> u64;

    /// Returns the remaining time in this attempt.
    fn attempt_remaining_millis(&self) -> u64;

    /// Returns the remaining total recovery budget.
    fn recovery_remaining_millis(&self) -> u64;
}

