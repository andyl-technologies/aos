//! Host-liveness deadline state for an in-flight QEMU quantum.

use std::time::{Duration, Instant};

/// Retains the original host deadline across shared-memory report retries.
#[derive(Debug, Default)]
pub(super) struct AdvanceWaitDeadline {
    deadline: Option<Instant>,
}

impl AdvanceWaitDeadline {
    /// Starts a deadline and reports whether the timeout fit in [`Instant`].
    // crucible-lint: allow clippy-disallowed-method -- host time bounds QEMU liveness only and never enters Crucible state.
    #[allow(clippy::disallowed_methods)]
    pub(super) fn start(&mut self, timeout: Duration) -> bool {
        self.deadline = Instant::now().checked_add(timeout);
        self.deadline.is_some()
    }

    /// Returns the remaining duration, saturated at zero.
    // crucible-lint: allow clippy-disallowed-method -- elapsed host time enforces the original QEMU liveness budget only.
    #[allow(clippy::disallowed_methods)]
    pub(super) fn remaining(&self) -> Option<Duration> {
        self.deadline
            .map(|deadline| deadline.saturating_duration_since(Instant::now()))
    }
}
