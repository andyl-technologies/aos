//! Host-time deadlines that bound QEMU process supervision.

use std::time::{Duration, Instant};

/// A host deadline that never contributes to modeled state or ordering.
pub(super) struct HostSupervisionDeadline {
    started: Instant,
    timeout: Duration,
}

impl HostSupervisionDeadline {
    /// Starts a host-only supervision deadline.
    // crucible-lint: allow clippy-disallowed-method -- host time bounds QEMU liveness only and never enters modeled state.
    #[allow(clippy::disallowed_methods)]
    pub(super) fn start(timeout: Duration) -> Self {
        Self {
            started: Instant::now(),
            timeout,
        }
    }

    /// Reports whether the host-only supervision budget remains available.
    // crucible-lint: allow clippy-disallowed-method -- elapsed host time bounds QEMU liveness only and never enters modeled state.
    #[allow(clippy::disallowed_methods)]
    pub(super) fn has_time_remaining(&self) -> bool {
        self.started.elapsed() < self.timeout
    }
}
