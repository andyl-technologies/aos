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

    /// Returns the remaining duration, saturated by absence at expiry.
    // crucible-lint: allow clippy-disallowed-method -- elapsed host time bounds QEMU liveness only and never enters modeled state.
    #[allow(clippy::disallowed_methods)]
    pub(super) fn remaining(&self) -> Option<Duration> {
        self.timeout.checked_sub(self.started.elapsed())
    }
}

/// Retains an absolute host deadline inside the private sampling boundary.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(super) struct AbsoluteHostDeadline(Instant);

impl AbsoluteHostDeadline {
    /// Starts a checked absolute host-only deadline for the opaque parent facade.
    pub(super) fn checked_after(timeout: Duration) -> Option<Self> {
        absolute_host_now().checked_add(timeout).map(Self)
    }

    /// Returns the original deadline's host budget, saturated at zero.
    pub(super) fn remaining(self) -> Duration {
        self.0.saturating_duration_since(absolute_host_now())
    }

    /// Includes the exact original deadline instant in existing test assertions.
    #[cfg(test)]
    pub(super) fn has_not_elapsed(self) -> bool {
        absolute_host_now() <= self.0
    }
}

/// Samples host time only for an absolute supervision budget, never guest state.
// crucible-lint: allow clippy-disallowed-method -- host time bounds QEMU liveness only and never enters modeled state.
#[allow(clippy::disallowed_methods)]
fn absolute_host_now() -> Instant {
    Instant::now()
}
