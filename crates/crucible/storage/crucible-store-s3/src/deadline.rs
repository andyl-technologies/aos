//! Operational-only monotonic deadlines for synchronous S3 commands.

use std::time::{Duration, Instant};

/// One host-monotonic deadline that never enters canonical state.
#[derive(Clone, Copy)]
pub(super) struct OperationalDeadline(Instant);

impl OperationalDeadline {
    /// Creates a deadline relative to the current host-monotonic time.
    pub(super) fn after(timeout: Duration) -> Option<Self> {
        operational_now().checked_add(timeout).map(Self)
    }

    /// Returns the nonnegative time remaining until this deadline.
    pub(super) fn remaining(self) -> Duration {
        self.0.saturating_duration_since(operational_now())
    }
}

// crucible-lint: allow clippy-disallowed-method -- host monotonic time enforces operational I/O deadlines and never enters canonical state.
#[allow(clippy::disallowed_methods)]
fn operational_now() -> Instant {
    Instant::now()
}
