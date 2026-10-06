//! Keeps private host transport clock coordinates outside operational API records.

use std::time::{Duration, Instant};

/// Opaque finite original-start fallback for explicitly unsupervised utilities.
#[derive(Clone, Copy, Debug)]
pub(super) struct TransportDeadline(Instant);

impl TransportDeadline {
    /// Starts one checked positive allowance.
    ///
    /// # Errors
    /// Returns invalid input for zero or unrepresentable monotonic allowances.
    pub(super) fn after(duration: Duration) -> std::io::Result<Self> {
        if duration.is_zero() {
            return Err(std::io::Error::new(
                std::io::ErrorKind::InvalidInput,
                "zero RAM exchange allowance",
            ));
        }
        monotonic_now()
            .checked_add(duration)
            .map(Self)
            .ok_or_else(|| {
                std::io::Error::new(
                    std::io::ErrorKind::InvalidInput,
                    "RAM exchange allowance overflow",
                )
            })
    }

    /// Returns remaining time without restarting the original allowance.
    ///
    /// # Errors
    /// Returns timeout after the original allowance expires.
    pub(super) fn remaining(self) -> std::io::Result<Duration> {
        self.0
            .checked_duration_since(monotonic_now())
            .filter(|duration| !duration.is_zero())
            .ok_or_else(|| {
                std::io::Error::new(
                    std::io::ErrorKind::TimedOut,
                    "RAM exchange allowance expired",
                )
            })
    }
}

// crucible-lint: allow clippy-disallowed-method -- This private operational transport deadline samples host monotonic time; its opaque token never enters guest execution state.
#[allow(
    clippy::disallowed_methods,
    reason = "private operational supervision clock boundary"
)]
fn monotonic_now() -> Instant {
    Instant::now()
}
