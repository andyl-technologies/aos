//! Private operational clocks for process supervision and fork-rate admission.
//!
//! These clocks never define guest time, an execution horizon, campaign fuel,
//! or a persisted execution result. Process deadlines only stop host waiting;
//! the fork clock feeds the process-wide launch-rate limiter, not planner
//! selection. Neither clock exposes its host timestamp to callers.

use std::time::{Duration, Instant};

/// Measures elapsed host time solely for operational fork-rate admission.
pub(super) struct ForkRateClock {
    origin: Instant,
}

impl ForkRateClock {
    pub(super) fn new() -> Self {
        Self { origin: now() }
    }

    pub(super) fn elapsed_nanos(&self) -> u64 {
        let elapsed = now().saturating_duration_since(self.origin);
        u64::try_from(elapsed.as_nanos()).unwrap_or(u64::MAX)
    }
}

/// Bounds one host process operation without exposing an absolute timestamp.
#[derive(Clone, Copy)]
pub(super) struct ProcessDeadline {
    deadline: Instant,
}

impl ProcessDeadline {
    /// Returns no deadline if the requested host duration cannot be represented.
    pub(super) fn after(timeout: Duration) -> Option<Self> {
        now().checked_add(timeout).map(|deadline| Self { deadline })
    }

    pub(super) fn expired(self) -> bool {
        now() >= self.deadline
    }

    /// Caps a process-poll pause at the remaining operational wait allowance.
    pub(super) fn pause(self, maximum: Duration) {
        std::thread::sleep(maximum.min(self.deadline.saturating_duration_since(now())));
    }
}

// Host time controls operational waiting and admission only. Keeping the read
// here prevents public lifecycle APIs from exporting a raw host-clock basis.
// crucible-lint: allow clippy-disallowed-method -- monotonic host time bounds only process supervision and operational fork admission.
#[allow(clippy::disallowed_methods)]
fn now() -> Instant {
    Instant::now()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn zero_process_allowance_is_already_expired() {
        assert!(ProcessDeadline::after(Duration::ZERO).is_some_and(ProcessDeadline::expired));
    }

    #[test]
    fn overflowing_process_allowance_is_rejected() {
        assert!(ProcessDeadline::after(Duration::MAX).is_none());
    }

    #[test]
    fn fork_rate_clock_never_moves_backwards() {
        let clock = ForkRateClock::new();
        let first = clock.elapsed_nanos();
        assert!(clock.elapsed_nanos() >= first);
    }
}
