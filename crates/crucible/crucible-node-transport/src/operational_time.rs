//! Private host monotonic budgets and separately named physical measurements.
//!
//! Deadlines can report only remaining I/O allowance or expiration. Their raw
//! clock coordinates have no getter, codec or public export. Physical elapsed
//! durations are observed evidence for the conditional reference-device budget;
//! they do not define a simulation Position or replace original logical grants.

use std::time::{Duration, Instant};

/// Retains an opaque operational deadline without exporting a clock coordinate.
#[derive(Clone, Copy, Eq, Ord, PartialEq, PartialOrd)]
pub(super) struct OperationalDeadline(Instant);

impl OperationalDeadline {
    /// Starts a checked budget; zero remains immediately expired.
    pub(super) fn after(budget: Duration) -> Option<Self> {
        clock_now().checked_add(budget).map(Self)
    }

    /// Initializes a transport handle before its separately validated reset.
    pub(super) fn at_current() -> Self {
        Self(clock_now())
    }

    /// Returns only the remaining operational I/O allowance.
    pub(super) fn remaining(self) -> Option<Duration> {
        self.0.checked_duration_since(clock_now())
    }

    /// Reports whether a host operation has exhausted its original budget.
    pub(super) fn is_expired(self) -> bool {
        clock_now() >= self.0
    }

    #[cfg(test)]
    pub(super) fn expired_fixture() -> Self {
        Self(clock_now() - Duration::from_millis(1))
    }
}

impl std::fmt::Debug for OperationalDeadline {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str("OperationalDeadline { .. }")
    }
}

/// Measures physical elapsed execution separately from logical event time.
pub(super) struct PhysicalMeasurement(Instant);

impl PhysicalMeasurement {
    /// Starts actual physical observation before the original native request.
    pub(super) fn begin() -> Self {
        Self(clock_now())
    }

    /// Returns the physical duration retained in conditional budget evidence.
    pub(super) fn elapsed(self) -> Duration {
        clock_now().duration_since(self.0)
    }
}

// The private clock supports only audited I/O budgets and physical observation.
// No caller can access an Instant, serialize it or turn it into modeled time.
// crucible-lint: allow rust-allow -- private host operational clock primitive.
// crucible-lint: allow clippy-disallowed-method -- private operational budgets and explicitly physical elapsed evidence.
#[allow(clippy::disallowed_methods)]
fn clock_now() -> Instant {
    Instant::now()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn expired_original_budget_cannot_be_renewed_by_copying() {
        let original = OperationalDeadline::expired_fixture();
        let copied = original;

        assert!(original.is_expired());
        assert!(copied.is_expired());
        assert!(original.remaining().is_none());
        assert!(copied.remaining().is_none());
    }

    #[test]
    fn diagnostics_never_export_the_host_coordinate() {
        let deadline = OperationalDeadline::at_current();
        assert_eq!(format!("{deadline:?}"), "OperationalDeadline { .. }");
        let measurement = PhysicalMeasurement::begin();
        let _physical_duration = measurement.elapsed();
    }

    #[test]
    fn unsupported_representation_refuses_without_a_clock_coordinate() {
        assert!(OperationalDeadline::after(Duration::MAX).is_none());
    }
}
