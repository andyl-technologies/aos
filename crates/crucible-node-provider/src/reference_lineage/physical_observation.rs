//! Records physical elapsed native activation separately from all logical time.
//!
//! The driver starts this observation immediately before its original exchange.
//! Only elapsed nanoseconds and the original physical-budget comparison leave
//! this module. Neither result can supply a logical Position or clock coordinate.

use std::time::Duration;

use crucible_node_contract::U64;

use crate::ProviderError;
// crucible-lint: allow host-nondeterminism-state -- This private native observer imports only physical elapsed duration, never a raw host timestamp.
use crate::operational_time::PhysicalMeasurement;

// crucible-lint: allow host-nondeterminism-state -- The original activation observation owns an opaque nonserialized physical-duration measurement.
pub(super) struct PhysicalActivation(PhysicalMeasurement);

pub(super) struct ActivationDuration {
    pub(super) nanoseconds: U64,
    pub(super) exceeded_budget: bool,
}

impl PhysicalActivation {
    pub(super) fn begin() -> Self {
        // crucible-lint: allow host-nondeterminism-state -- Begins actual native activation observation without exposing a host coordinate.
        Self(PhysicalMeasurement::begin())
    }

    pub(super) fn finish(
        self,
        original_budget: Duration,
    ) -> Result<ActivationDuration, ProviderError> {
        let elapsed = self.0.elapsed();
        let nanoseconds = u64::try_from(elapsed.as_nanos())
            .map(U64::new)
            .map_err(|_| ProviderError::Correlation("lineage physical duration extent"))?;
        Ok(ActivationDuration {
            nanoseconds,
            exceeded_budget: elapsed > original_budget,
        })
    }
}
