//! Lends the sole fixed-service native clock recipe to paid Host cold entry.
//!
//! This inert native original is neither a Host role nor a Source grant. Its
//! caller prepays the complete compiled/dynamic representation on the actual
//! current Host Control, retains failures and independently reaches its after.

use super::{FixedServiceOperationClosedV4, clock::OperationClockV4};
use aos_sandbox_model::{AccountingError, RawPairedClockSample, ResourceDimension as D, ResourceVector};

/// Retains the shared native clock for opening and two finite HELLO sends.
///
/// No deadline, boot, authority or financial balance is reconstructed from
/// caller DATA. Successful samples stay comparisons; the actual Session and
/// current Source owners remain separately required.
pub struct HostControlColdClockOriginalV1 {
    original: OperationClockV4,
}

impl Default for HostControlColdClockOriginalV1 {
    fn default() -> Self { Self { original: OperationClockV4::default() } }
}

impl HostControlColdClockOriginalV1 {
    /// Bounds the actual shared clock and simultaneous construction carriers.
    ///
    /// # Errors
    /// Refuses checked carrier-size or dynamic native geometry overflow.
    pub fn receiving_demand_v1() -> Result<ResourceVector, AccountingError> {
        let overflow = AccountingError::ArithmeticOverflow { dimension: D::MemoryBytes };
        let bytes = std::mem::size_of::<Self>().checked_mul(2)
            .and_then(|bytes| u64::try_from(bytes).ok()).ok_or(overflow)?;
        OperationClockV4::dynamic_demand()?.checked_add(ResourceVector::ZERO.with(D::MemoryBytes, bytes))
    }

    /// Captures the actual opening sample once using the sole native recipe.
    ///
    /// # Errors
    /// Retains native/provenance failure or refuses repeated opening entry.
    pub fn actual_before_clock_v1(&mut self) -> Result<RawPairedClockSample, FixedServiceOperationClosedV4> {
        self.original.observe_primary(1)
    }

    /// Borrows the original opening without observing or renewing its horizon.
    ///
    /// # Errors
    /// Refuses a missing opening, retained clock failure or completed after.
    pub fn retained_opening_clock_data_v1(&self) -> Result<RawPairedClockSample, FixedServiceOperationClosedV4> {
        self.original.opening_data()
    }

    /// Borrows the last actual sample and same retained native cutoff.
    ///
    /// # Errors
    /// Refuses a missing bound/sample, retained failure or completed after.
    pub fn retained_interval_data_v1(&self) -> Result<(RawPairedClockSample, u64), FixedServiceOperationClosedV4> {
        self.original.retained_interval_data_v4()
    }

    /// Captures the next finite same-original HELLO-send comparison.
    ///
    /// # Errors
    /// Retains native/continuity/expiry failure or refuses more than two sends.
    pub fn fresh_before_effect_clock_v1(&mut self) -> Result<RawPairedClockSample, FixedServiceOperationClosedV4> {
        self.original.observe_primary(3)
    }

    /// Narrows the same retained native horizon without extending either bound.
    ///
    /// # Errors
    /// Refuses zero/expired bounds, missing opening or an already failed clock.
    pub fn narrow_deadline_data_v1(&mut self, cutoff: u64, wall_expiry: Option<i64>)
        -> Result<(), FixedServiceOperationClosedV4> {
        self.original.narrow(cutoff, wall_expiry)
    }

    /// Checks the retained current sample against its immutable narrowed bounds.
    ///
    /// # Errors
    /// Refuses incomplete, expired or failed native custody without new IO.
    pub fn require_current_v1(&mut self) -> Result<(), FixedServiceOperationClosedV4> {
        self.original.require_current()
    }

    /// Reaches the independently owed native after, even following failure.
    ///
    /// # Errors
    /// Retains native/continuity/expiry failure or refuses repeated after entry.
    pub fn finish_native_once_v1(&mut self) -> Result<(), FixedServiceOperationClosedV4> {
        self.original.finish_once()
    }

    /// Reports the actual complete positive pair without creating a grant.
    #[must_use]
    pub fn completed_native_v1(&self) -> bool { self.original.completed_inventory_pair_v5() }

    /// Borrows the original chronological native cause without cloning it.
    #[must_use]
    pub fn failure_v1(&self) -> Option<&(dyn std::error::Error + 'static)> { self.original.failure() }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn finite_cold_sends_keep_first_native_pair_ceiling_and_independent_after() {
        let mut clock = HostControlColdClockOriginalV1::default();
        let opening = clock.actual_before_clock_v1().unwrap();
        let cutoff = opening.boottime_nanoseconds().checked_add(30_000_000_000).unwrap();
        clock.narrow_deadline_data_v1(cutoff, None).unwrap();
        for _ in 0 .. 2 { opening.validate_later_sample(clock.fresh_before_effect_clock_v1().unwrap()).unwrap(); }
        clock.narrow_deadline_data_v1(cutoff + 1, None).unwrap();
        assert_eq!(clock.retained_interval_data_v1().unwrap().1, cutoff);

        assert!(clock.fresh_before_effect_clock_v1().is_err());
        let first = clock.failure_v1().unwrap() as *const dyn std::error::Error;
        assert!(clock.finish_native_once_v1().is_err());

        assert!(std::ptr::addr_eq(first, clock.failure_v1().unwrap() as *const dyn std::error::Error));
        assert!(!clock.completed_native_v1());
    }
}
