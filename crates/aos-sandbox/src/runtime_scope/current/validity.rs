//! Non-renewable paired-clock bounds for a single current-runtime observation.
//!
//! These scalar bounds carry no authority without their enclosing protected
//! selection and authenticated Host observation. Time checks cannot establish
//! current publication or execution identity.

use aos_sandbox_core::RawPairedClockSample;
use aos_sandbox_core::ownership_lease::{
    CLOCK_PAIR_TOLERANCE_NANOSECONDS, LEASE_SAFETY_MARGIN_SECONDS,
};
use aos_sandbox_ownership_protocol::SignedOwnershipLease;

use super::CurrentRuntimeScopeError;

const NANOS_PER_SECOND: u64 = 1_000_000_000;

pub(super) struct ObservationValidity {
    initial: RawPairedClockSample,
    expires_wall_seconds: i64,
    deadline_boottime_nanoseconds: u64,
}

impl ObservationValidity {
    pub(super) const fn initial(&self) -> RawPairedClockSample {
        self.initial
    }

    pub(super) const fn expires_wall_seconds(&self) -> i64 {
        self.expires_wall_seconds
    }

    pub(super) fn new(
        initial: RawPairedClockSample,
        lease: &SignedOwnershipLease,
        plan_expires: i64,
        maximum_seconds: u32,
    ) -> Result<Self, CurrentRuntimeScopeError> {
        Self::from_bounds(
            initial,
            lease.authority_expires_seconds(),
            lease.maximum_clock_skew_seconds(),
            plan_expires,
            maximum_seconds,
        )
    }

    fn from_bounds(
        initial: RawPairedClockSample,
        lease_expires: i64,
        skew: u64,
        plan_expires: i64,
        maximum_seconds: u32,
    ) -> Result<Self, CurrentRuntimeScopeError> {
        let guard = skew
            .checked_add(LEASE_SAFETY_MARGIN_SECONDS)
            .and_then(|guard| i64::try_from(guard).ok())
            .ok_or(CurrentRuntimeScopeError::Clock)?;
        let expires_wall_seconds = lease_expires
            .checked_sub(guard)
            .ok_or(CurrentRuntimeScopeError::Clock)?
            .min(plan_expires)
            .min(
                initial
                    .wall_seconds()
                    .checked_add(i64::from(maximum_seconds))
                    .ok_or(CurrentRuntimeScopeError::Clock)?,
            );
        let duration = expires_wall_seconds
            .checked_sub(initial.wall_seconds())
            .and_then(|seconds| u64::try_from(seconds).ok())
            .filter(|seconds| *seconds > 0)
            .and_then(|seconds| seconds.checked_mul(NANOS_PER_SECOND))
            .ok_or(CurrentRuntimeScopeError::Clock)?;
        let deadline_boottime_nanoseconds = initial
            .boottime_nanoseconds()
            .checked_add(duration)
            .ok_or(CurrentRuntimeScopeError::Clock)?;
        Ok(Self {
            initial,
            expires_wall_seconds,
            deadline_boottime_nanoseconds,
        })
    }

    pub(super) const fn deadline(&self) -> u64 {
        self.deadline_boottime_nanoseconds
    }

    pub(super) fn check(
        &self,
        fresh: RawPairedClockSample,
    ) -> Result<(), CurrentRuntimeScopeError> {
        if fresh.host_boot_id() != self.initial.host_boot_id()
            || fresh.provenance() != self.initial.provenance()
            || fresh.wall_seconds() >= self.expires_wall_seconds
            || fresh.boottime_nanoseconds() >= self.deadline_boottime_nanoseconds
        {
            return Err(CurrentRuntimeScopeError::Clock);
        }
        let wall_elapsed = fresh
            .wall_seconds()
            .checked_sub(self.initial.wall_seconds())
            .and_then(|seconds| u64::try_from(seconds).ok())
            .and_then(|seconds| seconds.checked_mul(NANOS_PER_SECOND))
            .ok_or(CurrentRuntimeScopeError::Clock)?;
        let boot_elapsed = fresh
            .boottime_nanoseconds()
            .checked_sub(self.initial.boottime_nanoseconds())
            .ok_or(CurrentRuntimeScopeError::Clock)?;
        if wall_elapsed.abs_diff(boot_elapsed) > CLOCK_PAIR_TOLERANCE_NANOSECONDS {
            return Err(CurrentRuntimeScopeError::Clock);
        }
        Ok(())
    }
}

#[cfg(test)]
#[allow(
    clippy::unwrap_used,
    reason = "Time-bound regression assertions intentionally panic."
)]
mod tests {
    use super::*;
    use aos_sandbox_core::RawClockProvenance;

    fn clock(wall: i64, boot: u64, identity: u8, provenance: u8) -> RawPairedClockSample {
        RawPairedClockSample::new_untrusted(
            RawClockProvenance::new_untrusted([provenance; 16]).unwrap(),
            [identity; 16],
            wall,
            boot,
        )
        .unwrap()
    }

    #[test]
    fn shortest_bound_wins_and_rechecks_never_extend_it() {
        let initial = clock(100, 1_000_000_000, 1, 2);
        for (lease_end, skew, plan_end, maximum, expected) in [
            (120, 10, 200, 30, 6_000_000_000),
            (200, 0, 107, 30, 8_000_000_000),
            (200, 0, 200, 3, 4_000_000_000),
        ] {
            let validity =
                ObservationValidity::from_bounds(initial, lease_end, skew, plan_end, maximum)
                    .unwrap();
            assert_eq!(validity.deadline(), expected);
            validity.check(clock(101, 2_000_000_000, 1, 2)).unwrap();
            assert_eq!(validity.deadline(), expected);
            assert!(validity.check(clock(101, expected, 1, 2)).is_err());
        }
    }

    #[test]
    fn expiry_rollback_divergence_boot_and_provenance_fail_closed() {
        let initial = clock(100, 10_000_000_000, 1, 2);
        let validity = ObservationValidity::from_bounds(initial, 200, 10, 200, 30).unwrap();
        for fresh in [
            clock(99, 11_000_000_000, 1, 2),
            clock(100, 9_999_999_999, 1, 2),
            clock(100, 13_000_000_001, 1, 2),
            clock(104, 11_000_000_000, 1, 2),
            clock(101, 11_000_000_000, 3, 2),
            clock(101, 11_000_000_000, 1, 3),
            clock(130, 39_999_999_999, 1, 2),
            clock(129, 40_000_000_000, 1, 2),
        ] {
            assert!(validity.check(fresh).is_err(), "accepted {fresh:?}");
        }
    }

    #[test]
    fn exhausted_intervals_and_arithmetic_overflow_are_rejected() {
        let initial = clock(100, 1_000_000_000, 1, 2);
        for (lease, skew, plan, maximum) in [
            (115, 10, 200, 30),
            (200, 0, 100, 30),
            (200, 0, 200, 0),
            (i64::MIN, 0, 200, 30),
            (200, u64::MAX, 200, 30),
        ] {
            assert!(ObservationValidity::from_bounds(initial, lease, skew, plan, maximum).is_err());
        }
        assert!(
            ObservationValidity::from_bounds(clock(100, u64::MAX, 1, 2), 200, 0, 200, 30).is_err()
        );
        assert!(
            ObservationValidity::from_bounds(clock(i64::MAX, 1, 1, 2), i64::MAX, 0, i64::MAX, 30)
                .is_err()
        );
    }
}
