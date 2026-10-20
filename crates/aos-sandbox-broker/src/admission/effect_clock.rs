//! Compares sampled clock DATA with the existing durable effect clock contract.
//!
//! Copying these fixed scalar facts supplies no effect authority. The genuine
//! broker still admits, commits and binds its original effect independently.
//! Both the ordinary checker and retained native-write borrowers use this sole
//! clock-policy body, including signed WALL caps and paired elapsed-time drift.

use aos_sandbox_core::{RawPairedClockSample, CLOCK_PAIR_TOLERANCE_NANOSECONDS};

use super::{BrokerAdmissionError, BrokerEffectClockDispositionV1, BrokerEffectIntentV1};

/// Holds the passive clock-comparison fields of one durable effect intent.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct BrokerEffectClockComparisonV3 {
    admitted_wall_seconds: i64,
    admitted_boottime_nanoseconds: u64,
    clock_provenance: [u8; 16],
    host_boot_id: [u8; 16],
    effect_deadline_boottime_nanoseconds: u64,
    plan_expires_seconds: i64,
    authority_expires_seconds: i64,
}

impl BrokerEffectClockComparisonV3 {
    /// Copies only comparison DATA from the caller's existing effect intent.
    pub fn from_effect(effect: &BrokerEffectIntentV1) -> Self {
        Self {
            admitted_wall_seconds: effect.admitted_wall_seconds(),
            admitted_boottime_nanoseconds: effect.admitted_boottime_nanoseconds(),
            clock_provenance: *effect.clock_provenance(),
            host_boot_id: *effect.host_boot_id(),
            effect_deadline_boottime_nanoseconds: effect.effect_deadline_boottime_nanoseconds(),
            plan_expires_seconds: effect.plan_expires_seconds(),
            authority_expires_seconds: effect.authority_expires_seconds(),
        }
    }

    /// Copies passive ongoing clock fields received from an existing owning caller.
    ///
    /// This supplies comparison DATA only. It admits no request or worker and
    /// grants no deadline; the independently owned ongoing permission remains
    /// mandatory. Ordinary effect classification refuses the zero local bound.
    #[must_use]
    pub fn from_original_clock_fields_data_v4(
        admitted: RawPairedClockSample,
        plan_expires_seconds: i64,
        authority_expires_seconds: i64,
    ) -> Self {
        Self {
            admitted_wall_seconds: admitted.wall_seconds(),
            admitted_boottime_nanoseconds: admitted.boottime_nanoseconds(),
            clock_provenance: admitted.provenance().as_bytes(),
            host_boot_id: admitted.host_boot_id(),
            effect_deadline_boottime_nanoseconds: 0,
            plan_expires_seconds,
            authority_expires_seconds,
        }
    }

    /// Applies the same expiry and continuity rules as the broker checker.
    ///
    /// # Errors
    /// Rejects boot/provenance substitution, backwards time, excessive paired
    /// drift or either signed WALL expiry preceding the BOOTTIME deadline.
    pub fn classify(
        &self,
        current_clock: &RawPairedClockSample,
    ) -> Result<BrokerEffectClockDispositionV1, BrokerAdmissionError> {
        let wall_elapsed = current_clock
            .wall_seconds()
            .checked_sub(self.admitted_wall_seconds)
            .and_then(|seconds| u64::try_from(seconds).ok())
            .and_then(|seconds| seconds.checked_mul(1_000_000_000))
            .ok_or(BrokerAdmissionError::FenceRejected)?;
        let boottime_elapsed = current_clock
            .boottime_nanoseconds()
            .checked_sub(self.admitted_boottime_nanoseconds)
            .ok_or(BrokerAdmissionError::FenceRejected)?;
        if current_clock.provenance().as_bytes() != self.clock_provenance
            || wall_elapsed.abs_diff(boottime_elapsed) > CLOCK_PAIR_TOLERANCE_NANOSECONDS
            || current_clock.host_boot_id() != self.host_boot_id
        {
            return Err(BrokerAdmissionError::FenceRejected);
        }

        if current_clock.boottime_nanoseconds() >= self.effect_deadline_boottime_nanoseconds {
            Ok(BrokerEffectClockDispositionV1::Expired)
        } else if current_clock.wall_seconds() >= self.plan_expires_seconds
            || current_clock.wall_seconds() >= self.authority_expires_seconds
        {
            // The BOOTTIME deadline is derived conservatively from both wall
            // expiries. Reaching either wall expiry first indicates clock
            // inconsistency, not a safe tombstone condition.
            Err(BrokerAdmissionError::FenceRejected)
        } else {
            Ok(BrokerEffectClockDispositionV1::Fresh)
        }
    }

    /// Compares DATA for a separately owned original ongoing permission.
    ///
    /// This projection does not widen the request-local effect or authorize any
    /// operation. Only a genuine owning caller may supply its independently
    /// admitted ongoing bound. Original boot, provenance, elapsed-pair rules and
    /// both signed WALL ceilings remain unchanged in the same checker.
    ///
    /// # Errors
    /// Rejects zero/expired ongoing bounds or any original signed clock refusal.
    pub fn require_original_ongoing_clock_data_v4(
        &self, current: &RawPairedClockSample, original_ongoing_deadline: u64,
    ) -> Result<(), BrokerAdmissionError> {
        if original_ongoing_deadline == 0 {
            return Err(BrokerAdmissionError::FenceRejected);
        }
        let comparison = Self {
            effect_deadline_boottime_nanoseconds: original_ongoing_deadline,
            ..*self
        };
        comparison.require_fresh(current)
    }

    /// Requires a fresh clock under the unchanged durable comparison contract.
    ///
    /// # Errors
    /// Rejects expiry or any continuity failure from [`Self::classify`].
    pub fn require_fresh(&self, current: &RawPairedClockSample) -> Result<(), BrokerAdmissionError> {
        match self.classify(current)? {
            BrokerEffectClockDispositionV1::Fresh => Ok(()),
            BrokerEffectClockDispositionV1::Expired => Err(BrokerAdmissionError::FenceRejected),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use aos_sandbox_core::RawClockProvenance;

    fn contract() -> BrokerEffectClockComparisonV3 {
        BrokerEffectClockComparisonV3 {
            admitted_wall_seconds: 100,
            admitted_boottime_nanoseconds: 1_000_000_000,
            clock_provenance: [7; 16],
            host_boot_id: [8; 16],
            effect_deadline_boottime_nanoseconds: 21_000_000_000,
            plan_expires_seconds: 110,
            authority_expires_seconds: 115,
        }
    }

    fn sample(wall: i64, boottime: u64) -> RawPairedClockSample {
        RawPairedClockSample::new_untrusted(
            RawClockProvenance::new_untrusted([7; 16]).unwrap(), [8; 16], wall, boottime,
        ).unwrap()
    }

    #[test]
    fn received_clock_fields_enforce_each_signed_wall_ceiling() {
        let admitted = sample(100, 1_000_000_000);
        for (plan, lease) in [(110, 115), (115, 110)] {
            let comparison = BrokerEffectClockComparisonV3::from_original_clock_fields_data_v4(admitted, plan, lease);
            comparison.require_original_ongoing_clock_data_v4(&sample(109, 10_000_000_000), 30_000_000_000).unwrap();
            assert!(comparison.require_original_ongoing_clock_data_v4(&sample(110, 11_000_000_000), 30_000_000_000).is_err());
            assert!(comparison.require_original_ongoing_clock_data_v4(&sample(109, 2_000_000_000), 30_000_000_000).is_err());
            assert_eq!(comparison.classify(&admitted), Ok(BrokerEffectClockDispositionV1::Expired));
        }
    }

    #[test]
    fn ongoing_projection_keeps_original_effect_and_both_signed_ceilings() {
        let mut original = contract();
        original.effect_deadline_boottime_nanoseconds = 5_000_000_000;
        let current = sample(106, 7_000_000_000);
        assert_eq!(original.classify(&current), Ok(BrokerEffectClockDispositionV1::Expired));

        original.require_original_ongoing_clock_data_v4(&current, 20_000_000_000).unwrap();
        assert_eq!(original.classify(&current), Ok(BrokerEffectClockDispositionV1::Expired));
        assert!(original.require_original_ongoing_clock_data_v4(&current, 0).is_err());
        assert!(original.require_original_ongoing_clock_data_v4(&current, 7_000_000_000).is_err());
        assert!(original.require_original_ongoing_clock_data_v4(
            &sample(110, 11_000_000_000), 20_000_000_000).is_err());

        let mut lease_first = original;
        lease_first.plan_expires_seconds = 120;
        lease_first.authority_expires_seconds = 110;
        assert!(lease_first.require_original_ongoing_clock_data_v4(
            &sample(110, 11_000_000_000), 20_000_000_000).is_err());
        let mut foreign = current;
        foreign = RawPairedClockSample::new_untrusted(
            foreign.provenance(), [99; 16], foreign.wall_seconds(), foreign.boottime_nanoseconds()).unwrap();
        assert!(original.require_original_ongoing_clock_data_v4(&foreign, 20_000_000_000).is_err());
    }

    #[test]
    fn wall_expiry_refuses_even_with_future_boottime_cutoff() {
        let comparison = contract();
        assert_eq!(comparison.classify(&sample(109, 10_000_000_000)),
            Ok(BrokerEffectClockDispositionV1::Fresh));
        assert_eq!(comparison.classify(&sample(110, 11_000_000_000)),
            Err(BrokerAdmissionError::FenceRejected));
        let mut lease_first = comparison;
        lease_first.plan_expires_seconds = 120;
        lease_first.authority_expires_seconds = 110;
        assert_eq!(lease_first.classify(&sample(110, 11_000_000_000)),
            Err(BrokerAdmissionError::FenceRejected));
    }

    #[test]
    fn paired_continuity_is_checked_before_expiry_classification() {
        let comparison = contract();
        assert_eq!(comparison.classify(&sample(101, 21_000_000_000)),
            Err(BrokerAdmissionError::FenceRejected));
        assert_eq!(comparison.classify(&sample(120, 21_000_000_000)),
            Ok(BrokerEffectClockDispositionV1::Expired));
    }
}
