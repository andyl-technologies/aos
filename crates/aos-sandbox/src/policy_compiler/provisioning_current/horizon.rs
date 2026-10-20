//! Checks an original absolute continuation horizon at reached native frontiers.
//!
//! This is comparison DATA and a paid mechanical clock owner, not a payer or
//! proof constructor. A concrete purpose must derive the original sample and
//! cutoff from its real accepted admission, then tighten it with actual Root
//! policy/lease/Prepare expiry. It never installs a new relative deadline.

use std::error::Error;
use std::mem::size_of;
use aos_sandbox_core::{RawPairedClockSample, ResourceDimension as D, ResourceVector};
use crate::journal::JournalError;
use crate::hierarchy::genesis_profile::SourceGenesisErrorV1;
use crate::policy_compiler::RetainedKernelPairedClockAttemptV1;

/// Carries an original comparison bound without currentness or authority.
#[derive(Clone, Copy)]
pub(crate) struct RootContinuationHorizonDataV1 {
    original: RawPairedClockSample,
    cutoff: u64,
    wall_expires: Option<i64>,
}

impl RootContinuationHorizonDataV1 {
    /// Checks passive original fields; the purpose separately proves provenance.
    pub(crate) fn from_original_data_v1(original: RawPairedClockSample, cutoff: u64)
        -> Result<Self, JournalError>
    {
        if cutoff <= original.boottime_nanoseconds() { return Err(JournalError::ProtectedBoundary); }
        Ok(Self { original, cutoff, wall_expires: None })
    }

    /// Narrows comparison DATA with an already authenticated wall expiry.
    ///
    /// The concrete purpose supplies its retained policy/lease/plan original;
    /// this method cannot grant authority or extend either existing bound.
    pub(crate) fn with_wall_expiry_data_v1(mut self, expires: i64) -> Self {
        self.wall_expires = Some(self.wall_expires.map_or(expires, |old| old.min(expires)));
        self
    }

    /// Checks that a passive request cutoff remains inside the original bound.
    pub(crate) fn require_narrowed_cutoff_data_v2(self, cutoff: u64) -> Result<(), JournalError> {
        if cutoff <= self.original.boottime_nanoseconds() || cutoff > self.cutoff {
            return Err(JournalError::ProtectedBoundary);
        }
        Ok(())
    }

    pub(crate) fn require_sample_v1(self, sample: RawPairedClockSample) -> Result<(), JournalError> {
        self.original.validate_later_sample(sample).map_err(|_| JournalError::ProtectedBoundary)?;
        if sample.boottime_nanoseconds() >= self.cutoff
            || self.wall_expires.is_some_and(|expires| sample.wall_seconds() >= expires) {
            return Err(JournalError::ProtectedBoundary);
        }
        Ok(())
    }
}

pub(crate) struct RootContinuationClockGateV1 {
    horizon: RootContinuationHorizonDataV1,
    latest: RawPairedClockSample,
    source: ContinuationClockSourceV1,
    current: Option<Box<ContinuationClockOriginalV1>>,
    observed: Option<Result<RawPairedClockSample, SourceGenesisErrorV1>>,
    comparison: Option<Result<(), JournalError>>,
}

#[derive(Clone, Copy)]
enum ContinuationClockSourceV1 {
    Kernel,
    ControllerAuthorization,
}

enum ContinuationClockOriginalV1 {
    Kernel(RetainedKernelPairedClockAttemptV1),
    ControllerAuthorization(crate::controller::RetainedControllerProtectedClockAttemptV1),
}

impl ContinuationClockSourceV1 {
    fn destination_v1(self) -> ContinuationClockOriginalV1 {
        match self {
            Self::Kernel => ContinuationClockOriginalV1::Kernel(Default::default()),
            Self::ControllerAuthorization => ContinuationClockOriginalV1::ControllerAuthorization(Default::default()),
        }
    }
}

impl ContinuationClockOriginalV1 {
    fn observe_once_v1(&mut self, original: RawPairedClockSample)
        -> Result<RawPairedClockSample, SourceGenesisErrorV1> {
        match self {
            Self::Kernel(clock) => clock.observe_once(Some(original)),
            Self::ControllerAuthorization(clock) => clock.observe_once_v1()
                .map_err(|_| SourceGenesisErrorV1::Stale),
        }
    }

    fn failure(&self) -> Option<&(dyn Error + 'static)> {
        match self {
            Self::Kernel(clock) => clock.failure(),
            Self::ControllerAuthorization(clock) => clock.failure(),
        }
    }
}

impl RootContinuationClockGateV1 {
    /// Borrows the unchanged, paid Root opening origin as comparison DATA.
    pub(crate) fn original_sample_data_v1(&self) -> RawPairedClockSample {
        self.horizon.original
    }

    /// Joins an earlier client origin to this independently sampled opening.
    ///
    /// This passive comparison neither samples nor extends the retained gate.
    pub(crate) fn require_opening_cutoff_data_v2(
        &self, original: RawPairedClockSample, cutoff: u64,
    ) -> Result<(), JournalError> {
        original.validate_later_sample(self.horizon.original)
            .map_err(|_| JournalError::ProtectedBoundary)?;
        self.horizon.require_narrowed_cutoff_data_v2(cutoff)
    }

    pub(crate) fn new(horizon: RootContinuationHorizonDataV1) -> Self {
        Self { latest: horizon.original, horizon, source: ContinuationClockSourceV1::Kernel,
            current: None, observed: None, comparison: None }
    }

    /// Keeps the genuine Controller authorization clock source on its horizon.
    pub(crate) fn new_controller_authorization_v1(horizon: RootContinuationHorizonDataV1) -> Self {
        Self { source: ContinuationClockSourceV1::ControllerAuthorization, ..Self::new(horizon) }
    }

    /// Narrows this same original gate after actual policy/input verification.
    ///
    /// A foreign origin or already failed native destination stays refused.
    pub(crate) fn narrow_horizon_data_v1(&mut self, horizon: RootContinuationHorizonDataV1)
        -> Result<(), JournalError> {
        if self.current.is_some() || self.horizon.original != horizon.original {
            self.comparison = Some(Err(JournalError::ProtectedBoundary));
            return Err(JournalError::ProtectedBoundary);
        }
        self.horizon.cutoff = self.horizon.cutoff.min(horizon.cutoff);
        if let Some(expires) = horizon.wall_expires {
            self.narrow_wall_expiry_data_v1(expires);
        }
        self.comparison = Some(self.horizon.require_sample_v1(self.latest));
        if !matches!(self.comparison, Some(Ok(()))) {
            return Err(JournalError::ProtectedBoundary);
        }
        self.comparison = None;
        Ok(())
    }

    /// Narrows only D while retaining this gate's actual sampled Root origin.
    /// An earlier Controller sample need not equal the independently sampled
    /// Root origin. Containment alone does not change a bound; this adapter
    /// enters the same narrowing engine after checking the unchanged origin.
    pub(crate) fn narrow_original_cutoff_data_v2(&mut self, cutoff: u64)
        -> Result<(), JournalError> {
        if self.failure().is_some() {
            return Err(JournalError::ProtectedBoundary);
        }
        self.comparison = Some(self.horizon.require_narrowed_cutoff_data_v2(cutoff));
        if !matches!(self.comparison, Some(Ok(()))) {
            return Err(JournalError::ProtectedBoundary);
        }
        self.narrow_horizon_data_v1(RootContinuationHorizonDataV1 {
            cutoff, ..self.horizon
        })
    }

    /// Tightens the same gate without sampling, decoding or renewing a horizon.
    pub(crate) fn narrow_wall_expiry_data_v1(&mut self, expires: i64) {
        self.horizon = self.horizon.with_wall_expiry_data_v1(expires);
    }

    pub(crate) fn receiving_demand_v1() -> Result<ResourceVector, JournalError> {
        let bytes = RetainedKernelPairedClockAttemptV1::dominant_requested_bytes_v1()
            .and_then(|bytes| bytes.checked_add(size_of::<ContinuationClockOriginalV1>()))
            .and_then(|bytes| bytes.checked_add(2 * size_of::<Self>()))
            .and_then(|bytes| u64::try_from(bytes).ok()).ok_or(JournalError::JournalTooLarge)?;
        Ok(ResourceVector::ZERO.with(D::MemoryBytes, bytes).with(D::OpenFiles,
            RetainedKernelPairedClockAttemptV1::MAXIMUM_RETAINED_FILES_V1 as u64))
    }

    pub(crate) fn controller_authorization_receiving_demand_v1() -> Result<ResourceVector, JournalError> {
        let native = crate::controller::RetainedControllerProtectedClockAttemptV1::receiving_demand_v1()?;
        let carrier = size_of::<ContinuationClockOriginalV1>()
            .checked_add(2 * size_of::<Self>()).and_then(|bytes| u64::try_from(bytes).ok())
            .ok_or(JournalError::JournalTooLarge)?;
        native.checked_add(ResourceVector::ZERO.with(D::MemoryBytes, carrier))
            .map_err(|_| JournalError::JournalTooLarge)
    }

    pub(crate) fn check_next_once_v1(&mut self) -> Result<RawPairedClockSample, JournalError> {
        // A failed native or comparison owner never disappears or rearms.
        if self.current.is_some() { return Err(JournalError::ProtectedBoundary); }
        self.current = Some(Box::new(self.source.destination_v1()));
        self.observed = Some(self.current.as_mut().ok_or(JournalError::ProtectedBoundary)?
            .observe_once_v1(self.latest));
        let sample = *self.observed.as_ref().and_then(|sample| sample.as_ref().ok())
            .ok_or(JournalError::ProtectedBoundary)?;
        self.comparison = Some(self.latest.validate_later_sample(sample)
            .map_err(|_| JournalError::ProtectedBoundary)
            .and_then(|()| self.horizon.require_sample_v1(sample)));
        if !matches!(self.comparison, Some(Ok(()))) { return Err(JournalError::ProtectedBoundary); }
        if self.current.as_ref().is_some_and(|clock| clock.failure().is_some()) {
            return Err(JournalError::ProtectedBoundary);
        }
        self.latest = sample;
        // The selected native sampler already retired its positive boot files
        // before returning this sample. Complete comparison now precedes
        // physical disposal of the positive control/Results. One prepaid peak
        // can serve the next frontier; no financial refund or failed-row reset.
        drop(self.current.take());
        self.observed = None;
        self.comparison = None;
        Ok(sample)
    }

    pub(crate) fn require_final_sample_v1(&self, sample: RawPairedClockSample) -> Result<(), JournalError> {
        if self.current.is_some() { return Err(JournalError::ProtectedBoundary); }
        self.latest.validate_later_sample(sample).map_err(|_| JournalError::ProtectedBoundary)?;
        self.horizon.require_sample_v1(sample)
    }

    pub(crate) fn failure(&self) -> Option<&(dyn Error + 'static)> {
        self.current.as_ref().and_then(|clock| clock.failure())
            .or_else(|| self.observed.as_ref()?.as_ref().err().map(|cause| cause as _))
            .or_else(|| self.comparison.as_ref()?.as_ref().err().map(|cause| cause as _))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use aos_sandbox_core::RawClockProvenance;

    fn sample(wall: i64, boot: u64) -> RawPairedClockSample {
        RawPairedClockSample::new_untrusted(
            RawClockProvenance::new_untrusted([1; 16]).unwrap(), [2; 16],
            wall, boot * 1_000_000_000,
        ).unwrap()
    }

    #[test]
    fn earlier_client_d_really_narrows_the_same_later_root_origin() {
        let earlier = sample(100, 10);
        let root = sample(110, 20);
        assert!(earlier.validate_later_sample(root).is_ok());
        assert!(earlier.validate_later_sample(sample(101, 20)).is_err());
        let original = RootContinuationHorizonDataV1::from_original_data_v1(root, 90_000_000_000).unwrap();
        let mut gate = RootContinuationClockGateV1::new(original);
        gate.require_opening_cutoff_data_v2(earlier, 40_000_000_000).unwrap();
        assert!(gate.require_final_sample_v1(sample(140, 50)).is_ok());

        gate.narrow_original_cutoff_data_v2(40_000_000_000).unwrap();

        assert!(gate.require_final_sample_v1(sample(120, 30)).is_ok());
        assert!(gate.require_final_sample_v1(sample(130, 40)).is_err());
        assert!(gate.require_final_sample_v1(sample(140, 50)).is_err());
        assert!(gate.narrow_original_cutoff_data_v2(80_000_000_000).is_err());
        let first = gate.failure().unwrap() as *const dyn std::error::Error as *const ();
        assert!(gate.narrow_original_cutoff_data_v2(35_000_000_000).is_err());
        assert_eq!(first, gate.failure().unwrap() as *const dyn std::error::Error as *const ());
    }

    #[test]
    fn request_cutoff_may_narrow_but_never_restart_the_original_horizon() {
        let horizon = RootContinuationHorizonDataV1::from_original_data_v1(
            sample(100, 10), 20_000_000_000,
        ).unwrap();

        assert!(horizon.require_narrowed_cutoff_data_v2(11_000_000_000).is_ok());
        assert!(horizon.require_narrowed_cutoff_data_v2(20_000_000_000).is_ok());
        assert!(horizon.require_narrowed_cutoff_data_v2(10_000_000_000).is_err());
        assert!(horizon.require_narrowed_cutoff_data_v2(20_000_000_001).is_err());
    }

    #[test]
    fn body_bound_joins_the_distinct_later_opening_without_extending_it() {
        let original = sample(100, 10);
        let gate = RootContinuationClockGateV1::new(
            RootContinuationHorizonDataV1::from_original_data_v1(
                sample(101, 11), 20_000_000_000,
            ).unwrap(),
        );

        assert!(gate.require_opening_cutoff_data_v2(original, 19_000_000_000).is_ok());
        assert!(gate.require_opening_cutoff_data_v2(original, 20_000_000_001).is_err());
        assert!(gate.require_opening_cutoff_data_v2(sample(102, 12), 19_000_000_000).is_err());
        assert!(gate.current.is_none());
        assert_eq!(gate.latest, sample(101, 11));
    }

    #[test]
    fn wall_authority_remains_strict_inside_allowed_clock_divergence() {
        let origin = sample(100, 10);
        let later = sample(120, 28);
        let horizon = RootContinuationHorizonDataV1::from_original_data_v1(
            origin, 29_000_000_000,
        ).unwrap();

        assert!(origin.validate_later_sample(later).is_ok());
        assert!(horizon.require_sample_v1(later).is_ok());
        assert!(horizon.with_wall_expiry_data_v1(120).require_sample_v1(later).is_err());
    }

    #[test]
    fn later_expiry_data_never_extends_a_retained_wall_bound() {
        let horizon = RootContinuationHorizonDataV1::from_original_data_v1(
            sample(100, 10), 40_000_000_000,
        ).unwrap().with_wall_expiry_data_v1(120).with_wall_expiry_data_v1(130);

        assert!(horizon.require_sample_v1(sample(120, 29)).is_err());
        assert!(horizon.require_sample_v1(sample(119, 28)).is_ok());
    }

    #[test]
    fn authorization_horizon_preserves_its_genuine_clock_source() {
        let origin = RawPairedClockSample::new_untrusted(
            RawClockProvenance::new_untrusted(*b"aos-cli-clock-v1").unwrap(),
            [2; 16], 100, 10_000_000_000,
        ).unwrap();
        let same_source = RawPairedClockSample::new_untrusted(
            RawClockProvenance::new_untrusted(*b"aos-cli-clock-v1").unwrap(),
            [2; 16], 101, 11_000_000_000,
        ).unwrap();
        let other_source = RawPairedClockSample::new_untrusted(
            RawClockProvenance::new_untrusted(*b"aos-kernel-clock").unwrap(),
            [2; 16], 101, 11_000_000_000,
        ).unwrap();
        let horizon = RootContinuationHorizonDataV1::from_original_data_v1(origin, 75_000_000_000).unwrap();

        assert!(horizon.require_sample_v1(same_source).is_ok());
        assert!(horizon.require_sample_v1(other_source).is_err());
    }

    #[test]
    fn failed_primary_gate_does_not_suppress_a_distinct_final_native_destination() {
        use crate::controller::RetainedControllerProtectedClockAttemptV1;
        let mut opening = RetainedControllerProtectedClockAttemptV1::default();
        let origin = opening.observe_once_v1().unwrap();
        let horizon = RootContinuationHorizonDataV1::from_original_data_v1(
            origin, origin.boottime_nanoseconds().checked_add(65_000_000_000).unwrap(),
        ).unwrap();
        let mut primary = RootContinuationClockGateV1::new_controller_authorization_v1(horizon);
        // A failed primary retains its selected destination and cannot rearm.
        primary.current = Some(Box::new(primary.source.destination_v1()));
        primary.comparison = Some(Err(JournalError::ProtectedBoundary));
        assert!(primary.check_next_once_v1().is_err());

        let mut final_native = RetainedControllerProtectedClockAttemptV1::default();
        let sample = final_native.observe_once_v1().unwrap();

        assert!(origin.validate_later_sample(sample).is_ok());
        assert!(final_native.failure().is_none());
        assert!(primary.require_final_sample_v1(sample).is_err());
        assert!(primary.failure().is_some());
    }
}
