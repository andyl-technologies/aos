//! Checks an original absolute continuation horizon at reached native frontiers.
//!
//! This is comparison DATA and a paid mechanical clock owner, not a payer or
//! proof constructor. A concrete purpose must derive the original sample and
//! cutoff from its real accepted admission, then tighten it with actual Root
//! policy/lease/Prepare expiry. It never installs a new relative deadline.

use aos_sandbox_model::{RawPairedClockSample, ResourceDimension as D, ResourceVector};
use std::error::Error;
use std::marker::PhantomData;
use std::mem::size_of;

use crate::controller_clock::{
    ContinuationClockErrorV1, RetainedControllerProtectedClockAttemptV1,
};
use crate::kernel_clock::{KernelPairedClockErrorV1, RetainedKernelPairedClockAttemptV1};

/// Carries an original comparison bound without currentness or authority.
pub struct RootContinuationHorizonDataV1<E> {
    original: RawPairedClockSample,
    cutoff: u64,
    wall_expires: Option<i64>,
    error: PhantomData<fn() -> E>,
}

impl<E> Copy for RootContinuationHorizonDataV1<E> {}

impl<E> Clone for RootContinuationHorizonDataV1<E> {
    fn clone(&self) -> Self {
        *self
    }
}

impl<E: ContinuationClockErrorV1> RootContinuationHorizonDataV1<E> {
    /// Checks passive original fields; the purpose separately proves provenance.
    ///
    /// # Errors
    /// Refuses a cutoff at or before the original sample.
    pub fn from_original_data_v1(original: RawPairedClockSample, cutoff: u64) -> Result<Self, E> {
        if cutoff <= original.boottime_nanoseconds() {
            return Err(E::protected_boundary());
        }
        Ok(Self {
            original,
            cutoff,
            wall_expires: None,
            error: PhantomData,
        })
    }

    /// Narrows comparison DATA with an already authenticated wall expiry.
    ///
    /// The concrete purpose supplies its retained policy/lease/plan original;
    /// this method cannot grant authority or extend either existing bound.
    pub fn with_wall_expiry_data_v1(mut self, expires: i64) -> Self {
        self.wall_expires = Some(self.wall_expires.map_or(expires, |old| old.min(expires)));
        self
    }

    /// Checks that a passive request cutoff remains inside the original bound.
    ///
    /// # Errors
    /// Refuses a cutoff outside the original strict interval.
    pub fn require_narrowed_cutoff_data_v2(self, cutoff: u64) -> Result<(), E> {
        if cutoff <= self.original.boottime_nanoseconds() || cutoff > self.cutoff {
            return Err(E::protected_boundary());
        }
        Ok(())
    }

    /// Checks a sample against the retained boot, progression, and strict bounds.
    ///
    /// # Errors
    /// Refuses a changed clock origin, invalid progression, or expired bound.
    pub fn require_sample_v1(self, sample: RawPairedClockSample) -> Result<(), E> {
        self.original
            .validate_later_sample(sample)
            .map_err(|_| E::protected_boundary())?;
        if sample.boottime_nanoseconds() >= self.cutoff
            || self
                .wall_expires
                .is_some_and(|expires| sample.wall_seconds() >= expires)
        {
            return Err(E::protected_boundary());
        }
        Ok(())
    }
}

/// Retains the fixed native source, strict original horizon, and failed prefix.
///
/// The two diagnostic parameters preserve caller error categories; they cannot
/// provide observations, change the finite source choice, or authorize work.
pub struct RootContinuationClockGateV1<K, E> {
    horizon: RootContinuationHorizonDataV1<E>,
    latest: RawPairedClockSample,
    source: ContinuationClockSourceV1,
    current: Option<Box<ContinuationClockOriginalV1<K, E>>>,
    observed: Option<Result<RawPairedClockSample, K>>,
    comparison: Option<Result<(), E>>,
}

#[derive(Clone, Copy)]
enum ContinuationClockSourceV1 {
    Kernel,
    ControllerAuthorization,
}

enum ContinuationClockOriginalV1<K, E> {
    Kernel(RetainedKernelPairedClockAttemptV1<K>),
    ControllerAuthorization(RetainedControllerProtectedClockAttemptV1<E>),
}

impl ContinuationClockSourceV1 {
    fn destination_v1<K, E>(self) -> ContinuationClockOriginalV1<K, E> {
        match self {
            Self::Kernel => ContinuationClockOriginalV1::Kernel(Default::default()),
            Self::ControllerAuthorization => {
                ContinuationClockOriginalV1::ControllerAuthorization(Default::default())
            }
        }
    }
}

impl<K: KernelPairedClockErrorV1, E: ContinuationClockErrorV1> ContinuationClockOriginalV1<K, E> {
    fn observe_once_v1(
        &mut self,
        original: RawPairedClockSample,
    ) -> Result<RawPairedClockSample, K> {
        match self {
            Self::Kernel(clock) => clock.observe_once(Some(original)),
            Self::ControllerAuthorization(clock) => clock.observe_once_v1().map_err(|_| K::stale()),
        }
    }

    fn failure(&self) -> Option<&(dyn Error + 'static)> {
        match self {
            Self::Kernel(clock) => clock.failure(),
            Self::ControllerAuthorization(clock) => clock.failure(),
        }
    }
}

impl<K: KernelPairedClockErrorV1, E: ContinuationClockErrorV1> RootContinuationClockGateV1<K, E> {
    /// Borrows the unchanged, paid Root opening origin as comparison DATA.
    pub fn original_sample_data_v1(&self) -> RawPairedClockSample {
        self.horizon.original
    }

    /// Joins an earlier client origin to this independently sampled opening.
    ///
    /// This passive comparison neither samples nor extends the retained gate.
    ///
    /// # Errors
    /// Refuses a foreign opening origin or a request cutoff outside the bound.
    pub fn require_opening_cutoff_data_v2(
        &self,
        original: RawPairedClockSample,
        cutoff: u64,
    ) -> Result<(), E> {
        original
            .validate_later_sample(self.horizon.original)
            .map_err(|_| E::protected_boundary())?;
        self.horizon.require_narrowed_cutoff_data_v2(cutoff)
    }

    /// Constructs an inert gate for the existing fixed kernel sampler.
    ///
    /// The caller retains the original purpose and pays `receiving_demand_v1`
    /// before any native destination is constructed by `check_next_once_v1`.
    pub fn new(horizon: RootContinuationHorizonDataV1<E>) -> Self {
        Self {
            latest: horizon.original,
            horizon,
            source: ContinuationClockSourceV1::Kernel,
            current: None,
            observed: None,
            comparison: None,
        }
    }

    /// Keeps the genuine Controller authorization clock source on its horizon.
    pub fn new_controller_authorization_v1(horizon: RootContinuationHorizonDataV1<E>) -> Self {
        Self {
            source: ContinuationClockSourceV1::ControllerAuthorization,
            ..Self::new(horizon)
        }
    }

    /// Narrows this same original gate after actual policy/input verification.
    ///
    /// A foreign origin or already failed native destination stays refused.
    ///
    /// # Errors
    /// Refuses an entered native destination, foreign origin, or narrowed expiry.
    pub fn narrow_horizon_data_v1(
        &mut self,
        horizon: RootContinuationHorizonDataV1<E>,
    ) -> Result<(), E> {
        if self.current.is_some() || self.horizon.original != horizon.original {
            self.comparison = Some(Err(E::protected_boundary()));
            return Err(E::protected_boundary());
        }
        self.horizon.cutoff = self.horizon.cutoff.min(horizon.cutoff);
        if let Some(expires) = horizon.wall_expires {
            self.narrow_wall_expiry_data_v1(expires);
        }
        self.comparison = Some(self.horizon.require_sample_v1(self.latest));
        if !matches!(self.comparison, Some(Ok(()))) {
            return Err(E::protected_boundary());
        }
        self.comparison = None;
        Ok(())
    }

    /// Narrows only D while retaining this gate's actual sampled Root origin.
    /// An earlier Controller sample need not equal the independently sampled
    /// Root origin. Containment alone does not change a bound; this adapter
    /// enters the same narrowing engine after checking the unchanged origin.
    ///
    /// # Errors
    /// Refuses an existing failure, widened cutoff, or expired narrowed bound.
    pub fn narrow_original_cutoff_data_v2(&mut self, cutoff: u64) -> Result<(), E> {
        if self.failure().is_some() {
            return Err(E::protected_boundary());
        }
        self.comparison = Some(self.horizon.require_narrowed_cutoff_data_v2(cutoff));
        if !matches!(self.comparison, Some(Ok(()))) {
            return Err(E::protected_boundary());
        }
        self.narrow_horizon_data_v1(RootContinuationHorizonDataV1 {
            cutoff,
            ..self.horizon
        })
    }

    /// Tightens the same gate without sampling, decoding or renewing a horizon.
    pub fn narrow_wall_expiry_data_v1(&mut self, expires: i64) {
        self.horizon = self.horizon.with_wall_expiry_data_v1(expires);
    }

    /// Returns the kernel sampler and actual retained construction carriers.
    ///
    /// # Errors
    /// Refuses arithmetic overflow with the caller's existing size diagnostic.
    pub fn receiving_demand_v1() -> Result<ResourceVector, E> {
        let bytes = RetainedKernelPairedClockAttemptV1::<K>::dominant_requested_bytes_v1()
            .and_then(|bytes| bytes.checked_add(size_of::<ContinuationClockOriginalV1<K, E>>()))
            .and_then(|bytes| bytes.checked_add(2 * size_of::<Self>()))
            .and_then(|bytes| u64::try_from(bytes).ok())
            .ok_or(E::journal_too_large())?;
        Ok(ResourceVector::ZERO.with(D::MemoryBytes, bytes).with(
            D::OpenFiles,
            RetainedKernelPairedClockAttemptV1::<K>::MAXIMUM_RETAINED_FILES_V1 as u64,
        ))
    }

    /// Returns the Controller sampler and actual retained construction carriers.
    ///
    /// # Errors
    /// Refuses native supplier or construction-carrier arithmetic overflow.
    pub fn controller_authorization_receiving_demand_v1() -> Result<ResourceVector, E> {
        let native = RetainedControllerProtectedClockAttemptV1::<E>::receiving_demand_v1()?;
        let carrier = size_of::<ContinuationClockOriginalV1<K, E>>()
            .checked_add(2 * size_of::<Self>())
            .and_then(|bytes| u64::try_from(bytes).ok())
            .ok_or(E::journal_too_large())?;
        native
            .checked_add(ResourceVector::ZERO.with(D::MemoryBytes, carrier))
            .map_err(|_| E::journal_too_large())
    }

    /// Samples the same finite native source at the next reached frontier.
    ///
    /// A positive native/comparison graph retires before the next frontier.
    /// Every failed destination remains resident and prevents reentry.
    ///
    /// # Errors
    /// Refuses a retained failure, native acquisition failure, invalid clock
    /// progression, or expiry. `failure` borrows the actual selected cause.
    pub fn check_next_once_v1(&mut self) -> Result<RawPairedClockSample, E> {
        // A failed native or comparison owner never disappears or rearms.
        if self.current.is_some() {
            return Err(E::protected_boundary());
        }
        self.current = Some(Box::new(self.source.destination_v1()));
        self.observed = Some(
            self.current
                .as_mut()
                .ok_or(E::protected_boundary())?
                .observe_once_v1(self.latest),
        );
        let sample = *self
            .observed
            .as_ref()
            .and_then(|sample| sample.as_ref().ok())
            .ok_or(E::protected_boundary())?;
        self.comparison = Some(
            self.latest
                .validate_later_sample(sample)
                .map_err(|_| E::protected_boundary())
                .and_then(|()| self.horizon.require_sample_v1(sample)),
        );
        if !matches!(self.comparison, Some(Ok(()))) {
            return Err(E::protected_boundary());
        }
        if self
            .current
            .as_ref()
            .is_some_and(|clock| clock.failure().is_some())
        {
            return Err(E::protected_boundary());
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

    /// Compares an independently observed final sample without native IO.
    ///
    /// # Errors
    /// Refuses a retained native destination, foreign clock, or expired bound.
    pub fn require_final_sample_v1(&self, sample: RawPairedClockSample) -> Result<(), E> {
        if self.current.is_some() {
            return Err(E::protected_boundary());
        }
        self.latest
            .validate_later_sample(sample)
            .map_err(|_| E::protected_boundary())?;
        self.horizon.require_sample_v1(sample)
    }

    /// Borrows the retained native, observation, or comparison cause in order.
    pub fn failure(&self) -> Option<&(dyn Error + 'static)> {
        self.current
            .as_ref()
            .and_then(|clock| clock.failure())
            .or_else(|| {
                self.observed
                    .as_ref()?
                    .as_ref()
                    .err()
                    .map(|cause| cause as _)
            })
            .or_else(|| {
                self.comparison
                    .as_ref()?
                    .as_ref()
                    .err()
                    .map(|cause| cause as _)
            })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[derive(Debug, thiserror::Error)]
    enum TestError {
        #[error("protected boundary")]
        ProtectedBoundary,
        #[error("journal too large")]
        JournalTooLarge,
        #[error("stale clock")]
        Stale,
        #[error(transparent)]
        Kernel(#[from] aos_linux_descriptors::Error),
    }

    impl ContinuationClockErrorV1 for TestError {
        fn protected_boundary() -> Self {
            Self::ProtectedBoundary
        }
        fn journal_too_large() -> Self {
            Self::JournalTooLarge
        }
    }

    impl KernelPairedClockErrorV1 for TestError {
        fn stale() -> Self {
            Self::Stale
        }
        fn kernel(error: aos_linux_descriptors::Error) -> Self {
            Self::Kernel(error)
        }
    }

    type JournalError = TestError;
    type RootContinuationHorizonDataV1 = super::RootContinuationHorizonDataV1<TestError>;
    type RootContinuationClockGateV1 = super::RootContinuationClockGateV1<TestError, TestError>;
    type RetainedControllerProtectedClockAttemptV1 =
        crate::controller_clock::RetainedControllerProtectedClockAttemptV1<TestError>;
    use aos_sandbox_model::RawClockProvenance;

    fn sample(wall: i64, boot: u64) -> RawPairedClockSample {
        RawPairedClockSample::new_untrusted(
            RawClockProvenance::new_untrusted([1; 16]).unwrap(),
            [2; 16],
            wall,
            boot * 1_000_000_000,
        )
        .unwrap()
    }

    #[test]
    fn earlier_client_d_really_narrows_the_same_later_root_origin() {
        let earlier = sample(100, 10);
        let root = sample(110, 20);
        assert!(earlier.validate_later_sample(root).is_ok());
        assert!(earlier.validate_later_sample(sample(101, 20)).is_err());
        let original =
            RootContinuationHorizonDataV1::from_original_data_v1(root, 90_000_000_000).unwrap();
        let mut gate = RootContinuationClockGateV1::new(original);
        gate.require_opening_cutoff_data_v2(earlier, 40_000_000_000)
            .unwrap();
        assert!(gate.require_final_sample_v1(sample(140, 50)).is_ok());

        gate.narrow_original_cutoff_data_v2(40_000_000_000).unwrap();

        assert!(gate.require_final_sample_v1(sample(120, 30)).is_ok());
        assert!(gate.require_final_sample_v1(sample(130, 40)).is_err());
        assert!(gate.require_final_sample_v1(sample(140, 50)).is_err());
        assert!(gate.narrow_original_cutoff_data_v2(80_000_000_000).is_err());
        let first = gate.failure().unwrap() as *const dyn std::error::Error as *const ();
        assert!(gate.narrow_original_cutoff_data_v2(35_000_000_000).is_err());
        assert_eq!(
            first,
            gate.failure().unwrap() as *const dyn std::error::Error as *const ()
        );
    }

    #[test]
    fn request_cutoff_may_narrow_but_never_restart_the_original_horizon() {
        let horizon =
            RootContinuationHorizonDataV1::from_original_data_v1(sample(100, 10), 20_000_000_000)
                .unwrap();

        assert!(
            horizon
                .require_narrowed_cutoff_data_v2(11_000_000_000)
                .is_ok()
        );
        assert!(
            horizon
                .require_narrowed_cutoff_data_v2(20_000_000_000)
                .is_ok()
        );
        assert!(
            horizon
                .require_narrowed_cutoff_data_v2(10_000_000_000)
                .is_err()
        );
        assert!(
            horizon
                .require_narrowed_cutoff_data_v2(20_000_000_001)
                .is_err()
        );
    }

    #[test]
    fn body_bound_joins_the_distinct_later_opening_without_extending_it() {
        let original = sample(100, 10);
        let gate = RootContinuationClockGateV1::new(
            RootContinuationHorizonDataV1::from_original_data_v1(sample(101, 11), 20_000_000_000)
                .unwrap(),
        );

        assert!(
            gate.require_opening_cutoff_data_v2(original, 19_000_000_000)
                .is_ok()
        );
        assert!(
            gate.require_opening_cutoff_data_v2(original, 20_000_000_001)
                .is_err()
        );
        assert!(
            gate.require_opening_cutoff_data_v2(sample(102, 12), 19_000_000_000)
                .is_err()
        );
        assert!(gate.current.is_none());
        assert_eq!(gate.latest, sample(101, 11));
    }

    #[test]
    fn wall_authority_remains_strict_inside_allowed_clock_divergence() {
        let origin = sample(100, 10);
        let later = sample(120, 28);
        let horizon =
            RootContinuationHorizonDataV1::from_original_data_v1(origin, 29_000_000_000).unwrap();

        assert!(origin.validate_later_sample(later).is_ok());
        assert!(horizon.require_sample_v1(later).is_ok());
        assert!(
            horizon
                .with_wall_expiry_data_v1(120)
                .require_sample_v1(later)
                .is_err()
        );
    }

    #[test]
    fn later_expiry_data_never_extends_a_retained_wall_bound() {
        let horizon =
            RootContinuationHorizonDataV1::from_original_data_v1(sample(100, 10), 40_000_000_000)
                .unwrap()
                .with_wall_expiry_data_v1(120)
                .with_wall_expiry_data_v1(130);

        assert!(horizon.require_sample_v1(sample(120, 29)).is_err());
        assert!(horizon.require_sample_v1(sample(119, 28)).is_ok());
    }

    #[test]
    fn authorization_horizon_preserves_its_genuine_clock_source() {
        let origin = RawPairedClockSample::new_untrusted(
            RawClockProvenance::new_untrusted(*b"aos-cli-clock-v1").unwrap(),
            [2; 16],
            100,
            10_000_000_000,
        )
        .unwrap();
        let same_source = RawPairedClockSample::new_untrusted(
            RawClockProvenance::new_untrusted(*b"aos-cli-clock-v1").unwrap(),
            [2; 16],
            101,
            11_000_000_000,
        )
        .unwrap();
        let other_source = RawPairedClockSample::new_untrusted(
            RawClockProvenance::new_untrusted(*b"aos-kernel-clock").unwrap(),
            [2; 16],
            101,
            11_000_000_000,
        )
        .unwrap();
        let horizon =
            RootContinuationHorizonDataV1::from_original_data_v1(origin, 75_000_000_000).unwrap();

        assert!(horizon.require_sample_v1(same_source).is_ok());
        assert!(horizon.require_sample_v1(other_source).is_err());
    }

    #[test]
    fn failed_primary_gate_does_not_suppress_a_distinct_final_native_destination() {
        let mut opening = RetainedControllerProtectedClockAttemptV1::default();
        let origin = opening.observe_once_v1().unwrap();
        let horizon = RootContinuationHorizonDataV1::from_original_data_v1(
            origin,
            origin
                .boottime_nanoseconds()
                .checked_add(65_000_000_000)
                .unwrap(),
        )
        .unwrap();
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
