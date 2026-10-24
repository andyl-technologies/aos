//! Keeps the two genuine Root input/publication current-loan positions distinct.
//!
//! Input retains the actual target. Publication excludes it so the same target
//! may be mutably appended while independent Authority/gen1 and Origin remain
//! borrowed. Both positions originate only after the actual same-financial join.

use super::super::RootPolicyTargetOriginalV1;
use super::{RootPolicyPublicationErrorV1 as ErrorV1, retain_model_verification_v1};
use crate::native::authority::{RootAuthorityGen1LoanV1, RootAuthorityQ04FlightOriginalV1};
use crate::native::journal::PolicyJournalStorageV1;
use aos_sandbox_broker::receiving::{RootQ04OriginBorrowerV1, RootQ04OriginPurposeV1};
use aos_sandbox_model::RawPairedClockSample;
use aos_sandbox_protocol::domain_ledger::create_q04_history::Q04CutIdentityV1;
use std::cell::RefCell;
use std::panic::{AssertUnwindSafe, catch_unwind, resume_unwind};

type Cause = std::sync::OnceLock<ErrorV1>;

/// Borrows the genuine Policy target and accepted Origin for one current cut.
///
/// Only actual Target work constructs this value after same-financial and
/// gen1 checks. It has no supplied-parts constructor or mutable native projection.
pub struct RootOriginalInputLoanV1<'cut, 'origin, 'startup> {
    origin: RootQ04OriginBorrowerV1<'origin, 'startup>,
    target: &'cut RootPolicyTargetOriginalV1,
    clock: RawPairedClockSample,
    cause: &'cut Cause,
    debt: &'cut Cause,
    target_post_failure: &'cut Cause,
    secondary_panic: &'cut RefCell<Option<Box<dyn std::any::Any + Send>>>,
}

pub(in crate::native) struct RootOriginalPublicationLoanV1<'cut, 'origin, 'startup> {
    origin: RootQ04OriginBorrowerV1<'origin, 'startup>,
    clock: RawPairedClockSample,
    cause: &'cut Cause,
}

pub(in crate::native) enum RootCurrentOwnerLoanV1<'cut, 'origin, 'startup> {
    Input(RootOriginalInputLoanV1<'cut, 'origin, 'startup>),
    Publication(RootOriginalPublicationLoanV1<'cut, 'origin, 'startup>),
}

// No supplied origin, clock or profile can install these loans. The actual
// gen1 association supplies its same external Origin, and the actual Target's
// selected financial owner must be that very original before returning.
fn same_origin_v1<'origin, 'startup>(
    target: &RootPolicyTargetOriginalV1,
    gen1: &RootAuthorityGen1LoanV1<'_, 'origin, 'startup>,
) -> Result<
    (
        RootQ04OriginBorrowerV1<'origin, 'startup>,
        RawPairedClockSample,
    ),
    ErrorV1,
> {
    let origin = gen1.original_transport_v1()?;
    require_matching_target_origin_v1(target, &origin)?;
    let (clock, _) = gen1.original_clock_data_v1()?;
    Ok((origin, clock))
}

fn same_ready_origin_v1<'origin, 'startup>(
    target: &RootPolicyTargetOriginalV1,
    flight: &RootAuthorityQ04FlightOriginalV1<'_, 'origin, 'startup>,
) -> Result<(RootQ04OriginBorrowerV1<'origin, 'startup>, RawPairedClockSample), ErrorV1> {
    let origin = flight.original_transport_ready_v1()?;
    require_matching_target_origin_v1(target, &origin)?;
    let (clock, _) = flight.original_clock_data_v1()?;
    Ok((origin, clock))
}

fn require_matching_target_origin_v1(
    target: &RootPolicyTargetOriginalV1,
    origin: &RootQ04OriginBorrowerV1<'_, '_>,
) -> Result<(), ErrorV1> {
    let mut original = origin.try_borrow_mut()?;
    match (&target.journal.storage, origin.purpose_v1()) {
        (PolicyJournalStorageV1::Selected { financial, .. }, RootQ04OriginPurposeV1::Selected) => {
            if !original.same_selected_financial_original_data_v1(financial) {
                return Err(ErrorV1::ChangedCut);
            }
        }
        (PolicyJournalStorageV1::Ordinary { .. }, RootQ04OriginPurposeV1::Ordinary) => {
            original.require_ordinary_original_v1()?;
        }
        _ => return Err(ErrorV1::ChangedCut),
    }
    Ok(())
}

impl<'cut, 'origin, 'startup> RootOriginalInputLoanV1<'cut, 'origin, 'startup> {
    fn admit_controls_v1(target: &RootPolicyTargetOriginalV1) -> Result<(), ErrorV1> {
        use aos_sandbox_model::{ResourceDimension as D, ResourceVector};
        let bytes = std::mem::size_of::<Self>()
            .checked_mul(3)
            .and_then(|bytes| {
                bytes.checked_add(std::mem::size_of::<Result<Self, ErrorV1>>().checked_mul(3)?)
            })
            .and_then(|bytes| bytes.checked_add(Self::authority_bookend_control_bytes_v1()?))
            .and_then(|bytes| bytes.checked_add(target_names_post_control_bytes_v1()?))
            .and_then(|bytes| u64::try_from(bytes).ok())
            .ok_or_else(crate::native::PolicyNativeJournalErrorV1::geometry)?;
        target
            .journal
            .admit_role_observation_v1(ResourceVector::ZERO.with(D::MemoryBytes, bytes))?;
        Ok(())
    }

    fn authority_bookend_control_bytes_v1() -> Option<usize> {
        use std::mem::size_of;
        type Panic = Box<dyn std::any::Any + Send>;
        type Flight<'borrow, 'authority, 'origin, 'startup> =
            &'borrow RootAuthorityQ04FlightOriginalV1<'authority, 'origin, 'startup>;

        size_of::<(&Self, Flight<'_, '_, 'origin, 'startup>)>().checked_mul(3)?
            .checked_add(size_of::<(&Self, Option<Flight<'_, '_, 'origin, 'startup>>)>()
                .checked_mul(3)?)?
            .checked_add(size_of::<Option<Flight<'_, '_, 'origin, 'startup>>>()
                .checked_mul(3)?)?
            .checked_add(size_of::<Result<RawPairedClockSample, ErrorV1>>().checked_mul(3)?)?
            .checked_add(size_of::<Result<(), crate::native::RootAuthorityErrorV1>>()
                .checked_mul(6)?)?
            .checked_add(size_of::<Result<(), ErrorV1>>().checked_mul(3)?)?
            .checked_add(size_of::<Result<Result<(), ErrorV1>, Panic>>().checked_mul(3)?)?
            .checked_add(size_of::<(&Self, &Option<Flight<'_, '_, 'origin, 'startup>>)>()
                .checked_mul(3)?)?
            .checked_add(size_of::<Flight<'_, '_, 'origin, 'startup>>().checked_mul(3)?)?
            .checked_add(size_of::<Option<usize>>().checked_mul(3)?)
    }

    pub(in crate::native) fn new(
        target: &'cut RootPolicyTargetOriginalV1,
        gen1: &RootAuthorityGen1LoanV1<'_, 'origin, 'startup>,
        cause: &'cut Cause,
        debt: &'cut Cause,
        target_post_failure: &'cut Cause,
        secondary_panic: &'cut RefCell<Option<Box<dyn std::any::Any + Send>>>,
    ) -> Result<Self, ErrorV1> {
        Self::admit_controls_v1(target)?;
        let (origin, clock) = same_origin_v1(target, gen1)?;
        Ok(Self {
            origin,
            target,
            clock,
            cause,
            debt,
            target_post_failure,
            secondary_panic,
        })
    }

    pub(in crate::native) fn from_ready_flight_v1(
        target: &'cut RootPolicyTargetOriginalV1,
        flight: &RootAuthorityQ04FlightOriginalV1<'_, 'origin, 'startup>,
        cause: &'cut Cause,
        debt: &'cut Cause,
        target_post_failure: &'cut Cause,
        secondary_panic: &'cut RefCell<Option<Box<dyn std::any::Any + Send>>>,
    ) -> Result<Self, ErrorV1> {
        Self::admit_controls_v1(target)?;
        let (origin, clock) = same_ready_origin_v1(target, flight)?;
        Ok(Self { origin, target, clock, cause, debt, target_post_failure, secondary_panic })
    }

    /// Reports a failure retained by this same Work's genuine current loan.
    ///
    /// This diagnostic performs no observation and grants no append permission.
    #[must_use]
    pub fn has_retained_failure_v1(&self) -> bool {
        self.cause.get().is_some()
            || self.debt.get().is_some()
            || self.target_post_failure.get().is_some()
            || self.secondary_panic.borrow().is_some()
    }

    /// Rechecks this same original Input loan without issuing a floor or publication.
    ///
    /// # Errors
    /// Retains actual Origin, target-name and owed-post refusals on their owners.
    pub fn recheck_v1(&self) -> Result<RawPairedClockSample, ErrorV1> {
        self.recheck()
    }

    /// Rechecks the complete original cut with this same genuine Authority.
    ///
    /// The same native engine places Authority between the original queue
    /// prefix and Target names, then completes the original clock last.
    /// Actual Authority/Target failures are retained before independent posts.
    ///
    /// # Errors
    /// Refuses a foreign or unavailable Flight, or the original prefix,
    /// Authority, Target, clock or independently owed post. A retained failure
    /// must be selected through this Work's diagnostic before projecting its
    /// coarse returned marker into an upper owning error.
    ///
    /// # Panics
    /// Resumes an actual Authority/Target panic after all reached independent
    /// native posts, retaining any later post panic on this same Work.
    pub fn recheck_with_authority_v1(
        &self,
        authority: &RootAuthorityQ04FlightOriginalV1<'_, 'origin, 'startup>,
    ) -> Result<RawPairedClockSample, ErrorV1> {
        if self.cause.get().is_some() {
            return Err(ErrorV1::ChangedCut);
        }
        if let Err(error) = authority.require_same_origin_v1(&self.origin) {
            let _later = self.cause.set(error.into());
            return Err(ErrorV1::ChangedCut);
        }
        self.recheck_owned(Some(authority))
    }

    /// Completes the separately owed Target-name observation on this same owner.
    ///
    /// This does not consult an earlier Work refusal or attempt another Origin
    /// entry. The caller retains its Result beside every other independent post.
    ///
    /// # Errors
    /// Retains the actual Target native/name failure on that original owner.
    pub fn require_original_target_names_post_once_v1(
        &self,
    ) -> Result<(), ()> {
        observe_target_names_post_once_v1(self.target, self.target_post_failure)
    }

    /// Copies the retained original clock; it does not resample or extend it.
    #[must_use]
    pub const fn original_clock_data_v1(&self) -> RawPairedClockSample {
        self.clock
    }

    fn recheck_owned(
        &self,
        authority: Option<&RootAuthorityQ04FlightOriginalV1<'_, 'origin, 'startup>>,
    ) -> Result<RawPairedClockSample, ErrorV1> {
        let mut origin = self.origin.try_borrow_mut()?;
        let native = origin.begin_input_current_once_v1()?;
        let observed = catch_unwind(AssertUnwindSafe(|| {
            if let Some(authority) = authority {
                authority.recheck()?;
            }
            self.target.require_original_input_names_v1()?;
            Ok::<(), ErrorV1>(())
        }));
        match observed {
            Ok(Ok(())) => Ok(native.finish_once_v1()?),
            Ok(Err(error)) => {
                // Park the actual Authority/Target failure before independent finish.
                let _later = self.cause.set(error);
                if let Err(error) = native.finish_negative_posts_once_v1() {
                    let _later = self.debt.set(error.into());
                }
                Err(ErrorV1::ChangedCut)
            }
            Err(first_panic) => {
                // The actual owner retains its reached panic prefix. Owed
                // Origin posts run before the original panic resumes.
                let finished = catch_unwind(AssertUnwindSafe(|| {
                    native.finish_negative_posts_once_v1()
                }));
                match finished {
                    Ok(Err(error)) => {
                        let _later = self.debt.set(error.into());
                    }
                    Err(later_panic) => {
                        let mut retained = self.secondary_panic.borrow_mut();
                        if retained.is_some() {
                            std::process::abort();
                        }
                        *retained = Some(later_panic);
                    }
                    Ok(Ok(())) => {}
                }
                resume_unwind(first_panic)
            }
        }
    }

    pub(in crate::native) fn recheck(&self) -> Result<RawPairedClockSample, ErrorV1> {
        if self.cause.get().is_some() {
            return Err(ErrorV1::ChangedCut);
        }
        self.recheck_owned(None)
    }

    pub(in crate::native) fn require_cache_uid_v1(&self, cache_uid: u32) -> Result<(), ErrorV1> {
        if self.origin.try_borrow_mut()?.expected_identities_data_v1()?[3] != cache_uid {
            return Err(ErrorV1::ChangedCut);
        }
        Ok(())
    }

    pub(in crate::native) fn require_same_origin_v1(
        &self,
        expected: &RootQ04OriginBorrowerV1<'origin, 'startup>,
    ) -> Result<(), ()> {
        if self.cause.get().is_some() {
            return Err(());
        }
        if !self.origin.same_origin_v1(expected) {
            let _later = self.cause.set(ErrorV1::ChangedCut);
            return Err(());
        }
        Ok(())
    }

    pub(in crate::native) fn recheck_cut_v1(
        &self,
        identity: &Q04CutIdentityV1,
    ) -> Result<RawPairedClockSample, ()> {
        let returned = (|| {
            let current = self.recheck()?;
            if identity.bytes()[112..128] != self.clock.host_boot_id()
                || identity.bytes()[144..152] != self.clock.boottime_nanoseconds().to_be_bytes()
                || current.boottime_nanoseconds()
                    >= u64::from_be_bytes(crate::q04_data::fixed(identity.bytes(), 136))
            {
                return Err(ErrorV1::Expired);
            }
            Ok(current)
        })();
        match returned {
            Ok(sample) => Ok(sample),
            Err(error) => {
                let _later = self.cause.set(error);
                Err(())
            }
        }
    }
}

impl<'cut, 'origin, 'startup> RootOriginalPublicationLoanV1<'cut, 'origin, 'startup> {
    fn admit_controls_v1(target: &RootPolicyTargetOriginalV1) -> Result<(), ErrorV1> {
        use aos_sandbox_model::{ResourceDimension as D, ResourceVector};
        let bytes = std::mem::size_of::<Self>()
            .checked_mul(3)
            .and_then(|bytes| {
                bytes.checked_add(std::mem::size_of::<Result<Self, ErrorV1>>().checked_mul(3)?)
            })
            .and_then(|bytes| u64::try_from(bytes).ok())
            .ok_or_else(crate::native::PolicyNativeJournalErrorV1::geometry)?;
        target
            .journal
            .admit_role_observation_v1(ResourceVector::ZERO.with(D::MemoryBytes, bytes))?;
        Ok(())
    }

    pub(in crate::native) fn new(
        target: &RootPolicyTargetOriginalV1,
        gen1: &RootAuthorityGen1LoanV1<'_, 'origin, 'startup>,
        cause: &'cut Cause,
    ) -> Result<Self, ErrorV1> {
        Self::admit_controls_v1(target)?;
        let (origin, clock) = same_origin_v1(target, gen1)?;
        Ok(Self {
            origin,
            clock,
            cause,
        })
    }

    fn recheck(&self) -> Result<RawPairedClockSample, ErrorV1> {
        if self.cause.get().is_some() {
            return Err(ErrorV1::ChangedCut);
        }
        Ok(self.origin.try_borrow_mut()?.observe_current_once_v1()?)
    }
}

impl RootCurrentOwnerLoanV1<'_, '_, '_> {
    pub(super) fn clock(&self) -> RawPairedClockSample {
        match self {
            Self::Input(original) => original.clock,
            Self::Publication(original) => original.clock,
        }
    }

    pub(super) fn recheck(&self) -> Result<RawPairedClockSample, ErrorV1> {
        match self {
            Self::Input(original) => original.recheck(),
            Self::Publication(original) => original.recheck(),
        }
    }

    pub(super) fn require_cache_uid_v1(&self, cache_uid: u32) -> Result<(), ErrorV1> {
        let origin = match self {
            Self::Input(original) => original.origin,
            Self::Publication(original) => original.origin,
        };
        if origin.try_borrow_mut()?.expected_identities_data_v1()?[3] != cache_uid {
            return Err(ErrorV1::ChangedCut);
        }
        Ok(())
    }

    pub(super) fn require_model_verification(&self, outcome: Result<bool, ErrorV1>) -> bool {
        let cause = match self {
            Self::Input(original) => original.cause,
            Self::Publication(original) => original.cause,
        };
        retain_model_verification_v1(cause, outcome)
    }
}

// Input and final Work posts share the actual independent Target IO and its
// dedicated diagnostic slot. Neither entry consults the healthy Work gate.
pub(super) fn observe_target_names_post_once_v1(
    target: &RootPolicyTargetOriginalV1,
    target_post_failure: &Cause,
) -> Result<(), ()> {
    match target.require_original_input_names_post_once_v1() {
        Ok(()) => Ok(()),
        Err(error) => {
            let _later = target_post_failure.set(error.into());
            Err(())
        }
    }
}

pub(super) fn target_names_post_control_bytes_v1() -> Option<usize> {
    use std::mem::size_of;
    size_of::<(&RootPolicyTargetOriginalV1, &Cause)>().checked_mul(3)?
        .checked_add(size_of::<Result<(), ()>>().checked_mul(3)?)?
        .checked_add(size_of::<Result<(), crate::native::PolicyNativeJournalErrorV1>>().checked_mul(3)?)?
        .checked_add(size_of::<Result<(), ErrorV1>>().checked_mul(3)?)?
        .checked_add(size_of::<Option<usize>>().checked_mul(3)?)
}
