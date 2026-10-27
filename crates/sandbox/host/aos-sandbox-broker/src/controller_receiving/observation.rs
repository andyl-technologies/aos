//! Retains the same fixed profile/pair/profile original observation.
//!
//! This is observation DATA only. Actual paired startup, native writer, Bank
//! and launch gates remain in their closed owners. No descriptor, capacity,
//! account or decoded enrollment constructs this observation's original.

use std::sync::Arc;
use aos_sandbox_model::{ResourceDimension as D, ResourceVector};
use crate::receiving::{OriginalEnrollment, OriginalEnrollmentPairAttemptV1};
use super::{ControllerReceivingErrorV1, ControllerReceivingOriginalV1};
use super::profile::{ControllerProfileErrorV1, ControllerSelfProfileOriginalV1};
use super::operation_intake::OperationIntakePurposeV1;

#[derive(Clone, Copy)]
enum ProfileObservation {
    Baseline,
    OperationIntake { purpose: OperationIntakePurposeV1, first_slot: usize },
}

impl ProfileObservation {
    fn observe(self, profile: &ControllerSelfProfileOriginalV1,
        original: &Arc<ControllerReceivingOriginalV1>, offset: usize,
    ) -> Result<([u8; 16], [u8; 16]), ControllerProfileErrorV1> {
        match self {
            Self::Baseline => profile.require_resource_producer(),
            Self::OperationIntake { purpose, first_slot } =>
                profile.observe_operation_intake_producer_v1(original, purpose, first_slot + offset),
        }
    }
}

/// Retains each reached fixed original/native bookend in execution order.
#[must_use]
pub struct ControllerOriginalObservationV1 {
    entry: Option<Result<(), ControllerReceivingErrorV1>>,
    before: Option<Result<([u8; 16], [u8; 16]), ControllerProfileErrorV1>>,
    pair: Option<OriginalEnrollmentPairAttemptV1>,
    returned: Option<Result<OriginalEnrollment, ControllerReceivingErrorV1>>,
    after: Option<Result<([u8; 16], [u8; 16]), ControllerProfileErrorV1>>,
    binding: Option<Result<(), ControllerReceivingErrorV1>>,
    retirement: Option<Result<(), crate::receiving::OriginalPairErrorV1>>,
    attempted: bool,
}

impl ControllerOriginalObservationV1 {
    /// Creates vacant destinations without IO, allocation or admission.
    #[must_use]
    pub const fn new() -> Self {
        Self { entry: None, before: None, pair: None, returned: None,
            after: None, binding: None, retirement: None, attempted: false }
    }

    /// Describes this actual observation's added native and compiled carriers.
    #[must_use]
    pub fn receiving_demand_v1() -> Option<ResourceVector> {
        let bytes = std::mem::size_of::<Self>().checked_mul(2)?;
        ResourceVector::ZERO.with(D::MemoryBytes, u64::try_from(bytes).ok()?)
            .checked_add(OriginalEnrollmentPairAttemptV1::additional_receiving_demand_v1()?).ok()
    }

    /// Observes only the same genuine C and its linked measured profile once.
    ///
    /// The enclosing real coordinator prepays this fixed representation. All
    /// native Results remain here; pair failure does not suppress the already
    /// owed independent profile observation. Success returns comparison DATA.
    ///
    /// # Errors
    /// Retains the actual pair/profile/native failure or same-original refusal.
    pub fn observe_once(
        &mut self,
        original: &Arc<ControllerReceivingOriginalV1>,
        profile: &ControllerSelfProfileOriginalV1,
    ) -> Result<OriginalEnrollment, ControllerReceivingErrorV1> {
        self.observe_inner(original, profile, ProfileObservation::Baseline)
    }

    pub(in crate::controller_receiving) fn observe_operation_intake_once_v1(
        &mut self,
        original: &Arc<ControllerReceivingOriginalV1>,
        profile: &ControllerSelfProfileOriginalV1,
        purpose: OperationIntakePurposeV1,
        first_slot: usize,
    ) -> Result<OriginalEnrollment, ControllerReceivingErrorV1> {
        self.observe_inner(original, profile,
            ProfileObservation::OperationIntake { purpose, first_slot })
    }

    fn observe_inner(
        &mut self,
        original: &Arc<ControllerReceivingOriginalV1>,
        profile: &ControllerSelfProfileOriginalV1,
        schedule: ProfileObservation,
    ) -> Result<OriginalEnrollment, ControllerReceivingErrorV1> {
        if self.attempted { return Err(ControllerReceivingErrorV1::Conflict); }
        self.attempted = true;
        self.entry = Some(if original.process == std::process::id()
            && profile.has_same_baseline_original(original)
        { Ok(()) } else { Err(ControllerReceivingErrorV1::Conflict) });
        if !matches!(self.entry, Some(Ok(()))) {
            return Err(ControllerReceivingErrorV1::Conflict);
        }
        self.before = Some(schedule.observe(profile, original, 0));
        self.pair = Some(OriginalEnrollmentPairAttemptV1::new_controller(original.writer_native_layout()));
        self.returned = Some(self.pair.as_mut().ok_or(ControllerReceivingErrorV1::Conflict)?
            .observe_once(&original.policy, &original.enrollment).copied()
            .map_err(|_| ControllerReceivingErrorV1::EnrollmentUnavailable));
        self.after = Some(schedule.observe(profile, original, 1));
        self.binding = Some((|| {
            let before = self.before.as_ref().and_then(|result| result.as_ref().ok())
                .ok_or(ControllerReceivingErrorV1::Conflict)?;
            let actual = self.returned.as_ref().and_then(|result| result.as_ref().ok())
                .ok_or(ControllerReceivingErrorV1::Conflict)?;
            let after = self.after.as_ref().and_then(|result| result.as_ref().ok())
                .ok_or(ControllerReceivingErrorV1::Conflict)?;
            if before != after || *actual != original.writer_enrollment()?
                || actual.recipient_invocation != before.0
                || actual.identity.native_fields().invocation != before.1
            { return Err(ControllerReceivingErrorV1::Conflict); }
            Ok(())
        })());
        if matches!(self.binding, Some(Ok(()))) {
            // The entire same-observation before/pair/after/binding interval
            // is now positive. No later stage reads this temporary boot File;
            // the genuine startup's separate original boot owner is untouched.
            self.retirement = Some(self.pair.as_mut().ok_or(ControllerReceivingErrorV1::Conflict)?
                .retire_positive_boot_file_once());
        }
        self.value().copied().ok_or(ControllerReceivingErrorV1::Conflict)
    }

    /// Borrows only this observation's actual fully joined comparison DATA.
    #[must_use]
    pub fn value(&self) -> Option<&OriginalEnrollment> {
        if !matches!(self.binding, Some(Ok(())))
            || !matches!(self.retirement, Some(Ok(()))) { return None; }
        self.returned.as_ref()?.as_ref().ok()
    }

    /// Borrows the first native/profile refusal, preserving its actual owner.
    #[must_use]
    pub fn failure(&self) -> Option<&(dyn std::error::Error + 'static)> {
        error(&self.entry).or_else(|| error(&self.before))
            .or_else(|| self.pair.as_ref().and_then(|pair| pair.failure()))
            .or_else(|| error(&self.returned)).or_else(|| error(&self.after))
            .or_else(|| error(&self.binding)).or_else(|| error(&self.retirement))
    }
}

fn error<T, E: std::error::Error + 'static>(
    result: &Option<Result<T, E>>,
) -> Option<&(dyn std::error::Error + 'static)> {
    result.as_ref()?.as_ref().err().map(|cause| cause as _)
}

impl ControllerOriginalObservationV1 {
    // Resolve only a reached profile marker in its actual chronological slot.
    // A native pair/read error before the after-profile marker keeps priority.
    pub(in crate::controller_receiving) fn operation_profile_failure_slot_v1(
        &self, first_slot: usize,
    ) -> Option<usize> {
        if self.entry.as_ref().is_some_and(Result::is_err) { return None; }
        if self.before.as_ref().is_some_and(Result::is_err) { return Some(first_slot); }
        if self.pair.as_ref().is_some_and(|pair| pair.failure().is_some())
            || self.returned.as_ref().is_some_and(Result::is_err)
        { return None; }
        self.after.as_ref().is_some_and(Result::is_err).then_some(first_slot + 1)
    }
}
