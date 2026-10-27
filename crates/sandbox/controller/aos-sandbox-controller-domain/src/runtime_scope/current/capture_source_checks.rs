//! Retains the existing temporary assignment verifier on Capture source paths.
//!
//! Every check uses the unchanged target clock/selection/continuity engine.
//! Only completed positive temporaries are disposed at their former boundary;
//! the first failed check, partial graph and preceding lease stay resident.

use std::error::Error;
use aos_sandbox_model::{RawPairedClockSample, ResourceVector};
use aos_sandbox_broker::paired_clock::ProtectedOwnershipClockError;
use aos_sandbox_ownership_protocol::SignedOwnershipLease;
use super::{CurrentAssignmentTarget, CurrentRuntimeScopeError};
use super::capture_lifetime::VerificationV2;
use crate::Journal;

/// Holds the actual selected source-check verifier and its first refusal.
///
/// This is an inert result destination, not an assignment or effect factory.
/// The actual caller pays the named target-derived representation before
/// construction. No caller amount, deadline or signed-lease DTO is accepted.
#[doc(hidden)]
pub struct ControllerCaptureAssignmentChecksV4 {
    required: ResourceVector,
    verification: VerificationV2,
    lease: Option<SignedOwnershipLease>,
    returned: Option<Result<(), CurrentRuntimeScopeError>>,
}

impl ControllerCaptureAssignmentChecksV4 {
    fn require_capacity(&self, target: &CurrentAssignmentTarget, journal: &Journal)
        -> Result<(), CurrentRuntimeScopeError>
    {
        if self.returned.as_ref().is_some_and(Result::is_err)
            || self.lease.is_some()
            || !target.capture_source_checks_receiving_demand_v4(journal)
                .is_some_and(|required| required.is_within(self.required))
        { return Err(CurrentRuntimeScopeError::CurrentMismatch); }
        Ok(())
    }

    pub(crate) fn recheck_v4<T>(&mut self, target: &CurrentAssignmentTarget,
        journal: &mut Journal, clock: &mut T) -> Result<(), CurrentRuntimeScopeError>
    where T: FnMut() -> Result<RawPairedClockSample, ProtectedOwnershipClockError>
    {
        if self.returned.as_ref().is_some_and(Result::is_err) {
            return Err(CurrentRuntimeScopeError::CurrentMismatch);
        }
        let result = self.require_capacity(target, journal)
            .and_then(|()| target.recheck_with_capture_v2(journal, clock, Some(&mut self.verification)));
        self.returned = Some(result);
        if !matches!(self.returned, Some(Ok(()))) { return Err(CurrentRuntimeScopeError::CurrentMismatch); }
        // The old consuming verifier's completed temporary ended here too.
        // No failed graph, financial debit or native obligation is retired.
        self.verification = VerificationV2::new();
        Ok(())
    }

    pub(crate) fn verified_plan_lease_v4<T>(&mut self, target: &CurrentAssignmentTarget,
        journal: &mut Journal, clock: &mut T)
        -> Result<(SignedOwnershipLease, RawPairedClockSample), CurrentRuntimeScopeError>
    where T: FnMut() -> Result<RawPairedClockSample, ProtectedOwnershipClockError>
    {
        if self.returned.as_ref().is_some_and(Result::is_err) {
            return Err(CurrentRuntimeScopeError::CurrentMismatch);
        }
        let result = self.require_capacity(target, journal)
            .and_then(|()| target.verified_plan_lease_with_source_checks_v4(journal, clock, Some(self)));
        match result {
            Ok(value) => {
                self.returned = Some(Ok(()));
                self.verification = VerificationV2::new();
                Ok(value)
            }
            Err(cause) => {
                self.returned = Some(Err(cause));
                Err(CurrentRuntimeScopeError::CurrentMismatch)
            }
        }
    }

    pub(super) fn recheck_inside_lease_v4<T>(&mut self, target: &CurrentAssignmentTarget,
        journal: &mut Journal, clock: &mut T) -> Result<(), CurrentRuntimeScopeError>
    where T: FnMut() -> Result<RawPairedClockSample, ProtectedOwnershipClockError>
    {
        target.recheck_with_capture_v2(journal, clock, Some(&mut self.verification))?;
        self.verification = VerificationV2::new();
        Ok(())
    }

    pub(super) fn verify_lease_v4(&mut self, journal: &Journal,
        binding: &crate::runtime_authority::RuntimeAuthorityBindingV1,
        publication: &crate::publication::CurrentAuthorityPublicationV1,
        policy: &super::CurrentRuntimeScopePolicy, sample: RawPairedClockSample)
        -> Result<(), CurrentRuntimeScopeError>
    {
        self.verification.verify_once_v2(journal, binding, publication, policy, sample)?;
        self.lease = Some(self.verification.take_value_once_v4()
            .ok_or(CurrentRuntimeScopeError::CurrentMismatch)?);
        self.verification = VerificationV2::new();
        Ok(())
    }

    pub(super) fn take_lease_v4(&mut self) -> Result<SignedOwnershipLease, CurrentRuntimeScopeError> {
        self.lease.take().ok_or(CurrentRuntimeScopeError::CurrentMismatch)
    }

    #[cfg(test)]
    pub(super) fn retained_lease_for_test_v4(&self) -> Option<&SignedOwnershipLease> {
        self.lease.as_ref()
    }

    /// Borrows the actual first partial verifier/claim error before its marker.
    #[must_use]
    pub fn failure_v4(&self) -> Option<&(dyn Error + 'static)> {
        self.verification.failure_v4().or_else(|| self.returned.as_ref()
            .and_then(|result| result.as_ref().err()).map(|cause| cause as _))
    }
}

impl CurrentAssignmentTarget {
    /// Prices the actual selected temporary verifier and preceding lease peak.
    ///
    /// The two existing verifier/gate planes dominate the returned positive
    /// lease beside a following verifier. Only actual compiled bytes are added.
    #[must_use]
    pub fn capture_source_checks_receiving_demand_v4(&self, journal: &Journal) -> Option<ResourceVector> {
        self.capture_verification_pair_receiving_demand_v4(journal,
            std::mem::size_of::<ControllerCaptureAssignmentChecksV4>())
    }

    /// Constructs inert temporary-verifier destinations after C18 prepayment.
    ///
    /// # Errors
    /// Refuses unavailable actual artifact/gate geometry. It performs no native
    /// check and grants no assignment, IO, currentness or effect authority.
    pub fn prepare_capture_source_checks_v4(&self, journal: &Journal)
        -> Result<ControllerCaptureAssignmentChecksV4, CurrentRuntimeScopeError>
    {
        Ok(ControllerCaptureAssignmentChecksV4 {
            required: self.capture_source_checks_receiving_demand_v4(journal)
                .ok_or(CurrentRuntimeScopeError::CurrentMismatch)?,
            verification: VerificationV2::new(), lease: None, returned: None,
        })
    }
}
