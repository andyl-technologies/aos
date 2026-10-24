//! Lends original assignment residency bounds independently of observation freshness.
//!
//! The original bound is derived only at actual target acquisition. A renewed
//! lease, later clock or fresh observation cannot replace that bound. The
//! borrower owns the same verified signed lease while the selected C18 issuer
//! constructs and signs its versioned Capture lifetime; it grants no IO itself.

use std::error::Error;
use std::mem::size_of;

use aos_sandbox_model::{ObjectDigest, RawPairedClockSample, ResourceDimension as D, ResourceVector};
use aos_sandbox_ownership_protocol::SignedOwnershipLease;
use aos_sandbox_broker::paired_clock::ProtectedOwnershipClockError;

use super::{CurrentAssignmentTarget, CurrentRuntimeScopeError, read_clock, select_exact_current};
use crate::Journal;

pub(super) struct AssignmentCaptureBoundsV2 {
    origin: RawPairedClockSample,
    lease_digest: ObjectDigest,
    lease_generation: u64,
    authority_expires: i64,
    maximum_skew: u64,
    plan_expires: Option<i64>,
    deadline: Result<u64, aos_sandbox_model::OwnershipLeaseVerificationError>,
    artifact_bytes: Option<usize>,
}

impl AssignmentCaptureBoundsV2 {
    pub(super) fn new(origin: RawPairedClockSample, lease: &SignedOwnershipLease,
        plan_expires: Option<i64>) -> Self
    {
        let deadline = origin.conservative_lease_expiry_deadline_data_v2(
            lease.authority_expires_seconds(), lease.maximum_clock_skew_seconds(),
        ).and_then(|lease_deadline| match plan_expires {
            Some(expires) => origin.conservative_expiry_deadline_data_v1(expires)
                .map(|plan_deadline| lease_deadline.min(plan_deadline))
                .ok_or(aos_sandbox_model::OwnershipLeaseVerificationError::DeadlineOverflow),
            None => Ok(lease_deadline),
        });
        let artifact_bytes = [lease.canonical_lease(), lease.canonical_signature(),
            lease.canonical_receipt(), lease.canonical_receipt_signature()]
            .into_iter().try_fold(0_usize, |sum, bytes| sum.checked_add(bytes.len()));
        Self { origin, lease_digest: lease.digest(), lease_generation: lease.generation(),
            authority_expires: lease.authority_expires_seconds(),
            maximum_skew: lease.maximum_clock_skew_seconds(), plan_expires,
            deadline, artifact_bytes }
    }
}

#[derive(Clone, Copy, PartialEq)]
struct OriginalSelectionV2 {
    origin: RawPairedClockSample,
    deadline: u64,
    lease_digest: ObjectDigest,
    generation: u64,
    authority_expires: i64,
    maximum_skew: u64,
    plan_expires: Option<i64>,
    assignment: aos_sandbox_model::BrokerAssignment,
    holder: Option<aos_sandbox_model::PrincipalId>,
    node: aos_sandbox_model::NodeId,
}

pub(super) struct VerificationV2 {
    capture: aos_sandbox_ownership_protocol::response_verification::OwnershipResponseVerifyCaptureV1,
    claim: Option<Result<aos_sandbox_ownership_protocol::OwnershipClaimV1, CurrentRuntimeScopeError>>,
    result: Option<Result<(), CurrentRuntimeScopeError>>,
}

impl VerificationV2 {
    pub(super) fn new() -> Self {
        Self { capture: Default::default(), claim: None, result: None }
    }

    pub(super) fn take_value_once_v4(&mut self) -> Option<SignedOwnershipLease> {
        self.capture.take_value_once()
    }

    pub(super) fn failure_v4(&self) -> Option<&(dyn Error + 'static)> {
        self.claim.as_ref().and_then(|result| result.as_ref().err()).map(|cause| cause as _)
            .or_else(|| self.capture.cause())
    }

    pub(super) fn verify_once_v2(&mut self, journal: &Journal,
        binding: &crate::runtime_authority::RuntimeAuthorityBindingV1,
        publication: &crate::publication::CurrentAuthorityPublicationV1,
        policy: &super::CurrentRuntimeScopePolicy, sample: RawPairedClockSample)
        -> Result<(), CurrentRuntimeScopeError>
    {
        self.claim = Some(crate::reconciler::runtime_authority_claim(journal, binding)
            .map_err(CurrentRuntimeScopeError::from));
        let claim = self.claim.as_ref().and_then(|result| result.as_ref().ok())
            .ok_or(CurrentRuntimeScopeError::CurrentMismatch)?;
        let lease = publication.lease();
        policy.ownership_verifier.verify_response_bytes_retaining_v1(
            claim, lease.canonical_lease(), lease.canonical_signature(), lease.canonical_receipt(),
            lease.canonical_receipt_signature(), &sample, &mut self.capture,
        )?;
        Ok(())
    }
}

/// Retains original selection and both actual same-verifier outcome graphs.
///
/// Its private constructor accepts only an actual acquired assignment target.
/// The selected C18 owner retains this complete value before observing, through
/// source signing and every failure. It contains no borrowed self-reference,
/// native grant, transport, replacement clock or new financial account.
#[doc(hidden)]
pub struct OriginalAssignmentCaptureLifetimeV2 {
    selection: OriginalSelectionV2,
    verification: [VerificationV2; 2],
    next: usize,
    repeated: Option<CurrentRuntimeScopeError>,
}

impl OriginalAssignmentCaptureLifetimeV2 {
    /// Enters the actual first original-lease verification once.
    ///
    /// # Errors
    /// Retains actual raw quartet, claim, decoder/crypto models and returned
    /// error for changed selection, unavailable journal or verification failure.
    pub fn observe_once_v2<T>(&mut self, target: &CurrentAssignmentTarget,
        journal: &mut Journal, clock: &mut T) -> Result<(), CurrentRuntimeScopeError>
    where T: FnMut() -> Result<RawPairedClockSample, ProtectedOwnershipClockError>
    {
        if self.next != 0 || self.repeated.is_some() {
            self.repeated.get_or_insert(CurrentRuntimeScopeError::CurrentMismatch);
            return Err(CurrentRuntimeScopeError::CurrentMismatch);
        }
        self.observe_next(target, journal, clock)
    }

    /// Rechecks the original lease using the distinct prearmed comparison destination.
    ///
    /// # Errors
    /// Refuses before a complete first observation, on reuse or on any changed
    /// original/clock/publication; every reached verification prefix stays held.
    pub fn require_current_v2<T>(&mut self, target: &CurrentAssignmentTarget,
        journal: &mut Journal, clock: &mut T) -> Result<(), CurrentRuntimeScopeError>
    where T: FnMut() -> Result<RawPairedClockSample, ProtectedOwnershipClockError>
    {
        if self.next != 1 || self.repeated.is_some() || !matches!(self.verification[0].result, Some(Ok(()))) {
            self.repeated.get_or_insert(CurrentRuntimeScopeError::CurrentMismatch);
            return Err(CurrentRuntimeScopeError::CurrentMismatch);
        }
        self.observe_next(target, journal, clock)
    }

    fn observe_next<T>(&mut self, target: &CurrentAssignmentTarget,
        journal: &mut Journal, clock: &mut T) -> Result<(), CurrentRuntimeScopeError>
    where T: FnMut() -> Result<RawPairedClockSample, ProtectedOwnershipClockError>
    {
        let index = self.next;
        self.next += 1;
        let slot = &mut self.verification[index];
        slot.result = Some((|| {
            if target.capture_selection_v2()? != self.selection {
                return Err(CurrentRuntimeScopeError::CurrentMismatch);
            }
            target.recheck_with_capture_v2(journal, clock, Some(slot))?;
            let sample = read_clock(&target.policy, clock)?;
            target.validity.check(sample)?;
            self.selection.origin.validate_later_sample(sample).map_err(|_| CurrentRuntimeScopeError::Clock)?;
            if sample.boottime_nanoseconds() >= self.selection.deadline {
                return Err(CurrentRuntimeScopeError::Clock);
            }
            select_exact_current(journal, target.selection, &target.policy, &target.binding)?;
            let lease = slot.capture.value().ok_or(CurrentRuntimeScopeError::CurrentMismatch)?;
            if lease.digest() != self.selection.lease_digest || lease.generation() != self.selection.generation
                || lease.authority_expires_seconds() != self.selection.authority_expires
                || lease.maximum_clock_skew_seconds() != self.selection.maximum_skew
            { return Err(CurrentRuntimeScopeError::CurrentMismatch); }
            Ok(())
        })());
        slot.result.as_ref().and_then(|result| result.as_ref().ok())
            .map(|()| ()).ok_or(CurrentRuntimeScopeError::CurrentMismatch)
    }

    /// Borrows the chronological original verification or returned cause.
    pub fn failure_v2(&self) -> Option<&(dyn Error + 'static)> {
        self.verification.iter().take(self.next).find_map(|slot| {
            slot.claim.as_ref().and_then(|result| result.as_ref().err()).map(|cause| cause as &(dyn Error + 'static))
                .or_else(|| slot.capture.cause())
                .or_else(|| slot.result.as_ref().and_then(|result| result.as_ref().err()).map(|cause| cause as _))
        }).or_else(|| self.repeated.as_ref().map(|cause| cause as _))
    }

    /// Borrows the exact actual first verified signed lease without copying it.
    ///
    /// # Errors
    /// Refuses an incomplete or failed first selected comparison.
    pub fn signed_lease_v2(&self) -> Result<&SignedOwnershipLease, CurrentRuntimeScopeError> {
        if self.repeated.is_some() || self.verification.iter().take(self.next)
            .any(|slot| !matches!(slot.result, Some(Ok(())))) || self.next == 0
        {
            return Err(CurrentRuntimeScopeError::CurrentMismatch);
        }
        self.verification[0].capture.value().ok_or(CurrentRuntimeScopeError::CurrentMismatch)
    }

    /// Forms whole original comparison inputs for the selected signed producer.
    ///
    /// # Errors
    /// Rejects absent actual verification, changed readers/boot, rollback or
    /// exhaustion of the immutable first residency bound.
    pub fn origins_data_v2(&self, first_pre_spawn: RawPairedClockSample,
        execution_parent_plan_expires_seconds: i64)
        -> Result<aos_sandbox_protocol::storage_capture_lifetime::StorageCaptureLifetimeOriginsDataV2,
            CurrentRuntimeScopeError>
    {
        self.signed_lease_v2()?;
        self.selection.origin.validate_later_sample(first_pre_spawn).map_err(|_| CurrentRuntimeScopeError::Clock)?;
        if first_pre_spawn.boottime_nanoseconds() >= self.selection.deadline {
            return Err(CurrentRuntimeScopeError::Clock);
        }
        Ok(aos_sandbox_protocol::storage_capture_lifetime::StorageCaptureLifetimeOriginsDataV2 {
            original_target_clock: self.selection.origin,
            original_lease_digest: self.selection.lease_digest,
            original_lease_generation: self.selection.generation,
            original_lease_authority_expires_seconds: self.selection.authority_expires,
            original_lease_maximum_clock_skew_seconds: self.selection.maximum_skew,
            original_root_plan_expires_seconds: self.selection.plan_expires,
            original_residency_deadline_boottime_nanoseconds: self.selection.deadline,
            first_pre_spawn_clock: first_pre_spawn,
            execution_parent_plan_expires_seconds,
        })
    }
}

impl CurrentAssignmentTarget {
    fn capture_selection_v2(&self) -> Result<OriginalSelectionV2, CurrentRuntimeScopeError> {
        let bound = self.validity.capture.as_ref().ok_or(CurrentRuntimeScopeError::CurrentMismatch)?;
        Ok(OriginalSelectionV2 {
            origin: bound.origin,
            deadline: bound.deadline.as_ref().copied().map_err(|_| CurrentRuntimeScopeError::Clock)?,
            lease_digest: bound.lease_digest, generation: bound.lease_generation,
            authority_expires: bound.authority_expires, maximum_skew: bound.maximum_skew,
            plan_expires: bound.plan_expires,
            assignment: self.binding.manifest().broker_assignment().map_err(|_| CurrentRuntimeScopeError::CurrentMismatch)?,
            holder: self.binding.holder(), node: self.policy.node,
        })
    }

    /// Prices both retained existing-verifier graphs before any model growth.
    ///
    /// This is passive Memory DATA. Rust fields create no namespace fee.
    pub fn capture_lifetime_receiving_demand_v2(&self, journal: &Journal) -> Option<ResourceVector> {
        self.capture_verification_pair_receiving_demand_v4(journal,
            size_of::<OriginalAssignmentCaptureLifetimeV2>())
    }

    pub(super) fn capture_verification_pair_receiving_demand_v4(&self, journal: &Journal,
        carrier_bytes: usize) -> Option<ResourceVector>
    {
        let bound = self.validity.capture.as_ref()?;
        let dynamic = self.policy.ownership_verifier
            .response_receiving_dynamic_bytes_v2(bound.artifact_bytes?)?;
        let gate = journal.get(crate::RecordNamespace::OwnershipGate, self.binding.operation().as_bytes())?;
        let claims = super::receiving::gate_receiving_bytes_v2(gate.len())?.checked_mul(2)?;
        let bytes = dynamic.checked_mul(2)?.checked_add(claims)?
            .checked_add(carrier_bytes.checked_mul(2)?)?;
        Some(ResourceVector::ZERO.with(D::MemoryBytes, u64::try_from(bytes).ok()?))
    }

    /// Creates the inert original-selection destinations after actual C18 prepayment.
    ///
    /// The caller retains this whole owner before `observe_once_v2`, including
    /// on failed verification. No clock is sampled or permission granted here.
    ///
    /// # Errors
    /// Rejects an absent or arithmetically unavailable original selection.
    pub fn prepare_capture_lifetime_v2(&self)
        -> Result<OriginalAssignmentCaptureLifetimeV2, CurrentRuntimeScopeError>
    {
        Ok(OriginalAssignmentCaptureLifetimeV2 {
            selection: self.capture_selection_v2()?, verification: std::array::from_fn(|_| VerificationV2::new()), next: 0, repeated: None,
        })
    }

    /// Borrows the original pure projection failure without observing or granting IO.
    pub fn capture_lifetime_failure_v2(&self) -> Option<&(dyn Error + 'static)> {
        self.validity.capture.as_ref()?.deadline.as_ref().err().map(|cause| cause as _)
    }
}
