//! Retains actual compiler and protected assignment DATA before acceptance.
//!
//! The same parked C18 pays the complete existing Runtime/publication selector
//! before model growth. The public source borrows those retained originals; it
//! cannot construct availability, an accepted Create, a native lease or a grant.

use std::error::Error;

use aos_sandbox_model::{CanonicalAssignmentManifestV1, RawPairedClockSample};
use crate::policy_compiler::provisioning_current::current_manifest::{
    CurrentProtectedAssignmentDataV2, CurrentProtectedAssignmentErrorV3,
    current_protected_assignment_data_v2,
};

use super::*;

#[derive(Clone, Copy)]
enum SourceFirst { Geometry, Funding, Selection, Binding, Reentry }

pub(super) struct ExecutionPublicAssignmentOriginalV2 {
    geometry: Slot<ResourceVector, ResourceReservationErrorV1>,
    funding: Slot<(), ResourceReservationErrorV1>,
    funding_native_selected: bool,
    assignment: Slot<CurrentProtectedAssignmentDataV2, CurrentProtectedAssignmentErrorV3>,
    binding: Slot<(), JournalError>,
    first: Option<SourceFirst>,
}

impl ExecutionPublicAssignmentOriginalV2 {
    pub(super) fn assignment_data_v2(&self) -> Result<&CurrentProtectedAssignmentDataV2, JournalError> {
        if self.first.is_some() || !matches!(self.binding, Some(Ok(()))) {
            return Err(JournalError::ProtectedBoundary);
        }
        self.assignment.as_ref().and_then(|value| value.as_ref().ok())
            .ok_or(JournalError::ProtectedBoundary)
    }

    pub(super) fn new() -> Self {
        Self { geometry: None, funding: None, funding_native_selected: false,
            assignment: None, binding: None, first: None }
    }

    pub(super) fn funding_native_selected_v2(&self) -> bool {
        self.funding_native_selected && matches!(self.first, Some(SourceFirst::Funding))
    }

    pub(super) fn failure_v2(&self) -> Option<&(dyn Error + 'static)> {
        match self.first? {
            SourceFirst::Geometry => error(&self.geometry),
            SourceFirst::Funding => error(&self.funding),
            SourceFirst::Selection => self.assignment.as_ref()?.as_ref().err().map(|cause| cause as _),
            SourceFirst::Binding => error(&self.binding),
            SourceFirst::Reentry => Some(&ResourceReservationErrorV1::Conflict),
        }
    }
}

/// Borrows the actual predurable compiler request and protected assignment.
///
/// The source supplies comparison DATA for the genuine retained Host and both
/// Storage availability owners. It neither names an accepted Create operation
/// nor turns historical assignment records into a live native currentness loan.
pub struct ExecutionPublicPreacceptSourceDataV2<'scope> {
    horizon: (RawPairedClockSample, i64, u64, u64),
    plan: &'scope Arc<crate::OperationPlan>,
    assignment: &'scope CurrentProtectedAssignmentDataV2,
}

impl ExecutionPublicPreacceptSourceDataV2<'_> {
    /// Borrows the exact manifest selected from both actual protected records.
    #[must_use]
    pub fn assignment_manifest_v2(&self) -> &CanonicalAssignmentManifestV1 {
        self.assignment.manifest_v2()
    }

    /// Returns the normalized digest of the actual retained production plan.
    #[must_use]
    pub fn public_request_digest_v2(&self) -> [u8; 32] {
        self.plan.request_digest()
    }

    /// Returns the same paid authorization clock without sampling a replacement.
    #[must_use]
    pub fn original_authorization_clock_v2(&self) -> RawPairedClockSample {
        self.horizon.0
    }

    /// Returns the exclusive original capability and policy expiry minimum.
    #[must_use]
    pub fn authorization_expires_v2(&self) -> i64 {
        self.horizon.1
    }

    /// Returns the immutable public request cutoff accepted by its actual peer.
    #[must_use]
    pub fn original_peer_deadline_v2(&self) -> u64 {
        self.horizon.2
    }

    /// Returns the actual Exec mutation's original bounded operation timeout.
    #[must_use]
    pub fn operation_timeout_nanoseconds_v2(&self) -> u64 {
        self.horizon.3
    }
}

impl ExecutionPublicAdmissionScopeV2 {
    pub(crate) fn prepare_assignment_once_v2(&mut self, controller: &mut Journal)
        -> Result<(), JournalError>
    {
        self.require_current_v2(controller)?;
        let Some(original) = self.prefix.assignment.as_ref() else {
            return Err(JournalError::ProtectedBoundary);
        };
        if original.geometry.is_some() {
            if let Some(original) = self.prefix.assignment.as_mut() {
                original.first.get_or_insert(SourceFirst::Reentry);
            }
            self.prefix.first.get_or_insert(First::Assignment);
            return Err(JournalError::ProtectedBoundary);
        }

        let returned = self.prepare_assignment_inner_v2(controller);
        if returned.is_err() {
            self.prefix.first.get_or_insert(First::Assignment);
        }
        returned
    }

    fn prepare_assignment_inner_v2(&mut self, controller: &mut Journal) -> Result<(), JournalError> {
        let bad = || JournalError::ProtectedBoundary;
        let compiler = self.prefix.compiler.as_ref().ok_or_else(bad)?;
        let plan = self.prefix.plan.as_ref().ok_or_else(bad)?;
        if !compiler.retains_plan_v2(plan) {
            return Err(bad());
        }
        let target = compiler.preaccept_target_v2()?;
        let original = self.prefix.assignment.as_mut().ok_or_else(bad)?;
        original.geometry = Some((|| {
            let selector = crate::runtime_authority::current_publication_receiving_demand_v2(controller)
                .ok_or(ResourceReservationErrorV1::Conflict)?;
            let bytes = crate::policy_compiler::provisioning_current::current_manifest::
                current_protected_assignment_carrier_receiving_bytes_v2()
                .and_then(|bytes| bytes.checked_add(std::mem::size_of::<ExecutionPublicPreacceptSourceDataV2<'_>>().checked_mul(2)?))
                .and_then(|bytes| u64::try_from(bytes).ok()).ok_or(ResourceReservationErrorV1::Conflict)?;
            selector.checked_add(ResourceVector::ZERO.with(D::MemoryBytes, bytes)).map_err(Into::into)
        })());
        let demand = match original.geometry.as_ref().and_then(|value| value.as_ref().ok()).copied() {
            Some(demand) => demand,
            None => {
                original.first = Some(SourceFirst::Geometry);
                return Err(bad());
            }
        };
        original.funding = Some((|| {
            let bank = self.bank.lock().map_err(|_| ResourceReservationErrorV1::EnrollmentUnavailable)?;
            let mut loan = self.financial.resume_public_admission_v2(&bank, controller, self.profile.as_ref())?;
            let complete = loan.prefix_demand_v2().checked_add(demand)?;
            let returned = loan.require_complete_v2(&bank, controller, self.profile.as_ref(),
                Demand::from_demand_v1(complete));
            let parked = loan.park_public_admission_v2();
            returned.and(parked)
        })());
        if !matches!(original.funding, Some(Ok(()))) {
            original.funding_native_selected = self.financial.failure().is_some();
            original.first = Some(SourceFirst::Funding);
            return Err(bad());
        }

        original.assignment = Some(current_protected_assignment_data_v2(controller, target.0));
        let Some(assignment) = original.assignment.as_ref().and_then(|value| value.as_ref().ok()) else {
            original.first = Some(SourceFirst::Selection);
            return Err(bad());
        };
        original.binding = Some((|| {
            let manifest = assignment.manifest_v2().manifest();
            if manifest.sandbox() != target.0 || manifest.incarnation().as_bytes() != &target.1
                || manifest.project() != target.2 || compiler.preaccept_horizon_checked_v2().is_err()
            {
                return Err(bad());
            }
            Ok(())
        })());
        if !matches!(original.binding, Some(Ok(()))) {
            original.first = Some(SourceFirst::Binding);
            return Err(bad());
        }
        Ok(())
    }

    /// Borrows actual retained comparison inputs without issuing availability.
    ///
    /// # Errors
    /// Refuses missing/failed preparation, a changed retained compiler/plan, or
    /// unavailable protected assignment and original authorization coordinates.
    pub fn preaccept_source_data_v2(&self) -> Result<ExecutionPublicPreacceptSourceDataV2<'_>, JournalError> {
        if self.retired || self.prefix.first.is_some()
            || !matches!(self.prefix.prepared_outcome, Some(Ok(())))
        {
            return Err(JournalError::ProtectedBoundary);
        }
        let compiler = self.prefix.compiler.as_ref().ok_or(JournalError::ProtectedBoundary)?;
        let plan = self.prefix.plan.as_ref().ok_or(JournalError::ProtectedBoundary)?;
        let original = self.prefix.assignment.as_ref().ok_or(JournalError::ProtectedBoundary)?;
        if original.first.is_some() || !matches!(original.binding, Some(Ok(())))
            || !compiler.retains_plan_v2(plan) || compiler.preaccept_horizon_checked_v2().is_err()
        {
            return Err(JournalError::ProtectedBoundary);
        }
        let assignment = original.assignment.as_ref().and_then(|value| value.as_ref().ok())
            .ok_or(JournalError::ProtectedBoundary)?;
        let horizon = compiler.preaccept_horizon_checked_v2()?;
        Ok(ExecutionPublicPreacceptSourceDataV2 { horizon, plan, assignment })
    }
}
