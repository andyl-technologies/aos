//! Joins protected accepted Create to its same retained public/assignment source.
//!
//! The accepted C18 borrower supplies the sole current accepted context. Its
//! separate public retirement obligation retains actual projection models and
//! exact comparison results for the Host64/Storage65 accepted-bind senders.

use aos_sandbox_model::{CanonicalAssignmentManifestV1, ExecutionId};
use aos_sandbox_protocol::domain_ledger::effect_history::PublicMutationEffectHistoryV1;
use aos_sandbox_protocol::host_execution_no_apply::{BeforeArgumentNoApplySourceDataV2,
    BeforeArgumentNoApplySourceFieldsV2};

use super::*;

pub(super) struct ExecutionAcceptedBindOriginalV2 {
    geometry: Slot<ResourceVector, ResourceReservationErrorV1>,
    funding: Slot<(), ResourceReservationErrorV1>,
    target: crate::reconciler::AcceptedExecutionTargetOriginalV2,
    binding: Slot<(), JournalError>,
    funding_native_selected: bool,
    entered: bool,
    context: Slot<Option<PublicMutationEffectHistoryV1>, crate::ReconcilerError>,
    resume: Slot<(), JournalError>,
}

impl ExecutionAcceptedBindOriginalV2 {
    pub(super) fn new() -> Self {
        Self { geometry: None, funding: None,
            target: crate::reconciler::AcceptedExecutionTargetOriginalV2::new(),
            binding: None, funding_native_selected: false, entered: false,
            context: None, resume: None }
    }

    pub(super) fn failure_v2(&self) -> Option<&(dyn Error + 'static)> {
        error(&self.geometry).or_else(|| error(&self.funding))
            .or_else(|| self.target.failure_v2()).or_else(|| error(&self.binding))
            .or_else(|| error(&self.context)).or_else(|| error(&self.resume))
    }

    pub(super) fn funding_native_selected_v2(&self) -> bool { self.funding_native_selected }
}

/// Borrows one real protected accepted Create and its original assignment DATA.
///
/// The value can supply the AOSNAB02 accepted-bind body without manufacturing
/// argument-source H/T fields. It is comparison DATA, not a Host/Storage lease,
/// terminal proof, effect grant or permission to send a replacement request.
pub struct ExecutionAcceptedCreateSourceDataV2<'original> {
    operation: OperationId,
    execution: ExecutionId,
    manifest: &'original aos_sandbox_model::CanonicalAssignmentManifestV1,
    public_request_digest: [u8; 32],
    host_boot: [u8; 16],
}

impl ExecutionAcceptedCreateSourceDataV2<'_> {
    /// Encodes the exact actual source without manufacturing argument H/T.
    ///
    /// # Errors
    /// Rejects an invalid identity or assignment coordinate in retained DATA.
    pub fn canonical_before_argument_source_v2(&self)
        -> Result<BeforeArgumentNoApplySourceDataV2, JournalError> {
        let manifest = self.manifest.manifest();
        BeforeArgumentNoApplySourceDataV2::new(BeforeArgumentNoApplySourceFieldsV2 {
            create_operation: self.operation.into_bytes(), execution: self.execution.into_bytes(),
            sandbox: *manifest.sandbox().as_bytes(), incarnation: *manifest.incarnation().as_bytes(),
            node: *manifest.node().as_bytes(), host_boot: self.host_boot,
            assignment_epoch: manifest.epoch().get(), desired_generation: manifest.desired_generation().get(),
            accepted_request_digest: self.public_request_digest,
            assignment_digest: *self.manifest.digest().as_bytes(),
        }).map_err(|_| JournalError::ProtectedBoundary)
    }

    /// Returns the actual protected accepted Create operation.
    #[must_use]
    pub const fn operation_v2(&self) -> OperationId { self.operation }

    /// Returns the exact current Requested execution selected by that Create.
    #[must_use]
    pub const fn execution_v2(&self) -> ExecutionId { self.execution }

    /// Borrows the same original protected assignment selected before acceptance.
    #[must_use]
    pub const fn assignment_manifest_v2(&self) -> &CanonicalAssignmentManifestV1 { self.manifest }

    /// Returns the normalized digest of the same retained public compiler plan.
    #[must_use]
    pub const fn public_request_digest_v2(&self) -> [u8; 32] { self.public_request_digest }

    /// Returns the actual original local kernel boot from paid authorization.
    #[must_use]
    pub const fn host_boot_v2(&self) -> [u8; 16] { self.host_boot }
}

impl ControllerExecutionAdmissionRetirementV2<'_> {
    /// Retains the exact accepted source beside its same native C18 borrower.
    ///
    /// # Errors
    /// Refuses reentry, changed native/current Journal or operation, failed
    /// complete receiving, another accepted request/projection/assignment, or
    /// absent canonical preparation. All reached models and errors stay held.
    pub fn prepare_accepted_create_source_once_v2(
        &mut self,
        loan: &mut ControllerExecutionOperationReceivingLoanV1<'_>,
        bank: &ControllerResourceBankOpeningV1,
        controller: &mut Journal,
        profile: &ProductionControllerNormalRootProfileV1,
    ) -> Result<(), ResourceReservationErrorV1> {
        let returned = self.prepare_accepted_source_inner_v2(loan, bank, controller, profile);
        if returned.is_err() {
            self.prefix.first.get_or_insert(First::AcceptedBind);
        }
        returned
    }

    fn prepare_accepted_source_inner_v2(
        &mut self,
        loan: &mut ControllerExecutionOperationReceivingLoanV1<'_>,
        bank: &ControllerResourceBankOpeningV1,
        controller: &mut Journal,
        profile: &ProductionControllerNormalRootProfileV1,
    ) -> Result<(), ResourceReservationErrorV1> {
        let bad = || ResourceReservationErrorV1::Conflict;
        if !self.active || self.prefix.first.is_some() || loan.operation != self.operation
            || self.prefix.journal_identity.as_ref().is_none_or(|identity| {
                !identity.is_same_original_v4(loan.journal_identity)
                    || !identity.is_same_original_v4(&controller.execution_observation_identity_v4())
            })
        {
            return Err(bad());
        }
        if self.prefix.accepted_bind.as_ref().is_some_and(|original| original.entered) {
            let accepted = loan.accepted_v1().ok_or_else(bad)?;
            let returned = require_retained_accepted_binding_data_v2(
                self.prefix, controller, self.operation, accepted);
            let original = self.prefix.accepted_bind.as_mut().ok_or_else(bad)?;
            if original.resume.is_some() || !matches!(original.binding, Some(Ok(()))) {
                return Err(bad());
            }
            original.resume = Some(returned);
            return if matches!(original.resume, Some(Ok(()))) { Ok(()) } else { Err(bad()) };
        }
        let original = self.prefix.accepted_bind.as_mut().ok_or_else(bad)?;
        original.entered = true;
        original.geometry = Some(accepted_target_receiving_demand_v2(controller));
        let demand = original.geometry.as_ref().and_then(|value| value.as_ref().ok())
            .copied().ok_or_else(bad)?;
        original.funding = Some((|| {
            let complete = loan.prefix_demand_v1().checked_add(demand)?;
            loan.require_complete_v1(bank, controller, profile, Demand::from_demand_v1(complete))
        })());
        if !matches!(original.funding, Some(Ok(()))) {
            original.funding_native_selected = true;
            return Err(bad());
        }

        let accepted = loan.accepted_v1().ok_or_else(bad)?;
        original.target.observe_once_v2(controller, self.operation, accepted)
            .map_err(|_| bad())?;
        let binding = require_retained_accepted_binding_data_v2(self.prefix, controller, self.operation, accepted);
        let original = self.prefix.accepted_bind.as_mut().ok_or_else(bad)?;
        original.binding = Some(binding);
        if !matches!(original.binding, Some(Ok(()))) { return Err(bad()); }
        Ok(())
    }

    /// Borrows the retained exact accepted-bind DATA after its actual native join.
    ///
    /// # Errors
    /// Refuses a failed/retired prefix or missing retained accepted source.
    pub fn accepted_create_source_data_v2(&self) -> Result<ExecutionAcceptedCreateSourceDataV2<'_>, JournalError> {
        let bad = || JournalError::ProtectedBoundary;
        if !self.active || self.prefix.first.is_some() { return Err(bad()); }
        let original = self.prefix.accepted_bind.as_ref().ok_or_else(bad)?;
        if !matches!(original.binding, Some(Ok(()))) { return Err(bad()); }
        let (_, execution) = original.target.target_v2().map_err(|_| bad())?;
        let assignment = self.prefix.assignment.as_ref().ok_or_else(bad)?.assignment_data_v2()?;
        let compiler = self.prefix.compiler.as_ref().ok_or_else(bad)?;
        let plan = self.prefix.plan.as_ref().ok_or_else(bad)?;
        let clock = compiler.preaccept_horizon_checked_v2()?.0;
        Ok(ExecutionAcceptedCreateSourceDataV2 { operation: self.operation, execution,
            manifest: assignment.manifest_v2(), public_request_digest: plan.request_digest(),
            host_boot: clock.host_boot_id() })
    }
}

// Both native consumers pay this exact same selector representation before
// invoking the one original target decoder; no second projection path exists.
fn accepted_target_receiving_demand_v2(
    controller: &Journal,
) -> Result<ResourceVector, ResourceReservationErrorV1> {
    let bad = || ResourceReservationErrorV1::Conflict;
    let decoder =
        crate::controller_service::public_projection::execution_source_receiving_bytes_v1(
            controller,
        )
        .ok_or_else(bad)?
        .max(
            crate::controller_service::public_projection::sandbox_source_receiving_bytes_v1(
                controller,
            )
            .ok_or_else(bad)?,
        )
        .max(
            crate::controller_service::public_projection::metadata_source_receiving_bytes_v2(
                controller,
            )
            .ok_or_else(bad)?,
        );
    let rows = controller
        .records(crate::RecordNamespace::DesiredState)
        .filter(|(key, _)| {
            key.starts_with(aos_sandbox_protocol::public_api::projection::PROJECTION_KEY_PREFIX)
        })
        .try_fold(0_u64, |count, _| count.checked_add(1))
        .ok_or_else(bad)?;
    let carriers = u64::try_from(std::mem::size_of::<
        aos_sandbox_protocol::public_api::projection::PublicProjectionRecordV1,
    >())
    .map_err(|_| bad())?;
    let memory = decoder
        .checked_mul(rows.checked_add(1).ok_or_else(bad)?)
        .and_then(|bytes| bytes.checked_add(carriers.checked_mul(rows)?.checked_mul(2)?))
        .ok_or_else(bad)?;
    Ok(ResourceVector::ZERO.with(D::MemoryBytes, memory))
}

fn require_retained_accepted_binding_data_v2(
    prefix: &ExecutionPublicAdmissionPrefixV2,
    controller: &Journal,
    operation: OperationId,
    accepted: &PublicMutationEffectHistoryV1,
) -> Result<(), JournalError> {
    let original = prefix
        .accepted_bind
        .as_ref()
        .ok_or(JournalError::ProtectedBoundary)?;
    let compiler = prefix
        .compiler
        .as_ref()
        .ok_or(JournalError::ProtectedBoundary)?;
    let plan = prefix
        .plan
        .as_ref()
        .ok_or(JournalError::ProtectedBoundary)?;
    let assignment = prefix
        .assignment
        .as_ref()
        .and_then(|original| original.assignment_data_v2().ok())
        .ok_or(JournalError::ProtectedBoundary)?;
    let (sandbox, _) = original
        .target
        .target_v2()
        .map_err(|_| JournalError::ProtectedBoundary)?;
    plan.require_same_public_execution_projection_v2(controller)?;
    if !compiler.retains_plan_v2(plan)
        || !compiler.matches_accepted_context_v2(accepted)
        || assignment.manifest_v2().manifest().sandbox() != sandbox
        || plan.operation_id() != operation
    {
        return Err(JournalError::ProtectedBoundary);
    }
    Ok(())
}

impl ExecutionPublicAdmissionScopeV2 {
    pub(super) fn accepted_bind_retained_demand_v2(
        &self,
    ) -> Result<ResourceVector, ResourceReservationErrorV1> {
        let Some(original) = self.prefix.accepted_bind.as_ref() else {
            return Err(ResourceReservationErrorV1::Conflict);
        };
        if !matches!(original.funding, Some(Ok(()))) {
            return Ok(ResourceVector::ZERO);
        }
        original
            .geometry
            .as_ref()
            .and_then(|value| value.as_ref().ok())
            .copied()
            .ok_or(ResourceReservationErrorV1::Conflict)
    }

    /// Reads already-durable acceptance under the same parked, receiving-only C18.
    pub(super) fn prepare_availability_accepted_source_once_v2(
        &mut self,
        controller: &mut Journal,
    ) -> Result<(), ResourceReservationErrorV1> {
        let returned = self.prepare_availability_accepted_source_inner_v2(controller);
        if returned.is_err() {
            self.prefix.first.get_or_insert(First::AcceptedBind);
        }
        returned
    }

    fn prepare_availability_accepted_source_inner_v2(
        &mut self,
        controller: &mut Journal,
    ) -> Result<(), ResourceReservationErrorV1> {
        let bad = || ResourceReservationErrorV1::Conflict;
        self.require_current_v2(controller).map_err(|_| bad())?;
        let operation = match self.prefix.accepted_outcome {
            Some(Ok(
                crate::AcceptOutcome::Accepted(operation) | crate::AcceptOutcome::Replay(operation),
            )) => operation,
            _ => return Err(bad()),
        };
        let original = self.prefix.accepted_bind.as_mut().ok_or_else(bad)?;
        if original.entered {
            return Err(bad());
        }
        original.entered = true;
        original.geometry = Some((|| {
            let target = accepted_target_receiving_demand_v2(controller)?;
            let accepted =
                crate::reconciler::accepted_public_effect_models_receiving_bytes_retaining_v4(
                    controller,
                )?;
            let fixed = std::mem::size_of::<ExecutionAcceptedBindOriginalV2>()
                .checked_mul(2)
                .and_then(|bytes| bytes.checked_add(accepted))
                .and_then(|bytes| u64::try_from(bytes).ok())
                .ok_or_else(bad)?;
            target
                .checked_add(ResourceVector::ZERO.with(D::MemoryBytes, fixed))
                .map_err(Into::into)
        })());
        let demand = original
            .geometry
            .as_ref()
            .and_then(|value| value.as_ref().ok())
            .copied()
            .ok_or_else(bad)?;
        original.funding = Some((|| {
            let bank = self
                .bank
                .lock()
                .map_err(|_| ResourceReservationErrorV1::EnrollmentUnavailable)?;
            let mut loan = self.financial.resume_public_admission_v2(
                &bank,
                controller,
                self.profile.as_ref(),
            )?;
            let complete = loan.prefix_demand_v2().checked_add(demand)?;
            let returned = loan.require_complete_v2(
                &bank,
                controller,
                self.profile.as_ref(),
                Demand::from_demand_v1(complete),
            );
            let parked = loan.park_public_admission_v2();
            returned.and(parked)
        })());
        if !matches!(original.funding, Some(Ok(()))) {
            original.funding_native_selected = self.financial.failure().is_some();
            return Err(bad());
        }

        let context = crate::reconciler::accepted_create_execution_effect_from_journal_v1(
            controller, operation,
        );
        let returned = (|| {
            let accepted = context
                .as_ref()
                .ok()
                .and_then(|value| value.as_ref())
                .ok_or_else(bad)?;
            let original = self.prefix.accepted_bind.as_mut().ok_or_else(bad)?;
            original
                .target
                .observe_once_v2(controller, operation, accepted)
                .map_err(|_| bad())?;
            let binding = require_retained_accepted_binding_data_v2(
                &self.prefix,
                controller,
                operation,
                accepted,
            );
            let original = self.prefix.accepted_bind.as_mut().ok_or_else(bad)?;
            original.binding = Some(binding);
            if matches!(original.binding, Some(Ok(()))) {
                Ok(())
            } else {
                Err(bad())
            }
        })();
        // Restore the whole actual decoder result before returning any error.
        self.prefix.accepted_bind.as_mut().ok_or_else(bad)?.context = Some(context);
        if returned.is_err() {
            self.prefix.first.get_or_insert(First::AcceptedBind);
        }
        returned
    }

    pub(super) fn availability_accepted_wire_data_v2(
        &self,
    ) -> Result<BeforeArgumentNoApplySourceDataV2, JournalError> {
        if self.prefix.first.is_some() {
            return Err(JournalError::ProtectedBoundary);
        }
        let operation = match self.prefix.accepted_outcome {
            Some(Ok(
                crate::AcceptOutcome::Accepted(operation) | crate::AcceptOutcome::Replay(operation),
            )) => operation,
            _ => return Err(JournalError::ProtectedBoundary),
        };
        let original = self
            .prefix
            .accepted_bind
            .as_ref()
            .ok_or(JournalError::ProtectedBoundary)?;
        if !matches!(original.binding, Some(Ok(()))) {
            return Err(JournalError::ProtectedBoundary);
        }
        let (_, execution) = original
            .target
            .target_v2()
            .map_err(|_| JournalError::ProtectedBoundary)?;
        let assignment = self
            .prefix
            .assignment
            .as_ref()
            .ok_or(JournalError::ProtectedBoundary)?
            .assignment_data_v2()?;
        let compiler = self
            .prefix
            .compiler
            .as_ref()
            .ok_or(JournalError::ProtectedBoundary)?;
        let plan = self
            .prefix
            .plan
            .as_ref()
            .ok_or(JournalError::ProtectedBoundary)?;
        let source = ExecutionAcceptedCreateSourceDataV2 {
            operation,
            execution,
            manifest: assignment.manifest_v2(),
            public_request_digest: plan.request_digest(),
            host_boot: compiler.preaccept_horizon_checked_v2()?.0.host_boot_id(),
        };
        source.canonical_before_argument_source_v2()
    }
}
