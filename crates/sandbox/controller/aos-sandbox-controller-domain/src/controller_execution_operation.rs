//! Keeps accepted execution work on the original Controller purpose18 flight.
//!
//! Claiming the configured subdivision does not authorize an execution. Entry
//! consumes its finite whole flight before the sole accepted-effect decoder,
//! and the actual accepted context remains borrowed through subsequent native
//! work. Source and Environment access share the original exclusive Source cut.

use std::error::Error;
use std::mem::size_of;

use aos_sandbox_model::{OperationId, ResourceDimension as D, ResourceVector};
use aos_sandbox_protocol::domain_ledger::effect_history::PublicMutationEffectHistoryV1;

use crate::controller_resource_reservation::{
    ControllerOperationIntakeDemandDataV1 as Demand,
    ControllerOperationIntakeOriginalV1, ControllerOperationIntakeReceivingLoanV1,
    ControllerResourceBankOpeningV1, ResourceReservationErrorV1,
};
use crate::environment::EnvironmentExecutionEvidenceOriginalV1;
use crate::normal_root::ProductionControllerNormalRootProfileV1;
use crate::{Journal, ReconcilerError};

mod admission;
mod no_apply_cleanup;
mod no_apply_client;
pub(crate) use no_apply_client::ControllerExecutionNoApplyAppendLoanV2;
pub use no_apply_client::{ControllerExecutionNoApplyClientLoanV2, ControllerExecutionNoApplyOriginalV2,
    ControllerExecutionNoApplyRecoveredMetadataV2};
pub use no_apply_client::{ControllerExecutionNoApplyCompletionV2, ControllerExecutionNoApplyDisposedOriginalV2,
    ControllerExecutionNoApplyTerminalRetirementV2};
pub use no_apply_cleanup::{ControllerExecutionCleanupReceivingLoanV2, ControllerExecutionCleanupSourceLoanV2};
mod runtime_custody;
pub use runtime_custody::{ControllerExecutionRuntimeCustodyV2, ControllerExecutionPublicCustodyTransferV2};
pub(crate) mod public_admission;
pub use admission::ControllerExecutionAdmissionReceivingLoanV2;
pub use public_admission::{ExecutionPublicAdmissionScopeV2, ControllerExecutionAdmissionRetirementV2};
pub use public_admission::ExecutionPublicPreacceptSourceDataV2;
pub use public_admission::ExecutionAcceptedCreateSourceDataV2;
pub use public_admission::ControllerExecutionAvailabilityClientLoanV2;
pub use public_admission::ControllerExecutionAvailabilityPositiveRetirementV2;
pub use public_admission::ControllerExecutionAvailabilitySessionCurrentnessErrorV2;

/// Owns the genuine configured execution subdivision and its reached originals.
///
/// This owner can only be claimed from the actual Bank/Controller/profile
/// conjunction. It has no account, policy-vector, reset or detached proof factory.
pub struct ControllerExecutionOperationOriginalV1 {
    native: ControllerOperationIntakeOriginalV1,
    journal_identity: crate::journal::ExecutionObservationJournalIdentityV4,
    accepted: Option<Result<Option<PublicMutationEffectHistoryV1>, ReconcilerError>>,
    append_demand: Option<Result<ResourceVector, crate::journal::JournalAppendReceivingDemandErrorV1>>,
    binding: Option<Result<(), ResourceReservationErrorV1>>,
    entry: Option<Result<(), ResourceReservationErrorV1>>,
    post: Option<Result<(), ResourceReservationErrorV1>>,
    evidence: EnvironmentExecutionEvidenceOriginalV1,
    clock: ControllerExecutionClockOriginalV1,
    active: bool,
    predurable_entered: bool,
    predurable_prefix: Option<ResourceVector>,
    environment_failure: Option<crate::protected_domain_journal::ProtectedDomainJournalErrorV1>,
    cleanup: no_apply_cleanup::ControllerExecutionCleanupOriginalV2,
}

/// Continuously borrows the consumed execution flight and accepted input.
#[must_use]
pub struct ControllerExecutionOperationReceivingLoanV1<'owner> {
    operation: OperationId,
    journal_identity: &'owner crate::journal::ExecutionObservationJournalIdentityV4,
    native: ControllerOperationIntakeReceivingLoanV1<'owner>,
    accepted: &'owner mut Option<Result<Option<PublicMutationEffectHistoryV1>, ReconcilerError>>,
    append_demand: &'owner mut Option<Result<ResourceVector, crate::journal::JournalAppendReceivingDemandErrorV1>>,
    binding: &'owner Option<Result<(), ResourceReservationErrorV1>>,
    entry: &'owner Option<Result<(), ResourceReservationErrorV1>>,
    post: &'owner mut Option<Result<(), ResourceReservationErrorV1>>,
    evidence: &'owner mut EnvironmentExecutionEvidenceOriginalV1,
    clock: &'owner mut ControllerExecutionClockOriginalV1,
    active: &'owner mut bool,
    prefix: ResourceVector,
    environment_failure: &'owner mut Option<crate::protected_domain_journal::ProtectedDomainJournalErrorV1>,
}

impl ControllerExecutionOperationOriginalV1 {
    /// Claims the actual declared execution lane before constructing its owner.
    ///
    /// `runtime_resident` is passive concrete upper representation DATA. It
    /// cannot select a purpose, amount, payer or larger declaration: the Bank
    /// obtains those exclusively from its measured original and same C writer.
    ///
    /// # Errors
    /// Rejects missing/foreign enrollment, profile or declaration, a prior
    /// claim, or insufficient configured capacity for the concrete resident peak.
    pub fn claim_once_v1(
        bank: &ControllerResourceBankOpeningV1,
        controller: &mut Journal,
        profile: &ProductionControllerNormalRootProfileV1,
        runtime_resident: aos_sandbox_broker::controller_receiving::bank_launch::ControllerOperationIntakeDemandDataV1,
    ) -> Result<Self, ResourceReservationErrorV1> {
        let resident = Self::resident_demand_v2(runtime_resident.demand_v1())?;
        let native = bank.claim_declared_execution_operation_intake_once_v1(
            controller, profile, Demand::from_demand_v1(resident),
        )?;
        Ok(Self::from_funded_intake_v2(native, controller))
    }

    pub(crate) fn resident_demand_v2(runtime: ResourceVector)
        -> Result<ResourceVector, ResourceReservationErrorV1> {
        let bytes = size_of::<Self>().checked_mul(2)
            .and_then(|bytes| bytes.checked_add(size_of::<public_admission::ExecutionPublicAdmissionScopeV2>().checked_mul(2)?))
            .and_then(|bytes| bytes.checked_add(size_of::<usize>().checked_mul(2)?))
            .and_then(|n| u64::try_from(n).ok()).ok_or(ResourceReservationErrorV1::Conflict)?;
        Ok(runtime.checked_add(ResourceVector::ZERO.with(D::MemoryBytes, bytes))?)
    }

    // Both initial enrollment and recovered enrollment supply the actual
    // permanently funded native owner. A declared vector cannot enter here.
    pub(crate) fn from_funded_intake_v2(
        native: ControllerOperationIntakeOriginalV1,
        controller: &Journal,
    ) -> Self {
        Self { native, journal_identity: controller.execution_observation_identity_v4(),
            accepted: None, append_demand: None, binding: None, entry: None, post: None,
            evidence: EnvironmentExecutionEvidenceOriginalV1::new(), clock: ControllerExecutionClockOriginalV1::new(), active: false, predurable_entered: false, predurable_prefix: None, environment_failure: None,
            cleanup: no_apply_cleanup::ControllerExecutionCleanupOriginalV2::new() }
    }

    pub(crate) fn bind_recovered_enrollment_once_v2(
        &mut self,
        bank: &ControllerResourceBankOpeningV1,
        enrolled: &aos_sandbox_broker::controller_receiving::bank_launch::ControllerRecoveredEnrollmentReceivingV2,
        controller: &Journal,
        profile: &ProductionControllerNormalRootProfileV1,
    ) -> Result<(), ResourceReservationErrorV1> {
        bank.bind_recovered_operation_intake_once_v2(
            &mut self.native, enrolled, controller, profile,
        )
    }

    /// Checks placement of this actual unentered recovered operation owner.
    ///
    /// This comparison grants no native effect or fresh receiving interval.
    ///
    /// # Errors
    /// Refuses prior entry, initial funding, a foreign bank or changed enrollment.
    #[doc(hidden)]
    pub fn require_unentered_recovered_runtime_placement_v2(
        &self,
        bank: &ControllerResourceBankOpeningV1,
        controller: &Journal,
        profile: &ProductionControllerNormalRootProfileV1,
    ) -> Result<(), ResourceReservationErrorV1> {
        use aos_sandbox_broker::controller_receiving::bank_launch::ControllerOperationIntakeFundingKindDataV2 as Kind;

        if self.active || self.entry.is_some() || self.accepted.is_some()
            || self.binding.is_some() || self.post.is_some()
            || self.native.funding_kind_data_v2() != Kind::RecoveredBaseline
        {
            return Err(ResourceReservationErrorV1::Conflict);
        }
        bank.require_funded_operation_intake_entry_v2(&self.native, controller, profile)
    }

    /// Consumes the same whole finite flight before any accepted-model decode.
    ///
    /// The expected context is comparison DATA from the actual executor call.
    /// Only the existing protected accepted-effect engine supplies the context
    /// lent by the returned scope. A failed entered body still owes its native
    /// post and keeps every reached original in this owner.
    ///
    /// # Errors
    /// Rejects overlap, failed prior work, arithmetic overflow or insufficient
    /// declaration before new native/model growth.
    pub fn begin_once_v1<'owner>(
        &'owner mut self,
        bank: &ControllerResourceBankOpeningV1,
        controller: &mut Journal,
        profile: &ProductionControllerNormalRootProfileV1,
        operation: OperationId,
        expected: &PublicMutationEffectHistoryV1,
        runtime_fixed: aos_sandbox_broker::controller_receiving::bank_launch::ControllerOperationIntakeDemandDataV1,
    ) -> Result<ControllerExecutionOperationReceivingLoanV1<'owner>, ResourceReservationErrorV1> {
        self.begin_execution_engine_v4(bank, controller, profile, operation, Some(expected), runtime_fixed)
    }

    /// Begins a read of the actual protected Create execution after payment.
    ///
    /// No caller-decoded context can replace the canonical accepted operation
    /// selected by this same scope. The original fixed subdivision and spent
    /// traffic remain unchanged across positive observation intervals.
    ///
    /// # Errors
    /// Refuses overlap, prior failure, insufficient capacity or an unrelated,
    /// blocked or corrupt protected Create execution operation.
    pub fn begin_periodic_observation_once_v4<'owner>(
        &'owner mut self,
        bank: &ControllerResourceBankOpeningV1,
        controller: &mut Journal,
        profile: &ProductionControllerNormalRootProfileV1,
        operation: OperationId,
        runtime_fixed: aos_sandbox_broker::controller_receiving::bank_launch::ControllerOperationIntakeDemandDataV1,
    ) -> Result<ControllerExecutionOperationReceivingLoanV1<'owner>, ResourceReservationErrorV1> {
        self.begin_execution_engine_v4(bank, controller, profile, operation, None, runtime_fixed)
    }

    fn begin_execution_engine_v4<'owner>(
        &'owner mut self,
        bank: &ControllerResourceBankOpeningV1,
        controller: &mut Journal,
        profile: &ProductionControllerNormalRootProfileV1,
        operation: OperationId,
        expected: Option<&PublicMutationEffectHistoryV1>,
        runtime_fixed: aos_sandbox_broker::controller_receiving::bank_launch::ControllerOperationIntakeDemandDataV1,
    ) -> Result<ControllerExecutionOperationReceivingLoanV1<'owner>, ResourceReservationErrorV1> {
        if self.active || self.accepted.is_some() || self.post.is_some() {
            return Err(ResourceReservationErrorV1::Conflict);
        }
        let prefix = accepted_receiving_demand_v1(controller)?
            .checked_add(ControllerExecutionClockOriginalV1::fixed_demand_v1()
                .ok_or(ResourceReservationErrorV1::Conflict)?)?
            .checked_add(runtime_fixed.demand_v1())?
            .checked_add(EnvironmentExecutionEvidenceOriginalV1::fixed_demand_v1()
                .ok_or(ResourceReservationErrorV1::Conflict)?)?;
        self.begin_native_engine_v2(bank, controller, profile, prefix)?
            .bind_accepted_v2(controller, operation, expected)
    }

    /// Borrows the original entered cause ahead of separately owed completion.
    #[must_use]
    pub fn failure(&self) -> Option<&(dyn Error + 'static)> {
        self.entry.as_ref().and_then(|result| result.as_ref().err())
            .and_then(|_| self.native.failure())
            .or_else(|| error(&self.entry))
            .or_else(|| error(&self.accepted))
            .or_else(|| error(&self.binding))
            .or_else(|| error(&self.append_demand))
            .or_else(|| self.evidence.failure())
            .or_else(|| self.clock.failure())
            .or_else(|| self.cleanup.failure())
            .or_else(|| self.environment_failure.as_ref().map(|cause| cause as _))
            .or_else(|| self.native.failure())
            .or_else(|| error(&self.post))
    }

}

impl<'owner> ControllerExecutionOperationReceivingLoanV1<'owner> {
    /// Admits the five actual fixed/receipt Controller writes before encoding.
    ///
    /// The later specification is admitted separately at its exact byte width.
    /// This preserves legitimate smaller specs under a finite native file cap.
    ///
    /// # Errors
    /// Retains held-metadata/geometry failures and refuses insufficient SAME18.
    pub fn prepare_fixed_controller_records_v1(
        &mut self,
        bank: &ControllerResourceBankOpeningV1,
        controller: &mut Journal,
        profile: &ProductionControllerNormalRootProfileV1,
    ) -> Result<(), ResourceReservationErrorV1> {
        if self.accepted_v1().is_none() || self.append_demand.as_ref().is_some_and(|result| result.is_err()) {
            return Err(ResourceReservationErrorV1::Conflict);
        }
        let widths = [
            crate::controller_execution_preissue::ControllerExecutionPreissueV1::receiving_record_shape_v1(),
            crate::controller_execution_preissue::ControllerExecutionOutputAttemptV1::receiving_record_shape_v1(),
            crate::controller_execution_output_settlement::ProtectedControllerOutputSettlementV1::receiving_record_shape_v1(),
            aos_sandbox_journal::geometry::RecordShape {
                key_bytes: 16,
                value_bytes: Some(crate::controller_execution_argument_attempt::CONTROLLER_EXECUTION_ARGUMENT_ATTEMPT_BYTES_V1),
            },
            crate::controller_execution_argument_receipt::AuthenticatedControllerHostArgumentObservationV1::receiving_record_shape_v1(),
        ];
        *self.append_demand = Some(controller.append_sequence_receiving_demand_v1(
            widths.into_iter().map(|shape| Ok(std::iter::once(shape))),
        ));
        let demand = self.append_demand.as_ref().and_then(|result| result.as_ref().ok()).copied()
            .ok_or(ResourceReservationErrorV1::Conflict)?;
        let source_bytes = crate::sandbox_spec_state::execution_source_receiving_bytes_v1(controller)
            .and_then(|bytes| bytes.checked_add(aos_sandbox_protocol::public_api::projection::geometry::execution_source_receiving_bytes_v1(controller.historical_read_view_v1().rows_data_v2())?))
            .ok_or(ResourceReservationErrorV1::Conflict)?;
        let complete = self.prefix.checked_add(demand)?
            .checked_add(ResourceVector::ZERO.with(D::MemoryBytes, source_bytes))?;
        self.require_complete_v1(bank, controller, profile, Demand::from_demand_v1(complete))
    }

    /// Prepays the existing Controller models for a periodic historical read.
    ///
    /// This forecasts no reserve, admission, Environment activation or effect
    /// append. The exact eventual public projection append is paid separately
    /// after its genuine signed completion is retained.
    ///
    /// # Errors
    /// Refuses arithmetic overflow, unavailable canonical model geometry or
    /// insufficient capacity on the same already-consumed execution original.
    pub fn prepare_periodic_controller_models_v4(
        &mut self,
        bank: &ControllerResourceBankOpeningV1,
        controller: &mut Journal,
        profile: &ProductionControllerNormalRootProfileV1,
    ) -> Result<(), ResourceReservationErrorV1> {
        let sources = crate::sandbox_spec_state::execution_source_receiving_bytes_v1(controller)
            .and_then(|bytes| bytes.checked_add(aos_sandbox_protocol::public_api::projection::geometry::execution_source_receiving_bytes_v1(controller.historical_read_view_v1().rows_data_v2())?))
            .ok_or(ResourceReservationErrorV1::Conflict)?;
        let state = controller.historical_read_view_v1().materialized_state_v1();
        let publication = crate::cold_launch_publication::completion::create_stopped_controller_receiving_demand_v1(state)
            .ok_or(ResourceReservationErrorV1::Conflict)?;
        let entries = crate::cold_launch_publication::completion::controller_selector_namespace_entries_v1(state)
            .and_then(|entries| u64::try_from(entries).ok())
            .ok_or(ResourceReservationErrorV1::Conflict)?;
        let complete = self.prefix.checked_add(publication)?
            .checked_add(ResourceVector::ZERO.with(D::MemoryBytes, sources).with(D::MetadataEntries, entries))?;
        self.require_complete_v1(bank, controller, profile, Demand::from_demand_v1(complete))
    }

    /// Borrows the exact protected accepted context while its paid cut lives.
    #[must_use]
    pub fn accepted_v1(&self) -> Option<&PublicMutationEffectHistoryV1> {
        if !matches!(self.entry, Some(Ok(()))) || !matches!(self.binding, Some(Ok(()))) {
            return None;
        }
        self.accepted.as_ref()?.as_ref().ok()?.as_ref()
    }

    /// Checks the complete actual reached upper/native requirement before IO.
    ///
    /// # Errors
    /// Rejects an unaccepted input, changed original or a requirement beyond
    /// the same already-consumed declaration; it creates no capacity or proof.
    pub fn require_complete_v1(
        &mut self, bank: &ControllerResourceBankOpeningV1, controller: &mut Journal,
        profile: &ProductionControllerNormalRootProfileV1,
        complete: aos_sandbox_broker::controller_receiving::bank_launch::ControllerOperationIntakeDemandDataV1,
    ) -> Result<(), ResourceReservationErrorV1> {
        if self.accepted_v1().is_none() || self.post.is_some() {
            return Err(ResourceReservationErrorV1::Conflict);
        }
        bank.require_execution_complete_v1(&mut self.native, controller, profile, complete)?;
        self.prefix = self.prefix.componentwise_max(complete.demand_v1());
        Ok(())
    }

    /// Borrows this actual admitted prefix as passive complete-bound DATA.
    #[must_use]
    pub fn prefix_demand_v1(&self) -> ResourceVector { self.prefix }

    /// Holds the same Source writer while lending its readonly Environment.
    ///
    /// # Errors
    /// Rejects an unaccepted/finished flight, another C/Source original or a
    /// Source native entry refusal. Returned entered native custody still owes
    /// its independent completion, even when its before observation failed.
    pub fn prepare_source_once_v1<'scope>(
        &'scope mut self,
        bank: &ControllerResourceBankOpeningV1,
        source: &'scope mut crate::source_domain::ProtectedSourceDomainJournalOwnerV1,
        controller: &Journal,
        profile: &ProductionControllerNormalRootProfileV1,
    ) -> Result<ControllerExecutionSourceReceivingLoanV1<'scope, 'owner>, ResourceReservationErrorV1> {
        if self.accepted_v1().is_none() || self.post.is_some() {
            return Err(ResourceReservationErrorV1::Conflict);
        }
        let source = bank.borrow_execution_source_scope_v1(
            source, &mut self.native, controller, profile,
        )?;
        Ok(ControllerExecutionSourceReceivingLoanV1 {
            operation: self.operation,
            journal_identity: self.journal_identity,
            source, evidence: self.evidence, clock: self.clock, accepted: self.accepted,
            append_demand: self.append_demand,
            post: self.post, environment_failure: self.environment_failure,
            active: self.active, complete: self.prefix, historical_environment: None, historical_environment_split: false, historical_financial_failure: false,
        })
    }

    /// Runs independently prepaid native posts after an early entered refusal.
    ///
    /// This grants no retry, execution completion or positive disposal. A
    /// Source-entered caller finishes through its actual joint Source owner.
    pub fn finish_without_source_v1(
        &mut self, bank: &ControllerResourceBankOpeningV1, controller: &mut Journal,
        profile: &ProductionControllerNormalRootProfileV1,
    ) {
        if self.post.is_none() {
            *self.post = Some(bank.finish_operation_intake_native_once_v1(
                &mut self.native, controller, profile,
            ));
        }
    }

    /// Quarantines this same Controller after its independently owed posts.
    ///
    /// # Errors
    /// Refuses a foreign Journal identity. This only poisons; it grants no IO.
    pub fn fence_observation_after_refusal_v4(&self, controller: &mut Journal)
        -> Result<(), crate::JournalError>
    {
        controller.fence_execution_observation_v4(self.journal_identity)
    }
}

fn error<T, E: Error + 'static>(value: &Option<Result<T, E>>) -> Option<&(dyn Error + 'static)> {
    value.as_ref()?.as_ref().err().map(|cause| cause as _)
}

fn accepted_receiving_demand_v1(controller: &Journal) -> Result<ResourceVector, ResourceReservationErrorV1> {
    let invalid = || ResourceReservationErrorV1::Conflict;
    let models = crate::reconciler::accepted_public_effect_models_receiving_bytes_v4(controller)
        .ok_or_else(invalid)?;
    let source_scope = Journal::execution_semantic_scope_construction_bytes_v1().ok_or_else(invalid)?;
    let bytes = models.checked_add(source_scope)
        .and_then(|n| n.checked_add(size_of::<ControllerExecutionOperationReceivingLoanV1<'_>>().checked_mul(2)?))
        .and_then(|n| n.checked_add(size_of::<ControllerExecutionAdmissionReceivingLoanV2<'_>>().checked_mul(2)?))
        .and_then(|n| n.checked_add(size_of::<ControllerExecutionSourceReceivingLoanV1<'_, '_>>().checked_mul(2)?))
        .and_then(|n| n.checked_add(size_of::<ControllerExecutionPositiveDisposalV1<'_>>().checked_mul(2)?))
        .and_then(|n| u64::try_from(n).ok()).ok_or_else(invalid)?;
    Ok(ResourceVector::ZERO.with(D::MemoryBytes, bytes))
}

/// Keeps actual Source/C originals through Environment and native execution IO.
///
/// This borrowed owner exposes no Source writer, append or detached historical
/// proof. Its Environment owner is readonly and cannot enter the ordinary Nix
/// mutation methods. Every returned model stays bounded by the consumed C18.
#[must_use]
pub struct ControllerExecutionSourceReceivingLoanV1<'scope, 'owner> {
    operation: OperationId,
    journal_identity: &'scope crate::journal::ExecutionObservationJournalIdentityV4,
    source: crate::controller_resource_reservation::ControllerExecutionSourceScopeV1<'scope, 'owner>,
    evidence: &'scope mut EnvironmentExecutionEvidenceOriginalV1,
    clock: &'scope mut ControllerExecutionClockOriginalV1,
    accepted: &'scope mut Option<Result<Option<PublicMutationEffectHistoryV1>, ReconcilerError>>,
    append_demand: &'scope mut Option<Result<ResourceVector, crate::journal::JournalAppendReceivingDemandErrorV1>>,
    post: &'scope mut Option<Result<(), ResourceReservationErrorV1>>,
    environment_failure: &'scope mut Option<crate::protected_domain_journal::ProtectedDomainJournalErrorV1>,
    active: &'scope mut bool,
    complete: ResourceVector,
    historical_environment: Option<Result<(), ResourceReservationErrorV1>>,
    historical_environment_split: bool,
    historical_financial_failure: bool,
}

impl<'scope, 'owner> ControllerExecutionSourceReceivingLoanV1<'scope, 'owner> {
    /// Quarantines this same Controller after independent Source/C posts.
    ///
    /// # Errors
    /// Refuses a foreign Journal. No rollback or positive recovery is granted.
    pub fn fence_observation_after_refusal_v4(&self, controller: &mut Journal)
        -> Result<(), crate::JournalError>
    {
        controller.fence_execution_observation_v4(self.journal_identity)
    }

    /// Admits another concrete Session stage on this same consumed Source/C cut.
    ///
    /// # Errors
    /// Refuses finished/failed originals or demand beyond the same declaration.
    pub fn require_session_representation_v1(
        &mut self, bank: &ControllerResourceBankOpeningV1,
        controller: &mut Journal, profile: &ProductionControllerNormalRootProfileV1,
        representation: Demand,
    ) -> Result<(), ResourceReservationErrorV1> {
        if self.post.is_some() { return Err(ResourceReservationErrorV1::Conflict); }
        let complete = self.complete.checked_add(representation.demand_v1())
            .map_err(|_| ResourceReservationErrorV1::Conflict)?;
        bank.require_execution_source_complete_v1(&mut self.source, controller, profile,
            Demand::from_demand_v1(complete))?;
        self.complete = complete;
        Ok(())
    }

    /// Borrows the retained first body/native cause before independent posts.
    #[must_use]
    pub fn failure(&self) -> Option<&(dyn Error + 'static)> {
        if let Some(cause) = error(&self.historical_environment) {
            // Latch the reached payment refusal before independent owed posts.
            // Only an actual source failure already present at that frontier
            // may supply its financial/native cause in place of the marker.
            return if self.historical_financial_failure { self.source.failure().or(Some(cause)) }
                else { Some(cause) };
        }
        error(&self.append_demand)
            .or_else(|| self.clock.failure())
            .or_else(|| self.evidence.failure())
            .or_else(|| self.environment_failure.as_ref().map(|cause| cause as _))
            .or_else(|| error(&self.historical_environment))
            .or_else(|| self.source.failure())
            .or_else(|| error(&self.post))
    }

    /// Publishes the matching generation, activation and lease through genuine Root/C18.
    ///
    /// # Errors
    /// Retains actual Root/Source/native/model failures and every owed post.
    /// A row, empty configuration or storage Ready seal cannot satisfy this path.
    pub fn prepare_environment_v1(
        &mut self, bank: &ControllerResourceBankOpeningV1, controller: &mut Journal,
        profile: &std::sync::Arc<ProductionControllerNormalRootProfileV1>,
        assignment: &crate::runtime_scope::CurrentAssignmentTarget,
        parent: &crate::execution_parent_resource::ExecutionParentResourceSourceV1,
        execution: aos_sandbox_model::ExecutionId,
    ) -> Result<(), ResourceReservationErrorV1> {
        if self.post.is_some() || self.environment_failure.is_some() || self.historical_environment.is_some() {
            return Err(ResourceReservationErrorV1::Conflict);
        }
        self.evidence.prepare_once_v1(&mut self.source, &mut self.complete, bank, controller,
            profile, self.operation, execution, parent, assignment, self.clock)
            .map_err(|_| ResourceReservationErrorV1::Conflict)?;
        let view = self.source.historical_view_v1().map_err(|_| ResourceReservationErrorV1::Conflict)?;
        let models = crate::environment::execution_source_receiving_demand_v1(view)?;
        let complete = self.complete.checked_add(models)?;
        bank.require_execution_source_complete_v1(&mut self.source, controller, profile,
            Demand::from_demand_v1(complete))?;
        self.complete = complete;
        if self.evidence.owner_mut_v1().is_none() { return Err(ResourceReservationErrorV1::Conflict); }
        Ok(())
    }

    /// Borrows the same fixed evidence and exclusive Source cut as Environment.
    ///
    /// # Errors
    /// Retains the actual failed canonical/model/evidence result before returning
    /// a coarse stopped-flight marker. No returned context grants execution.
    pub fn environment_and_receiving_v1<'read>(&'read mut self)
        -> Result<(crate::environment::EnvironmentProtectedJournalOwnerV1<'read, 'read>,
            ControllerExecutionReadReceivingLoanV1<'read, 'owner>, &'read mut ControllerExecutionClockOriginalV1), ResourceReservationErrorV1>
    {
        if self.environment_failure.is_some() || self.post.is_some() || self.historical_environment.is_some() {
            return Err(ResourceReservationErrorV1::Conflict);
        }
        let evidence = self.evidence.owner_mut_v1()
            .ok_or(ResourceReservationErrorV1::Conflict)?;
        let (read, receiving) = self.source.split_execution_read_v1()
            .map_err(|_| ResourceReservationErrorV1::Conflict)?;
        match crate::environment::EnvironmentProtectedJournalOwnerV1::claim_execution_source_v2(
            read, evidence,
        ) {
            Ok(owner) => Ok((owner, ControllerExecutionReadReceivingLoanV1 {
                operation: self.operation,
                receiving, complete: &mut self.complete, append_demand: self.append_demand,
            }, self.clock)),
            Err(cause) => {
                *self.environment_failure = Some(cause);
                Err(ResourceReservationErrorV1::Conflict)
            }
        }
    }

    /// Prepays historical Environment/spec replay without Root or a lease append.
    ///
    /// The original protected specification row supplies its actual width. The
    /// current accepted operation retains its own C18/Source native interval;
    /// original Create and expired execution leases remain historical DATA.
    ///
    /// # Errors
    /// Retains refusal on reentry, mixed issuance, failed native originals,
    /// missing protected spec, arithmetic or insufficient SAME consumed flight.
    pub fn prepare_historical_environment_v4(
        &mut self, bank: &ControllerResourceBankOpeningV1, controller: &mut Journal,
        profile: &ProductionControllerNormalRootProfileV1,
        execution: aos_sandbox_model::ExecutionId,
    ) -> Result<(), ResourceReservationErrorV1> {
        if self.historical_environment.is_some() || self.post.is_some() || self.failure().is_some()
            || self.environment_failure.is_some() || self.evidence.failure().is_some()
            || self.evidence.owner_mut_v1().is_some()
        { return Err(ResourceReservationErrorV1::Conflict); }
        self.historical_environment = Some((|| {
            controller.ensure_protected_authority().map_err(|_| ResourceReservationErrorV1::Conflict)?;
            let encoded = controller.get(crate::RecordNamespace::ControllerExecutionSpecAttempt,
                execution.as_bytes()).ok_or(ResourceReservationErrorV1::Conflict)?.len();
            let spec_model = aos_sandbox_protocol::execution_spec_attempt::execution_spec_validation_model_memory_bytes_v2(encoded)
                .and_then(|bytes| bytes.checked_add(encoded.checked_mul(2)?))
                .and_then(|bytes| bytes.checked_add(std::mem::size_of::<
                    crate::environment::HistoricalEnvironmentExecutionOwnerV4<'_>>().checked_mul(2)?))
                .and_then(|bytes| bytes.checked_add(std::mem::size_of::<
                    crate::controller_execution_spec_attempt::ControllerExecutionSpecAttemptV1>().checked_mul(2)?))
                .and_then(|bytes| u64::try_from(bytes).ok()).ok_or(ResourceReservationErrorV1::Conflict)?;
            let view = self.source.historical_view_v1().map_err(|_| ResourceReservationErrorV1::Conflict)?;
            let models = crate::environment::execution_source_receiving_demand_v1(view)?
                .checked_add(ResourceVector::ZERO.with(D::MemoryBytes, spec_model))?;
            let complete = self.complete.checked_add(models)?;
            if let Err(cause) = bank.require_execution_source_complete_v1(&mut self.source, controller, profile,
                Demand::from_demand_v1(complete))
            {
                self.historical_financial_failure = self.source.failure().is_some();
                return Err(cause);
            }
            self.complete = complete;
            Ok(())
        })());
        if matches!(self.historical_environment, Some(Ok(()))) { Ok(()) }
        else { Err(ResourceReservationErrorV1::Conflict) }
    }

    /// Splits the same paid Source into a historical owner, read loan and clock.
    ///
    /// The caller must retain and observe the inert historical owner against
    /// the actual protected original spec before any Query61 comparison. It
    /// cannot produce an execution source, append or new Environment evidence.
    ///
    /// # Errors
    /// Refuses missing payment, prior refusal, finished or foreign Source/C cut.
    pub fn historical_environment_and_receiving_v4<'read>(&'read mut self)
        -> Result<(crate::environment::HistoricalEnvironmentExecutionOwnerV4<'read>,
            ControllerExecutionReadReceivingLoanV1<'read, 'owner>, &'read mut ControllerExecutionClockOriginalV1), ResourceReservationErrorV1>
    {
        if !matches!(self.historical_environment, Some(Ok(()))) || self.historical_environment_split
            || self.environment_failure.is_some() || self.post.is_some()
        { return Err(ResourceReservationErrorV1::Conflict); }
        self.historical_environment_split = true;
        let (read, receiving) = self.source.split_execution_read_v1()
            .map_err(|_| ResourceReservationErrorV1::Conflict)?;
        Ok((crate::environment::HistoricalEnvironmentExecutionOwnerV4::from_source_read_v4(read),
            ControllerExecutionReadReceivingLoanV1 { operation: self.operation, receiving,
                complete: &mut self.complete, append_demand: self.append_demand }, self.clock))
    }

    /// Checks complete cumulative native/semantic demand before its next frontier.
    ///
    /// # Errors
    /// Rejects changed original/currentness or insufficient already-paid capacity.
    pub fn require_complete_v1(
        &mut self, bank: &ControllerResourceBankOpeningV1, controller: &mut Journal,
        profile: &ProductionControllerNormalRootProfileV1,
        complete: aos_sandbox_broker::controller_receiving::bank_launch::ControllerOperationIntakeDemandDataV1,
    ) -> Result<(), ResourceReservationErrorV1> {
        bank.require_execution_source_complete_v1(&mut self.source, controller, profile, complete)?;
        self.complete = self.complete.componentwise_max(complete.demand_v1());
        Ok(())
    }

    /// Runs the independent prearmed Source and C posts on either body outcome.
    pub fn finish_native_once_v1(
        &mut self, bank: &ControllerResourceBankOpeningV1, controller: &mut Journal,
        profile: &ProductionControllerNormalRootProfileV1,
    ) {
        if self.post.is_none() {
            *self.post = Some(bank.finish_execution_source_native_once_v1(
                &mut self.source, controller, profile,
            ));
        }
    }

    /// Keeps actual positive Source/C originals while upper owners retire.
    ///
    /// This is a resource-disposal interval, not execution or terminal proof.
    /// The caller must also retain its real authenticated completion and drop
    /// all matching native/model destinations before completing this token.
    ///
    /// # Errors
    /// Refuses failed or missing independent posts, failed evidence/clock,
    /// changed C/Source originals or native uncertainty. Failure keeps the
    /// original operation spent through the existing scope guard.
    pub fn prepare_positive_disposal_v1<'disposal>(
        &'disposal mut self,
        bank: &ControllerResourceBankOpeningV1,
        controller: &'disposal Journal,
        profile: &ProductionControllerNormalRootProfileV1,
    ) -> Result<ControllerExecutionPositiveDisposalV1<'disposal>, ResourceReservationErrorV1> {
        if !matches!(self.post, Some(Ok(()))) || self.environment_failure.is_some()
            || self.historical_environment.as_ref().is_some_and(Result::is_err)
            || self.append_demand.as_ref().is_some_and(|result| result.is_err())
            || self.evidence.failure().is_some() || self.clock.failure().is_some()
        {
            return Err(ResourceReservationErrorV1::Conflict);
        }
        let native = bank.prepare_execution_source_disposal_v1(&mut self.source, controller, profile)?;
        Ok(ControllerExecutionPositiveDisposalV1 {
            cleanup: None,
            operation: self.operation,
            journal_identity: self.journal_identity,
            native,
            evidence: self.evidence,
            accepted: self.accepted,
            append_demand: self.append_demand,
            clock: self.clock,
            post: self.post,
            active: self.active,
        })
    }

}

/// Holds the genuine completed Source/C interval through upper disposal.
///
/// Only the real execution scope's positive-post path constructs this type.
/// Its operation identity is comparison DATA bound at the original accepted
/// decode. It issues no request, effect, Ready, execution or terminal proof.
#[must_use]
pub struct ControllerExecutionPositiveDisposalV1<'disposal> {
    cleanup: Option<&'disposal mut no_apply_cleanup::ControllerExecutionCleanupOriginalV2>,
    operation: OperationId,
    journal_identity: &'disposal crate::journal::ExecutionObservationJournalIdentityV4,
    native: crate::controller_resource_reservation::ControllerExecutionSourceDisposalV1<'disposal>,
    evidence: &'disposal mut EnvironmentExecutionEvidenceOriginalV1,
    accepted: &'disposal mut Option<Result<Option<PublicMutationEffectHistoryV1>, ReconcilerError>>,
    append_demand: &'disposal mut Option<Result<ResourceVector, crate::journal::JournalAppendReceivingDemandErrorV1>>,
    clock: &'disposal mut ControllerExecutionClockOriginalV1,
    post: &'disposal mut Option<Result<(), ResourceReservationErrorV1>>,
    active: &'disposal mut bool,
}

impl ControllerExecutionPositiveDisposalV1<'_> {
    /// Completes actual Source/C18 disposal before releasing a NoApply terminal witness.
    ///
    /// The distinct original proves completed native NoApply, causal Root
    /// confirmation and Core retirement. The concrete caller must also drop
    /// its matching SDK and Runtime prefixes before invoking this method.
    /// This resource-disposal token is not an Apply proof.
    ///
    /// # Errors
    /// Refuses a different original Controller writer or operation. Its actual
    /// native Source guard retains failed or abandoned completion custody.
    pub fn complete_no_apply_after_disposal_v2(self,
        disposed: ControllerExecutionNoApplyDisposedOriginalV2,
    ) -> Result<ControllerExecutionNoApplyCompletionV2, ResourceReservationErrorV1> {
        disposed.require_disposal_v2(&self)?;
        self.complete_after_disposal_v1();
        Ok(disposed.into_completion_v2())
    }

    /// Returns the accepted operation owning this disposal interval.
    #[must_use]
    pub const fn operation_v1(&self) -> OperationId { self.operation }

    /// Disposes owned positive evidence before the sole native completion.
    ///
    /// All upper borrowed native/model owners must already have retired. An
    /// abandoned token retains the existing lower fail-closed Drop behavior.
    pub fn complete_after_disposal_v1(self) {
        if let Some(cleanup) = self.cleanup {
            drop(std::mem::replace(cleanup, no_apply_cleanup::ControllerExecutionCleanupOriginalV2::new()));
        }
        drop(std::mem::replace(self.evidence, EnvironmentExecutionEvidenceOriginalV1::new()));
        *self.accepted = None;
        *self.append_demand = None;
        *self.clock = ControllerExecutionClockOriginalV1::new();
        self.native.complete_after_disposal_v1();
        *self.post = None;
        *self.active = false;
    }
}

/// Keeps the same financial reborrow live beside a readonly Environment owner.
///
/// This type cannot finish, dispose, reopen or append Source. The enclosing
/// execution Source scope retains those responsibilities and its real posts.
#[must_use]
pub struct ControllerExecutionReadReceivingLoanV1<'read, 'owner> {
    operation: OperationId,
    receiving: crate::controller_resource_reservation::ControllerExecutionSourceCompleteBorrowV1<'read, 'owner>,
    complete: &'read mut ResourceVector,
    append_demand: &'read mut Option<Result<ResourceVector, crate::journal::JournalAppendReceivingDemandErrorV1>>,
}

impl ControllerExecutionReadReceivingLoanV1<'_, '_> {
    // This is the actual accepted semantic operation retained by the original
    // Source scope, not a caller operation selector or another financial loan.
    pub(crate) const fn operation_v3(&self) -> OperationId { self.operation }

    /// Returns the accepted operation already bound to this live read loan.
    ///
    /// This comparison DATA does not transfer, finish or reconstruct its
    /// financial original or the enclosing Source interval.
    #[must_use]
    pub const fn operation_v1(&self) -> OperationId { self.operation }

    // Only the selected same-crate encoder lends its actual canonical width.
    // No caller-supplied amount, capacity or append permission is returned.
    pub(crate) fn admit_controller_append_v1(
        &mut self,
        bank: &ControllerResourceBankOpeningV1,
        controller: &mut Journal,
        profile: &ProductionControllerNormalRootProfileV1,
        records: impl ExactSizeIterator<Item = aos_sandbox_journal::geometry::RecordShape>,
    ) -> Result<(), ResourceReservationErrorV1> {
        if self.append_demand.as_ref().is_some_and(|result| result.is_err()) {
            return Err(ResourceReservationErrorV1::Conflict);
        }
        self.require_current_v1(bank, controller, profile)?;
        *self.append_demand = Some(controller.append_receiving_demand_v1(records));
        let demand = self.append_demand.as_ref().and_then(|result| result.as_ref().ok()).copied()
            .ok_or(ResourceReservationErrorV1::Conflict)?;
        self.admit_stage_v1(bank, controller, profile, Demand::from_demand_v1(demand))
    }

    /// Rechecks the same admitted complete bound before a retained continuation.
    ///
    /// # Errors
    /// Rejects a changed Source/C original, held NEXT or current profile. This
    /// consumes no new flight and grants no new representation or IO extent.
    pub fn require_current_v1(
        &mut self,
        bank: &ControllerResourceBankOpeningV1,
        controller: &mut Journal,
        profile: &ProductionControllerNormalRootProfileV1,
    ) -> Result<(), ResourceReservationErrorV1> {
        bank.require_execution_source_read_complete_v1(
            &mut self.receiving,
            controller,
            profile,
            Demand::from_demand_v1(*self.complete),
        )
    }

    /// Checks a named actual upper stage before its model/native IO growth.
    ///
    /// The caller supplies passive compiled representation DATA from the real
    /// bounded engine. This adds no declaration, account or refundable credit.
    ///
    /// # Errors
    /// Rejects arithmetic overflow, changed original/currentness or insufficient
    /// finite capacity. The whole declaration was consumed at initial entry.
    pub fn admit_stage_v1(
        &mut self, bank: &ControllerResourceBankOpeningV1, controller: &mut Journal,
        profile: &ProductionControllerNormalRootProfileV1,
        stage: aos_sandbox_broker::controller_receiving::bank_launch::ControllerOperationIntakeDemandDataV1,
    ) -> Result<(), ResourceReservationErrorV1> {
        let complete = self.complete.checked_add(stage.demand_v1())?;
        bank.require_execution_source_read_complete_v1(&mut self.receiving, controller, profile,
            Demand::from_demand_v1(complete))?;
        *self.complete = complete;
        Ok(())
    }
}

/// Borrows the canonical paired-clock engine on the genuine execution flight.
///
/// A complete positive primitive is disposed before the next sample. Failed
/// native boot/read prefixes remain resident and suppress replacement samples;
/// the independently prepaid C and Source posts have separate originals.
pub struct ControllerExecutionClockOriginalV1 {
    native: crate::policy_compiler::RetainedKernelPairedClockAttemptV1,
    result: Option<Result<aos_sandbox_model::RawPairedClockSample,
        crate::hierarchy::genesis_profile::SourceGenesisErrorV1>>,
}

impl ControllerExecutionClockOriginalV1 {
    pub(crate) fn new() -> Self { Self { native: Default::default(), result: None } }

    pub(crate) fn fixed_demand_v1() -> Option<ResourceVector> {
        use crate::policy_compiler::RetainedKernelPairedClockAttemptV1 as Pair;
        let bytes = Pair::dominant_requested_bytes_v1()?
            .checked_add(size_of::<Self>().checked_mul(2)?)?;
        Some(ResourceVector::ZERO.with(D::MemoryBytes, u64::try_from(bytes).ok()?)
            .with(D::OpenFiles, u64::try_from(Pair::MAXIMUM_RETAINED_FILES_V1).ok()?))
    }

    /// Samples the same native kernel pair while preserving a failed original.
    ///
    /// # Errors
    /// Retains the original boot/clock/conversion cause and returns the existing
    /// coarse ownership-clock refusal; no failed native owner is reconstructed.
    pub fn sample_v1(&mut self) -> Result<aos_sandbox_model::RawPairedClockSample,
        aos_sandbox_broker::paired_clock::ProtectedOwnershipClockError>
    {
        if self.result.as_ref().is_some_and(|result| result.is_err()) {
            return Err(aos_sandbox_broker::paired_clock::ProtectedOwnershipClockError);
        }
        if self.result.is_some() {
            // Only copied clock DATA escaped the fully positive primitive.
            self.native = Default::default();
            self.result = None;
        }
        self.result = Some(self.native.observe_once(None));
        self.result.as_ref().and_then(|result| result.as_ref().ok()).copied()
            .ok_or(aos_sandbox_broker::paired_clock::ProtectedOwnershipClockError)
    }

    /// Borrows the reached native cause without observing or replacing it.
    #[must_use]
    pub fn failure(&self) -> Option<&(dyn Error + 'static)> {
        self.native.failure().or_else(|| error(&self.result))
    }
}
