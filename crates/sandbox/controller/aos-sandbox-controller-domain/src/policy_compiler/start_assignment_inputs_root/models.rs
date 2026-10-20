//! Joins the exact accepted Start to Root's actual current C/Source/policy cut.
//!
//! The genuine Inputs stage prepays complete selector and Source graph shapes
//! before any decoder/store grows. All records stay with this whole owner; no
//! observed pair or unsigned reply is promoted to resource authority.

use std::error::Error;
use std::mem::size_of;

use aos_sandbox_model::{OperationId, RawPairedClockSample, ResourceDimension as D, ResourceVector};
use aos_sandbox_protocol::domain_ledger::{
    effect_history::{EffectLedgerRecord, decode_effect},
    operation::effect_key,
    provisioning_root::start_assignment_inputs::{
        StartAssignmentInputsQueryDataV2, StartAssignmentInputsSubjectDataV2,
    },
};
use crate::controller_resource_reservation::RootContinuationDemandV1;
use crate::journal::{JournalError, RecordNamespace};
use crate::lifecycle::{LifecycleHistoricalReadOriginalV1, LifecycleIntentV1};
use crate::normal_root::{NormalRootStartupErrorV1, RootStartAssignmentInputsStageReceivingV2};
use crate::policy_compiler::continuation_policy::RootStartAssignmentInputsPolicyOriginalV2;
use crate::policy_compiler::public_start_source::{
    CurrentAcceptedStartProjectSourceV2, current_accepted_start_source_from_root_records_v2,
};
use crate::policy_compiler::provisioning_current::{
    current_manifest::{CurrentProtectedAssignmentDataV2, current_protected_assignment_data_v2},
    finality_readonly::RootCreateFinalityReadonlyOriginalV1,
    require_current_start_signed_inputs_v2,
};

type Cause = Box<dyn Error>;

pub(super) struct RootStartAssignmentInputsModelsOriginalV2 {
    geometry: Option<Result<ResourceVector, JournalError>>,
    funding: Option<Result<(), NormalRootStartupErrorV1>>,
    source: LifecycleHistoricalReadOriginalV1,
    source_read: Option<Result<(), JournalError>>,
    predecessor: Option<Result<CurrentProtectedAssignmentDataV2, Cause>>,
    accepted_effect: Option<Result<EffectLedgerRecord, Cause>>,
    current: Option<Result<CurrentAcceptedStartProjectSourceV2, Cause>>,
    result: Option<Result<(), Cause>>,
    reentered: bool,
}

impl RootStartAssignmentInputsModelsOriginalV2 {
    pub(super) fn new() -> Self {
        Self {
            geometry: None,
            funding: None,
            source: LifecycleHistoricalReadOriginalV1::new(),
            source_read: None,
            predecessor: None,
            accepted_effect: None,
            current: None,
            result: None,
            reentered: false,
        }
    }

    fn receiving_demand_v2(
        &self,
        readonly: &mut RootCreateFinalityReadonlyOriginalV1,
    ) -> Result<ResourceVector, JournalError> {
        let (controller, source) = readonly.journals_v1()?;
        let state = controller.historical_read_view_v1().materialized_state_v1();
        let selectors = crate::cold_launch_publication::completion::
            create_stopped_controller_receiving_demand_v1(state).ok_or(JournalError::JournalTooLarge)?;
        let lifecycle = crate::lifecycle::retained_lifecycle_replay_receiving_demand_v1(
            source.all_records(),
        ).ok_or(JournalError::JournalTooLarge)?;
        let tree = crate::hierarchy::protected_journal::start_assignment_tree_receiving_demand_v2(source)?;
        let (policy_bytes, policy_rows) = controller.records(RecordNamespace::PublisherPolicy)
            .try_fold((0_usize, 0_usize), |(bytes, rows), (key, value)| {
                Some((bytes.checked_add(key.len())?.checked_add(value.len())?, rows.checked_add(1)?))
            }).ok_or(JournalError::JournalTooLarge)?;
        let policy = crate::public_mutation_compiler::delete_admission::geometry::
            authorization_model_bytes_v1(policy_bytes, policy_rows).ok_or(JournalError::JournalTooLarge)?;
        let names = crate::publisher_admin::policy_namespace_entries_v2(controller)
            .and_then(|entries| u64::try_from(entries).ok()).ok_or(JournalError::JournalTooLarge)?;
        let fixed = size_of::<Self>().checked_mul(2)
            .and_then(|bytes| bytes.checked_add(LifecycleHistoricalReadOriginalV1::carrier_receiving_bytes_v1()?))
            .and_then(|bytes| bytes.checked_add(crate::policy_compiler::provisioning_current::
                current_manifest::current_protected_assignment_carrier_receiving_bytes_v2()?))
            .and_then(|bytes| bytes.checked_add(policy))
            .and_then(|bytes| u64::try_from(bytes).ok()).ok_or(JournalError::JournalTooLarge)?;
        let projection = crate::controller_service::public_projection::sandbox_source_receiving_bytes_v1(controller)
            .ok_or(JournalError::JournalTooLarge)?;

        let memory = fixed.checked_add(projection).ok_or(JournalError::JournalTooLarge)?;
        selectors.checked_add(lifecycle)
            .and_then(|value| value.checked_add(tree))
            .and_then(|value| value.checked_add(ResourceVector::ZERO
                .with(D::MemoryBytes, memory).with(D::MetadataEntries, names)))
            .map_err(JournalError::ReceivingAccounting)
    }

    pub(super) fn observe_once_v2(
        &mut self,
        stage: &mut RootStartAssignmentInputsStageReceivingV2<'_, '_>,
        readonly: &mut RootCreateFinalityReadonlyOriginalV1,
        policy: &RootStartAssignmentInputsPolicyOriginalV2,
        query: StartAssignmentInputsQueryDataV2,
        subject: StartAssignmentInputsSubjectDataV2<'_>,
        sample: RawPairedClockSample,
    ) -> Result<(), JournalError> {
        if self.geometry.is_some() {
            self.reentered = true;
            return Err(JournalError::ProtectedBoundary);
        }
        self.geometry = Some(self.receiving_demand_v2(readonly));
        let demand = self.geometry.as_ref().and_then(|value| value.as_ref().ok())
            .copied().ok_or(JournalError::JournalTooLarge)?;
        self.funding = Some(stage.admit_start_assignment_inputs_models_once_v2(
            RootContinuationDemandV1::from_demand_v1(demand),
        ));
        if !matches!(self.funding, Some(Ok(()))) {
            return Err(JournalError::ProtectedBoundary);
        }
        self.result = Some(self.observe_inner_v2(stage, readonly, policy, query, subject, sample));
        self.current_v2().map(|_| ())
    }

    fn observe_inner_v2(
        &mut self,
        stage: &RootStartAssignmentInputsStageReceivingV2<'_, '_>,
        readonly: &mut RootCreateFinalityReadonlyOriginalV1,
        policy: &RootStartAssignmentInputsPolicyOriginalV2,
        query: StartAssignmentInputsQueryDataV2,
        subject: StartAssignmentInputsSubjectDataV2<'_>,
        sample: RawPairedClockSample,
    ) -> Result<(), Cause> {
        let operation = OperationId::from_bytes(subject.start_operation.try_into()?);
        let (controller_cut, _) = readonly.cuts_v1()?;
        if (query.controller_next, query.controller_end) != (controller_cut.next, controller_cut.end) {
            return Err(JournalError::ProtectedBoundary.into());
        }
        let (controller, source) = readonly.journals_v1()?;
        if controller.get(RecordNamespace::Operation, operation.as_bytes()) != Some(subject.accepted_start) {
            return Err(JournalError::ProtectedBoundary.into());
        }
        crate::policy_compiler::provisioning_current::apply_inputs::require_controller_bank_head_data_v2(
            controller.historical_read_view_v1().materialized_state_v1(), subject.controller_account,
            stage.controller_baseline_partition_v1()?, stage.enrolled_node_v1()?,
        )?;
        self.source_read = Some(self.source.observe_once_v1(source, operation));
        let (selected, _) = self.source.operation_v1()?;
        let LifecycleIntentV1::Start { sandbox, .. } = selected.intent() else {
            return Err(JournalError::ProtectedBoundary.into());
        };
        self.predecessor = Some(current_protected_assignment_data_v2(controller, *sandbox).map_err(Into::into));
        let predecessor = value(&self.predecessor)?;
        if predecessor.manifest_v2().manifest().node().as_bytes() != &stage.enrolled_node_v1()? {
            return Err(JournalError::ProtectedBoundary.into());
        }
        self.accepted_effect = Some((|| {
            let raw = controller.get(RecordNamespace::Effect, &effect_key(operation, 0))
                .ok_or(JournalError::ProtectedBoundary)?;
            Ok(decode_effect(raw)?)
        })());
        let context = value(&self.accepted_effect)?.plan().public_mutation_context()?
            .ok_or(JournalError::ProtectedBoundary)?;
        if context.canonical_request() != subject.canonical_request {
            return Err(JournalError::ProtectedBoundary.into());
        }
        self.current = Some(current_accepted_start_source_from_root_records_v2(
            controller, operation, &self.source, predecessor.manifest_v2(), sample,
        ).map_err(|cause| cause as Cause));
        let current = value(&self.current)?;
        let (record, tree_head, _) = crate::hierarchy::protected_journal::start_assignment_source_tree_data_v2(
            source, current.project_v2(), current.sandbox_v2(),
        )?;
        let previous = predecessor.manifest_v2().manifest();
        if record.parent().is_some() || record.project() != previous.project()
            || record.incarnation() != Some(previous.incarnation())
            || record.desired_generation() != previous.desired_generation()
        {
            return Err(JournalError::ProtectedBoundary.into());
        }
        require_current_start_signed_inputs_v2(current,
            policy.verified_v1().ok_or(JournalError::ProtectedBoundary)?, tree_head, sample).map_err(|cause| cause as Cause)?;
        let origin = current.native_origin_data_v2();
        if query.original_boot != origin.first_native_clock_v1().host_boot_id()
            || query.original_boottime_ns != origin.first_native_clock_v1().boottime_nanoseconds()
            || query.original_cutoff_ns != origin.cutoff_v1()
        {
            return Err(JournalError::ProtectedBoundary.into());
        }
        Ok(())
    }

    pub(super) fn current_v2(&self) -> Result<&CurrentAcceptedStartProjectSourceV2, JournalError> {
        if self.reentered || !matches!(self.result, Some(Ok(()))) || self.failure().is_some() {
            return Err(JournalError::ProtectedBoundary);
        }
        value(&self.current)
    }

    pub(super) fn funding_failed_v2(&self) -> bool {
        matches!(self.funding, Some(Err(_)))
    }

    pub(super) fn failure(&self) -> Option<&(dyn Error + 'static)> {
        self.geometry.as_ref().and_then(|value| value.as_ref().err()).map(|cause| cause as _)
            .or_else(|| self.funding.as_ref().and_then(|value| value.as_ref().err()).map(|cause| cause as _))
            .or_else(|| self.source.failure())
            .or_else(|| cause(&self.predecessor))
            .or_else(|| cause(&self.accepted_effect))
            .or_else(|| cause(&self.current))
            .or_else(|| cause(&self.result))
            .or_else(|| self.reentered.then_some(&CLOSED as _))
    }
}

fn value<T>(result: &Option<Result<T, Cause>>) -> Result<&T, JournalError> {
    result.as_ref().and_then(|value| value.as_ref().ok()).ok_or(JournalError::ProtectedBoundary)
}

fn cause<T>(result: &Option<Result<T, Cause>>) -> Option<&(dyn Error + 'static)> {
    result.as_ref()?.as_ref().err().map(|cause| cause.as_ref())
}

const CLOSED: JournalError = JournalError::ProtectedBoundary;
