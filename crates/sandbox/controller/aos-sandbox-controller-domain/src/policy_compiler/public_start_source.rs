//! Selects an accepted Start and its current protected publisher inputs.
//!
//! This proof has a distinct private constructor from the Create source proof.
//! The caller pays full C/Source replay and model construction in its genuine
//! Start or Root interval before entering this pure selection. Native custody,
//! currentness, independent posts and actual effect authority stay with it.

use aos_sandbox_api::aos::sandbox::v1::DesiredLifecycle;
use aos_sandbox_model::{
    CanonicalAssignmentManifestV1, DesiredGeneration, ObjectDigest, OperationId,
    ProjectId, RawPairedClockSample, SandboxId,
};
use aos_sandbox_protocol::public_api::{
    PublicOperationMethodV1,
    projection::{PublicProjectionKindV1, PublicProjectionResourceV1},
    request::DormantSandboxRequestKindV1,
};
use crate::controller_service::public_projection::get_from_observation_v2;
use crate::journal::historical_observation::HistoricalObservationV1;
use crate::lifecycle::{
    LifecycleHistoricalReadOriginalV1, LifecycleIntentV1, LifecyclePhaseV1,
    lifecycle_operation_from_public_mutation_v1, lifecycle_public_mutation_admission_from_observation_v2,
    require_same_lifecycle_admission_v1,
};
use crate::{Journal, JournalError, OperationPlan};

use super::public_create_source::{
    CurrentPublisherPolicyDataV2, current_publisher_policy_data_v2,
};

type Cause = Box<dyn std::error::Error + Send + Sync>;

/// Carries only the current accepted Start's independently selected policy DATA.
pub(crate) struct CurrentAcceptedStartProjectSourceV2 {
    operation: OperationId,
    project: ProjectId,
    sandbox: SandboxId,
    predecessor_generation: DesiredGeneration,
    successor_generation: DesiredGeneration,
    projection_revision: ObjectDigest,
    native_origin: aos_sandbox_protocol::domain_ledger::operation::StartNativeOriginDataV1,
    publisher: CurrentPublisherPolicyDataV2,
}

impl CurrentAcceptedStartProjectSourceV2 {
    pub(crate) const fn operation_v2(&self) -> OperationId {
        self.operation
    }

    pub(crate) const fn project_v2(&self) -> ProjectId {
        self.project
    }

    pub(crate) const fn sandbox_v2(&self) -> SandboxId {
        self.sandbox
    }

    pub(crate) const fn predecessor_generation_v2(&self) -> DesiredGeneration {
        self.predecessor_generation
    }

    pub(crate) const fn successor_generation_v2(&self) -> DesiredGeneration {
        self.successor_generation
    }

    pub(crate) const fn projection_revision_v2(&self) -> ObjectDigest {
        self.projection_revision
    }

    pub(in crate::policy_compiler) const fn native_origin_data_v2(&self)
        -> aos_sandbox_protocol::domain_ledger::operation::StartNativeOriginDataV1
    {
        self.native_origin
    }

    pub(in crate::policy_compiler) fn publisher_v2(&self) -> &CurrentPublisherPolicyDataV2 {
        &self.publisher
    }
}

/// Selects the actual current Start without minting the Create source proof.
///
/// The original manifest is a predecessor comparison only. Its incarnation,
/// epoch, node and exact specification are preserved; its desired generation
/// cannot substitute for the accepted Start successor.
///
/// # Errors
/// Rejects an altered accepted operation or request, a missing full Source
/// selection, another origin/intent/project, a terminal Source row, a changed
/// projection/specification or a stale current publisher policy.
pub(crate) fn current_accepted_start_project_source_v2(
    controller: &mut Journal,
    plan: &OperationPlan,
    source: &LifecycleHistoricalReadOriginalV1,
    previous: &CanonicalAssignmentManifestV1,
    sample: RawPairedClockSample,
) -> Result<CurrentAcceptedStartProjectSourceV2, Cause> {
    select_current_start_source_v2(
        HistoricalObservationV1::from_journal_v1(controller),
        StartSourceSelectionV2::Controller { plan, journal: controller }, source, previous, sample,
    )
}

/// Selects the same Start DATA from Root's independently replayed actual C rows.
///
/// The actual Root purpose must retain its full C/Source reads and native posts.
/// This private pure selector creates neither an OperationPlan nor a receiving
/// original from replayed records.
pub(crate) fn current_accepted_start_source_from_root_records_v2(
    controller: HistoricalObservationV1<'_>,
    operation: OperationId,
    source: &LifecycleHistoricalReadOriginalV1,
    previous: &CanonicalAssignmentManifestV1,
    sample: RawPairedClockSample,
) -> Result<CurrentAcceptedStartProjectSourceV2, Cause> {
    select_current_start_source_v2(
        controller, StartSourceSelectionV2::Root(operation), source, previous, sample,
    )
}

#[derive(Clone, Copy)]
enum StartSourceSelectionV2<'plan> {
    Controller { plan: &'plan OperationPlan, journal: &'plan Journal },
    Root(OperationId),
}

fn select_current_start_source_v2(
    controller: HistoricalObservationV1<'_>,
    selected: StartSourceSelectionV2<'_>,
    source: &LifecycleHistoricalReadOriginalV1,
    previous: &CanonicalAssignmentManifestV1,
    sample: RawPairedClockSample,
) -> Result<CurrentAcceptedStartProjectSourceV2, Cause> {
    controller.ensure_protected_authority()?;
    let operation_id = match selected {
        StartSourceSelectionV2::Controller { plan, journal } => {
            plan.require_accepted_start_data_v1(journal)?;
            plan.operation_id()
        }
        StartSourceSelectionV2::Root(operation) => operation,
    };
    let record = aos_sandbox_protocol::domain_ledger::operation::decode_operation(
        controller.get(crate::RecordNamespace::Operation, operation_id.as_bytes())
            .ok_or(CLOSED)?,
    )?;
    let public = record.public_operation().ok_or(CLOSED)?;
    let accepted = record.accepted_start_origin_v1().ok_or(CLOSED)?;
    if record.state().is_terminal() || record.effect_count() != 1
        || record.ownership_gated() || record.runtime_intent_digest().is_some()
        || public.method() != PublicOperationMethodV1::StartSandbox
    {
        return Err(CLOSED.into());
    }

    let effect_key = aos_sandbox_protocol::domain_ledger::operation::effect_key(operation_id, 0);
    let effect_bytes = controller.get(crate::RecordNamespace::Effect, &effect_key).ok_or(CLOSED)?;
    let effect = aos_sandbox_protocol::domain_ledger::effect_history::decode_effect(effect_bytes)?;
    if effect.plan().public_mutation_method() != Some(PublicOperationMethodV1::StartSandbox) {
        return Err(CLOSED.into());
    }
    let context = effect.plan().public_mutation_context()?.ok_or(CLOSED)?;
    if context.accepted_wall_seconds() != public.accepted_wall_seconds_v1() {
        return Err(CLOSED.into());
    }
    if let StartSourceSelectionV2::Controller { plan, .. } = selected {
        let original = plan.original_start_context_v1()?;
        if plan.accepted_start_origin_data_v1() != Some(accepted)
            || context.caller() != original.caller()
            || context.project() != original.project()
            || context.accepted_wall_seconds() != original.accepted_wall_seconds()
            || context.canonical_request() != original.canonical_request()
        {
            return Err(CLOSED.into());
        }
    }
    let request = context.validated_request()?;
    controller.require_public_mutation_targets_live_v2(context.project(), &request)?;
    let DormantSandboxRequestKindV1::Start(start) = &request else {
        return Err(CLOSED.into());
    };
    let decision = controller.rows_data_v2()
        .idempotency_decision_data_v2(start.mutation.as_option().ok_or(CLOSED)?.idempotency_key.as_slice()).ok_or(CLOSED)?;
    if decision.operation_id != operation_id {
        return Err(CLOSED.into());
    }
    let request_digest = decision.request_digest;
    if let StartSourceSelectionV2::Controller { plan, .. } = selected {
        if plan.request_digest() != request_digest {
            return Err(CLOSED.into());
        }
    }
    let previous = previous.manifest();
    if start.sandbox_id.as_slice() != previous.sandbox().as_bytes()
        || context.project() != previous.project()
    {
        return Err(CLOSED.into());
    }
    let (operation, _) = source.operation_v1()?;
    let origin = operation.start_native_origin_v1().ok_or(CLOSED)?;
    if operation.operation_id() != operation_id
        || origin.accepted_v1() != accepted
        || operation.phase() != LifecyclePhaseV1::Accepted
        || operation.terminal_result().is_some()
        || operation.semantic_commit().is_some()
    {
        return Err(CLOSED.into());
    }
    match selected {
        StartSourceSelectionV2::Controller { .. } => {
            origin.first_native_clock_v1().validate_later_sample(sample)?;
        }
        StartSourceSelectionV2::Root(_) => {
            origin.first_native_clock_v1().validate_same_boot_elapsed_data_v1(sample)?;
        }
    }
    if sample.boottime_nanoseconds() >= origin.cutoff_v1()
        || accepted.cutoff_for_sample_data_v1(sample).is_none()
    {
        return Err(CLOSED.into());
    }

    let admission = lifecycle_public_mutation_admission_from_observation_v2(
        controller, operation_id, context.project(), previous.node(), &request,
    )?;
    let expected = lifecycle_operation_from_public_mutation_v1(
        operation_id, context.caller(), context.project(),
        context.accepted_wall_seconds(), context.canonical_request(), &request, admission,
    )?;
    require_same_lifecycle_admission_v1(&expected, operation)?;
    let LifecycleIntentV1::Start { sandbox, fence } = operation.intent() else {
        return Err(CLOSED.into());
    };
    if *sandbox != previous.sandbox()
        || fence.expected_generation() != previous.desired_generation()
    {
        return Err(CLOSED.into());
    }
    let successor = fence.expected_generation().get().checked_add(1).ok_or(CLOSED)?;

    let projection = get_from_observation_v2(controller, PublicProjectionKindV1::Sandbox, *sandbox.as_bytes())?.ok_or(CLOSED)?;
    let PublicProjectionResourceV1::Sandbox(resource) = projection.resource() else {
        return Err(CLOSED.into());
    };
    let desired = resource.desired.as_option().ok_or(CLOSED)?;
    let specification = desired.specification.as_option().ok_or(CLOSED)?;
    let requested_policy = desired.requested_policy.as_option().ok_or(CLOSED)?;
    let effective_policy = resource.effective_policy.as_option().ok_or(CLOSED)?;
    if projection.operation() != operation_id
        || projection.project() != previous.project()
        || resource.project_id.as_slice() != previous.project().as_bytes()
        || !resource.parent_sandbox_id.is_empty()
        || desired.generation != successor
        || desired.lifecycle.as_known() != Some(DesiredLifecycle::DESIRED_LIFECYCLE_RUNNING)
        || resource.resource_version != crate::production_operation_compiler::admitted_public_resource_version_v1(
            operation_id, PublicOperationMethodV1::StartSandbox,
            successor, request_digest,
        )
        || specification.media_type != previous.sandbox_spec().media_type().as_str()
        || specification.sha256.as_slice() != previous.sandbox_spec().digest().as_bytes()
        || specification.encoded_size != previous.sandbox_spec().encoded_size()
        || requested_policy != effective_policy
    {
        return Err(CLOSED.into());
    }
    let projection_revision = projection.revision();
    let publisher = current_publisher_policy_data_v2(
        controller, previous.project(), &requested_policy.media_type,
        &requested_policy.sha256, requested_policy.encoded_size, Some(sample.wall_seconds()),
    )?;

    Ok(CurrentAcceptedStartProjectSourceV2 {
        operation: operation_id,
        project: previous.project(),
        sandbox: *sandbox,
        predecessor_generation: previous.desired_generation(),
        successor_generation: DesiredGeneration::new(successor),
        projection_revision,
        native_origin: origin,
        publisher,
    })
}

const CLOSED: JournalError = JournalError::ProtectedBoundary;

/// Prices only new genuine-owner selector and typed projection forwarding.
pub(crate) fn start_source_observation_control_bytes_v2() -> Option<usize> {
    start_source_selector_control_bytes_v2()?
        .checked_add(HistoricalObservationV1::journal_receiving_control_bytes_v1()?)
}

/// Prices Root's selector after its genuine model giver already paid the loan.
pub(crate) fn start_source_root_observation_control_bytes_v2() -> Option<usize> {
    start_source_selector_control_bytes_v2()
}

fn start_source_selector_control_bytes_v2() -> Option<usize> {
    use std::mem::size_of;
    use super::public_create_source::CurrentPublisherPolicyDataErrorV2;

    let selection = size_of::<(HistoricalObservationV1<'_>, StartSourceSelectionV2<'_>,
        &LifecycleHistoricalReadOriginalV1, &CanonicalAssignmentManifestV1, RawPairedClockSample)>()
        .checked_mul(3)?
        .checked_add(size_of::<Result<CurrentAcceptedStartProjectSourceV2, Cause>>().checked_mul(3)?)?;
    let publisher = size_of::<(HistoricalObservationV1<'_>, ProjectId, &str, &[u8], u64, Option<i64>)>()
        .checked_mul(3)?
        .checked_add(size_of::<Result<CurrentPublisherPolicyDataV2, CurrentPublisherPolicyDataErrorV2>>().checked_mul(3)?)?;
    selection.checked_add(publisher)?
        // The finite Journal/Root quote entry forwards this one shared result.
        .checked_add(size_of::<Option<usize>>().checked_mul(3)?)?
        .checked_add(crate::lifecycle::historical_admission_control_bytes_v2()?)
}
