//! Compiles the proposed successor assignment for one genuine accepted Start.
//!
//! The native Controller/Source owner prepays and retains this whole pure
//! result before any Ownership contact. This DATA does not authorize a resource
//! operation. Root independently repeats the current signed-input compilation
//! and the later exact plan/lease checks before it issues a resource grant.

use aos_sandbox_core::{CanonicalAssignmentManifestV1, ObjectDigest, RawPairedClockSample};
use aos_sandbox_policy::{CompiledPolicyCandidateV1, PolicyCompilerInputV1};
use crate::lifecycle::LifecycleHistoricalReadOriginalV1;
use crate::policy_compiler::root_signed_sources::RootSignedProjectSourcesV1;
use crate::policy_compiler::{
    AssignmentManifestPlacementDataV2, CurrentAcceptedStartProjectSourceV2,
    assignment_manifest_policy_data_v2, current_accepted_start_project_source_v2,
    materialize_assignment_manifest_v2,
};
use crate::{Journal, JournalError, OperationPlan};

pub(crate) type StartAssignmentCompilationResultV2 =
    Result<StartAssignmentCompilationDataV2, Box<dyn std::error::Error + Send + Sync>>;

/// Retains the actual source selection, compiler models and new canonical value.
pub(crate) struct StartAssignmentCompilationDataV2 {
    source: CurrentAcceptedStartProjectSourceV2,
    input: PolicyCompilerInputV1,
    candidate: CompiledPolicyCandidateV1,
    manifest: CanonicalAssignmentManifestV1,
}

impl StartAssignmentCompilationDataV2 {
    pub(crate) fn manifest_v2(&self) -> &CanonicalAssignmentManifestV1 {
        &self.manifest
    }

    pub(crate) fn source_v2(&self) -> &CurrentAcceptedStartProjectSourceV2 {
        &self.source
    }

    pub(in crate::policy_compiler) fn candidate_v2(&self) -> &CompiledPolicyCandidateV1 {
        &self.candidate
    }
}

/// Reuses the same parentless compiler and canonical manifest materializer.
///
/// # Errors
/// Refuses a changed accepted Start/Source origin, stale signed publisher/tree
/// prerequisites, altered exact specification, changed exclusive placement or
/// capacity differing from the still-carried original assignment reservation.
pub(crate) fn compile_accepted_start_assignment_v2(
    controller: &mut Journal,
    plan: &OperationPlan,
    source: &LifecycleHistoricalReadOriginalV1,
    previous: &CanonicalAssignmentManifestV1,
    specification: &crate::sandbox_spec_state::DurableSandboxSpecV1,
    signed: &RootSignedProjectSourcesV1,
    source_tree_head: ObjectDigest,
    sample: RawPairedClockSample,
) -> StartAssignmentCompilationResultV2 {
    let current = current_accepted_start_project_source_v2(
        controller, plan, source, previous, sample,
    )?;
    compile_current_start_assignment_v2(current, previous, specification, signed,
        source_tree_head, sample)
}

/// Rebuilds Start's successor from Root's actual completed current readers.
///
/// The caller prepays and retains complete C/Source/policy/native models.
/// This shares Controller's compiler and materializer and returns comparison
/// DATA only, never an OperationPlan, receiving original or predecessor grant.
pub(in crate::policy_compiler) fn compile_root_start_assignment_v2(
    controller: &mut Journal,
    operation: aos_sandbox_core::OperationId,
    source: &LifecycleHistoricalReadOriginalV1,
    previous: &CanonicalAssignmentManifestV1,
    specification: &crate::sandbox_spec_state::DurableSandboxSpecV1,
    signed: &RootSignedProjectSourcesV1,
    source_tree_head: ObjectDigest,
    sample: RawPairedClockSample,
) -> StartAssignmentCompilationResultV2 {
    let current = crate::policy_compiler::public_start_source::
        current_accepted_start_source_from_root_records_v2(
            controller, operation, source, previous, sample,
        )?;
    compile_current_start_assignment_v2(current, previous, specification, signed,
        source_tree_head, sample)
}

fn compile_current_start_assignment_v2(
    current: CurrentAcceptedStartProjectSourceV2,
    previous: &CanonicalAssignmentManifestV1,
    specification: &crate::sandbox_spec_state::DurableSandboxSpecV1,
    signed: &RootSignedProjectSourcesV1,
    source_tree_head: ObjectDigest,
    sample: RawPairedClockSample,
) -> StartAssignmentCompilationResultV2 {
    if specification.descriptor() != previous.manifest().sandbox_spec() {
        return Err(JournalError::ProtectedBoundary.into());
    }
    require_current_start_signed_inputs_v2(&current, signed, source_tree_head, sample)?;
    let publisher = current.publisher_v2();

    let (input, candidate) = super::parentless_compiler::compile_parentless_current_v1(
        signed, current.project_v2(), current.sandbox_v2(), publisher.cache_domain,
    )?;
    let reservations = crate::policy_compiler::create_q04::candidate_capacity(&candidate)?;
    let previous_model = previous.manifest();
    if reservations != previous_model.reservations() {
        return Err(JournalError::ProtectedBoundary.into());
    }
    let policy = candidate.portable();
    let policy_data = assignment_manifest_policy_data_v2(policy.policy(), specification.spec())?;
    let placement = AssignmentManifestPlacementDataV2 {
        sandbox: previous_model.sandbox(),
        project: previous_model.project(),
        ancestry: previous_model.ancestry().clone(),
        incarnation: previous_model.incarnation(),
        node: previous_model.node(),
        epoch: previous_model.epoch(),
        desired_generation: current.successor_generation_v2(),
        namespace_generation: previous_model.namespace_generation(),
    };
    let manifest = materialize_assignment_manifest_v2(
        placement, specification.spec(), specification.descriptor(), policy_data,
        policy.policy_descriptor().clone(), reservations,
    )?;
    super::parentless_compiler::require_manifest_candidate_v1(
        &manifest, specification.spec(), &candidate,
    )?;

    Ok(StartAssignmentCompilationDataV2 { source: current, input, candidate, manifest })
}

/// Compares the same current Start/publisher/Tree and signed-policy cut.
///
/// Controller compilation and Root's read-only input reply share this pure
/// predicate. Neither path can replace actual current native Source or policy
/// custody with a successful comparison result.
pub(crate) fn require_current_start_signed_inputs_v2(
    current: &CurrentAcceptedStartProjectSourceV2,
    signed: &RootSignedProjectSourcesV1,
    source_tree_head: ObjectDigest,
    sample: RawPairedClockSample,
) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    let publisher = current.publisher_v2();
    let project = signed.0.head();
    if project.project() != current.project_v2()
        || project.publisher_generation() != publisher.policy_generation
        || project.publisher_digest() != publisher.policy_digest
        || signed.0.cache_domain() != publisher.cache_domain
        || project.prerequisite_claims() != [
            source_tree_head,
            signed.1.packet_digest(),
            publisher.cache_domain_head,
            publisher.revocation_head,
        ]
        || sample.wall_seconds() >= publisher.expires
        || sample.wall_seconds() >= project.expires_at()
        || sample.wall_seconds() >= signed.1.expires_at()
    {
        return Err(JournalError::ProtectedBoundary.into());
    }

    Ok(())
}
