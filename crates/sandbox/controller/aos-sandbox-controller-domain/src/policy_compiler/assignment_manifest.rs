//! Materializes canonical assignment proposal DATA for Create and fresh Start.
//!
//! The owning caller establishes its accepted operation, native interval,
//! current Source/policy inputs and complete receiving before this pure body.
//! Placement DATA supplies no currentness, lease, signing or publication grant.

use aos_sandbox_model::{
    AssignmentEpoch, CanonicalAssignmentManifestV1, DesiredGeneration,
    IncarnationId, NamespaceGeneration, NodeId, ObjectDescriptor, ProjectId,
    FeatureRef, ObjectDigest, ResourceVector, SandboxId,
};
use aos_sandbox_model::model::{
    AssignmentManifestV1, InvalidAssignmentManifest, Policy, SandboxAncestry,
    SandboxSpec, assignment_required_features_v1,
};

/// Keeps the independently established placement separate from policy expansion.
pub(crate) struct AssignmentManifestPlacementDataV2 {
    pub(crate) sandbox: SandboxId,
    pub(crate) project: ProjectId,
    pub(crate) ancestry: SandboxAncestry,
    pub(crate) incarnation: IncarnationId,
    pub(crate) node: NodeId,
    pub(crate) epoch: AssignmentEpoch,
    pub(crate) desired_generation: DesiredGeneration,
    pub(crate) namespace_generation: NamespaceGeneration,
}

/// Owns the same policy-derived collections before placement construction.
pub(crate) struct AssignmentManifestPolicyDataV2 {
    commitments: Vec<ObjectDescriptor>,
    features: Vec<FeatureRef>,
    resource_commitment: ObjectDigest,
}

/// Derives the canonical policy collections at the caller's original frontier.
///
/// # Errors
/// Rejects the existing noncanonical or oversized required-feature union.
pub(crate) fn assignment_manifest_policy_data_v2(
    policy: &Policy,
    specification: &SandboxSpec,
) -> Result<AssignmentManifestPolicyDataV2, InvalidAssignmentManifest> {
    let mut commitments = policy.input_commitments().to_vec();
    commitments.sort();
    commitments.dedup();
    let features = assignment_required_features_v1(policy, specification)?;

    Ok(AssignmentManifestPolicyDataV2 {
        commitments,
        features,
        resource_commitment: aos_sandbox_model::resource_profile_digest_v1(policy.limits()),
    })
}

/// Applies the sole canonical assignment model and encoding recipe.
///
/// Create supplies its genuine first placement. Fresh Start supplies its actual
/// accepted successor generation and the same exclusive incarnation/epoch/node;
/// neither caller edits the historical canonical manifest.
///
/// # Errors
/// Returns the existing canonical assignment model's validation error.
pub(crate) fn materialize_assignment_manifest_v2(
    placement: AssignmentManifestPlacementDataV2,
    specification: &SandboxSpec,
    specification_descriptor: &ObjectDescriptor,
    policy: AssignmentManifestPolicyDataV2,
    policy_descriptor: ObjectDescriptor,
    reservations: ResourceVector,
) -> Result<CanonicalAssignmentManifestV1, InvalidAssignmentManifest> {
    let manifest = AssignmentManifestV1::new(
        placement.sandbox,
        placement.project,
        placement.ancestry,
        placement.incarnation,
        placement.node,
        placement.epoch,
        placement.desired_generation,
        placement.namespace_generation,
        specification_descriptor.clone(),
        policy_descriptor,
        specification.environment().clone(),
        specification.root_view().clone(),
        policy.commitments,
        policy.resource_commitment,
        reservations,
        policy.features,
    )?;

    Ok(CanonicalAssignmentManifestV1::new(manifest))
}

/// Bounds the two additional passive construction carriers without namespaces.
pub(crate) fn assignment_manifest_construction_receiving_bytes_v2() -> Option<usize> {
    std::mem::size_of::<AssignmentManifestPlacementDataV2>()
        .checked_add(std::mem::size_of::<AssignmentManifestPolicyDataV2>())?
        .checked_mul(2)
}
