//! Protected-current parent resource input for execution specification production.
//!
//! The canonical sandbox specification is retained by the controller journal.
//! This source joins its exact bytes to the current public sandbox projection
//! and protected bound assignment under one exclusive journal borrow. The
//! source is not a broker-ledger reservation or a runtime-effect capability.

use aos_sandbox_model::model::spec::ResourceProfile;
use aos_sandbox_model::{
    CanonicalAssignmentManifestV1, NodeId, ObjectDescriptor, ObjectDigest, ProjectId,
    ResourceVector, SandboxId, resource_profile_digest_v1,
};

use crate::Journal;
use crate::journal::historical_observation::HistoricalObservationV1;
use aos_sandbox_protocol::public_api::projection::{PublicProjectionError, PublicProjectionKindV1};
use crate::lifecycle::{
    LifecycleRuntimeAdmissionErrorV1, lifecycle_runtime_admission_fence_from_observation_v2,
};
use crate::runtime_authority::{
    RuntimeAuthorityError, RuntimeAuthorityLimits, RuntimeAuthorityStateV1,
};
use crate::sandbox_spec_state::{self, SandboxSpecStateError};

/// Reports an unavailable or inconsistent current parent resource profile.
#[derive(Debug, thiserror::Error)]
pub enum ExecutionParentResourceSourceErrorV1 {
    /// The protected assignment, projection, or retained specification changed.
    #[error("current execution parent resource input is unavailable")]
    NotCurrent,
    /// The exact current profile is unresolved or does not match its assignment.
    #[error("current execution parent resource profile is not admitted")]
    ProfileUnavailable,
    /// The public/protected lifecycle join failed.
    #[error(transparent)]
    Lifecycle(#[from] LifecycleRuntimeAdmissionErrorV1),
    /// The public projection could not be replayed.
    #[error(transparent)]
    Projection(#[from] PublicProjectionError),
    /// The protected runtime-assignment namespace could not be replayed.
    #[error(transparent)]
    RuntimeAuthority(#[from] RuntimeAuthorityError),
    /// The canonical sandbox-specification namespace could not be replayed.
    #[error(transparent)]
    SandboxSpecification(#[from] SandboxSpecStateError),
}

/// Holds one exact resolved parent profile from protected current state.
///
/// The assignment and its reservation vector are included for subsequent
/// admission joins. Neither this value nor its reservation vector reserves
/// output bytes or authorizes a Host effect after the journal borrow ends.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ExecutionParentResourceSourceV1 {
    project: ProjectId,
    sandbox: SandboxId,
    node: NodeId,
    projection_revision: ObjectDigest,
    binding_digest: ObjectDigest,
    specification_descriptor: ObjectDescriptor,
    specification_record_digest: ObjectDigest,
    assignment: CanonicalAssignmentManifestV1,
    profile: ResourceProfile,
    profile_commitment: ObjectDigest,
    parent_reservations: ResourceVector,
}

impl ExecutionParentResourceSourceV1 {
    /// Borrows the exact resolved parent resource profile.
    #[must_use]
    pub const fn profile(&self) -> &ResourceProfile {
        &self.profile
    }

    /// Returns the profile commitment retained by current assignment.
    #[must_use]
    pub const fn profile_commitment(&self) -> ObjectDigest {
        self.profile_commitment
    }

    /// Borrows the exact current canonical assignment.
    #[must_use]
    pub const fn assignment(&self) -> &CanonicalAssignmentManifestV1 {
        &self.assignment
    }

    /// Returns the current assignment's parent reservation vector.
    #[must_use]
    pub const fn parent_reservations(&self) -> ResourceVector {
        self.parent_reservations
    }

    /// Returns the complete public projection record digest observed at the join.
    #[must_use]
    pub const fn projection_revision(&self) -> ObjectDigest {
        self.projection_revision
    }

    /// Returns the protected runtime binding record commitment.
    #[must_use]
    pub const fn binding_digest(&self) -> ObjectDigest {
        self.binding_digest
    }

    /// Borrows the exact canonical sandbox-specification descriptor.
    #[must_use]
    pub const fn specification_descriptor(&self) -> &ObjectDescriptor {
        &self.specification_descriptor
    }

    /// Returns the immutable sandbox-specification publication record digest.
    #[must_use]
    pub const fn specification_record_digest(&self) -> ObjectDigest {
        self.specification_record_digest
    }
}

/// Joins a current bound assignment to its durable canonical parent profile.
///
/// The lifecycle join rejects a stale public sandbox observation and validates
/// the complete protected runtime-authority namespace. The specification
/// namespace is then replayed and its resolved profile must reproduce the
/// assignment's exact resource commitment. The exclusive journal borrow
/// prevents an intervening controller mutation, but does not establish live
/// Host currentness or broker-ledger admission.
///
/// # Errors
///
/// Returns [`ExecutionParentResourceSourceErrorV1`] for absent, stale, corrupt,
/// unresolved, or commitment-mismatched current resource evidence.
pub fn current_execution_parent_resource_from_journal_v1(
    journal: &mut Journal,
    project: ProjectId,
    sandbox: SandboxId,
    node: NodeId,
) -> Result<ExecutionParentResourceSourceV1, ExecutionParentResourceSourceErrorV1> {
    current_execution_parent_resource_from_observation_v2(
        HistoricalObservationV1::from_journal_v1(journal), project, sandbox, node,
    )
}

/// Compares current parent DATA under the actual retained historical owner.
///
/// The original lifecycle, projection and Runtime protection checks remain at
/// their original semantic frontiers. The returned source grants no effect.
///
/// # Errors
/// Refuses the original missing, stale, corrupt or mismatched parent evidence.
pub(crate) fn current_execution_parent_resource_from_observation_v2(
    journal: HistoricalObservationV1<'_>,
    project: ProjectId,
    sandbox: SandboxId,
    node: NodeId,
) -> Result<ExecutionParentResourceSourceV1, ExecutionParentResourceSourceErrorV1> {
    let _current =
        lifecycle_runtime_admission_fence_from_observation_v2(journal, project, sandbox, node)?;
    let projection = crate::controller_service::public_projection::get_from_observation_v2(
        journal, PublicProjectionKindV1::Sandbox, *sandbox.as_bytes(),
    )?
        .ok_or(ExecutionParentResourceSourceErrorV1::NotCurrent)?;
    let binding = crate::runtime_authority::current_observed_v2(
        journal, RuntimeAuthorityLimits::default(), sandbox,
    )?
        .filter(|binding| {
            binding.state() == RuntimeAuthorityStateV1::Bound && binding.holder().is_some()
        })
        .ok_or(ExecutionParentResourceSourceErrorV1::NotCurrent)?;
    let assignment = binding.manifest().clone();
    let manifest = assignment.manifest();
    if projection.project() != project
        || manifest.project() != project
        || manifest.sandbox() != sandbox
        || manifest.node() != node
    {
        return Err(ExecutionParentResourceSourceErrorV1::NotCurrent);
    }

    let specification_descriptor = manifest.sandbox_spec();
    let specification = sandbox_spec_state::get_from_observation_v2(journal, specification_descriptor)?
        .ok_or(ExecutionParentResourceSourceErrorV1::ProfileUnavailable)?;
    let profile = specification.spec().resource_profile().clone();
    let profile_commitment = manifest.resource_commitment();
    let parent_reservations = manifest.reservations();
    validate_current_parent_profile(&profile, profile_commitment)?;

    Ok(ExecutionParentResourceSourceV1 {
        project,
        sandbox,
        node,
        projection_revision: projection.revision(),
        binding_digest: binding.digest(),
        specification_descriptor: specification_descriptor.clone(),
        specification_record_digest: specification.record_digest(),
        assignment,
        profile,
        profile_commitment,
        parent_reservations,
    })
}

/// Replays and compares a previously observed parent resource source.
///
/// The result is still nonauthorizing after the journal borrow ends; effect
/// admission requires an ordered cross-owner currentness barrier.
///
/// # Errors
///
/// Returns [`ExecutionParentResourceSourceErrorV1`] if any current projection,
/// binding, specification, profile, or parent reservation differs or fails replay.
pub fn revalidate_execution_parent_resource_from_journal_v1(
    journal: &mut Journal,
    source: &ExecutionParentResourceSourceV1,
) -> Result<(), ExecutionParentResourceSourceErrorV1> {
    revalidate_execution_parent_resource_from_observation_v2(
        HistoricalObservationV1::from_journal_v1(journal), source,
    )
}

/// Revalidates a retained parent against the same genuine observation owner.
///
/// # Errors
/// Refuses the original replay failure or any changed parent field.
pub(crate) fn revalidate_execution_parent_resource_from_observation_v2(
    journal: HistoricalObservationV1<'_>,
    source: &ExecutionParentResourceSourceV1,
) -> Result<(), ExecutionParentResourceSourceErrorV1> {
    let current = current_execution_parent_resource_from_observation_v2(
        journal,
        source.project,
        source.sandbox,
        source.node,
    )?;
    if current != *source {
        return Err(ExecutionParentResourceSourceErrorV1::NotCurrent);
    }
    Ok(())
}

/// Prices the actual current-parent observation interfaces before model growth.
///
/// Dynamic projections, Runtime history, specification maps and profile clones
/// retain their original complete invoice. The two projection/Runtime calls
/// are distinct: the lifecycle join and the subsequent exact parent comparison.
pub(crate) fn observed_current_control_bytes_v2() -> Option<usize> {
    use std::mem::size_of;
    use crate::lifecycle::LifecycleRuntimeAdmissionFenceV1;

    type Arguments<'a> = (HistoricalObservationV1<'a>, ProjectId, SandboxId, NodeId);
    type Current = Result<ExecutionParentResourceSourceV1, ExecutionParentResourceSourceErrorV1>;
    type Lifecycle = Result<LifecycleRuntimeAdmissionFenceV1, LifecycleRuntimeAdmissionErrorV1>;

    // The current entry and nested lifecycle entry own distinct ABI planes.
    size_of::<Arguments<'_>>().checked_mul(3)?
        .checked_add(size_of::<Current>().checked_mul(3)?)?
        .checked_add(size_of::<Arguments<'_>>().checked_mul(3)?)?
        .checked_add(size_of::<Lifecycle>().checked_mul(3)?)?
        .checked_add(size_of::<LifecycleRuntimeAdmissionErrorV1>().checked_mul(3)?)?
        .checked_add(size_of::<ExecutionParentResourceSourceErrorV1>().checked_mul(3)?)?
        .checked_add(crate::controller_service::public_projection::
            projection_observation_control_bytes_v2()?.checked_mul(2)?)?
        .checked_add(crate::runtime_authority::current_observation_control_bytes_v2()?.checked_mul(2)?)?
        .checked_add(sandbox_spec_state::observed_get_control_bytes_v2()?)?
        .checked_add(size_of::<Option<usize>>().checked_mul(3)?)
}

/// Prices revalidation's own argument and owning return forwarding controls.
///
/// This includes the current-parent call once and grants no observation owner.
pub(crate) fn observed_revalidation_control_bytes_v2() -> Option<usize> {
    use std::mem::size_of;

    observed_current_control_bytes_v2()?
        .checked_add(size_of::<(HistoricalObservationV1<'_>, &ExecutionParentResourceSourceV1)>()
            .checked_mul(3)?)?
        .checked_add(size_of::<Result<(), ExecutionParentResourceSourceErrorV1>>().checked_mul(3)?)?
        .checked_add(size_of::<Option<usize>>().checked_mul(3)?)
}

fn validate_current_parent_profile(
    profile: &ResourceProfile,
    assignment_commitment: ObjectDigest,
) -> Result<(), ExecutionParentResourceSourceErrorV1> {
    if profile.contains_inherited() || resource_profile_digest_v1(profile) != assignment_commitment
    {
        return Err(ExecutionParentResourceSourceErrorV1::ProfileUnavailable);
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use aos_sandbox_model::model::spec::{Limit, LimitDimension, LimitValue, ResourceProfile};
    use aos_sandbox_model::{FeatureRef, NodeId, ObjectDigest, ProjectId, SandboxId};
    use tempfile::TempDir;

    use crate::{Journal, lifecycle::LifecycleRuntimeAdmissionErrorV1};

    use super::{
        ExecutionParentResourceSourceErrorV1, current_execution_parent_resource_from_journal_v1,
        validate_current_parent_profile,
    };

    #[test]
    fn parent_profile_requires_exact_current_commitment_and_no_inheritance() {
        let resolved = ResourceProfile::new(vec![Limit::new(
            LimitDimension::Memory,
            LimitValue::Bounded(4096),
            FeatureRef::new("aos.sandbox.runtime.linux-systemd", 1, 0).expect("feature"),
        )])
        .expect("resolved profile");
        let commitment = aos_sandbox_model::resource_profile_digest_v1(&resolved);
        assert!(validate_current_parent_profile(&resolved, commitment).is_ok());
        assert!(matches!(
            validate_current_parent_profile(&resolved, ObjectDigest::from_bytes([7; 32])),
            Err(ExecutionParentResourceSourceErrorV1::ProfileUnavailable)
        ));

        let inherited = ResourceProfile::new(vec![Limit::new(
            LimitDimension::Memory,
            LimitValue::Inherited,
            FeatureRef::new("aos.sandbox.runtime.linux-systemd", 1, 0).expect("feature"),
        )])
        .expect("inherited profile");
        let inherited_commitment = aos_sandbox_model::resource_profile_digest_v1(&inherited);
        assert!(matches!(
            validate_current_parent_profile(&inherited, inherited_commitment),
            Err(ExecutionParentResourceSourceErrorV1::ProfileUnavailable)
        ));
    }

    #[test]
    fn absent_current_assignment_cannot_produce_parent_profile() {
        let directory = TempDir::new().expect("temporary directory");
        let (mut journal, _) = Journal::open(
            directory.path().join("controller.journal"),
            Default::default(),
        )
        .expect("journal");
        let result = current_execution_parent_resource_from_journal_v1(
            &mut journal,
            ProjectId::from_bytes([1; 16]),
            SandboxId::from_bytes([2; 16]),
            NodeId::from_bytes([3; 16]),
        );

        assert!(matches!(
            result,
            Err(ExecutionParentResourceSourceErrorV1::Lifecycle(
                LifecycleRuntimeAdmissionErrorV1::MissingProjection
            ))
        ));
    }
}
