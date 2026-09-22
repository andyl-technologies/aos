//! Protected runtime fences for lifecycle admission.
//!
//! Runtime-bound public mutations need more than the public sandbox
//! projection: the namespace generation exists only in protected assignment
//! state. This join reads both namespaces while the controller holds exclusive
//! journal custody and returns a non-authorizing lifecycle fence. Dispatch
//! still requires fresh ownership, broker-plan, clock, and live-runtime proof.

use aos_sandbox_core::{NodeId, ProjectId, Revision, SandboxId};

use crate::Journal;
use crate::controller_service::public_projection::{
    PublicProjectionError, PublicProjectionKindV1, PublicProjectionResourceV1,
    PublicProjectionStoreV1,
};
use crate::runtime_authority::{
    RuntimeAuthorityError, RuntimeAuthorityLimits, RuntimeAuthorityStateV1, RuntimeAuthorityStore,
};

use super::{
    DesiredStateFenceV1, LifecycleModelError, LifecycleResourceStateDigestV1, LifecycleResourceV1,
    LiveRuntimeFenceV1, ResourceExpectationV1,
};

/// Carries the exact sandbox expectation and live assignment fence admitted together.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct LifecycleRuntimeAdmissionFenceV1 {
    expectation: ResourceExpectationV1,
    runtime: LiveRuntimeFenceV1,
}

impl LifecycleRuntimeAdmissionFenceV1 {
    /// Borrows the exact protected sandbox expectation.
    #[must_use]
    pub const fn expectation(&self) -> &ResourceExpectationV1 {
        &self.expectation
    }

    /// Returns the exact incarnation, assignment, and namespace fence.
    #[must_use]
    pub const fn runtime(&self) -> LiveRuntimeFenceV1 {
        self.runtime
    }
}

/// Reports a failed public-projection and protected-assignment join.
#[derive(Debug, thiserror::Error)]
pub enum LifecycleRuntimeAdmissionErrorV1 {
    /// The current public sandbox projection is absent or names another schema.
    #[error("current public sandbox projection is unavailable")]
    MissingProjection,
    /// The public observation and protected assignment do not describe one current runtime.
    #[error("public sandbox observation does not match protected current assignment")]
    CurrentMismatch,
    /// The protected runtime assignment is absent or revoked.
    #[error("protected current runtime assignment is unavailable")]
    MissingAssignment,
    /// The public projection namespace is malformed.
    #[error(transparent)]
    PublicProjection(#[from] PublicProjectionError),
    /// The runtime-authority namespace is malformed or exceeds its replay bounds.
    #[error(transparent)]
    RuntimeAuthority(#[from] RuntimeAuthorityError),
    /// The joined values cannot form a canonical lifecycle fence.
    #[error(transparent)]
    Lifecycle(#[from] LifecycleModelError),
}

/// Joins one public sandbox observation to its protected current assignment.
///
/// The returned value is admission evidence only. It contains the real
/// namespace generation without exposing a live runtime or effect authority.
/// The sole controller journal borrow prevents either namespace from changing
/// between the two reads.
///
/// # Errors
///
/// Returns [`LifecycleRuntimeAdmissionErrorV1`] when either namespace is
/// malformed, the sandbox has no bound assignment on `node`, or the public
/// incarnation, assignment epoch, desired generation, or specification does
/// not exactly match protected current state.
pub fn lifecycle_runtime_admission_fence_from_journal_v1(
    journal: &mut Journal,
    project: ProjectId,
    sandbox: SandboxId,
    node: NodeId,
) -> Result<LifecycleRuntimeAdmissionFenceV1, LifecycleRuntimeAdmissionErrorV1> {
    let projection = PublicProjectionStoreV1::new(journal)
        .get(PublicProjectionKindV1::Sandbox, *sandbox.as_bytes())?
        .ok_or(LifecycleRuntimeAdmissionErrorV1::MissingProjection)?;
    if projection.project() != project {
        return Err(LifecycleRuntimeAdmissionErrorV1::CurrentMismatch);
    }
    let PublicProjectionResourceV1::Sandbox(public) = projection.resource() else {
        return Err(LifecycleRuntimeAdmissionErrorV1::MissingProjection);
    };
    let desired = public
        .desired
        .as_option()
        .ok_or(LifecycleRuntimeAdmissionErrorV1::CurrentMismatch)?;
    let observed = public
        .observed
        .as_option()
        .ok_or(LifecycleRuntimeAdmissionErrorV1::CurrentMismatch)?;

    let binding = RuntimeAuthorityStore::load(journal, RuntimeAuthorityLimits::default())?
        .current(sandbox)?
        .filter(|binding| binding.state() == RuntimeAuthorityStateV1::Bound)
        .ok_or(LifecycleRuntimeAdmissionErrorV1::MissingAssignment)?;
    let manifest = binding.manifest().manifest();
    let public_specification = desired
        .specification
        .as_option()
        .ok_or(LifecycleRuntimeAdmissionErrorV1::CurrentMismatch)?;
    let protected_specification = manifest.sandbox_spec();
    if public.project_id.as_slice() != project.as_bytes()
        || public.sandbox_id.as_slice() != sandbox.as_bytes()
        || binding.sandbox() != sandbox
        || binding.holder().is_none()
        || manifest.node() != node
        || observed.incarnation_id.as_slice() != manifest.incarnation().as_bytes()
        || observed.assignment_epoch != manifest.epoch().get()
        || observed.desired_generation != manifest.desired_generation().get()
        || public_specification.media_type != protected_specification.media_type().as_str()
        || public_specification.sha256.as_slice() != protected_specification.digest().as_bytes()
        || public_specification.encoded_size != protected_specification.encoded_size()
    {
        return Err(LifecycleRuntimeAdmissionErrorV1::CurrentMismatch);
    }

    let resource = LifecycleResourceV1::Sandbox(sandbox);
    let revision = Revision::new(manifest.desired_generation().get());
    let state = LifecycleResourceStateDigestV1::from_stored(binding.assignment_digest())?;
    let desired =
        DesiredStateFenceV1::new(resource, manifest.desired_generation(), revision, state)?;
    let expectation = ResourceExpectationV1::present(resource, revision, state)?;
    let runtime = LiveRuntimeFenceV1::new(
        sandbox,
        desired,
        manifest.incarnation(),
        manifest.epoch(),
        manifest.namespace_generation(),
    )?;

    Ok(LifecycleRuntimeAdmissionFenceV1 {
        expectation,
        runtime,
    })
}
