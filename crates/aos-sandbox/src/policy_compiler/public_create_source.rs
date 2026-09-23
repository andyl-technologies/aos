//! Query-time canonical project-policy source for a parentless public Create.
//!
//! The controller journal already retains the exact canonical publisher
//! revision bytes. This join checks the accepted operation, its current
//! sandbox projection, and the publisher's current revision in one protected
//! journal claim. It is a source observation, not a compiler layer or a
//! durable AOSPCB01 binding.

use std::time::{SystemTime, UNIX_EPOCH};

use aos_sandbox_core::{ObjectDigest, OperationId, ProjectId, SandboxId};
use sha2::{Digest as _, Sha256};

use crate::controller_query::PublicOperationMethodV1;
use crate::controller_service::public_projection::{
    PublicProjectionError, PublicProjectionKindV1, PublicProjectionResourceV1,
    PublicProjectionStoreV1,
};
use crate::publisher_policy::{PublisherPolicyError, PublisherPolicyLimits, PublisherPolicyStore};
use crate::reconciler::{
    ReconcilerError, public_operation_resource_from_journal_v1,
    recovered_public_operation_admission_v1,
};
use crate::{Journal, JournalError};

const SOURCE_DOMAIN: &[u8] = b"aos.sandbox.public-create-project-source.v1\0";

/// Reports a failed protected public-Create source join.
#[derive(Debug, thiserror::Error)]
pub enum CurrentCreatePolicySourceErrorV1 {
    /// The selected public operation or projection is absent or mismatched.
    #[error("public Create source is not current")]
    NotCurrent,
    /// The protected controller journal is unavailable.
    #[error(transparent)]
    Journal(#[from] JournalError),
    /// The public operation could not be validated.
    #[error(transparent)]
    Operation(#[from] ReconcilerError),
    /// The public projection could not be validated.
    #[error(transparent)]
    Projection(#[from] PublicProjectionError),
    /// The publisher policy namespace could not be validated.
    #[error(transparent)]
    Publisher(#[from] PublisherPolicyError),
}

/// Retains exact canonical publisher bytes under a current Create selector.
///
/// This read-only value expires with the publisher head. Before any compiler
/// binding or effect, the caller must rejoin current operation, projection,
/// and policy heads under protected custody.
pub struct CurrentCreateProjectPolicySourceV1 {
    operation: OperationId,
    sandbox: SandboxId,
    project: ProjectId,
    projection_revision: ObjectDigest,
    policy_generation: u64,
    policy_digest: ObjectDigest,
    canonical_policy: Vec<u8>,
    commitment: ObjectDigest,
}

impl CurrentCreateProjectPolicySourceV1 {
    /// Returns the admitted public Create operation identity.
    #[must_use]
    pub const fn operation(&self) -> OperationId {
        self.operation
    }

    /// Returns the exact selected sandbox identity.
    #[must_use]
    pub const fn sandbox(&self) -> SandboxId {
        self.sandbox
    }

    /// Returns the protected project partition.
    #[must_use]
    pub const fn project(&self) -> ProjectId {
        self.project
    }

    /// Returns the complete checked public projection record digest.
    #[must_use]
    pub const fn projection_revision(&self) -> ObjectDigest {
        self.projection_revision
    }

    /// Returns the exact current publisher generation observed at the join.
    #[must_use]
    pub const fn policy_generation(&self) -> u64 {
        self.policy_generation
    }

    /// Returns the canonical publisher policy object's digest.
    #[must_use]
    pub const fn policy_digest(&self) -> ObjectDigest {
        self.policy_digest
    }

    /// Returns exact canonical publisher policy bytes validated by its store.
    #[must_use]
    pub fn canonical_policy(&self) -> &[u8] {
        &self.canonical_policy
    }

    /// Returns the versioned query-time source commitment.
    #[must_use]
    pub const fn commitment(&self) -> ObjectDigest {
        self.commitment
    }
}

/// Joins one parentless public Create to exact current canonical policy bytes.
///
/// The publisher policy is a resolved core policy, not a PolicyLayerV1. This
/// function makes no claim about project/request/ancestor layer provenance.
/// It rejects parented Create until an authenticated ancestry source exists.
///
/// # Errors
///
/// Returns an error for unsafe journal authority, missing or mismatched
/// operation/projection/policy, parented Create, expired current policy, or
/// noncanonical protected state.
pub fn current_parentless_create_project_source_v1(
    journal: &mut Journal,
    operation: OperationId,
    sandbox: SandboxId,
) -> Result<CurrentCreateProjectPolicySourceV1, CurrentCreatePolicySourceErrorV1> {
    journal.ensure_protected_authority()?;
    if operation.as_bytes() == &[0; 16] || sandbox.as_bytes() == &[0; 16] {
        return Err(CurrentCreatePolicySourceErrorV1::NotCurrent);
    }

    let admission = recovered_public_operation_admission_v1(journal, operation)?
        .ok_or(CurrentCreatePolicySourceErrorV1::NotCurrent)?;
    let public_operation = public_operation_resource_from_journal_v1(journal, operation)?
        .ok_or(CurrentCreatePolicySourceErrorV1::NotCurrent)?;
    if public_operation.operation_id.as_slice() != operation.as_bytes()
        || public_operation.method != PublicOperationMethodV1::CreateSandbox.as_str()
    {
        return Err(CurrentCreatePolicySourceErrorV1::NotCurrent);
    }

    let projection = PublicProjectionStoreV1::new(journal)
        .get(PublicProjectionKindV1::Sandbox, *sandbox.as_bytes())?
        .ok_or(CurrentCreatePolicySourceErrorV1::NotCurrent)?;
    let PublicProjectionResourceV1::Sandbox(sandbox_resource) = projection.resource() else {
        return Err(CurrentCreatePolicySourceErrorV1::NotCurrent);
    };
    if projection.operation() != operation
        || sandbox_resource.sandbox_id.as_slice() != sandbox.as_bytes()
        || !sandbox_resource.parent_sandbox_id.is_empty()
    {
        return Err(CurrentCreatePolicySourceErrorV1::NotCurrent);
    }
    let project = projection.project();
    if sandbox_resource.project_id.as_slice() != project.as_bytes()
        || admission.project() != project
    {
        return Err(CurrentCreatePolicySourceErrorV1::NotCurrent);
    }
    let desired = sandbox_resource
        .desired
        .as_option()
        .ok_or(CurrentCreatePolicySourceErrorV1::NotCurrent)?;
    let requested_policy = desired
        .requested_policy
        .as_option()
        .ok_or(CurrentCreatePolicySourceErrorV1::NotCurrent)?;
    let effective_policy = sandbox_resource
        .effective_policy
        .as_option()
        .ok_or(CurrentCreatePolicySourceErrorV1::NotCurrent)?;
    if requested_policy != effective_policy || desired.specification.as_option().is_none() {
        return Err(CurrentCreatePolicySourceErrorV1::NotCurrent);
    }
    let projection_revision = projection.revision();

    let revision = PublisherPolicyStore::load(journal, PublisherPolicyLimits::default())?
        .current_policy(project)?
        .ok_or(CurrentCreatePolicySourceErrorV1::NotCurrent)?;
    let descriptor = revision.descriptor();
    if requested_policy.media_type != descriptor.media_type().as_str()
        || requested_policy.sha256.as_slice() != descriptor.digest().as_bytes()
        || requested_policy.encoded_size != descriptor.encoded_size()
    {
        return Err(CurrentCreatePolicySourceErrorV1::NotCurrent);
    }
    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_err(|_| CurrentCreatePolicySourceErrorV1::NotCurrent)?;
    let now =
        i64::try_from(now.as_secs()).map_err(|_| CurrentCreatePolicySourceErrorV1::NotCurrent)?;
    if now < revision.not_before() || now >= revision.expires_at() {
        return Err(CurrentCreatePolicySourceErrorV1::NotCurrent);
    }

    let policy_generation = revision.generation();
    let policy_digest = descriptor.digest();
    let canonical_policy = revision.canonical_policy().to_vec();
    let commitment = ObjectDigest::from_bytes(
        Sha256::new()
            .chain_update(SOURCE_DOMAIN)
            .chain_update(operation.as_bytes())
            .chain_update(sandbox.as_bytes())
            .chain_update(project.as_bytes())
            .chain_update(projection_revision.as_bytes())
            .chain_update(policy_generation.to_be_bytes())
            .chain_update(policy_digest.as_bytes())
            .finalize()
            .into(),
    );
    Ok(CurrentCreateProjectPolicySourceV1 {
        operation,
        sandbox,
        project,
        projection_revision,
        policy_generation,
        policy_digest,
        canonical_policy,
        commitment,
    })
}
