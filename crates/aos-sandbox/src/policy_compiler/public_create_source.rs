//! Query-time canonical project-policy source for a parentless public Create.
//!
//! The controller journal already retains the exact canonical publisher
//! revision bytes. This join checks the accepted operation, its current
//! sandbox projection, and the publisher's current revision in one protected
//! journal claim. It is a source observation, not a compiler layer or a
//! durable AOSPCB01 binding.

use std::time::{SystemTime, UNIX_EPOCH};

use aos_proto::aos::sandbox::v1::{Operation, OperationPhase};
use aos_sandbox_core::model::CacheDomain;
use aos_sandbox_core::{ObjectDigest, OperationId, ProjectId, RevocationScopeId, SandboxId};
use sha2::{Digest as _, Sha256};

use crate::cache_residency::{
    CacheResidencyProtectedJournalErrorV1, CacheResidencyProtectedOwnerV1,
    CurrentProjectPhysicalCacheHeadV1,
};
use crate::controller_query::PublicOperationMethodV1;
use crate::controller_service::public_projection::{
    PublicProjectionError, PublicProjectionKindV1, PublicProjectionResourceV1,
    PublicProjectionStoreV1,
};
use crate::hierarchy::protected_journal::{
    HierarchyProtectedJournalErrorV1, HierarchyProtectedJournalOwnerV1,
};
use crate::lifecycle::protected_journal_join::ProtectedSourceDomainJournalOwnerV1;
use crate::publisher_policy::{PublisherPolicyError, PublisherPolicyLimits, PublisherPolicyStore};
use crate::reconciler::{
    ReconcilerError, public_operation_resource_from_journal_v1,
    recovered_public_operation_admission_v1,
};
use crate::{Journal, JournalError};

use super::{
    CacheDomainInputV1, HardLimitValueV1, PolicyCompilerInputV1, PolicyDeploymentSourcesV1,
    PolicyPublicationPrerequisitesV1, RevocationInputV1, SignedProjectPolicySourceV1,
    normalized_policy_input_digest_v1,
};

const SOURCE_DOMAIN: &[u8] = b"aos.sandbox.public-create-project-source.v2\0";
const DRAFT_DOMAIN: &[u8] = b"aos.sandbox.public-create-policy-draft.v1\0";

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
    /// The independent physical Cache owner could not establish currentness.
    #[error(transparent)]
    Cache(#[from] CacheResidencyProtectedJournalErrorV1),
    /// The independent source-domain ancestry owner could not establish currentness.
    #[error(transparent)]
    Hierarchy(HierarchyProtectedJournalErrorV1),
}

/// Carries a read-only snapshot of two independent heads at one held cut.
///
/// The value cannot authorize publication once the held writer callback ends.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct CurrentCreatePolicyBarrierHeadsV2 {
    ancestry: ObjectDigest,
    physical_partition: ObjectDigest,
    physical_cache: ObjectDigest,
}

impl CurrentCreatePolicyBarrierHeadsV2 {
    /// Returns the current protected source-domain ancestry head.
    #[must_use]
    pub const fn ancestry(self) -> ObjectDigest {
        self.ancestry
    }

    /// Returns the selected complete physical Cache partition commitment.
    #[must_use]
    pub const fn physical_partition(self) -> ObjectDigest {
        self.physical_partition
    }

    /// Returns the current protected physical Cache replay head.
    #[must_use]
    pub const fn physical_cache(self) -> ObjectDigest {
        self.physical_cache
    }
}

/// Retains exact canonical publisher bytes under a current Create selector.
///
/// This read-only value expires with the accepted operation, projection,
/// publisher, cache-domain, or revocation head. Before any compiler binding
/// or effect, the caller must rejoin those heads under protected custody.
pub struct CurrentCreateProjectPolicySourceV1 {
    operation: OperationId,
    operation_revision: ObjectDigest,
    accepted_generation: u64,
    sandbox: SandboxId,
    project: ProjectId,
    projection_revision: ObjectDigest,
    policy_generation: u64,
    policy_digest: ObjectDigest,
    cache_domain: CacheDomain,
    cache_domain_head: ObjectDigest,
    revocation_scope: RevocationScopeId,
    revocation_generation: u64,
    revocation_head: ObjectDigest,
    canonical_policy: Vec<u8>,
    commitment: ObjectDigest,
}

impl CurrentCreateProjectPolicySourceV1 {
    /// Returns the admitted public Create operation identity.
    #[must_use]
    pub const fn operation(&self) -> OperationId {
        self.operation
    }

    /// Returns the exact accepted operation and effect-record revision.
    #[must_use]
    pub const fn operation_revision(&self) -> ObjectDigest {
        self.operation_revision
    }

    /// Returns the protected admission generation of the selected Create.
    #[must_use]
    pub const fn accepted_generation(&self) -> u64 {
        self.accepted_generation
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

    /// Returns the publisher-selected project disclosure domain.
    #[must_use]
    pub const fn cache_domain(&self) -> CacheDomain {
        self.cache_domain
    }

    /// Returns the publisher-owned current project cache-domain head.
    #[must_use]
    pub const fn cache_domain_head(&self) -> ObjectDigest {
        self.cache_domain_head
    }

    /// Returns the protected scope selected for this project.
    #[must_use]
    pub const fn revocation_scope(&self) -> RevocationScopeId {
        self.revocation_scope
    }

    /// Returns the exact current generation of the selected revocation scope.
    #[must_use]
    pub const fn revocation_generation(&self) -> u64 {
        self.revocation_generation
    }

    /// Returns the independent protected project revocation head observed
    /// with the publisher revision.
    #[must_use]
    pub const fn revocation_head(&self) -> ObjectDigest {
        self.revocation_head
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

/// Checks one complete parentless Create compiler draft against selected sources.
///
/// The returned digest records consistency only. Its source observation and
/// prerequisite heads can change immediately after this call. A publication
/// issuer must independently hold every writer behind a cross-service fence
/// through the binding CAS and effect handoff before treating it as authority.
///
/// # Errors
///
/// Returns [`CurrentCreatePolicySourceErrorV1::NotCurrent`] when the target,
/// signed project layer, publisher revision, claimed heads, deployment inputs,
/// or unsupported request/ancestor shape differs.
pub fn checked_parentless_create_policy_draft_v1(
    source: &CurrentCreateProjectPolicySourceV1,
    signed_project: &SignedProjectPolicySourceV1,
    deployment: &PolicyDeploymentSourcesV1,
    input: &PolicyCompilerInputV1,
    prerequisites: &PolicyPublicationPrerequisitesV1,
    now_unix_seconds: i64,
) -> Result<ObjectDigest, CurrentCreatePolicySourceErrorV1> {
    let project_head = signed_project.head();
    let claimed_heads = project_head.prerequisite_claims();
    if project_head.project() != source.project
        || project_head.publisher_generation() != source.policy_generation
        || project_head.publisher_digest() != source.policy_digest
        || now_unix_seconds >= project_head.expires_at()
        || claimed_heads
            != [
                prerequisites.ancestry_head(),
                prerequisites.compiler_authority_head(),
                prerequisites.cache_domain_head(),
                prerequisites.revocation_head(),
            ]
        || prerequisites.revocation_head() != source.revocation_head
        || prerequisites.cache_domain_head() != source.cache_domain_head
        || input.sandbox() != source.sandbox
        || input.project().project() != source.project
        || input.project().layer() != signed_project.layer()
        || input.node() != deployment.node()
        || input.site() != deployment.site()
        || input.backend() != deployment.backend()
        || !input.ancestors().is_empty()
        || !input.endpoints().entries().is_empty()
        || !input.destinations().entries().is_empty()
        || !request_is_inherited(input)
    {
        return Err(CurrentCreatePolicySourceErrorV1::NotCurrent);
    }

    let normalized_input = normalized_policy_input_digest_v1(input)
        .map_err(|_| CurrentCreatePolicySourceErrorV1::NotCurrent)?;
    Ok(ObjectDigest::from_bytes(
        Sha256::new()
            .chain_update(DRAFT_DOMAIN)
            .chain_update(source.commitment.as_bytes())
            .chain_update(project_head.packet_digest().as_bytes())
            .chain_update(project_head.input_digest().as_bytes())
            .chain_update(prerequisites.digest().as_bytes())
            .chain_update(normalized_input.as_bytes())
            .finalize()
            .into(),
    ))
}

fn request_is_inherited(input: &PolicyCompilerInputV1) -> bool {
    let layer = input.request().layer();
    layer.grants().is_empty()
        && layer.namespace_rules().is_empty()
        && layer.advisory_actions().is_empty()
        && matches!(layer.cache_domain(), CacheDomainInputV1::Inherit)
        && matches!(layer.revocation(), RevocationInputV1::Inherit)
        && layer
            .resources()
            .portable()
            .iter()
            .chain(layer.resources().accounting())
            .all(|limit| limit.value() == HardLimitValueV1::Inherit)
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
/// operation/projection/policy, missing project revocation binding, parented
/// Create, expired current policy, or noncanonical protected state.
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
    let (operation_revision, accepted_generation) =
        accepted_create_operation_revision(&public_operation, operation)?;

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

    let publisher = PublisherPolicyStore::load(journal, PublisherPolicyLimits::default())?;
    let revision = publisher
        .current_policy(project)?
        .ok_or(CurrentCreatePolicySourceErrorV1::NotCurrent)?;
    let revocation = publisher
        .project_revocation_head(project)?
        .ok_or(CurrentCreatePolicySourceErrorV1::NotCurrent)?;
    let cache_domain = publisher
        .project_cache_domain_head(project)?
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
    let cache_domain_head = cache_domain.digest();
    let cache_domain = cache_domain.domain();
    let revocation_scope = revocation.scope();
    let revocation_generation = revocation.generation();
    let revocation_head = revocation.digest();
    let canonical_policy = revision.canonical_policy().to_vec();
    let commitment = ObjectDigest::from_bytes(
        Sha256::new()
            .chain_update(SOURCE_DOMAIN)
            .chain_update(operation.as_bytes())
            .chain_update(operation_revision.as_bytes())
            .chain_update(accepted_generation.to_be_bytes())
            .chain_update(sandbox.as_bytes())
            .chain_update(project.as_bytes())
            .chain_update(projection_revision.as_bytes())
            .chain_update(policy_generation.to_be_bytes())
            .chain_update(policy_digest.as_bytes())
            .chain_update(cache_domain_head.as_bytes())
            .chain_update(revocation_scope.as_bytes())
            .chain_update(revocation_generation.to_be_bytes())
            .chain_update(revocation_head.as_bytes())
            .finalize()
            .into(),
    );
    Ok(CurrentCreateProjectPolicySourceV1 {
        operation,
        operation_revision,
        accepted_generation,
        sandbox,
        project,
        projection_revision,
        policy_generation,
        policy_digest,
        cache_domain,
        cache_domain_head,
        revocation_scope,
        revocation_generation,
        revocation_head,
        canonical_policy,
        commitment,
    })
}

fn accepted_create_operation_revision(
    public_operation: &Operation,
    operation: OperationId,
) -> Result<(ObjectDigest, u64), CurrentCreatePolicySourceErrorV1> {
    if public_operation.operation_id.as_slice() != operation.as_bytes()
        || public_operation.method != PublicOperationMethodV1::CreateSandbox.as_str()
        || public_operation.phase.as_known() != Some(OperationPhase::OPERATION_PHASE_ACCEPTED)
        || public_operation.accepted_generation == 0
    {
        return Err(CurrentCreatePolicySourceErrorV1::NotCurrent);
    }
    let revision: [u8; 32] = public_operation
        .resource_version
        .as_slice()
        .try_into()
        .map_err(|_| CurrentCreatePolicySourceErrorV1::NotCurrent)?;
    if revision == [0; 32] {
        return Err(CurrentCreatePolicySourceErrorV1::NotCurrent);
    }

    Ok((
        ObjectDigest::from_bytes(revision),
        public_operation.accepted_generation,
    ))
}

/// Holds the accepted Create and matching physical Cache partition for one action.
///
/// The controller writer must be acquired before the Cache owner. Both remain
/// held through the callback, and both are rechecked afterward. This still
/// cannot publish AOSPCB01: source-domain ancestry, root binding CAS, and
/// effect-handoff custody must join this same cut under a versioned record.
///
/// # Errors
///
/// Rejects a changed or non-accepted Create, changed publisher head, absent
/// physical partition, or mismatched project disclosure domain.
pub(crate) fn with_current_parentless_create_physical_cache_v1<R>(
    controller: &mut Journal,
    cache: &mut CacheResidencyProtectedOwnerV1,
    operation: OperationId,
    sandbox: SandboxId,
    action: impl FnOnce(&CurrentCreateProjectPolicySourceV1, CurrentProjectPhysicalCacheHeadV1) -> R,
) -> Result<R, CurrentCreatePolicySourceErrorV1> {
    let source = current_parentless_create_project_source_v1(controller, operation, sandbox)?;
    let joined = cache.while_current_project_physical_cache(source.project(), |physical| {
        if physical.project() != source.project()
            || physical.partition().disclosure() != source.cache_domain()
            || physical.head().as_bytes() == &[0; 32]
        {
            return Err(CurrentCreatePolicySourceErrorV1::NotCurrent);
        }

        let result = action(&source, physical);
        let current = current_parentless_create_project_source_v1(controller, operation, sandbox)?;
        if current.commitment() != source.commitment() {
            return Err(CurrentCreatePolicySourceErrorV1::NotCurrent);
        }

        Ok(result)
    })?;
    joined
}

/// Holds current Create, ancestry, and physical Cache sources for one inspection.
///
/// The caller must open and retain the controller writer, then source-domain
/// writer, then Cache writer; the callback may acquire the root policy writer
/// last. The callback must not perform an effect or publish AOSPCB02. It can
/// only prepare a candidate for a later root CAS and effect-handoff protocol.
/// Every local head is rechecked before the writer borrows are released.
///
/// # Errors
///
/// Rejects an absent, stale, or unhealthy owner head before or after the
/// callback. Errors from the callback remain its caller's responsibility.
pub fn with_current_create_policy_source_barrier_v2<R>(
    controller: &mut Journal,
    source_domains: &mut ProtectedSourceDomainJournalOwnerV1,
    cache: &mut CacheResidencyProtectedOwnerV1,
    operation: OperationId,
    sandbox: SandboxId,
    inspect: impl FnOnce(&CurrentCreateProjectPolicySourceV1, CurrentCreatePolicyBarrierHeadsV2) -> R,
) -> Result<R, CurrentCreatePolicySourceErrorV1> {
    controller.ensure_protected_authority()?;
    let hierarchy = HierarchyProtectedJournalOwnerV1::claim(source_domains)
        .map_err(CurrentCreatePolicySourceErrorV1::Hierarchy)?;

    let joined = with_current_parentless_create_physical_cache_v1(
        controller,
        cache,
        operation,
        sandbox,
        |source, physical| {
            let ancestry = hierarchy
                .project_ancestry_head(source.project())
                .map_err(CurrentCreatePolicySourceErrorV1::Hierarchy)?
                .ok_or(CurrentCreatePolicySourceErrorV1::NotCurrent)?
                .evidence()
                .head();
            let heads = CurrentCreatePolicyBarrierHeadsV2 {
                ancestry,
                physical_partition: physical.partition().digest(),
                physical_cache: physical.head(),
            };
            let result = inspect(source, heads);

            let current_ancestry = hierarchy
                .project_ancestry_head(source.project())
                .map_err(CurrentCreatePolicySourceErrorV1::Hierarchy)?
                .ok_or(CurrentCreatePolicySourceErrorV1::NotCurrent)?;
            if current_ancestry.evidence().head() != ancestry {
                return Err(CurrentCreatePolicySourceErrorV1::NotCurrent);
            }
            Ok(result)
        },
    )?;
    joined
}

#[cfg(test)]
mod tests {
    use aos_sandbox_core::model::{CacheDomainKind, LimitDimension};
    use aos_sandbox_core::{CacheDomainId, ObjectDescriptor, ResourceDimension};
    use ed25519_dalek::{Signer as _, SigningKey};

    use super::*;
    use crate::policy_compiler::{
        AuthenticatedEndpointCatalogV1, AuthenticatedNamespaceCatalogV1,
        AuthenticatedSandboxProjectRelationV1, ClosedPolicyRootCasBaseV2,
        EndpointCatalogVerifierV1, HardLimitRequestV1, HardResourceKeyV1, HardResourceProfileV1,
        NamespaceCatalogVerifierV1, PORTABLE_LIMIT_DIMENSIONS, PolicyCompilationError,
        PolicyCompilerLimitsV1, PolicyCompilerV1, PolicyDeploymentInputsV1, PolicyLayerV1,
        ProjectPolicyInputV1, RequestPolicyInputV1, SandboxProjectRelationVerifierV1,
        decode_policy_deployment_sources_v1, propose_closed_current_create_policy_binding_v2,
        verify_policy_deployment_head_v1, verify_signed_project_policy_source_v1,
    };

    struct FixtureVerifier;

    impl SandboxProjectRelationVerifierV1 for FixtureVerifier {
        fn verify(&self, _: SandboxId, _: ProjectId, _: &ObjectDescriptor, _: &[u8]) -> bool {
            true
        }
    }

    impl EndpointCatalogVerifierV1 for FixtureVerifier {
        fn verify(&self, _: &ObjectDescriptor, _: &[u8]) -> bool {
            true
        }
    }

    impl NamespaceCatalogVerifierV1 for FixtureVerifier {
        fn verify(&self, _: &ObjectDescriptor, _: &[u8]) -> bool {
            true
        }
    }

    fn inherited_layer() -> PolicyLayerV1 {
        let portable = PORTABLE_LIMIT_DIMENSIONS
            .into_iter()
            .map(|dimension| {
                HardLimitRequestV1::new(
                    HardResourceKeyV1::Portable(dimension),
                    HardLimitValueV1::Inherit,
                    None,
                )
                .expect("portable limit")
            })
            .collect();
        let accounting = ResourceDimension::ALL
            .into_iter()
            .map(|dimension| {
                HardLimitRequestV1::new(
                    HardResourceKeyV1::Accounting(dimension),
                    HardLimitValueV1::Inherit,
                    None,
                )
                .expect("accounting limit")
            })
            .collect();
        PolicyLayerV1::new(
            Vec::new(),
            HardResourceProfileV1::new(portable, accounting).expect("complete profile"),
            Vec::new(),
            Vec::new(),
            CacheDomainInputV1::Inherit,
            RevocationInputV1::Inherit,
        )
        .expect("inherited layer")
    }

    fn sign_packet(payload: &mut Vec<u8>, key: &SigningKey, domain: &[u8]) {
        let mut signed = domain.to_vec();
        signed.extend_from_slice(payload);
        payload.extend_from_slice(&key.sign(&signed).to_bytes());
    }

    #[test]
    fn accepted_create_selector_binds_exact_protected_operation_revision() {
        let operation = OperationId::from_bytes([1; 16]);
        let mut resource = Operation {
            operation_id: operation.as_bytes().to_vec(),
            resource_version: vec![2; 32],
            method: PublicOperationMethodV1::CreateSandbox.as_str().to_owned(),
            phase: OperationPhase::OPERATION_PHASE_ACCEPTED.into(),
            accepted_generation: 7,
            ..Default::default()
        };

        assert_eq!(
            accepted_create_operation_revision(&resource, operation).expect("accepted Create"),
            (ObjectDigest::from_bytes([2; 32]), 7)
        );

        resource.phase = OperationPhase::OPERATION_PHASE_PREPARING.into();
        assert!(accepted_create_operation_revision(&resource, operation).is_err());
        resource.phase = OperationPhase::OPERATION_PHASE_ACCEPTED.into();

        resource.operation_id = vec![3; 16];
        assert!(accepted_create_operation_revision(&resource, operation).is_err());
        resource.operation_id = operation.as_bytes().to_vec();

        resource.resource_version = vec![0; 32];
        assert!(accepted_create_operation_revision(&resource, operation).is_err());
        resource.resource_version = vec![2; 31];
        assert!(accepted_create_operation_revision(&resource, operation).is_err());
        resource.resource_version = vec![2; 32];

        resource.accepted_generation = 0;
        assert!(accepted_create_operation_revision(&resource, operation).is_err());
        resource.accepted_generation = 7;

        resource.method = PublicOperationMethodV1::DeleteSandbox.as_str().to_owned();
        assert!(accepted_create_operation_revision(&resource, operation).is_err());
    }

    #[test]
    fn checked_create_draft_binds_signed_source_and_exact_claims() {
        let project = ProjectId::from_bytes([3; 16]);
        let sandbox = SandboxId::from_bytes([4; 16]);
        let portable = PORTABLE_LIMIT_DIMENSIONS
            .map(|dimension| {
                let enforcement = match dimension {
                    LimitDimension::Bytes
                    | LimitDimension::Inodes
                    | LimitDimension::SnapshotCount => "zfs-quota",
                    LimitDimension::Processes
                    | LimitDimension::Memory
                    | LimitDimension::CpuWeight
                    | LimitDimension::CpuQuota
                    | LimitDimension::IoWeight
                    | LimitDimension::IoBandwidth => "cgroup-v2",
                    LimitDimension::OpenFiles => "combined-file-descriptor",
                    LimitDimension::FuseMemory => "combined-memory-accounting",
                    LimitDimension::CacheBytes => "node-bounded-shared-residency",
                    LimitDimension::MountCount
                    | LimitDimension::FuseRequests
                    | LimitDimension::ChildCount
                    | LimitDimension::ExecutionCount => "broker-ledger",
                };
                serde_json::json!({
                    "amount": 4096,
                    "enforcement": enforcement,
                    "kind": "bounded",
                })
            })
            .to_vec();
        let accounting = vec![
            serde_json::json!({
                "amount": 4096,
                "enforcement": "broker-ledger",
                "kind": "bounded",
            });
            ResourceDimension::COUNT
        ];

        let node = serde_json::to_vec(&serde_json::json!({
            "generation": 1, "input": {"portable": portable, "accounting": accounting},
            "magic": "AOSPNI01",
        }))
        .expect("node bytes");
        let site = String::from_utf8(node.clone())
            .expect("UTF-8")
            .replace("AOSPNI01", "AOSPSI01")
            .into_bytes();
        let backend = br#"{"generation":1,"input":{"enforcement":["cgroup-v2","broker-ledger","zfs-quota","node-bounded-shared-residency","combined-file-descriptor","combined-memory-accounting"]},"magic":"AOSPBI01"}"#;
        let catalogs =
            br#"{"generation":1,"input":{"destinations":[],"endpoints":[]},"magic":"AOSPCI01"}"#;
        let deployment_inputs = PolicyDeploymentInputsV1 {
            node: &node,
            site: &site,
            backend,
            catalogs,
        };
        let deployment_key = SigningKey::from_bytes(&[9; 32]);
        let mut deployment_packet = b"AOSPDH01".to_vec();
        deployment_packet.extend_from_slice(&1_u64.to_be_bytes());
        deployment_packet.extend_from_slice(&10_i64.to_be_bytes());
        deployment_packet.extend_from_slice(&30_i64.to_be_bytes());
        for bytes in [node.as_slice(), site.as_slice(), backend, catalogs] {
            deployment_packet.extend_from_slice(&Sha256::digest(bytes));
        }
        sign_packet(
            &mut deployment_packet,
            &deployment_key,
            b"aos.sandbox.policy-deployment-head.v1\0",
        );
        let deployment_head = verify_policy_deployment_head_v1(
            &deployment_packet,
            &deployment_inputs,
            &deployment_key.verifying_key(),
            20,
        )
        .expect("signed deployment");
        let deployment = decode_policy_deployment_sources_v1(&deployment_inputs, deployment_head)
            .expect("typed deployment");

        let project_input = serde_json::to_vec(&serde_json::json!({
            "generation": 1,
            "input": {
                "accounting": vec![serde_json::json!({"kind": "inherit"}); 22],
                "advisory_actions": [],
                "cache_domain": "inherit",
                "grants": [],
                "namespace_rules": [],
                "portable": vec![serde_json::json!({"kind": "inherit"}); 16],
                "revocation": "inherit",
            },
            "magic": "AOSPPL01",
            "project_id": project.to_string(),
        }))
        .expect("project bytes");
        let prerequisites = PolicyPublicationPrerequisitesV1::new(
            ObjectDigest::from_bytes([5; 32]),
            ObjectDigest::from_bytes(Sha256::digest(&deployment_packet).into()),
            ObjectDigest::from_bytes([7; 32]),
            ObjectDigest::from_bytes([8; 32]),
            1,
        )
        .expect("prerequisite tuple");
        let project_key = SigningKey::from_bytes(&[21; 32]);
        let mut project_packet = b"AOSPPH01".to_vec();
        project_packet.extend_from_slice(project.as_bytes());
        project_packet.extend_from_slice(&1_u64.to_be_bytes());
        project_packet.extend_from_slice(&10_i64.to_be_bytes());
        project_packet.extend_from_slice(&30_i64.to_be_bytes());
        project_packet.extend_from_slice(&2_u64.to_be_bytes());
        project_packet.extend_from_slice(&[6; 32]);
        project_packet.extend_from_slice(&Sha256::digest(&project_input));
        for head in [
            prerequisites.ancestry_head(),
            prerequisites.compiler_authority_head(),
            prerequisites.cache_domain_head(),
            prerequisites.revocation_head(),
        ] {
            project_packet.extend_from_slice(head.as_bytes());
        }
        sign_packet(
            &mut project_packet,
            &project_key,
            b"aos.sandbox.policy-project-head.v1\0",
        );
        let signed_project = verify_signed_project_policy_source_v1(
            &project_packet,
            &project_input,
            &project_key.verifying_key(),
            20,
        )
        .expect("signed project");

        let verifier = FixtureVerifier;
        let relation =
            AuthenticatedSandboxProjectRelationV1::authenticate(sandbox, project, &verifier)
                .expect("relation");
        let input = PolicyCompilerInputV1::new(
            relation,
            deployment.node().clone(),
            deployment.site().clone(),
            ProjectPolicyInputV1::new(project, signed_project.layer().clone())
                .expect("project layer"),
            Vec::new(),
            RequestPolicyInputV1::new(inherited_layer()).expect("request layer"),
            AuthenticatedEndpointCatalogV1::authenticate(Vec::new(), &verifier)
                .expect("endpoint catalog"),
            AuthenticatedNamespaceCatalogV1::authenticate(Vec::new(), &verifier)
                .expect("namespace catalog"),
            deployment.backend().clone(),
            PolicyCompilerLimitsV1::DEFAULT,
        )
        .expect("compiler input");
        let mut source = CurrentCreateProjectPolicySourceV1 {
            operation: OperationId::from_bytes([1; 16]),
            operation_revision: ObjectDigest::from_bytes([10; 32]),
            accepted_generation: 1,
            sandbox,
            project,
            projection_revision: ObjectDigest::from_bytes([2; 32]),
            policy_generation: 2,
            policy_digest: ObjectDigest::from_bytes([6; 32]),
            cache_domain: CacheDomain::new(
                CacheDomainKind::Project,
                CacheDomainId::from_bytes(*project.as_bytes()),
            ),
            cache_domain_head: prerequisites.cache_domain_head(),
            revocation_scope: RevocationScopeId::from_bytes([12; 16]),
            revocation_generation: 1,
            revocation_head: prerequisites.revocation_head(),
            canonical_policy: Vec::new(),
            commitment: ObjectDigest::from_bytes([9; 32]),
        };

        let draft = checked_parentless_create_policy_draft_v1(
            &source,
            &signed_project,
            &deployment,
            &input,
            &prerequisites,
            20,
        )
        .expect("matching draft");
        assert_ne!(draft.as_bytes(), &[0; 32]);

        let heads = CurrentCreatePolicyBarrierHeadsV2 {
            ancestry: prerequisites.ancestry_head(),
            physical_partition: ObjectDigest::from_bytes([22; 32]),
            physical_cache: ObjectDigest::from_bytes([23; 32]),
        };
        let root_base = ClosedPolicyRootCasBaseV2::from_untrusted_remote_fields(
            [24; 16],
            ObjectDigest::from_bytes([0; 32]),
            1,
            1,
            1,
        )
        .expect("canonical remote root base");
        // Every currently admitted v1 signed layer inherits both cross-cutting
        // choices. The closed producer must not invent either one from a
        // publisher descriptor or an untrusted request.
        assert!(matches!(
            PolicyCompilerV1::compile(input.clone()),
            Err(PolicyCompilationError::UnresolvedCacheDomain)
        ));
        assert!(
            propose_closed_current_create_policy_binding_v2(
                &source,
                heads,
                &signed_project,
                deployment_head,
                &deployment,
                &input,
                root_base,
                20,
            )
            .is_err()
        );

        let stale_heads = CurrentCreatePolicyBarrierHeadsV2 {
            ancestry: ObjectDigest::from_bytes([25; 32]),
            ..heads
        };
        assert!(
            propose_closed_current_create_policy_binding_v2(
                &source,
                stale_heads,
                &signed_project,
                deployment_head,
                &deployment,
                &input,
                root_base,
                20,
            )
            .is_err()
        );

        source.policy_generation += 1;
        assert!(
            checked_parentless_create_policy_draft_v1(
                &source,
                &signed_project,
                &deployment,
                &input,
                &prerequisites,
                20,
            )
            .is_err()
        );
        source.policy_generation -= 1;

        source.revocation_head = ObjectDigest::from_bytes([11; 32]);
        assert!(
            checked_parentless_create_policy_draft_v1(
                &source,
                &signed_project,
                &deployment,
                &input,
                &prerequisites,
                20,
            )
            .is_err()
        );
        source.revocation_head = prerequisites.revocation_head();

        source.cache_domain_head = ObjectDigest::from_bytes([11; 32]);
        assert!(
            checked_parentless_create_policy_draft_v1(
                &source,
                &signed_project,
                &deployment,
                &input,
                &prerequisites,
                20,
            )
            .is_err()
        );
        source.cache_domain_head = prerequisites.cache_domain_head();

        let stale_revocation_head = ObjectDigest::from_bytes([11; 32]);
        let stale_revocation = PolicyPublicationPrerequisitesV1::new(
            prerequisites.ancestry_head(),
            prerequisites.compiler_authority_head(),
            prerequisites.cache_domain_head(),
            stale_revocation_head,
            1,
        )
        .expect("changed revocation head");
        let mut stale_project_packet = project_packet[..248].to_vec();
        stale_project_packet[216..248].copy_from_slice(stale_revocation_head.as_bytes());
        sign_packet(
            &mut stale_project_packet,
            &project_key,
            b"aos.sandbox.policy-project-head.v1\0",
        );
        let stale_signed_project = verify_signed_project_policy_source_v1(
            &stale_project_packet,
            &project_input,
            &project_key.verifying_key(),
            20,
        )
        .expect("signed project with changed revocation claim");
        assert!(
            checked_parentless_create_policy_draft_v1(
                &source,
                &stale_signed_project,
                &deployment,
                &input,
                &stale_revocation,
                20,
            )
            .is_err()
        );

        let stale_cache = PolicyPublicationPrerequisitesV1::new(
            prerequisites.ancestry_head(),
            prerequisites.compiler_authority_head(),
            ObjectDigest::from_bytes([10; 32]),
            prerequisites.revocation_head(),
            1,
        )
        .expect("changed cache head");
        assert!(
            checked_parentless_create_policy_draft_v1(
                &source,
                &signed_project,
                &deployment,
                &input,
                &stale_cache,
                20,
            )
            .is_err()
        );
        assert!(
            checked_parentless_create_policy_draft_v1(
                &source,
                &signed_project,
                &deployment,
                &input,
                &prerequisites,
                30,
            )
            .is_err()
        );
    }
}
