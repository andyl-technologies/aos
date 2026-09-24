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

use super::{
    CacheDomainInputV1, HardLimitValueV1, PolicyCompilerInputV1, PolicyDeploymentSourcesV1,
    PolicyPublicationPrerequisitesV1, RevocationInputV1, SignedProjectPolicySourceV1,
    normalized_policy_input_digest_v1,
};

const SOURCE_DOMAIN: &[u8] = b"aos.sandbox.public-create-project-source.v1\0";
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

#[cfg(test)]
mod tests {
    use aos_sandbox_core::{ObjectDescriptor, ResourceDimension};
    use ed25519_dalek::{Signer as _, SigningKey};

    use super::*;
    use crate::policy_compiler::{
        AuthenticatedEndpointCatalogV1, AuthenticatedNamespaceCatalogV1,
        AuthenticatedSandboxProjectRelationV1, EndpointCatalogVerifierV1, HardLimitRequestV1,
        HardResourceKeyV1, HardResourceProfileV1, NamespaceCatalogVerifierV1,
        PORTABLE_LIMIT_DIMENSIONS, PolicyCompilerLimitsV1, PolicyDeploymentInputsV1, PolicyLayerV1,
        ProjectPolicyInputV1, RequestPolicyInputV1, SandboxProjectRelationVerifierV1,
        decode_policy_deployment_sources_v1, verify_policy_deployment_head_v1,
        verify_signed_project_policy_source_v1,
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
    fn checked_create_draft_binds_signed_source_and_exact_claims() {
        let project = ProjectId::from_bytes([3; 16]);
        let sandbox = SandboxId::from_bytes([4; 16]);
        let inherit = serde_json::json!({"kind": "inherit"});
        let portable = vec![inherit.clone(); 16];
        let accounting = vec![inherit; 22];

        let node = serde_json::to_vec(&serde_json::json!({
            "generation": 1, "input": {"portable": portable, "accounting": accounting},
            "magic": "AOSPNI01",
        }))
        .expect("node bytes");
        let site = String::from_utf8(node.clone())
            .expect("UTF-8")
            .replace("AOSPNI01", "AOSPSI01")
            .into_bytes();
        let backend = br#"{"generation":1,"input":{"enforcement":[]},"magic":"AOSPBI01"}"#;
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
            sandbox,
            project,
            projection_revision: ObjectDigest::from_bytes([2; 32]),
            policy_generation: 2,
            policy_digest: ObjectDigest::from_bytes([6; 32]),
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
