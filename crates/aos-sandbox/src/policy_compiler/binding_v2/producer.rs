//! Non-authorizing AOSPCB02 proposal from one held Create/source/Cache cut.
//!
//! The caller retains all three protected writers while this function runs and
//! while the root service compares and commits the returned bytes. The root
//! base is only a proposal input; its own writer verifies it at CAS. This
//! producer never grants publication or an effect.

use aos_sandbox_core::ObjectDigest;
use sha2::{Digest as _, Sha256};

use super::{ClosedPolicyRootBindingV2, ClosedPolicyRootCasBaseV2};
use crate::policy_compiler::{
    CurrentCreatePolicyBarrierHeadsV2, CurrentCreateProjectPolicySourceV1,
    PolicyCompilerJournalErrorV1, PolicyDeploymentHeadV1, PolicyDeploymentSourcesV1,
    PolicyPublicationPrerequisitesV1, SignedProjectPolicySourceV1,
    VerifiedSignedProjectPolicySourceV2, checked_parentless_create_policy_draft_v1,
    checked_parentless_create_verified_policy_draft_v2, normalized_policy_input_digest_v1,
};
use aos_sandbox_policy::{PolicyCompilerInputV1, PolicyCompilerV1};

const BARRIER_DOMAIN: &[u8] = b"aos.sandbox.policy-compiler.held-cut.v2\0";
const EFFECT_TRANSACTION_DOMAIN: &[u8] = b"aos.sandbox.policy-compiler.closed-handoff.v2\0";

/// Builds one exact closed proposal from a currently held owner cut.
///
/// The signed project claims must equal the independent ancestry, publisher,
/// cache-domain, revocation, and deployment heads. The compiler candidate and
/// normalized input are computed here, not accepted from a request. The root
/// service must still compare the signer generations and root predecessor
/// under its own writer. The returned bytes confer no publication authority.
///
/// # Errors
///
/// Rejects stale or mismatched signed sources, an unsupported compiler input,
/// a failed deterministic compilation, or a malformed root CAS base.
#[allow(clippy::too_many_arguments)]
pub fn propose_closed_current_create_policy_binding_v2(
    source: &CurrentCreateProjectPolicySourceV1,
    heads: CurrentCreatePolicyBarrierHeadsV2,
    signed_project: &SignedProjectPolicySourceV1,
    deployment_head: PolicyDeploymentHeadV1,
    deployment: &PolicyDeploymentSourcesV1,
    input: &PolicyCompilerInputV1,
    root_base: ClosedPolicyRootCasBaseV2,
    now_unix_seconds: i64,
) -> Result<Vec<u8>, PolicyCompilerJournalErrorV1> {
    if now_unix_seconds >= deployment_head.expires_at() {
        return Err(PolicyCompilerJournalErrorV1::UnauthenticatedCandidate);
    }
    let prerequisites = PolicyPublicationPrerequisitesV1::new(
        heads.ancestry(),
        deployment_head.packet_digest(),
        source.cache_domain_head(),
        source.revocation_head(),
        root_base.next_generation(),
    )?;
    let checked_draft = checked_parentless_create_policy_draft_v1(
        source,
        signed_project,
        deployment,
        input,
        &prerequisites,
        now_unix_seconds,
    )
    .map_err(|_| PolicyCompilerJournalErrorV1::UnauthenticatedCandidate)?;

    encode_closed_proposal(
        source,
        heads,
        signed_project.head().packet_digest(),
        signed_project.head().input_digest(),
        deployment_head,
        input,
        root_base,
        checked_draft,
    )
}

/// Builds one inert AOSPCB02 proposal from a verified explicit V2 source.
///
/// The source is not independently admitted by this function. The caller
/// must hold the controller, source-domain, and Cache writers, then root must
/// compare the exact V2 packet/input and signer pins under its own writer.
/// This proposal still grants no publication or effect authority.
///
/// # Errors
///
/// Rejects mismatched V2 signer generations, stale signed/current heads,
/// substituted compiler input, or failed deterministic compilation.
#[allow(clippy::too_many_arguments)]
pub fn propose_closed_current_create_explicit_policy_binding_v2(
    source: &CurrentCreateProjectPolicySourceV1,
    heads: CurrentCreatePolicyBarrierHeadsV2,
    signed_project: &VerifiedSignedProjectPolicySourceV2,
    deployment_head: PolicyDeploymentHeadV1,
    deployment: &PolicyDeploymentSourcesV1,
    input: &PolicyCompilerInputV1,
    root_base: ClosedPolicyRootCasBaseV2,
    now_unix_seconds: i64,
) -> Result<Vec<u8>, PolicyCompilerJournalErrorV1> {
    let project_head = signed_project.head();
    if now_unix_seconds >= deployment_head.expires_at()
        || project_head.deployment_signer_generation() != root_base.deployment_signer_generation()
        || project_head.project_signer_generation() != root_base.project_signer_generation()
    {
        return Err(PolicyCompilerJournalErrorV1::UnauthenticatedCandidate);
    }
    let prerequisites = PolicyPublicationPrerequisitesV1::new(
        heads.ancestry(),
        deployment_head.packet_digest(),
        source.cache_domain_head(),
        source.revocation_head(),
        root_base.next_generation(),
    )?;
    let checked_draft = checked_parentless_create_verified_policy_draft_v2(
        source,
        signed_project,
        deployment,
        input,
        &prerequisites,
        now_unix_seconds,
    )
    .map_err(|_| PolicyCompilerJournalErrorV1::UnauthenticatedCandidate)?;

    encode_closed_proposal(
        source,
        heads,
        project_head.packet_digest(),
        project_head.input_digest(),
        deployment_head,
        input,
        root_base,
        checked_draft,
    )
}

// This borrowed view contains only comparison fields already selected by a
// caller's real owner engine. It is not a Controller source, brand or permission
// to publish. Root constructs it only after its independent original-cut join.
pub(in crate::policy_compiler) struct ClosedCreateProposalFieldViewV2<'cut> {
    pub(in crate::policy_compiler) source_commitment: &'cut ObjectDigest,
    pub(in crate::policy_compiler) operation: &'cut aos_sandbox_core::OperationId,
    pub(in crate::policy_compiler) operation_revision: &'cut ObjectDigest,
    pub(in crate::policy_compiler) accepted_generation: &'cut u64,
    pub(in crate::policy_compiler) sandbox: &'cut aos_sandbox_core::SandboxId,
    pub(in crate::policy_compiler) project: &'cut aos_sandbox_core::ProjectId,
    pub(in crate::policy_compiler) projection_revision: &'cut ObjectDigest,
    pub(in crate::policy_compiler) publisher_generation: &'cut u64,
    pub(in crate::policy_compiler) publisher_head: &'cut ObjectDigest,
    pub(in crate::policy_compiler) cache_domain_head: &'cut ObjectDigest,
    pub(in crate::policy_compiler) revocation_head: &'cut ObjectDigest,
    pub(in crate::policy_compiler) ancestry: &'cut ObjectDigest,
    pub(in crate::policy_compiler) physical_partition: &'cut ObjectDigest,
    pub(in crate::policy_compiler) physical_cache: &'cut ObjectDigest,
}

#[allow(clippy::too_many_arguments)]
fn encode_closed_proposal(
    source: &CurrentCreateProjectPolicySourceV1,
    heads: CurrentCreatePolicyBarrierHeadsV2,
    project_packet: ObjectDigest,
    project_input: ObjectDigest,
    deployment_head: PolicyDeploymentHeadV1,
    input: &PolicyCompilerInputV1,
    root_base: ClosedPolicyRootCasBaseV2,
    checked_draft: ObjectDigest,
) -> Result<Vec<u8>, PolicyCompilerJournalErrorV1> {
    let normalized_input = normalized_policy_input_digest_v1(input)?;
    let candidate = PolicyCompilerV1::compile(input.clone())
        .map_err(|_| PolicyCompilerJournalErrorV1::UnauthenticatedCandidate)?
        .commitment()
        .digest();

    // No allocation, check, effect or user-defined drop is introduced here.
    // The old source and held-head getters supply the same encoder fields.
    let source_commitment = source.commitment();
    let operation = source.operation();
    let operation_revision = source.operation_revision();
    let accepted_generation = source.accepted_generation();
    let sandbox = source.sandbox();
    let project = source.project();
    let projection_revision = source.projection_revision();
    let publisher_generation = source.policy_generation();
    let publisher_head = source.policy_digest();
    let cache_domain_head = source.cache_domain_head();
    let revocation_head = source.revocation_head();
    let ancestry = heads.ancestry();
    let physical_partition = heads.physical_partition();
    let physical_cache = heads.physical_cache();
    let fields = ClosedCreateProposalFieldViewV2 {
        source_commitment: &source_commitment,
        operation: &operation,
        operation_revision: &operation_revision,
        accepted_generation: &accepted_generation,
        sandbox: &sandbox,
        project: &project,
        projection_revision: &projection_revision,
        publisher_generation: &publisher_generation,
        publisher_head: &publisher_head,
        cache_domain_head: &cache_domain_head,
        revocation_head: &revocation_head,
        ancestry: &ancestry,
        physical_partition: &physical_partition,
        physical_cache: &physical_cache,
    };
    encode_closed_proposal_fields(
        &fields, project_packet, project_input, deployment_head,
        normalized_input, candidate, root_base, checked_draft,
    )
}

// Q04 may borrow its already compiled candidate/input commitments here only
// after its actual Root/current-owner verifier rechecks the full original cut.
// This sole serializer/barrier/effect recipe remains comparison DATA.
#[allow(clippy::too_many_arguments)]
pub(in crate::policy_compiler) fn encode_closed_proposal_fields(
    fields: &ClosedCreateProposalFieldViewV2<'_>,
    project_packet: ObjectDigest,
    project_input: ObjectDigest,
    deployment_head: PolicyDeploymentHeadV1,
    normalized_input: ObjectDigest,
    candidate: ObjectDigest,
    root_base: ClosedPolicyRootCasBaseV2,
    checked_draft: ObjectDigest,
) -> Result<Vec<u8>, PolicyCompilerJournalErrorV1> {
    let barrier_head = ObjectDigest::from_bytes(
        Sha256::new()
            .chain_update(BARRIER_DOMAIN)
            .chain_update(fields.source_commitment.as_bytes())
            .chain_update(checked_draft.as_bytes())
            .chain_update(fields.ancestry.as_bytes())
            .chain_update(fields.physical_partition.as_bytes())
            .chain_update(fields.physical_cache.as_bytes())
            .chain_update(project_packet.as_bytes())
            .chain_update(deployment_head.packet_digest().as_bytes())
            .chain_update(normalized_input.as_bytes())
            .chain_update(candidate.as_bytes())
            .chain_update(root_base.predecessor().as_bytes())
            .chain_update(root_base.next_generation().to_be_bytes())
            .finalize()
            .into(),
    );
    // The effect ID is deterministic across a lost response. A second root
    // generation cannot reuse it for the same accepted Create.
    let effect_digest = Sha256::new()
        .chain_update(EFFECT_TRANSACTION_DOMAIN)
        .chain_update(fields.operation.as_bytes())
        .chain_update(fields.operation_revision.as_bytes())
        .chain_update(normalized_input.as_bytes())
        .chain_update(candidate.as_bytes())
        .finalize();
    let effect_transaction: [u8; 16] = effect_digest[..16]
        .try_into()
        .map_err(|_| PolicyCompilerJournalErrorV1::UnauthenticatedCandidate)?;

    ClosedPolicyRootBindingV2 {
        issuer_owner: root_base.issuer_owner(),
        project: *fields.project,
        sandbox: *fields.sandbox,
        operation: *fields.operation,
        operation_revision: *fields.operation_revision,
        accepted_generation: *fields.accepted_generation,
        projection_revision: *fields.projection_revision,
        publisher_generation: *fields.publisher_generation,
        publisher_head: *fields.publisher_head,
        project_policy_head: project_packet,
        project_policy_input: project_input,
        ancestry_head: *fields.ancestry,
        compiler_head: deployment_head.packet_digest(),
        cache_domain_head: *fields.cache_domain_head,
        revocation_head: *fields.revocation_head,
        physical_partition: *fields.physical_partition,
        physical_cache_head: *fields.physical_cache,
        normalized_input,
        candidate,
        project_signer_generation: root_base.project_signer_generation(),
        deployment_signer_generation: root_base.deployment_signer_generation(),
        barrier_epoch: root_base.next_generation(),
        barrier_head,
        root_predecessor: root_base.predecessor(),
        root_generation: root_base.next_generation(),
        effect_transaction,
        handoff_epoch: root_base.next_generation(),
    }
    .encode()
}
