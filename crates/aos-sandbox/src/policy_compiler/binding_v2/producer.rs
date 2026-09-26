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
    CurrentCreatePolicyBarrierHeadsV2, CurrentCreateProjectPolicySourceV1, PolicyCompilerInputV1,
    PolicyCompilerJournalErrorV1, PolicyCompilerV1, PolicyDeploymentHeadV1,
    PolicyDeploymentSourcesV1, PolicyPublicationPrerequisitesV1, SignedProjectPolicySourceV1,
    VerifiedSignedProjectPolicySourceV2, checked_parentless_create_policy_draft_v1,
    checked_parentless_create_verified_policy_draft_v2, normalized_policy_input_digest_v1,
};

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
    let barrier_head = ObjectDigest::from_bytes(
        Sha256::new()
            .chain_update(BARRIER_DOMAIN)
            .chain_update(source.commitment().as_bytes())
            .chain_update(checked_draft.as_bytes())
            .chain_update(heads.ancestry().as_bytes())
            .chain_update(heads.physical_partition().as_bytes())
            .chain_update(heads.physical_cache().as_bytes())
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
        .chain_update(source.operation().as_bytes())
        .chain_update(source.operation_revision().as_bytes())
        .chain_update(normalized_input.as_bytes())
        .chain_update(candidate.as_bytes())
        .finalize();
    let effect_transaction: [u8; 16] = effect_digest[..16]
        .try_into()
        .map_err(|_| PolicyCompilerJournalErrorV1::UnauthenticatedCandidate)?;

    ClosedPolicyRootBindingV2 {
        issuer_owner: root_base.issuer_owner(),
        project: source.project(),
        sandbox: source.sandbox(),
        operation: source.operation(),
        operation_revision: source.operation_revision(),
        accepted_generation: source.accepted_generation(),
        projection_revision: source.projection_revision(),
        publisher_generation: source.policy_generation(),
        publisher_head: source.policy_digest(),
        project_policy_head: project_packet,
        project_policy_input: project_input,
        ancestry_head: heads.ancestry(),
        compiler_head: deployment_head.packet_digest(),
        cache_domain_head: source.cache_domain_head(),
        revocation_head: source.revocation_head(),
        physical_partition: heads.physical_partition(),
        physical_cache_head: heads.physical_cache(),
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
