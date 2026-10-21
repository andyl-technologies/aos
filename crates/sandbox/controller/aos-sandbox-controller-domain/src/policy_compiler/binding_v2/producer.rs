//! Non-authorizing AOSPCB02 proposal from one held Create/source/Cache cut.
//!
//! The caller retains all three protected writers while this function runs and
//! while the root service compares and commits the returned bytes. The root
//! base is only a proposal input; its own writer verifies it at CAS. This
//! producer never grants publication or an effect.

use aos_sandbox_policy::signed_inputs::{
    PolicyDeploymentHeadV1, PolicyDeploymentSourcesV1, VerifiedSignedProjectPolicySourceV2,
};

use aos_sandbox_model::ObjectDigest;
use sha2::{Digest as _, Sha256};

use super::{ClosedPolicyRootBindingV2, ClosedPolicyRootCasBaseV2};
use crate::policy_compiler::{
    CurrentCreatePolicyBarrierHeadsV2, CurrentCreateProjectPolicySourceV1,
    PolicyCompilerJournalErrorV1, PolicyPublicationPrerequisitesV1,
    checked_parentless_create_verified_policy_draft_v2, normalized_policy_input_digest_v1,
};
use aos_sandbox_policy::{PolicyCompilerInputV1, PolicyCompilerV1};

const BARRIER_DOMAIN: &[u8] = b"aos.sandbox.policy-compiler.held-cut.v2\0";
const EFFECT_TRANSACTION_DOMAIN: &[u8] = b"aos.sandbox.policy-compiler.closed-handoff.v2\0";

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

use aos_sandbox_policy::q04_data::{
    ClosedCreateProposalFieldViewV2, encode_closed_proposal_fields,
};

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
    let normalized_input = normalized_policy_input_digest_v1(input)
        .map_err(|_| PolicyCompilerJournalErrorV1::NonCanonicalPublication)?;
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
        &fields,
        project_packet,
        project_input,
        deployment_head,
        normalized_input,
        candidate,
        root_base,
        checked_draft,
    )
    .map_err(Into::into)
}
