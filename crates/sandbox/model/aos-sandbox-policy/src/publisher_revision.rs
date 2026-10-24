//! Qualifies retained compiler provenance against independently typed inputs.
//!
//! Canonical publisher revisions, origin framing and byte-link validation live
//! in Protocol's `policy_data`. This module owns the real compiler comparison
//! and normalized typed-input transcript; neither supplies current authority.

use crate::{CompiledPolicyCandidateV1, PolicyCompilerInputV1, PolicyCompilerV1};
use aos_sandbox_model::{ObjectDescriptor, ObjectDigest};
use aos_sandbox_protocol::policy_data::{
    PublisherPolicyDataError, RetainedPublisherCompilerOriginV3, canonical_bytes,
};
use sha2::{Digest as _, Sha256};

const INPUT_DOMAIN: &[u8] = b"aos.sandbox.publisher-original-compiler-input.v3";

/// Reports an invalid canonical normalized-input transcript.
///
/// The transcript rejects sentinel identities or descriptors, zero encoded
/// sizes and a rule count that cannot be represented by its u64 field. This
/// error conveys no protected currentness or compiler-publication authority.
#[derive(Debug, thiserror::Error)]
#[error("compiled policy publication is noncanonical")]
pub struct NormalizedPolicyInputErrorV1;

/// Checks derivation using the real compiler and independently typed inputs.
///
/// This never decodes retained JSON into authenticated models. A caller
/// must separately establish current/historical input owner custody. The
/// original target is mandatory even when a later Create selects another
/// child. Successful equality is derivation/provenance, not effect authority.
///
/// # Errors
///
/// Rejects substituted targets, any of the six layer fields, incomplete
/// 16/22 resource profiles, input commitments, outputs, or failed compile.
pub fn verify_publisher_compiler_derivation_v3(
    origin: &RetainedPublisherCompilerOriginV3,
    expected: &PolicyCompilerInputV1,
) -> Result<(), PublisherPolicyDataError> {
    if expected.project().project() != origin.project()
        || expected.sandbox() != origin.original_target()
        || !expected.ancestors().is_empty()
    {
        return Err(PublisherPolicyDataError::InvalidPolicyRevision);
    }
    let candidate = PolicyCompilerV1::compile_retained(expected)
        .map_err(|_| PublisherPolicyDataError::InvalidPolicyRevision)?;
    compare_publisher_compiler_derivation_v3(origin, expected, &candidate)
}

/// Compares complete retained provenance to an independently typed candidate.
///
/// This reuses the supplied candidate instead of compiling again. Callers
/// must establish its genuine input and currentness custody separately;
/// equality does not grant a resource read or publication authority.
///
/// # Errors
///
/// Rejects nonparentless input, invalid normalized or serialized input,
/// invalid output links or oversized origin data, and any difference in
/// the complete freshly retained value, including original target and bytes.
pub fn compare_publisher_compiler_derivation_v3(
    origin: &RetainedPublisherCompilerOriginV3,
    expected: &PolicyCompilerInputV1,
    candidate: &CompiledPolicyCandidateV1,
) -> Result<(), PublisherPolicyDataError> {
    let derived = retain_publisher_compiler_derivation_v3(expected, candidate)?;
    if &derived != origin {
        return Err(PublisherPolicyDataError::InvalidPolicyRevision);
    }
    Ok(())
}

/// Retains checked original input bytes and one candidate's complete outputs.
///
/// The recipe records normalized input, canonical full-input JSON, the project
/// and request layers, all four outputs and five plan commitments, then validates
/// the whole bounded record. It does not authenticate its supplied inputs or
/// construct a native compiled revision, protected admission or currentness loan.
///
/// # Errors
///
/// Rejects nonparentless input, invalid normalized input, failed canonical input
/// serialization, inconsistent output links, or an oversized retained record.
pub fn retain_publisher_compiler_derivation_v3(
    input: &PolicyCompilerInputV1,
    candidate: &CompiledPolicyCandidateV1,
) -> Result<RetainedPublisherCompilerOriginV3, PublisherPolicyDataError> {
    if !input.ancestors().is_empty() {
        return Err(PublisherPolicyDataError::InvalidPolicyRevision);
    }
    let normalized_input = normalized_policy_input_digest_v1(input)
        .map_err(|_| PublisherPolicyDataError::InvalidPolicyRevision)?;
    let full_input = canonical_bytes(INPUT_DOMAIN, input)
        .map_err(crate::PolicyModelError::from)
        .map_err(|_| PublisherPolicyDataError::InvalidPolicyRevision)?;
    let output = candidate.portable();
    RetainedPublisherCompilerOriginV3::from_parts_v3(
        input.project().project(),
        input.sandbox(),
        normalized_input,
        candidate.commitment().digest(),
        candidate.commitment_plan_digests(),
        [
            full_input,
            input.project().canonical_bytes().to_vec(),
            input.request().canonical_bytes().to_vec(),
            output.policy_bytes().to_vec(),
            output.optimization_bytes().to_vec(),
            output.namespace_graph_bytes().to_vec(),
            output.advisory_program_bytes().to_vec(),
        ],
    )
}

const NORMALIZED_INPUT_DOMAIN: &[u8] = b"aos.sandbox.policy-compiler.normalized-input.v1\0";

/// Computes the canonical normalized-input digest used by publication checks.
///
/// # Errors
///
/// Returns [`NormalizedPolicyInputErrorV1`] for sentinel project or target IDs,
/// a descriptor with a zero digest or encoded size, or a rule count that cannot
/// fit its u64 transcript field. Hashing establishes a commitment, not authority.
pub fn normalized_policy_input_digest_v1(
    input: &PolicyCompilerInputV1,
) -> Result<ObjectDigest, NormalizedPolicyInputErrorV1> {
    if input.sandbox().as_bytes() == &[0; 16] || input.project().project().as_bytes() == &[0; 16] {
        return Err(NormalizedPolicyInputErrorV1);
    }
    let mut hasher = Sha256::new();
    hasher.update(NORMALIZED_INPUT_DOMAIN);
    hasher.update(input.sandbox().as_bytes());
    hasher.update(input.project().project().as_bytes());
    update_descriptor(&mut hasher, input.relation().descriptor())?;
    update_descriptor(&mut hasher, input.node().descriptor())?;
    update_descriptor(&mut hasher, input.site().descriptor())?;
    update_descriptor(&mut hasher, input.project().descriptor())?;
    for ancestor in input.ancestors() {
        update_descriptor(&mut hasher, ancestor.descriptor())?;
    }
    update_descriptor(&mut hasher, input.request().descriptor())?;
    update_descriptor(&mut hasher, input.endpoints().descriptor())?;
    update_descriptor(&mut hasher, input.destinations().descriptor())?;
    update_descriptor(&mut hasher, input.backend().descriptor())?;
    hasher.update(input.limits().work().to_be_bytes());
    hasher.update(input.limits().dag_depth().to_be_bytes());
    let rule_limit =
        u64::try_from(input.limits().rules()).map_err(|_| NormalizedPolicyInputErrorV1)?;
    hasher.update(rule_limit.to_be_bytes());
    Ok(ObjectDigest::from_bytes(hasher.finalize().into()))
}

fn update_descriptor(
    hasher: &mut Sha256,
    descriptor: &ObjectDescriptor,
) -> Result<(), NormalizedPolicyInputErrorV1> {
    if descriptor.digest().as_bytes() == &[0; 32] || descriptor.encoded_size() == 0 {
        return Err(NormalizedPolicyInputErrorV1);
    }
    hasher.update((descriptor.media_type().as_str().len() as u64).to_be_bytes());
    hasher.update(descriptor.media_type().as_str().as_bytes());
    hasher.update(descriptor.digest().as_bytes());
    hasher.update(descriptor.encoded_size().to_be_bytes());
    Ok(())
}
