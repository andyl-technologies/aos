//! Owns native compiled-revision preparation and Publisher store publication.
//!
//! Only the real compiler producer constructs [`CompiledPublisherPolicyRevisionV2`].
//! The lower Policy owner supplies bounded canonical revision and retained-origin
//! DATA. Cold decoding preserves bytes and commitments without reconstructing
//! authenticated model constructors; comparison requires independently typed
//! original inputs and their original target.
//!
//! The native producer retains its sealed wrapper and complete record ceiling.
//! Publication still uses the existing protected Publisher store's trusted
//! Controller contract; neither DATA consistency nor this wrapper alone proves
//! independently current inputs, publication authority or an effect handoff.

use crate::CommitResult;
use crate::publisher_policy::{PublisherPolicyError, PublisherPolicyStore};
use aos_sandbox_core::DecodeLimits;
use aos_sandbox_policy::{
    PolicyCompilerInputV1, PolicyCompilerV1, PreparedPublisherPolicyRevisionV1,
    RetainedPublisherCompilerOriginV3, retain_publisher_compiler_derivation_v3,
};

// Existing native whole-revision bound, not extra journal capacity.
const MAXIMUM_BYTES: usize = 4 * 1024 * 1024;

/// Retains a prepared publisher revision produced only by real compilation.
pub struct CompiledPublisherPolicyRevisionV2 {
    revision: PreparedPublisherPolicyRevisionV1,
}

impl CompiledPublisherPolicyRevisionV2 {
    /// Returns the exact resolved policy revision and retained provenance data.
    #[must_use]
    pub const fn revision(&self) -> &PreparedPublisherPolicyRevisionV1 {
        &self.revision
    }
}

/// Compiles an explicit parentless original input and prepares its V2 revision.
///
/// No layer is inferred from resolved Policy or user data. Existing constructors
/// and the full compiler own normalization, six layer fields, complete resource
/// ceilings, and grant intersection. The result is still nonauthoritative until
/// genuine independent owners and the protected publication barrier qualify it.
///
/// # Errors
///
/// Rejects a nonparentless input, compile failure, invalid revision, or an
/// encoded revision exceeding the unchanged publisher record limit.
pub fn compile_publisher_policy_revision_v2(
    input: &PolicyCompilerInputV1,
    generation: u64,
    not_before: i64,
    expires_at: i64,
) -> Result<CompiledPublisherPolicyRevisionV2, PublisherPolicyError> {
    let origin = derive_origin(input)?;
    let origin_bytes = origin
        .to_record_bytes()
        .map_err(PublisherPolicyError::from)?
        .len();
    let mut revision = PreparedPublisherPolicyRevisionV1::from_canonical_bytes(
        origin.project(),
        generation,
        not_before,
        expires_at,
        origin.output_bytes()[0],
        DecodeLimits::default(),
    )
    .map_err(PublisherPolicyError::from)?;
    revision
        .retain_compiler_origin(origin)
        .map_err(PublisherPolicyError::from)?;
    // Account for policy bytes, origin bytes, framing, and the existing header.
    let size = 88usize
        .checked_add(revision.canonical_policy().len())
        .and_then(|size| size.checked_add(origin_bytes))
        .ok_or(PublisherPolicyError::LimitExceeded("policy revision bytes"))?;
    if size > MAXIMUM_BYTES + 128 {
        return Err(PublisherPolicyError::LimitExceeded("policy revision bytes"));
    }
    Ok(CompiledPublisherPolicyRevisionV2 { revision })
}

impl PublisherPolicyStore<'_> {
    /// Publishes actual compiler provenance in the existing revision/head CAS.
    ///
    /// This retains the trusted Controller administration contract of the V1
    /// store. It adds no installed input-owner or public Create authority.
    ///
    /// # Errors
    ///
    /// Rejects CAS, resource cross-link, capacity, protection, or commit errors
    /// exactly as the existing publisher revision transaction does.
    pub fn publish_compiled_policy_from_trusted_controller_v2(
        &mut self,
        transaction_id: [u8; 16],
        expected_generation: Option<u64>,
        prepared: &CompiledPublisherPolicyRevisionV2,
    ) -> Result<CommitResult, PublisherPolicyError> {
        self.publish_policy_from_trusted_controller(
            transaction_id,
            expected_generation,
            prepared.revision(),
        )
    }
}

fn derive_origin(
    input: &PolicyCompilerInputV1,
) -> Result<RetainedPublisherCompilerOriginV3, PublisherPolicyError> {
    if !input.ancestors().is_empty() {
        return Err(PublisherPolicyError::InvalidPolicyRevision);
    }
    let candidate = PolicyCompilerV1::compile_retained(input)
        .map_err(|_| PublisherPolicyError::InvalidPolicyRevision)?;
    retain_publisher_compiler_derivation_v3(input, &candidate).map_err(PublisherPolicyError::from)
}
