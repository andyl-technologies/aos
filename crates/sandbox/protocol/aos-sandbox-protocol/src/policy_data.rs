//! Owns canonical publisher and compiler-commitment consistency DATA.
//!
//! Publisher revisions and AOSPCO03 provenance retain exact bounded bytes and
//! links. The canonical compiler transcript retains its existing JSON framing
//! and digest domains. None authenticates compiler inputs, native custody,
//! protected currentness, publication, or effect authority.

mod canonical;
mod publisher_revision;

/// Owns canonical Root binding-chain, hold and qualified-proof comparison DATA.
pub mod binding_v2;

/// Owns canonical saved Policy public signer-pin tuple DATA.
pub mod signer_pins;

pub use canonical::{
    MAXIMUM_CANONICAL_OBJECT_BYTES, PolicyCanonicalDataErrorV1, canonical_bytes,
    canonical_json_decode_error_receiving_bytes_v1, canonical_payload_count_control_bytes_v1, canonical_model_receiving_bytes_v1, canonical_serialization_failure_backing_bytes_v1, canonical_payload_size_v1,
    compiled_policy_candidate_digest_v1, digest,
};
pub use publisher_revision::{
    PreparedPublisherPolicyRevisionV1, PublisherPolicyDataError, RetainedPublisherCompilerOriginV3,
};

/// Hashes a supplied project revocation head without establishing currentness.
pub fn project_revocation_digest(
    project: aos_sandbox_model::ProjectId,
    scope: aos_sandbox_model::RevocationScopeId,
    generation: u64,
) -> aos_sandbox_model::ObjectDigest {
    use sha2::Digest as _;

    aos_sandbox_model::ObjectDigest::from_bytes(
        sha2::Sha256::new()
            .chain_update(b"aos.sandbox.publisher-project-revocation-head.v1\0")
            .chain_update(project.as_bytes())
            .chain_update(scope.as_bytes())
            .chain_update(generation.to_be_bytes())
            .finalize()
            .into(),
    )
}
