//! Owns canonical publisher and compiler-commitment consistency DATA.
//!
//! Publisher revisions and AOSPCO03 provenance retain exact bounded bytes and
//! links. The canonical compiler transcript retains its existing JSON framing
//! and digest domains. None authenticates compiler inputs, native custody,
//! protected currentness, publication, or effect authority.

mod canonical;
mod publisher_revision;

pub use canonical::{
    MAXIMUM_CANONICAL_OBJECT_BYTES, PolicyCanonicalDataErrorV1, canonical_bytes,
    canonical_payload_size_v1, compiled_policy_candidate_digest_v1, digest,
};
pub use publisher_revision::{
    PreparedPublisherPolicyRevisionV1, PublisherPolicyDataError, RetainedPublisherCompilerOriginV3,
};
