//! Checks non-authorizing node-session DATA shapes shared by native verifiers.
//!
//! This predicate authenticates no peer or carrier and constructs no grant.
//! The actual protected owner must independently verify its fixed trust key,
//! detached signature, exact bytes, native time and one-shot session custody.

use crate::{NodeId, ObjectDigest};

/// Reports whether bounded session DATA avoids the native verifier's sentinels.
///
/// Frame ceilings are DATA inputs here. Actual native callers supply their
/// compiled ceilings, and this result is never a currentness or authority proof.
#[must_use]
#[allow(clippy::too_many_arguments)]
pub fn node_session_data_is_well_formed_v1(
    node: NodeId,
    binding: [u8; 32],
    audience_digest: ObjectDigest,
    disclosure_domain_digest: ObjectDigest,
    authenticated_frame_digest: ObjectDigest,
    authenticated_frame_bytes: u32,
    coordinator_epoch: u64,
    authenticated_at_unix_seconds: u64,
    valid_until_unix_seconds: u64,
    maximum_request_bytes: u32,
    maximum_response_bytes: u32,
    request_ceiling: u32,
    response_ceiling: u32,
    replay_fence: ObjectDigest,
) -> bool {
    !(node.as_bytes() == &[0; 16]
        || binding == [0; 32]
        || audience_digest.as_bytes() == &[0; 32]
        || disclosure_domain_digest.as_bytes() == &[0; 32]
        || authenticated_frame_digest.as_bytes() == &[0; 32]
        || replay_fence.as_bytes() == &[0; 32]
        || authenticated_frame_bytes == 0
        || authenticated_frame_bytes > response_ceiling
        || coordinator_epoch == 0
        || valid_until_unix_seconds <= authenticated_at_unix_seconds
        || maximum_request_bytes == 0
        || maximum_request_bytes > request_ceiling
        || maximum_response_bytes == 0
        || maximum_response_bytes > response_ceiling)
}
