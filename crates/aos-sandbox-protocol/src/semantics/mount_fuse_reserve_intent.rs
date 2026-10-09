//! Exact purpose-57 semantics for one original FUSE attachment reservation.
//!
//! The fixed comparison tuple contains the entire canonical attachment intent,
//! current desired-record and namespace-allocation commitments, Host runtime
//! scope, assignment, and original request. It is not an owner custody token.
//!
//! ```text
//! domain | method:u16=44 | purpose:u32=57 | protocol:u16[2]=[3,0]
//! | audience:u16=1 | feature-length:u16 | presentation-feature | feature:[1,0]
//! | request-id:16 | deadline:u64 | response-ceiling:u32 | assignment-fence
//! | intent-length:u32 | canonical-attachment-intent-v2
//! | desired-record:32 | namespace-generation:u64 | allocation:32
//! | runtime:32 | payload-scope:32 | binding-version:u32=2
//! | policy-media-length:u16 | policy-media | policy-digest:32 | policy-size:u64
//! | complete-request:32 | descriptor-count:u16=0
//! ```
//!
//! Integers use network byte order. Issuance must keep the genuine Controller
//! owner held; Mount separately authenticates the original pending session,
//! desired-state authorization, current Host scope and physical reservation.

use aos_sandbox_core::{
    BrokerArgumentCommitment, BrokerGrantTarget, BrokerResourceHandle, BrokerVerb,
    MOUNT_FUSE_PRESENTATION_FEATURE_NAMESPACE, encode_attachment_intent_v2,
};

use crate::mount_fuse_reserve_intent::ValidatedFuseReserveIntentRequestV1;

const DOMAIN: &[u8] = b"aos.sandbox.mount.fuse-reserve-intent.v2\0";

/// Reports an unrepresentable or unspecified FUSE reservation comparison.
#[derive(Clone, Copy, Debug, Eq, PartialEq, thiserror::Error)]
pub enum MountFuseReserveIntentSemanticErrorV1 {
    /// The current desired-record resource commitment is a reserved sentinel.
    #[error("FUSE desired-record comparison target is unspecified")]
    InvalidTarget,
    /// A canonical field exceeds the closed wire width or body bound.
    #[error("FUSE intent comparison encoding exceeds its fixed bounds")]
    EncodingTooLarge,
}

/// Retains one exact reservation tuple without granting effect authority.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct CanonicalMountFuseReserveIntentSemanticsV1 {
    bytes: Vec<u8>,
    target: BrokerGrantTarget,
    commitment: BrokerArgumentCommitment,
}

impl CanonicalMountFuseReserveIntentSemanticsV1 {
    /// Returns only the distinct FUSE reservation purpose.
    #[must_use]
    pub const fn verb(&self) -> BrokerVerb {
        BrokerVerb::MountReserveFuseWorkerIntent
    }

    /// Returns the exact desired-record resource comparison target.
    #[must_use]
    pub const fn target(&self) -> BrokerGrantTarget {
        self.target
    }

    /// Returns the domain-separated full intent/request comparison commitment.
    #[must_use]
    pub const fn commitment(&self) -> BrokerArgumentCommitment {
        self.commitment
    }

    /// Borrows the canonical tuple for exact plan matching and vectors.
    #[must_use]
    pub fn canonical_bytes(&self) -> &[u8] {
        &self.bytes
    }
}

/// Commits the complete validated intent and its original dispatch coordinates.
///
/// Every input remains comparison data. This function performs no signing,
/// journal admission, namespace adoption, worker launch or currentness claim.
///
/// # Errors
///
/// Rejects an unspecified resource target or an unrepresentable field length.
pub fn canonical_mount_fuse_reserve_intent_semantics_v1(
    request: &ValidatedFuseReserveIntentRequestV1,
) -> Result<CanonicalMountFuseReserveIntentSemanticsV1, MountFuseReserveIntentSemanticErrorV1> {
    let target = BrokerResourceHandle::from_bytes(*request.desired_record_digest())
        .map_err(|_| MountFuseReserveIntentSemanticErrorV1::InvalidTarget)?;
    let feature = MOUNT_FUSE_PRESENTATION_FEATURE_NAMESPACE.as_bytes();
    let feature_length = u16::try_from(feature.len())
        .map_err(|_| MountFuseReserveIntentSemanticErrorV1::EncodingTooLarge)?;
    let intent = encode_attachment_intent_v2(request.intent());
    let intent_length = u32::try_from(intent.len())
        .map_err(|_| MountFuseReserveIntentSemanticErrorV1::EncodingTooLarge)?;

    let mut bytes = Vec::with_capacity(DOMAIN.len() + feature.len() + intent.len() + 320);
    bytes.extend_from_slice(DOMAIN);
    bytes.extend_from_slice(&44_u16.to_be_bytes());
    bytes.extend_from_slice(&57_u32.to_be_bytes());
    for value in [3_u16, 0, 1, feature_length] {
        bytes.extend_from_slice(&value.to_be_bytes());
    }
    bytes.extend_from_slice(feature);
    bytes.extend_from_slice(&1_u16.to_be_bytes());
    bytes.extend_from_slice(&0_u16.to_be_bytes());

    let header = request.header();
    bytes.extend_from_slice(header.request_id());
    bytes.extend_from_slice(&header.deadline_boottime_nanoseconds().to_be_bytes());
    bytes.extend_from_slice(&header.maximum_response_bytes().to_be_bytes());
    let fence = request.fence();
    bytes.extend_from_slice(fence.sandbox_id());
    bytes.extend_from_slice(fence.incarnation_id());
    bytes.extend_from_slice(&fence.assignment_epoch().to_be_bytes());
    bytes.extend_from_slice(&fence.desired_generation().to_be_bytes());
    bytes.extend_from_slice(fence.assignment_digest());
    bytes.extend_from_slice(&intent_length.to_be_bytes());
    bytes.extend_from_slice(&intent);
    bytes.extend_from_slice(request.desired_record_digest());
    bytes.extend_from_slice(&request.namespace_target_generation().to_be_bytes());
    bytes.extend_from_slice(request.namespace_allocation_digest());
    bytes.extend_from_slice(request.runtime_handle());
    bytes.extend_from_slice(request.payload_scope_handle());
    bytes.extend_from_slice(&2_u32.to_be_bytes());
    let policy = request.accepted_policy();
    let media = policy.media_type().as_str().as_bytes();
    let media_length = u16::try_from(media.len())
        .map_err(|_| MountFuseReserveIntentSemanticErrorV1::EncodingTooLarge)?;
    bytes.extend_from_slice(&media_length.to_be_bytes());
    bytes.extend_from_slice(media);
    bytes.extend_from_slice(policy.digest().as_bytes());
    bytes.extend_from_slice(&policy.encoded_size().to_be_bytes());
    bytes.extend_from_slice(request.request_commitment());
    bytes.extend_from_slice(&0_u16.to_be_bytes());

    Ok(CanonicalMountFuseReserveIntentSemanticsV1 {
        commitment: BrokerArgumentCommitment::for_canonical_bytes(&bytes),
        target: BrokerGrantTarget::Resource(target),
        bytes,
    })
}
