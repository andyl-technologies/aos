//! Reads capability history through the existing sole canonical recipes.

use std::io;
use aos_sandbox_model::bounded_codec::{BoundedAppendError, append_with_capped_doubling};
use aos_sandbox_model::{AuditId, CapabilityId, CapabilityRecord, ObjectDigest,
    Operation, OperationSet, ResourceId, ResourceKind, ResourceVector, Selector};
use aos_sandbox_protocol::publisher_policy::PublisherReadDataV2;
use aos_sandbox_model::RecordNamespace;
use serde::{Deserialize, Serialize};
use sha2::{Digest as _, Sha256};

#[derive(Debug)]
pub(super) enum PublisherAuthorityError {
    MalformedRecord, InvalidParentLink, InvalidHandle, CapabilityKeyMismatch,
    IssuanceCrosslinkMismatch, InvalidIssuanceMetadata, UnsupportedVersion(u16),
    LimitExceeded(&'static str), UnknownCapability, Revoked,
}
crate::define_provider_issuance_data_recipe_v1! {
    invalid_metadata: PublisherAuthorityError::InvalidIssuanceMetadata,
    crosslink: PublisherAuthorityError::IssuanceCrosslinkMismatch,
    malformed: PublisherAuthorityError::MalformedRecord
}
crate::define_provider_runtime_issuance_data_recipe_v1! {
    invalid_metadata: PublisherAuthorityError::InvalidIssuanceMetadata,
    crosslink: PublisherAuthorityError::IssuanceCrosslinkMismatch
}
crate::define_provider_capability_record_data_recipe_v1! {
    malformed: PublisherAuthorityError::MalformedRecord,
    invalid_parent: PublisherAuthorityError::InvalidParentLink,
    invalid_handle: PublisherAuthorityError::InvalidHandle,
    key_mismatch: PublisherAuthorityError::CapabilityKeyMismatch,
    crosslink: PublisherAuthorityError::IssuanceCrosslinkMismatch,
    unsupported: PublisherAuthorityError::UnsupportedVersion,
    limit: PublisherAuthorityError::LimitExceeded
}

pub(super) struct PublisherAuthorityLimits { maximum_record_bytes: usize }
impl Default for PublisherAuthorityLimits {
    fn default() -> Self { Self { maximum_record_bytes: MAXIMUM_RECORD_BYTES } }
}

pub(super) fn resolve_current_capability_from_data_v2(
    records: PublisherReadDataV2<'_>, id: CapabilityId, limits: PublisherAuthorityLimits,
) -> Result<CapabilityRecord, PublisherAuthorityError> {
    crate::resolve_current_capability_read_data_v2!(records, id,
        limits.maximum_record_bytes, PublisherAuthorityError::UnknownCapability,
        PublisherAuthorityError::Revoked)
}

// Actual private canonical decoder/control owners, without dynamic payloads.
pub(super) fn receiving_control_bytes_v2() -> Option<usize> {
    use std::mem::size_of;
    size_of::<DecodedCapabilityRecordV1>().checked_mul(2)?
        .checked_add(size_of::<DurableCapabilityRecordWireV1>().checked_mul(2)?)?
        .checked_add(size_of::<Result<DecodedCapabilityRecordV1, PublisherAuthorityError>>()
            .checked_mul(3)?)?
        .checked_add(size_of::<Result<CapabilityRecord, PublisherAuthorityError>>()
            .checked_mul(3)?)?
        .checked_add(size_of::<PublisherAuthorityLimits>().checked_mul(3)?)
}
