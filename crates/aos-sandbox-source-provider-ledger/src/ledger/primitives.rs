//! Pure canonical key, digest, and closed-enum decoding primitives.
//!
//! ```text
//! Authority = "aos.source-provider.authority.v1\0" || provider[16]                  (49)
//! Catalog = "aos.source-provider.catalog.v1\0" || provider[16] || generation:u64be (55)
//! HolderHead = "aos.source-provider.session.v1\0" || provider[16] || holder[16]     (63)
//! SessionHistory = "aos.source-provider.session-history.v1\0" || provider[16] ||
//!                  holder[16] || session-binding[32]                                (103)
//! Attempt = "aos.source-provider.attempt.v1\0" || provider[16] || holder[16] ||
//!           root-record-key[16] || method:u8 || request-id[16]                       (96)
//! Acquisition = "aos.source-provider.acquisition.v1\0" || provider[16] ||
//!               holder[16] || acquisition-id[32]                                    (99)
//! Release = "aos.source-provider.release.v1\0" || provider[16] || holder[16] ||
//!           acquisition-id[32]                                                      (95)
//! ```

use aos_sandbox_core::ObjectDigest;
use aos_sandbox_source_provider_protocol::{SourceProviderMethod, SourceProviderStatus};
use sha2::{Digest as _, Sha256};

use super::LedgerFormatErrorV1;
use super::model::{
    AcquisitionKeyV1, AttemptKeyV1, ProviderAcquisitionStateV1, ProviderAttemptStateV1,
    ProviderAuthorityStateV1, ProviderReleaseStateV1, ReleaseKeyV1,
};

const AUTHORITY_KEY_PREFIX: &[u8] = b"aos.source-provider.authority.v1\0";
const CATALOG_KEY_PREFIX: &[u8] = b"aos.source-provider.catalog.v1\0";
const SESSION_KEY_PREFIX: &[u8] = b"aos.source-provider.session.v1\0";
const SESSION_HISTORY_KEY_PREFIX: &[u8] = b"aos.source-provider.session-history.v1\0";
const ATTEMPT_KEY_PREFIX: &[u8] = b"aos.source-provider.attempt.v1\0";
const ACQUISITION_KEY_PREFIX: &[u8] = b"aos.source-provider.acquisition.v1\0";
const RELEASE_KEY_PREFIX: &[u8] = b"aos.source-provider.release.v1\0";

const _: () = assert!(AUTHORITY_KEY_PREFIX.len() + 16 == 49);
const _: () = assert!(CATALOG_KEY_PREFIX.len() + 16 + 8 == 55);
const _: () = assert!(SESSION_KEY_PREFIX.len() + 16 + 16 == 63);
const _: () = assert!(SESSION_HISTORY_KEY_PREFIX.len() + 16 + 16 + 32 == 103);
const _: () = assert!(ATTEMPT_KEY_PREFIX.len() + 16 + 16 + 16 + 1 + 16 == 96);
const _: () = assert!(ACQUISITION_KEY_PREFIX.len() + 16 + 16 + 32 == 99);
const _: () = assert!(RELEASE_KEY_PREFIX.len() + 16 + 16 + 32 == 95);

/// Constructs the unique provider-authority head key.
pub fn authority_key(provider_id: [u8; 16]) -> Vec<u8> {
    key_with_parts(AUTHORITY_KEY_PREFIX, &[&provider_id])
}

/// Constructs one immutable catalog-generation key.
pub fn catalog_key(provider_id: [u8; 16], generation: u64) -> Vec<u8> {
    key_with_parts(
        CATALOG_KEY_PREFIX,
        &[&provider_id, &generation.to_be_bytes()],
    )
}

/// Constructs the current holder-session head key.
pub fn session_key(provider_id: [u8; 16], holder_id: [u8; 16]) -> Vec<u8> {
    key_with_parts(SESSION_KEY_PREFIX, &[&provider_id, &holder_id])
}

/// Constructs one immutable holder-session transcript key.
pub fn session_history_key(
    provider_id: [u8; 16],
    holder_id: [u8; 16],
    session_binding: ObjectDigest,
) -> Vec<u8> {
    key_with_parts(
        SESSION_HISTORY_KEY_PREFIX,
        &[&provider_id, &holder_id, session_binding.as_bytes()],
    )
}

/// Constructs one provider-attempt identity key.
pub fn attempt_key(key: &AttemptKeyV1) -> Vec<u8> {
    key_with_parts(
        ATTEMPT_KEY_PREFIX,
        &[
            &key.provider_id,
            &key.holder_id,
            &key.root_record_key_id,
            &[key.method],
            &key.request_id,
        ],
    )
}

/// Constructs one provider-acquisition identity key.
pub fn acquisition_key(key: &AcquisitionKeyV1) -> Vec<u8> {
    key_with_parts(
        ACQUISITION_KEY_PREFIX,
        &[
            &key.provider_id,
            &key.holder_id,
            key.acquisition_id.as_bytes(),
        ],
    )
}

/// Constructs the unique release-lineage key for an acquisition.
pub fn release_key(key: &ReleaseKeyV1) -> Vec<u8> {
    key_with_parts(
        RELEASE_KEY_PREFIX,
        &[
            &key.provider_id,
            &key.holder_id,
            key.acquisition_id.as_bytes(),
        ],
    )
}

pub(super) fn decode_authority_state(
    value: u8,
) -> Result<ProviderAuthorityStateV1, LedgerFormatErrorV1> {
    match value {
        1 => Ok(ProviderAuthorityStateV1::Active),
        2 => Ok(ProviderAuthorityStateV1::AcquireClosed),
        3 => Ok(ProviderAuthorityStateV1::Retired),
        _ => Err(LedgerFormatErrorV1::Corrupt("authority state")),
    }
}

pub(super) fn decode_attempt_state(
    value: u8,
) -> Result<ProviderAttemptStateV1, LedgerFormatErrorV1> {
    match value {
        1 => Ok(ProviderAttemptStateV1::Reserved),
        2 => Ok(ProviderAttemptStateV1::Completed),
        3 => Ok(ProviderAttemptStateV1::Retired),
        _ => Err(LedgerFormatErrorV1::Corrupt("attempt state")),
    }
}

pub(super) fn decode_acquisition_state(
    value: u8,
) -> Result<ProviderAcquisitionStateV1, LedgerFormatErrorV1> {
    match value {
        1 => Ok(ProviderAcquisitionStateV1::Applying),
        2 => Ok(ProviderAcquisitionStateV1::Pending),
        3 => Ok(ProviderAcquisitionStateV1::Active),
        4 => Ok(ProviderAcquisitionStateV1::Releasing),
        5 => Ok(ProviderAcquisitionStateV1::Released),
        6 => Ok(ProviderAcquisitionStateV1::Faulted),
        _ => Err(LedgerFormatErrorV1::Corrupt("acquisition state")),
    }
}

pub(super) fn decode_release_state(
    value: u8,
) -> Result<ProviderReleaseStateV1, LedgerFormatErrorV1> {
    match value {
        1 => Ok(ProviderReleaseStateV1::Intent),
        2 => Ok(ProviderReleaseStateV1::Tombstone),
        _ => Err(LedgerFormatErrorV1::Corrupt("release state")),
    }
}

pub(super) fn decode_method(value: u8) -> Result<SourceProviderMethod, LedgerFormatErrorV1> {
    match value {
        2 => Ok(SourceProviderMethod::Acquire),
        3 => Ok(SourceProviderMethod::Release),
        4 => Ok(SourceProviderMethod::Inventory),
        _ => Err(LedgerFormatErrorV1::Corrupt("attempt method")),
    }
}

pub(super) fn decode_optional_status(
    value: u8,
) -> Result<Option<SourceProviderStatus>, LedgerFormatErrorV1> {
    match value {
        0 => Ok(None),
        1 => Ok(Some(SourceProviderStatus::Complete)),
        2 => Ok(Some(SourceProviderStatus::Pending)),
        3 => Ok(Some(SourceProviderStatus::Rejected)),
        4 => Ok(Some(SourceProviderStatus::Unavailable)),
        _ => Err(LedgerFormatErrorV1::Corrupt("attempt status")),
    }
}

pub(super) fn key_with_parts(prefix: &[u8], parts: &[&[u8]]) -> Vec<u8> {
    let length = parts
        .iter()
        .fold(prefix.len(), |total, part| total + part.len());
    let mut key = Vec::with_capacity(length);
    key.extend_from_slice(prefix);
    for part in parts {
        key.extend_from_slice(part);
    }
    key
}

pub(super) fn optional_bytes_digest(bytes: &[u8]) -> ObjectDigest {
    if bytes.is_empty() {
        ObjectDigest::from_bytes([0; 32])
    } else {
        ObjectDigest::from_bytes(Sha256::digest(bytes).into())
    }
}
