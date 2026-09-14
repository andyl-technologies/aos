//! Canonical bounded envelope for protected publisher records.
//!
//! ```text
//! magic "AOSPAD01" (8) | version:u16be | kind:u8 | flags:u8
//! sequence:u64be | key_len:u16be | payload_len:u32be
//! predecessor:sha256[32] | payload_digest:sha256[32]
//! key:key_len | payload:payload_len
//! ```
//!
//! Version 1 admits no flags. The payload digest covers the record kind, key,
//! sequence, predecessor, and payload under a domain separator, so moving bytes
//! between record families or keys is rejected.

use aos_sandbox_core::ObjectDigest;
use sha2::{Digest as _, Sha256};

use super::{AdmissionLimits, ProtectedRecordKindV1};

const MAGIC: &[u8; 8] = b"AOSPAD01";
const VERSION: u16 = 1;
const HEADER_BYTES: usize = 90;
const RECORD_DOMAIN: &[u8] = b"aos.sandbox.publisher.protected-record.v1\0";

/// Owns one structurally and cryptographically validated protected record.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct DecodedProtectedRecordV1 {
    /// Closed semantic record family.
    pub kind: ProtectedRecordKindV1,
    /// Monotone namespace-local record sequence.
    pub sequence: u64,
    /// Exact canonical record key.
    pub key: Vec<u8>,
    /// Digest of the preceding record in this logical history.
    pub predecessor: Option<ObjectDigest>,
    /// Exact canonical family payload.
    pub payload: Vec<u8>,
    /// Digest authenticating the complete envelope semantics.
    pub digest: ObjectDigest,
}

/// Reports malformed or excessive protected record bytes.
#[derive(Clone, Debug, Eq, PartialEq, thiserror::Error)]
pub enum ProtectedRecordCodecError {
    /// Record exceeds configured or hard bounds.
    #[error("protected publisher record exceeds its bound")]
    LimitExceeded,
    /// Magic, version, flags, lengths, sequence, or predecessor is invalid.
    #[error("protected publisher record framing is malformed")]
    Malformed,
    /// Record kind is not in the closed v1 registry.
    #[error("protected publisher record kind is unknown")]
    UnknownKind,
    /// Domain-separated record digest does not match.
    #[error("protected publisher record digest differs")]
    DigestMismatch,
    /// Allocation for bounded output failed.
    #[error("protected publisher record allocation failed")]
    Allocation,
}

/// Encodes one canonical protected record.
///
/// # Errors
///
/// Returns [`ProtectedRecordCodecError`] for empty/oversized keys or payloads,
/// zero sequence, an invalid generation-one predecessor, overflow, or allocation
/// failure.
pub fn encode_protected_record_v1(
    kind: ProtectedRecordKindV1,
    sequence: u64,
    key: &[u8],
    predecessor: Option<ObjectDigest>,
    payload: &[u8],
    limits: AdmissionLimits,
) -> Result<Vec<u8>, ProtectedRecordCodecError> {
    validate_parts(sequence, key, predecessor, payload, limits)?;
    let key_len = u16::try_from(key.len()).map_err(|_| ProtectedRecordCodecError::LimitExceeded)?;
    let payload_len =
        u32::try_from(payload.len()).map_err(|_| ProtectedRecordCodecError::LimitExceeded)?;
    let total = HEADER_BYTES
        .checked_add(key.len())
        .and_then(|size| size.checked_add(payload.len()))
        .ok_or(ProtectedRecordCodecError::LimitExceeded)?;
    if total > limits.maximum_record_bytes {
        return Err(ProtectedRecordCodecError::LimitExceeded);
    }
    let predecessor_bytes = predecessor.map_or([0; 32], |digest| *digest.as_bytes());
    let digest = record_digest(kind, sequence, key, &predecessor_bytes, payload);
    let mut bytes = Vec::new();
    bytes
        .try_reserve_exact(total)
        .map_err(|_| ProtectedRecordCodecError::Allocation)?;
    bytes.extend_from_slice(MAGIC);
    bytes.extend_from_slice(&VERSION.to_be_bytes());
    bytes.push(kind as u8);
    bytes.push(0);
    bytes.extend_from_slice(&sequence.to_be_bytes());
    bytes.extend_from_slice(&key_len.to_be_bytes());
    bytes.extend_from_slice(&payload_len.to_be_bytes());
    bytes.extend_from_slice(&predecessor_bytes);
    bytes.extend_from_slice(digest.as_bytes());
    bytes.extend_from_slice(key);
    bytes.extend_from_slice(payload);
    Ok(bytes)
}

/// Decodes one exact canonical protected record.
///
/// # Errors
///
/// Returns [`ProtectedRecordCodecError`] for any size, framing, closed-kind,
/// predecessor, digest, allocation, trailing-byte, or noncanonical encoding
/// violation.
pub fn decode_protected_record_v1(
    bytes: &[u8],
    limits: AdmissionLimits,
) -> Result<DecodedProtectedRecordV1, ProtectedRecordCodecError> {
    if bytes.len() < HEADER_BYTES || bytes.len() > limits.maximum_record_bytes {
        return Err(ProtectedRecordCodecError::LimitExceeded);
    }
    if &bytes[..8] != MAGIC
        || u16::from_be_bytes(exact(&bytes[8..10])?) != VERSION
        || bytes[11] != 0
    {
        return Err(ProtectedRecordCodecError::Malformed);
    }
    let kind = ProtectedRecordKindV1::from_code(bytes[10])?;
    let sequence = u64::from_be_bytes(exact(&bytes[12..20])?);
    let key_len = usize::from(u16::from_be_bytes(exact(&bytes[20..22])?));
    let payload_len = usize::try_from(u32::from_be_bytes(exact(&bytes[22..26])?))
        .map_err(|_| ProtectedRecordCodecError::LimitExceeded)?;
    let expected = HEADER_BYTES
        .checked_add(key_len)
        .and_then(|size| size.checked_add(payload_len))
        .ok_or(ProtectedRecordCodecError::LimitExceeded)?;
    if expected != bytes.len() {
        return Err(ProtectedRecordCodecError::Malformed);
    }
    let predecessor_bytes: [u8; 32] = exact(&bytes[26..58])?;
    let stored_digest = ObjectDigest::from_bytes(exact(&bytes[58..90])?);
    let key_end = HEADER_BYTES + key_len;
    let key = &bytes[HEADER_BYTES..key_end];
    let payload = &bytes[key_end..];
    let predecessor = if predecessor_bytes == [0; 32] {
        None
    } else {
        Some(ObjectDigest::from_bytes(predecessor_bytes))
    };
    validate_parts(sequence, key, predecessor, payload, limits)?;
    let digest = record_digest(kind, sequence, key, &predecessor_bytes, payload);
    if digest != stored_digest {
        return Err(ProtectedRecordCodecError::DigestMismatch);
    }
    let mut owned_key = Vec::new();
    owned_key
        .try_reserve_exact(key.len())
        .map_err(|_| ProtectedRecordCodecError::Allocation)?;
    owned_key.extend_from_slice(key);
    let mut owned_payload = Vec::new();
    owned_payload
        .try_reserve_exact(payload.len())
        .map_err(|_| ProtectedRecordCodecError::Allocation)?;
    owned_payload.extend_from_slice(payload);
    let decoded = DecodedProtectedRecordV1 {
        kind,
        sequence,
        key: owned_key,
        predecessor,
        payload: owned_payload,
        digest,
    };
    if encode_protected_record_v1(
        decoded.kind,
        decoded.sequence,
        &decoded.key,
        decoded.predecessor,
        &decoded.payload,
        limits,
    )? != bytes
    {
        return Err(ProtectedRecordCodecError::Malformed);
    }
    Ok(decoded)
}

fn validate_parts(
    sequence: u64,
    key: &[u8],
    predecessor: Option<ObjectDigest>,
    payload: &[u8],
    limits: AdmissionLimits,
) -> Result<(), ProtectedRecordCodecError> {
    if sequence == 0
        || key.is_empty()
        || key.len() > 1024
        || payload.is_empty()
        || payload.len() > limits.maximum_record_bytes
        || (sequence == 1) != predecessor.is_none()
        || predecessor.is_some_and(|digest| digest.as_bytes() == &[0; 32])
    {
        return Err(ProtectedRecordCodecError::Malformed);
    }
    Ok(())
}

fn record_digest(
    kind: ProtectedRecordKindV1,
    sequence: u64,
    key: &[u8],
    predecessor: &[u8; 32],
    payload: &[u8],
) -> ObjectDigest {
    let mut hash = Sha256::new();
    hash.update(RECORD_DOMAIN);
    hash.update([kind as u8]);
    hash.update(sequence.to_be_bytes());
    hash.update((key.len() as u64).to_be_bytes());
    hash.update(key);
    hash.update(predecessor);
    hash.update((payload.len() as u64).to_be_bytes());
    hash.update(payload);
    ObjectDigest::from_bytes(hash.finalize().into())
}

fn exact<const N: usize>(bytes: &[u8]) -> Result<[u8; N], ProtectedRecordCodecError> {
    bytes
        .try_into()
        .map_err(|_| ProtectedRecordCodecError::Malformed)
}
