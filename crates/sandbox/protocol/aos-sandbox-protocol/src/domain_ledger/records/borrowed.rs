//! Borrows the sole protected-domain framing grammar without schema adoption.
//!
//! Schema-specific payload, companion and identity predicates remain in the
//! existing retained decoder. These views provide no replay or writer authority.

use super::{DomainLedgerDataError, ProtectedReducerPhaseV1, decode_phase};
use aos_sandbox_model::ObjectDigest;
use sha2::{Digest as _, Sha256};

fn invalid() -> DomainLedgerDataError {
    DomainLedgerDataError::NonCanonicalRecord
}

fn read<const N: usize>(bytes: &[u8], offset: usize) -> Result<[u8; N], DomainLedgerDataError> {
    bytes
        .get(offset..offset + N)
        .and_then(|slice| slice.try_into().ok())
        .ok_or_else(invalid)
}

/// Borrows the canonical key's raw kind and identity, before schema validation.
///
/// # Errors
/// Rejects a wrong prefix/version, empty/oversized identity or alternate length.
pub fn borrow_protected_key_data_v1<'a>(
    bytes: &'a [u8],
    prefix: &[u8],
) -> Result<(u8, &'a [u8]), DomainLedgerDataError> {
    let header = prefix.len().checked_add(4).ok_or_else(invalid)?;
    if bytes.len() < header || !bytes.starts_with(prefix) || bytes[prefix.len()] != 1 {
        return Err(invalid());
    }
    let length = usize::from(u16::from_be_bytes(read(bytes, prefix.len() + 2)?));
    if length == 0
        || length > super::MAXIMUM_DOMAIN_IDENTITY_BYTES
        || header.checked_add(length) != Some(bytes.len())
    {
        return Err(invalid());
    }
    Ok((bytes[prefix.len() + 1], &bytes[header..]))
}

/// Borrows checksum-checked envelope framing before reducer semantics.
#[derive(Clone, Copy, Debug)]
pub struct ProtectedEnvelopeFrameDataV1<'a> {
    /// Encoded revision; successor semantics are checked by the retained owner.
    pub revision: u64,
    /// Encoded optional predecessor.
    pub predecessor: Option<ObjectDigest>,
    /// Borrowed complete reducer bytes.
    pub payload: &'a [u8],
}

impl<'a> ProtectedEnvelopeFrameDataV1<'a> {
    /// Checks exact envelope framing and key-bound checksum without allocation.
    ///
    /// # Errors
    /// Rejects selector, reserved bytes, extent, bound or checksum mismatches.
    pub fn decode(
        bytes: &'a [u8],
        key: &[u8],
        magic: &[u8; 8],
        kind: u8,
        maximum: usize,
        domain: &[u8],
    ) -> Result<Self, DomainLedgerDataError> {
        u32::try_from(key.len()).map_err(|_| invalid())?;
        let frame = Self::decode_structure(bytes, magic, kind, maximum)?;
        let expected = envelope_digest_data_v1(
            domain,
            key,
            frame.revision,
            frame.predecessor,
            frame.payload,
        );
        if bytes[bytes.len() - 32..] != *expected.as_bytes() {
            return Err(invalid());
        }
        Ok(frame)
    }

    pub(super) fn decode_structure(
        bytes: &'a [u8],
        magic: &[u8; 8],
        kind: u8,
        maximum: usize,
    ) -> Result<Self, DomainLedgerDataError> {
        if bytes.len() < 88
            || bytes
                .len()
                .checked_sub(88)
                .is_none_or(|size| size > maximum)
            || &bytes[..8] != magic
            || read::<2>(bytes, 8)? != [0, 1]
            || bytes[10] != kind
            || bytes[11] != 0
        {
            return Err(invalid());
        }
        let revision = u64::from_be_bytes(read(bytes, 12)?);
        let previous = ObjectDigest::from_bytes(read(bytes, 20)?);
        let predecessor = (previous.as_bytes() != &[0; 32]).then_some(previous);
        let length =
            usize::try_from(u32::from_be_bytes(read(bytes, 52)?)).map_err(|_| invalid())?;
        let end = 56_usize.checked_add(length).ok_or_else(invalid)?;
        if length == 0 || length > maximum || end.checked_add(32) != Some(bytes.len()) {
            return Err(invalid());
        }
        Ok(Self {
            revision,
            predecessor,
            payload: &bytes[56..end],
        })
    }
}

pub(super) fn envelope_digest_data_v1(
    domain: &[u8],
    key: &[u8],
    revision: u64,
    predecessor: Option<ObjectDigest>,
    payload: &[u8],
) -> ObjectDigest {
    let key_length = key.len() as u32;
    ObjectDigest::from_bytes(
        Sha256::new()
            .chain_update(domain)
            .chain_update(b"envelope\0")
            .chain_update(key_length.to_be_bytes())
            .chain_update(key)
            .chain_update(revision.to_be_bytes())
            .chain_update(predecessor.map_or([0; 32], |value| *value.as_bytes()))
            .chain_update((payload.len() as u64).to_be_bytes())
            .chain_update(payload)
            .finalize()
            .into(),
    )
}

/// Borrows durable-member framing without validating its schema or atomic set.
#[derive(Clone, Copy, Debug)]
pub struct DurableMemberFrameDataV1<'a> {
    /// Encoded transaction identity.
    pub transaction_id: [u8; 16],
    /// Encoded member ordinal.
    pub member_index: u16,
    /// Encoded complete member count.
    pub member_count: u16,
    /// Encoded atomic-set commitment.
    pub set_digest: ObjectDigest,
    /// Borrowed nested envelope bytes.
    pub envelope: &'a [u8],
}

impl<'a> DurableMemberFrameDataV1<'a> {
    /// Checks exact durable framing and checksum without copying its envelope.
    ///
    /// # Errors
    /// Rejects invalid identity/count, selectors, extent, bound or checksum.
    pub fn decode(
        bytes: &'a [u8],
        maximum: usize,
        domain: &[u8],
    ) -> Result<Self, DomainLedgerDataError> {
        if bytes.len() < 189
            || bytes
                .len()
                .checked_sub(188)
                .is_none_or(|size| size > maximum)
            || &bytes[..8] != b"AOSDTX01"
            || read::<2>(bytes, 8)? != [0, 1]
            || read::<2>(bytes, 10)? != [0; 2]
        {
            return Err(invalid());
        }
        let transaction_id = read(bytes, 12)?;
        let member_index = u16::from_be_bytes(read(bytes, 28)?);
        let member_count = u16::from_be_bytes(read(bytes, 30)?);
        let set_digest = ObjectDigest::from_bytes(read(bytes, 32)?);
        let length =
            usize::try_from(u32::from_be_bytes(read(bytes, 64)?)).map_err(|_| invalid())?;
        let end = 68_usize.checked_add(length).ok_or_else(invalid)?;
        if transaction_id == [0; 16]
            || member_count == 0
            || member_index >= member_count
            || set_digest.as_bytes() == &[0; 32]
            || end.checked_add(32) != Some(bytes.len())
        {
            return Err(invalid());
        }
        let expected: [u8; 32] = Sha256::new()
            .chain_update(domain)
            .chain_update(b"durable-member\0")
            .chain_update(&bytes[..end])
            .finalize()
            .into();
        if bytes[end..] != expected {
            return Err(invalid());
        }
        Ok(Self {
            transaction_id,
            member_index,
            member_count,
            set_digest,
            envelope: &bytes[68..end],
        })
    }
}

/// Borrows canonical reducer framing without interpreting its phase or companions.
#[derive(Clone, Copy, Debug)]
pub struct ReducerFrameDataV1<'a> {
    /// Canonical encoded reducer phase.
    pub phase: ProtectedReducerPhaseV1,
    /// Sorted unique nonzero companion digests, as encoded bytes.
    pub companions: &'a [u8],
    /// Borrowed schema-specific body.
    pub body: &'a [u8],
}

impl<'a> ReducerFrameDataV1<'a> {
    /// Checks reducer framing; the schema must still derive phase and companions.
    ///
    /// # Errors
    /// Rejects malformed selectors, phase, count, ordering, extent or checksum.
    pub fn decode(
        bytes: &'a [u8],
        family: u8,
        kind: u8,
        maximum: usize,
        domain: &[u8],
    ) -> Result<Self, DomainLedgerDataError> {
        let frame = Self::decode_structure(bytes, family, kind, maximum)?;
        Self::require_checksum(bytes, domain)?;
        Ok(frame)
    }

    pub(super) fn decode_structure(
        bytes: &'a [u8],
        family: u8,
        kind: u8,
        maximum: usize,
    ) -> Result<Self, DomainLedgerDataError> {
        if bytes.len() < 60
            || bytes.len() > maximum
            || &bytes[..8] != b"AOSRDP01"
            || read::<2>(bytes, 8)? != [0, 1]
            || bytes[10] != family
            || bytes[11] != kind
            || bytes[13] != 0
        {
            return Err(invalid());
        }
        let phase = decode_phase(bytes[12]).ok_or_else(invalid)?;
        let count = usize::from(u16::from_be_bytes(read(bytes, 14)?));
        if count > super::MAXIMUM_REDUCER_COMPANIONS {
            return Err(invalid());
        }
        let length =
            usize::try_from(u32::from_be_bytes(read(bytes, 16)?)).map_err(|_| invalid())?;
        let companions_end = 20 + count * 32;
        let end = companions_end.checked_add(length).ok_or_else(invalid)?;
        if length < 8 || end.checked_add(32) != Some(bytes.len()) {
            return Err(invalid());
        }
        let companions = &bytes[20..companions_end];
        if companions.chunks_exact(32).any(|digest| digest == [0; 32])
            || !companions
                .chunks_exact(32)
                .zip(companions.chunks_exact(32).skip(1))
                .all(|(left, right)| left < right)
        {
            return Err(invalid());
        }
        Ok(Self {
            phase,
            companions,
            body: &bytes[companions_end..end],
        })
    }
    pub(super) fn require_checksum(
        bytes: &[u8],
        domain: &[u8],
    ) -> Result<(), DomainLedgerDataError> {
        let end = bytes.len().checked_sub(32).ok_or_else(invalid)?;
        let expected: [u8; 32] = Sha256::new()
            .chain_update(domain)
            .chain_update(b"reducer-payload\0")
            .chain_update(&bytes[..end])
            .finalize()
            .into();
        if bytes[end..] != expected {
            return Err(invalid());
        }
        Ok(())
    }
}
