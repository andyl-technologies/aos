//! Canonical V1 historical ownership entry and current-pointer formats.
//!
//! ```text
//! AOSOWNE1 || version:u16be || status:u8 || reserved:5 || authority-key ||
//! claim || claim-digest || accepted-wall:i64be || response-fence || lengths ||
//! lease || lease-signature || receipt || receipt-signature
//! AOSOWNC1 || version:u16be || request-id:16 || generation:u64be || digest:32
//! ```
//!
//! Completion decoding authenticates all four original artifacts at their
//! recorded acceptance time; it does not grant present liveness.

use super::*;

pub(super) fn durable_entry_key(request_id: &[u8; 16]) -> Vec<u8> {
    let mut key = Vec::with_capacity(DURABLE_ENTRY_PREFIX.len() + request_id.len());
    key.extend_from_slice(DURABLE_ENTRY_PREFIX);
    key.extend_from_slice(request_id);
    key
}

pub(super) fn durable_current_key(sandbox: SandboxId) -> Vec<u8> {
    let mut key = Vec::with_capacity(DURABLE_CURRENT_PREFIX.len() + 16);
    key.extend_from_slice(DURABLE_CURRENT_PREFIX);
    key.extend_from_slice(sandbox.as_bytes());
    key
}

pub(super) fn completion_transaction_id(request_id: [u8; 16]) -> [u8; 16] {
    ownership_transaction_id(COMPLETION_TRANSACTION_DOMAIN, request_id)
}

pub(super) fn begin_transaction_id(request_id: [u8; 16]) -> [u8; 16] {
    ownership_transaction_id(BEGIN_TRANSACTION_DOMAIN, request_id)
}

pub(super) fn ownership_transaction_id(domain: &[u8], request_id: [u8; 16]) -> [u8; 16] {
    let mut digest = Sha256::new();
    digest.update(domain);
    digest.update(request_id);
    let mut id = [0; 16];
    id.copy_from_slice(&digest.finalize()[..16]);
    // Journal transaction IDs reserve all-zero. Fixing one bit avoids a
    // probabilistic invalid output without admitting caller-selected bytes.
    id[0] |= 0x80;
    id
}

pub(super) fn encode_durable_entry(
    entry: &DurableOwnershipEntry,
    authority: &KeyReference,
) -> Vec<u8> {
    let key_id = authority.stable_key_id().as_str().as_bytes();
    let response_bytes = match &entry.state {
        DurableEntryState::Intent => 0,
        DurableEntryState::Completed { lease, .. } => {
            lease.canonical_lease().len()
                + lease.canonical_signature().len()
                + lease.canonical_receipt().len()
                + lease.canonical_receipt_signature().len()
        }
    };
    let mut bytes = Vec::with_capacity(328 + key_id.len() + response_bytes);
    bytes.extend_from_slice(DURABLE_ENTRY_MAGIC);
    bytes.extend_from_slice(&DURABLE_FORMAT_VERSION.to_be_bytes());
    bytes.push(match entry.state {
        DurableEntryState::Intent => 1,
        DurableEntryState::Completed { .. } => 2,
    });
    bytes.extend_from_slice(&[0; 5]);
    bytes.extend_from_slice(&(key_id.len() as u16).to_be_bytes());
    bytes.extend_from_slice(key_id);
    bytes.extend_from_slice(&authority.generation().to_be_bytes());
    bytes.extend_from_slice(authority.public_key_sha256().as_bytes());
    bytes.extend_from_slice(entry.claim.canonical_bytes());
    bytes.extend_from_slice(entry.claim.digest().as_bytes());
    match &entry.state {
        DurableEntryState::Intent => {
            bytes.extend_from_slice(&[0; 8 + 8 + 32 + 4 + 4 + 4 + 4]);
        }
        DurableEntryState::Completed {
            accepted_wall_seconds,
            lease,
        } => {
            bytes.extend_from_slice(&accepted_wall_seconds.to_be_bytes());
            bytes.extend_from_slice(&lease.generation().to_be_bytes());
            bytes.extend_from_slice(lease.digest().as_bytes());
            bytes.extend_from_slice(&(lease.canonical_lease().len() as u32).to_be_bytes());
            bytes.extend_from_slice(&(lease.canonical_signature().len() as u32).to_be_bytes());
            bytes.extend_from_slice(&(lease.canonical_receipt().len() as u32).to_be_bytes());
            bytes.extend_from_slice(
                &(lease.canonical_receipt_signature().len() as u32).to_be_bytes(),
            );
            bytes.extend_from_slice(lease.canonical_lease());
            bytes.extend_from_slice(lease.canonical_signature());
            bytes.extend_from_slice(lease.canonical_receipt());
            bytes.extend_from_slice(lease.canonical_receipt_signature());
        }
    }
    debug_assert!(bytes.len() <= MAXIMUM_DURABLE_ENTRY_BYTES);
    bytes
}

pub(super) fn decode_durable_entry(
    key: &[u8],
    bytes: &[u8],
    verifier: &OwnershipAuthorityVerifier,
) -> Result<DurableOwnershipEntry, OwnershipHistoryError> {
    if key.len() != DURABLE_ENTRY_PREFIX.len() + 16
        || !key.starts_with(DURABLE_ENTRY_PREFIX)
        || bytes.len() > MAXIMUM_DURABLE_ENTRY_BYTES
    {
        return Err(OwnershipHistoryError::CorruptState);
    }
    let request_id: [u8; 16] = key[DURABLE_ENTRY_PREFIX.len()..]
        .try_into()
        .map_err(|_| OwnershipHistoryError::CorruptState)?;

    let mut cursor = 0;
    if durable_take::<8>(bytes, &mut cursor)? != *DURABLE_ENTRY_MAGIC
        || u16::from_be_bytes(durable_take::<2>(bytes, &mut cursor)?) != DURABLE_FORMAT_VERSION
    {
        return Err(OwnershipHistoryError::CorruptState);
    }

    let status = durable_take::<1>(bytes, &mut cursor)?[0];
    if durable_take::<5>(bytes, &mut cursor)? != [0; 5] {
        return Err(OwnershipHistoryError::CorruptState);
    }

    let key_id_length = usize::from(u16::from_be_bytes(durable_take::<2>(bytes, &mut cursor)?));
    if key_id_length == 0 || key_id_length > 255 {
        return Err(OwnershipHistoryError::CorruptState);
    }
    let key_id = durable_slice(bytes, &mut cursor, key_id_length)?;
    let authority_generation = u64::from_be_bytes(durable_take::<8>(bytes, &mut cursor)?);
    let authority_fingerprint = ObjectDigest::from_bytes(durable_take::<32>(bytes, &mut cursor)?);
    if key_id != verifier.authority().stable_key_id().as_str().as_bytes()
        || authority_generation != verifier.authority().generation()
        || authority_fingerprint != verifier.authority().public_key_sha256()
    {
        return Err(OwnershipHistoryError::CorruptState);
    }

    let claim_bytes = durable_take::<CLAIM_BYTES>(bytes, &mut cursor)?;
    let claim = OwnershipClaimV1::from_canonical_bytes(&claim_bytes)
        .map_err(|_| OwnershipHistoryError::CorruptState)?;
    let persisted_claim_digest = ObjectDigest::from_bytes(durable_take::<32>(bytes, &mut cursor)?);
    if claim.request_id() != &request_id || persisted_claim_digest != claim.digest() {
        return Err(OwnershipHistoryError::CorruptState);
    }

    let accepted_wall_seconds = i64::from_be_bytes(durable_take::<8>(bytes, &mut cursor)?);
    let response_generation = u64::from_be_bytes(durable_take::<8>(bytes, &mut cursor)?);
    let response_digest = ObjectDigest::from_bytes(durable_take::<32>(bytes, &mut cursor)?);
    let lease_length = usize::try_from(u32::from_be_bytes(durable_take::<4>(bytes, &mut cursor)?))
        .map_err(|_| OwnershipHistoryError::CorruptState)?;
    let signature_length =
        usize::try_from(u32::from_be_bytes(durable_take::<4>(bytes, &mut cursor)?))
            .map_err(|_| OwnershipHistoryError::CorruptState)?;
    let receipt_length =
        usize::try_from(u32::from_be_bytes(durable_take::<4>(bytes, &mut cursor)?))
            .map_err(|_| OwnershipHistoryError::CorruptState)?;
    let receipt_signature_length =
        usize::try_from(u32::from_be_bytes(durable_take::<4>(bytes, &mut cursor)?))
            .map_err(|_| OwnershipHistoryError::CorruptState)?;

    if status == 1 {
        if accepted_wall_seconds != 0
            || response_generation != 0
            || response_digest.as_bytes() != &[0; 32]
            || lease_length != 0
            || signature_length != 0
            || receipt_length != 0
            || receipt_signature_length != 0
            || cursor != bytes.len()
        {
            return Err(OwnershipHistoryError::CorruptState);
        }
        return Ok(DurableOwnershipEntry {
            claim,
            state: DurableEntryState::Intent,
        });
    }

    if status != 2
        || response_generation == 0
        || response_digest.as_bytes() == &[0; 32]
        || lease_length == 0
        || lease_length > MAXIMUM_LEASE_BYTES
        || signature_length == 0
        || signature_length > MAXIMUM_SIGNATURE_BYTES
        || receipt_length == 0
        || receipt_length > aos_sandbox_ownership_protocol::MAXIMUM_RECEIPT_BYTES
        || receipt_signature_length == 0
        || receipt_signature_length > MAXIMUM_SIGNATURE_BYTES
        || lease_length
            .checked_add(signature_length)
            .and_then(|length| length.checked_add(receipt_length))
            .and_then(|length| length.checked_add(receipt_signature_length))
            .and_then(|length| cursor.checked_add(length))
            != Some(bytes.len())
    {
        return Err(OwnershipHistoryError::CorruptState);
    }

    let response = UnverifiedOwnershipLeaseResponse::from_transport(
        durable_slice(bytes, &mut cursor, lease_length)?.to_vec(),
        durable_slice(bytes, &mut cursor, signature_length)?.to_vec(),
        durable_slice(bytes, &mut cursor, receipt_length)?.to_vec(),
        durable_slice(bytes, &mut cursor, receipt_signature_length)?.to_vec(),
    )
    .map_err(|_| OwnershipHistoryError::CorruptState)?;
    let lease = verifier
        .authenticate_historical_response(
            &claim,
            response,
            accepted_wall_seconds,
            response_generation,
            response_digest,
        )
        .map_err(|_| OwnershipHistoryError::CorruptState)?;

    Ok(DurableOwnershipEntry {
        claim,
        state: DurableEntryState::Completed {
            accepted_wall_seconds,
            lease: Box::new(lease),
        },
    })
}

pub(super) fn encode_current_pointer(
    request_id: [u8; 16],
    lease: &RecoveredOwnershipLease,
) -> Vec<u8> {
    let mut bytes = Vec::with_capacity(66);
    bytes.extend_from_slice(DURABLE_CURRENT_MAGIC);
    bytes.extend_from_slice(&DURABLE_FORMAT_VERSION.to_be_bytes());
    bytes.extend_from_slice(&request_id);
    bytes.extend_from_slice(&lease.generation().to_be_bytes());
    bytes.extend_from_slice(lease.digest().as_bytes());
    bytes
}

pub(super) fn decode_current_pointer(
    key: &[u8],
    bytes: &[u8],
) -> Result<(SandboxId, [u8; 16], u64, ObjectDigest), OwnershipHistoryError> {
    if key.len() != DURABLE_CURRENT_PREFIX.len() + 16
        || !key.starts_with(DURABLE_CURRENT_PREFIX)
        || bytes.len() != 66
    {
        return Err(OwnershipHistoryError::CorruptState);
    }
    let sandbox = SandboxId::from_bytes(
        key[DURABLE_CURRENT_PREFIX.len()..]
            .try_into()
            .map_err(|_| OwnershipHistoryError::CorruptState)?,
    );
    let mut cursor = 0;
    if durable_take::<8>(bytes, &mut cursor)? != *DURABLE_CURRENT_MAGIC
        || u16::from_be_bytes(durable_take::<2>(bytes, &mut cursor)?) != DURABLE_FORMAT_VERSION
    {
        return Err(OwnershipHistoryError::CorruptState);
    }
    let request_id = durable_take::<16>(bytes, &mut cursor)?;
    let generation = u64::from_be_bytes(durable_take::<8>(bytes, &mut cursor)?);
    let digest = ObjectDigest::from_bytes(durable_take::<32>(bytes, &mut cursor)?);
    if sandbox.as_bytes() == &[0; 16]
        || request_id == [0; 16]
        || generation == 0
        || digest.as_bytes() == &[0; 32]
        || cursor != bytes.len()
    {
        return Err(OwnershipHistoryError::CorruptState);
    }
    Ok((sandbox, request_id, generation, digest))
}

pub(super) fn durable_take<const N: usize>(
    bytes: &[u8],
    cursor: &mut usize,
) -> Result<[u8; N], OwnershipHistoryError> {
    durable_slice(bytes, cursor, N)?
        .try_into()
        .map_err(|_| OwnershipHistoryError::CorruptState)
}

pub(super) fn durable_slice<'a>(
    bytes: &'a [u8],
    cursor: &mut usize,
    length: usize,
) -> Result<&'a [u8], OwnershipHistoryError> {
    let end = cursor
        .checked_add(length)
        .ok_or(OwnershipHistoryError::CorruptState)?;
    let value = bytes
        .get(*cursor..end)
        .ok_or(OwnershipHistoryError::CorruptState)?;
    *cursor = end;
    Ok(value)
}
