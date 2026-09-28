//! Authenticated header and exact structural-index payload partition.

use super::*;

pub(super) struct ValidatedInput<'a> {
    pub(super) records: &'a [u8],
    pub(super) lookup: &'a [u8],
    pub(super) directory: &'a [u8],
    pub(super) record_capacity: usize,
    pub(super) summary: IndexSummary,
    pub(super) layout: IndexLayout,
}

/// Authenticates only the envelope, not record or table semantics.
pub(super) fn authenticate_input<'a>(
    bytes: &'a [u8],
    maximum_bytes: u64,
    expected: &IndexExpectation<'_>,
) -> Result<ValidatedInput<'a>, IndexError> {
    if bytes.len() as u64 > maximum_bytes {
        return Err(IndexError::LimitExceeded);
    }
    if bytes.len() < HEADER_BYTES {
        return Err(IndexError::InvalidHeader);
    }
    if expected.tree_features & !KNOWN_FEATURES != 0 {
        return Err(IndexError::InvalidHeader);
    }
    let mut cursor = Cursor::new(bytes);
    if cursor.take(8)? != MAGIC {
        return Err(IndexError::InvalidHeader);
    }
    let version = cursor.u32()?;
    let header_bytes = cursor.u32()? as usize;
    if version != VERSION || header_bytes != HEADER_BYTES {
        return Err(IndexError::InvalidHeader);
    }
    let index_media = MediaType::new(INDEX_MEDIA_TYPE).map_err(|_| IndexError::InvalidHeader)?;
    if expected.index.media_type() != &index_media
        || descriptor_for_bytes(index_media, bytes) != *expected.index
    {
        return Err(IndexError::DescriptorMismatch);
    }
    let compiler_abi = cursor.array::<32>()?;
    let tree_digest = ObjectDigest::from_bytes(cursor.array::<32>()?);
    let tree_size = cursor.u64()?;
    let root_digest = ObjectDigest::from_bytes(cursor.array::<32>()?);
    let root_size = cursor.u64()?;
    let tree_features = cursor.u32()?;
    if cursor.u32()? != 0 {
        return Err(IndexError::InvalidHeader);
    }
    let records = cursor.u64()?;
    if records == 0 {
        return Err(IndexError::InvalidHeader);
    }
    let payload_bytes = cursor.u64()?;
    let expected_hash = cursor.array::<32>()?;
    let records_bytes = cursor.u64()?;
    let lookup_slots = cursor.u64()?;
    if cursor.u32()? as usize != LOOKUP_SLOT_BYTES
        || cursor.u32()? != LOOKUP_HASH_SHA256
        || cursor.u64()? != 0
    {
        return Err(IndexError::InvalidHeader);
    }
    let directory_slots = cursor.u64()?;
    if cursor.u32()? as usize != DIRECTORY_SLOT_BYTES || cursor.u32()? != 0 {
        return Err(IndexError::InvalidHeader);
    }
    let root_nlink = cursor.u64()?;
    if root_nlink < 2 || cursor.u64()? != 0 {
        return Err(IndexError::InvalidHeader);
    }
    let layout = IndexLayout {
        records_bytes,
        lookup_slots,
        directory_slots,
        root_nlink,
    };
    if compiler_abi != expected.compiler_abi
        || tree_digest != expected.tree.digest()
        || tree_size != expected.tree.encoded_size()
        || root_digest != expected.root.digest()
        || root_size != expected.root.encoded_size()
        || tree_features != expected.tree_features
        || validate_descriptor_role(DescriptorRole::ImmutableViewSource, expected.tree).is_err()
        || validate_descriptor_role(DescriptorRole::DirectoryChild, expected.root).is_err()
    {
        return Err(IndexError::InvalidHeader);
    }
    let payload_len = usize::try_from(payload_bytes).map_err(|_| IndexError::LimitExceeded)?;
    if cursor.remaining() != payload_len {
        return Err(IndexError::InvalidHeader);
    }
    let payload = cursor.take(payload_len)?;
    let actual_hash: [u8; 32] = Sha256::digest(payload).into();
    if actual_hash != expected_hash {
        return Err(IndexError::ChecksumMismatch);
    }
    let records_len = usize::try_from(records_bytes).map_err(|_| IndexError::LimitExceeded)?;
    if records_len > payload.len() {
        return Err(IndexError::InvalidHeader);
    }
    let canonical_slots = lookup_slot_count(records)?;
    let lookup_bytes = lookup_allocation_bytes(canonical_slots)?;
    let lookup_len = usize::try_from(lookup_bytes).map_err(|_| IndexError::LimitExceeded)?;
    if records_len
        .checked_add(lookup_len)
        .ok_or(IndexError::LimitExceeded)?
        > payload.len()
    {
        return Err(IndexError::InvalidHeader);
    }
    let records_payload = &payload[..records_len];
    let lookup_payload = &payload[records_len..records_len + lookup_len];
    let directory_payload = &payload[records_len + lookup_len..];
    let canonical_slots_u64 =
        u64::try_from(canonical_slots).map_err(|_| IndexError::LimitExceeded)?;
    if lookup_slots != canonical_slots_u64 || lookup_bytes != lookup_payload.len() as u64 {
        return Err(IndexError::InvalidHeader);
    }
    let directory_bytes = directory_allocation_bytes(canonical_slots)?;
    if directory_slots != canonical_slots_u64 || directory_bytes != directory_payload.len() as u64 {
        return Err(IndexError::InvalidHeader);
    }
    if records_bytes
        .checked_add(lookup_bytes)
        .and_then(|bytes| bytes.checked_add(directory_bytes))
        .ok_or(IndexError::LimitExceeded)?
        != payload_bytes
    {
        return Err(IndexError::InvalidHeader);
    }
    let record_capacity = usize::try_from(records).map_err(|_| IndexError::LimitExceeded)?;
    if record_capacity > records_payload.len() / RECORD_FIXED_BYTES {
        return Err(IndexError::InvalidHeader);
    }

    Ok(ValidatedInput {
        records: records_payload,
        lookup: lookup_payload,
        directory: directory_payload,
        record_capacity,
        summary: IndexSummary {
            compiler_abi,
            tree_digest,
            tree_size,
            root_digest,
            root_size,
            records,
            bytes: bytes.len() as u64,
        },
        layout,
    })
}
