//! Writable-memory mappings, dirty ranges, and canonical digests.

use super::*;

/// Fixed encoded size of one flattened writable-RAM mapping record.
pub const MEMORY_MAPPING_RECORD_V1_BYTES: usize = 104;
/// Mapping guest-physical-address field offset.
pub const MEMORY_MAPPING_GPA_OFFSET: usize = 0;
/// Mapping byte-length field offset.
pub const MEMORY_MAPPING_LENGTH_OFFSET: usize = 8;
/// Mapping MemoryRegion-relative field offset.
pub const MEMORY_MAPPING_REGION_OFFSET: usize = 16;
/// Mapping RAMBlock-relative field offset.
pub const MEMORY_MAPPING_RAM_BLOCK_OFFSET: usize = 24;
/// Mapping flags field offset.
pub const MEMORY_MAPPING_FLAGS_OFFSET: usize = 32;
/// Mapping reserved field offset.
pub const MEMORY_MAPPING_RESERVED_OFFSET: usize = 36;
/// Mapping MemoryRegion identity-digest field offset.
pub const MEMORY_MAPPING_REGION_IDENTITY_OFFSET: usize = 40;
/// Mapping RAMBlock identity-digest field offset.
pub const MEMORY_MAPPING_RAM_BLOCK_IDENTITY_OFFSET: usize = 72;
/// Version-1 mappings admit only normal writable RAM, so no flag is defined.
pub const MEMORY_MAPPING_FLAGS_V1_MASK: u32 = 0;
/// Maximum flattened writable-RAM mappings carried by one evidence payload.
pub const HARD_MEMORY_MAPPING_RECORDS: usize = 16_384;
/// SHA-256 domain prefix for a complete flattened writable-RAM mapping.
pub const MEMORY_MAPPING_SHA256_DOMAIN_V1: &[u8] = b"crucible.memory-mapping.v1\0";

/// One stable record from QEMU's complete flattened writable-RAM map.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct MemoryMappingRecordV1 {
    /// First guest-physical byte of the mapping.
    pub guest_physical_start: u64,
    /// Positive mapping length.
    pub length: u64,
    /// Byte offset from the selected MemoryRegion's canonical base.
    pub memory_region_offset: u64,
    /// Byte offset from the selected RAMBlock's canonical base.
    pub ram_block_offset: u64,
    /// Closed [`MEMORY_MAPPING_FLAGS_V1_MASK`] bit set.
    pub flags: u32,
    /// Stable digest of the canonical MemoryRegion identity.
    pub memory_region_identity_sha256: [u8; 32],
    /// Stable digest of the canonical RAMBlock identifier.
    pub ram_block_identity_sha256: [u8; 32],
}

impl MemoryMappingRecordV1 {
    /// Encodes one fixed-width little-endian mapping record.
    ///
    /// # Errors
    ///
    /// Returns [`MemoryMutationEvidenceError::Mapping`] for zero length,
    /// overflow, unknown flags, or a zero identity digest.
    pub fn encode(
        self,
    ) -> Result<[u8; MEMORY_MAPPING_RECORD_V1_BYTES], MemoryMutationEvidenceError> {
        self.validate()?;
        let mut bytes = [0; MEMORY_MAPPING_RECORD_V1_BYTES];
        bytes[0..8].copy_from_slice(&self.guest_physical_start.to_le_bytes());
        bytes[8..16].copy_from_slice(&self.length.to_le_bytes());
        bytes[16..24].copy_from_slice(&self.memory_region_offset.to_le_bytes());
        bytes[24..32].copy_from_slice(&self.ram_block_offset.to_le_bytes());
        bytes[32..36].copy_from_slice(&self.flags.to_le_bytes());
        bytes[40..72].copy_from_slice(&self.memory_region_identity_sha256);
        bytes[72..104].copy_from_slice(&self.ram_block_identity_sha256);
        Ok(bytes)
    }

    /// Decodes one fixed-width canonical mapping record.
    ///
    /// # Errors
    ///
    /// Returns [`MemoryMutationEvidenceError::Mapping`] when the record is
    /// malformed or violates its closed version-1 invariants.
    pub fn decode(bytes: &[u8]) -> Result<Self, MemoryMutationEvidenceError> {
        if bytes.len() != MEMORY_MAPPING_RECORD_V1_BYTES
            || bytes[36..40].iter().any(|byte| *byte != 0)
        {
            return Err(MemoryMutationEvidenceError::Mapping);
        }
        let value = Self {
            guest_physical_start: read_u64(bytes, 0),
            length: read_u64(bytes, 8),
            memory_region_offset: read_u64(bytes, 16),
            ram_block_offset: read_u64(bytes, 24),
            flags: read_u32(bytes, 32),
            memory_region_identity_sha256: read_array32(bytes, 40),
            ram_block_identity_sha256: read_array32(bytes, 72),
        };
        value.validate()?;
        Ok(value)
    }

    fn validate(self) -> Result<(), MemoryMutationEvidenceError> {
        if self.length == 0
            || self
                .guest_physical_start
                .checked_add(self.length - 1)
                .is_none()
            || self
                .memory_region_offset
                .checked_add(self.length - 1)
                .is_none()
            || self.ram_block_offset.checked_add(self.length - 1).is_none()
            || self.flags & !MEMORY_MAPPING_FLAGS_V1_MASK != 0
            || self.memory_region_identity_sha256 == [0; 32]
            || self.ram_block_identity_sha256 == [0; 32]
        {
            return Err(MemoryMutationEvidenceError::Mapping);
        }
        Ok(())
    }
}

/// Fixed dirty-bitmap granule used by QEMU's version-1 mutation evidence.
pub const MEMORY_DIRTY_PAGE_BYTES_V1: u32 = 4_096;
/// Fixed encoded size of one canonical dirty-page range.
pub const MEMORY_DIRTY_RANGE_V1_BYTES: usize = 48;
/// Dirty range RAMBlock identity field offset.
pub const MEMORY_DIRTY_RANGE_RAM_BLOCK_IDENTITY_OFFSET: usize = 0;
/// Dirty range RAMBlock byte-offset field offset.
pub const MEMORY_DIRTY_RANGE_RAM_BLOCK_OFFSET: usize = 32;
/// Dirty range page-count field offset.
pub const MEMORY_DIRTY_RANGE_PAGE_COUNT_OFFSET: usize = 40;
/// Dirty range page-size field offset.
pub const MEMORY_DIRTY_RANGE_PAGE_SIZE_OFFSET: usize = 44;
/// SHA-256 domain prefix for canonical dirty-page ranges.
pub const MEMORY_DIRTY_SHA256_DOMAIN_V1: &[u8] = b"crucible.memory-dirty-pages.v1\0";

/// One contiguous dirty-page range within a stable RAMBlock.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct MemoryDirtyRangeV1 {
    /// Stable digest of the canonical RAMBlock identifier.
    pub ram_block_identity_sha256: [u8; 32],
    /// First dirty-page byte offset within the RAMBlock.
    pub ram_block_offset: u64,
    /// Positive number of contiguous dirty pages.
    pub page_count: u32,
    /// Fixed version-1 page size, [`MEMORY_DIRTY_PAGE_BYTES_V1`].
    pub page_size: u32,
}

impl MemoryDirtyRangeV1 {
    /// Encodes one fixed-width little-endian dirty-page range.
    ///
    /// # Errors
    ///
    /// Returns [`MemoryMutationEvidenceError::DirtyRange`] for a zero identity,
    /// wrong page size, unaligned offset, zero count, or range overflow.
    pub fn encode(self) -> Result<[u8; MEMORY_DIRTY_RANGE_V1_BYTES], MemoryMutationEvidenceError> {
        self.validate()?;
        let mut bytes = [0; MEMORY_DIRTY_RANGE_V1_BYTES];
        bytes[0..32].copy_from_slice(&self.ram_block_identity_sha256);
        bytes[32..40].copy_from_slice(&self.ram_block_offset.to_le_bytes());
        bytes[40..44].copy_from_slice(&self.page_count.to_le_bytes());
        bytes[44..48].copy_from_slice(&self.page_size.to_le_bytes());
        Ok(bytes)
    }

    /// Decodes one fixed-width canonical dirty-page range.
    ///
    /// # Errors
    ///
    /// Returns [`MemoryMutationEvidenceError::DirtyRange`] when the record is
    /// malformed or violates its closed version-1 invariants.
    pub fn decode(bytes: &[u8]) -> Result<Self, MemoryMutationEvidenceError> {
        if bytes.len() != MEMORY_DIRTY_RANGE_V1_BYTES {
            return Err(MemoryMutationEvidenceError::DirtyRange);
        }
        let value = Self {
            ram_block_identity_sha256: read_array32(bytes, 0),
            ram_block_offset: read_u64(bytes, 32),
            page_count: read_u32(bytes, 40),
            page_size: read_u32(bytes, 44),
        };
        value.validate()?;
        Ok(value)
    }

    fn validate(self) -> Result<(), MemoryMutationEvidenceError> {
        let length = u64::from(self.page_count)
            .checked_mul(u64::from(self.page_size))
            .filter(|length| *length != 0);
        if self.ram_block_identity_sha256 == [0; 32]
            || self.page_size != MEMORY_DIRTY_PAGE_BYTES_V1
            || !self
                .ram_block_offset
                .is_multiple_of(u64::from(self.page_size))
            || length
                .and_then(|value| self.ram_block_offset.checked_add(value - 1))
                .is_none()
        {
            return Err(MemoryMutationEvidenceError::DirtyRange);
        }
        Ok(())
    }
}

/// Computes the canonical SHA-256 of a complete flattened writable-RAM map.
///
/// # Errors
///
/// Returns [`MemoryMutationEvidenceError::Mapping`] for an empty, oversized,
/// invalid, overlapping, or non-ascending mapping sequence.
pub fn memory_mapping_sha256(
    records: &[MemoryMappingRecordV1],
) -> Result<[u8; 32], MemoryMutationEvidenceError> {
    if records.is_empty() || records.len() > HARD_MEMORY_MAPPING_RECORDS {
        return Err(MemoryMutationEvidenceError::Mapping);
    }
    let mut prior_end = None;
    let mut hasher = Sha256::new();
    hasher.update(MEMORY_MAPPING_SHA256_DOMAIN_V1);
    hasher.update((records.len() as u32).to_le_bytes());
    for record in records {
        let encoded = record.encode()?;
        if prior_end.is_some_and(|end| record.guest_physical_start < end) {
            return Err(MemoryMutationEvidenceError::Mapping);
        }
        prior_end = record.guest_physical_start.checked_add(record.length);
        if prior_end.is_none() {
            return Err(MemoryMutationEvidenceError::Mapping);
        }
        hasher.update(encoded);
    }
    Ok(hasher.finalize().into())
}

/// Computes the canonical SHA-256 of sorted, coalesced dirty-page ranges.
///
/// # Errors
///
/// Returns [`MemoryMutationEvidenceError::DirtyRange`] for an empty, invalid,
/// overlapping, adjacent-uncoalesced, or non-canonical sequence.
pub fn memory_dirty_ranges_sha256(
    records: &[MemoryDirtyRangeV1],
) -> Result<[u8; 32], MemoryMutationEvidenceError> {
    if records.is_empty() || records.len() > u32::MAX as usize {
        return Err(MemoryMutationEvidenceError::DirtyRange);
    }
    let mut prior: Option<MemoryDirtyRangeV1> = None;
    let mut hasher = Sha256::new();
    hasher.update(MEMORY_DIRTY_SHA256_DOMAIN_V1);
    hasher.update((records.len() as u32).to_le_bytes());
    for record in records {
        let encoded = record.encode()?;
        if let Some(previous) = prior {
            let previous_end = previous
                .ram_block_offset
                .checked_add(u64::from(previous.page_count) * u64::from(previous.page_size))
                .ok_or(MemoryMutationEvidenceError::DirtyRange)?;
            if (record.ram_block_identity_sha256, record.ram_block_offset)
                <= (
                    previous.ram_block_identity_sha256,
                    previous.ram_block_offset,
                )
                || (record.ram_block_identity_sha256 == previous.ram_block_identity_sha256
                    && record.ram_block_offset <= previous_end)
            {
                return Err(MemoryMutationEvidenceError::DirtyRange);
            }
        }
        prior = Some(*record);
        hasher.update(encoded);
    }
    Ok(hasher.finalize().into())
}

/// Derives the exact sorted, coalesced dirty-page ranges for RAM fragments.
///
/// # Errors
///
/// Returns [`MemoryMutationEvidenceError::DirtyRange`] when a fragment is
/// invalid, page rounding overflows, or the page count is not representable.
pub fn memory_dirty_ranges_for_fragments(
    fragments: &[MemoryMutationFragmentV1],
) -> Result<Vec<MemoryDirtyRangeV1>, MemoryMutationEvidenceError> {
    let page_size = u64::from(MEMORY_DIRTY_PAGE_BYTES_V1);
    let mut raw = Vec::with_capacity(fragments.len());
    for fragment in fragments {
        fragment.validate()?;
        let last = fragment
            .ram_block_offset
            .checked_add(u64::from(fragment.length) - 1)
            .ok_or(MemoryMutationEvidenceError::DirtyRange)?;
        let start = fragment.ram_block_offset / page_size * page_size;
        let end = last
            .checked_div(page_size)
            .and_then(|page| page.checked_add(1))
            .and_then(|page| page.checked_mul(page_size))
            .ok_or(MemoryMutationEvidenceError::DirtyRange)?;
        raw.push((fragment.ram_block_identity_sha256, start, end));
    }
    raw.sort_unstable();
    let mut merged: Vec<([u8; 32], u64, u64)> = Vec::with_capacity(raw.len());
    for (identity, start, end) in raw {
        match merged.last_mut() {
            Some((previous_identity, _previous_start, previous_end))
                if *previous_identity == identity && start <= *previous_end =>
            {
                *previous_end = (*previous_end).max(end);
            }
            _ => merged.push((identity, start, end)),
        }
    }
    merged
        .into_iter()
        .map(|(ram_block_identity_sha256, ram_block_offset, end)| {
            let page_count = u32::try_from((end - ram_block_offset) / page_size)
                .map_err(|_source| MemoryMutationEvidenceError::DirtyRange)?;
            let range = MemoryDirtyRangeV1 {
                ram_block_identity_sha256,
                ram_block_offset,
                page_count,
                page_size: MEMORY_DIRTY_PAGE_BYTES_V1,
            };
            range.validate()?;
            Ok(range)
        })
        .collect()
}

/// Computes the canonical SHA-256 for a GVA translation sequence.
///
/// # Errors
///
/// Returns [`MemoryMutationEvidenceError::Translation`] for an empty,
/// invalid, overlapping, or non-ascending sequence.
pub fn memory_translation_sha256(
    vcpu_index: u32,
    records: &[MemoryTranslationRecordV1],
) -> Result<[u8; 32], MemoryMutationEvidenceError> {
    if records.is_empty() || records.len() > u32::MAX as usize {
        return Err(MemoryMutationEvidenceError::Translation);
    }
    let mut prior_end = None;
    let mut hasher = Sha256::new();
    hasher.update(MEMORY_TRANSLATION_SHA256_DOMAIN_V1);
    hasher.update(vcpu_index.to_le_bytes());
    hasher.update((records.len() as u32).to_le_bytes());
    for record in records {
        let encoded = record.encode()?;
        if prior_end.is_some_and(|end| record.virtual_page_start < end) {
            return Err(MemoryMutationEvidenceError::Translation);
        }
        prior_end = record.virtual_page_start.checked_add(record.page_size);
        if prior_end.is_none() {
            return Err(MemoryMutationEvidenceError::Translation);
        }
        hasher.update(encoded);
    }
    Ok(hasher.finalize().into())
}
