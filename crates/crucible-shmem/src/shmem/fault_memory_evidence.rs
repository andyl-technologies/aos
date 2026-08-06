//! Canonical translation records and QEMU memory-mutation evidence.
//!
//! Translation digests are SHA-256 over the domain
//! `crucible.memory-translation.v1\0`, the little-endian vCPU index and record
//! count, then fixed-width records in ascending virtual-address order. Memory
//! evidence carries the same records plus stable RAM-region identities and
//! bounded inline before/after bytes.

use core::fmt::Write as _;

use sha2::{Digest as _, Sha256};
use thiserror::Error;

use crate::{
    HARD_FAULT_PAYLOAD_BYTES, MemoryMutationAddressSpace, MemoryMutationPayloadError,
    MemoryMutationTransformKind,
};

/// Fixed encoded size of one canonical translation record.
pub const MEMORY_TRANSLATION_RECORD_V1_BYTES: usize = 32;
/// Translation virtual-page field offset.
pub const MEMORY_TRANSLATION_VIRTUAL_PAGE_OFFSET: usize = 0;
/// Translation physical-page field offset.
pub const MEMORY_TRANSLATION_PHYSICAL_PAGE_OFFSET: usize = 8;
/// Translation page-size field offset.
pub const MEMORY_TRANSLATION_PAGE_SIZE_OFFSET: usize = 16;
/// Translation permissions field offset.
pub const MEMORY_TRANSLATION_PERMISSIONS_OFFSET: usize = 24;
/// Translation attributes field offset.
pub const MEMORY_TRANSLATION_ATTRIBUTES_OFFSET: usize = 26;
/// Translation covered-byte-count field offset.
pub const MEMORY_TRANSLATION_COVERED_BYTES_OFFSET: usize = 28;
/// Read permission bit in a translation record.
pub const MEMORY_TRANSLATION_PERMISSION_READ: u16 = 1 << 0;
/// Write permission bit in a translation record.
pub const MEMORY_TRANSLATION_PERMISSION_WRITE: u16 = 1 << 1;
/// Execute permission bit in a translation record.
pub const MEMORY_TRANSLATION_PERMISSION_EXECUTE: u16 = 1 << 2;
/// User-accessible permission bit in a translation record.
pub const MEMORY_TRANSLATION_PERMISSION_USER: u16 = 1 << 3;
/// Complete permission mask understood by version 1.
pub const MEMORY_TRANSLATION_PERMISSIONS_V1_MASK: u16 = (1 << 4) - 1;
/// Secure transaction attribute bit.
pub const MEMORY_TRANSLATION_ATTRIBUTE_SECURE: u16 = 1 << 0;
/// User transaction attribute bit.
pub const MEMORY_TRANSLATION_ATTRIBUTE_USER: u16 = 1 << 1;
/// Complete transaction-attribute mask understood by version 1.
pub const MEMORY_TRANSLATION_ATTRIBUTES_V1_MASK: u16 = (1 << 2) - 1;
/// SHA-256 domain prefix for canonical translation evidence.
pub const MEMORY_TRANSLATION_SHA256_DOMAIN_V1: &[u8] = b"crucible.memory-translation.v1\0";
/// SHA-256 domain prefix for a canonical QEMU MemoryRegion identity.
pub const MEMORY_REGION_IDENTITY_SHA256_DOMAIN_V1: &[u8] = b"crucible.memory-region-identity.v1\0";
/// SHA-256 domain prefix for a canonical QEMU RAMBlock identity.
pub const MEMORY_RAM_BLOCK_IDENTITY_SHA256_DOMAIN_V1: &[u8] = b"crucible.ram-block-identity.v1\0";

/// Computes a stable identity digest for a canonical QEMU MemoryRegion.
///
/// The length prefix makes the byte framing explicit across independent Rust
/// and C implementations. The QEMU side supplies the full canonical owner path
/// and the stable region name, never a host pointer.
///
/// # Errors
///
/// Returns [`MemoryMutationEvidenceError::Identity`] when the identity is
/// empty, contains a NUL byte, or exceeds the version-1 length field.
pub fn memory_region_identity_sha256(
    owner_path: &str,
    region_name: &str,
) -> Result<[u8; 32], MemoryMutationEvidenceError> {
    let owner_length = validate_identity_component(owner_path)?;
    let name_length = validate_identity_component(region_name)?;
    let mut hasher = Sha256::new();
    hasher.update(MEMORY_REGION_IDENTITY_SHA256_DOMAIN_V1);
    hasher.update(owner_length.to_le_bytes());
    hasher.update(owner_path.as_bytes());
    hasher.update(name_length.to_le_bytes());
    hasher.update(region_name.as_bytes());
    Ok(hasher.finalize().into())
}

/// Computes a stable identity digest for a canonical QEMU RAMBlock identifier.
///
/// # Errors
///
/// Returns [`MemoryMutationEvidenceError::Identity`] when the identifier is
/// empty, contains a NUL byte, or exceeds the version-1 length field.
pub fn memory_ram_block_identity_sha256(
    identity: &str,
) -> Result<[u8; 32], MemoryMutationEvidenceError> {
    let length = validate_identity_component(identity)?;
    let mut hasher = Sha256::new();
    hasher.update(MEMORY_RAM_BLOCK_IDENTITY_SHA256_DOMAIN_V1);
    hasher.update(length.to_le_bytes());
    hasher.update(identity.as_bytes());
    Ok(hasher.finalize().into())
}

fn validate_identity_component(value: &str) -> Result<u32, MemoryMutationEvidenceError> {
    if value.is_empty() || value.as_bytes().contains(&0) {
        return Err(MemoryMutationEvidenceError::Identity);
    }
    u32::try_from(value.len()).map_err(|_source| MemoryMutationEvidenceError::Identity)
}

/// One page-table translation contributing to a GVA mutation.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct MemoryTranslationRecordV1 {
    /// Virtual page base in the selected vCPU address space.
    pub virtual_page_start: u64,
    /// Guest-physical page base resolved at the safe boundary.
    pub physical_page_start: u64,
    /// Architecture-reported mapping page size.
    pub page_size: u64,
    /// Closed [`MEMORY_TRANSLATION_PERMISSIONS_V1_MASK`] bit set.
    pub permissions: u16,
    /// Closed [`MEMORY_TRANSLATION_ATTRIBUTES_V1_MASK`] transaction bit set.
    pub attributes: u16,
    /// Number of requested bytes covered by this record.
    pub covered_bytes: u32,
}

impl MemoryTranslationRecordV1 {
    /// Encodes one fixed-width little-endian translation record.
    ///
    /// # Errors
    ///
    /// Returns [`MemoryMutationEvidenceError::Translation`] for an invalid
    /// page size, alignment, permission set, attributes, or covered length.
    pub fn encode(
        self,
    ) -> Result<[u8; MEMORY_TRANSLATION_RECORD_V1_BYTES], MemoryMutationEvidenceError> {
        self.validate()?;
        let mut bytes = [0; MEMORY_TRANSLATION_RECORD_V1_BYTES];
        bytes[0..8].copy_from_slice(&self.virtual_page_start.to_le_bytes());
        bytes[8..16].copy_from_slice(&self.physical_page_start.to_le_bytes());
        bytes[16..24].copy_from_slice(&self.page_size.to_le_bytes());
        bytes[24..26].copy_from_slice(&self.permissions.to_le_bytes());
        bytes[26..28].copy_from_slice(&self.attributes.to_le_bytes());
        bytes[28..32].copy_from_slice(&self.covered_bytes.to_le_bytes());
        Ok(bytes)
    }

    /// Decodes one fixed-width canonical translation record.
    ///
    /// # Errors
    ///
    /// Returns [`MemoryMutationEvidenceError::Translation`] when the record is
    /// malformed or violates its closed version-1 invariants.
    pub fn decode(bytes: &[u8]) -> Result<Self, MemoryMutationEvidenceError> {
        if bytes.len() != MEMORY_TRANSLATION_RECORD_V1_BYTES {
            return Err(MemoryMutationEvidenceError::Translation);
        }
        let value = Self {
            virtual_page_start: read_u64(bytes, 0),
            physical_page_start: read_u64(bytes, 8),
            page_size: read_u64(bytes, 16),
            permissions: read_u16(bytes, 24),
            attributes: read_u16(bytes, 26),
            covered_bytes: read_u32(bytes, 28),
        };
        value.validate()?;
        Ok(value)
    }

    fn validate(self) -> Result<(), MemoryMutationEvidenceError> {
        if self.page_size < 4_096
            || !self.page_size.is_power_of_two()
            || !self.virtual_page_start.is_multiple_of(self.page_size)
            || !self.physical_page_start.is_multiple_of(self.page_size)
            || self.permissions == 0
            || self.permissions & !MEMORY_TRANSLATION_PERMISSIONS_V1_MASK != 0
            || self.attributes & !MEMORY_TRANSLATION_ATTRIBUTES_V1_MASK != 0
            || self.covered_bytes == 0
            || u64::from(self.covered_bytes) > self.page_size
        {
            return Err(MemoryMutationEvidenceError::Translation);
        }
        Ok(())
    }
}

/// Fixed encoded size of one resolved RAM fragment record.
pub const MEMORY_MUTATION_FRAGMENT_V1_BYTES: usize = 104;
/// Fragment guest-physical-address field offset.
pub const MEMORY_MUTATION_FRAGMENT_GPA_OFFSET: usize = 0;
/// Fragment request-offset field offset.
pub const MEMORY_MUTATION_FRAGMENT_REQUEST_OFFSET: usize = 8;
/// Fragment byte-length field offset.
pub const MEMORY_MUTATION_FRAGMENT_LENGTH_OFFSET: usize = 12;
/// Fragment flags field offset.
pub const MEMORY_MUTATION_FRAGMENT_FLAGS_OFFSET: usize = 16;
/// Fragment reserved field offset.
pub const MEMORY_MUTATION_FRAGMENT_RESERVED_OFFSET: usize = 20;
/// Fragment MemoryRegion-relative field offset.
pub const MEMORY_MUTATION_FRAGMENT_REGION_OFFSET: usize = 24;
/// Fragment RAMBlock-relative field offset.
pub const MEMORY_MUTATION_FRAGMENT_RAM_BLOCK_OFFSET: usize = 32;
/// Fragment MemoryRegion identity-digest field offset.
pub const MEMORY_MUTATION_FRAGMENT_REGION_IDENTITY_OFFSET: usize = 40;
/// Fragment RAMBlock identity-digest field offset.
pub const MEMORY_MUTATION_FRAGMENT_RAM_BLOCK_IDENTITY_OFFSET: usize = 72;
/// Fragment flag indicating that the commit covers the range with TB invalidation.
pub const MEMORY_MUTATION_FRAGMENT_TB_INVALIDATED: u32 = 1 << 0;
/// Complete fragment flag mask understood by version 1.
pub const MEMORY_MUTATION_FRAGMENT_FLAGS_V1_MASK: u32 = MEMORY_MUTATION_FRAGMENT_TB_INVALIDATED;

/// One normal-RAM fragment resolved before an all-or-nothing mutation commits.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct MemoryMutationFragmentV1 {
    /// First guest-physical byte of the fragment.
    pub guest_physical_start: u64,
    /// Byte offset of this fragment within the requested mutation range.
    pub request_offset: u32,
    /// Positive byte length within one MemoryRegion and RAMBlock.
    pub length: u32,
    /// Closed [`MEMORY_MUTATION_FRAGMENT_FLAGS_V1_MASK`] bit set.
    pub flags: u32,
    /// Byte offset from the selected MemoryRegion's canonical base.
    pub memory_region_offset: u64,
    /// Byte offset from the selected RAMBlock's canonical base.
    pub ram_block_offset: u64,
    /// Stable digest of the canonical MemoryRegion owner path.
    pub memory_region_identity_sha256: [u8; 32],
    /// Stable digest of the canonical RAMBlock identifier.
    pub ram_block_identity_sha256: [u8; 32],
}

impl MemoryMutationFragmentV1 {
    /// Encodes one fixed-width little-endian resolved-fragment record.
    ///
    /// # Errors
    ///
    /// Returns [`MemoryMutationEvidenceError::Fragment`] for zero length,
    /// address overflow, unknown flags, or a zero object identity.
    pub fn encode(
        self,
    ) -> Result<[u8; MEMORY_MUTATION_FRAGMENT_V1_BYTES], MemoryMutationEvidenceError> {
        self.validate()?;
        let mut bytes = [0; MEMORY_MUTATION_FRAGMENT_V1_BYTES];
        bytes[0..8].copy_from_slice(&self.guest_physical_start.to_le_bytes());
        bytes[8..12].copy_from_slice(&self.request_offset.to_le_bytes());
        bytes[12..16].copy_from_slice(&self.length.to_le_bytes());
        bytes[16..20].copy_from_slice(&self.flags.to_le_bytes());
        bytes[24..32].copy_from_slice(&self.memory_region_offset.to_le_bytes());
        bytes[32..40].copy_from_slice(&self.ram_block_offset.to_le_bytes());
        bytes[40..72].copy_from_slice(&self.memory_region_identity_sha256);
        bytes[72..104].copy_from_slice(&self.ram_block_identity_sha256);
        Ok(bytes)
    }

    /// Decodes one fixed-width canonical resolved-fragment record.
    ///
    /// # Errors
    ///
    /// Returns [`MemoryMutationEvidenceError::Fragment`] when the record is
    /// malformed or violates its closed version-1 invariants.
    pub fn decode(bytes: &[u8]) -> Result<Self, MemoryMutationEvidenceError> {
        if bytes.len() != MEMORY_MUTATION_FRAGMENT_V1_BYTES
            || bytes[20..24].iter().any(|byte| *byte != 0)
        {
            return Err(MemoryMutationEvidenceError::Fragment);
        }
        let array = |range: core::ops::Range<usize>| {
            let mut value = [0; 32];
            value.copy_from_slice(&bytes[range]);
            value
        };
        let value = Self {
            guest_physical_start: read_u64(bytes, 0),
            request_offset: read_u32(bytes, 8),
            length: read_u32(bytes, 12),
            flags: read_u32(bytes, 16),
            memory_region_offset: read_u64(bytes, 24),
            ram_block_offset: read_u64(bytes, 32),
            memory_region_identity_sha256: array(40..72),
            ram_block_identity_sha256: array(72..104),
        };
        value.validate()?;
        Ok(value)
    }

    fn validate(self) -> Result<(), MemoryMutationEvidenceError> {
        if self.length == 0
            || self
                .guest_physical_start
                .checked_add(u64::from(self.length) - 1)
                .is_none()
            || self.request_offset.checked_add(self.length).is_none()
            || self
                .memory_region_offset
                .checked_add(u64::from(self.length) - 1)
                .is_none()
            || self
                .ram_block_offset
                .checked_add(u64::from(self.length) - 1)
                .is_none()
            || self.flags & !MEMORY_MUTATION_FRAGMENT_FLAGS_V1_MASK != 0
            || self.memory_region_identity_sha256 == [0; 32]
            || self.ram_block_identity_sha256 == [0; 32]
        {
            return Err(MemoryMutationEvidenceError::Fragment);
        }
        Ok(())
    }
}

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

/// Eight-byte magic for version-1 mutation evidence.
pub const MEMORY_MUTATION_EVIDENCE_MAGIC_V1: [u8; 8] = *b"CRUCMER1";
/// Mutation-evidence semantic version.
pub const MEMORY_MUTATION_EVIDENCE_VERSION_V1: u16 = 1;
/// Fixed evidence header size before canonical records and inline bytes.
pub const MEMORY_MUTATION_EVIDENCE_HEADER_V1_BYTES: usize = 304;
/// Evidence semantic-version field offset.
pub const MEMORY_MUTATION_EVIDENCE_VERSION_OFFSET: usize = 8;
/// Evidence flags field offset.
pub const MEMORY_MUTATION_EVIDENCE_FLAGS_OFFSET: usize = 10;
/// Evidence address-space field offset.
pub const MEMORY_MUTATION_EVIDENCE_ADDRESS_SPACE_OFFSET: usize = 12;
/// Evidence transform field offset.
pub const MEMORY_MUTATION_EVIDENCE_TRANSFORM_OFFSET: usize = 14;
/// Evidence vCPU-index field offset.
pub const MEMORY_MUTATION_EVIDENCE_VCPU_INDEX_OFFSET: usize = 16;
/// Evidence mutation-length field offset.
pub const MEMORY_MUTATION_EVIDENCE_LENGTH_OFFSET: usize = 20;
/// Evidence requested-address field offset.
pub const MEMORY_MUTATION_EVIDENCE_ADDRESS_OFFSET: usize = 24;
/// Evidence exact observed-icount field offset.
pub const MEMORY_MUTATION_EVIDENCE_OBSERVED_ICOUNT_OFFSET: usize = 32;
/// Evidence translation-record count field offset.
pub const MEMORY_MUTATION_EVIDENCE_TRANSLATION_COUNT_OFFSET: usize = 40;
/// Evidence RAM-fragment count field offset.
pub const MEMORY_MUTATION_EVIDENCE_FRAGMENT_COUNT_OFFSET: usize = 44;
/// Evidence complete mapping-record count field offset.
pub const MEMORY_MUTATION_EVIDENCE_MAPPING_COUNT_OFFSET: usize = 48;
/// Evidence dirty-range record count field offset.
pub const MEMORY_MUTATION_EVIDENCE_DIRTY_COUNT_OFFSET: usize = 52;
/// Evidence inline before/after byte count field offset.
pub const MEMORY_MUTATION_EVIDENCE_INLINE_LENGTH_OFFSET: usize = 56;
/// Evidence reserved field offset.
pub const MEMORY_MUTATION_EVIDENCE_RESERVED_OFFSET: usize = 60;
/// Evidence before-byte SHA-256 field offset.
pub const MEMORY_MUTATION_EVIDENCE_BEFORE_SHA256_OFFSET: usize = 64;
/// Evidence after-byte SHA-256 field offset.
pub const MEMORY_MUTATION_EVIDENCE_AFTER_SHA256_OFFSET: usize = 96;
/// Evidence canonical-translation SHA-256 field offset.
pub const MEMORY_MUTATION_EVIDENCE_TRANSLATION_SHA256_OFFSET: usize = 128;
/// Evidence mapping-generation SHA-256 field offset.
pub const MEMORY_MUTATION_EVIDENCE_MAPPING_SHA256_OFFSET: usize = 160;
/// Evidence dirty-page-set SHA-256 field offset.
pub const MEMORY_MUTATION_EVIDENCE_DIRTY_SHA256_OFFSET: usize = 192;
/// Evidence first-invalidated-address field offset.
pub const MEMORY_MUTATION_EVIDENCE_INVALIDATED_START_OFFSET: usize = 224;
/// Evidence last-invalidated-address field offset.
pub const MEMORY_MUTATION_EVIDENCE_INVALIDATED_END_OFFSET: usize = 232;
/// Evidence exact target-node identity hash field offset.
pub const MEMORY_MUTATION_EVIDENCE_TARGET_NODE_HASH_OFFSET: usize = 240;
/// Evidence node-fingerprint field offset.
pub const MEMORY_MUTATION_EVIDENCE_NODE_FINGERPRINT_OFFSET: usize = 272;
/// Maximum before-byte count inlined together with the same number after bytes.
pub const MEMORY_MUTATION_EVIDENCE_INLINE_BYTES: u32 = 65_536;
/// Evidence flag indicating that before and after bytes are present.
pub const MEMORY_MUTATION_EVIDENCE_FLAG_INLINE_BYTES: u16 = 1 << 0;
/// Evidence flag indicating that executable translations were invalidated.
pub const MEMORY_MUTATION_EVIDENCE_FLAG_TB_INVALIDATED: u16 = 1 << 1;
/// Complete evidence flag mask understood by version 1.
pub const MEMORY_MUTATION_EVIDENCE_FLAGS_V1_MASK: u16 = (1 << 2) - 1;
/// SHA-256 domain prefix for the exact post-mutation boundary fingerprint.
pub const MEMORY_BOUNDARY_FINGERPRINT_SHA256_DOMAIN_V1: &[u8] =
    b"crucible.memory-boundary-fingerprint.v1\0";
/// SHA-256 domain prefix for a prepared memory mutation authorization.
pub const MEMORY_MUTATION_PRECONDITION_SHA256_DOMAIN_V1: &[u8] =
    b"crucible.memory-mutation-precondition.v1\0";

/// Binds a commit to the bytes, transform result, translations, and RAM map
/// observed by an earlier non-mutating preparation at a frozen boundary.
#[must_use]
pub fn memory_mutation_precondition_sha256(
    before_sha256: [u8; 32],
    after_sha256: [u8; 32],
    translation_sha256: [u8; 32],
    mapping_generation_sha256: [u8; 32],
) -> [u8; 32] {
    let mut hasher = Sha256::new();
    hasher.update(MEMORY_MUTATION_PRECONDITION_SHA256_DOMAIN_V1);
    hasher.update(before_sha256);
    hasher.update(after_sha256);
    hasher.update(translation_sha256);
    hasher.update(mapping_generation_sha256);
    hasher.finalize().into()
}

/// Complete, independently verifiable evidence for one memory mutation.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct MemoryMutationEvidenceV1 {
    /// Address space mutated by QEMU.
    pub address_space: MemoryMutationAddressSpace,
    /// Transform applied to the before bytes.
    pub transform: MemoryMutationTransformKind,
    /// vCPU translation context, or `u32::MAX` for GPA.
    pub vcpu_index: u32,
    /// First requested GVA or GPA byte.
    pub address: u64,
    /// Total changed-byte range length.
    pub length: u32,
    /// Exact retired-instruction coordinate at which QEMU committed.
    pub observed_icount: u64,
    /// Canonical GVA translations; empty for GPA.
    pub translations: Vec<MemoryTranslationRecordV1>,
    /// Ordered normal-RAM fragments covering the complete mutation.
    pub fragments: Vec<MemoryMutationFragmentV1>,
    /// Complete flattened writable-RAM map observed before commit.
    pub mappings: Vec<MemoryMappingRecordV1>,
    /// Sorted, coalesced dirty-page ranges produced by the commit.
    pub dirty_ranges: Vec<MemoryDirtyRangeV1>,
    /// SHA-256 of all before bytes in address order.
    pub before_sha256: [u8; 32],
    /// SHA-256 of all after bytes in address order.
    pub after_sha256: [u8; 32],
    /// SHA-256 of the complete flattened RAM mapping generation.
    pub mapping_generation_sha256: [u8; 32],
    /// SHA-256 of canonical dirty RAM page ranges.
    pub dirty_pages_sha256: [u8; 32],
    /// First invalidated RAM/TB address, if executable code was affected.
    pub invalidated_start: Option<u64>,
    /// Last inclusive invalidated RAM/TB address.
    pub invalidated_end: Option<u64>,
    /// Hash of the exact target node identity from the command envelope.
    pub target_node_hash: [u8; 32],
    /// Canonical post-mutation boundary fingerprint.
    pub node_fingerprint: [u8; 32],
    /// Before bytes when the length is within the inline bound.
    pub before_bytes: Vec<u8>,
    /// After bytes when the length is within the inline bound.
    pub after_bytes: Vec<u8>,
}

impl MemoryMutationEvidenceV1 {
    /// Returns the canonical translation digest, or zero for GPA evidence.
    ///
    /// # Errors
    ///
    /// Returns [`MemoryMutationEvidenceError`] when a translation record is
    /// malformed or the record count cannot be represented canonically.
    pub fn translation_sha256(&self) -> Result<[u8; 32], MemoryMutationEvidenceError> {
        if self.translations.is_empty() {
            Ok([0; 32])
        } else {
            memory_translation_sha256(self.vcpu_index, &self.translations)
        }
    }

    /// Encodes canonical memory-mutation evidence.
    ///
    /// # Errors
    ///
    /// Returns [`MemoryMutationEvidenceError`] for inconsistent translation,
    /// digest, invalidation, inline-byte, or transport bounds.
    pub fn encode(&self) -> Result<Vec<u8>, MemoryMutationEvidenceError> {
        self.validate()?;
        let inline_len = self.before_bytes.len();
        let translation_count = self.translations.len();
        let fragment_count = self.fragments.len();
        let mapping_count = self.mappings.len();
        let dirty_count = self.dirty_ranges.len();
        let translation_count_u32 = u32::try_from(translation_count)
            .map_err(|_source| MemoryMutationEvidenceError::Length)?;
        let fragment_count_u32 =
            u32::try_from(fragment_count).map_err(|_source| MemoryMutationEvidenceError::Length)?;
        let mapping_count_u32 =
            u32::try_from(mapping_count).map_err(|_source| MemoryMutationEvidenceError::Length)?;
        let dirty_count_u32 =
            u32::try_from(dirty_count).map_err(|_source| MemoryMutationEvidenceError::Length)?;
        let inline_len_u32 =
            u32::try_from(inline_len).map_err(|_source| MemoryMutationEvidenceError::Length)?;
        let length = MEMORY_MUTATION_EVIDENCE_HEADER_V1_BYTES
            .checked_add(
                translation_count
                    .checked_mul(MEMORY_TRANSLATION_RECORD_V1_BYTES)
                    .ok_or(MemoryMutationEvidenceError::Length)?,
            )
            .and_then(|value| {
                value.checked_add(fragment_count.checked_mul(MEMORY_MUTATION_FRAGMENT_V1_BYTES)?)
            })
            .and_then(|value| {
                value.checked_add(mapping_count.checked_mul(MEMORY_MAPPING_RECORD_V1_BYTES)?)
            })
            .and_then(|value| {
                value.checked_add(dirty_count.checked_mul(MEMORY_DIRTY_RANGE_V1_BYTES)?)
            })
            .and_then(|value| value.checked_add(inline_len.checked_mul(2)?))
            .ok_or(MemoryMutationEvidenceError::Length)?;
        if length > HARD_FAULT_PAYLOAD_BYTES as usize {
            return Err(MemoryMutationEvidenceError::Length);
        }
        let mut flags = 0_u16;
        if inline_len != 0 {
            flags |= MEMORY_MUTATION_EVIDENCE_FLAG_INLINE_BYTES;
        }
        if self.invalidated_start.is_some() {
            flags |= MEMORY_MUTATION_EVIDENCE_FLAG_TB_INVALIDATED;
        }
        let translation_sha = self.translation_sha256()?;
        let mut bytes = vec![0; MEMORY_MUTATION_EVIDENCE_HEADER_V1_BYTES];
        bytes[0..8].copy_from_slice(&MEMORY_MUTATION_EVIDENCE_MAGIC_V1);
        put_u16(&mut bytes, 8, MEMORY_MUTATION_EVIDENCE_VERSION_V1);
        put_u16(&mut bytes, 10, flags);
        put_u16(&mut bytes, 12, self.address_space as u16);
        put_u16(&mut bytes, 14, self.transform as u16);
        put_u32(&mut bytes, 16, self.vcpu_index);
        put_u32(&mut bytes, 20, self.length);
        put_u64(&mut bytes, 24, self.address);
        put_u64(&mut bytes, 32, self.observed_icount);
        put_u32(&mut bytes, 40, translation_count_u32);
        put_u32(&mut bytes, 44, fragment_count_u32);
        put_u32(&mut bytes, 48, mapping_count_u32);
        put_u32(&mut bytes, 52, dirty_count_u32);
        put_u32(&mut bytes, 56, inline_len_u32);
        bytes[64..96].copy_from_slice(&self.before_sha256);
        bytes[96..128].copy_from_slice(&self.after_sha256);
        bytes[128..160].copy_from_slice(&translation_sha);
        bytes[160..192].copy_from_slice(&self.mapping_generation_sha256);
        bytes[192..224].copy_from_slice(&self.dirty_pages_sha256);
        put_u64(&mut bytes, 224, self.invalidated_start.unwrap_or(0));
        put_u64(&mut bytes, 232, self.invalidated_end.unwrap_or(0));
        bytes[240..272].copy_from_slice(&self.target_node_hash);
        bytes[272..304].copy_from_slice(&self.node_fingerprint);
        for record in &self.translations {
            bytes.extend_from_slice(&record.encode()?);
        }
        for fragment in &self.fragments {
            bytes.extend_from_slice(&fragment.encode()?);
        }
        for mapping in &self.mappings {
            bytes.extend_from_slice(&mapping.encode()?);
        }
        for dirty_range in &self.dirty_ranges {
            bytes.extend_from_slice(&dirty_range.encode()?);
        }
        bytes.extend_from_slice(&self.before_bytes);
        bytes.extend_from_slice(&self.after_bytes);
        Ok(bytes)
    }

    /// Decodes and validates canonical memory-mutation evidence.
    ///
    /// # Errors
    ///
    /// Returns [`MemoryMutationEvidenceError`] for bad framing, unknown tags,
    /// invalid records, mismatched digests, or inconsistent inline bytes.
    pub fn decode(bytes: &[u8]) -> Result<Self, MemoryMutationEvidenceError> {
        if bytes.len() < MEMORY_MUTATION_EVIDENCE_HEADER_V1_BYTES
            || bytes[0..8] != MEMORY_MUTATION_EVIDENCE_MAGIC_V1
            || read_u16(bytes, 8) != MEMORY_MUTATION_EVIDENCE_VERSION_V1
            || bytes[60..64].iter().any(|byte| *byte != 0)
        {
            return Err(MemoryMutationEvidenceError::Framing);
        }
        let flags = read_u16(bytes, 10);
        if flags & !MEMORY_MUTATION_EVIDENCE_FLAGS_V1_MASK != 0 {
            return Err(MemoryMutationEvidenceError::Framing);
        }
        let translation_count = read_u32(bytes, 40) as usize;
        let fragment_count = read_u32(bytes, 44) as usize;
        let mapping_count = read_u32(bytes, 48) as usize;
        let dirty_count = read_u32(bytes, 52) as usize;
        let inline_len = read_u32(bytes, 56) as usize;
        if (flags & MEMORY_MUTATION_EVIDENCE_FLAG_INLINE_BYTES != 0) != (inline_len != 0)
            || (flags & MEMORY_MUTATION_EVIDENCE_FLAG_TB_INVALIDATED == 0
                && bytes[MEMORY_MUTATION_EVIDENCE_INVALIDATED_START_OFFSET
                    ..MEMORY_MUTATION_EVIDENCE_TARGET_NODE_HASH_OFFSET]
                    .iter()
                    .any(|byte| *byte != 0))
        {
            return Err(MemoryMutationEvidenceError::Invalidation);
        }
        let translations_end = MEMORY_MUTATION_EVIDENCE_HEADER_V1_BYTES
            .checked_add(
                translation_count
                    .checked_mul(MEMORY_TRANSLATION_RECORD_V1_BYTES)
                    .ok_or(MemoryMutationEvidenceError::Length)?,
            )
            .ok_or(MemoryMutationEvidenceError::Length)?;
        let fragments_end = translations_end
            .checked_add(
                fragment_count
                    .checked_mul(MEMORY_MUTATION_FRAGMENT_V1_BYTES)
                    .ok_or(MemoryMutationEvidenceError::Length)?,
            )
            .ok_or(MemoryMutationEvidenceError::Length)?;
        let mappings_end = fragments_end
            .checked_add(
                mapping_count
                    .checked_mul(MEMORY_MAPPING_RECORD_V1_BYTES)
                    .ok_or(MemoryMutationEvidenceError::Length)?,
            )
            .ok_or(MemoryMutationEvidenceError::Length)?;
        let dirty_ranges_end = mappings_end
            .checked_add(
                dirty_count
                    .checked_mul(MEMORY_DIRTY_RANGE_V1_BYTES)
                    .ok_or(MemoryMutationEvidenceError::Length)?,
            )
            .ok_or(MemoryMutationEvidenceError::Length)?;
        let expected = dirty_ranges_end
            .checked_add(
                inline_len
                    .checked_mul(2)
                    .ok_or(MemoryMutationEvidenceError::Length)?,
            )
            .ok_or(MemoryMutationEvidenceError::Length)?;
        if expected != bytes.len() || expected > HARD_FAULT_PAYLOAD_BYTES as usize {
            return Err(MemoryMutationEvidenceError::Length);
        }
        let translations = bytes[MEMORY_MUTATION_EVIDENCE_HEADER_V1_BYTES..translations_end]
            .chunks_exact(MEMORY_TRANSLATION_RECORD_V1_BYTES)
            .map(MemoryTranslationRecordV1::decode)
            .collect::<Result<Vec<_>, _>>()?;
        let fragments = bytes[translations_end..fragments_end]
            .chunks_exact(MEMORY_MUTATION_FRAGMENT_V1_BYTES)
            .map(MemoryMutationFragmentV1::decode)
            .collect::<Result<Vec<_>, _>>()?;
        let mappings = bytes[fragments_end..mappings_end]
            .chunks_exact(MEMORY_MAPPING_RECORD_V1_BYTES)
            .map(MemoryMappingRecordV1::decode)
            .collect::<Result<Vec<_>, _>>()?;
        let dirty_ranges = bytes[mappings_end..dirty_ranges_end]
            .chunks_exact(MEMORY_DIRTY_RANGE_V1_BYTES)
            .map(MemoryDirtyRangeV1::decode)
            .collect::<Result<Vec<_>, _>>()?;
        let value = Self {
            address_space: MemoryMutationAddressSpace::decode(read_u16(bytes, 12))
                .map_err(MemoryMutationEvidenceError::Payload)?,
            transform: MemoryMutationTransformKind::decode(read_u16(bytes, 14))
                .map_err(MemoryMutationEvidenceError::Payload)?,
            vcpu_index: read_u32(bytes, 16),
            length: read_u32(bytes, 20),
            address: read_u64(bytes, 24),
            observed_icount: read_u64(bytes, 32),
            translations,
            fragments,
            mappings,
            dirty_ranges,
            before_sha256: read_array32(bytes, 64),
            after_sha256: read_array32(bytes, 96),
            mapping_generation_sha256: read_array32(bytes, 160),
            dirty_pages_sha256: read_array32(bytes, 192),
            invalidated_start: (flags & MEMORY_MUTATION_EVIDENCE_FLAG_TB_INVALIDATED != 0)
                .then(|| read_u64(bytes, 224)),
            invalidated_end: (flags & MEMORY_MUTATION_EVIDENCE_FLAG_TB_INVALIDATED != 0)
                .then(|| read_u64(bytes, 232)),
            target_node_hash: read_array32(bytes, 240),
            node_fingerprint: read_array32(bytes, 272),
            before_bytes: bytes[dirty_ranges_end..dirty_ranges_end + inline_len].to_vec(),
            after_bytes: bytes[dirty_ranges_end + inline_len..].to_vec(),
        };
        let translation_sha = read_array32(bytes, 128);
        let expected_translation = if value.translations.is_empty() {
            [0; 32]
        } else {
            memory_translation_sha256(value.vcpu_index, &value.translations)?
        };
        if translation_sha != expected_translation {
            return Err(MemoryMutationEvidenceError::Digest);
        }
        value.validate()?;
        Ok(value)
    }

    fn validate(&self) -> Result<(), MemoryMutationEvidenceError> {
        let length = self.length as usize;
        let inline = !self.before_bytes.is_empty() || !self.after_bytes.is_empty();
        let before_inline_sha256: [u8; 32] = Sha256::digest(&self.before_bytes).into();
        let after_inline_sha256: [u8; 32] = Sha256::digest(&self.after_bytes).into();
        let inline_digest_invalid = if inline {
            self.before_sha256 != before_inline_sha256 || self.after_sha256 != after_inline_sha256
        } else {
            self.before_sha256 == [0; 32] || self.after_sha256 == [0; 32]
        };
        if length == 0
            || (inline
                && (length > MEMORY_MUTATION_EVIDENCE_INLINE_BYTES as usize
                    || self.before_bytes.len() != length
                    || self.after_bytes.len() != length))
            || (!inline && (!self.before_bytes.is_empty() || !self.after_bytes.is_empty()))
            || inline_digest_invalid
            || self.target_node_hash == [0; 32]
        {
            return Err(MemoryMutationEvidenceError::Digest);
        }
        if memory_mapping_sha256(&self.mappings)? != self.mapping_generation_sha256
            || memory_dirty_ranges_sha256(&self.dirty_ranges)? != self.dirty_pages_sha256
            || self.expected_node_fingerprint()? != self.node_fingerprint
        {
            return Err(MemoryMutationEvidenceError::Digest);
        }
        let covered_fragment_bytes =
            self.fragments
                .iter()
                .try_fold(0_u32, |expected_offset, fragment| {
                    fragment
                        .validate()
                        .ok()
                        .filter(|()| fragment.request_offset == expected_offset)
                        .and_then(|()| expected_offset.checked_add(fragment.length))
                });
        if self.fragments.is_empty() || covered_fragment_bytes != Some(self.length) {
            return Err(MemoryMutationEvidenceError::Fragment);
        }
        if memory_dirty_ranges_for_fragments(&self.fragments)? != self.dirty_ranges {
            return Err(MemoryMutationEvidenceError::DirtyRange);
        }
        if self.fragments.iter().any(|fragment| {
            !self.mappings.iter().any(|mapping| {
                fragment.guest_physical_start >= mapping.guest_physical_start
                    && fragment
                        .guest_physical_start
                        .checked_add(u64::from(fragment.length))
                        .is_some_and(|end| {
                            mapping
                                .guest_physical_start
                                .checked_add(mapping.length)
                                .is_some_and(|mapping_end| end <= mapping_end)
                        })
                    && fragment.memory_region_identity_sha256
                        == mapping.memory_region_identity_sha256
                    && fragment.ram_block_identity_sha256 == mapping.ram_block_identity_sha256
                    && fragment.memory_region_offset
                        == mapping.memory_region_offset
                            + (fragment.guest_physical_start - mapping.guest_physical_start)
                    && fragment.ram_block_offset
                        == mapping.ram_block_offset
                            + (fragment.guest_physical_start - mapping.guest_physical_start)
            })
        }) {
            return Err(MemoryMutationEvidenceError::Mapping);
        }
        match self.address_space {
            MemoryMutationAddressSpace::GuestPhysical
                if self.vcpu_index != u32::MAX || !self.translations.is_empty() =>
            {
                return Err(MemoryMutationEvidenceError::Translation);
            }
            MemoryMutationAddressSpace::GuestVirtual
                if self.vcpu_index == u32::MAX || self.translations.is_empty() =>
            {
                return Err(MemoryMutationEvidenceError::Translation);
            }
            MemoryMutationAddressSpace::GuestPhysical
            | MemoryMutationAddressSpace::GuestVirtual => {}
        }
        if self.address_space == MemoryMutationAddressSpace::GuestPhysical
            && self.fragments.iter().any(|fragment| {
                self.address.checked_add(u64::from(fragment.request_offset))
                    != Some(fragment.guest_physical_start)
            })
        {
            return Err(MemoryMutationEvidenceError::Fragment);
        }
        if !self.translations.is_empty() {
            let mut request_offset = 0_u32;
            for record in &self.translations {
                record.validate()?;
                let virtual_address = self
                    .address
                    .checked_add(u64::from(request_offset))
                    .ok_or(MemoryMutationEvidenceError::Translation)?;
                let page_end = record
                    .virtual_page_start
                    .checked_add(record.page_size)
                    .ok_or(MemoryMutationEvidenceError::Translation)?;
                let remaining = self.length - request_offset;
                let expected_covered = page_end
                    .checked_sub(virtual_address)
                    .map(|available| available.min(u64::from(remaining)))
                    .and_then(|covered| u32::try_from(covered).ok());
                if virtual_address < record.virtual_page_start
                    || expected_covered != Some(record.covered_bytes)
                    || record.permissions
                        & (MEMORY_TRANSLATION_PERMISSION_READ | MEMORY_TRANSLATION_PERMISSION_WRITE)
                        != (MEMORY_TRANSLATION_PERMISSION_READ
                            | MEMORY_TRANSLATION_PERMISSION_WRITE)
                {
                    return Err(MemoryMutationEvidenceError::Translation);
                }
                request_offset = request_offset
                    .checked_add(record.covered_bytes)
                    .ok_or(MemoryMutationEvidenceError::Translation)?;
            }
            if request_offset != self.length
                || self.fragments.iter().any(|fragment| {
                    let virtual_address =
                        self.address.checked_add(u64::from(fragment.request_offset));
                    self.translations.iter().all(|record| {
                        let page_end = record
                            .virtual_page_start
                            .checked_add(record.page_size)
                            .unwrap_or(record.virtual_page_start);
                        virtual_address.is_none_or(|address| {
                            address < record.virtual_page_start
                                || address >= page_end
                                || address
                                    .checked_add(u64::from(fragment.length))
                                    .is_none_or(|end| end > page_end)
                                || record
                                    .physical_page_start
                                    .checked_add(address - record.virtual_page_start)
                                    != Some(fragment.guest_physical_start)
                        })
                    })
                })
            {
                return Err(MemoryMutationEvidenceError::Translation);
            }
        }
        let mut expected_invalidated_start = None;
        let mut expected_invalidated_end = None;
        for fragment in &self.fragments {
            let invalidated = fragment.flags & MEMORY_MUTATION_FRAGMENT_TB_INVALIDATED != 0;
            let requires_invalidation = match self.address_space {
                MemoryMutationAddressSpace::GuestPhysical => true,
                MemoryMutationAddressSpace::GuestVirtual => {
                    let virtual_start = self
                        .address
                        .checked_add(u64::from(fragment.request_offset))
                        .ok_or(MemoryMutationEvidenceError::Invalidation)?;
                    let virtual_end = virtual_start
                        .checked_add(u64::from(fragment.length))
                        .ok_or(MemoryMutationEvidenceError::Invalidation)?;
                    self.translations.iter().any(|record| {
                        let page_end = record.virtual_page_start.checked_add(record.page_size);
                        virtual_start >= record.virtual_page_start
                            && page_end.is_some_and(|end| virtual_end <= end)
                            && record.permissions & MEMORY_TRANSLATION_PERMISSION_EXECUTE != 0
                    })
                }
            };
            if requires_invalidation && !invalidated {
                return Err(MemoryMutationEvidenceError::Invalidation);
            }
            if invalidated {
                let end = fragment
                    .guest_physical_start
                    .checked_add(u64::from(fragment.length) - 1)
                    .ok_or(MemoryMutationEvidenceError::Invalidation)?;
                expected_invalidated_start = Some(
                    expected_invalidated_start
                        .map_or(fragment.guest_physical_start, |start: u64| {
                            start.min(fragment.guest_physical_start)
                        }),
                );
                expected_invalidated_end =
                    Some(expected_invalidated_end.map_or(end, |previous: u64| previous.max(end)));
            }
        }
        if (self.invalidated_start, self.invalidated_end)
            != (expected_invalidated_start, expected_invalidated_end)
        {
            return Err(MemoryMutationEvidenceError::Invalidation);
        }
        Ok(())
    }

    /// Computes the canonical post-mutation boundary fingerprint.
    ///
    /// The fingerprint binds the node identity and exact icount to the mutation
    /// coordinates, before/after bytes, translations, mapping generation,
    /// dirty ranges, and translated-block invalidation evidence.
    ///
    /// # Errors
    ///
    /// Returns [`MemoryMutationEvidenceError::Translation`] when the embedded
    /// translation sequence is invalid.
    pub fn expected_node_fingerprint(&self) -> Result<[u8; 32], MemoryMutationEvidenceError> {
        let translation_sha256 = if self.translations.is_empty() {
            [0; 32]
        } else {
            memory_translation_sha256(self.vcpu_index, &self.translations)?
        };
        let mut hasher = Sha256::new();
        hasher.update(MEMORY_BOUNDARY_FINGERPRINT_SHA256_DOMAIN_V1);
        hasher.update(self.target_node_hash);
        hasher.update(self.observed_icount.to_le_bytes());
        hasher.update((self.address_space as u16).to_le_bytes());
        hasher.update((self.transform as u16).to_le_bytes());
        hasher.update(self.vcpu_index.to_le_bytes());
        hasher.update(self.address.to_le_bytes());
        hasher.update(self.length.to_le_bytes());
        hasher.update(self.before_sha256);
        hasher.update(self.after_sha256);
        hasher.update(translation_sha256);
        hasher.update(self.mapping_generation_sha256);
        hasher.update(self.dirty_pages_sha256);
        hasher.update([u8::from(self.invalidated_start.is_some())]);
        hasher.update(self.invalidated_start.unwrap_or(0).to_le_bytes());
        hasher.update(self.invalidated_end.unwrap_or(0).to_le_bytes());
        Ok(hasher.finalize().into())
    }
}

/// Memory translation or mutation-evidence codec failure.
#[derive(Clone, Debug, Error, PartialEq, Eq)]
pub enum MemoryMutationEvidenceError {
    /// Framing, version, flags, or reserved bytes are invalid.
    #[error("memory mutation evidence framing is invalid")]
    Framing,
    /// A canonical translation record or sequence is invalid.
    #[error("memory translation evidence is invalid")]
    Translation,
    /// A stable MemoryRegion or RAMBlock identity is invalid.
    #[error("memory object identity is invalid")]
    Identity,
    /// A resolved RAM fragment record or sequence is invalid.
    #[error("memory mutation fragment evidence is invalid")]
    Fragment,
    /// A flattened writable-RAM mapping record or sequence is invalid.
    #[error("memory mapping evidence is invalid")]
    Mapping,
    /// A dirty-page range record or sequence is invalid.
    #[error("memory dirty-page evidence is invalid")]
    DirtyRange,
    /// Evidence length is inconsistent or exceeds the transport.
    #[error("memory mutation evidence length is invalid")]
    Length,
    /// A before, after, or translation digest is inconsistent.
    #[error("memory mutation evidence digest is invalid")]
    Digest,
    /// The translated-block invalidation interval is inconsistent.
    #[error("memory mutation invalidation evidence is invalid")]
    Invalidation,
    /// A shared memory-payload tag is invalid.
    #[error("memory mutation evidence payload tag is invalid: {0}")]
    Payload(MemoryMutationPayloadError),
}

pub(crate) fn emit_memory_evidence_c_header(out: &mut String) {
    let values = [
        (
            "CRUCIBLE_MEMORY_TRANSLATION_RECORD_V1_BYTES",
            MEMORY_TRANSLATION_RECORD_V1_BYTES as u64,
        ),
        (
            "CRUCIBLE_MEMORY_TRANSLATION_VIRTUAL_PAGE_OFFSET",
            MEMORY_TRANSLATION_VIRTUAL_PAGE_OFFSET as u64,
        ),
        (
            "CRUCIBLE_MEMORY_TRANSLATION_PHYSICAL_PAGE_OFFSET",
            MEMORY_TRANSLATION_PHYSICAL_PAGE_OFFSET as u64,
        ),
        (
            "CRUCIBLE_MEMORY_TRANSLATION_PAGE_SIZE_OFFSET",
            MEMORY_TRANSLATION_PAGE_SIZE_OFFSET as u64,
        ),
        (
            "CRUCIBLE_MEMORY_TRANSLATION_PERMISSIONS_OFFSET",
            MEMORY_TRANSLATION_PERMISSIONS_OFFSET as u64,
        ),
        (
            "CRUCIBLE_MEMORY_TRANSLATION_ATTRIBUTES_OFFSET",
            MEMORY_TRANSLATION_ATTRIBUTES_OFFSET as u64,
        ),
        (
            "CRUCIBLE_MEMORY_TRANSLATION_COVERED_BYTES_OFFSET",
            MEMORY_TRANSLATION_COVERED_BYTES_OFFSET as u64,
        ),
        (
            "CRUCIBLE_MEMORY_TRANSLATION_PERMISSION_READ",
            MEMORY_TRANSLATION_PERMISSION_READ as u64,
        ),
        (
            "CRUCIBLE_MEMORY_TRANSLATION_PERMISSION_WRITE",
            MEMORY_TRANSLATION_PERMISSION_WRITE as u64,
        ),
        (
            "CRUCIBLE_MEMORY_TRANSLATION_PERMISSION_EXECUTE",
            MEMORY_TRANSLATION_PERMISSION_EXECUTE as u64,
        ),
        (
            "CRUCIBLE_MEMORY_TRANSLATION_PERMISSION_USER",
            MEMORY_TRANSLATION_PERMISSION_USER as u64,
        ),
        (
            "CRUCIBLE_MEMORY_TRANSLATION_PERMISSIONS_V1_MASK",
            MEMORY_TRANSLATION_PERMISSIONS_V1_MASK as u64,
        ),
        (
            "CRUCIBLE_MEMORY_TRANSLATION_ATTRIBUTE_SECURE",
            MEMORY_TRANSLATION_ATTRIBUTE_SECURE as u64,
        ),
        (
            "CRUCIBLE_MEMORY_TRANSLATION_ATTRIBUTE_USER",
            MEMORY_TRANSLATION_ATTRIBUTE_USER as u64,
        ),
        (
            "CRUCIBLE_MEMORY_TRANSLATION_ATTRIBUTES_V1_MASK",
            MEMORY_TRANSLATION_ATTRIBUTES_V1_MASK as u64,
        ),
        (
            "CRUCIBLE_MEMORY_MUTATION_FRAGMENT_V1_BYTES",
            MEMORY_MUTATION_FRAGMENT_V1_BYTES as u64,
        ),
        (
            "CRUCIBLE_MEMORY_MUTATION_FRAGMENT_GPA_OFFSET",
            MEMORY_MUTATION_FRAGMENT_GPA_OFFSET as u64,
        ),
        (
            "CRUCIBLE_MEMORY_MUTATION_FRAGMENT_REQUEST_OFFSET",
            MEMORY_MUTATION_FRAGMENT_REQUEST_OFFSET as u64,
        ),
        (
            "CRUCIBLE_MEMORY_MUTATION_FRAGMENT_LENGTH_OFFSET",
            MEMORY_MUTATION_FRAGMENT_LENGTH_OFFSET as u64,
        ),
        (
            "CRUCIBLE_MEMORY_MUTATION_FRAGMENT_FLAGS_OFFSET",
            MEMORY_MUTATION_FRAGMENT_FLAGS_OFFSET as u64,
        ),
        (
            "CRUCIBLE_MEMORY_MUTATION_FRAGMENT_RESERVED_OFFSET",
            MEMORY_MUTATION_FRAGMENT_RESERVED_OFFSET as u64,
        ),
        (
            "CRUCIBLE_MEMORY_MUTATION_FRAGMENT_REGION_OFFSET",
            MEMORY_MUTATION_FRAGMENT_REGION_OFFSET as u64,
        ),
        (
            "CRUCIBLE_MEMORY_MUTATION_FRAGMENT_RAM_BLOCK_OFFSET",
            MEMORY_MUTATION_FRAGMENT_RAM_BLOCK_OFFSET as u64,
        ),
        (
            "CRUCIBLE_MEMORY_MUTATION_FRAGMENT_REGION_IDENTITY_OFFSET",
            MEMORY_MUTATION_FRAGMENT_REGION_IDENTITY_OFFSET as u64,
        ),
        (
            "CRUCIBLE_MEMORY_MUTATION_FRAGMENT_RAM_BLOCK_IDENTITY_OFFSET",
            MEMORY_MUTATION_FRAGMENT_RAM_BLOCK_IDENTITY_OFFSET as u64,
        ),
        (
            "CRUCIBLE_MEMORY_MUTATION_FRAGMENT_TB_INVALIDATED",
            MEMORY_MUTATION_FRAGMENT_TB_INVALIDATED as u64,
        ),
        (
            "CRUCIBLE_MEMORY_MUTATION_FRAGMENT_FLAGS_V1_MASK",
            MEMORY_MUTATION_FRAGMENT_FLAGS_V1_MASK as u64,
        ),
        (
            "CRUCIBLE_MEMORY_MAPPING_RECORD_V1_BYTES",
            MEMORY_MAPPING_RECORD_V1_BYTES as u64,
        ),
        (
            "CRUCIBLE_MEMORY_MAPPING_GPA_OFFSET",
            MEMORY_MAPPING_GPA_OFFSET as u64,
        ),
        (
            "CRUCIBLE_MEMORY_MAPPING_LENGTH_OFFSET",
            MEMORY_MAPPING_LENGTH_OFFSET as u64,
        ),
        (
            "CRUCIBLE_MEMORY_MAPPING_REGION_OFFSET",
            MEMORY_MAPPING_REGION_OFFSET as u64,
        ),
        (
            "CRUCIBLE_MEMORY_MAPPING_RAM_BLOCK_OFFSET",
            MEMORY_MAPPING_RAM_BLOCK_OFFSET as u64,
        ),
        (
            "CRUCIBLE_MEMORY_MAPPING_FLAGS_OFFSET",
            MEMORY_MAPPING_FLAGS_OFFSET as u64,
        ),
        (
            "CRUCIBLE_MEMORY_MAPPING_RESERVED_OFFSET",
            MEMORY_MAPPING_RESERVED_OFFSET as u64,
        ),
        (
            "CRUCIBLE_MEMORY_MAPPING_REGION_IDENTITY_OFFSET",
            MEMORY_MAPPING_REGION_IDENTITY_OFFSET as u64,
        ),
        (
            "CRUCIBLE_MEMORY_MAPPING_RAM_BLOCK_IDENTITY_OFFSET",
            MEMORY_MAPPING_RAM_BLOCK_IDENTITY_OFFSET as u64,
        ),
        (
            "CRUCIBLE_MEMORY_MAPPING_FLAGS_V1_MASK",
            MEMORY_MAPPING_FLAGS_V1_MASK as u64,
        ),
        (
            "CRUCIBLE_MEMORY_MAPPING_HARD_RECORDS",
            HARD_MEMORY_MAPPING_RECORDS as u64,
        ),
        (
            "CRUCIBLE_MEMORY_DIRTY_PAGE_BYTES_V1",
            MEMORY_DIRTY_PAGE_BYTES_V1 as u64,
        ),
        (
            "CRUCIBLE_MEMORY_DIRTY_RANGE_V1_BYTES",
            MEMORY_DIRTY_RANGE_V1_BYTES as u64,
        ),
        (
            "CRUCIBLE_MEMORY_DIRTY_RANGE_RAM_BLOCK_IDENTITY_OFFSET",
            MEMORY_DIRTY_RANGE_RAM_BLOCK_IDENTITY_OFFSET as u64,
        ),
        (
            "CRUCIBLE_MEMORY_DIRTY_RANGE_RAM_BLOCK_OFFSET",
            MEMORY_DIRTY_RANGE_RAM_BLOCK_OFFSET as u64,
        ),
        (
            "CRUCIBLE_MEMORY_DIRTY_RANGE_PAGE_COUNT_OFFSET",
            MEMORY_DIRTY_RANGE_PAGE_COUNT_OFFSET as u64,
        ),
        (
            "CRUCIBLE_MEMORY_DIRTY_RANGE_PAGE_SIZE_OFFSET",
            MEMORY_DIRTY_RANGE_PAGE_SIZE_OFFSET as u64,
        ),
        (
            "CRUCIBLE_MEMORY_MUTATION_EVIDENCE_VERSION_V1",
            MEMORY_MUTATION_EVIDENCE_VERSION_V1 as u64,
        ),
        (
            "CRUCIBLE_MEMORY_MUTATION_EVIDENCE_HEADER_V1_BYTES",
            MEMORY_MUTATION_EVIDENCE_HEADER_V1_BYTES as u64,
        ),
        (
            "CRUCIBLE_MEMORY_MUTATION_EVIDENCE_VERSION_OFFSET",
            MEMORY_MUTATION_EVIDENCE_VERSION_OFFSET as u64,
        ),
        (
            "CRUCIBLE_MEMORY_MUTATION_EVIDENCE_FLAGS_OFFSET",
            MEMORY_MUTATION_EVIDENCE_FLAGS_OFFSET as u64,
        ),
        (
            "CRUCIBLE_MEMORY_MUTATION_EVIDENCE_ADDRESS_SPACE_OFFSET",
            MEMORY_MUTATION_EVIDENCE_ADDRESS_SPACE_OFFSET as u64,
        ),
        (
            "CRUCIBLE_MEMORY_MUTATION_EVIDENCE_TRANSFORM_OFFSET",
            MEMORY_MUTATION_EVIDENCE_TRANSFORM_OFFSET as u64,
        ),
        (
            "CRUCIBLE_MEMORY_MUTATION_EVIDENCE_VCPU_INDEX_OFFSET",
            MEMORY_MUTATION_EVIDENCE_VCPU_INDEX_OFFSET as u64,
        ),
        (
            "CRUCIBLE_MEMORY_MUTATION_EVIDENCE_LENGTH_OFFSET",
            MEMORY_MUTATION_EVIDENCE_LENGTH_OFFSET as u64,
        ),
        (
            "CRUCIBLE_MEMORY_MUTATION_EVIDENCE_ADDRESS_OFFSET",
            MEMORY_MUTATION_EVIDENCE_ADDRESS_OFFSET as u64,
        ),
        (
            "CRUCIBLE_MEMORY_MUTATION_EVIDENCE_OBSERVED_ICOUNT_OFFSET",
            MEMORY_MUTATION_EVIDENCE_OBSERVED_ICOUNT_OFFSET as u64,
        ),
        (
            "CRUCIBLE_MEMORY_MUTATION_EVIDENCE_TRANSLATION_COUNT_OFFSET",
            MEMORY_MUTATION_EVIDENCE_TRANSLATION_COUNT_OFFSET as u64,
        ),
        (
            "CRUCIBLE_MEMORY_MUTATION_EVIDENCE_FRAGMENT_COUNT_OFFSET",
            MEMORY_MUTATION_EVIDENCE_FRAGMENT_COUNT_OFFSET as u64,
        ),
        (
            "CRUCIBLE_MEMORY_MUTATION_EVIDENCE_MAPPING_COUNT_OFFSET",
            MEMORY_MUTATION_EVIDENCE_MAPPING_COUNT_OFFSET as u64,
        ),
        (
            "CRUCIBLE_MEMORY_MUTATION_EVIDENCE_DIRTY_COUNT_OFFSET",
            MEMORY_MUTATION_EVIDENCE_DIRTY_COUNT_OFFSET as u64,
        ),
        (
            "CRUCIBLE_MEMORY_MUTATION_EVIDENCE_INLINE_LENGTH_OFFSET",
            MEMORY_MUTATION_EVIDENCE_INLINE_LENGTH_OFFSET as u64,
        ),
        (
            "CRUCIBLE_MEMORY_MUTATION_EVIDENCE_RESERVED_OFFSET",
            MEMORY_MUTATION_EVIDENCE_RESERVED_OFFSET as u64,
        ),
        (
            "CRUCIBLE_MEMORY_MUTATION_EVIDENCE_BEFORE_SHA256_OFFSET",
            MEMORY_MUTATION_EVIDENCE_BEFORE_SHA256_OFFSET as u64,
        ),
        (
            "CRUCIBLE_MEMORY_MUTATION_EVIDENCE_AFTER_SHA256_OFFSET",
            MEMORY_MUTATION_EVIDENCE_AFTER_SHA256_OFFSET as u64,
        ),
        (
            "CRUCIBLE_MEMORY_MUTATION_EVIDENCE_TRANSLATION_SHA256_OFFSET",
            MEMORY_MUTATION_EVIDENCE_TRANSLATION_SHA256_OFFSET as u64,
        ),
        (
            "CRUCIBLE_MEMORY_MUTATION_EVIDENCE_MAPPING_SHA256_OFFSET",
            MEMORY_MUTATION_EVIDENCE_MAPPING_SHA256_OFFSET as u64,
        ),
        (
            "CRUCIBLE_MEMORY_MUTATION_EVIDENCE_DIRTY_SHA256_OFFSET",
            MEMORY_MUTATION_EVIDENCE_DIRTY_SHA256_OFFSET as u64,
        ),
        (
            "CRUCIBLE_MEMORY_MUTATION_EVIDENCE_INVALIDATED_START_OFFSET",
            MEMORY_MUTATION_EVIDENCE_INVALIDATED_START_OFFSET as u64,
        ),
        (
            "CRUCIBLE_MEMORY_MUTATION_EVIDENCE_INVALIDATED_END_OFFSET",
            MEMORY_MUTATION_EVIDENCE_INVALIDATED_END_OFFSET as u64,
        ),
        (
            "CRUCIBLE_MEMORY_MUTATION_EVIDENCE_TARGET_NODE_HASH_OFFSET",
            MEMORY_MUTATION_EVIDENCE_TARGET_NODE_HASH_OFFSET as u64,
        ),
        (
            "CRUCIBLE_MEMORY_MUTATION_EVIDENCE_NODE_FINGERPRINT_OFFSET",
            MEMORY_MUTATION_EVIDENCE_NODE_FINGERPRINT_OFFSET as u64,
        ),
        (
            "CRUCIBLE_MEMORY_MUTATION_EVIDENCE_INLINE_BYTES",
            MEMORY_MUTATION_EVIDENCE_INLINE_BYTES as u64,
        ),
        (
            "CRUCIBLE_MEMORY_MUTATION_EVIDENCE_FLAG_INLINE_BYTES",
            MEMORY_MUTATION_EVIDENCE_FLAG_INLINE_BYTES as u64,
        ),
        (
            "CRUCIBLE_MEMORY_MUTATION_EVIDENCE_FLAG_TB_INVALIDATED",
            MEMORY_MUTATION_EVIDENCE_FLAG_TB_INVALIDATED as u64,
        ),
        (
            "CRUCIBLE_MEMORY_MUTATION_EVIDENCE_FLAGS_V1_MASK",
            MEMORY_MUTATION_EVIDENCE_FLAGS_V1_MASK as u64,
        ),
    ];
    out.push_str("#define CRUCIBLE_MEMORY_TRANSLATION_SHA256_DOMAIN_V1 \"crucible.memory-translation.v1\\0\"\n");
    out.push_str("#define CRUCIBLE_MEMORY_TRANSLATION_SHA256_DOMAIN_V1_BYTES 31\n");
    out.push_str("#define CRUCIBLE_MEMORY_REGION_IDENTITY_SHA256_DOMAIN_V1 \"crucible.memory-region-identity.v1\\0\"\n");
    out.push_str("#define CRUCIBLE_MEMORY_REGION_IDENTITY_SHA256_DOMAIN_V1_BYTES 35\n");
    out.push_str("#define CRUCIBLE_MEMORY_RAM_BLOCK_IDENTITY_SHA256_DOMAIN_V1 \"crucible.ram-block-identity.v1\\0\"\n");
    out.push_str("#define CRUCIBLE_MEMORY_RAM_BLOCK_IDENTITY_SHA256_DOMAIN_V1_BYTES 31\n");
    out.push_str(
        "#define CRUCIBLE_MEMORY_MAPPING_SHA256_DOMAIN_V1 \"crucible.memory-mapping.v1\\0\"\n",
    );
    out.push_str("#define CRUCIBLE_MEMORY_MAPPING_SHA256_DOMAIN_V1_BYTES 27\n");
    out.push_str(
        "#define CRUCIBLE_MEMORY_DIRTY_SHA256_DOMAIN_V1 \"crucible.memory-dirty-pages.v1\\0\"\n",
    );
    out.push_str("#define CRUCIBLE_MEMORY_DIRTY_SHA256_DOMAIN_V1_BYTES 31\n");
    out.push_str("#define CRUCIBLE_MEMORY_BOUNDARY_FINGERPRINT_SHA256_DOMAIN_V1 \"crucible.memory-boundary-fingerprint.v1\\0\"\n");
    out.push_str("#define CRUCIBLE_MEMORY_BOUNDARY_FINGERPRINT_SHA256_DOMAIN_V1_BYTES 40\n");
    out.push_str("#define CRUCIBLE_MEMORY_MUTATION_PRECONDITION_SHA256_DOMAIN_V1 \"crucible.memory-mutation-precondition.v1\\0\"\n");
    out.push_str("#define CRUCIBLE_MEMORY_MUTATION_PRECONDITION_SHA256_DOMAIN_V1_BYTES 41\n");
    out.push_str("#define CRUCIBLE_MEMORY_MUTATION_EVIDENCE_MAGIC_V1 \"CRUCMER1\"\n");
    for (name, value) in values {
        let _ = writeln!(out, "#define {name} {value}");
    }
}

fn read_u16(bytes: &[u8], offset: usize) -> u16 {
    u16::from_le_bytes([bytes[offset], bytes[offset + 1]])
}
fn read_u32(bytes: &[u8], offset: usize) -> u32 {
    u32::from_le_bytes([
        bytes[offset],
        bytes[offset + 1],
        bytes[offset + 2],
        bytes[offset + 3],
    ])
}
fn read_u64(bytes: &[u8], offset: usize) -> u64 {
    u64::from_le_bytes([
        bytes[offset],
        bytes[offset + 1],
        bytes[offset + 2],
        bytes[offset + 3],
        bytes[offset + 4],
        bytes[offset + 5],
        bytes[offset + 6],
        bytes[offset + 7],
    ])
}
fn read_array32(bytes: &[u8], offset: usize) -> [u8; 32] {
    let mut value = [0; 32];
    value.copy_from_slice(&bytes[offset..offset + 32]);
    value
}
fn put_u16(bytes: &mut [u8], offset: usize, value: u16) {
    bytes[offset..offset + 2].copy_from_slice(&value.to_le_bytes());
}
fn put_u32(bytes: &mut [u8], offset: usize, value: u32) {
    bytes[offset..offset + 4].copy_from_slice(&value.to_le_bytes());
}
fn put_u64(bytes: &mut [u8], offset: usize, value: u64) {
    bytes[offset..offset + 8].copy_from_slice(&value.to_le_bytes());
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn prepared_precondition_binds_every_boundary_digest() {
        let baseline = memory_mutation_precondition_sha256([1; 32], [2; 32], [3; 32], [4; 32]);
        assert_ne!(
            baseline,
            memory_mutation_precondition_sha256([9; 32], [2; 32], [3; 32], [4; 32])
        );
        assert_ne!(
            baseline,
            memory_mutation_precondition_sha256([1; 32], [9; 32], [3; 32], [4; 32])
        );
        assert_ne!(
            baseline,
            memory_mutation_precondition_sha256([1; 32], [2; 32], [9; 32], [4; 32])
        );
        assert_ne!(
            baseline,
            memory_mutation_precondition_sha256([1; 32], [2; 32], [3; 32], [9; 32])
        );
    }

    #[test]
    fn translation_digest_and_evidence_round_trip() {
        let records = vec![MemoryTranslationRecordV1 {
            virtual_page_start: 0x4000,
            physical_page_start: 0x8000,
            page_size: 4096,
            permissions: MEMORY_TRANSLATION_PERMISSION_READ
                | MEMORY_TRANSLATION_PERMISSION_WRITE
                | MEMORY_TRANSLATION_PERMISSION_EXECUTE,
            attributes: MEMORY_TRANSLATION_ATTRIBUTE_USER,
            covered_bytes: 3,
        }];
        let before = vec![1, 2, 3];
        let after = vec![0, 2, 7];
        let region_identity =
            memory_region_identity_sha256("/machine/unattached/system-memory", "ram")
                .unwrap_or_else(|error| panic!("region identity: {error}"));
        let ram_block_identity = memory_ram_block_identity_sha256("pc.ram")
            .unwrap_or_else(|error| panic!("RAMBlock identity: {error}"));
        let mappings = vec![MemoryMappingRecordV1 {
            guest_physical_start: 0,
            length: 0x1_0000,
            memory_region_offset: 0,
            ram_block_offset: 0,
            flags: 0,
            memory_region_identity_sha256: region_identity,
            ram_block_identity_sha256: ram_block_identity,
        }];
        let dirty_ranges = vec![MemoryDirtyRangeV1 {
            ram_block_identity_sha256: ram_block_identity,
            ram_block_offset: 0x8000,
            page_count: 1,
            page_size: MEMORY_DIRTY_PAGE_BYTES_V1,
        }];
        let mapping_generation_sha256 = memory_mapping_sha256(&mappings)
            .unwrap_or_else(|error| panic!("mapping digest: {error}"));
        let dirty_pages_sha256 = memory_dirty_ranges_sha256(&dirty_ranges)
            .unwrap_or_else(|error| panic!("dirty digest: {error}"));
        let mut evidence = MemoryMutationEvidenceV1 {
            address_space: MemoryMutationAddressSpace::GuestVirtual,
            transform: MemoryMutationTransformKind::BitFlip,
            vcpu_index: 0,
            address: 0x4001,
            length: 3,
            observed_icount: 11,
            translations: records,
            fragments: vec![MemoryMutationFragmentV1 {
                guest_physical_start: 0x8001,
                request_offset: 0,
                length: 3,
                flags: MEMORY_MUTATION_FRAGMENT_TB_INVALIDATED,
                memory_region_offset: 0x8001,
                ram_block_offset: 0x8001,
                memory_region_identity_sha256: region_identity,
                ram_block_identity_sha256: ram_block_identity,
            }],
            mappings,
            dirty_ranges,
            before_sha256: Sha256::digest(&before).into(),
            after_sha256: Sha256::digest(&after).into(),
            mapping_generation_sha256,
            dirty_pages_sha256,
            invalidated_start: Some(0x8001),
            invalidated_end: Some(0x8003),
            target_node_hash: [5; 32],
            node_fingerprint: [0; 32],
            before_bytes: before,
            after_bytes: after,
        };
        evidence.node_fingerprint = evidence
            .expected_node_fingerprint()
            .unwrap_or_else(|error| panic!("node fingerprint: {error}"));
        let bytes = evidence
            .encode()
            .unwrap_or_else(|error| panic!("encode evidence: {error}"));
        assert_eq!(
            MemoryMutationEvidenceV1::decode(&bytes),
            Ok(evidence.clone())
        );

        let mut wrong_interval = evidence.clone();
        wrong_interval.invalidated_start = Some(0x8000);
        wrong_interval.node_fingerprint = wrong_interval
            .expected_node_fingerprint()
            .unwrap_or_else(|error| panic!("wrong-interval fingerprint: {error}"));
        assert_eq!(
            wrong_interval.validate(),
            Err(MemoryMutationEvidenceError::Invalidation)
        );

        let mut missing_executable_invalidation = evidence.clone();
        missing_executable_invalidation.fragments[0].flags = 0;
        missing_executable_invalidation.invalidated_start = None;
        missing_executable_invalidation.invalidated_end = None;
        missing_executable_invalidation.node_fingerprint = missing_executable_invalidation
            .expected_node_fingerprint()
            .unwrap_or_else(|error| panic!("missing-invalidation fingerprint: {error}"));
        assert_eq!(
            missing_executable_invalidation.validate(),
            Err(MemoryMutationEvidenceError::Invalidation)
        );

        let mut missing_physical_invalidation = evidence.clone();
        missing_physical_invalidation.address_space = MemoryMutationAddressSpace::GuestPhysical;
        missing_physical_invalidation.vcpu_index = u32::MAX;
        missing_physical_invalidation.address = 0x8001;
        missing_physical_invalidation.translations.clear();
        missing_physical_invalidation.fragments[0].flags = 0;
        missing_physical_invalidation.invalidated_start = None;
        missing_physical_invalidation.invalidated_end = None;
        missing_physical_invalidation.node_fingerprint = missing_physical_invalidation
            .expected_node_fingerprint()
            .unwrap_or_else(|error| panic!("physical-invalidation fingerprint: {error}"));
        assert_eq!(
            missing_physical_invalidation.validate(),
            Err(MemoryMutationEvidenceError::Invalidation)
        );

        let mut hidden_interval = bytes;
        let flags = read_u16(&hidden_interval, MEMORY_MUTATION_EVIDENCE_FLAGS_OFFSET)
            & !MEMORY_MUTATION_EVIDENCE_FLAG_TB_INVALIDATED;
        put_u16(
            &mut hidden_interval,
            MEMORY_MUTATION_EVIDENCE_FLAGS_OFFSET,
            flags,
        );
        assert_eq!(
            MemoryMutationEvidenceV1::decode(&hidden_interval),
            Err(MemoryMutationEvidenceError::Invalidation)
        );
    }
}
