//! Translation and resolved RAM-fragment evidence records.

use super::*;

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

    pub(super) fn validate(self) -> Result<(), MemoryMutationEvidenceError> {
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

    pub(super) fn validate(self) -> Result<(), MemoryMutationEvidenceError> {
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
