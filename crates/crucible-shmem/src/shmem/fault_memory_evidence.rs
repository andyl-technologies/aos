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

/// Computes a stable identity digest for a canonical QEMU MemoryRegion path.
///
/// The length prefix makes the byte framing explicit across independent Rust
/// and C implementations. The QEMU side supplies the full canonical owner path
/// and never a host pointer.
///
/// # Errors
///
/// Returns [`MemoryMutationEvidenceError::Identity`] when the identity is
/// empty, contains a NUL byte, or exceeds the version-1 length field.
pub fn memory_region_identity_sha256(
    identity: &str,
) -> Result<[u8; 32], MemoryMutationEvidenceError> {
    memory_object_identity_sha256(MEMORY_REGION_IDENTITY_SHA256_DOMAIN_V1, identity)
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
    memory_object_identity_sha256(MEMORY_RAM_BLOCK_IDENTITY_SHA256_DOMAIN_V1, identity)
}

fn memory_object_identity_sha256(
    domain: &[u8],
    identity: &str,
) -> Result<[u8; 32], MemoryMutationEvidenceError> {
    if identity.is_empty() || identity.as_bytes().contains(&0) {
        return Err(MemoryMutationEvidenceError::Identity);
    }
    let length =
        u32::try_from(identity.len()).map_err(|_source| MemoryMutationEvidenceError::Identity)?;
    let mut hasher = Sha256::new();
    hasher.update(domain);
    hasher.update(length.to_le_bytes());
    hasher.update(identity.as_bytes());
    Ok(hasher.finalize().into())
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
            || self.virtual_page_start % self.page_size != 0
            || self.physical_page_start % self.page_size != 0
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
/// Fragment flag indicating that the mapped guest page was executable.
pub const MEMORY_MUTATION_FRAGMENT_EXECUTABLE: u32 = 1 << 0;
/// Fragment flag indicating explicitly supported RAM-backed device memory.
pub const MEMORY_MUTATION_FRAGMENT_DEVICE_MEMORY: u32 = 1 << 1;
/// Complete fragment flag mask understood by version 1.
pub const MEMORY_MUTATION_FRAGMENT_FLAGS_V1_MASK: u32 = (1 << 2) - 1;

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
/// Fixed evidence header size before translation records and inline bytes.
pub const MEMORY_MUTATION_EVIDENCE_HEADER_V1_BYTES: usize = 256;
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
/// Evidence translation-record count field offset.
pub const MEMORY_MUTATION_EVIDENCE_TRANSLATION_COUNT_OFFSET: usize = 32;
/// Evidence RAM-fragment count field offset.
pub const MEMORY_MUTATION_EVIDENCE_FRAGMENT_COUNT_OFFSET: usize = 36;
/// Evidence inline before/after byte count field offset.
pub const MEMORY_MUTATION_EVIDENCE_INLINE_LENGTH_OFFSET: usize = 40;
/// Evidence reserved field offset.
pub const MEMORY_MUTATION_EVIDENCE_RESERVED_OFFSET: usize = 44;
/// Evidence before-byte SHA-256 field offset.
pub const MEMORY_MUTATION_EVIDENCE_BEFORE_SHA256_OFFSET: usize = 48;
/// Evidence after-byte SHA-256 field offset.
pub const MEMORY_MUTATION_EVIDENCE_AFTER_SHA256_OFFSET: usize = 80;
/// Evidence canonical-translation SHA-256 field offset.
pub const MEMORY_MUTATION_EVIDENCE_TRANSLATION_SHA256_OFFSET: usize = 112;
/// Evidence mapping-generation SHA-256 field offset.
pub const MEMORY_MUTATION_EVIDENCE_MAPPING_SHA256_OFFSET: usize = 144;
/// Evidence dirty-page-set SHA-256 field offset.
pub const MEMORY_MUTATION_EVIDENCE_DIRTY_SHA256_OFFSET: usize = 176;
/// Evidence first-invalidated-address field offset.
pub const MEMORY_MUTATION_EVIDENCE_INVALIDATED_START_OFFSET: usize = 208;
/// Evidence last-invalidated-address field offset.
pub const MEMORY_MUTATION_EVIDENCE_INVALIDATED_END_OFFSET: usize = 216;
/// Evidence node-fingerprint field offset.
pub const MEMORY_MUTATION_EVIDENCE_NODE_FINGERPRINT_OFFSET: usize = 224;
/// Maximum before-byte count inlined together with the same number after bytes.
pub const MEMORY_MUTATION_EVIDENCE_INLINE_BYTES: u32 = 65_536;
/// Evidence flag indicating that before and after bytes are present.
pub const MEMORY_MUTATION_EVIDENCE_FLAG_INLINE_BYTES: u16 = 1 << 0;
/// Evidence flag indicating that executable translations were invalidated.
pub const MEMORY_MUTATION_EVIDENCE_FLAG_TB_INVALIDATED: u16 = 1 << 1;
/// Complete evidence flag mask understood by version 1.
pub const MEMORY_MUTATION_EVIDENCE_FLAGS_V1_MASK: u16 = (1 << 2) - 1;

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
    /// Canonical GVA translations; empty for GPA.
    pub translations: Vec<MemoryTranslationRecordV1>,
    /// Ordered normal-RAM fragments covering the complete mutation.
    pub fragments: Vec<MemoryMutationFragmentV1>,
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
    /// Node execution fingerprint at the mutation boundary.
    pub node_fingerprint: [u8; 32],
    /// Before bytes when the length is within the inline bound.
    pub before_bytes: Vec<u8>,
    /// After bytes when the length is within the inline bound.
    pub after_bytes: Vec<u8>,
}

impl MemoryMutationEvidenceV1 {
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
        let translation_count_u32 = u32::try_from(translation_count)
            .map_err(|_source| MemoryMutationEvidenceError::Length)?;
        let fragment_count_u32 =
            u32::try_from(fragment_count).map_err(|_source| MemoryMutationEvidenceError::Length)?;
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
        let translation_sha = if self.translations.is_empty() {
            [0; 32]
        } else {
            memory_translation_sha256(self.vcpu_index, &self.translations)?
        };
        let mut bytes = vec![0; MEMORY_MUTATION_EVIDENCE_HEADER_V1_BYTES];
        bytes[0..8].copy_from_slice(&MEMORY_MUTATION_EVIDENCE_MAGIC_V1);
        put_u16(&mut bytes, 8, MEMORY_MUTATION_EVIDENCE_VERSION_V1);
        put_u16(&mut bytes, 10, flags);
        put_u16(&mut bytes, 12, self.address_space as u16);
        put_u16(&mut bytes, 14, self.transform as u16);
        put_u32(&mut bytes, 16, self.vcpu_index);
        put_u32(&mut bytes, 20, self.length);
        put_u64(&mut bytes, 24, self.address);
        put_u32(&mut bytes, 32, translation_count_u32);
        put_u32(&mut bytes, 36, fragment_count_u32);
        put_u32(&mut bytes, 40, inline_len_u32);
        bytes[48..80].copy_from_slice(&self.before_sha256);
        bytes[80..112].copy_from_slice(&self.after_sha256);
        bytes[112..144].copy_from_slice(&translation_sha);
        bytes[144..176].copy_from_slice(&self.mapping_generation_sha256);
        bytes[176..208].copy_from_slice(&self.dirty_pages_sha256);
        put_u64(&mut bytes, 208, self.invalidated_start.unwrap_or(0));
        put_u64(&mut bytes, 216, self.invalidated_end.unwrap_or(0));
        bytes[224..256].copy_from_slice(&self.node_fingerprint);
        for record in &self.translations {
            bytes.extend_from_slice(&record.encode()?);
        }
        for fragment in &self.fragments {
            bytes.extend_from_slice(&fragment.encode()?);
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
            || bytes[44..48].iter().any(|byte| *byte != 0)
        {
            return Err(MemoryMutationEvidenceError::Framing);
        }
        let flags = read_u16(bytes, 10);
        if flags & !MEMORY_MUTATION_EVIDENCE_FLAGS_V1_MASK != 0 {
            return Err(MemoryMutationEvidenceError::Framing);
        }
        let translation_count = read_u32(bytes, 32) as usize;
        let fragment_count = read_u32(bytes, 36) as usize;
        let inline_len = read_u32(bytes, 40) as usize;
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
        let expected = fragments_end
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
        let array = |range: core::ops::Range<usize>| {
            let mut value = [0; 32];
            value.copy_from_slice(&bytes[range]);
            value
        };
        let value = Self {
            address_space: MemoryMutationAddressSpace::decode(read_u16(bytes, 12))
                .map_err(MemoryMutationEvidenceError::Payload)?,
            transform: MemoryMutationTransformKind::decode(read_u16(bytes, 14))
                .map_err(MemoryMutationEvidenceError::Payload)?,
            vcpu_index: read_u32(bytes, 16),
            length: read_u32(bytes, 20),
            address: read_u64(bytes, 24),
            translations,
            fragments,
            before_sha256: array(48..80),
            after_sha256: array(80..112),
            mapping_generation_sha256: array(144..176),
            dirty_pages_sha256: array(176..208),
            invalidated_start: (flags & MEMORY_MUTATION_EVIDENCE_FLAG_TB_INVALIDATED != 0)
                .then(|| read_u64(bytes, 208)),
            invalidated_end: (flags & MEMORY_MUTATION_EVIDENCE_FLAG_TB_INVALIDATED != 0)
                .then(|| read_u64(bytes, 216)),
            node_fingerprint: array(224..256),
            before_bytes: bytes[fragments_end..fragments_end + inline_len].to_vec(),
            after_bytes: bytes[fragments_end + inline_len..].to_vec(),
        };
        let translation_sha = array(112..144);
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
            || self.mapping_generation_sha256 == [0; 32]
            || self.dirty_pages_sha256 == [0; 32]
            || self.node_fingerprint == [0; 32]
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
        if !self.translations.is_empty()
            && self.translations.iter().try_fold(0_u64, |total, record| {
                total.checked_add(u64::from(record.covered_bytes))
            }) != Some(u64::from(self.length))
        {
            return Err(MemoryMutationEvidenceError::Translation);
        }
        match (self.invalidated_start, self.invalidated_end) {
            (None, None) => {}
            (Some(start), Some(end)) if start <= end => {}
            _ => return Err(MemoryMutationEvidenceError::Invalidation),
        }
        Ok(())
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
            "CRUCIBLE_MEMORY_MUTATION_FRAGMENT_EXECUTABLE",
            MEMORY_MUTATION_FRAGMENT_EXECUTABLE as u64,
        ),
        (
            "CRUCIBLE_MEMORY_MUTATION_FRAGMENT_DEVICE_MEMORY",
            MEMORY_MUTATION_FRAGMENT_DEVICE_MEMORY as u64,
        ),
        (
            "CRUCIBLE_MEMORY_MUTATION_FRAGMENT_FLAGS_V1_MASK",
            MEMORY_MUTATION_FRAGMENT_FLAGS_V1_MASK as u64,
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
            "CRUCIBLE_MEMORY_MUTATION_EVIDENCE_TRANSLATION_COUNT_OFFSET",
            MEMORY_MUTATION_EVIDENCE_TRANSLATION_COUNT_OFFSET as u64,
        ),
        (
            "CRUCIBLE_MEMORY_MUTATION_EVIDENCE_FRAGMENT_COUNT_OFFSET",
            MEMORY_MUTATION_EVIDENCE_FRAGMENT_COUNT_OFFSET as u64,
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
    fn translation_digest_and_evidence_round_trip() {
        let records = vec![MemoryTranslationRecordV1 {
            virtual_page_start: 0x4000,
            physical_page_start: 0x8000,
            page_size: 4096,
            permissions: MEMORY_TRANSLATION_PERMISSION_READ | MEMORY_TRANSLATION_PERMISSION_WRITE,
            attributes: MEMORY_TRANSLATION_ATTRIBUTE_USER,
            covered_bytes: 3,
        }];
        let before = vec![1, 2, 3];
        let after = vec![0, 2, 7];
        let region_identity =
            memory_region_identity_sha256("/machine/unattached/system-memory/ram")
                .unwrap_or_else(|error| panic!("region identity: {error}"));
        let ram_block_identity = memory_ram_block_identity_sha256("pc.ram")
            .unwrap_or_else(|error| panic!("RAMBlock identity: {error}"));
        let evidence = MemoryMutationEvidenceV1 {
            address_space: MemoryMutationAddressSpace::GuestVirtual,
            transform: MemoryMutationTransformKind::BitFlip,
            vcpu_index: 0,
            address: 0x4001,
            length: 3,
            translations: records,
            fragments: vec![MemoryMutationFragmentV1 {
                guest_physical_start: 0x8001,
                request_offset: 0,
                length: 3,
                flags: MEMORY_MUTATION_FRAGMENT_EXECUTABLE,
                memory_region_offset: 0x8001,
                ram_block_offset: 0x8001,
                memory_region_identity_sha256: region_identity,
                ram_block_identity_sha256: ram_block_identity,
            }],
            before_sha256: Sha256::digest(&before).into(),
            after_sha256: Sha256::digest(&after).into(),
            mapping_generation_sha256: [3; 32],
            dirty_pages_sha256: [4; 32],
            invalidated_start: Some(0x8001),
            invalidated_end: Some(0x8003),
            node_fingerprint: [5; 32],
            before_bytes: before,
            after_bytes: after,
        };
        let bytes = evidence
            .encode()
            .unwrap_or_else(|error| panic!("encode evidence: {error}"));
        assert_eq!(MemoryMutationEvidenceV1::decode(&bytes), Ok(evidence));
    }
}
