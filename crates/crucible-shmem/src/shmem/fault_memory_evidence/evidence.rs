//! Complete independently verifiable memory-mutation evidence.

use super::*;

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

    pub(crate) fn validate(&self) -> Result<(), MemoryMutationEvidenceError> {
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
