//! Memory-evidence errors, C declarations, and byte helpers.

use super::*;

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

pub(super) fn read_u16(bytes: &[u8], offset: usize) -> u16 {
    u16::from_le_bytes([bytes[offset], bytes[offset + 1]])
}
pub(super) fn read_u32(bytes: &[u8], offset: usize) -> u32 {
    u32::from_le_bytes([
        bytes[offset],
        bytes[offset + 1],
        bytes[offset + 2],
        bytes[offset + 3],
    ])
}
pub(super) fn read_u64(bytes: &[u8], offset: usize) -> u64 {
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
pub(super) fn read_array32(bytes: &[u8], offset: usize) -> [u8; 32] {
    let mut value = [0; 32];
    value.copy_from_slice(&bytes[offset..offset + 32]);
    value
}
pub(super) fn put_u16(bytes: &mut [u8], offset: usize, value: u16) {
    bytes[offset..offset + 2].copy_from_slice(&value.to_le_bytes());
}
pub(super) fn put_u32(bytes: &mut [u8], offset: usize, value: u32) {
    bytes[offset..offset + 4].copy_from_slice(&value.to_le_bytes());
}
pub(super) fn put_u64(bytes: &mut [u8], offset: usize, value: u64) {
    bytes[offset..offset + 8].copy_from_slice(&value.to_le_bytes());
}
