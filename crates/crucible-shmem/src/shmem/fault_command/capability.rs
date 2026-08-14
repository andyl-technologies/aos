//! Canonical QEMU fault capability rows and manifests.

use super::*;

/// One immutable, canonically sorted QEMU command capability row.
#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub struct FaultCapabilityRowV1 {
    /// Registered command kind.
    pub command_kind: FaultCommandKind,
    /// Exact command semantic version.
    pub semantic_version: u32,
    /// Architecture or device scope tag from the closed boundary registry.
    pub scope: FaultCapabilityScope,
    /// Bit set for every supported [`FaultBoundaryPhase`].
    pub phase_mask: u32,
    /// Maximum accepted payload bytes.
    pub maximum_payload_bytes: u32,
    /// Maximum pending commands of this kind.
    pub maximum_pending_commands: u32,
    /// Required patch-series feature bits.
    pub required_feature_bits: u64,
    /// Digest of the public capability name and payload schema.
    pub capability_hash: [u8; 32],
}

impl FaultCapabilityRowV1 {
    /// Encodes one canonical capability row.
    #[must_use]
    pub fn encode(&self) -> [u8; FAULT_CAPABILITY_ROW_V1_BYTES] {
        let mut bytes = [0_u8; FAULT_CAPABILITY_ROW_V1_BYTES];
        let mut writer = FaultByteWriter::new(&mut bytes);
        writer.u16(self.command_kind as u16);
        writer.u16(self.scope as u16);
        writer.u32(self.semantic_version);
        writer.u32(self.phase_mask);
        writer.u32(self.maximum_payload_bytes);
        writer.u32(self.maximum_pending_commands);
        writer.u64(self.required_feature_bits);
        writer.array32(self.capability_hash);
        bytes
    }

    /// Decodes and validates one capability row.
    ///
    /// # Errors
    ///
    /// Returns [`FaultAbiError`] for malformed tags, versions, phase masks, or
    /// resource limits.
    pub fn decode(bytes: &[u8]) -> Result<Self, FaultAbiError> {
        if bytes.len() != FAULT_CAPABILITY_ROW_V1_BYTES {
            return Err(FaultAbiError::HeaderLength);
        }
        let mut reader = FaultByteReader::new(bytes);
        let value = Self {
            command_kind: FaultCommandKind::from_u16(reader.u16()?)?,
            scope: FaultCapabilityScope::from_u16(reader.u16()?)?,
            semantic_version: reader.u32()?,
            phase_mask: reader.u32()?,
            maximum_payload_bytes: reader.u32()?,
            maximum_pending_commands: reader.u32()?,
            required_feature_bits: reader.u64()?,
            capability_hash: reader.array32()?,
        };
        if !reader.exhausted()
            || value.semantic_version != FAULT_COMMAND_SEMANTIC_VERSION
            || value.phase_mask == 0
            || value.phase_mask & !0x7f != 0
            || value.maximum_payload_bytes > HARD_FAULT_PAYLOAD_BYTES
            || value.maximum_pending_commands == 0
            || value.maximum_pending_commands > HARD_FAULT_COMMAND_CAPACITY
            || value.required_feature_bits & !FAULT_CAPABILITY_FEATURES_V1_MASK != 0
        {
            return Err(FaultAbiError::CapabilityInvariant);
        }
        Ok(value)
    }

    /// Returns whether the row advertises one exact boundary phase.
    #[must_use]
    pub const fn supports_phase(&self, phase: FaultBoundaryPhase) -> bool {
        self.phase_mask & phase.bit() != 0
    }
}

/// Validates canonical row ordering and returns the manifest digest.
///
/// # Errors
///
/// Returns [`FaultAbiError::CapabilityInvariant`] for duplicate or unsorted
/// rows, invalid row contracts, or an empty capability set.
pub fn fault_capability_manifest_digest(
    rows: &[FaultCapabilityRowV1],
) -> Result<[u8; 32], FaultAbiError> {
    if rows.is_empty()
        || rows.windows(2).any(|pair| {
            (
                pair[0].command_kind,
                pair[0].semantic_version,
                pair[0].scope,
            ) >= (
                pair[1].command_kind,
                pair[1].semantic_version,
                pair[1].scope,
            )
        })
    {
        return Err(FaultAbiError::CapabilityInvariant);
    }
    let mut hasher = blake3::Hasher::new();
    hasher.update(b"crucible.qemu-fault-capabilities.v1\0");
    for row in rows {
        let bytes = row.encode();
        let decoded = FaultCapabilityRowV1::decode(&bytes)?;
        if decoded != *row {
            return Err(FaultAbiError::CapabilityInvariant);
        }
        hasher.update(&bytes);
    }
    Ok(*hasher.finalize().as_bytes())
}

/// Magic prefix for a returned QEMU fault-capability manifest.
pub const FAULT_CAPABILITY_MANIFEST_MAGIC_V1: [u8; 8] = *b"CRUCFCP1";
/// Semantic version of the capability-manifest payload codec.
pub const FAULT_CAPABILITY_MANIFEST_VERSION_V1: u16 = 1;
/// Fixed header size before the canonical capability rows.
pub const FAULT_CAPABILITY_MANIFEST_HEADER_V1_BYTES: usize = 48;
/// Hard maximum number of QEMU capability rows accepted from one backend.
pub const HARD_FAULT_CAPABILITY_ROWS: usize = 4_096;

/// Encodes a canonical, self-authenticating QEMU capability manifest.
///
/// # Errors
///
/// Returns [`FaultAbiError::CapabilityInvariant`] when `rows` is empty,
/// unsorted, duplicated, invalid, or exceeds [`HARD_FAULT_CAPABILITY_ROWS`].
pub fn encode_fault_capability_manifest(
    rows: &[FaultCapabilityRowV1],
) -> Result<Vec<u8>, FaultAbiError> {
    if rows.len() > HARD_FAULT_CAPABILITY_ROWS {
        return Err(FaultAbiError::CapabilityInvariant);
    }
    let digest = fault_capability_manifest_digest(rows)?;
    let count = u32::try_from(rows.len()).map_err(|_| FaultAbiError::CapabilityInvariant)?;
    let body_bytes = rows
        .len()
        .checked_mul(FAULT_CAPABILITY_ROW_V1_BYTES)
        .ok_or(FaultAbiError::CapabilityInvariant)?;
    let capacity = FAULT_CAPABILITY_MANIFEST_HEADER_V1_BYTES
        .checked_add(body_bytes)
        .ok_or(FaultAbiError::CapabilityInvariant)?;
    let mut bytes = Vec::with_capacity(capacity);
    bytes.extend_from_slice(&FAULT_CAPABILITY_MANIFEST_MAGIC_V1);
    bytes.extend_from_slice(&FAULT_CAPABILITY_MANIFEST_VERSION_V1.to_le_bytes());
    bytes.extend_from_slice(&0_u16.to_le_bytes());
    bytes.extend_from_slice(&count.to_le_bytes());
    bytes.extend_from_slice(&digest);
    for row in rows {
        bytes.extend_from_slice(&row.encode());
    }
    Ok(bytes)
}

/// Decodes and authenticates a canonical QEMU capability manifest.
///
/// # Errors
///
/// Returns [`FaultAbiError`] when framing, version, bounds, row validation,
/// canonical ordering, or the embedded manifest digest is invalid.
pub fn decode_fault_capability_manifest(
    bytes: &[u8],
) -> Result<Vec<FaultCapabilityRowV1>, FaultAbiError> {
    if bytes.len() < FAULT_CAPABILITY_MANIFEST_HEADER_V1_BYTES
        || bytes[..8] != FAULT_CAPABILITY_MANIFEST_MAGIC_V1
    {
        return Err(FaultAbiError::HeaderLength);
    }
    let version = u16::from_le_bytes([bytes[8], bytes[9]]);
    let reserved = u16::from_le_bytes([bytes[10], bytes[11]]);
    if version != FAULT_CAPABILITY_MANIFEST_VERSION_V1 || reserved != 0 {
        return Err(FaultAbiError::Version);
    }
    let count = usize::try_from(u32::from_le_bytes([
        bytes[12], bytes[13], bytes[14], bytes[15],
    ]))
    .map_err(|_source| FaultAbiError::CapabilityInvariant)?;
    if count == 0 || count > HARD_FAULT_CAPABILITY_ROWS {
        return Err(FaultAbiError::CapabilityInvariant);
    }
    let expected_len = count
        .checked_mul(FAULT_CAPABILITY_ROW_V1_BYTES)
        .and_then(|body| FAULT_CAPABILITY_MANIFEST_HEADER_V1_BYTES.checked_add(body))
        .ok_or(FaultAbiError::CapabilityInvariant)?;
    if bytes.len() != expected_len {
        return Err(FaultAbiError::HeaderLength);
    }
    let rows = bytes[FAULT_CAPABILITY_MANIFEST_HEADER_V1_BYTES..]
        .chunks_exact(FAULT_CAPABILITY_ROW_V1_BYTES)
        .map(FaultCapabilityRowV1::decode)
        .collect::<Result<Vec<_>, _>>()?;
    let digest = fault_capability_manifest_digest(&rows)?;
    if bytes[16..48] != digest {
        return Err(FaultAbiError::PayloadDigest);
    }
    Ok(rows)
}
