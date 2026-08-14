//! Canonical command and result envelopes.

use super::*;

/// One decoded command envelope with authenticated out-of-line payload bounds.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct FaultCommandHeaderV1 {
    /// ABI major version.
    pub abi_major: u16,
    /// ABI minor version.
    pub abi_minor: u16,
    /// Closed command kind.
    pub command_kind: FaultCommandKind,
    /// Versioned optional behavior flags.
    pub command_flags: u16,
    /// Exact safe-boundary phase at which QEMU must apply the command.
    pub phase: FaultBoundaryPhase,
    /// Exact command semantic version.
    pub semantic_version: u32,
    /// Strictly increasing per-node host sequence.
    pub command_sequence: u64,
    /// Hash of the exact target node identity.
    pub target_node_hash: [u8; 32],
    /// Exact target retired-instruction coordinate.
    pub target_icount: u64,
    /// Inclusive scheduler authorization ceiling.
    pub authorization_ceiling_icount: u64,
    /// Hash of the originating binding identity.
    pub binding_hash: [u8; 32],
    /// Hash of the exact opportunity, or all zero for a boundary command.
    pub opportunity_hash: [u8; 32],
    /// Required before-state digest, or all zero when the command has none.
    pub expected_precondition_hash: [u8; 32],
    /// Digest of the exact payload bytes.
    pub payload_hash: [u8; 32],
    /// Region-relative byte offset of the copied payload.
    pub payload_offset: u64,
    /// Exact payload length.
    pub payload_length: u32,
}

impl FaultCommandHeaderV1 {
    /// Encodes the canonical little-endian command header.
    #[must_use]
    pub fn encode(&self) -> [u8; FAULT_COMMAND_HEADER_V1_BYTES] {
        let mut bytes = [0_u8; FAULT_COMMAND_HEADER_V1_BYTES];
        let mut writer = FaultByteWriter::new(&mut bytes);
        writer.u16(self.abi_major);
        writer.u16(self.abi_minor);
        writer.u16(self.command_kind as u16);
        writer.u16(self.command_flags);
        writer.u16(self.phase as u16);
        writer.u16(0);
        writer.u32(self.semantic_version);
        writer.u64(self.command_sequence);
        writer.array32(self.target_node_hash);
        writer.u64(self.target_icount);
        writer.u64(self.authorization_ceiling_icount);
        writer.array32(self.binding_hash);
        writer.array32(self.opportunity_hash);
        writer.array32(self.expected_precondition_hash);
        writer.array32(self.payload_hash);
        writer.u64(self.payload_offset);
        writer.u32(self.payload_length);
        writer.u32(0);
        bytes
    }

    /// Decodes and validates one canonical command header and payload.
    ///
    /// # Errors
    ///
    /// Returns [`FaultAbiError`] for any length, version, tag, flag, sequence,
    /// coordinate, bound, reserved-byte, or payload-digest violation.
    pub fn decode<'a>(
        bytes: &[u8],
        payload_region: &'a [u8],
    ) -> Result<(Self, &'a [u8]), FaultAbiError> {
        let value = Self::decode_header(bytes)?;
        let payload = payload_slice(payload_region, value.payload_offset, value.payload_length)?;
        value.authenticate_payload(payload)?;
        Ok((value, payload))
    }

    fn decode_header(bytes: &[u8]) -> Result<Self, FaultAbiError> {
        if bytes.len() != FAULT_COMMAND_HEADER_V1_BYTES {
            return Err(FaultAbiError::HeaderLength);
        }
        let mut reader = FaultByteReader::new(bytes);
        let abi_major = reader.u16()?;
        let abi_minor = reader.u16()?;
        let command_kind = FaultCommandKind::from_u16(reader.u16()?)?;
        let command_flags = reader.u16()?;
        let phase = FaultBoundaryPhase::from_u16(reader.u16()?)?;
        if reader.u16()? != 0 {
            return Err(FaultAbiError::ReservedNonzero);
        }
        let value = Self {
            abi_major,
            abi_minor,
            command_kind,
            command_flags,
            phase,
            semantic_version: reader.u32()?,
            command_sequence: reader.u64()?,
            target_node_hash: reader.array32()?,
            target_icount: reader.u64()?,
            authorization_ceiling_icount: reader.u64()?,
            binding_hash: reader.array32()?,
            opportunity_hash: reader.array32()?,
            expected_precondition_hash: reader.array32()?,
            payload_hash: reader.array32()?,
            payload_offset: reader.u64()?,
            payload_length: reader.u32()?,
        };
        if reader.u32()? != 0 || !reader.exhausted() {
            return Err(FaultAbiError::ReservedNonzero);
        }
        value.validate()?;
        Ok(value)
    }

    fn authenticate_payload(&self, payload: &[u8]) -> Result<(), FaultAbiError> {
        if *blake3::hash(payload).as_bytes() != self.payload_hash {
            return Err(FaultAbiError::PayloadDigest);
        }
        Ok(())
    }

    fn validate(&self) -> Result<(), FaultAbiError> {
        if self.abi_major != FAULT_COMMAND_ABI_MAJOR
            || self.abi_minor != FAULT_COMMAND_ABI_MINOR
            || self.semantic_version != FAULT_COMMAND_SEMANTIC_VERSION
        {
            return Err(FaultAbiError::Version);
        }
        if self.command_flags & !FAULT_COMMAND_FLAGS_V1_MASK != 0 {
            return Err(FaultAbiError::Flags);
        }
        if self.command_sequence == 0 {
            return Err(FaultAbiError::Sequence);
        }
        if self.target_icount > self.authorization_ceiling_icount {
            return Err(FaultAbiError::Coordinate);
        }
        if self.payload_length > HARD_FAULT_PAYLOAD_BYTES {
            return Err(FaultAbiError::PayloadLimit);
        }
        if self.payload_length == 0 && self.payload_offset != 0 {
            return Err(FaultAbiError::PayloadBounds);
        }
        Ok(())
    }
}

/// One decoded command result with authenticated out-of-line evidence bytes.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct FaultResultHeaderV1 {
    /// ABI major version.
    pub abi_major: u16,
    /// ABI minor version.
    pub abi_minor: u16,
    /// Echoed raw command kind, including an unsupported input tag.
    pub command_kind: u16,
    /// Canonical application status.
    pub status: FaultResultStatus,
    /// Echoed command semantic version.
    pub semantic_version: u32,
    /// Echoed command sequence.
    pub command_sequence: u64,
    /// Icount at which QEMU observed or rejected the command.
    pub observed_icount: u64,
    /// Icount at which mutation committed, or zero when it did not.
    pub applied_icount: u64,
    /// Exact QEMU handler capability version.
    pub capability_version: u32,
    /// Boundary phase reached by QEMU.
    pub phase: FaultBoundaryPhase,
    /// Before-state fingerprint.
    pub before_hash: [u8; 32],
    /// After-state fingerprint, equal to `before_hash` on rejection.
    pub after_hash: [u8; 32],
    /// Digest of handler-specific canonical evidence.
    pub evidence_hash: [u8; 32],
    /// Digest of the typed result payload.
    pub result_payload_hash: [u8; 32],
    /// Region-relative byte offset of the typed result payload.
    pub result_offset: u64,
    /// Exact result payload length.
    pub result_length: u32,
}

impl FaultResultHeaderV1 {
    /// Encodes the canonical little-endian result header.
    #[must_use]
    pub fn encode(&self) -> [u8; FAULT_RESULT_HEADER_V1_BYTES] {
        let mut bytes = [0_u8; FAULT_RESULT_HEADER_V1_BYTES];
        let mut writer = FaultByteWriter::new(&mut bytes);
        writer.u16(self.abi_major);
        writer.u16(self.abi_minor);
        writer.u16(self.command_kind);
        writer.u16(self.status as u16);
        writer.u32(self.semantic_version);
        writer.u64(self.command_sequence);
        writer.u64(self.observed_icount);
        writer.u64(self.applied_icount);
        writer.u32(self.capability_version);
        writer.u16(self.phase as u16);
        writer.u16(0);
        writer.array32(self.before_hash);
        writer.array32(self.after_hash);
        writer.array32(self.evidence_hash);
        writer.array32(self.result_payload_hash);
        writer.u64(self.result_offset);
        writer.u32(self.result_length);
        writer.u32(0);
        bytes
    }

    /// Decodes and validates one canonical result header and result payload.
    ///
    /// # Errors
    ///
    /// Returns [`FaultAbiError`] for malformed versions, tags, reserved fields,
    /// status invariants, bounds, or payload authentication.
    pub fn decode<'a>(
        bytes: &[u8],
        payload_region: &'a [u8],
    ) -> Result<(Self, &'a [u8]), FaultAbiError> {
        let value = Self::decode_header(bytes)?;
        let payload = payload_slice(payload_region, value.result_offset, value.result_length)?;
        value.authenticate_payload(payload)?;
        Ok((value, payload))
    }

    fn decode_header(bytes: &[u8]) -> Result<Self, FaultAbiError> {
        if bytes.len() != FAULT_RESULT_HEADER_V1_BYTES {
            return Err(FaultAbiError::HeaderLength);
        }
        let mut reader = FaultByteReader::new(bytes);
        let value = Self {
            abi_major: reader.u16()?,
            abi_minor: reader.u16()?,
            command_kind: reader.u16()?,
            status: FaultResultStatus::from_u16(reader.u16()?)?,
            semantic_version: reader.u32()?,
            command_sequence: reader.u64()?,
            observed_icount: reader.u64()?,
            applied_icount: reader.u64()?,
            capability_version: reader.u32()?,
            phase: FaultBoundaryPhase::from_u16(reader.u16()?)?,
            before_hash: {
                if reader.u16()? != 0 {
                    return Err(FaultAbiError::ReservedNonzero);
                }
                reader.array32()?
            },
            after_hash: reader.array32()?,
            evidence_hash: reader.array32()?,
            result_payload_hash: reader.array32()?,
            result_offset: reader.u64()?,
            result_length: reader.u32()?,
        };
        if reader.u32()? != 0 || !reader.exhausted() {
            return Err(FaultAbiError::ReservedNonzero);
        }
        if value.abi_major != FAULT_COMMAND_ABI_MAJOR
            || value.abi_minor != FAULT_COMMAND_ABI_MINOR
            || value.semantic_version != FAULT_COMMAND_SEMANTIC_VERSION
        {
            return Err(FaultAbiError::Version);
        }
        if value.command_sequence == 0 || value.capability_version == 0 {
            return Err(FaultAbiError::Sequence);
        }
        if value.result_length > HARD_FAULT_PAYLOAD_BYTES {
            return Err(FaultAbiError::PayloadLimit);
        }
        if value.result_length == 0 && value.result_offset != 0 {
            return Err(FaultAbiError::PayloadBounds);
        }
        if value.status != FaultResultStatus::Applied
            && (value.applied_icount != 0 || value.after_hash != value.before_hash)
        {
            return Err(FaultAbiError::ResultInvariant);
        }
        if value.status == FaultResultStatus::Applied {
            FaultCommandKind::from_u16(value.command_kind)?;
        }
        Ok(value)
    }

    fn authenticate_payload(&self, payload: &[u8]) -> Result<(), FaultAbiError> {
        if *blake3::hash(payload).as_bytes() != self.result_payload_hash {
            return Err(FaultAbiError::PayloadDigest);
        }
        Ok(())
    }
}
