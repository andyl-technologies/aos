//! Closed byte-level fault command, result, and capability protocol.
//!
//! These values cross the Apache host/GPL QEMU process boundary only as
//! explicitly encoded little-endian bytes. They are not native Rust or C wire
//! layouts. Every decoder rejects unknown tags, nonzero reserved fields,
//! unsupported versions, invalid bounds, and unauthenticated payload bytes.

use core::fmt::Write as _;
use thiserror::Error;

/// Fault command ABI major version.
pub const FAULT_COMMAND_ABI_MAJOR: u16 = 1;
/// Fault command ABI minor version.
pub const FAULT_COMMAND_ABI_MINOR: u16 = 0;
/// Exact semantic version implemented by every initial command kind.
pub const FAULT_COMMAND_SEMANTIC_VERSION: u32 = 1;
/// Default maximum command or result payload bytes.
pub const DEFAULT_FAULT_PAYLOAD_BYTES: u32 = 1_048_576;
/// Hard maximum command or result payload bytes.
pub const HARD_FAULT_PAYLOAD_BYTES: u32 = 16_777_216;
/// Default command and result ring capacity per node.
pub const DEFAULT_FAULT_COMMAND_CAPACITY: u32 = 4_096;
/// Hard command and result ring capacity per node.
pub const HARD_FAULT_COMMAND_CAPACITY: u32 = 65_536;
/// Encoded command header byte length.
pub const FAULT_COMMAND_HEADER_V1_BYTES: usize = 216;
/// Command ABI-major field offset.
pub const FAULT_COMMAND_ABI_MAJOR_OFFSET: usize = 0;
/// Command ABI-minor field offset.
pub const FAULT_COMMAND_ABI_MINOR_OFFSET: usize = 2;
/// Command-kind field offset.
pub const FAULT_COMMAND_KIND_OFFSET: usize = 4;
/// Command-flags field offset.
pub const FAULT_COMMAND_FLAGS_OFFSET: usize = 6;
/// Command safe-boundary phase field offset.
pub const FAULT_COMMAND_PHASE_OFFSET: usize = 8;
/// First command reserved field offset.
pub const FAULT_COMMAND_RESERVED0_OFFSET: usize = 10;
/// Command semantic-version field offset.
pub const FAULT_COMMAND_SEMANTIC_VERSION_OFFSET: usize = 12;
/// Command sequence field offset.
pub const FAULT_COMMAND_SEQUENCE_OFFSET: usize = 16;
/// Command target-node hash field offset.
pub const FAULT_COMMAND_TARGET_NODE_HASH_OFFSET: usize = 24;
/// Command target-icount field offset.
pub const FAULT_COMMAND_TARGET_ICOUNT_OFFSET: usize = 56;
/// Command authorization-ceiling field offset.
pub const FAULT_COMMAND_AUTHORIZATION_CEILING_OFFSET: usize = 64;
/// Command binding hash field offset.
pub const FAULT_COMMAND_BINDING_HASH_OFFSET: usize = 72;
/// Command opportunity hash field offset.
pub const FAULT_COMMAND_OPPORTUNITY_HASH_OFFSET: usize = 104;
/// Command expected-precondition hash field offset.
pub const FAULT_COMMAND_PRECONDITION_HASH_OFFSET: usize = 136;
/// Command payload hash field offset.
pub const FAULT_COMMAND_PAYLOAD_HASH_OFFSET: usize = 168;
/// Command payload-offset field offset.
pub const FAULT_COMMAND_PAYLOAD_OFFSET_OFFSET: usize = 200;
/// Command payload-length field offset.
pub const FAULT_COMMAND_PAYLOAD_LENGTH_OFFSET: usize = 208;
/// Final command reserved field offset.
pub const FAULT_COMMAND_RESERVED1_OFFSET: usize = 212;
/// Encoded result header byte length.
pub const FAULT_RESULT_HEADER_V1_BYTES: usize = 188;
/// Result ABI-major field offset.
pub const FAULT_RESULT_ABI_MAJOR_OFFSET: usize = 0;
/// Result ABI-minor field offset.
pub const FAULT_RESULT_ABI_MINOR_OFFSET: usize = 2;
/// Result command-kind field offset.
pub const FAULT_RESULT_KIND_OFFSET: usize = 4;
/// Result status field offset.
pub const FAULT_RESULT_STATUS_OFFSET: usize = 6;
/// Result semantic-version field offset.
pub const FAULT_RESULT_SEMANTIC_VERSION_OFFSET: usize = 8;
/// Result command-sequence field offset.
pub const FAULT_RESULT_SEQUENCE_OFFSET: usize = 12;
/// Result observed-icount field offset.
pub const FAULT_RESULT_OBSERVED_ICOUNT_OFFSET: usize = 20;
/// Result applied-icount field offset.
pub const FAULT_RESULT_APPLIED_ICOUNT_OFFSET: usize = 28;
/// Result capability-version field offset.
pub const FAULT_RESULT_CAPABILITY_VERSION_OFFSET: usize = 36;
/// Result safe-boundary phase field offset.
pub const FAULT_RESULT_PHASE_OFFSET: usize = 40;
/// First result reserved field offset.
pub const FAULT_RESULT_RESERVED0_OFFSET: usize = 42;
/// Result before-state hash field offset.
pub const FAULT_RESULT_BEFORE_HASH_OFFSET: usize = 44;
/// Result after-state hash field offset.
pub const FAULT_RESULT_AFTER_HASH_OFFSET: usize = 76;
/// Result evidence hash field offset.
pub const FAULT_RESULT_EVIDENCE_HASH_OFFSET: usize = 108;
/// Result payload hash field offset.
pub const FAULT_RESULT_PAYLOAD_HASH_OFFSET: usize = 140;
/// Result payload-offset field offset.
pub const FAULT_RESULT_PAYLOAD_OFFSET_OFFSET: usize = 172;
/// Result payload-length field offset.
pub const FAULT_RESULT_PAYLOAD_LENGTH_OFFSET: usize = 180;
/// Final result reserved field offset.
pub const FAULT_RESULT_RESERVED1_OFFSET: usize = 184;
/// Encoded capability row byte length.
pub const FAULT_CAPABILITY_ROW_V1_BYTES: usize = 60;
/// Capability command-kind field offset.
pub const FAULT_CAPABILITY_KIND_OFFSET: usize = 0;
/// Capability architecture/device-scope field offset.
pub const FAULT_CAPABILITY_SCOPE_OFFSET: usize = 2;
/// Capability semantic-version field offset.
pub const FAULT_CAPABILITY_SEMANTIC_VERSION_OFFSET: usize = 4;
/// Capability supported-phase mask field offset.
pub const FAULT_CAPABILITY_PHASE_MASK_OFFSET: usize = 8;
/// Capability maximum-payload field offset.
pub const FAULT_CAPABILITY_MAXIMUM_PAYLOAD_OFFSET: usize = 12;
/// Capability maximum-pending field offset.
pub const FAULT_CAPABILITY_MAXIMUM_PENDING_OFFSET: usize = 16;
/// Capability required-feature-bits field offset.
pub const FAULT_CAPABILITY_REQUIRED_FEATURES_OFFSET: usize = 20;
/// Capability identity hash field offset.
pub const FAULT_CAPABILITY_HASH_OFFSET: usize = 28;

/// No optional command behavior is selected.
pub const FAULT_COMMAND_FLAG_NONE: u16 = 0;
/// The only bit mask accepted for command flags in ABI v1.
pub const FAULT_COMMAND_FLAGS_V1_MASK: u16 = FAULT_COMMAND_FLAG_NONE;

/// Closed command kind registry shared by the host, plugin, and QEMU patches.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
#[repr(u16)]
pub enum FaultCommandKind {
    /// Returns the immutable QEMU capability manifest.
    QueryCapabilities = 1,
    /// Probes exact-boundary quiescence without mutating guest state.
    BoundaryProbe = 2,
    /// Applies a node lifecycle transition.
    NodeLifecycle = 16,
    /// Applies or removes node/vCPU hang state.
    NodeHang = 17,
    /// Applies rational vCPU service state.
    CpuService = 18,
    /// Applies vCPU online, offline, or stall state.
    CpuVcpuState = 19,
    /// Applies register mutation or a persistent register rule.
    CpuRegisterTransform = 20,
    /// Applies one instruction mutation.
    CpuInstructionTransform = 21,
    /// Injects one architecture exception or hardware CPU error.
    CpuException = 22,
    /// Applies an interrupt disposition rule or opportunity result.
    InterruptDisposition = 23,
    /// Installs or advances a bounded interrupt storm.
    InterruptStorm = 24,
    /// Atomically mutates guest memory at a safe boundary.
    MemoryMutation = 25,
    /// Applies a persistent or opportunity memory access transform.
    MemoryAccessTransform = 26,
    /// Injects one corrected or uncorrectable ECC event.
    MemoryEccEvent = 27,
    /// Applies stateful failed-range, retention, or disturbance state.
    MemoryRegionState = 28,
    /// Applies memory latency, bandwidth, or service state.
    MemoryService = 29,
    /// Applies a guest clock transform.
    ClockTransform = 30,
    /// Applies guest clock failure, fallback, or synchronization state.
    ClockSourceState = 31,
    /// Applies accelerator lifecycle state.
    AcceleratorLifecycle = 32,
    /// Applies an accelerator result transform.
    AcceleratorResultTransform = 33,
    /// Applies an accelerator memory or ECC event.
    AcceleratorMemoryEvent = 34,
    /// Applies accelerator compute, memory, thermal, or power service state.
    AcceleratorService = 35,
}

impl FaultCommandKind {
    /// Decodes one exact registered numeric tag.
    ///
    /// # Errors
    ///
    /// Returns [`FaultAbiError::UnknownCommandKind`] for unregistered values.
    pub fn from_u16(value: u16) -> Result<Self, FaultAbiError> {
        match value {
            1 => Ok(Self::QueryCapabilities),
            2 => Ok(Self::BoundaryProbe),
            16 => Ok(Self::NodeLifecycle),
            17 => Ok(Self::NodeHang),
            18 => Ok(Self::CpuService),
            19 => Ok(Self::CpuVcpuState),
            20 => Ok(Self::CpuRegisterTransform),
            21 => Ok(Self::CpuInstructionTransform),
            22 => Ok(Self::CpuException),
            23 => Ok(Self::InterruptDisposition),
            24 => Ok(Self::InterruptStorm),
            25 => Ok(Self::MemoryMutation),
            26 => Ok(Self::MemoryAccessTransform),
            27 => Ok(Self::MemoryEccEvent),
            28 => Ok(Self::MemoryRegionState),
            29 => Ok(Self::MemoryService),
            30 => Ok(Self::ClockTransform),
            31 => Ok(Self::ClockSourceState),
            32 => Ok(Self::AcceleratorLifecycle),
            33 => Ok(Self::AcceleratorResultTransform),
            34 => Ok(Self::AcceleratorMemoryEvent),
            35 => Ok(Self::AcceleratorService),
            _ => Err(FaultAbiError::UnknownCommandKind(value)),
        }
    }
}

/// Exact QEMU application boundary selected by a fault command.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
#[repr(u16)]
pub enum FaultBoundaryPhase {
    /// Between scheduler quanta with all vCPUs and due device work quiescent.
    NodeBoundary = 1,
    /// Immediately before a selected instruction.
    BeforeInstruction = 2,
    /// Immediately after a selected instruction commits.
    AfterInstruction = 3,
    /// After address resolution and before a memory side effect.
    BeforeMemoryAccess = 4,
    /// After a memory side effect and before its consumer commits.
    AfterMemoryAccess = 5,
    /// At a typed interrupt pipeline phase.
    Interrupt = 6,
    /// At a typed accelerator or device phase.
    Device = 7,
}

impl FaultBoundaryPhase {
    fn from_u16(value: u16) -> Result<Self, FaultAbiError> {
        match value {
            1 => Ok(Self::NodeBoundary),
            2 => Ok(Self::BeforeInstruction),
            3 => Ok(Self::AfterInstruction),
            4 => Ok(Self::BeforeMemoryAccess),
            5 => Ok(Self::AfterMemoryAccess),
            6 => Ok(Self::Interrupt),
            7 => Ok(Self::Device),
            _ => Err(FaultAbiError::UnknownBoundaryPhase(value)),
        }
    }

    const fn bit(self) -> u32 {
        1_u32 << (self as u16 - 1)
    }
}

/// Stable canonical result status returned by QEMU.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
#[repr(u16)]
pub enum FaultResultStatus {
    /// The mutation committed and its evidence is complete.
    Applied = 1,
    /// The selected opportunity did not occur by its ceiling.
    NotApplicable = 2,
    /// The supplied before-state digest did not match.
    PreconditionMismatch = 3,
    /// The target is absent or outside the compiled architecture/device scope.
    InvalidTarget = 4,
    /// The command kind is illegal at the requested phase.
    InvalidPhase = 5,
    /// The matched QEMU does not advertise this exact command capability.
    UnsupportedCapability = 6,
    /// The target boundary was already passed.
    PastBoundary = 7,
    /// A declared or hard resource bound was exceeded before mutation.
    ResourceLimit = 8,
    /// The modeled guest/device interface rejected the operation.
    GuestRejected = 9,
    /// QEMU could not preserve the atomic application contract.
    InternalError = 10,
}

impl FaultResultStatus {
    fn from_u16(value: u16) -> Result<Self, FaultAbiError> {
        match value {
            1 => Ok(Self::Applied),
            2 => Ok(Self::NotApplicable),
            3 => Ok(Self::PreconditionMismatch),
            4 => Ok(Self::InvalidTarget),
            5 => Ok(Self::InvalidPhase),
            6 => Ok(Self::UnsupportedCapability),
            7 => Ok(Self::PastBoundary),
            8 => Ok(Self::ResourceLimit),
            9 => Ok(Self::GuestRejected),
            10 => Ok(Self::InternalError),
            _ => Err(FaultAbiError::UnknownResultStatus(value)),
        }
    }
}

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
        let payload = payload_slice(payload_region, value.payload_offset, value.payload_length)?;
        if *blake3::hash(payload).as_bytes() != value.payload_hash {
            return Err(FaultAbiError::PayloadDigest);
        }
        Ok((value, payload))
    }

    fn validate(&self) -> Result<(), FaultAbiError> {
        if self.abi_major != FAULT_COMMAND_ABI_MAJOR
            || self.abi_minor > FAULT_COMMAND_ABI_MINOR
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
    /// Echoed command kind.
    pub command_kind: FaultCommandKind,
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
        writer.u16(self.command_kind as u16);
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
        if bytes.len() != FAULT_RESULT_HEADER_V1_BYTES {
            return Err(FaultAbiError::HeaderLength);
        }
        let mut reader = FaultByteReader::new(bytes);
        let value = Self {
            abi_major: reader.u16()?,
            abi_minor: reader.u16()?,
            command_kind: FaultCommandKind::from_u16(reader.u16()?)?,
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
            || value.abi_minor > FAULT_COMMAND_ABI_MINOR
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
        let payload = payload_slice(payload_region, value.result_offset, value.result_length)?;
        if *blake3::hash(payload).as_bytes() != value.result_payload_hash {
            return Err(FaultAbiError::PayloadDigest);
        }
        Ok((value, payload))
    }
}

/// One immutable, canonically sorted QEMU command capability row.
#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub struct FaultCapabilityRowV1 {
    /// Registered command kind.
    pub command_kind: FaultCommandKind,
    /// Exact command semantic version.
    pub semantic_version: u32,
    /// Architecture or device scope tag from the closed boundary registry.
    pub scope: u16,
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
        writer.u16(self.scope);
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
            scope: reader.u16()?,
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

fn payload_slice(region: &[u8], offset: u64, length: u32) -> Result<&[u8], FaultAbiError> {
    let start = usize::try_from(offset).map_err(|_| FaultAbiError::PayloadBounds)?;
    let length = usize::try_from(length).map_err(|_| FaultAbiError::PayloadBounds)?;
    let end = start
        .checked_add(length)
        .ok_or(FaultAbiError::PayloadBounds)?;
    region.get(start..end).ok_or(FaultAbiError::PayloadBounds)
}

struct FaultByteWriter<'a> {
    bytes: &'a mut [u8],
    cursor: usize,
}

impl<'a> FaultByteWriter<'a> {
    const fn new(bytes: &'a mut [u8]) -> Self {
        Self { bytes, cursor: 0 }
    }

    fn write(&mut self, value: &[u8]) {
        let end = self.cursor + value.len();
        self.bytes[self.cursor..end].copy_from_slice(value);
        self.cursor = end;
    }

    fn u16(&mut self, value: u16) {
        self.write(&value.to_le_bytes());
    }

    fn u32(&mut self, value: u32) {
        self.write(&value.to_le_bytes());
    }

    fn u64(&mut self, value: u64) {
        self.write(&value.to_le_bytes());
    }

    fn array32(&mut self, value: [u8; 32]) {
        self.write(&value);
    }
}

struct FaultByteReader<'a> {
    bytes: &'a [u8],
    cursor: usize,
}

impl<'a> FaultByteReader<'a> {
    const fn new(bytes: &'a [u8]) -> Self {
        Self { bytes, cursor: 0 }
    }

    fn read<const N: usize>(&mut self) -> Result<[u8; N], FaultAbiError> {
        let end = self
            .cursor
            .checked_add(N)
            .ok_or(FaultAbiError::HeaderLength)?;
        let source = self
            .bytes
            .get(self.cursor..end)
            .ok_or(FaultAbiError::HeaderLength)?;
        let mut value = [0_u8; N];
        value.copy_from_slice(source);
        self.cursor = end;
        Ok(value)
    }

    fn u16(&mut self) -> Result<u16, FaultAbiError> {
        Ok(u16::from_le_bytes(self.read()?))
    }

    fn u32(&mut self) -> Result<u32, FaultAbiError> {
        Ok(u32::from_le_bytes(self.read()?))
    }

    fn u64(&mut self) -> Result<u64, FaultAbiError> {
        Ok(u64::from_le_bytes(self.read()?))
    }

    fn array32(&mut self) -> Result<[u8; 32], FaultAbiError> {
        self.read()
    }

    const fn exhausted(&self) -> bool {
        self.cursor == self.bytes.len()
    }
}

/// Byte-level fault ABI validation failure.
#[derive(Clone, Debug, Error, PartialEq, Eq)]
pub enum FaultAbiError {
    /// The command or result header has the wrong exact byte length.
    #[error("fault ABI header length mismatch")]
    HeaderLength,
    /// The ABI or semantic version is unsupported.
    #[error("fault ABI version mismatch")]
    Version,
    /// A command kind tag is not registered.
    #[error("unknown fault command kind {0}")]
    UnknownCommandKind(u16),
    /// A result status tag is not registered.
    #[error("unknown fault result status {0}")]
    UnknownResultStatus(u16),
    /// A boundary phase tag is not registered.
    #[error("unknown fault boundary phase {0}")]
    UnknownBoundaryPhase(u16),
    /// Unsupported command flag bits are set.
    #[error("unsupported fault command flags")]
    Flags,
    /// A sequence or capability version is zero.
    #[error("invalid fault ABI sequence")]
    Sequence,
    /// The target coordinate exceeds its authorization ceiling.
    #[error("invalid fault ABI coordinate")]
    Coordinate,
    /// Reserved bytes are nonzero.
    #[error("fault ABI reserved bytes are nonzero")]
    ReservedNonzero,
    /// A payload exceeds its compiled hard limit.
    #[error("fault ABI payload exceeds the hard limit")]
    PayloadLimit,
    /// A payload offset and length escape the supplied arena.
    #[error("fault ABI payload bounds are invalid")]
    PayloadBounds,
    /// A payload digest does not authenticate the selected bytes.
    #[error("fault ABI payload digest mismatch")]
    PayloadDigest,
    /// Applied/rejected result fields contradict the status.
    #[error("fault ABI result invariants are invalid")]
    ResultInvariant,
    /// A capability row or manifest violates its canonical contract.
    #[error("fault ABI capability invariant is invalid")]
    CapabilityInvariant,
}

pub(crate) fn emit_fault_command_c_header(out: &mut String) {
    macro_rules! define {
        ($name:literal, $value:expr) => {
            let _ = writeln!(out, "#define {} {}", $name, $value);
        };
    }

    out.push_str("\n/* Byte-encoded QEMU fault command/result ABI. */\n");
    define!("CRUCIBLE_FAULT_COMMAND_ABI_MAJOR", FAULT_COMMAND_ABI_MAJOR);
    define!("CRUCIBLE_FAULT_COMMAND_ABI_MINOR", FAULT_COMMAND_ABI_MINOR);
    define!(
        "CRUCIBLE_FAULT_COMMAND_SEMANTIC_VERSION",
        FAULT_COMMAND_SEMANTIC_VERSION
    );
    define!(
        "CRUCIBLE_FAULT_DEFAULT_PAYLOAD_BYTES",
        DEFAULT_FAULT_PAYLOAD_BYTES
    );
    define!(
        "CRUCIBLE_FAULT_HARD_PAYLOAD_BYTES",
        HARD_FAULT_PAYLOAD_BYTES
    );
    define!(
        "CRUCIBLE_FAULT_DEFAULT_COMMAND_CAPACITY",
        DEFAULT_FAULT_COMMAND_CAPACITY
    );
    define!(
        "CRUCIBLE_FAULT_HARD_COMMAND_CAPACITY",
        HARD_FAULT_COMMAND_CAPACITY
    );
    define!(
        "CRUCIBLE_FAULT_COMMAND_HEADER_V1_BYTES",
        FAULT_COMMAND_HEADER_V1_BYTES
    );
    define!(
        "CRUCIBLE_FAULT_RESULT_HEADER_V1_BYTES",
        FAULT_RESULT_HEADER_V1_BYTES
    );
    define!(
        "CRUCIBLE_FAULT_CAPABILITY_ROW_V1_BYTES",
        FAULT_CAPABILITY_ROW_V1_BYTES
    );

    for (name, value) in [
        (
            "CRUCIBLE_FAULT_COMMAND_ABI_MAJOR_OFFSET",
            FAULT_COMMAND_ABI_MAJOR_OFFSET,
        ),
        (
            "CRUCIBLE_FAULT_COMMAND_ABI_MINOR_OFFSET",
            FAULT_COMMAND_ABI_MINOR_OFFSET,
        ),
        (
            "CRUCIBLE_FAULT_COMMAND_KIND_OFFSET",
            FAULT_COMMAND_KIND_OFFSET,
        ),
        (
            "CRUCIBLE_FAULT_COMMAND_FLAGS_OFFSET",
            FAULT_COMMAND_FLAGS_OFFSET,
        ),
        (
            "CRUCIBLE_FAULT_COMMAND_PHASE_OFFSET",
            FAULT_COMMAND_PHASE_OFFSET,
        ),
        (
            "CRUCIBLE_FAULT_COMMAND_RESERVED0_OFFSET",
            FAULT_COMMAND_RESERVED0_OFFSET,
        ),
        (
            "CRUCIBLE_FAULT_COMMAND_SEMANTIC_VERSION_OFFSET",
            FAULT_COMMAND_SEMANTIC_VERSION_OFFSET,
        ),
        (
            "CRUCIBLE_FAULT_COMMAND_SEQUENCE_OFFSET",
            FAULT_COMMAND_SEQUENCE_OFFSET,
        ),
        (
            "CRUCIBLE_FAULT_COMMAND_TARGET_NODE_HASH_OFFSET",
            FAULT_COMMAND_TARGET_NODE_HASH_OFFSET,
        ),
        (
            "CRUCIBLE_FAULT_COMMAND_TARGET_ICOUNT_OFFSET",
            FAULT_COMMAND_TARGET_ICOUNT_OFFSET,
        ),
        (
            "CRUCIBLE_FAULT_COMMAND_AUTHORIZATION_CEILING_OFFSET",
            FAULT_COMMAND_AUTHORIZATION_CEILING_OFFSET,
        ),
        (
            "CRUCIBLE_FAULT_COMMAND_BINDING_HASH_OFFSET",
            FAULT_COMMAND_BINDING_HASH_OFFSET,
        ),
        (
            "CRUCIBLE_FAULT_COMMAND_OPPORTUNITY_HASH_OFFSET",
            FAULT_COMMAND_OPPORTUNITY_HASH_OFFSET,
        ),
        (
            "CRUCIBLE_FAULT_COMMAND_PRECONDITION_HASH_OFFSET",
            FAULT_COMMAND_PRECONDITION_HASH_OFFSET,
        ),
        (
            "CRUCIBLE_FAULT_COMMAND_PAYLOAD_HASH_OFFSET",
            FAULT_COMMAND_PAYLOAD_HASH_OFFSET,
        ),
        (
            "CRUCIBLE_FAULT_COMMAND_PAYLOAD_OFFSET_OFFSET",
            FAULT_COMMAND_PAYLOAD_OFFSET_OFFSET,
        ),
        (
            "CRUCIBLE_FAULT_COMMAND_PAYLOAD_LENGTH_OFFSET",
            FAULT_COMMAND_PAYLOAD_LENGTH_OFFSET,
        ),
        (
            "CRUCIBLE_FAULT_COMMAND_RESERVED1_OFFSET",
            FAULT_COMMAND_RESERVED1_OFFSET,
        ),
        (
            "CRUCIBLE_FAULT_RESULT_ABI_MAJOR_OFFSET",
            FAULT_RESULT_ABI_MAJOR_OFFSET,
        ),
        (
            "CRUCIBLE_FAULT_RESULT_ABI_MINOR_OFFSET",
            FAULT_RESULT_ABI_MINOR_OFFSET,
        ),
        (
            "CRUCIBLE_FAULT_RESULT_KIND_OFFSET",
            FAULT_RESULT_KIND_OFFSET,
        ),
        (
            "CRUCIBLE_FAULT_RESULT_STATUS_OFFSET",
            FAULT_RESULT_STATUS_OFFSET,
        ),
        (
            "CRUCIBLE_FAULT_RESULT_SEMANTIC_VERSION_OFFSET",
            FAULT_RESULT_SEMANTIC_VERSION_OFFSET,
        ),
        (
            "CRUCIBLE_FAULT_RESULT_SEQUENCE_OFFSET",
            FAULT_RESULT_SEQUENCE_OFFSET,
        ),
        (
            "CRUCIBLE_FAULT_RESULT_OBSERVED_ICOUNT_OFFSET",
            FAULT_RESULT_OBSERVED_ICOUNT_OFFSET,
        ),
        (
            "CRUCIBLE_FAULT_RESULT_APPLIED_ICOUNT_OFFSET",
            FAULT_RESULT_APPLIED_ICOUNT_OFFSET,
        ),
        (
            "CRUCIBLE_FAULT_RESULT_CAPABILITY_VERSION_OFFSET",
            FAULT_RESULT_CAPABILITY_VERSION_OFFSET,
        ),
        (
            "CRUCIBLE_FAULT_RESULT_PHASE_OFFSET",
            FAULT_RESULT_PHASE_OFFSET,
        ),
        (
            "CRUCIBLE_FAULT_RESULT_RESERVED0_OFFSET",
            FAULT_RESULT_RESERVED0_OFFSET,
        ),
        (
            "CRUCIBLE_FAULT_RESULT_BEFORE_HASH_OFFSET",
            FAULT_RESULT_BEFORE_HASH_OFFSET,
        ),
        (
            "CRUCIBLE_FAULT_RESULT_AFTER_HASH_OFFSET",
            FAULT_RESULT_AFTER_HASH_OFFSET,
        ),
        (
            "CRUCIBLE_FAULT_RESULT_EVIDENCE_HASH_OFFSET",
            FAULT_RESULT_EVIDENCE_HASH_OFFSET,
        ),
        (
            "CRUCIBLE_FAULT_RESULT_PAYLOAD_HASH_OFFSET",
            FAULT_RESULT_PAYLOAD_HASH_OFFSET,
        ),
        (
            "CRUCIBLE_FAULT_RESULT_PAYLOAD_OFFSET_OFFSET",
            FAULT_RESULT_PAYLOAD_OFFSET_OFFSET,
        ),
        (
            "CRUCIBLE_FAULT_RESULT_PAYLOAD_LENGTH_OFFSET",
            FAULT_RESULT_PAYLOAD_LENGTH_OFFSET,
        ),
        (
            "CRUCIBLE_FAULT_RESULT_RESERVED1_OFFSET",
            FAULT_RESULT_RESERVED1_OFFSET,
        ),
        (
            "CRUCIBLE_FAULT_CAPABILITY_KIND_OFFSET",
            FAULT_CAPABILITY_KIND_OFFSET,
        ),
        (
            "CRUCIBLE_FAULT_CAPABILITY_SCOPE_OFFSET",
            FAULT_CAPABILITY_SCOPE_OFFSET,
        ),
        (
            "CRUCIBLE_FAULT_CAPABILITY_SEMANTIC_VERSION_OFFSET",
            FAULT_CAPABILITY_SEMANTIC_VERSION_OFFSET,
        ),
        (
            "CRUCIBLE_FAULT_CAPABILITY_PHASE_MASK_OFFSET",
            FAULT_CAPABILITY_PHASE_MASK_OFFSET,
        ),
        (
            "CRUCIBLE_FAULT_CAPABILITY_MAXIMUM_PAYLOAD_OFFSET",
            FAULT_CAPABILITY_MAXIMUM_PAYLOAD_OFFSET,
        ),
        (
            "CRUCIBLE_FAULT_CAPABILITY_MAXIMUM_PENDING_OFFSET",
            FAULT_CAPABILITY_MAXIMUM_PENDING_OFFSET,
        ),
        (
            "CRUCIBLE_FAULT_CAPABILITY_REQUIRED_FEATURES_OFFSET",
            FAULT_CAPABILITY_REQUIRED_FEATURES_OFFSET,
        ),
        (
            "CRUCIBLE_FAULT_CAPABILITY_HASH_OFFSET",
            FAULT_CAPABILITY_HASH_OFFSET,
        ),
    ] {
        let _ = writeln!(out, "#define {name} {value}");
    }

    for (name, value) in [
        (
            "CRUCIBLE_FAULT_COMMAND_QUERY_CAPABILITIES",
            FaultCommandKind::QueryCapabilities as u16,
        ),
        (
            "CRUCIBLE_FAULT_COMMAND_BOUNDARY_PROBE",
            FaultCommandKind::BoundaryProbe as u16,
        ),
        (
            "CRUCIBLE_FAULT_COMMAND_NODE_LIFECYCLE",
            FaultCommandKind::NodeLifecycle as u16,
        ),
        (
            "CRUCIBLE_FAULT_COMMAND_NODE_HANG",
            FaultCommandKind::NodeHang as u16,
        ),
        (
            "CRUCIBLE_FAULT_COMMAND_CPU_SERVICE",
            FaultCommandKind::CpuService as u16,
        ),
        (
            "CRUCIBLE_FAULT_COMMAND_CPU_VCPU_STATE",
            FaultCommandKind::CpuVcpuState as u16,
        ),
        (
            "CRUCIBLE_FAULT_COMMAND_CPU_REGISTER_TRANSFORM",
            FaultCommandKind::CpuRegisterTransform as u16,
        ),
        (
            "CRUCIBLE_FAULT_COMMAND_CPU_INSTRUCTION_TRANSFORM",
            FaultCommandKind::CpuInstructionTransform as u16,
        ),
        (
            "CRUCIBLE_FAULT_COMMAND_CPU_EXCEPTION",
            FaultCommandKind::CpuException as u16,
        ),
        (
            "CRUCIBLE_FAULT_COMMAND_INTERRUPT_DISPOSITION",
            FaultCommandKind::InterruptDisposition as u16,
        ),
        (
            "CRUCIBLE_FAULT_COMMAND_INTERRUPT_STORM",
            FaultCommandKind::InterruptStorm as u16,
        ),
        (
            "CRUCIBLE_FAULT_COMMAND_MEMORY_MUTATION",
            FaultCommandKind::MemoryMutation as u16,
        ),
        (
            "CRUCIBLE_FAULT_COMMAND_MEMORY_ACCESS_TRANSFORM",
            FaultCommandKind::MemoryAccessTransform as u16,
        ),
        (
            "CRUCIBLE_FAULT_COMMAND_MEMORY_ECC_EVENT",
            FaultCommandKind::MemoryEccEvent as u16,
        ),
        (
            "CRUCIBLE_FAULT_COMMAND_MEMORY_REGION_STATE",
            FaultCommandKind::MemoryRegionState as u16,
        ),
        (
            "CRUCIBLE_FAULT_COMMAND_MEMORY_SERVICE",
            FaultCommandKind::MemoryService as u16,
        ),
        (
            "CRUCIBLE_FAULT_COMMAND_CLOCK_TRANSFORM",
            FaultCommandKind::ClockTransform as u16,
        ),
        (
            "CRUCIBLE_FAULT_COMMAND_CLOCK_SOURCE_STATE",
            FaultCommandKind::ClockSourceState as u16,
        ),
        (
            "CRUCIBLE_FAULT_COMMAND_ACCELERATOR_LIFECYCLE",
            FaultCommandKind::AcceleratorLifecycle as u16,
        ),
        (
            "CRUCIBLE_FAULT_COMMAND_ACCELERATOR_RESULT_TRANSFORM",
            FaultCommandKind::AcceleratorResultTransform as u16,
        ),
        (
            "CRUCIBLE_FAULT_COMMAND_ACCELERATOR_MEMORY_EVENT",
            FaultCommandKind::AcceleratorMemoryEvent as u16,
        ),
        (
            "CRUCIBLE_FAULT_COMMAND_ACCELERATOR_SERVICE",
            FaultCommandKind::AcceleratorService as u16,
        ),
    ] {
        let _ = writeln!(out, "#define {name} {value}");
    }

    for (name, value) in [
        (
            "CRUCIBLE_FAULT_PHASE_NODE_BOUNDARY",
            FaultBoundaryPhase::NodeBoundary as u16,
        ),
        (
            "CRUCIBLE_FAULT_PHASE_BEFORE_INSTRUCTION",
            FaultBoundaryPhase::BeforeInstruction as u16,
        ),
        (
            "CRUCIBLE_FAULT_PHASE_AFTER_INSTRUCTION",
            FaultBoundaryPhase::AfterInstruction as u16,
        ),
        (
            "CRUCIBLE_FAULT_PHASE_BEFORE_MEMORY_ACCESS",
            FaultBoundaryPhase::BeforeMemoryAccess as u16,
        ),
        (
            "CRUCIBLE_FAULT_PHASE_AFTER_MEMORY_ACCESS",
            FaultBoundaryPhase::AfterMemoryAccess as u16,
        ),
        (
            "CRUCIBLE_FAULT_PHASE_INTERRUPT",
            FaultBoundaryPhase::Interrupt as u16,
        ),
        (
            "CRUCIBLE_FAULT_PHASE_DEVICE",
            FaultBoundaryPhase::Device as u16,
        ),
        (
            "CRUCIBLE_FAULT_STATUS_APPLIED",
            FaultResultStatus::Applied as u16,
        ),
        (
            "CRUCIBLE_FAULT_STATUS_NOT_APPLICABLE",
            FaultResultStatus::NotApplicable as u16,
        ),
        (
            "CRUCIBLE_FAULT_STATUS_PRECONDITION_MISMATCH",
            FaultResultStatus::PreconditionMismatch as u16,
        ),
        (
            "CRUCIBLE_FAULT_STATUS_INVALID_TARGET",
            FaultResultStatus::InvalidTarget as u16,
        ),
        (
            "CRUCIBLE_FAULT_STATUS_INVALID_PHASE",
            FaultResultStatus::InvalidPhase as u16,
        ),
        (
            "CRUCIBLE_FAULT_STATUS_UNSUPPORTED_CAPABILITY",
            FaultResultStatus::UnsupportedCapability as u16,
        ),
        (
            "CRUCIBLE_FAULT_STATUS_PAST_BOUNDARY",
            FaultResultStatus::PastBoundary as u16,
        ),
        (
            "CRUCIBLE_FAULT_STATUS_RESOURCE_LIMIT",
            FaultResultStatus::ResourceLimit as u16,
        ),
        (
            "CRUCIBLE_FAULT_STATUS_GUEST_REJECTED",
            FaultResultStatus::GuestRejected as u16,
        ),
        (
            "CRUCIBLE_FAULT_STATUS_INTERNAL_ERROR",
            FaultResultStatus::InternalError as u16,
        ),
    ] {
        let _ = writeln!(out, "#define {name} {value}");
    }
    out.push_str("/* Headers and rows are byte arrays; use the offsets above with explicit little-endian loads/stores. */\n");
}

#[cfg(test)]
mod tests {
    use super::*;

    fn hash(value: &[u8]) -> [u8; 32] {
        *blake3::hash(value).as_bytes()
    }

    fn command(payload: &[u8]) -> FaultCommandHeaderV1 {
        FaultCommandHeaderV1 {
            abi_major: FAULT_COMMAND_ABI_MAJOR,
            abi_minor: FAULT_COMMAND_ABI_MINOR,
            command_kind: FaultCommandKind::MemoryMutation,
            command_flags: FAULT_COMMAND_FLAG_NONE,
            phase: FaultBoundaryPhase::NodeBoundary,
            semantic_version: FAULT_COMMAND_SEMANTIC_VERSION,
            command_sequence: 7,
            target_node_hash: hash(b"node"),
            target_icount: 10,
            authorization_ceiling_icount: 12,
            binding_hash: hash(b"binding"),
            opportunity_hash: [0; 32],
            expected_precondition_hash: hash(b"before"),
            payload_hash: hash(payload),
            payload_offset: 2,
            payload_length: u32::try_from(payload.len())
                .unwrap_or_else(|error| panic!("test payload length: {error}")),
        }
    }

    #[test]
    fn command_round_trip_authenticates_payload_and_reserved_bytes() {
        let payload = b"mutation";
        let mut arena = vec![0, 0];
        arena.extend_from_slice(payload);
        let value = command(payload);
        let bytes = value.encode();
        let (decoded, selected) = FaultCommandHeaderV1::decode(&bytes, &arena)
            .unwrap_or_else(|error| panic!("decode command: {error}"));
        assert_eq!(decoded, value);
        assert_eq!(selected, payload);

        let mut corrupt_payload = arena.clone();
        corrupt_payload[2] ^= 1;
        assert_eq!(
            FaultCommandHeaderV1::decode(&bytes, &corrupt_payload),
            Err(FaultAbiError::PayloadDigest)
        );
        let mut nonzero_reserved = bytes;
        nonzero_reserved[FAULT_COMMAND_HEADER_V1_BYTES - 1] = 1;
        assert_eq!(
            FaultCommandHeaderV1::decode(&nonzero_reserved, &arena),
            Err(FaultAbiError::ReservedNonzero)
        );
    }

    #[test]
    fn result_status_controls_mutation_evidence_invariants() {
        let payload = b"evidence";
        let value = FaultResultHeaderV1 {
            abi_major: FAULT_COMMAND_ABI_MAJOR,
            abi_minor: FAULT_COMMAND_ABI_MINOR,
            command_kind: FaultCommandKind::MemoryMutation,
            status: FaultResultStatus::Applied,
            semantic_version: FAULT_COMMAND_SEMANTIC_VERSION,
            command_sequence: 7,
            observed_icount: 10,
            applied_icount: 10,
            capability_version: 1,
            phase: FaultBoundaryPhase::NodeBoundary,
            before_hash: hash(b"before"),
            after_hash: hash(b"after"),
            evidence_hash: hash(b"handler-evidence"),
            result_payload_hash: hash(payload),
            result_offset: 0,
            result_length: u32::try_from(payload.len())
                .unwrap_or_else(|error| panic!("test result length: {error}")),
        };
        let bytes = value.encode();
        let (decoded, selected) = FaultResultHeaderV1::decode(&bytes, payload)
            .unwrap_or_else(|error| panic!("decode result: {error}"));
        assert_eq!(decoded, value);
        assert_eq!(selected, payload);

        let mut rejected = value;
        rejected.status = FaultResultStatus::InvalidTarget;
        assert_eq!(
            FaultResultHeaderV1::decode(&rejected.encode(), payload),
            Err(FaultAbiError::ResultInvariant)
        );
    }

    #[test]
    fn capability_manifest_is_sorted_bounded_and_content_addressed() {
        let row = |kind, scope| FaultCapabilityRowV1 {
            command_kind: kind,
            semantic_version: FAULT_COMMAND_SEMANTIC_VERSION,
            scope,
            phase_mask: FaultBoundaryPhase::NodeBoundary.bit(),
            maximum_payload_bytes: DEFAULT_FAULT_PAYLOAD_BYTES,
            maximum_pending_commands: DEFAULT_FAULT_COMMAND_CAPACITY,
            required_feature_bits: 1,
            capability_hash: hash(b"capability"),
        };
        let rows = [
            row(FaultCommandKind::NodeLifecycle, 1),
            row(FaultCommandKind::MemoryMutation, 1),
        ];
        let first = fault_capability_manifest_digest(&rows)
            .unwrap_or_else(|error| panic!("capability manifest: {error}"));
        let second = fault_capability_manifest_digest(&rows)
            .unwrap_or_else(|error| panic!("capability manifest twice: {error}"));
        assert_eq!(first, second);
        assert_eq!(
            fault_capability_manifest_digest(&[rows[1].clone(), rows[0].clone()]),
            Err(FaultAbiError::CapabilityInvariant)
        );
    }
}
