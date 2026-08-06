//! Closed byte-level fault command, result, and capability protocol.
//!
//! These values cross the Apache host/GPL QEMU process boundary only as
//! explicitly encoded little-endian bytes. They are not native Rust or C wire
//! layouts. Every decoder rejects unknown tags, nonzero reserved fields,
//! unsupported versions, invalid bounds, and unauthenticated payload bytes.

use crate::RingHeader;
use core::fmt::Write as _;
use core::sync::atomic::Ordering;
use thiserror::Error;

/// Fault command ABI major version.
pub const FAULT_COMMAND_ABI_MAJOR: u16 = 1;
/// Fault command ABI minor version.
pub const FAULT_COMMAND_ABI_MINOR: u16 = 1;
/// Exact semantic version implemented by every initial command kind.
pub const FAULT_COMMAND_SEMANTIC_VERSION: u32 = 1;
/// Default maximum encoded command or result payload bytes.
///
/// This is the exact envelope for 64 replacement actions whose cumulative
/// selected bytes reach the default 1 MiB ceiling: two bytes of mask/value
/// data per selected byte, every action header and record, and the batch
/// header.
pub const DEFAULT_FAULT_PAYLOAD_BYTES: u32 = 2_106_448;
/// Hard maximum command or result payload bytes.
///
/// This admits 64 replacement actions whose cumulative selected bytes reach
/// the 16 MiB hard ceiling, including every action header and record plus the
/// batch header.
pub const HARD_FAULT_PAYLOAD_BYTES: u32 = 33_563_728;
/// Default bytes reserved for each per-node command or result payload arena.
pub const DEFAULT_FAULT_PAYLOAD_ARENA_BYTES: u32 = DEFAULT_FAULT_PAYLOAD_BYTES;
/// Hard ceiling for each per-node command or result payload arena.
pub const HARD_FAULT_PAYLOAD_ARENA_BYTES: u32 = HARD_FAULT_PAYLOAD_BYTES;
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

/// Exact shared-memory size of one command transport slot.
pub const FAULT_COMMAND_SLOT_V1_BYTES: usize = 256;
/// Exact shared-memory size of one result transport slot.
pub const FAULT_RESULT_SLOT_V1_BYTES: usize = 256;
/// Exact shared-memory size of one payload-arena cursor header.
pub const FAULT_PAYLOAD_ARENA_HEADER_BYTES: usize = 128;
/// Command-slot reservation-start field offset.
pub const FAULT_COMMAND_SLOT_RESERVATION_START_OFFSET: usize =
    core::mem::offset_of!(FaultCommandSlotV1, reservation_start);
/// Command-slot payload-start field offset.
pub const FAULT_COMMAND_SLOT_PAYLOAD_START_OFFSET: usize =
    core::mem::offset_of!(FaultCommandSlotV1, payload_start);
/// Command-slot reservation-end field offset.
pub const FAULT_COMMAND_SLOT_RESERVATION_END_OFFSET: usize =
    core::mem::offset_of!(FaultCommandSlotV1, reservation_end);
/// Command-slot encoded-header field offset.
pub const FAULT_COMMAND_SLOT_HEADER_OFFSET: usize =
    core::mem::offset_of!(FaultCommandSlotV1, header);
/// Result-slot reservation-start field offset.
pub const FAULT_RESULT_SLOT_RESERVATION_START_OFFSET: usize =
    core::mem::offset_of!(FaultResultSlotV1, reservation_start);
/// Result-slot payload-start field offset.
pub const FAULT_RESULT_SLOT_PAYLOAD_START_OFFSET: usize =
    core::mem::offset_of!(FaultResultSlotV1, payload_start);
/// Result-slot reservation-end field offset.
pub const FAULT_RESULT_SLOT_RESERVATION_END_OFFSET: usize =
    core::mem::offset_of!(FaultResultSlotV1, reservation_end);
/// Result-slot encoded-header field offset.
pub const FAULT_RESULT_SLOT_HEADER_OFFSET: usize = core::mem::offset_of!(FaultResultSlotV1, header);
/// Payload-arena consumer-cursor field offset.
pub const FAULT_PAYLOAD_ARENA_READ_CURSOR_OFFSET: usize =
    core::mem::offset_of!(FaultPayloadArenaHeader, read_cursor);
/// Payload-arena producer-cursor field offset.
pub const FAULT_PAYLOAD_ARENA_WRITE_CURSOR_OFFSET: usize =
    core::mem::offset_of!(FaultPayloadArenaHeader, write_cursor);

/// One command-ring slot with transport-owned payload reservation metadata.
///
/// The reservation cursors are outside the authenticated command envelope so a
/// consumer can release arena space even when the command itself is malformed.
/// A valid command must independently agree with these bounds.
#[derive(Clone, Copy)]
#[repr(C, align(64))]
pub struct FaultCommandSlotV1 {
    reservation_start: u64,
    payload_start: u64,
    reservation_end: u64,
    header: [u8; FAULT_COMMAND_HEADER_V1_BYTES],
    _reserved: [u8; 16],
}

impl FaultCommandSlotV1 {
    /// Builds a zeroed, unpublished command slot.
    #[must_use]
    pub const fn new() -> Self {
        Self {
            reservation_start: 0,
            payload_start: 0,
            reservation_end: 0,
            header: [0; FAULT_COMMAND_HEADER_V1_BYTES],
            _reserved: [0; 16],
        }
    }

    pub(crate) fn write_bytes(&self, bytes: &mut [u8]) {
        bytes.fill(0);
        bytes[0..8].copy_from_slice(&self.reservation_start.to_le_bytes());
        bytes[8..16].copy_from_slice(&self.payload_start.to_le_bytes());
        bytes[16..24].copy_from_slice(&self.reservation_end.to_le_bytes());
        bytes[24..24 + FAULT_COMMAND_HEADER_V1_BYTES].copy_from_slice(&self.header);
    }
}

impl Default for FaultCommandSlotV1 {
    fn default() -> Self {
        Self::new()
    }
}

/// One result-ring slot with transport-owned payload reservation metadata.
#[derive(Clone, Copy)]
#[repr(C, align(64))]
pub struct FaultResultSlotV1 {
    reservation_start: u64,
    payload_start: u64,
    reservation_end: u64,
    header: [u8; FAULT_RESULT_HEADER_V1_BYTES],
    _reserved: [u8; 44],
}

impl FaultResultSlotV1 {
    /// Builds a zeroed, unpublished result slot.
    #[must_use]
    pub const fn new() -> Self {
        Self {
            reservation_start: 0,
            payload_start: 0,
            reservation_end: 0,
            header: [0; FAULT_RESULT_HEADER_V1_BYTES],
            _reserved: [0; 44],
        }
    }

    pub(crate) fn write_bytes(&self, bytes: &mut [u8]) {
        bytes.fill(0);
        bytes[0..8].copy_from_slice(&self.reservation_start.to_le_bytes());
        bytes[8..16].copy_from_slice(&self.payload_start.to_le_bytes());
        bytes[16..24].copy_from_slice(&self.reservation_end.to_le_bytes());
        bytes[24..24 + FAULT_RESULT_HEADER_V1_BYTES].copy_from_slice(&self.header);
    }
}

impl Default for FaultResultSlotV1 {
    fn default() -> Self {
        Self::new()
    }
}

/// SPSC byte-arena cursors shared by one payload producer and one consumer.
///
/// Cursors are monotonically increasing logical byte positions. Physical
/// offsets wrap within the fixed arena, but one payload is always contiguous;
/// the producer accounts for skipped tail bytes in the published reservation.
#[repr(C, align(128))]
pub struct FaultPayloadArenaHeader {
    read_cursor: core::sync::atomic::AtomicU64,
    _pad_read: [u8; 56],
    write_cursor: core::sync::atomic::AtomicU64,
    _pad_write: [u8; 56],
}

impl Clone for FaultPayloadArenaHeader {
    fn clone(&self) -> Self {
        Self {
            read_cursor: core::sync::atomic::AtomicU64::new(
                self.read_cursor.load(core::sync::atomic::Ordering::Acquire),
            ),
            _pad_read: [0; 56],
            write_cursor: core::sync::atomic::AtomicU64::new(
                self.write_cursor
                    .load(core::sync::atomic::Ordering::Acquire),
            ),
            _pad_write: [0; 56],
        }
    }
}

impl FaultPayloadArenaHeader {
    /// Builds an empty payload arena header.
    #[must_use]
    pub const fn new() -> Self {
        Self {
            read_cursor: core::sync::atomic::AtomicU64::new(0),
            _pad_read: [0; 56],
            write_cursor: core::sync::atomic::AtomicU64::new(0),
            _pad_write: [0; 56],
        }
    }

    /// Returns the consumer-owned logical read cursor.
    #[must_use]
    pub fn read_cursor(&self) -> u64 {
        self.read_cursor.load(core::sync::atomic::Ordering::Acquire)
    }

    /// Returns the producer-owned logical write cursor.
    #[must_use]
    pub fn write_cursor(&self) -> u64 {
        self.write_cursor
            .load(core::sync::atomic::Ordering::Acquire)
    }

    /// Returns whether all cache-line padding bytes remain zero.
    #[must_use]
    pub fn padding_bytes_are_zero(&self) -> bool {
        self._pad_read.iter().all(|byte| *byte == 0)
            && self._pad_write.iter().all(|byte| *byte == 0)
    }

    pub(crate) fn write_bytes(&self, bytes: &mut [u8]) {
        bytes.fill(0);
        bytes[0..8].copy_from_slice(&self.read_cursor().to_le_bytes());
        bytes[64..72].copy_from_slice(&self.write_cursor().to_le_bytes());
    }
}

impl Default for FaultPayloadArenaHeader {
    fn default() -> Self {
        Self::new()
    }
}

const _: () = assert!(core::mem::size_of::<FaultCommandSlotV1>() == FAULT_COMMAND_SLOT_V1_BYTES);
const _: () = assert!(core::mem::align_of::<FaultCommandSlotV1>() == 64);
const _: () = assert!(core::mem::size_of::<FaultResultSlotV1>() == FAULT_RESULT_SLOT_V1_BYTES);
const _: () = assert!(core::mem::align_of::<FaultResultSlotV1>() == 64);
const _: () =
    assert!(core::mem::size_of::<FaultPayloadArenaHeader>() == FAULT_PAYLOAD_ARENA_HEADER_BYTES);
const _: () = assert!(core::mem::align_of::<FaultPayloadArenaHeader>() == 128);
const _: () = assert!(FAULT_COMMAND_SLOT_RESERVATION_START_OFFSET == 0);
const _: () = assert!(FAULT_COMMAND_SLOT_PAYLOAD_START_OFFSET == 8);
const _: () = assert!(FAULT_COMMAND_SLOT_RESERVATION_END_OFFSET == 16);
const _: () = assert!(FAULT_COMMAND_SLOT_HEADER_OFFSET == 24);
const _: () = assert!(FAULT_RESULT_SLOT_RESERVATION_START_OFFSET == 0);
const _: () = assert!(FAULT_RESULT_SLOT_PAYLOAD_START_OFFSET == 8);
const _: () = assert!(FAULT_RESULT_SLOT_RESERVATION_END_OFFSET == 16);
const _: () = assert!(FAULT_RESULT_SLOT_HEADER_OFFSET == 24);
const _: () = assert!(FAULT_PAYLOAD_ARENA_READ_CURSOR_OFFSET == 0);
const _: () = assert!(FAULT_PAYLOAD_ARENA_WRITE_CURSOR_OFFSET == 64);

/// No optional command behavior is selected.
pub const FAULT_COMMAND_FLAG_NONE: u16 = 0;
/// Resolves and authenticates a mutation without making guest-visible changes.
pub const FAULT_COMMAND_FLAG_PREPARE_ONLY: u16 = 1 << 0;
/// The only bit mask accepted for command flags in ABI v1.
pub const FAULT_COMMAND_FLAGS_V1_MASK: u16 = FAULT_COMMAND_FLAG_PREPARE_ONLY;

/// Closed capability scope shared by the host, plugin, and QEMU dispatcher.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
#[repr(u16)]
pub enum FaultCapabilityScope {
    /// Capability is architecture-independent.
    All = 1,
    /// Capability applies only to x86-64 targets.
    X86_64 = 2,
    /// Capability applies only to AArch64 targets.
    Aarch64 = 3,
    /// Capability applies to an explicitly identified virtio device class.
    Virtio = 4,
    /// Capability applies to a non-virtio device class named by its schema.
    Device = 5,
    /// Capability applies to an accelerator class named by its schema.
    Accelerator = 6,
}

impl FaultCapabilityScope {
    /// Decodes one exact registered scope tag.
    ///
    /// # Errors
    ///
    /// Returns [`FaultAbiError::CapabilityInvariant`] for an unknown scope.
    pub fn from_u16(value: u16) -> Result<Self, FaultAbiError> {
        match value {
            1 => Ok(Self::All),
            2 => Ok(Self::X86_64),
            3 => Ok(Self::Aarch64),
            4 => Ok(Self::Virtio),
            5 => Ok(Self::Device),
            6 => Ok(Self::Accelerator),
            _ => Err(FaultAbiError::CapabilityInvariant),
        }
    }
}

/// Memory-mutation patch feature requirement.
pub const FAULT_CAPABILITY_FEATURE_MEMORY_MUTATION: u64 = 1 << 0;
/// Memory-access patch feature requirement.
pub const FAULT_CAPABILITY_FEATURE_MEMORY_ACCESS: u64 = 1 << 1;
/// Register-mutation patch feature requirement.
pub const FAULT_CAPABILITY_FEATURE_REGISTER_MUTATION: u64 = 1 << 2;
/// Instruction-fault patch feature requirement.
pub const FAULT_CAPABILITY_FEATURE_INSTRUCTION: u64 = 1 << 3;
/// Interrupt-fault patch feature requirement.
pub const FAULT_CAPABILITY_FEATURE_INTERRUPT: u64 = 1 << 4;
/// Hardware-error patch feature requirement.
pub const FAULT_CAPABILITY_FEATURE_HARDWARE_ERROR: u64 = 1 << 5;
/// vCPU-service patch feature requirement.
pub const FAULT_CAPABILITY_FEATURE_VCPU_SERVICE: u64 = 1 << 6;
/// Node-lifecycle patch feature requirement.
pub const FAULT_CAPABILITY_FEATURE_NODE_LIFECYCLE: u64 = 1 << 7;
/// Guest-clock patch feature requirement.
pub const FAULT_CAPABILITY_FEATURE_GUEST_CLOCK: u64 = 1 << 8;
/// Accelerator-device patch feature requirement.
pub const FAULT_CAPABILITY_FEATURE_ACCELERATOR: u64 = 1 << 9;
/// Fault-VMState patch feature requirement.
pub const FAULT_CAPABILITY_FEATURE_VMSTATE: u64 = 1 << 10;
/// Every feature bit understood by capability ABI v1.
pub const FAULT_CAPABILITY_FEATURES_V1_MASK: u64 = (1 << 11) - 1;

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

    /// Returns this phase's bit in a capability `phase_mask`.
    #[must_use]
    pub const fn bit(self) -> u32 {
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
    /// The command envelope or typed payload is not canonically encoded.
    MalformedCommand = 11,
    /// The command sequence was already accepted or is not monotonic.
    DuplicateSequence = 12,
    /// The command or result payload failed digest authentication.
    AuthenticationFailed = 13,
    /// Preconditions were resolved at a frozen boundary without mutation.
    Prepared = 14,
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
            11 => Ok(Self::MalformedCommand),
            12 => Ok(Self::DuplicateSequence),
            13 => Ok(Self::AuthenticationFailed),
            14 => Ok(Self::Prepared),
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

/// One command removed from the transport after its arena reservation is freed.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum DequeuedFaultCommand {
    /// The envelope and copied payload passed every ABI check.
    Valid {
        /// Decoded command envelope.
        header: Box<FaultCommandHeaderV1>,
        /// Owned payload bytes, no longer borrowed from shared memory.
        payload: Vec<u8>,
    },
    /// The transport framing was sound but the command ABI was rejected.
    Rejected {
        /// Raw kind tag, preserved even when it is not registered.
        raw_command_kind: u16,
        /// Raw sequence, preserved for a canonical result when nonzero.
        command_sequence: u64,
        /// Exact ABI validation failure.
        error: FaultAbiError,
    },
}

/// Enqueues one command and payload with release publication.
///
/// The operation first proves that both the command ring and circular byte
/// arena have capacity. It then copies the payload, writes the complete slot,
/// publishes the arena cursor, and finally publishes the ring index. A failure
/// before publication changes neither shared cursor.
///
/// `arena_region_offset` is the byte offset of `arena` from the shared region
/// base and is encoded into the command header.
///
/// # Errors
///
/// Returns [`FaultTransportError`] when a capacity, index, payload, arithmetic,
/// or command-envelope invariant is violated.
pub fn enqueue_fault_command(
    ring: &RingHeader,
    slots: &mut [FaultCommandSlotV1],
    arena_header: &FaultPayloadArenaHeader,
    arena: &mut [u8],
    arena_region_offset: u64,
    mut header: FaultCommandHeaderV1,
    payload: &[u8],
) -> Result<(), FaultTransportError> {
    let (tail, slot_index) = producer_ring_slot(ring, slots.len())?;
    let reservation = reserve_arena(arena_header, arena.len(), payload.len())?;
    copy_payload(arena, reservation.payload_start, payload)?;

    header.payload_offset = if payload.is_empty() {
        0
    } else {
        arena_region_offset
            .checked_add(reservation.payload_start % arena_len_u64(arena.len())?)
            .ok_or(FaultTransportError::ArithmeticOverflow)?
    };
    header.payload_length = u32::try_from(payload.len())
        .map_err(|_| FaultTransportError::PayloadTooLarge { len: payload.len() })?;
    header.payload_hash = *blake3::hash(payload).as_bytes();
    header.validate().map_err(FaultTransportError::Abi)?;

    slots[slot_index] = FaultCommandSlotV1 {
        reservation_start: reservation.start,
        payload_start: reservation.payload_start,
        reservation_end: reservation.end,
        header: header.encode(),
        _reserved: [0; 16],
    };
    arena_header
        .write_cursor
        .store(reservation.end, Ordering::Release);
    ring.write_idx
        .store(tail.wrapping_add(1), Ordering::Release);
    Ok(())
}

/// Removes one command, copies its payload, and releases its transport space.
///
/// ABI-invalid commands are returned as [`DequeuedFaultCommand::Rejected`] and
/// still consume their sound transport reservation, preventing a malformed
/// host command from wedging the plugin. Corrupt transport-owned framing fails
/// loudly because advancing an untrusted cursor would risk releasing live data.
///
/// # Errors
///
/// Returns [`FaultTransportError`] for invalid capacity, corrupt indices,
/// inconsistent reservation framing, or arithmetic overflow.
pub fn dequeue_fault_command(
    ring: &RingHeader,
    slots: &[FaultCommandSlotV1],
    arena_header: &FaultPayloadArenaHeader,
    arena: &[u8],
    arena_region_offset: u64,
) -> Result<Option<DequeuedFaultCommand>, FaultTransportError> {
    let Some((head, slot_index)) = consumer_ring_slot(ring, slots.len())? else {
        return Ok(None);
    };
    let slot = slots[slot_index];
    let payload = copy_reserved_payload(
        arena_header,
        arena,
        slot.reservation_start,
        slot.payload_start,
        slot.reservation_end,
    )?;
    let raw_command_kind = read_raw_u16(&slot.header, FAULT_COMMAND_KIND_OFFSET);
    let command_sequence = read_raw_u64(&slot.header, FAULT_COMMAND_SEQUENCE_OFFSET);
    let decoded = FaultCommandHeaderV1::decode_header(&slot.header).and_then(|header| {
        validate_envelope_reservation(
            header.payload_offset,
            header.payload_length,
            arena_region_offset,
            arena.len(),
            slot.payload_start,
            slot.reservation_end,
        )?;
        header.authenticate_payload(&payload)?;
        Ok(header)
    });

    arena_header
        .read_cursor
        .store(slot.reservation_end, Ordering::Release);
    ring.read_idx.store(head.wrapping_add(1), Ordering::Release);

    Ok(Some(match decoded {
        Ok(header) => DequeuedFaultCommand::Valid {
            header: Box::new(header),
            payload,
        },
        Err(error) => DequeuedFaultCommand::Rejected {
            raw_command_kind,
            command_sequence,
            error,
        },
    }))
}

/// One result removed from the transport after its arena reservation is freed.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum DequeuedFaultResult {
    /// The result envelope and copied evidence payload passed every ABI check.
    Valid {
        /// Decoded result envelope.
        header: FaultResultHeaderV1,
        /// Owned result payload bytes.
        payload: Vec<u8>,
    },
    /// A malformed result was consumed and must fail the run loudly.
    Invalid {
        /// Raw command sequence for diagnostics and correlation.
        command_sequence: u64,
        /// Exact ABI validation failure.
        error: FaultAbiError,
    },
}

/// Enqueues one QEMU result and payload with release publication.
///
/// # Errors
///
/// Returns [`FaultTransportError`] when ring or arena capacity is exhausted, a
/// cursor is corrupt, arithmetic overflows, or the result violates its ABI.
pub fn enqueue_fault_result(
    ring: &RingHeader,
    slots: &mut [FaultResultSlotV1],
    arena_header: &FaultPayloadArenaHeader,
    arena: &mut [u8],
    arena_region_offset: u64,
    mut header: FaultResultHeaderV1,
    payload: &[u8],
) -> Result<(), FaultTransportError> {
    let (tail, slot_index) = producer_ring_slot(ring, slots.len())?;
    let reservation = reserve_arena(arena_header, arena.len(), payload.len())?;
    copy_payload(arena, reservation.payload_start, payload)?;

    header.result_offset = if payload.is_empty() {
        0
    } else {
        arena_region_offset
            .checked_add(reservation.payload_start % arena_len_u64(arena.len())?)
            .ok_or(FaultTransportError::ArithmeticOverflow)?
    };
    header.result_length = u32::try_from(payload.len())
        .map_err(|_| FaultTransportError::PayloadTooLarge { len: payload.len() })?;
    header.result_payload_hash = *blake3::hash(payload).as_bytes();
    FaultResultHeaderV1::decode_header(&header.encode()).map_err(FaultTransportError::Abi)?;

    slots[slot_index] = FaultResultSlotV1 {
        reservation_start: reservation.start,
        payload_start: reservation.payload_start,
        reservation_end: reservation.end,
        header: header.encode(),
        _reserved: [0; 44],
    };
    arena_header
        .write_cursor
        .store(reservation.end, Ordering::Release);
    ring.write_idx
        .store(tail.wrapping_add(1), Ordering::Release);
    Ok(())
}

/// Reports whether one result payload can be published without mutation.
///
/// This preflight is exact for the single plugin producer: it checks the same
/// ring slot and contiguous arena reservation used by [`enqueue_fault_result`]
/// but advances no cursor. The caller must serialize preflight and enqueue.
///
/// # Errors
///
/// Returns [`FaultTransportError`] for invalid capacities, corrupt cursors,
/// payloads above the hard bound, or arithmetic overflow. Ordinary ring or
/// arena backpressure returns `Ok(false)`.
pub fn can_enqueue_fault_result(
    ring: &RingHeader,
    slots: &[FaultResultSlotV1],
    arena_header: &FaultPayloadArenaHeader,
    arena: &[u8],
    payload_len: usize,
) -> Result<bool, FaultTransportError> {
    match producer_ring_slot(ring, slots.len()) {
        Ok((_tail, _slot)) => {}
        Err(FaultTransportError::RingFull { .. }) => return Ok(false),
        Err(error) => return Err(error),
    }
    match reserve_arena(arena_header, arena.len(), payload_len) {
        Ok(_reservation) => Ok(true),
        Err(FaultTransportError::PayloadArenaFull { .. }) => Ok(false),
        Err(error) => Err(error),
    }
}

/// Removes one result, copies its payload, and releases its transport space.
///
/// Sound transport framing is consumed even when the result ABI is invalid so
/// a bad plugin result cannot permanently fill the ring. The returned invalid
/// value is a mandatory run failure, never a simulated guest outcome.
///
/// # Errors
///
/// Returns [`FaultTransportError`] for invalid capacity, corrupt indices,
/// inconsistent reservation framing, or arithmetic overflow.
pub fn dequeue_fault_result(
    ring: &RingHeader,
    slots: &[FaultResultSlotV1],
    arena_header: &FaultPayloadArenaHeader,
    arena: &[u8],
    arena_region_offset: u64,
) -> Result<Option<DequeuedFaultResult>, FaultTransportError> {
    let Some((head, slot_index)) = consumer_ring_slot(ring, slots.len())? else {
        return Ok(None);
    };
    let slot = slots[slot_index];
    let payload = copy_reserved_payload(
        arena_header,
        arena,
        slot.reservation_start,
        slot.payload_start,
        slot.reservation_end,
    )?;
    let command_sequence = read_raw_u64(&slot.header, FAULT_RESULT_SEQUENCE_OFFSET);
    let decoded = FaultResultHeaderV1::decode_header(&slot.header).and_then(|header| {
        validate_envelope_reservation(
            header.result_offset,
            header.result_length,
            arena_region_offset,
            arena.len(),
            slot.payload_start,
            slot.reservation_end,
        )?;
        header.authenticate_payload(&payload)?;
        Ok(header)
    });

    arena_header
        .read_cursor
        .store(slot.reservation_end, Ordering::Release);
    ring.read_idx.store(head.wrapping_add(1), Ordering::Release);

    Ok(Some(match decoded {
        Ok(header) => DequeuedFaultResult::Valid { header, payload },
        Err(error) => DequeuedFaultResult::Invalid {
            command_sequence,
            error,
        },
    }))
}

#[derive(Clone, Copy)]
struct ArenaReservation {
    start: u64,
    payload_start: u64,
    end: u64,
}

fn producer_ring_slot(
    ring: &RingHeader,
    capacity: usize,
) -> Result<(u64, usize), FaultTransportError> {
    let capacity = validated_transport_capacity(capacity)?;
    let tail = ring.write_idx.load(Ordering::Relaxed);
    let head = ring.read_idx.load(Ordering::Acquire);
    let live = tail.wrapping_sub(head);
    if live > capacity {
        return Err(FaultTransportError::CorruptRingIndices {
            read: head,
            write: tail,
            capacity,
        });
    }
    if live == capacity {
        return Err(FaultTransportError::RingFull { capacity });
    }
    Ok((tail, (tail & (capacity - 1)) as usize))
}

fn consumer_ring_slot(
    ring: &RingHeader,
    capacity: usize,
) -> Result<Option<(u64, usize)>, FaultTransportError> {
    let capacity = validated_transport_capacity(capacity)?;
    let head = ring.read_idx.load(Ordering::Relaxed);
    let tail = ring.write_idx.load(Ordering::Acquire);
    let live = tail.wrapping_sub(head);
    if live > capacity {
        return Err(FaultTransportError::CorruptRingIndices {
            read: head,
            write: tail,
            capacity,
        });
    }
    Ok((live != 0).then_some((head, (head & (capacity - 1)) as usize)))
}

fn validated_transport_capacity(capacity: usize) -> Result<u64, FaultTransportError> {
    if capacity == 0
        || !capacity.is_power_of_two()
        || capacity > HARD_FAULT_COMMAND_CAPACITY as usize
    {
        return Err(FaultTransportError::InvalidRingCapacity { capacity });
    }
    Ok(capacity as u64)
}

fn arena_len_u64(len: usize) -> Result<u64, FaultTransportError> {
    if len == 0 || len > HARD_FAULT_PAYLOAD_BYTES as usize {
        return Err(FaultTransportError::InvalidArenaCapacity { capacity: len });
    }
    u64::try_from(len).map_err(|_| FaultTransportError::ArithmeticOverflow)
}

fn reserve_arena(
    header: &FaultPayloadArenaHeader,
    arena_len: usize,
    payload_len: usize,
) -> Result<ArenaReservation, FaultTransportError> {
    let capacity = arena_len_u64(arena_len)?;
    let payload_len_usize = payload_len;
    let payload_len = u64::try_from(payload_len)
        .map_err(|_| FaultTransportError::PayloadTooLarge { len: payload_len })?;
    if payload_len > capacity || payload_len > u64::from(HARD_FAULT_PAYLOAD_BYTES) {
        return Err(FaultTransportError::PayloadTooLarge {
            len: payload_len_usize,
        });
    }
    let write = header.write_cursor.load(Ordering::Relaxed);
    let read = header.read_cursor.load(Ordering::Acquire);
    let live = write.wrapping_sub(read);
    if live > capacity {
        return Err(FaultTransportError::CorruptArenaCursors {
            read,
            write,
            capacity,
        });
    }
    if payload_len == 0 {
        return Ok(ArenaReservation {
            start: write,
            payload_start: write,
            end: write,
        });
    }
    let physical = write % capacity;
    let remaining = capacity - physical;
    let padding = if payload_len > remaining {
        remaining
    } else {
        0
    };
    let reservation_len = padding
        .checked_add(payload_len)
        .ok_or(FaultTransportError::ArithmeticOverflow)?;
    if live
        .checked_add(reservation_len)
        .ok_or(FaultTransportError::ArithmeticOverflow)?
        > capacity
    {
        return Err(FaultTransportError::PayloadArenaFull {
            requested: reservation_len,
            available: capacity - live,
        });
    }
    let payload_start = write
        .checked_add(padding)
        .ok_or(FaultTransportError::ArithmeticOverflow)?;
    let end = payload_start
        .checked_add(payload_len)
        .ok_or(FaultTransportError::ArithmeticOverflow)?;
    Ok(ArenaReservation {
        start: write,
        payload_start,
        end,
    })
}

fn copy_payload(
    arena: &mut [u8],
    logical_start: u64,
    payload: &[u8],
) -> Result<(), FaultTransportError> {
    if payload.is_empty() {
        return Ok(());
    }
    let capacity = arena_len_u64(arena.len())?;
    let start = usize::try_from(logical_start % capacity)
        .map_err(|_| FaultTransportError::ArithmeticOverflow)?;
    let end = start
        .checked_add(payload.len())
        .ok_or(FaultTransportError::ArithmeticOverflow)?;
    let destination = arena
        .get_mut(start..end)
        .ok_or(FaultTransportError::CorruptReservation)?;
    destination.copy_from_slice(payload);
    Ok(())
}

fn copy_reserved_payload(
    header: &FaultPayloadArenaHeader,
    arena: &[u8],
    start: u64,
    payload_start: u64,
    end: u64,
) -> Result<Vec<u8>, FaultTransportError> {
    let capacity = arena_len_u64(arena.len())?;
    let expected_start = header.read_cursor.load(Ordering::Relaxed);
    let published_end = header.write_cursor.load(Ordering::Acquire);
    if start != expected_start
        || payload_start < start
        || end < payload_start
        || end.wrapping_sub(start) > capacity
        || end > published_end
    {
        return Err(FaultTransportError::CorruptReservation);
    }
    let physical_start = usize::try_from(payload_start % capacity)
        .map_err(|_| FaultTransportError::ArithmeticOverflow)?;
    let payload_len = usize::try_from(end - payload_start)
        .map_err(|_| FaultTransportError::ArithmeticOverflow)?;
    let physical_end = physical_start
        .checked_add(payload_len)
        .ok_or(FaultTransportError::ArithmeticOverflow)?;
    arena
        .get(physical_start..physical_end)
        .map(<[u8]>::to_vec)
        .ok_or(FaultTransportError::CorruptReservation)
}

fn validate_envelope_reservation(
    payload_offset: u64,
    payload_length: u32,
    arena_region_offset: u64,
    arena_len: usize,
    payload_start: u64,
    reservation_end: u64,
) -> Result<(), FaultAbiError> {
    if payload_length == 0 {
        return (payload_offset == 0 && payload_start == reservation_end)
            .then_some(())
            .ok_or(FaultAbiError::PayloadBounds);
    }
    let capacity = u64::try_from(arena_len).map_err(|_| FaultAbiError::PayloadBounds)?;
    let expected_offset = arena_region_offset
        .checked_add(payload_start % capacity)
        .ok_or(FaultAbiError::PayloadBounds)?;
    if payload_offset != expected_offset
        || reservation_end.wrapping_sub(payload_start) != u64::from(payload_length)
    {
        return Err(FaultAbiError::PayloadBounds);
    }
    Ok(())
}

fn read_raw_u16(bytes: &[u8], offset: usize) -> u16 {
    bytes
        .get(offset..offset + 2)
        .and_then(|value| <[u8; 2]>::try_from(value).ok())
        .map(u16::from_le_bytes)
        .unwrap_or(0)
}

fn read_raw_u64(bytes: &[u8], offset: usize) -> u64 {
    bytes
        .get(offset..offset + 8)
        .and_then(|value| <[u8; 8]>::try_from(value).ok())
        .map(u64::from_le_bytes)
        .unwrap_or(0)
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

/// Shared-memory fault command transport failure.
#[derive(Clone, Debug, Error, PartialEq, Eq)]
pub enum FaultTransportError {
    /// The command/result ring capacity is invalid for the ABI.
    #[error("fault transport ring capacity {capacity} is invalid")]
    InvalidRingCapacity {
        /// Invalid entry count.
        capacity: usize,
    },
    /// The payload arena capacity is zero or exceeds the ABI hard bound.
    #[error("fault payload arena capacity {capacity} is invalid")]
    InvalidArenaCapacity {
        /// Invalid byte capacity.
        capacity: usize,
    },
    /// The command/result ring cannot accept another entry.
    #[error("fault command/result ring is full at capacity {capacity}")]
    RingFull {
        /// Fixed entry capacity.
        capacity: u64,
    },
    /// The payload arena cannot accept one contiguous reservation.
    #[error("fault payload arena has {available} bytes available, need {requested}")]
    PayloadArenaFull {
        /// Requested payload plus any required wrap padding.
        requested: u64,
        /// Currently free bytes.
        available: u64,
    },
    /// One payload cannot fit under the configured or hard limit.
    #[error("fault payload length {len} exceeds the arena or ABI limit")]
    PayloadTooLarge {
        /// Rejected payload length.
        len: usize,
    },
    /// Producer and consumer indices describe more live entries than capacity.
    #[error("fault ring indices are corrupt: read={read} write={write} capacity={capacity}")]
    CorruptRingIndices {
        /// Consumer-owned index.
        read: u64,
        /// Producer-owned index.
        write: u64,
        /// Fixed entry capacity.
        capacity: u64,
    },
    /// Producer and consumer byte cursors describe impossible live storage.
    #[error("fault arena cursors are corrupt: read={read} write={write} capacity={capacity}")]
    CorruptArenaCursors {
        /// Consumer-owned cursor.
        read: u64,
        /// Producer-owned cursor.
        write: u64,
        /// Fixed byte capacity.
        capacity: u64,
    },
    /// Slot-owned reservation framing disagrees with the arena state.
    #[error("fault payload reservation framing is corrupt")]
    CorruptReservation,
    /// An offset, cursor, or length calculation overflowed.
    #[error("fault transport arithmetic overflow")]
    ArithmeticOverflow,
    /// The command envelope violates the byte-level ABI.
    #[error(transparent)]
    Abi(FaultAbiError),
}

pub(crate) fn emit_fault_command_c_header(out: &mut String) {
    macro_rules! define {
        ($name:expr, $value:expr) => {
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
        "CRUCIBLE_FAULT_DEFAULT_PAYLOAD_ARENA_BYTES",
        DEFAULT_FAULT_PAYLOAD_ARENA_BYTES
    );
    define!(
        "CRUCIBLE_FAULT_HARD_PAYLOAD_ARENA_BYTES",
        HARD_FAULT_PAYLOAD_ARENA_BYTES
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
    define!(
        "CRUCIBLE_FAULT_COMMAND_SLOT_V1_BYTES",
        FAULT_COMMAND_SLOT_V1_BYTES
    );
    define!(
        "CRUCIBLE_FAULT_RESULT_SLOT_V1_BYTES",
        FAULT_RESULT_SLOT_V1_BYTES
    );
    define!(
        "CRUCIBLE_FAULT_PAYLOAD_ARENA_HEADER_BYTES",
        FAULT_PAYLOAD_ARENA_HEADER_BYTES
    );
    define!(
        "CRUCIBLE_FAULT_CAPABILITY_SCOPE_ALL",
        FaultCapabilityScope::All as u16
    );
    define!(
        "CRUCIBLE_FAULT_CAPABILITY_SCOPE_X86_64",
        FaultCapabilityScope::X86_64 as u16
    );
    define!(
        "CRUCIBLE_FAULT_CAPABILITY_SCOPE_AARCH64",
        FaultCapabilityScope::Aarch64 as u16
    );
    define!(
        "CRUCIBLE_FAULT_CAPABILITY_SCOPE_VIRTIO",
        FaultCapabilityScope::Virtio as u16
    );
    define!(
        "CRUCIBLE_FAULT_CAPABILITY_SCOPE_DEVICE",
        FaultCapabilityScope::Device as u16
    );
    define!(
        "CRUCIBLE_FAULT_CAPABILITY_SCOPE_ACCELERATOR",
        FaultCapabilityScope::Accelerator as u16
    );
    define!(
        "CRUCIBLE_FAULT_CAPABILITY_FEATURES_V1_MASK",
        FAULT_CAPABILITY_FEATURES_V1_MASK
    );
    for (name, value) in [
        (
            "CRUCIBLE_FAULT_CAPABILITY_FEATURE_MEMORY_MUTATION",
            FAULT_CAPABILITY_FEATURE_MEMORY_MUTATION,
        ),
        (
            "CRUCIBLE_FAULT_CAPABILITY_FEATURE_MEMORY_ACCESS",
            FAULT_CAPABILITY_FEATURE_MEMORY_ACCESS,
        ),
        (
            "CRUCIBLE_FAULT_CAPABILITY_FEATURE_REGISTER_MUTATION",
            FAULT_CAPABILITY_FEATURE_REGISTER_MUTATION,
        ),
        (
            "CRUCIBLE_FAULT_CAPABILITY_FEATURE_INSTRUCTION",
            FAULT_CAPABILITY_FEATURE_INSTRUCTION,
        ),
        (
            "CRUCIBLE_FAULT_CAPABILITY_FEATURE_INTERRUPT",
            FAULT_CAPABILITY_FEATURE_INTERRUPT,
        ),
        (
            "CRUCIBLE_FAULT_CAPABILITY_FEATURE_HARDWARE_ERROR",
            FAULT_CAPABILITY_FEATURE_HARDWARE_ERROR,
        ),
        (
            "CRUCIBLE_FAULT_CAPABILITY_FEATURE_VCPU_SERVICE",
            FAULT_CAPABILITY_FEATURE_VCPU_SERVICE,
        ),
        (
            "CRUCIBLE_FAULT_CAPABILITY_FEATURE_NODE_LIFECYCLE",
            FAULT_CAPABILITY_FEATURE_NODE_LIFECYCLE,
        ),
        (
            "CRUCIBLE_FAULT_CAPABILITY_FEATURE_GUEST_CLOCK",
            FAULT_CAPABILITY_FEATURE_GUEST_CLOCK,
        ),
        (
            "CRUCIBLE_FAULT_CAPABILITY_FEATURE_ACCELERATOR",
            FAULT_CAPABILITY_FEATURE_ACCELERATOR,
        ),
        (
            "CRUCIBLE_FAULT_CAPABILITY_FEATURE_VMSTATE",
            FAULT_CAPABILITY_FEATURE_VMSTATE,
        ),
    ] {
        define!(name, value);
    }

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
        (
            "CRUCIBLE_FAULT_COMMAND_SLOT_RESERVATION_START_OFFSET",
            FAULT_COMMAND_SLOT_RESERVATION_START_OFFSET,
        ),
        (
            "CRUCIBLE_FAULT_COMMAND_SLOT_PAYLOAD_START_OFFSET",
            FAULT_COMMAND_SLOT_PAYLOAD_START_OFFSET,
        ),
        (
            "CRUCIBLE_FAULT_COMMAND_SLOT_RESERVATION_END_OFFSET",
            FAULT_COMMAND_SLOT_RESERVATION_END_OFFSET,
        ),
        (
            "CRUCIBLE_FAULT_COMMAND_SLOT_HEADER_OFFSET",
            FAULT_COMMAND_SLOT_HEADER_OFFSET,
        ),
        (
            "CRUCIBLE_FAULT_RESULT_SLOT_RESERVATION_START_OFFSET",
            FAULT_RESULT_SLOT_RESERVATION_START_OFFSET,
        ),
        (
            "CRUCIBLE_FAULT_RESULT_SLOT_PAYLOAD_START_OFFSET",
            FAULT_RESULT_SLOT_PAYLOAD_START_OFFSET,
        ),
        (
            "CRUCIBLE_FAULT_RESULT_SLOT_RESERVATION_END_OFFSET",
            FAULT_RESULT_SLOT_RESERVATION_END_OFFSET,
        ),
        (
            "CRUCIBLE_FAULT_RESULT_SLOT_HEADER_OFFSET",
            FAULT_RESULT_SLOT_HEADER_OFFSET,
        ),
        (
            "CRUCIBLE_FAULT_PAYLOAD_ARENA_READ_CURSOR_OFFSET",
            FAULT_PAYLOAD_ARENA_READ_CURSOR_OFFSET,
        ),
        (
            "CRUCIBLE_FAULT_PAYLOAD_ARENA_WRITE_CURSOR_OFFSET",
            FAULT_PAYLOAD_ARENA_WRITE_CURSOR_OFFSET,
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
            "CRUCIBLE_FAULT_COMMAND_FLAG_PREPARE_ONLY",
            FAULT_COMMAND_FLAG_PREPARE_ONLY,
        ),
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
        (
            "CRUCIBLE_FAULT_STATUS_MALFORMED_COMMAND",
            FaultResultStatus::MalformedCommand as u16,
        ),
        (
            "CRUCIBLE_FAULT_STATUS_DUPLICATE_SEQUENCE",
            FaultResultStatus::DuplicateSequence as u16,
        ),
        (
            "CRUCIBLE_FAULT_STATUS_AUTHENTICATION_FAILED",
            FaultResultStatus::AuthenticationFailed as u16,
        ),
        (
            "CRUCIBLE_FAULT_STATUS_PREPARED",
            FaultResultStatus::Prepared as u16,
        ),
    ] {
        let _ = writeln!(out, "#define {name} {value}");
    }
    out.push_str(
        r#"
typedef struct CRUCIBLE_SHMEM_ALIGNED(64) crucible_fault_command_slot_v1 {
    uint64_t reservation_start;
    uint64_t payload_start;
    uint64_t reservation_end;
    uint8_t header[CRUCIBLE_FAULT_COMMAND_HEADER_V1_BYTES];
    uint8_t reserved[16];
} crucible_fault_command_slot_v1;

CRUCIBLE_SHMEM_STATIC_ASSERT(sizeof(crucible_fault_command_slot_v1) == CRUCIBLE_FAULT_COMMAND_SLOT_V1_BYTES, "crucible_fault_command_slot_v1 size");
CRUCIBLE_SHMEM_STATIC_ASSERT(_Alignof(crucible_fault_command_slot_v1) == 64, "crucible_fault_command_slot_v1 alignment");
CRUCIBLE_SHMEM_STATIC_ASSERT(offsetof(crucible_fault_command_slot_v1, reservation_start) == CRUCIBLE_FAULT_COMMAND_SLOT_RESERVATION_START_OFFSET, "crucible_fault_command_slot_v1.reservation_start offset");
CRUCIBLE_SHMEM_STATIC_ASSERT(offsetof(crucible_fault_command_slot_v1, payload_start) == CRUCIBLE_FAULT_COMMAND_SLOT_PAYLOAD_START_OFFSET, "crucible_fault_command_slot_v1.payload_start offset");
CRUCIBLE_SHMEM_STATIC_ASSERT(offsetof(crucible_fault_command_slot_v1, reservation_end) == CRUCIBLE_FAULT_COMMAND_SLOT_RESERVATION_END_OFFSET, "crucible_fault_command_slot_v1.reservation_end offset");
CRUCIBLE_SHMEM_STATIC_ASSERT(offsetof(crucible_fault_command_slot_v1, header) == CRUCIBLE_FAULT_COMMAND_SLOT_HEADER_OFFSET, "crucible_fault_command_slot_v1.header offset");

typedef struct CRUCIBLE_SHMEM_ALIGNED(64) crucible_fault_result_slot_v1 {
    uint64_t reservation_start;
    uint64_t payload_start;
    uint64_t reservation_end;
    uint8_t header[CRUCIBLE_FAULT_RESULT_HEADER_V1_BYTES];
    uint8_t reserved[44];
} crucible_fault_result_slot_v1;

CRUCIBLE_SHMEM_STATIC_ASSERT(sizeof(crucible_fault_result_slot_v1) == CRUCIBLE_FAULT_RESULT_SLOT_V1_BYTES, "crucible_fault_result_slot_v1 size");
CRUCIBLE_SHMEM_STATIC_ASSERT(_Alignof(crucible_fault_result_slot_v1) == 64, "crucible_fault_result_slot_v1 alignment");
CRUCIBLE_SHMEM_STATIC_ASSERT(offsetof(crucible_fault_result_slot_v1, reservation_start) == CRUCIBLE_FAULT_RESULT_SLOT_RESERVATION_START_OFFSET, "crucible_fault_result_slot_v1.reservation_start offset");
CRUCIBLE_SHMEM_STATIC_ASSERT(offsetof(crucible_fault_result_slot_v1, payload_start) == CRUCIBLE_FAULT_RESULT_SLOT_PAYLOAD_START_OFFSET, "crucible_fault_result_slot_v1.payload_start offset");
CRUCIBLE_SHMEM_STATIC_ASSERT(offsetof(crucible_fault_result_slot_v1, reservation_end) == CRUCIBLE_FAULT_RESULT_SLOT_RESERVATION_END_OFFSET, "crucible_fault_result_slot_v1.reservation_end offset");
CRUCIBLE_SHMEM_STATIC_ASSERT(offsetof(crucible_fault_result_slot_v1, header) == CRUCIBLE_FAULT_RESULT_SLOT_HEADER_OFFSET, "crucible_fault_result_slot_v1.header offset");

typedef struct CRUCIBLE_SHMEM_ALIGNED(128) crucible_fault_payload_arena_header {
    _Atomic uint64_t read_cursor;
    uint8_t pad_read[56];
    _Atomic uint64_t write_cursor;
    uint8_t pad_write[56];
} crucible_fault_payload_arena_header;

CRUCIBLE_SHMEM_STATIC_ASSERT(sizeof(crucible_fault_payload_arena_header) == CRUCIBLE_FAULT_PAYLOAD_ARENA_HEADER_BYTES, "crucible_fault_payload_arena_header size");
CRUCIBLE_SHMEM_STATIC_ASSERT(_Alignof(crucible_fault_payload_arena_header) == 128, "crucible_fault_payload_arena_header alignment");
CRUCIBLE_SHMEM_STATIC_ASSERT(offsetof(crucible_fault_payload_arena_header, read_cursor) == CRUCIBLE_FAULT_PAYLOAD_ARENA_READ_CURSOR_OFFSET, "crucible_fault_payload_arena_header.read_cursor offset");
CRUCIBLE_SHMEM_STATIC_ASSERT(offsetof(crucible_fault_payload_arena_header, write_cursor) == CRUCIBLE_FAULT_PAYLOAD_ARENA_WRITE_CURSOR_OFFSET, "crucible_fault_payload_arena_header.write_cursor offset");

/* Headers and rows are byte arrays; use the offsets above with explicit little-endian loads/stores. */
"#,
    );
    crate::fault_memory::emit_memory_fault_c_header(out);
    crate::fault_memory_batch::emit_memory_batch_c_header(out);
    crate::fault_memory_evidence::emit_memory_evidence_c_header(out);
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
        let mut obsolete_minor = value;
        obsolete_minor.abi_minor = FAULT_COMMAND_ABI_MINOR - 1;
        assert_eq!(
            FaultCommandHeaderV1::decode(&obsolete_minor.encode(), &arena),
            Err(FaultAbiError::Version)
        );
    }

    #[test]
    fn result_status_controls_mutation_evidence_invariants() {
        let payload = b"evidence";
        let value = FaultResultHeaderV1 {
            abi_major: FAULT_COMMAND_ABI_MAJOR,
            abi_minor: FAULT_COMMAND_ABI_MINOR,
            command_kind: FaultCommandKind::MemoryMutation as u16,
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

        let mut rejected = value.clone();
        rejected.status = FaultResultStatus::InvalidTarget;
        assert_eq!(
            FaultResultHeaderV1::decode(&rejected.encode(), payload),
            Err(FaultAbiError::ResultInvariant)
        );

        let mut prepared = value;
        prepared.status = FaultResultStatus::Prepared;
        prepared.applied_icount = 0;
        prepared.after_hash = prepared.before_hash;
        let decoded = FaultResultHeaderV1::decode(&prepared.encode(), payload)
            .unwrap_or_else(|error| panic!("decode prepared result: {error}"));
        assert_eq!(decoded.0, prepared);
        prepared.abi_minor = FAULT_COMMAND_ABI_MINOR - 1;
        assert_eq!(
            FaultResultHeaderV1::decode(&prepared.encode(), payload),
            Err(FaultAbiError::Version)
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
            row(FaultCommandKind::NodeLifecycle, FaultCapabilityScope::All),
            row(FaultCommandKind::MemoryMutation, FaultCapabilityScope::All),
        ];
        let first = fault_capability_manifest_digest(&rows)
            .unwrap_or_else(|error| panic!("capability manifest: {error}"));
        let second = fault_capability_manifest_digest(&rows)
            .unwrap_or_else(|error| panic!("capability manifest twice: {error}"));
        assert_eq!(first, second);
        let encoded = encode_fault_capability_manifest(&rows)
            .unwrap_or_else(|error| panic!("encode capability manifest: {error}"));
        assert_eq!(
            decode_fault_capability_manifest(&encoded),
            Ok(rows.to_vec())
        );
        let mut corrupt = encoded;
        corrupt[16] ^= 1;
        assert_eq!(
            decode_fault_capability_manifest(&corrupt),
            Err(FaultAbiError::PayloadDigest)
        );
        assert_eq!(
            fault_capability_manifest_digest(&[rows[1].clone(), rows[0].clone()]),
            Err(FaultAbiError::CapabilityInvariant)
        );

        let mut unknown_features = rows[0].clone();
        unknown_features.required_feature_bits = FAULT_CAPABILITY_FEATURES_V1_MASK + 1;
        assert_eq!(
            FaultCapabilityRowV1::decode(&unknown_features.encode()),
            Err(FaultAbiError::CapabilityInvariant)
        );
    }

    #[test]
    fn result_preflight_reports_backpressure_without_mutating_transport() {
        let ring = RingHeader::new();
        let arena_header = FaultPayloadArenaHeader::new();
        let mut slots = vec![FaultResultSlotV1::new(); 2];
        let mut arena = vec![0_u8; 16];
        let rejected_result = |sequence| FaultResultHeaderV1 {
            abi_major: FAULT_COMMAND_ABI_MAJOR,
            abi_minor: FAULT_COMMAND_ABI_MINOR,
            command_kind: FaultCommandKind::BoundaryProbe as u16,
            status: FaultResultStatus::InvalidTarget,
            semantic_version: FAULT_COMMAND_SEMANTIC_VERSION,
            command_sequence: sequence,
            observed_icount: 4,
            applied_icount: 0,
            capability_version: 1,
            phase: FaultBoundaryPhase::NodeBoundary,
            before_hash: [0; 32],
            after_hash: [0; 32],
            evidence_hash: hash(b"rejected"),
            result_payload_hash: [0; 32],
            result_offset: 0,
            result_length: 0,
        };

        enqueue_fault_result(
            &ring,
            &mut slots,
            &arena_header,
            &mut arena,
            8_192,
            rejected_result(1),
            b"0123456789abcdef",
        )
        .unwrap_or_else(|error| panic!("fill result arena: {error}"));
        let indices_before = (ring.read_index(), ring.write_index());
        let cursors_before = (arena_header.read_cursor(), arena_header.write_cursor());
        assert_eq!(
            can_enqueue_fault_result(&ring, &slots, &arena_header, &arena, 1),
            Ok(false)
        );
        assert_eq!((ring.read_index(), ring.write_index()), indices_before);
        assert_eq!(
            (arena_header.read_cursor(), arena_header.write_cursor()),
            cursors_before
        );

        enqueue_fault_result(
            &ring,
            &mut slots,
            &arena_header,
            &mut arena,
            8_192,
            rejected_result(2),
            &[],
        )
        .unwrap_or_else(|error| panic!("fill result ring: {error}"));
        let indices_before = (ring.read_index(), ring.write_index());
        let cursors_before = (arena_header.read_cursor(), arena_header.write_cursor());
        assert_eq!(
            can_enqueue_fault_result(&ring, &slots, &arena_header, &arena, 0),
            Ok(false)
        );
        assert_eq!((ring.read_index(), ring.write_index()), indices_before);
        assert_eq!(
            (arena_header.read_cursor(), arena_header.write_cursor()),
            cursors_before
        );
    }

    #[test]
    fn command_transport_wraps_without_splitting_payloads() {
        let ring = RingHeader::new();
        let arena_header = FaultPayloadArenaHeader::new();
        let mut slots = vec![FaultCommandSlotV1::new(); 4];
        let mut arena = vec![0_u8; 16];

        enqueue_fault_command(
            &ring,
            &mut slots,
            &arena_header,
            &mut arena,
            4_096,
            command(&[]),
            b"abcdefghijkl",
        )
        .unwrap_or_else(|error| panic!("enqueue first command: {error}"));
        let first = dequeue_fault_command(&ring, &slots, &arena_header, &arena, 4_096)
            .unwrap_or_else(|error| panic!("dequeue first command: {error}"));
        assert!(matches!(
            first,
            Some(DequeuedFaultCommand::Valid { payload, .. }) if payload == b"abcdefghijkl"
        ));

        let mut second_header = command(&[]);
        second_header.command_sequence = 8;
        enqueue_fault_command(
            &ring,
            &mut slots,
            &arena_header,
            &mut arena,
            4_096,
            second_header,
            b"mnopqrst",
        )
        .unwrap_or_else(|error| panic!("enqueue wrapped command: {error}"));
        assert_eq!(&arena[..8], b"mnopqrst");
        let second = dequeue_fault_command(&ring, &slots, &arena_header, &arena, 4_096)
            .unwrap_or_else(|error| panic!("dequeue wrapped command: {error}"));
        assert!(matches!(
            second,
            Some(DequeuedFaultCommand::Valid { payload, .. }) if payload == b"mnopqrst"
        ));
        assert_eq!(arena_header.read_cursor(), 24);
        assert_eq!(arena_header.write_cursor(), 24);
    }

    #[test]
    fn full_command_ring_fails_before_reserving_payload_bytes() {
        let ring = RingHeader::new();
        let arena_header = FaultPayloadArenaHeader::new();
        let mut slots = vec![FaultCommandSlotV1::new(); 2];
        let mut arena = vec![0_u8; 16];
        for sequence in [7, 8] {
            let mut header = command(&[]);
            header.command_sequence = sequence;
            enqueue_fault_command(
                &ring,
                &mut slots,
                &arena_header,
                &mut arena,
                4_096,
                header,
                b"x",
            )
            .unwrap_or_else(|error| panic!("fill command ring: {error}"));
        }
        let write_before = arena_header.write_cursor();
        let mut header = command(&[]);
        header.command_sequence = 9;
        assert_eq!(
            enqueue_fault_command(
                &ring,
                &mut slots,
                &arena_header,
                &mut arena,
                4_096,
                header,
                b"y",
            ),
            Err(FaultTransportError::RingFull { capacity: 2 })
        );
        assert_eq!(arena_header.write_cursor(), write_before);
    }

    #[test]
    fn malformed_command_is_consumed_without_losing_raw_correlation() {
        let ring = RingHeader::new();
        let arena_header = FaultPayloadArenaHeader::new();
        let mut slots = vec![FaultCommandSlotV1::new(); 2];
        let mut arena = vec![0_u8; 16];
        enqueue_fault_command(
            &ring,
            &mut slots,
            &arena_header,
            &mut arena,
            4_096,
            command(&[]),
            b"bad-kind",
        )
        .unwrap_or_else(|error| panic!("enqueue command: {error}"));
        slots[0].header[FAULT_COMMAND_KIND_OFFSET..FAULT_COMMAND_KIND_OFFSET + 2]
            .copy_from_slice(&0xffff_u16.to_le_bytes());

        let dequeued = dequeue_fault_command(&ring, &slots, &arena_header, &arena, 4_096)
            .unwrap_or_else(|error| panic!("dequeue malformed command: {error}"));
        assert_eq!(
            dequeued,
            Some(DequeuedFaultCommand::Rejected {
                raw_command_kind: 0xffff,
                command_sequence: 7,
                error: FaultAbiError::UnknownCommandKind(0xffff),
            })
        );
        assert_eq!(ring.read_index(), ring.write_index());
        assert_eq!(arena_header.read_cursor(), arena_header.write_cursor());
    }

    #[test]
    fn result_transport_accepts_unknown_kind_only_for_rejection() {
        let ring = RingHeader::new();
        let arena_header = FaultPayloadArenaHeader::new();
        let mut slots = vec![FaultResultSlotV1::new(); 2];
        let mut arena = vec![0_u8; 32];
        let before = hash(b"before");
        let result = FaultResultHeaderV1 {
            abi_major: FAULT_COMMAND_ABI_MAJOR,
            abi_minor: FAULT_COMMAND_ABI_MINOR,
            command_kind: 0xffff,
            status: FaultResultStatus::UnsupportedCapability,
            semantic_version: FAULT_COMMAND_SEMANTIC_VERSION,
            command_sequence: 11,
            observed_icount: 4,
            applied_icount: 0,
            capability_version: 1,
            phase: FaultBoundaryPhase::NodeBoundary,
            before_hash: before,
            after_hash: before,
            evidence_hash: hash(b"unsupported"),
            result_payload_hash: hash(&[]),
            result_offset: 0,
            result_length: 0,
        };
        enqueue_fault_result(
            &ring,
            &mut slots,
            &arena_header,
            &mut arena,
            8_192,
            result.clone(),
            b"reason",
        )
        .unwrap_or_else(|error| panic!("enqueue result: {error}"));
        let dequeued = dequeue_fault_result(&ring, &slots, &arena_header, &arena, 8_192)
            .unwrap_or_else(|error| panic!("dequeue result: {error}"));
        assert!(matches!(
            dequeued,
            Some(DequeuedFaultResult::Valid { header, payload })
                if header.command_kind == 0xffff && payload == b"reason"
        ));

        let mut applied = result;
        applied.command_sequence = 12;
        applied.command_kind = 0xfffe;
        applied.status = FaultResultStatus::Applied;
        applied.applied_icount = 4;
        applied.after_hash = hash(b"after");
        assert_eq!(
            enqueue_fault_result(
                &ring,
                &mut slots,
                &arena_header,
                &mut arena,
                8_192,
                applied,
                &[],
            ),
            Err(FaultTransportError::Abi(FaultAbiError::UnknownCommandKind(
                0xfffe
            )))
        );
    }
}
