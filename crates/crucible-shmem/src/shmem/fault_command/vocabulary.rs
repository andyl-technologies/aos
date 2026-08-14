//! Closed fault capability, command, boundary, and result vocabulary.

use super::*;

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
    /// Returns one immutable, typed target manifest selected by the payload.
    QueryTargetManifest = 3,
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
            3 => Ok(Self::QueryTargetManifest),
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
