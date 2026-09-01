//! Stable typed targets and fault-opportunity identities.
//!
//! Production adapters construct an opportunity before evaluating bindings.
//! Its identity contains only canonical modeled context; host addresses,
//! callback order, and thread scheduling cannot enter the digest.

use std::error::Error;
use std::fmt;

use super::{ContentHash, EffectKind, EffectLifetime, FaultAdapter, FaultPhase, FaultTargetKind};

mod target_canonical;
pub use target_canonical::FaultCanonicalMaterialError;

/// Maximum bytes in an author-supplied fault identifier.
pub const FAULT_ID_MAX_BYTES: usize = 96;

/// A canonical identifier used by targets, bindings, and adapter-owned objects.
#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord, Hash, serde::Serialize)]
pub struct FaultObjectId(String);

impl FaultObjectId {
    /// Parses a lower-case, hyphen-separated identifier.
    ///
    /// # Errors
    ///
    /// Returns [`FaultContractError::InvalidId`] if `value` is empty, too long,
    /// non-ASCII, begins with a non-letter, ends with a non-alphanumeric byte,
    /// contains an unsupported byte, or contains adjacent hyphens.
    pub fn parse(value: impl Into<String>) -> Result<Self, FaultContractError> {
        let value = value.into();
        if !valid_id(&value) {
            return Err(FaultContractError::InvalidId { value });
        }
        Ok(Self(value))
    }

    /// Returns the canonical identifier text.
    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl<'de> serde::Deserialize<'de> for FaultObjectId {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        let value = super::fallible_decode::deserialize_string(deserializer)?;
        Self::parse(value).map_err(serde::de::Error::custom)
    }
}

impl fmt::Display for FaultObjectId {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(&self.0)
    }
}

fn valid_id(value: &str) -> bool {
    if value.is_empty() || value.len() > FAULT_ID_MAX_BYTES || !value.is_ascii() {
        return false;
    }
    let bytes = value.as_bytes();
    if !bytes[0].is_ascii_lowercase() || !bytes[bytes.len() - 1].is_ascii_alphanumeric() {
        return false;
    }
    let mut previous_hyphen = false;
    for byte in bytes {
        let hyphen = *byte == b'-';
        if !(byte.is_ascii_lowercase() || byte.is_ascii_digit() || hyphen)
            || (hyphen && previous_hyphen)
        {
            return false;
        }
        previous_hyphen = hyphen;
    }
    true
}

/// A direction attached to an opportunity when the operation is directional.
#[derive(
    Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash, serde::Serialize, serde::Deserialize,
)]
#[serde(deny_unknown_fields)]
#[serde(rename_all = "snake_case")]
pub enum FaultDirection {
    /// From endpoint A toward endpoint B.
    AToB,
    /// From endpoint B toward endpoint A.
    BToA,
    /// Into the named target.
    Ingress,
    /// Out of the named target.
    Egress,
    /// A read from a target into its consumer.
    Read,
    /// A write from a producer into its target.
    Write,
}

impl FaultDirection {
    /// Returns the canonical schema spelling.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::AToB => "a_to_b",
            Self::BToA => "b_to_a",
            Self::Ingress => "ingress",
            Self::Egress => "egress",
            Self::Read => "read",
            Self::Write => "write",
        }
    }
}

/// A fully resolved, capability-checked target identity.
#[derive(
    Clone, Debug, PartialEq, Eq, PartialOrd, Ord, Hash, serde::Serialize, serde::Deserialize,
)]
#[serde(deny_unknown_fields)]
#[serde(tag = "kind", content = "parameters", rename_all = "snake_case")]
pub enum ResolvedFaultTarget {
    /// One endpoint interface.
    NetworkInterface {
        /// Endpoint identity.
        endpoint: FaultObjectId,
        /// Interface identity.
        interface: FaultObjectId,
    },
    /// One directed segment.
    NetworkSegment {
        /// Segment identity.
        segment: FaultObjectId,
        /// Direction through the segment.
        direction: FaultDirection,
    },
    /// One medium channel or resource.
    NetworkMedium {
        /// Medium identity.
        medium: FaultObjectId,
        /// Channel or resource identity.
        resource: FaultObjectId,
    },
    /// One queue owned by a forwarder or medium.
    NetworkQueue {
        /// Queue owner identity.
        owner: FaultObjectId,
        /// Queue identity within the owner.
        queue: FaultObjectId,
    },
    /// One forwarding device.
    NetworkForwarder {
        /// Forwarder identity.
        forwarder: FaultObjectId,
    },
    /// One path version and direction.
    NetworkPath {
        /// Immutable path-version identity.
        path_version: FaultObjectId,
        /// Direction through the path.
        direction: FaultDirection,
    },
    /// One endpoint attachment.
    NetworkAttachment {
        /// Endpoint identity.
        endpoint: FaultObjectId,
        /// Interface identity.
        interface: FaultObjectId,
        /// Attachment identity.
        attachment: FaultObjectId,
    },
    /// One contact between two endpoints.
    NetworkContact {
        /// Contact-plan identity.
        plan: FaultObjectId,
        /// First endpoint identity in canonical endpoint order.
        endpoint_a: FaultObjectId,
        /// Second endpoint identity in canonical endpoint order.
        endpoint_b: FaultObjectId,
        /// Contact identity.
        contact: FaultObjectId,
    },
    /// One block or flash device.
    BlockDevice {
        /// Device content identity.
        device: ContentHash,
    },
    /// One byte-addressed block range.
    BlockRange {
        /// Device content identity.
        device: ContentHash,
        /// First byte in the range.
        start_byte: u64,
        /// Positive range length.
        length_bytes: u64,
    },
    /// One storage controller namespace or path.
    StorageController {
        /// Controller identity.
        controller: FaultObjectId,
        /// Namespace or path identity.
        namespace_or_path: FaultObjectId,
    },
    /// One array member or path.
    StorageArray {
        /// Array identity.
        array: FaultObjectId,
        /// Member or path identity.
        member_or_path: FaultObjectId,
    },
    /// One 9p device.
    NinePDevice {
        /// Device content identity.
        device: ContentHash,
    },
    /// One emulated node.
    Node {
        /// Node identity.
        node: FaultObjectId,
    },
    /// One vCPU in a node.
    Vcpu {
        /// Node identity.
        node: FaultObjectId,
        /// Stable vCPU index.
        vcpu: u32,
    },
    /// One architecture-resolved register bit range.
    Register {
        /// Node identity.
        node: FaultObjectId,
        /// Stable vCPU index.
        vcpu: u32,
        /// Architecture registry identity.
        architecture: FaultObjectId,
        /// Architecture register identity.
        register: FaultObjectId,
        /// First selected bit.
        first_bit: u16,
        /// Positive selected bit count.
        bit_count: u16,
    },
    /// One guest physical or virtual memory range.
    MemoryRange {
        /// Node identity.
        node: FaultObjectId,
        /// Declared address-space identity.
        address_space: FaultObjectId,
        /// First address in the declared guest address space.
        guest_address: u64,
        /// Stable vCPU translation context for a virtual address.
        vcpu: Option<u32>,
        /// Positive range length.
        length_bytes: u64,
    },
    /// One fully routed interrupt identity.
    Interrupt {
        /// Node identity.
        node: FaultObjectId,
        /// Interrupt controller identity.
        controller: FaultObjectId,
        /// Interrupt source identity.
        source: FaultObjectId,
        /// Stable target vCPU index.
        target_vcpu: u32,
        /// Architecture interrupt vector or type number.
        vector: u32,
    },
    /// One guest-visible clock source.
    ClockSource {
        /// Node identity.
        node: FaultObjectId,
        /// Clock-source identity.
        source: FaultObjectId,
    },
    /// One accelerator device.
    Accelerator {
        /// Node identity.
        node: FaultObjectId,
        /// Bus/device/function or declared device identity.
        device: FaultObjectId,
    },
}

impl ResolvedFaultTarget {
    /// Returns the registered target kind.
    #[must_use]
    pub const fn kind(&self) -> FaultTargetKind {
        match self {
            Self::NetworkInterface { .. } => FaultTargetKind::NetworkInterface,
            Self::NetworkSegment { .. } => FaultTargetKind::NetworkSegment,
            Self::NetworkMedium { .. } => FaultTargetKind::NetworkMedium,
            Self::NetworkQueue { .. } => FaultTargetKind::NetworkQueue,
            Self::NetworkForwarder { .. } => FaultTargetKind::NetworkForwarder,
            Self::NetworkPath { .. } => FaultTargetKind::NetworkPath,
            Self::NetworkAttachment { .. } => FaultTargetKind::NetworkAttachment,
            Self::NetworkContact { .. } => FaultTargetKind::NetworkContact,
            Self::BlockDevice { .. } => FaultTargetKind::BlockDevice,
            Self::BlockRange { .. } => FaultTargetKind::BlockRange,
            Self::StorageController { .. } => FaultTargetKind::StorageController,
            Self::StorageArray { .. } => FaultTargetKind::StorageArray,
            Self::NinePDevice { .. } => FaultTargetKind::NinePDevice,
            Self::Node { .. } => FaultTargetKind::Node,
            Self::Vcpu { .. } => FaultTargetKind::Vcpu,
            Self::Register { .. } => FaultTargetKind::Register,
            Self::MemoryRange { .. } => FaultTargetKind::MemoryRange,
            Self::Interrupt { .. } => FaultTargetKind::Interrupt,
            Self::ClockSource { .. } => FaultTargetKind::ClockSource,
            Self::Accelerator { .. } => FaultTargetKind::Accelerator,
        }
    }

    /// Validates range and ordering invariants that are not encoded by types.
    ///
    /// # Errors
    ///
    /// Returns [`FaultContractError::InvalidTarget`] for a zero-sized range,
    /// overflowing range, empty register selection, invalid register bit end,
    /// non-network direction, or non-canonical contact endpoint order.
    pub fn validate(&self) -> Result<(), FaultContractError> {
        match self {
            Self::NetworkSegment { direction, .. } | Self::NetworkPath { direction, .. } => {
                if !matches!(direction, FaultDirection::AToB | FaultDirection::BToA) {
                    return Err(FaultContractError::InvalidTarget { kind: self.kind() });
                }
            }
            Self::NetworkContact {
                endpoint_a,
                endpoint_b,
                ..
            } if endpoint_a >= endpoint_b => {
                return Err(FaultContractError::InvalidTarget { kind: self.kind() });
            }
            Self::BlockRange {
                start_byte,
                length_bytes,
                ..
            }
            | Self::MemoryRange {
                guest_address: start_byte,
                length_bytes,
                ..
            } if *length_bytes == 0 || start_byte.checked_add(*length_bytes).is_none() => {
                return Err(FaultContractError::InvalidTarget { kind: self.kind() });
            }
            Self::MemoryRange {
                address_space,
                vcpu,
                ..
            } if !matches!(
                (address_space.as_str(), vcpu),
                ("gpa", None) | ("gva", Some(_))
            ) =>
            {
                return Err(FaultContractError::InvalidTarget { kind: self.kind() });
            }
            Self::Register {
                first_bit,
                bit_count,
                ..
            } if *bit_count == 0 || first_bit.checked_add(*bit_count).is_none() => {
                return Err(FaultContractError::InvalidTarget { kind: self.kind() });
            }
            _ => {}
        }
        Ok(())
    }
}

fn push_text(material: &mut String, value: &str) {
    material.push_str(&value.len().to_string());
    material.push(':');
    material.push_str(value);
    material.push(';');
}

fn push_u64(material: &mut String, value: u64) {
    material.push_str(&value.to_string());
    material.push(';');
}

/// A closed production-adapter operation that can expose fault opportunities.
#[derive(
    Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash, serde::Serialize, serde::Deserialize,
)]
#[serde(deny_unknown_fields)]
#[serde(rename_all = "snake_case")]
pub enum FaultOperation {
    /// A network transmission.
    NetworkTransmit,
    /// A network reception.
    NetworkReceive,
    /// Shared-medium contention.
    NetworkContend,
    /// Shared-medium resource allocation.
    NetworkAllocate,
    /// Queue admission.
    NetworkEnqueue,
    /// Queue service.
    NetworkServe,
    /// Queue removal.
    NetworkDequeue,
    /// Forwarding-table learning.
    NetworkLearn,
    /// Forwarding-table lookup.
    NetworkLookup,
    /// Route selection or transition.
    NetworkRoute,
    /// Address or protocol translation.
    NetworkTranslate,
    /// Network encapsulation.
    NetworkEncapsulate,
    /// Path, backend, beam, or gateway selection.
    NetworkSelect,
    /// Segment, medium, path, or contact traversal.
    NetworkTraverse,
    /// A versioned network topology or path change.
    NetworkChange,
    /// Network discovery.
    NetworkDiscover,
    /// Network authentication.
    NetworkAuthenticate,
    /// Network association.
    NetworkAssociate,
    /// Network handoff.
    NetworkHandoff,
    /// Contact acquisition.
    NetworkAcquire,
    /// Bundle custody transition.
    NetworkCustody,
    /// Contact teardown.
    NetworkTeardown,
    /// A block or 9p read request.
    StorageRead,
    /// A block or 9p write request.
    StorageWrite,
    /// A block or 9p flush request.
    StorageFlush,
    /// A block discard request.
    StorageDiscard,
    /// A block capacity request.
    StorageGetLength,
    /// A storage reset request.
    StorageReset,
    /// A flash erase operation.
    StorageErase,
    /// A media refresh operation.
    StorageRefresh,
    /// Storage-controller admission.
    StorageAdmit,
    /// Storage-controller submission.
    StorageSubmit,
    /// Storage-controller completion.
    StorageComplete,
    /// Storage-controller enumeration.
    StorageEnumerate,
    /// Array rebuild work.
    StorageRebuild,
    /// A node boot transition.
    NodeBoot,
    /// Node or vCPU execution.
    NodeRun,
    /// A node pause transition.
    NodePause,
    /// A node reset transition.
    NodeReset,
    /// A node stop transition.
    NodeStop,
    /// A node resume transition.
    NodeResume,
    /// An instruction execution.
    CpuInstruction,
    /// An architecture exception transition.
    CpuException,
    /// A vCPU halt transition.
    CpuHalt,
    /// A register access.
    RegisterAccess,
    /// An instruction fetch.
    MemoryFetch,
    /// A memory load.
    MemoryLoad,
    /// A memory store.
    MemoryStore,
    /// A DMA read.
    MemoryDmaRead,
    /// A DMA write.
    MemoryDmaWrite,
    /// A vCPU MMU page-table descriptor read.
    MemoryPageTableWalk,
    /// A modeled memory refresh.
    MemoryRefresh,
    /// An interrupt raise.
    InterruptRaise,
    /// An interrupt route.
    InterruptRoute,
    /// An interrupt acknowledgement.
    InterruptAcknowledge,
    /// An interrupt delivery.
    InterruptDeliver,
    /// An interrupt return.
    InterruptReturn,
    /// A guest clock read.
    ClockRead,
    /// A timer arm.
    ClockArm,
    /// A timer fire.
    ClockFire,
    /// A clock synchronization.
    ClockSynchronize,
    /// A guest clock source switch.
    ClockSourceSwitch,
    /// An accelerator job submission.
    AcceleratorSubmit,
    /// Accelerator execution.
    AcceleratorExecute,
    /// Accelerator completion.
    AcceleratorComplete,
    /// An accelerator memory access.
    AcceleratorMemoryAccess,
    /// An accelerator reset.
    AcceleratorReset,
}

impl FaultOperation {
    /// Returns every registered operation in canonical adapter order.
    #[must_use]
    pub const fn all() -> &'static [Self] {
        &[
            Self::NetworkTransmit,
            Self::NetworkReceive,
            Self::NetworkContend,
            Self::NetworkAllocate,
            Self::NetworkEnqueue,
            Self::NetworkServe,
            Self::NetworkDequeue,
            Self::NetworkLearn,
            Self::NetworkLookup,
            Self::NetworkRoute,
            Self::NetworkTranslate,
            Self::NetworkEncapsulate,
            Self::NetworkSelect,
            Self::NetworkTraverse,
            Self::NetworkChange,
            Self::NetworkDiscover,
            Self::NetworkAuthenticate,
            Self::NetworkAssociate,
            Self::NetworkHandoff,
            Self::NetworkAcquire,
            Self::NetworkCustody,
            Self::NetworkTeardown,
            Self::StorageRead,
            Self::StorageWrite,
            Self::StorageFlush,
            Self::StorageDiscard,
            Self::StorageGetLength,
            Self::StorageReset,
            Self::StorageErase,
            Self::StorageRefresh,
            Self::StorageAdmit,
            Self::StorageSubmit,
            Self::StorageComplete,
            Self::StorageEnumerate,
            Self::StorageRebuild,
            Self::NodeBoot,
            Self::NodeRun,
            Self::NodePause,
            Self::NodeReset,
            Self::NodeStop,
            Self::NodeResume,
            Self::CpuInstruction,
            Self::CpuException,
            Self::CpuHalt,
            Self::RegisterAccess,
            Self::MemoryFetch,
            Self::MemoryLoad,
            Self::MemoryStore,
            Self::MemoryDmaRead,
            Self::MemoryDmaWrite,
            Self::MemoryPageTableWalk,
            Self::MemoryRefresh,
            Self::InterruptRaise,
            Self::InterruptRoute,
            Self::InterruptAcknowledge,
            Self::InterruptDeliver,
            Self::InterruptReturn,
            Self::ClockRead,
            Self::ClockArm,
            Self::ClockFire,
            Self::ClockSynchronize,
            Self::ClockSourceSwitch,
            Self::AcceleratorSubmit,
            Self::AcceleratorExecute,
            Self::AcceleratorComplete,
            Self::AcceleratorMemoryAccess,
            Self::AcceleratorReset,
        ]
    }

    /// Returns the adapter that owns this operation.
    #[must_use]
    pub const fn adapter(self) -> FaultAdapter {
        match self {
            Self::NetworkTransmit
            | Self::NetworkReceive
            | Self::NetworkContend
            | Self::NetworkAllocate
            | Self::NetworkEnqueue
            | Self::NetworkServe
            | Self::NetworkDequeue
            | Self::NetworkLearn
            | Self::NetworkLookup
            | Self::NetworkRoute
            | Self::NetworkTranslate
            | Self::NetworkEncapsulate
            | Self::NetworkSelect
            | Self::NetworkTraverse
            | Self::NetworkChange
            | Self::NetworkDiscover
            | Self::NetworkAuthenticate
            | Self::NetworkAssociate
            | Self::NetworkHandoff
            | Self::NetworkAcquire
            | Self::NetworkCustody
            | Self::NetworkTeardown => FaultAdapter::Network,
            Self::StorageRead
            | Self::StorageWrite
            | Self::StorageFlush
            | Self::StorageDiscard
            | Self::StorageGetLength
            | Self::StorageReset
            | Self::StorageErase
            | Self::StorageRefresh
            | Self::StorageAdmit
            | Self::StorageSubmit
            | Self::StorageComplete
            | Self::StorageEnumerate
            | Self::StorageRebuild => FaultAdapter::Storage,
            Self::NodeBoot
            | Self::NodeRun
            | Self::NodePause
            | Self::NodeReset
            | Self::NodeStop
            | Self::NodeResume
            | Self::CpuInstruction
            | Self::CpuException
            | Self::CpuHalt
            | Self::RegisterAccess
            | Self::MemoryFetch
            | Self::MemoryLoad
            | Self::MemoryStore
            | Self::MemoryDmaRead
            | Self::MemoryDmaWrite
            | Self::MemoryPageTableWalk
            | Self::MemoryRefresh
            | Self::InterruptRaise
            | Self::InterruptRoute
            | Self::InterruptAcknowledge
            | Self::InterruptDeliver
            | Self::InterruptReturn
            | Self::ClockRead
            | Self::ClockArm
            | Self::ClockFire
            | Self::ClockSynchronize
            | Self::ClockSourceSwitch
            | Self::AcceleratorSubmit
            | Self::AcceleratorExecute
            | Self::AcceleratorComplete
            | Self::AcceleratorMemoryAccess
            | Self::AcceleratorReset => FaultAdapter::Node,
        }
    }

    /// Returns the canonical schema spelling.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::NetworkTransmit => "network_transmit",
            Self::NetworkReceive => "network_receive",
            Self::NetworkContend => "network_contend",
            Self::NetworkAllocate => "network_allocate",
            Self::NetworkEnqueue => "network_enqueue",
            Self::NetworkServe => "network_serve",
            Self::NetworkDequeue => "network_dequeue",
            Self::NetworkLearn => "network_learn",
            Self::NetworkLookup => "network_lookup",
            Self::NetworkRoute => "network_route",
            Self::NetworkTranslate => "network_translate",
            Self::NetworkEncapsulate => "network_encapsulate",
            Self::NetworkSelect => "network_select",
            Self::NetworkTraverse => "network_traverse",
            Self::NetworkChange => "network_change",
            Self::NetworkDiscover => "network_discover",
            Self::NetworkAuthenticate => "network_authenticate",
            Self::NetworkAssociate => "network_associate",
            Self::NetworkHandoff => "network_handoff",
            Self::NetworkAcquire => "network_acquire",
            Self::NetworkCustody => "network_custody",
            Self::NetworkTeardown => "network_teardown",
            Self::StorageRead => "storage_read",
            Self::StorageWrite => "storage_write",
            Self::StorageFlush => "storage_flush",
            Self::StorageDiscard => "storage_discard",
            Self::StorageGetLength => "storage_get_length",
            Self::StorageReset => "storage_reset",
            Self::StorageErase => "storage_erase",
            Self::StorageRefresh => "storage_refresh",
            Self::StorageAdmit => "storage_admit",
            Self::StorageSubmit => "storage_submit",
            Self::StorageComplete => "storage_complete",
            Self::StorageEnumerate => "storage_enumerate",
            Self::StorageRebuild => "storage_rebuild",
            Self::NodeBoot => "node_boot",
            Self::NodeRun => "node_run",
            Self::NodePause => "node_pause",
            Self::NodeReset => "node_reset",
            Self::NodeStop => "node_stop",
            Self::NodeResume => "node_resume",
            Self::CpuInstruction => "cpu_instruction",
            Self::CpuException => "cpu_exception",
            Self::CpuHalt => "cpu_halt",
            Self::RegisterAccess => "register_access",
            Self::MemoryFetch => "memory_fetch",
            Self::MemoryLoad => "memory_load",
            Self::MemoryStore => "memory_store",
            Self::MemoryDmaRead => "memory_dma_read",
            Self::MemoryDmaWrite => "memory_dma_write",
            Self::MemoryPageTableWalk => "memory_page_table_walk",
            Self::MemoryRefresh => "memory_refresh",
            Self::InterruptRaise => "interrupt_raise",
            Self::InterruptRoute => "interrupt_route",
            Self::InterruptAcknowledge => "interrupt_acknowledge",
            Self::InterruptDeliver => "interrupt_deliver",
            Self::InterruptReturn => "interrupt_return",
            Self::ClockRead => "clock_read",
            Self::ClockArm => "clock_arm",
            Self::ClockFire => "clock_fire",
            Self::ClockSynchronize => "clock_synchronize",
            Self::ClockSourceSwitch => "clock_source_switch",
            Self::AcceleratorSubmit => "accelerator_submit",
            Self::AcceleratorExecute => "accelerator_execute",
            Self::AcceleratorComplete => "accelerator_complete",
            Self::AcceleratorMemoryAccess => "accelerator_memory_access",
            Self::AcceleratorReset => "accelerator_reset",
        }
    }
}

/// A scheduler coordinate included in a fault-opportunity identity.
#[derive(
    Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash, serde::Serialize, serde::Deserialize,
)]
#[serde(deny_unknown_fields)]
pub struct FaultCoordinate {
    /// Global virtual time in nanoseconds.
    pub virtual_nanos: u64,
    /// Optional node-local retired-instruction coordinate.
    pub retired_instructions: Option<u64>,
}

impl FaultCoordinate {
    /// Reports whether `observed` is an exact backend refinement of this coordinate.
    ///
    /// Global virtual time and any authored retired-instruction coordinate are
    /// immutable. A virtual-time-only coordinate must acquire the concrete
    /// node-local instruction coordinate at which a backend applied an action.
    #[must_use]
    pub const fn accepts_backend_refinement(self, observed: Self) -> bool {
        self.virtual_nanos == observed.virtual_nanos
            && match self.retired_instructions {
                Some(expected) => match observed.retired_instructions {
                    Some(actual) => actual == expected,
                    None => false,
                },
                None => observed.retired_instructions.is_some(),
            }
    }
}

/// Maximum nested scheduler-owned protocol expansions for one network frame.
pub const HARD_NETWORK_PROTOCOL_EXPANSION_DEPTH: usize = 256;
/// Maximum nested scheduler-generated reverse-path responses.
pub const HARD_NETWORK_RESPONSE_DEPTH: u8 = 8;
/// Maximum policy-authorized forwarding mutations in one frame ancestry.
pub const HARD_NETWORK_FORWARDING_MUTATION_DEPTH: u8 = 64;

/// Bounded immutable metadata needed to distinguish and validate an operation.
#[derive(Clone, Debug, PartialEq, Eq, Hash, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
#[serde(tag = "kind", content = "parameters", rename_all = "snake_case")]
pub enum OpportunityPayload {
    /// No additional identity-bearing metadata is required.
    None,
    /// Network-frame identity and immutable payload summary.
    NetworkFrame {
        /// Stable producer identity.
        producer: FaultObjectId,
        /// Stable selected recipient or multicast-group identity.
        destination: FaultObjectId,
        /// Producer-owned monotonically recorded frame sequence.
        producer_sequence: u64,
        /// Nested scheduler-owned protocol-expansion ordinals.
        #[serde(deserialize_with = "super::fallible_decode::deserialize_vec")]
        protocol_expansion_path: Vec<u16>,
        /// Number of scheduler-generated responses in this frame's ancestry.
        generated_response_depth: u8,
        /// Opportunity that generated this frame, absent for guest frames.
        generated_response_cause: Option<ContentHash>,
        /// Ordered opportunities that changed this frame's World route.
        #[serde(deserialize_with = "super::fallible_decode::deserialize_vec")]
        forwarding_mutation_path: Vec<ContentHash>,
        /// Frame length in bytes.
        length_bytes: u64,
        /// Digest of immutable frame bytes or normalized fields.
        payload_digest: ContentHash,
    },
    /// Network-control request and its untransformed typed result.
    NetworkControl {
        /// World-declared technology contract.
        technology: FaultObjectId,
        /// Stable control-event sequence owned by the service queue.
        event_sequence: u64,
        /// Digest of the immutable typed request.
        request_digest: ContentHash,
        /// Schema of the successful operation result.
        result_schema: FaultObjectId,
        /// Digest of the untransformed successful result.
        result_digest: ContentHash,
    },
    /// Storage-request byte range and immutable request identity.
    StorageRequest {
        /// Adapter-owned request sequence.
        request_sequence: u64,
        /// First addressed byte, when the operation has a range.
        start_byte: Option<u64>,
        /// Positive addressed length, when the operation has a range.
        length_bytes: Option<u64>,
        /// Digest of write data or immutable typed request fields.
        request_digest: ContentHash,
    },
    /// Storage completion identity after device mutation and before publication.
    StorageCompletion {
        /// Adapter-owned request sequence.
        request_sequence: u64,
        /// First addressed byte, when the operation has a range.
        start_byte: Option<u64>,
        /// Positive addressed length, when the operation has a range.
        length_bytes: Option<u64>,
        /// Digest of the immutable original request.
        request_digest: ContentHash,
        /// Closed block response status wire byte.
        response_status: u8,
        /// Digest of the complete encoded response, including error or data bytes.
        response_digest: ContentHash,
    },
    /// Decoded instruction identity.
    Instruction {
        /// Program counter before the instruction.
        program_counter: u64,
        /// Stable translated-block identity.
        translated_block: ContentHash,
        /// Digest of normalized instruction bytes and decode fields.
        instruction_digest: ContentHash,
    },
    /// Memory-access identity.
    MemoryAccess {
        /// Resolved guest physical address.
        guest_physical_address: u64,
        /// Positive access width in bytes.
        width_bytes: u32,
    },
    /// Interrupt-delivery identity.
    Interrupt {
        /// Interrupt source identity.
        source: FaultObjectId,
        /// Stable target vCPU index.
        target_vcpu: u32,
        /// Architecture vector or interrupt type number.
        vector: u32,
    },
    /// Accelerator-job identity and immutable result summary.
    AcceleratorJob {
        /// Adapter-owned job sequence.
        job_sequence: u64,
        /// Digest of immutable job fields.
        job_digest: ContentHash,
    },
}

impl OpportunityPayload {
    fn validate(&self) -> Result<(), FaultContractError> {
        match self {
            Self::NetworkFrame {
                protocol_expansion_path,
                generated_response_depth,
                forwarding_mutation_path,
                ..
            } if protocol_expansion_path.len() > HARD_NETWORK_PROTOCOL_EXPANSION_DEPTH
                || *generated_response_depth > HARD_NETWORK_RESPONSE_DEPTH
                || forwarding_mutation_path.len()
                    > usize::from(HARD_NETWORK_FORWARDING_MUTATION_DEPTH) =>
            {
                return Err(FaultContractError::InvalidPayload);
            }
            Self::StorageRequest {
                start_byte,
                length_bytes,
                ..
            }
            | Self::StorageCompletion {
                start_byte,
                length_bytes,
                ..
            } => match (start_byte, length_bytes) {
                (None, None) => {}
                (Some(start), Some(length))
                    if *length > 0 && start.checked_add(*length).is_some() => {}
                _ => return Err(FaultContractError::InvalidPayload),
            },
            Self::MemoryAccess { width_bytes, .. } if *width_bytes == 0 => {
                return Err(FaultContractError::InvalidPayload);
            }
            _ => {}
        }
        Ok(())
    }

    fn append_canonical(&self, material: &mut String) {
        match self {
            Self::None => material.push_str("none;"),
            Self::NetworkFrame {
                producer,
                destination,
                producer_sequence,
                protocol_expansion_path,
                generated_response_depth,
                generated_response_cause,
                forwarding_mutation_path,
                length_bytes,
                payload_digest,
            } => {
                material.push_str("network_frame;");
                push_text(material, producer.as_str());
                push_text(material, destination.as_str());
                push_u64(material, *producer_sequence);
                push_u64(
                    material,
                    u64::try_from(protocol_expansion_path.len()).unwrap_or(u64::MAX),
                );
                for ordinal in protocol_expansion_path {
                    push_u64(material, u64::from(*ordinal));
                }
                push_u64(material, u64::from(*generated_response_depth));
                match generated_response_cause {
                    Some(cause) => push_text(material, &cause.to_hex()),
                    None => material.push_str("none;"),
                }
                push_u64(
                    material,
                    u64::try_from(forwarding_mutation_path.len()).unwrap_or(u64::MAX),
                );
                for cause in forwarding_mutation_path {
                    push_text(material, &cause.to_hex());
                }
                push_u64(material, *length_bytes);
                push_text(material, &payload_digest.to_hex());
            }
            Self::StorageRequest {
                request_sequence,
                start_byte,
                length_bytes,
                request_digest,
            } => {
                material.push_str("storage_request;");
                push_u64(material, *request_sequence);
                push_optional_u64(material, *start_byte);
                push_optional_u64(material, *length_bytes);
                push_text(material, &request_digest.to_hex());
            }
            Self::StorageCompletion {
                request_sequence,
                start_byte,
                length_bytes,
                request_digest,
                response_status,
                response_digest,
            } => {
                material.push_str("storage_completion;");
                push_u64(material, *request_sequence);
                push_optional_u64(material, *start_byte);
                push_optional_u64(material, *length_bytes);
                push_text(material, &request_digest.to_hex());
                push_u64(material, u64::from(*response_status));
                push_text(material, &response_digest.to_hex());
            }
            Self::NetworkControl {
                technology,
                event_sequence,
                request_digest,
                result_schema,
                result_digest,
            } => {
                material.push_str("network_control;");
                push_text(material, technology.as_str());
                push_u64(material, *event_sequence);
                push_text(material, &request_digest.to_hex());
                push_text(material, result_schema.as_str());
                push_text(material, &result_digest.to_hex());
            }
            Self::Instruction {
                program_counter,
                translated_block,
                instruction_digest,
            } => {
                material.push_str("instruction;");
                push_u64(material, *program_counter);
                push_text(material, &translated_block.to_hex());
                push_text(material, &instruction_digest.to_hex());
            }
            Self::MemoryAccess {
                guest_physical_address,
                width_bytes,
            } => {
                material.push_str("memory_access;");
                push_u64(material, *guest_physical_address);
                push_u64(material, u64::from(*width_bytes));
            }
            Self::Interrupt {
                source,
                target_vcpu,
                vector,
            } => {
                material.push_str("interrupt;");
                push_text(material, source.as_str());
                push_u64(material, u64::from(*target_vcpu));
                push_u64(material, u64::from(*vector));
            }
            Self::AcceleratorJob {
                job_sequence,
                job_digest,
            } => {
                material.push_str("accelerator_job;");
                push_u64(material, *job_sequence);
                push_text(material, &job_digest.to_hex());
            }
        }
    }
}

fn push_optional_u64(material: &mut String, value: Option<u64>) {
    match value {
        Some(value) => {
            material.push_str("some;");
            push_u64(material, value);
        }
        None => material.push_str("none;"),
    }
}

/// Canonical context for one possible effect application.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct FaultOpportunity {
    adapter: FaultAdapter,
    target: ResolvedFaultTarget,
    operation: FaultOperation,
    phase: FaultPhase,
    coordinate: FaultCoordinate,
    sequence: u64,
    direction: Option<FaultDirection>,
    payload: OpportunityPayload,
    id: ContentHash,
}

impl FaultOpportunity {
    /// Validates and content-addresses an adapter opportunity.
    ///
    /// # Errors
    ///
    /// Returns [`FaultContractError`] when the target is malformed, the target
    /// and operation belong to different adapters, or payload invariants fail.
    // crucible-lint: allow rust-allow -- an opportunity is the complete typed mutation coordinate and cannot omit an identity field.
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        target: ResolvedFaultTarget,
        operation: FaultOperation,
        phase: FaultPhase,
        coordinate: FaultCoordinate,
        sequence: u64,
        direction: Option<FaultDirection>,
        payload: OpportunityPayload,
    ) -> Result<Self, FaultContractError> {
        target.validate()?;
        payload.validate()?;
        let adapter = target.kind().adapter();
        if operation.adapter() != adapter {
            return Err(FaultContractError::AdapterMismatch {
                target: adapter,
                operation: operation.adapter(),
            });
        }
        let mut material = String::from("adapter:");
        material.push_str(match adapter {
            FaultAdapter::Network => "network;",
            FaultAdapter::Storage => "storage;",
            FaultAdapter::Node => "node;",
        });
        target.append_canonical(&mut material);
        push_text(&mut material, operation.as_str());
        push_text(&mut material, phase.as_str());
        push_u64(&mut material, coordinate.virtual_nanos);
        push_optional_u64(&mut material, coordinate.retired_instructions);
        push_u64(&mut material, sequence);
        match direction {
            Some(direction) => push_text(&mut material, direction.as_str()),
            None => material.push_str("no_direction;"),
        }
        payload.append_canonical(&mut material);
        let id = ContentHash::from_canonical_material("crucible.fault-opportunity.v1", &material);
        Ok(Self {
            adapter,
            target,
            operation,
            phase,
            coordinate,
            sequence,
            direction,
            payload,
            id,
        })
    }

    /// Returns the owning production adapter.
    #[must_use]
    pub const fn adapter(&self) -> FaultAdapter {
        self.adapter
    }

    /// Returns the resolved target.
    #[must_use]
    pub const fn target(&self) -> &ResolvedFaultTarget {
        &self.target
    }

    /// Returns the closed adapter operation.
    #[must_use]
    pub const fn operation(&self) -> FaultOperation {
        self.operation
    }

    /// Returns the application phase.
    #[must_use]
    pub const fn phase(&self) -> FaultPhase {
        self.phase
    }

    /// Returns the scheduler coordinate.
    #[must_use]
    pub const fn coordinate(&self) -> FaultCoordinate {
        self.coordinate
    }

    /// Returns the adapter-owned stable operation sequence.
    #[must_use]
    pub const fn sequence(&self) -> u64 {
        self.sequence
    }

    /// Returns the optional typed direction.
    #[must_use]
    pub const fn direction(&self) -> Option<FaultDirection> {
        self.direction
    }

    /// Returns the immutable bounded payload metadata.
    #[must_use]
    pub const fn payload(&self) -> &OpportunityPayload {
        &self.payload
    }

    /// Returns the content identity of the complete opportunity context.
    #[must_use]
    pub const fn id(&self) -> ContentHash {
        self.id
    }

    /// Returns the coordinate-independent identity of a network frame.
    ///
    /// The key includes the producer, destination, producer sequence, protocol
    /// expansion ancestry, and immutable bytes. It deliberately excludes
    /// scheduler time so a captured frame can be aligned after replay timing
    /// changes.
    #[must_use]
    pub fn network_frame_key(&self) -> Option<ContentHash> {
        let OpportunityPayload::NetworkFrame {
            producer,
            destination,
            producer_sequence,
            protocol_expansion_path,
            generated_response_depth,
            generated_response_cause,
            forwarding_mutation_path,
            length_bytes,
            payload_digest,
        } = &self.payload
        else {
            return None;
        };
        let mut material = String::new();
        push_text(&mut material, producer.as_str());
        push_text(&mut material, destination.as_str());
        push_u64(&mut material, *producer_sequence);
        push_u64(&mut material, protocol_expansion_path.len() as u64);
        for ordinal in protocol_expansion_path {
            push_u64(&mut material, u64::from(*ordinal));
        }
        push_u64(&mut material, u64::from(*generated_response_depth));
        match generated_response_cause {
            Some(cause) => push_text(&mut material, &cause.to_hex()),
            None => material.push_str("no_generated_cause;"),
        }
        push_u64(&mut material, forwarding_mutation_path.len() as u64);
        for mutation in forwarding_mutation_path {
            push_text(&mut material, &mutation.to_hex());
        }
        push_u64(&mut material, *length_bytes);
        push_text(&mut material, &payload_digest.to_hex());
        Some(ContentHash::from_canonical_material(
            "crucible.network-frame-key.v1",
            &material,
        ))
    }

    /// Returns the stable producer/direction sequence alignment key for a frame.
    #[must_use]
    pub fn network_producer_direction_key(&self) -> Option<ContentHash> {
        let OpportunityPayload::NetworkFrame {
            producer,
            producer_sequence,
            ..
        } = &self.payload
        else {
            return None;
        };
        let mut material = String::new();
        push_text(&mut material, producer.as_str());
        push_text(
            &mut material,
            self.direction.map_or("none", FaultDirection::as_str),
        );
        push_u64(&mut material, *producer_sequence);
        Some(ContentHash::from_canonical_material(
            "crucible.network-producer-direction-sequence.v1",
            &material,
        ))
    }
}

/// Validation failure for targets, opportunities, bindings, or effects.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum FaultContractError {
    /// An identifier is not canonical.
    InvalidId {
        /// Rejected text.
        value: String,
    },
    /// A resolved target violates its kind-specific invariant.
    InvalidTarget {
        /// Target kind being validated.
        kind: FaultTargetKind,
    },
    /// An operation and target belong to different adapters.
    AdapterMismatch {
        /// Adapter owning the target.
        target: FaultAdapter,
        /// Adapter owning the operation.
        operation: FaultAdapter,
    },
    /// Immutable opportunity payload metadata is malformed.
    InvalidPayload,
    /// A probability exceeds one million millionths.
    ProbabilityOutOfRange {
        /// Rejected probability.
        value: u32,
    },
    /// A field that requires a positive quantity was zero.
    ZeroValue {
        /// Field requiring a positive value.
        field: &'static str,
    },
    /// A requested amount exceeds its compiled semantic ceiling.
    ResourceLimitExceeded {
        /// Bounded field.
        field: &'static str,
        /// Requested amount.
        requested: u64,
        /// Compiled hard ceiling.
        hard: u64,
    },
    /// A byte range is empty or its exclusive end overflows.
    InvalidByteRange {
        /// First selected byte.
        start: u64,
        /// Requested byte count.
        length: u64,
    },
    /// Hexadecimal bytes are non-canonical or exceed their size ceiling.
    InvalidHexBytes {
        /// Encoded text length in bytes.
        encoded_bytes: usize,
        /// Maximum decoded payload bytes.
        limit_bytes: usize,
    },
    /// A required collection contains no values.
    EmptyCollection {
        /// Empty field.
        field: &'static str,
    },
    /// A homogeneous collection spans production adapters.
    MixedAdapters {
        /// Heterogeneous field.
        field: &'static str,
    },
    /// A piecewise service curve is empty, unordered, or does not begin at zero.
    InvalidServiceCurve,
    /// Exactly one of two effect fields must be present.
    MutuallyExclusiveFields {
        /// First alternative.
        left: &'static str,
        /// Second alternative.
        right: &'static str,
    },
    /// Dependent fields violate the named effect's closed parameter contract.
    InvalidEffectParameters {
        /// Effect whose parameter contract failed.
        effect: EffectKind,
    },
    /// Authored or replayed effect semantics differ from the implemented version.
    EffectVersionMismatch {
        /// Effect being validated.
        effect: EffectKind,
        /// Required semantic version.
        expected: u16,
        /// Rejected semantic version.
        actual: u16,
    },
    /// An effect kind does not permit the selected lifetime.
    UnsupportedLifetime {
        /// Effect being validated.
        effect: EffectKind,
        /// Rejected lifetime.
        lifetime: EffectLifetime,
    },
    /// An effect kind does not permit the resolved target kind.
    EffectTargetMismatch {
        /// Effect being validated.
        effect: EffectKind,
        /// Rejected target kind.
        target: FaultTargetKind,
    },
    /// An effect kind does not permit the recorded application phase.
    EffectPhaseMismatch {
        /// Effect being validated.
        effect: EffectKind,
        /// Rejected phase.
        phase: FaultPhase,
    },
    /// An opportunity-scoped resolved effect omits its opportunity identity.
    MissingOpportunity {
        /// Effect being validated.
        effect: EffectKind,
    },
    /// Resolved effect contributors are duplicated or not in binding order.
    NonCanonicalContributors,
    /// A resolved record names a capability other than the effect contract.
    CapabilityMismatch {
        /// Effect being validated.
        effect: EffectKind,
    },
    /// A replay record omits the live before-state digest.
    MissingReplayPrecondition {
        /// Effect whose mutation cannot be replayed safely.
        effect: EffectKind,
    },
    /// A production capability identifier is not canonical.
    InvalidCapabilityId {
        /// Rejected capability text.
        value: String,
    },
}

impl fmt::Display for FaultContractError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::InvalidId { value } => write!(formatter, "invalid fault identifier {value:?}"),
            Self::InvalidTarget { kind } => {
                write!(formatter, "invalid resolved {} target", kind.as_str())
            }
            Self::AdapterMismatch { target, operation } => write!(
                formatter,
                "target adapter {target:?} does not match operation adapter {operation:?}",
            ),
            Self::InvalidPayload => formatter.write_str("invalid fault-opportunity payload"),
            Self::ProbabilityOutOfRange { value } => {
                write!(
                    formatter,
                    "probability {value} exceeds one million millionths"
                )
            }
            Self::ZeroValue { field } => write!(formatter, "{field} must be positive"),
            Self::ResourceLimitExceeded {
                field,
                requested,
                hard,
            } => write!(
                formatter,
                "{field} requests {requested}, exceeding hard ceiling {hard}",
            ),
            Self::InvalidByteRange { start, length } => {
                write!(
                    formatter,
                    "invalid byte range start={start} length={length}"
                )
            }
            Self::InvalidHexBytes {
                encoded_bytes,
                limit_bytes,
            } => write!(
                formatter,
                "invalid hexadecimal payload of {encoded_bytes} encoded bytes (decoded limit {limit_bytes})",
            ),
            Self::EmptyCollection { field } => write!(formatter, "{field} must not be empty"),
            Self::MixedAdapters { field } => {
                write!(formatter, "{field} must belong to one adapter")
            }
            Self::InvalidServiceCurve => formatter
                .write_str("service curve must begin at zero and use increasing coordinates"),
            Self::MutuallyExclusiveFields { left, right } => {
                write!(
                    formatter,
                    "exactly one of {left} and {right} must be present"
                )
            }
            Self::InvalidEffectParameters { effect } => {
                write!(formatter, "invalid parameters for effect {effect}")
            }
            Self::EffectVersionMismatch {
                effect,
                expected,
                actual,
            } => write!(
                formatter,
                "effect {effect} requires semantic version {expected}, got {actual}",
            ),
            Self::UnsupportedLifetime { effect, lifetime } => {
                write!(
                    formatter,
                    "effect {effect} does not support lifetime {lifetime:?}"
                )
            }
            Self::EffectTargetMismatch { effect, target } => write!(
                formatter,
                "effect {effect} does not support target {}",
                target.as_str(),
            ),
            Self::EffectPhaseMismatch { effect, phase } => {
                write!(
                    formatter,
                    "effect {effect} does not support phase {phase:?}"
                )
            }
            Self::MissingOpportunity { effect } => {
                write!(
                    formatter,
                    "effect {effect} requires an opportunity identity"
                )
            }
            Self::NonCanonicalContributors => formatter
                .write_str("effect contributors must be unique and in canonical binding order"),
            Self::CapabilityMismatch { effect } => {
                write!(
                    formatter,
                    "effect {effect} capability does not match its registry"
                )
            }
            Self::MissingReplayPrecondition { effect } => write!(
                formatter,
                "effect {effect} omits its replay before-state digest"
            ),
            Self::InvalidCapabilityId { value } => {
                write!(formatter, "invalid fault capability identifier {value:?}")
            }
        }
    }
}

impl Error for FaultContractError {}

#[cfg(test)]
#[path = "opportunity/tests.rs"]
mod tests;
