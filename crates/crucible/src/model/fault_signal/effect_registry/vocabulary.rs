//! Effect capabilities, adapters, targets, phases, lifetimes, and composition.

use std::fmt;

/// A canonical fine-grained production-backend capability identifier.
#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord, Hash, serde::Serialize)]
pub struct FaultCapabilityId(String);

impl FaultCapabilityId {
    /// Parses a dot-separated lower-case capability identifier.
    ///
    /// # Errors
    ///
    /// Returns [`super::super::FaultContractError::InvalidCapabilityId`] when `value` is
    /// empty, longer than 160 bytes, or has a malformed component.
    pub fn parse(value: impl Into<String>) -> Result<Self, super::super::FaultContractError> {
        let value = value.into();
        let valid = !value.is_empty()
            && value.len() <= 160
            && value.is_ascii()
            && value.split('.').all(|component| {
                !component.is_empty()
                    && component.as_bytes()[0].is_ascii_lowercase()
                    && component.as_bytes()[component.len() - 1].is_ascii_alphanumeric()
                    && component.bytes().all(|byte| {
                        byte.is_ascii_lowercase() || byte.is_ascii_digit() || byte == b'-'
                    })
            });
        if !valid {
            return Err(super::super::FaultContractError::InvalidCapabilityId { value });
        }
        Ok(Self(value))
    }

    /// Returns the exact canonical capability text.
    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl<'de> serde::Deserialize<'de> for FaultCapabilityId {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        let value = <String as serde::Deserialize>::deserialize(deserializer)?;
        Self::parse(value).map_err(serde::de::Error::custom)
    }
}

impl fmt::Display for FaultCapabilityId {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(&self.0)
    }
}

/// A production adapter family that can apply an effect.
#[derive(
    Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash, serde::Serialize, serde::Deserialize,
)]
#[serde(deny_unknown_fields)]
#[serde(rename_all = "snake_case")]
pub enum FaultAdapter {
    /// Network links, queues, forwarding state, radio media, and contacts.
    Network,
    /// Block, flash, controller, array, and 9p storage behavior.
    Storage,
    /// Node, CPU, memory, interrupt, clock, and accelerator behavior in QEMU.
    Node,
}

/// A closed kind of object to which an executable fault may bind.
#[derive(
    Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash, serde::Serialize, serde::Deserialize,
)]
#[serde(deny_unknown_fields)]
#[serde(rename_all = "snake_case")]
pub enum FaultTargetKind {
    /// One endpoint interface.
    NetworkInterface,
    /// One directed physical or logical segment.
    NetworkSegment,
    /// One shared medium and channel resource.
    NetworkMedium,
    /// One bounded network queue.
    NetworkQueue,
    /// One switch, router, modem, repeater, or gateway.
    NetworkForwarder,
    /// One versioned directed network path.
    NetworkPath,
    /// One interface attachment or association.
    NetworkAttachment,
    /// One scheduled or acquired network contact.
    NetworkContact,
    /// One block or flash device.
    BlockDevice,
    /// One byte-addressed range of a block or flash device.
    BlockRange,
    /// One storage controller namespace or path.
    StorageController,
    /// One storage array member or path.
    StorageArray,
    /// One 9p device.
    NinePDevice,
    /// One emulated node.
    Node,
    /// One virtual CPU.
    Vcpu,
    /// One architecture-resolved register bit range.
    Register,
    /// One physical or virtual memory range resolved to guest physical memory.
    MemoryRange,
    /// One interrupt source, route, target, and vector.
    Interrupt,
    /// One guest-visible clock source.
    ClockSource,
    /// One declared accelerator device.
    Accelerator,
}

impl FaultTargetKind {
    /// Returns every executable target kind in canonical reference order.
    #[must_use]
    pub const fn all() -> &'static [Self] {
        &[
            Self::NetworkInterface,
            Self::NetworkSegment,
            Self::NetworkMedium,
            Self::NetworkQueue,
            Self::NetworkForwarder,
            Self::NetworkPath,
            Self::NetworkAttachment,
            Self::NetworkContact,
            Self::BlockDevice,
            Self::BlockRange,
            Self::StorageController,
            Self::StorageArray,
            Self::NinePDevice,
            Self::Node,
            Self::Vcpu,
            Self::Register,
            Self::MemoryRange,
            Self::Interrupt,
            Self::ClockSource,
            Self::Accelerator,
        ]
    }

    /// Returns the production adapter that owns this target kind.
    #[must_use]
    pub const fn adapter(self) -> FaultAdapter {
        match self {
            Self::NetworkInterface
            | Self::NetworkSegment
            | Self::NetworkMedium
            | Self::NetworkQueue
            | Self::NetworkForwarder
            | Self::NetworkPath
            | Self::NetworkAttachment
            | Self::NetworkContact => FaultAdapter::Network,
            Self::BlockDevice
            | Self::BlockRange
            | Self::StorageController
            | Self::StorageArray
            | Self::NinePDevice => FaultAdapter::Storage,
            Self::Node
            | Self::Vcpu
            | Self::Register
            | Self::MemoryRange
            | Self::Interrupt
            | Self::ClockSource
            | Self::Accelerator => FaultAdapter::Node,
        }
    }

    /// Returns the canonical schema spelling.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::NetworkInterface => "network_interface",
            Self::NetworkSegment => "network_segment",
            Self::NetworkMedium => "network_medium",
            Self::NetworkQueue => "network_queue",
            Self::NetworkForwarder => "network_forwarder",
            Self::NetworkPath => "network_path",
            Self::NetworkAttachment => "network_attachment",
            Self::NetworkContact => "network_contact",
            Self::BlockDevice => "block_device",
            Self::BlockRange => "block_range",
            Self::StorageController => "storage_controller",
            Self::StorageArray => "storage_array",
            Self::NinePDevice => "ninep_device",
            Self::Node => "node",
            Self::Vcpu => "vcpu",
            Self::Register => "register",
            Self::MemoryRange => "memory_range",
            Self::Interrupt => "interrupt",
            Self::ClockSource => "clock_source",
            Self::Accelerator => "accelerator",
        }
    }
}

/// A stable point in an adapter operation at which an effect may apply.
#[derive(
    Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash, serde::Serialize, serde::Deserialize,
)]
#[serde(deny_unknown_fields)]
#[serde(rename_all = "snake_case")]
pub enum FaultPhase {
    /// The adapter constructs a new operation or value.
    Produce,
    /// The adapter decides whether to accept an operation.
    Admit,
    /// The adapter enqueues or services an accepted operation.
    Queue,
    /// The adapter determines an operation's result.
    Resolve,
    /// The storage adapter changes the durable frontier.
    Persist,
    /// The 9p adapter changes the guest-visible frontier.
    Visibility,
    /// The adapter exposes the result to the consumer.
    Deliver,
    /// An adapter-owned state machine changes state.
    Transition,
    /// All affected execution contexts are quiescent at a scheduler boundary.
    Boundary,
    /// A vCPU or node consumes modeled execution service.
    Run,
    /// QEMU is about to execute a selected instruction.
    BeforeInstruction,
    /// QEMU has executed a selected instruction but not resumed the guest.
    AfterInstruction,
    /// A register is about to be read.
    BeforeRead,
    /// A register has been read.
    AfterRead,
    /// A register is about to be written.
    BeforeWrite,
    /// A register has been written.
    AfterWrite,
    /// Memory supplies an instruction fetch.
    Fetch,
    /// Memory supplies a CPU or device load.
    Load,
    /// Memory accepts a CPU or device store.
    Store,
    /// A device reads guest memory through DMA.
    DmaRead,
    /// A device writes guest memory through DMA.
    DmaWrite,
    /// A vCPU MMU reads a page-table descriptor during address translation.
    PageTableWalk,
    /// A memory or flash region performs a modeled refresh operation.
    Refresh,
    /// An interrupt source raises an interrupt.
    Raise,
    /// An interrupt controller routes an interrupt.
    Route,
    /// A vCPU acknowledges an interrupt.
    Acknowledge,
    /// An interrupt is delivered to a vCPU.
    InterruptDeliver,
    /// A vCPU returns from an interrupt.
    Return,
    /// A guest reads a clock source.
    ClockRead,
    /// A guest or device arms a timer.
    Arm,
    /// A timer fires.
    Fire,
    /// A clock is synchronized.
    Synchronize,
    /// A guest clock selects another source.
    SourceSwitch,
    /// An operation is submitted to an accelerator.
    Submit,
    /// An accelerator executes a job.
    Execute,
    /// An accelerator completes a job.
    Complete,
    /// An accelerator accesses attached or guest memory.
    AcceleratorMemoryAccess,
}

impl FaultPhase {
    /// Returns the canonical schema spelling.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Produce => "produce",
            Self::Admit => "admit",
            Self::Queue => "queue",
            Self::Resolve => "resolve",
            Self::Persist => "persist",
            Self::Visibility => "visibility",
            Self::Deliver => "deliver",
            Self::Transition => "transition",
            Self::Boundary => "boundary",
            Self::Run => "run",
            Self::BeforeInstruction => "before_instruction",
            Self::AfterInstruction => "after_instruction",
            Self::BeforeRead => "before_read",
            Self::AfterRead => "after_read",
            Self::BeforeWrite => "before_write",
            Self::AfterWrite => "after_write",
            Self::Fetch => "fetch",
            Self::Load => "load",
            Self::Store => "store",
            Self::DmaRead => "dma_read",
            Self::DmaWrite => "dma_write",
            Self::PageTableWalk => "page_table_walk",
            Self::Refresh => "refresh",
            Self::Raise => "raise",
            Self::Route => "route",
            Self::Acknowledge => "acknowledge",
            Self::InterruptDeliver => "interrupt_deliver",
            Self::Return => "return",
            Self::ClockRead => "clock_read",
            Self::Arm => "arm",
            Self::Fire => "fire",
            Self::Synchronize => "synchronize",
            Self::SourceSwitch => "source_switch",
            Self::Submit => "submit",
            Self::Execute => "execute",
            Self::Complete => "complete",
            Self::AcceleratorMemoryAccess => "accelerator_memory_access",
        }
    }
}

/// How long an applied effect contribution remains meaningful.
#[derive(
    Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash, serde::Serialize, serde::Deserialize,
)]
#[serde(deny_unknown_fields)]
#[serde(rename_all = "snake_case")]
pub enum EffectLifetime {
    /// The contribution remains active until its binding deactivates it.
    Persistent,
    /// The contribution is independently resolved for one opportunity.
    Opportunity,
    /// The contribution mutates state once and cannot be healed.
    Impulse,
    /// The contribution advances a bounded adapter state machine.
    StateMachine,
}

/// The deterministic algebra used to combine simultaneous contributions.
#[derive(
    Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash, serde::Serialize, serde::Deserialize,
)]
#[serde(deny_unknown_fields)]
#[serde(rename_all = "snake_case")]
pub enum CompositionAlgebra {
    /// Any active outage makes the target unavailable.
    OutageOr,
    /// Values add in canonical binding order and overflow is an error.
    CheckedSum,
    /// The least non-null cap wins while every limiter remains observable.
    Minimum,
    /// Reduced rational values multiply with checked intermediates.
    RationalProduct,
    /// Transforms run in binding order and retain each intermediate digest.
    OrderedTransform,
    /// A closed precedence lattice selects the greatest severity.
    Severity,
    /// Declared transition precedence orders state-machine inputs.
    StateMachine,
    /// Every keyed hazard is evaluated and any firing outcome applies.
    IndependentHazards,
    /// Distinct simultaneous contributions are invalid.
    Conflict,
    /// Effect-specific rules combine multiple component algebras.
    Composite,
}

/// Immutable admission metadata for one executable effect kind.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct EffectDescriptor {
    /// Stable effect key.
    pub key: EffectKind,
    /// Semantic version required for admission and locked replay.
    pub semantic_version: u16,
    /// Production adapter that owns application.
    pub adapter: FaultAdapter,
    /// Legal target kinds.
    pub targets: &'static [FaultTargetKind],
    /// Legal application phases.
    pub phases: &'static [FaultPhase],
    /// Legal lifetime classes.
    pub lifetimes: &'static [EffectLifetime],
    /// Deterministic contribution algebra.
    pub composition: CompositionAlgebra,
    /// Fine-grained production capability identifier.
    pub capability: &'static str,
    /// Evidence a replay record must retain.
    pub replay_evidence: &'static [&'static str],
}
