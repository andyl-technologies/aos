//! Closed effect, target, phase, and composition registries.
//!
//! Signal programs describe causes. This module describes the complete set of
//! effects those causes may request from production network, storage/9p, and
//! node/QEMU adapters. Registry descriptors are executable admission data, not
//! display-only documentation: an adapter must reject a target or phase that is
//! absent from an effect's descriptor.

use std::fmt;

/// The implementation version shared by every initial effect contract.
pub const EFFECT_SEMANTIC_VERSION: u16 = 1;

/// A canonical fine-grained production-backend capability identifier.
#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord, Hash, serde::Serialize)]
pub struct FaultCapabilityId(String);

impl FaultCapabilityId {
    /// Parses a dot-separated lower-case capability identifier.
    ///
    /// # Errors
    ///
    /// Returns [`super::FaultContractError::InvalidCapabilityId`] when `value` is
    /// empty, longer than 160 bytes, or has a malformed component.
    pub fn parse(value: impl Into<String>) -> Result<Self, super::FaultContractError> {
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
            return Err(super::FaultContractError::InvalidCapabilityId { value });
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

const NETWORK_TARGETS: &[FaultTargetKind] = &[
    FaultTargetKind::NetworkInterface,
    FaultTargetKind::NetworkSegment,
    FaultTargetKind::NetworkMedium,
    FaultTargetKind::NetworkQueue,
    FaultTargetKind::NetworkForwarder,
    FaultTargetKind::NetworkPath,
    FaultTargetKind::NetworkAttachment,
    FaultTargetKind::NetworkContact,
];
const STORAGE_TARGETS: &[FaultTargetKind] = &[
    FaultTargetKind::BlockDevice,
    FaultTargetKind::BlockRange,
    FaultTargetKind::StorageController,
    FaultTargetKind::StorageArray,
];
const NINEP_TARGETS: &[FaultTargetKind] = &[FaultTargetKind::NinePDevice];
const NODE_TARGETS: &[FaultTargetKind] = &[FaultTargetKind::Node];
const CPU_TARGETS: &[FaultTargetKind] = &[
    FaultTargetKind::Node,
    FaultTargetKind::Vcpu,
    FaultTargetKind::Register,
];
const MEMORY_TARGETS: &[FaultTargetKind] = &[FaultTargetKind::MemoryRange];
const INTERRUPT_TARGETS: &[FaultTargetKind] = &[FaultTargetKind::Interrupt];
const CLOCK_TARGETS: &[FaultTargetKind] = &[FaultTargetKind::ClockSource];
const ACCELERATOR_TARGETS: &[FaultTargetKind] = &[FaultTargetKind::Accelerator];

macro_rules! effect_registry {
    ($(#[$doc:meta] $variant:ident => {
        key: $key:literal,
        adapter: $adapter:ident,
        targets: $targets:ident,
        phases: [$($phase:ident),+ $(,)?],
        lifetimes: [$($lifetime:ident),+ $(,)?],
        composition: $composition:ident,
        capability: $capability:literal,
        evidence: [$($evidence:literal),+ $(,)?]
    }),+ $(,)?) => {
        /// The closed set of executable network, storage/9p, and node effects.
        #[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
        pub enum EffectKind {
            $(#[$doc] $variant,)+
        }

        impl EffectKind {
            /// Returns all effect kinds in canonical key order.
            #[must_use]
            pub const fn all() -> &'static [Self] {
                const ALL: &[EffectKind] = &[$(EffectKind::$variant,)+];
                ALL
            }

            /// Returns the stable schema key.
            #[must_use]
            pub const fn as_str(self) -> &'static str {
                match self { $(Self::$variant => $key,)+ }
            }

            /// Looks up an effect by its exact stable schema key.
            #[must_use]
            pub fn from_key(value: &str) -> Option<Self> {
                match value { $($key => Some(Self::$variant),)+ _ => None }
            }

            /// Returns the complete executable admission descriptor.
            #[must_use]
            pub const fn descriptor(self) -> EffectDescriptor {
                match self {
                    $(Self::$variant => EffectDescriptor {
                        key: Self::$variant,
                        semantic_version: EFFECT_SEMANTIC_VERSION,
                        adapter: FaultAdapter::$adapter,
                        targets: $targets,
                        phases: &[$(FaultPhase::$phase,)+],
                        lifetimes: &[$(EffectLifetime::$lifetime,)+],
                        composition: CompositionAlgebra::$composition,
                        capability: $capability,
                        replay_evidence: &[$($evidence,)+],
                    },)+
                }
            }

            /// Reports whether a target and phase are legal for this effect.
            #[must_use]
            pub fn accepts(self, target: FaultTargetKind, phase: FaultPhase) -> bool {
                let descriptor = self.descriptor();
                descriptor.targets.contains(&target) && descriptor.phases.contains(&phase)
            }
        }

        impl fmt::Display for EffectKind {
            fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
                formatter.write_str(self.as_str())
            }
        }
    };
}

effect_registry! {
    /// Directional interface, segment, path, or contact availability.
    NetworkAvailability => { key: "network.availability", adapter: Network, targets: NETWORK_TARGETS, phases: [Admit, Resolve], lifetimes: [Persistent], composition: OutageOr, capability: "network.availability.v1", evidence: ["old_state", "new_state", "direction", "queued_policy", "in_flight_policy"] },
    /// Link-down, training, and recovery transitions.
    NetworkFlap => { key: "network.flap", adapter: Network, targets: NETWORK_TARGETS, phases: [Boundary], lifetimes: [StateMachine], composition: StateMachine, capability: "network.flap.v1", evidence: ["transition_sequence", "timer_state"] },
    /// Negotiated rate, duplex, lane, FEC, and training state.
    NetworkNegotiatedMode => { key: "network.negotiated_mode", adapter: Network, targets: NETWORK_TARGETS, phases: [Boundary], lifetimes: [StateMachine], composition: Composite, capability: "network.negotiation.v1", evidence: ["old_mode", "new_mode", "training_outcome"] },
    /// Technology profile components resolved from physical inputs.
    NetworkProfileDelta => { key: "network.profile_delta", adapter: Network, targets: NETWORK_TARGETS, phases: [Resolve], lifetimes: [Persistent], composition: Composite, capability: "network.profile.v1", evidence: ["input_profile", "contributors", "resolved_profile_digest"] },
    /// Distance- or lookup-derived propagation delay.
    NetworkPropagationDelay => { key: "network.propagation_delay", adapter: Network, targets: NETWORK_TARGETS, phases: [Resolve], lifetimes: [Persistent, Opportunity], composition: CheckedSum, capability: "network.propagation.v1", evidence: ["range_input", "delay_nanos"] },
    /// Arbitration or retry access delay.
    NetworkAccessDelay => { key: "network.access_delay", adapter: Network, targets: NETWORK_TARGETS, phases: [Resolve], lifetimes: [Opportunity], composition: CheckedSum, capability: "network.access-delay.v1", evidence: ["delay_nanos", "cause"] },
    /// Keyed per-opportunity delay variation.
    NetworkJitter => { key: "network.jitter", adapter: Network, targets: NETWORK_TARGETS, phases: [Resolve], lifetimes: [Opportunity], composition: CheckedSum, capability: "network.jitter.v1", evidence: ["draw_key", "draw_value"] },
    /// Time-varying piecewise network service.
    NetworkServiceCurve => { key: "network.service_curve", adapter: Network, targets: NETWORK_TARGETS, phases: [Queue], lifetimes: [Persistent], composition: Minimum, capability: "network.service-curve.v1", evidence: ["service_intervals", "integration_ledger"] },
    /// Bounded token-bucket service state.
    NetworkTokenBucket => { key: "network.token_bucket", adapter: Network, targets: NETWORK_TARGETS, phases: [Queue], lifetimes: [Persistent, StateMachine], composition: Minimum, capability: "network.token-bucket.v1", evidence: ["tokens_before", "tokens_after", "refill_coordinate"] },
    /// Queue capacity, discipline, classes, and overflow behavior.
    NetworkQueuePolicy => { key: "network.queue_policy", adapter: Network, targets: NETWORK_TARGETS, phases: [Admit, Queue], lifetimes: [Persistent, StateMachine], composition: Conflict, capability: "network.queue.v1", evidence: ["occupancy", "selected_class", "overflow_decision"] },
    /// Keyed frame-loss outcome.
    NetworkFrameLoss => { key: "network.frame_loss", adapter: Network, targets: NETWORK_TARGETS, phases: [Resolve, Deliver], lifetimes: [Opportunity], composition: IndependentHazards, capability: "network.frame-loss.v1", evidence: ["frame_id", "decisions", "loss_cause"] },
    /// Correlated good/bad frame-error process.
    NetworkBurstErrorState => { key: "network.burst_error_state", adapter: Network, targets: NETWORK_TARGETS, phases: [Resolve], lifetimes: [StateMachine], composition: Conflict, capability: "network.burst-errors.v1", evidence: ["prior_state", "new_state", "decision_keys"] },
    /// Keyed bounded frame duplication.
    NetworkDuplicate => { key: "network.duplicate", adapter: Network, targets: NETWORK_TARGETS, phases: [Deliver], lifetimes: [Opportunity], composition: CheckedSum, capability: "network.duplicate.v1", evidence: ["copy_ids", "delivery_coordinates"] },
    /// Keyed delivery reordering within a bounded window.
    NetworkReorder => { key: "network.reorder", adapter: Network, targets: NETWORK_TARGETS, phases: [Deliver], lifetimes: [Opportunity], composition: Composite, capability: "network.reorder.v1", evidence: ["original_order", "resolved_order", "shifts"] },
    /// Ordered frame bit, field, truncation, or corruption transform.
    NetworkPayloadTransform => { key: "network.payload_transform", adapter: Network, targets: NETWORK_TARGETS, phases: [Resolve], lifetimes: [Opportunity], composition: OrderedTransform, capability: "network.payload-transform.v1", evidence: ["selectors", "before_digest", "after_digest"] },
    /// Receiver-visible detected CRC, framing, FCS, or FEC error.
    NetworkDetectedFrameError => { key: "network.detected_frame_error", adapter: Network, targets: NETWORK_TARGETS, phases: [Resolve], lifetimes: [Opportunity], composition: Severity, capability: "network.detected-error.v1", evidence: ["syndrome", "error_class", "receiver_action"] },
    /// Effective MTU and oversize disposition.
    NetworkMtu => { key: "network.mtu", adapter: Network, targets: NETWORK_TARGETS, phases: [Admit], lifetimes: [Persistent], composition: Composite, capability: "network.mtu.v1", evidence: ["original_size", "disposition"] },
    /// Class-scoped pause and resume backpressure state.
    NetworkPauseBackpressure => { key: "network.pause_backpressure", adapter: Network, targets: NETWORK_TARGETS, phases: [Queue], lifetimes: [Persistent, StateMachine], composition: StateMachine, capability: "network.backpressure.v1", evidence: ["queue", "service_suspension_ledger"] },
    /// Deterministic broadcast or multicast recipient filtering.
    NetworkRecipientSubset => { key: "network.recipient_subset", adapter: Network, targets: NETWORK_TARGETS, phases: [Deliver], lifetimes: [Opportunity], composition: OrderedTransform, capability: "network.recipient-subset.v1", evidence: ["candidate_ids", "delivered_ids"] },
    /// Forwarder restart, reset, or power-loss transition.
    NetworkForwarderLifecycle => { key: "network.forwarder_lifecycle", adapter: Network, targets: NETWORK_TARGETS, phases: [Boundary], lifetimes: [Impulse, StateMachine], composition: Severity, capability: "network.forwarder-lifecycle.v1", evidence: ["old_state", "new_state", "lost_data", "preserved_data"] },
    /// Deterministic mutation of a forwarding lookup result.
    NetworkForwardingMutation => { key: "network.forwarding_mutation", adapter: Network, targets: NETWORK_TARGETS, phases: [Resolve], lifetimes: [Persistent, Impulse], composition: OrderedTransform, capability: "network.forwarding-mutation.v1", evidence: ["lookup_inputs", "entry_before", "entry_after", "chosen_hop"] },
    /// Versioned path transition and convergence state.
    NetworkRouteTransition => { key: "network.route_transition", adapter: Network, targets: NETWORK_TARGETS, phases: [Boundary, Resolve], lifetimes: [StateMachine], composition: StateMachine, capability: "network.route-transition.v1", evidence: ["old_path", "new_path", "cause", "convergence", "traffic_treatment"] },
    /// Shared bounded service for control-plane events.
    NetworkControlPlaneService => { key: "network.control_plane_service", adapter: Network, targets: NETWORK_TARGETS, phases: [Queue, Resolve], lifetimes: [Persistent, StateMachine], composition: Minimum, capability: "network.control-plane.v1", evidence: ["queued_events", "applied_transitions"] },
    /// Stateful firewall accept, reject, or drop disposition.
    NetworkFirewallDisposition => { key: "network.firewall_disposition", adapter: Network, targets: NETWORK_TARGETS, phases: [Admit], lifetimes: [Opportunity, StateMachine], composition: Severity, capability: "network.firewall.v1", evidence: ["rule_trace", "state_transition"] },
    /// NAT, conntrack, load-balancer, tunnel, or DNS table state.
    NetworkConnectionState => { key: "network.connection_state", adapter: Network, targets: NETWORK_TARGETS, phases: [Resolve], lifetimes: [StateMachine], composition: StateMachine, capability: "network.connection-state.v1", evidence: ["entry_before", "entry_after", "resolved_result"] },
    /// Shared-medium arbitration, collision, capture, backoff, and duty cycle.
    NetworkSharedMedium => { key: "network.shared_medium", adapter: Network, targets: NETWORK_TARGETS, phases: [Admit, Queue, Resolve], lifetimes: [Persistent, StateMachine], composition: Conflict, capability: "network.shared-medium.v1", evidence: ["contenders", "allocation", "collision", "capture", "service"] },
    /// Geometry-, propagation-, and interference-derived RF channel state.
    NetworkRfChannel => { key: "network.rf_channel", adapter: Network, targets: NETWORK_TARGETS, phases: [Resolve], lifetimes: [Persistent, Opportunity], composition: Composite, capability: "network.rf-channel.v1", evidence: ["geometry", "fields", "power", "resolved_profile"] },
    /// Authentication, association, handoff, and address-continuity machine.
    NetworkAssociation => { key: "network.association", adapter: Network, targets: NETWORK_TARGETS, phases: [Boundary, Resolve], lifetimes: [StateMachine], composition: Conflict, capability: "network.association.v1", evidence: ["candidates", "timers", "old_attachment", "new_attachment", "traffic_policy"] },
    /// Typed mutation of network control-operation results.
    NetworkControlResultTransform => { key: "network.control_result_transform", adapter: Network, targets: NETWORK_TARGETS, phases: [Resolve, Deliver], lifetimes: [Opportunity], composition: OrderedTransform, capability: "network.control-result-transform.v1", evidence: ["request", "result_before", "result_after"] },
    /// Scheduled contact acquisition, availability, and teardown.
    NetworkContact => { key: "network.contact", adapter: Network, targets: NETWORK_TARGETS, phases: [Boundary, Resolve], lifetimes: [StateMachine], composition: OutageOr, capability: "network.contact.v1", evidence: ["contact_interval", "range", "beam", "gateway"] },
    /// Bounded custody queue and contact-plan routing state.
    NetworkCustodyQueue => { key: "network.custody_queue", adapter: Network, targets: NETWORK_TARGETS, phases: [Queue], lifetimes: [Persistent, StateMachine], composition: Conflict, capability: "network.custody.v1", evidence: ["bundle_id", "custody_transitions", "drops", "next_contact"] },

    /// Block-device online, offline, read-only, or degraded state.
    StorageAvailability => { key: "storage.availability", adapter: Storage, targets: STORAGE_TARGETS, phases: [Admit], lifetimes: [Persistent, StateMachine], composition: Severity, capability: "storage.availability.v1", evidence: ["old_state", "new_state", "rejected_operation"] },
    /// Guest-visible storage capacity.
    StorageReportedCapacity => { key: "storage.reported_capacity", adapter: Storage, targets: STORAGE_TARGETS, phases: [Produce, Admit], lifetimes: [Persistent], composition: Composite, capability: "storage.capacity.v1", evidence: ["old_length", "new_length", "affected_ranges"] },
    /// Operation-filtered storage latency and jitter.
    StorageLatency => { key: "storage.latency", adapter: Storage, targets: STORAGE_TARGETS, phases: [Resolve, Deliver], lifetimes: [Opportunity], composition: CheckedSum, capability: "storage.latency.v1", evidence: ["component_delays", "jitter_draw"] },
    /// Bounded byte, IOPS, queue, and token service state.
    StorageService => { key: "storage.service", adapter: Storage, targets: STORAGE_TARGETS, phases: [Queue], lifetimes: [Persistent, StateMachine], composition: Minimum, capability: "storage.service.v1", evidence: ["service_ledger", "queue_ledger"] },
    /// Typed per-operation storage error outcome.
    StorageOperationFailure => { key: "storage.operation_failure", adapter: Storage, targets: STORAGE_TARGETS, phases: [Resolve], lifetimes: [Opportunity], composition: Severity, capability: "storage.failure.v1", evidence: ["decision", "status"] },
    /// Storage stall, recovery, and modeled timeout.
    StorageStallTimeout => { key: "storage.stall_timeout", adapter: Storage, targets: STORAGE_TARGETS, phases: [Resolve], lifetimes: [Opportunity, StateMachine], composition: Composite, capability: "storage.stall.v1", evidence: ["wait_coordinate", "recovery_coordinate", "timeout_coordinate"] },
    /// Keyed storage-completion reordering.
    StorageCompletionReorder => { key: "storage.completion_reorder", adapter: Storage, targets: STORAGE_TARGETS, phases: [Deliver], lifetimes: [Opportunity], composition: Composite, capability: "storage.reorder.v1", evidence: ["original_order", "resolved_order"] },
    /// Protocol-valid duplicate storage completion.
    StorageDuplicateCompletion => { key: "storage.duplicate_completion", adapter: Storage, targets: STORAGE_TARGETS, phases: [Deliver], lifetimes: [Opportunity], composition: CheckedSum, capability: "storage.duplicate.v1", evidence: ["duplicate_ids", "guest_disposition"] },
    /// Ordered bit, stale-version, or misdirection read transform.
    StorageReadTransform => { key: "storage.read_transform", adapter: Storage, targets: STORAGE_TARGETS, phases: [Resolve], lifetimes: [Opportunity], composition: OrderedTransform, capability: "storage.read-transform.v1", evidence: ["source_version", "source_range", "before_digest", "after_digest"] },
    /// Applied, lost, torn, or misdirected write persistence.
    StorageWriteDisposition => { key: "storage.write_disposition", adapter: Storage, targets: STORAGE_TARGETS, phases: [Persist], lifetimes: [Opportunity], composition: Conflict, capability: "storage.write-disposition.v1", evidence: ["intended_range", "applied_range", "bytes", "durability"] },
    /// Declared partial order for durable storage operations.
    StoragePersistenceOrder => { key: "storage.persistence_order", adapter: Storage, targets: STORAGE_TARGETS, phases: [Persist], lifetimes: [Persistent, Opportunity], composition: Composite, capability: "storage.persistence-order.v1", evidence: ["volatile_sequence", "durable_sequence"] },
    /// Bounded volatile cache and loss transition.
    StorageVolatileCache => { key: "storage.volatile_cache", adapter: Storage, targets: STORAGE_TARGETS, phases: [Persist, Boundary], lifetimes: [Persistent, Impulse, StateMachine], composition: Conflict, capability: "storage.volatile-cache.v1", evidence: ["cache_entries", "durable_frontier_before", "durable_frontier_after"] },
    /// Honest, erroring, lying, or stalled flush disposition.
    StorageFlushDisposition => { key: "storage.flush_disposition", adapter: Storage, targets: STORAGE_TARGETS, phases: [Persist], lifetimes: [Opportunity], composition: Severity, capability: "storage.flush.v1", evidence: ["requested_barrier", "reported_status", "actual_durable_frontier"] },
    /// Canonically overlaid bad, latent, poisoned, or read-only media range.
    StorageMediaRange => { key: "storage.media_range", adapter: Storage, targets: STORAGE_TARGETS, phases: [Resolve, Persist], lifetimes: [Persistent, StateMachine], composition: OrderedTransform, capability: "storage.media-range.v1", evidence: ["resolved_range", "range_state", "thresholds"] },
    /// Per-erase-block flash wear, retention, and disturb state.
    StorageFlashState => { key: "storage.flash_state", adapter: Storage, targets: STORAGE_TARGETS, phases: [Persist], lifetimes: [Persistent, StateMachine], composition: StateMachine, capability: "storage.flash.v1", evidence: ["counters", "environment_inputs", "changed_cells"] },
    /// Controller reset, reconnect, enumeration, namespace, and path state.
    StorageControllerLifecycle => { key: "storage.controller_lifecycle", adapter: Storage, targets: STORAGE_TARGETS, phases: [Boundary], lifetimes: [StateMachine], composition: Severity, capability: "storage.controller.v1", evidence: ["old_controller", "new_controller", "queues", "namespaces", "paths"] },
    /// Array member, path, selection, rebuild, and consistency state.
    StorageArrayState => { key: "storage.array_state", adapter: Storage, targets: STORAGE_TARGETS, phases: [Resolve, Persist], lifetimes: [StateMachine], composition: Composite, capability: "storage.array.v1", evidence: ["selected_members", "degraded_state", "rebuild_state", "durability"] },
    /// Typed errno, stale, or misdirected 9p result.
    NinePResult => { key: "ninep.result", adapter: Storage, targets: NINEP_TARGETS, phases: [Resolve], lifetimes: [Opportunity], composition: Severity, capability: "ninep.result.v1", evidence: ["request", "response", "error"] },
    /// Stateful committed-versus-visible 9p frontier.
    NinePVisibility => { key: "ninep.visibility", adapter: Storage, targets: NINEP_TARGETS, phases: [Persist, Visibility, Deliver], lifetimes: [StateMachine], composition: Composite, capability: "ninep.visibility.v1", evidence: ["committed_frontier", "visible_frontier", "lookup_result"] },

    /// Node boot, reset, stop, crash, and power transition.
    NodeLifecycle => { key: "node.lifecycle", adapter: Node, targets: NODE_TARGETS, phases: [Boundary], lifetimes: [Impulse, StateMachine], composition: Severity, capability: "qemu.node.lifecycle.v1", evidence: ["backend_acknowledgement", "old_run_state", "new_run_state", "state_loss"] },
    /// Node or vCPU progress outage with explicit recovery.
    NodeHang => { key: "node.hang", adapter: Node, targets: NODE_TARGETS, phases: [Boundary, Run], lifetimes: [Persistent], composition: OutageOr, capability: "qemu.node.hang.v1", evidence: ["progress_counters", "recovery"] },
    /// Rational vCPU execution capacity and service schedule.
    CpuService => { key: "cpu.service", adapter: Node, targets: CPU_TARGETS, phases: [Run], lifetimes: [Persistent, StateMachine], composition: Minimum, capability: "qemu.cpu.service.v1", evidence: ["retired_budget", "service_ledger", "vcpu_schedule"] },
    /// Online, offline, or stalled vCPU state.
    CpuVcpuState => { key: "cpu.vcpu_state", adapter: Node, targets: CPU_TARGETS, phases: [Boundary], lifetimes: [StateMachine], composition: Severity, capability: "qemu.cpu.vcpu-state.v1", evidence: ["round_robin_cursor", "topology", "run_state"] },
    /// Architecture-resolved register bit, stuck, or replacement transform.
    CpuRegisterTransform => { key: "cpu.register_transform", adapter: Node, targets: CPU_TARGETS, phases: [BeforeRead, AfterRead, BeforeWrite, AfterWrite, Boundary], lifetimes: [Persistent, Opportunity, Impulse], composition: OrderedTransform, capability: "qemu.cpu.register-transform.v1", evidence: ["resolved_register", "before_value", "after_value", "icount"] },
    /// Instruction result corruption, skip, or replay.
    CpuInstructionTransform => { key: "cpu.instruction_transform", adapter: Node, targets: CPU_TARGETS, phases: [BeforeInstruction, AfterInstruction], lifetimes: [Opportunity], composition: Conflict, capability: "qemu.cpu.instruction-transform.v1", evidence: ["instruction", "operands", "results", "pc", "state_digest"] },
    /// Architecture-specific machine check or injected exception.
    CpuException => { key: "cpu.exception", adapter: Node, targets: CPU_TARGETS, phases: [BeforeInstruction, AfterInstruction, Boundary], lifetimes: [Impulse], composition: Severity, capability: "qemu.cpu.exception.v1", evidence: ["exception", "architecture_acknowledgement"] },
    /// Dropped, delayed, duplicated, or replaced interrupt.
    InterruptDisposition => { key: "interrupt.disposition", adapter: Node, targets: INTERRUPT_TARGETS, phases: [Raise, Route, InterruptDeliver], lifetimes: [Opportunity, StateMachine], composition: OrderedTransform, capability: "qemu.interrupt.control.v1", evidence: ["source", "target", "vector", "original_deliveries", "final_deliveries"] },
    /// Bounded generated interrupt event sequence.
    InterruptStorm => { key: "interrupt.storm", adapter: Node, targets: INTERRUPT_TARGETS, phases: [Raise], lifetimes: [StateMachine], composition: Composite, capability: "qemu.interrupt.storm.v1", evidence: ["event_sequence", "acknowledgements"] },
    /// Atomic physical or virtual memory mutation at a safe boundary.
    MemoryMutation => { key: "memory.mutation", adapter: Node, targets: MEMORY_TARGETS, phases: [Boundary], lifetimes: [Impulse], composition: OrderedTransform, capability: "qemu.memory.mutate.v1", evidence: ["translation", "before_bytes", "after_bytes", "dirty_tracking", "icount"] },
    /// Persistent or per-access memory corruption, loss, tearing, or poison.
    MemoryAccessTransform => { key: "memory.access_transform", adapter: Node, targets: MEMORY_TARGETS, phases: [Fetch, Load, Store, DmaRead, DmaWrite], lifetimes: [Persistent, Opportunity], composition: OrderedTransform, capability: "qemu.memory.access-transform.v1", evidence: ["access", "before_bytes", "after_bytes", "outcome", "range_state"] },
    /// Corrected or uncorrectable memory ECC event.
    MemoryEccEvent => { key: "memory.ecc_event", adapter: Node, targets: MEMORY_TARGETS, phases: [Fetch, Load, Store, DmaRead, DmaWrite, Boundary], lifetimes: [Impulse, Opportunity], composition: Severity, capability: "qemu.memory.ecc-event.v1", evidence: ["platform_record", "exception", "acknowledgement"] },
    /// Failed, retention-decaying, or rowhammer-disturbed memory region.
    MemoryRegionState => { key: "memory.region_state", adapter: Node, targets: MEMORY_TARGETS, phases: [Fetch, Load, Store, DmaRead, DmaWrite, Refresh], lifetimes: [Persistent, StateMachine], composition: OrderedTransform, capability: "qemu.memory.region-state.v1", evidence: ["counters", "aggressor_rows", "victim_rows", "changed_bits", "outcomes"] },
    /// Shared latency, bandwidth, and service constraints for memory.
    MemoryService => { key: "memory.service", adapter: Node, targets: MEMORY_TARGETS, phases: [Fetch, Load, Store, DmaRead, DmaWrite, Queue], lifetimes: [Persistent, StateMachine], composition: Composite, capability: "qemu.memory.service.v1", evidence: ["access_service_ledger"] },
    /// Offset, drift, jump, freeze, jitter, or wander clock transform.
    ClockTransform => { key: "clock.transform", adapter: Node, targets: CLOCK_TARGETS, phases: [ClockRead, Arm, Fire], lifetimes: [Persistent, Opportunity, Impulse], composition: Composite, capability: "qemu.clock.transform.v1", evidence: ["raw_value", "transformed_value", "timer_consequences", "state"] },
    /// Guest clock failure, fallback, source selection, and synchronization state.
    ClockSourceState => { key: "clock.source_state", adapter: Node, targets: CLOCK_TARGETS, phases: [SourceSwitch, Synchronize], lifetimes: [StateMachine], composition: Conflict, capability: "qemu.clock.source-state.v1", evidence: ["old_source", "new_source", "offset", "rate", "timer_rearm"] },
    /// Accelerator disappearance, reset, or reconnect transition.
    AcceleratorLifecycle => { key: "accelerator.lifecycle", adapter: Node, targets: ACCELERATOR_TARGETS, phases: [Boundary, Submit], lifetimes: [StateMachine], composition: Severity, capability: "qemu.accelerator.lifecycle.v1", evidence: ["enumeration_state", "run_state", "queue_treatment"] },
    /// Ordered accelerator job field or result-buffer transform.
    AcceleratorResultTransform => { key: "accelerator.result_transform", adapter: Node, targets: ACCELERATOR_TARGETS, phases: [Execute, Complete], lifetimes: [Opportunity], composition: OrderedTransform, capability: "qemu.accelerator.result-transform.v1", evidence: ["job_id", "before_digest", "after_digest"] },
    /// Corrected, uncorrectable, or transformed accelerator-memory event.
    AcceleratorMemoryEvent => { key: "accelerator.memory_event", adapter: Node, targets: ACCELERATOR_TARGETS, phases: [AcceleratorMemoryAccess, Boundary], lifetimes: [Opportunity, Impulse], composition: Severity, capability: "qemu.accelerator.memory-event.v1", evidence: ["device_memory", "guest_driver_outcome"] },
    /// Accelerator compute, memory, thermal, or power service cap.
    AcceleratorService => { key: "accelerator.service", adapter: Node, targets: ACCELERATOR_TARGETS, phases: [Execute, Queue], lifetimes: [Persistent, StateMachine], composition: Minimum, capability: "qemu.accelerator.service.v1", evidence: ["queue_ledger", "job_service_ledger"] },
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::BTreeSet;

    #[test]
    fn registry_has_exactly_seventy_unique_canonical_keys() {
        let kinds = EffectKind::all();
        assert_eq!(kinds.len(), 70);
        let keys: BTreeSet<_> = kinds.iter().map(|kind| kind.as_str()).collect();
        assert_eq!(keys.len(), kinds.len());
        assert!(keys.iter().all(|key| {
            !key.is_empty()
                && key
                    .bytes()
                    .all(|byte| byte.is_ascii_lowercase() || byte == b'.' || byte == b'_')
        }));
    }

    #[test]
    fn descriptors_are_closed_and_self_consistent() {
        for kind in EffectKind::all() {
            let descriptor = kind.descriptor();
            assert_eq!(descriptor.key, *kind);
            assert_eq!(descriptor.semantic_version, EFFECT_SEMANTIC_VERSION);
            assert!(!descriptor.targets.is_empty());
            assert!(!descriptor.phases.is_empty());
            assert!(!descriptor.lifetimes.is_empty());
            assert!(!descriptor.capability.is_empty());
            assert!(!descriptor.replay_evidence.is_empty());
            assert!(
                descriptor
                    .targets
                    .iter()
                    .all(|target| target.adapter() == descriptor.adapter)
            );
            for target in descriptor.targets {
                for phase in descriptor.phases {
                    assert!(kind.accepts(*target, *phase));
                }
            }
        }
    }

    #[test]
    fn exact_key_lookup_rejects_extension_spellings() {
        for kind in EffectKind::all() {
            assert_eq!(EffectKind::from_key(kind.as_str()), Some(*kind));
        }
        assert_eq!(EffectKind::from_key("network.availability.v2"), None);
        assert_eq!(EffectKind::from_key("sensor.bias"), None);
        assert_eq!(EffectKind::from_key("custom.effect"), None);
    }
}
