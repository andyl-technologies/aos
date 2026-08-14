//! Closed effect, target, phase, and composition registries.
//!
//! Signal programs describe causes. This module describes the complete set of
//! effects those causes may request from production network, storage/9p, and
//! node/QEMU adapters. Registry descriptors are executable admission data, not
//! display-only documentation: an adapter must reject a target or phase that is
//! absent from an effect's descriptor.

/// The implementation version shared by every initial effect contract.
pub const EFFECT_SEMANTIC_VERSION: u16 = 1;

mod vocabulary;

pub use vocabulary::*;

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
const NETWORK_MEDIUM_TARGETS: &[FaultTargetKind] = &[FaultTargetKind::NetworkMedium];
const NETWORK_ATTACHMENT_TARGETS: &[FaultTargetKind] = &[FaultTargetKind::NetworkAttachment];
const NETWORK_CONTROL_TARGETS: &[FaultTargetKind] = &[
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
const BLOCK_TARGETS: &[FaultTargetKind] =
    &[FaultTargetKind::BlockDevice, FaultTargetKind::BlockRange];
const NINEP_TARGETS: &[FaultTargetKind] = &[FaultTargetKind::NinePDevice];
const NODE_TARGETS: &[FaultTargetKind] = &[FaultTargetKind::Node];
const NODE_HANG_TARGETS: &[FaultTargetKind] = &[
    FaultTargetKind::Node,
    FaultTargetKind::Vcpu,
    FaultTargetKind::Accelerator,
];
const CPU_SERVICE_TARGETS: &[FaultTargetKind] = &[FaultTargetKind::Node, FaultTargetKind::Vcpu];
const VCPU_TARGETS: &[FaultTargetKind] = &[FaultTargetKind::Vcpu];
const REGISTER_TARGETS: &[FaultTargetKind] = &[FaultTargetKind::Register];
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
    NetworkControlPlaneService => { key: "network.control_plane_service", adapter: Network, targets: NETWORK_CONTROL_TARGETS, phases: [Boundary], lifetimes: [Persistent, StateMachine], composition: Minimum, capability: "network.control-plane.v1", evidence: ["queued_events", "applied_transitions"] },
    /// Stateful firewall accept, reject, or drop disposition.
    NetworkFirewallDisposition => { key: "network.firewall_disposition", adapter: Network, targets: NETWORK_TARGETS, phases: [Admit], lifetimes: [Opportunity, StateMachine], composition: Severity, capability: "network.firewall.v1", evidence: ["rule_trace", "state_transition"] },
    /// NAT, conntrack, load-balancer, tunnel, or DNS table state.
    NetworkConnectionState => { key: "network.connection_state", adapter: Network, targets: NETWORK_TARGETS, phases: [Resolve], lifetimes: [StateMachine], composition: StateMachine, capability: "network.connection-state.v1", evidence: ["entry_before", "entry_after", "resolved_result"] },
    /// Shared-medium arbitration, collision, capture, backoff, and duty cycle.
    NetworkSharedMedium => { key: "network.shared_medium", adapter: Network, targets: NETWORK_MEDIUM_TARGETS, phases: [Admit, Queue, Resolve], lifetimes: [Persistent, StateMachine], composition: Conflict, capability: "network.shared-medium.v1", evidence: ["contenders", "allocation", "collision", "capture", "service"] },
    /// Geometry-, propagation-, and interference-derived RF channel state.
    NetworkRfChannel => { key: "network.rf_channel", adapter: Network, targets: NETWORK_TARGETS, phases: [Resolve], lifetimes: [Persistent, Opportunity], composition: Composite, capability: "network.rf-channel.v1", evidence: ["geometry", "fields", "power", "resolved_profile"] },
    /// Authentication, association, handoff, and address-continuity machine.
    NetworkAssociation => { key: "network.association", adapter: Network, targets: NETWORK_ATTACHMENT_TARGETS, phases: [Boundary], lifetimes: [StateMachine], composition: Conflict, capability: "network.association.v1", evidence: ["candidates", "timers", "old_attachment", "new_attachment", "traffic_policy"] },
    /// Typed mutation of network control-operation results.
    NetworkControlResultTransform => { key: "network.control_result_transform", adapter: Network, targets: NETWORK_CONTROL_TARGETS, phases: [Resolve], lifetimes: [Opportunity], composition: OrderedTransform, capability: "network.control-result-transform.v1", evidence: ["request", "result_before", "result_after"] },
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
    StorageOperationFailure => { key: "storage.operation_failure", adapter: Storage, targets: STORAGE_TARGETS, phases: [Resolve, Persist], lifetimes: [Opportunity], composition: Severity, capability: "storage.failure.v1", evidence: ["decision", "status"] },
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
    /// Bounded volatile-cache admission and eviction policy.
    StorageVolatileCache => { key: "storage.volatile_cache", adapter: Storage, targets: BLOCK_TARGETS, phases: [Persist], lifetimes: [Persistent], composition: Conflict, capability: "storage.volatile-cache.v1", evidence: ["cache_entries", "evicted_entries", "durable_frontier_before", "durable_frontier_after"] },
    /// Explicit volatile-cache loss at a signal boundary.
    StorageVolatileCacheLoss => { key: "storage.volatile_cache_loss", adapter: Storage, targets: BLOCK_TARGETS, phases: [Boundary], lifetimes: [Impulse], composition: OrderedTransform, capability: "storage.volatile-cache-loss.v1", evidence: ["entry_set_digest", "eligible_entries", "selected_entries", "protected_entries", "durable_frontier_before", "durable_frontier_after"] },
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
    /// Node, vCPU-set, or accelerator progress outage with explicit recovery.
    NodeHang => { key: "node.hang", adapter: Node, targets: NODE_HANG_TARGETS, phases: [Boundary, Run], lifetimes: [Persistent], composition: OutageOr, capability: "qemu.node.hang.v1", evidence: ["progress_counters", "recovery"] },
    /// Rational vCPU execution capacity and service schedule.
    CpuService => { key: "cpu.service", adapter: Node, targets: CPU_SERVICE_TARGETS, phases: [Run], lifetimes: [Persistent, StateMachine], composition: Minimum, capability: "qemu.cpu.service.v1", evidence: ["retired_budget", "service_ledger", "vcpu_schedule"] },
    /// Online, offline, or stalled vCPU state.
    CpuVcpuState => { key: "cpu.vcpu_state", adapter: Node, targets: VCPU_TARGETS, phases: [Boundary], lifetimes: [StateMachine], composition: Severity, capability: "qemu.cpu.vcpu-state.v1", evidence: ["round_robin_cursor", "topology", "run_state"] },
    /// Architecture-resolved register bit, stuck, or replacement transform.
    CpuRegisterTransform => { key: "cpu.register_transform", adapter: Node, targets: REGISTER_TARGETS, phases: [BeforeInstruction, AfterInstruction, Boundary], lifetimes: [Persistent, Opportunity, Impulse], composition: OrderedTransform, capability: "qemu.register.mutate.v1", evidence: ["manifest_digest", "cpu_model_digest", "resolved_register", "vcpu_rr_cursor", "before_value", "after_value", "performed_side_effects", "execution_fingerprint", "icount"] },
    /// Instruction result corruption, skip, or replay.
    CpuInstructionTransform => { key: "cpu.instruction_transform", adapter: Node, targets: VCPU_TARGETS, phases: [BeforeInstruction, AfterInstruction], lifetimes: [Opportunity], composition: Conflict, capability: "qemu.cpu.instruction-transform.v1", evidence: ["instruction", "operands", "results", "pc", "state_digest"] },
    /// Architecture-specific machine check or injected exception.
    CpuException => { key: "cpu.exception", adapter: Node, targets: VCPU_TARGETS, phases: [BeforeInstruction, AfterInstruction, Boundary], lifetimes: [Impulse], composition: Severity, capability: "qemu.cpu.exception.v1", evidence: ["exception", "architecture_acknowledgement"] },
    /// Dropped, delayed, duplicated, or replaced interrupt.
    InterruptDisposition => { key: "interrupt.disposition", adapter: Node, targets: INTERRUPT_TARGETS, phases: [Raise, Route, InterruptDeliver], lifetimes: [Opportunity, StateMachine], composition: OrderedTransform, capability: "qemu.interrupt.control.v1", evidence: ["source", "target", "vector", "original_deliveries", "final_deliveries"] },
    /// Bounded generated interrupt event sequence.
    InterruptStorm => { key: "interrupt.storm", adapter: Node, targets: INTERRUPT_TARGETS, phases: [Raise], lifetimes: [StateMachine], composition: Composite, capability: "qemu.interrupt.storm.v1", evidence: ["event_sequence", "acknowledgements"] },
    /// Atomic physical or virtual memory mutation at a safe boundary.
    MemoryMutation => { key: "memory.mutation", adapter: Node, targets: MEMORY_TARGETS, phases: [Boundary], lifetimes: [Impulse], composition: OrderedTransform, capability: "qemu.memory.mutate.v1", evidence: ["translation", "before_bytes", "after_bytes", "dirty_tracking", "icount"] },
    /// Persistent or per-access memory corruption, loss, tearing, or poison.
    MemoryAccessTransform => { key: "memory.access_transform", adapter: Node, targets: MEMORY_TARGETS, phases: [Fetch, Load, Store, DmaRead, DmaWrite, PageTableWalk], lifetimes: [Persistent, Opportunity], composition: OrderedTransform, capability: "qemu.memory.access-transform.v1", evidence: ["access", "before_bytes", "after_bytes", "outcome", "range_state", "page_table_walk"] },
    /// Corrected or uncorrectable memory ECC event.
    MemoryEccEvent => { key: "memory.ecc_event", adapter: Node, targets: MEMORY_TARGETS, phases: [Fetch, Load, Store, DmaRead, DmaWrite, PageTableWalk, Boundary], lifetimes: [Impulse, Opportunity], composition: Severity, capability: "qemu.memory.ecc-event.v1", evidence: ["platform_record", "exception", "acknowledgement"] },
    /// Failed, retention-decaying, or rowhammer-disturbed memory region.
    MemoryRegionState => { key: "memory.region_state", adapter: Node, targets: MEMORY_TARGETS, phases: [Fetch, Load, Store, DmaRead, DmaWrite, PageTableWalk, Refresh], lifetimes: [Persistent, StateMachine], composition: OrderedTransform, capability: "qemu.memory.region-state.v1", evidence: ["counters", "aggressor_rows", "victim_rows", "changed_bits", "outcomes"] },
    /// Shared latency, bandwidth, and service constraints for memory.
    MemoryService => { key: "memory.service", adapter: Node, targets: MEMORY_TARGETS, phases: [Fetch, Load, Store, DmaRead, DmaWrite, PageTableWalk, Queue], lifetimes: [Persistent, StateMachine], composition: Composite, capability: "qemu.memory.service.v1", evidence: ["access_service_ledger", "page_table_walk"] },
    /// Offset, drift, jump, freeze, jitter, or wander clock transform.
    ClockTransform => { key: "clock.transform", adapter: Node, targets: CLOCK_TARGETS, phases: [ClockRead, Arm, Fire], lifetimes: [Persistent, Impulse], composition: Composite, capability: "qemu.clock.transform.v1", evidence: ["raw_value", "transformed_value", "timer_consequences", "state"] },
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
    fn registry_has_exactly_seventy_one_unique_canonical_keys() {
        let kinds = EffectKind::all();
        assert_eq!(kinds.len(), 71);
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

    #[test]
    fn node_effect_target_sets_match_the_closed_execution_contract() {
        let cases = [
            (EffectKind::NodeLifecycle, NODE_TARGETS),
            (EffectKind::NodeHang, NODE_HANG_TARGETS),
            (EffectKind::CpuService, CPU_SERVICE_TARGETS),
            (EffectKind::CpuVcpuState, VCPU_TARGETS),
            (EffectKind::CpuRegisterTransform, REGISTER_TARGETS),
            (EffectKind::CpuInstructionTransform, VCPU_TARGETS),
            (EffectKind::CpuException, VCPU_TARGETS),
            (EffectKind::InterruptDisposition, INTERRUPT_TARGETS),
            (EffectKind::InterruptStorm, INTERRUPT_TARGETS),
            (EffectKind::MemoryMutation, MEMORY_TARGETS),
            (EffectKind::MemoryAccessTransform, MEMORY_TARGETS),
            (EffectKind::MemoryEccEvent, MEMORY_TARGETS),
            (EffectKind::MemoryRegionState, MEMORY_TARGETS),
            (EffectKind::MemoryService, MEMORY_TARGETS),
            (EffectKind::ClockTransform, CLOCK_TARGETS),
            (EffectKind::ClockSourceState, CLOCK_TARGETS),
            (EffectKind::AcceleratorLifecycle, ACCELERATOR_TARGETS),
            (EffectKind::AcceleratorResultTransform, ACCELERATOR_TARGETS),
            (EffectKind::AcceleratorMemoryEvent, ACCELERATOR_TARGETS),
            (EffectKind::AcceleratorService, ACCELERATOR_TARGETS),
        ];
        for (kind, expected) in cases {
            assert_eq!(kind.descriptor().targets, expected, "{kind:?}");
        }
    }
}
