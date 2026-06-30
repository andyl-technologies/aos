//! Event-graph control-flow spine.
//!
//! RFC-0010 file 17a defines scenario control flow as a graph of events. This
//! module owns the first, condition-agnostic layer of that model: an [`Event`]
//! binds an optional [`Condition`] to an [`Action`] and a [`FirePolicy`], while
//! [`EventGraphState`] is the only local producer of fired actions. The
//! code-first builder and graph-native plan serialization keep that control flow
//! as a content-addressed scenario component instead of a separate scenario poke
//! path.

use std::collections::{BTreeMap, BTreeSet};
use std::error::Error;
use std::fmt;
use std::ops::Deref;

use crate::model::{
    AssertionDef, AssertionId, AssertionPhase, BlockFault, CodePoint, ContentHash,
    ControlFaultAction, Decision, DeviceId, EventKey, EventLogOffset, Fault, FaultId,
    FaultPlanEntry, FaultTag, FramePredicate, Icount, IoEventKind, LinkDef, LinkId, MarkerId,
    MemPlace, MembershipFault, MemoryCmp, NetworkFault, NinePFault, NodeFault, NodeId,
    NodeLifecycle, PartitionDirection, Plan, PlanEntry, Predicate, PreemptionKind, Properties,
    Property, ReachabilityExpectation, ReachableDisposition, RegexProgram, RestartPolicy,
    RngStreamId, SchedulerNodeId, SchedulingNodeKind, SimDuration, TimerId, VirtualTime,
    WhiteBoxPolicy, World, WorldStaticTopology,
};
use crate::scheduler::{
    AssertionRunVerdict, AssertionVerdictFailure, ControlOperationKind, ScheduledEvent,
    ScheduledEventKey, ScheduledEventPayload, ScheduledEventResolveClass,
    SchedulerEvaluationBoundaryKind, SchedulerEventLogClass, SchedulerEventLogEntry,
    SchedulerEventLogPayload, SchedulerQuiescence, TriggerActionApplication,
    scheduled_event_resolve_class, scheduler_event_log_empty_prefix,
    scheduler_event_log_segment_bytes,
};

pub use crate::model::EventId;

/// Shared predicate vocabulary used by both assertions and event triggers.
///
/// This is a public alias rather than a second enum: a predicate usable by the
/// assertion [`crate::model::Property`] layer is the same value accepted by an
/// event trigger.
pub type Condition = Predicate;

/// Identity-preserving event-graph lowering of a time-scheduled [`Plan`].
///
/// This is the RFC-0010 §17a.7 bridge between the legacy declarative fault plan
/// and trigger events: every lowered event has a pure [`Condition::At`] trigger
/// and an [`Action::InjectFault`] or [`Action::HealFault`] action. The lowering
/// deliberately carries the source plan's canonical bytes and content hash so a
/// pure-`At` plan and the equivalent event graph remain one content-addressed
/// value. Graph-native plans return their already-authored event graph with the
/// same identity-preserving wrapper.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct LoweredPlanEventGraph {
    graph: EventGraph,
    content_hash: ContentHash,
    canonical_bytes: Vec<u8>,
    evaluation_times: Vec<VirtualTime>,
}

impl LoweredPlanEventGraph {
    /// Returns the lowered trigger graph.
    #[must_use]
    pub fn event_graph(&self) -> &EventGraph {
        &self.graph
    }

    /// Consumes the lowering and returns the trigger graph.
    #[must_use]
    pub fn into_event_graph(self) -> EventGraph {
        self.graph
    }

    /// Returns the identity-preserving content hash inherited from the source plan.
    #[must_use]
    pub fn content_hash(&self) -> ContentHash {
        self.content_hash
    }

    /// Returns the canonical bytes used by the inherited content hash.
    #[must_use]
    pub fn canonical_bytes(&self) -> &[u8] {
        &self.canonical_bytes
    }

    /// Returns the exact virtual-time points where the pure-`At` graph must run.
    #[must_use]
    pub fn evaluation_times(&self) -> &[VirtualTime] {
        &self.evaluation_times
    }
}

impl Plan {
    /// Lowers this plan into the event graph executed by the trigger layer.
    ///
    /// Each [`PlanEntry::Activate`] becomes one once-only event with an
    /// [`Condition::At`] trigger and [`Action::InjectFault`] action. Each
    /// [`PlanEntry::Heal`] becomes one once-only event with an [`Action::HealFault`]
    /// action. The returned lowering preserves this plan's canonical bytes and
    /// content hash as the graph identity.
    ///
    /// # Errors
    ///
    /// Returns [`EventGraphError`] when the lowered graph fails event-graph
    /// validation against `world`.
    pub fn lower_to_event_graph_for_world(
        &self,
        world: &World,
    ) -> Result<LoweredPlanEventGraph, EventGraphError> {
        if let Some(graph) = self.event_graph() {
            let graph = EventGraph::new_with_assertions_for_world(
                graph.events().to_vec(),
                event_graph_assertion_references(graph.events()),
                world,
            )?;
            let evaluation_times = graph_static_evaluation_times(graph.events());
            return Ok(LoweredPlanEventGraph {
                graph,
                content_hash: self.content_hash(),
                canonical_bytes: self.canonical_bytes(),
                evaluation_times,
            });
        }
        if let Some(plan) = self.fault_plan() {
            let actions = lower_fault_plan_actions(plan.entries());
            let events = actions
                .iter()
                .enumerate()
                .map(lower_fault_plan_action_to_event)
                .collect::<Vec<_>>();
            let evaluation_times = fault_plan_action_evaluation_times(&actions);
            let graph = EventGraph::new_for_world(events, world)?;
            return Ok(LoweredPlanEventGraph {
                graph,
                content_hash: self.content_hash(),
                canonical_bytes: self.canonical_bytes(),
                evaluation_times,
            });
        }
        let events = self
            .entries()
            .iter()
            .enumerate()
            .map(lower_plan_entry_to_event)
            .collect::<Vec<_>>();
        let evaluation_times = plan_evaluation_times(self.entries());
        let graph = EventGraph::new_for_world(events, world)?;
        Ok(LoweredPlanEventGraph {
            graph,
            content_hash: self.content_hash(),
            canonical_bytes: self.canonical_bytes(),
            evaluation_times,
        })
    }
}

fn graph_static_evaluation_times(events: &[Event]) -> Vec<VirtualTime> {
    events
        .iter()
        .filter_map(|event| match &event.trigger {
            None => Some(VirtualTime { ticks: 0 }),
            Some(Condition::At { at }) => Some(*at),
            Some(_) => None,
        })
        .collect::<BTreeSet<_>>()
        .into_iter()
        .collect()
}

fn event_graph_assertion_references(events: &[Event]) -> Vec<AssertionId> {
    let mut assertions = BTreeSet::new();
    for event in events {
        if let Some(trigger) = &event.trigger {
            collect_condition_assertion_references(trigger, &mut assertions);
        }
    }
    assertions.into_iter().collect()
}

fn collect_condition_assertion_references(
    condition: &Condition,
    assertions: &mut BTreeSet<AssertionId>,
) {
    match condition {
        Condition::AssertionState { name, .. } => {
            assertions.insert(name.clone());
        }
        Condition::AllOf { predicates } | Condition::AnyOf { predicates } => {
            for condition in predicates {
                collect_condition_assertion_references(condition, assertions);
            }
        }
        Condition::Once { predicate } | Condition::Not { predicate } => {
            collect_condition_assertion_references(predicate, assertions);
        }
        Condition::At { .. }
        | Condition::After { .. }
        | Condition::Timer { .. }
        | Condition::NetworkMatch { .. }
        | Condition::ConsoleMatch { .. }
        | Condition::CoveragePoint { .. }
        | Condition::MemoryPredicate { .. }
        | Condition::IoPattern { .. }
        | Condition::NodeState { .. }
        | Condition::Quiescent
        | Condition::Named { .. }
        | Condition::GuestMarker { .. } => {}
    }
}

/// Host-resolved executable guest code coordinate.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub struct ResolvedCodePoint {
    address: u64,
}

impl ResolvedCodePoint {
    /// Builds a resolved guest-address code point.
    #[must_use]
    pub const fn guest_address(address: u64) -> Self {
        Self { address }
    }

    /// Returns the resolved guest instruction address.
    #[must_use]
    pub const fn address(self) -> u64 {
        self.address
    }
}

/// Host-resolved guest memory or register coordinate.
#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum ResolvedMemPlace {
    /// Guest physical address sampled out of band.
    PhysicalAddress {
        /// Guest physical address.
        address: u64,
        /// Sample width in bytes.
        bytes: u8,
    },
    /// Guest virtual address sampled out of band.
    VirtualAddress {
        /// Guest virtual address.
        address: u64,
        /// Sample width in bytes.
        bytes: u8,
    },
    /// Architectural register sampled out of band.
    Register {
        /// Stable register name.
        name: String,
        /// Sample width in bytes.
        bytes: u8,
    },
}

impl ResolvedMemPlace {
    /// Builds a resolved physical-address place.
    #[must_use]
    pub const fn physical_address(address: u64, bytes: u8) -> Self {
        Self::PhysicalAddress { address, bytes }
    }

    /// Builds a resolved virtual-address place.
    #[must_use]
    pub const fn virtual_address(address: u64, bytes: u8) -> Self {
        Self::VirtualAddress { address, bytes }
    }

    /// Builds a resolved register place.
    #[must_use]
    pub fn register(name: impl Into<String>, bytes: u8) -> Self {
        Self::Register {
            name: name.into(),
            bytes,
        }
    }
}

/// One black-box observable event visible to condition evaluation.
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub struct ObservableEvent {
    at: VirtualTime,
    payload: ObservableEventPayload,
}

impl ObservableEvent {
    /// Builds a delivered-network-frame observation.
    #[must_use]
    pub fn network_delivered(
        at: VirtualTime,
        link: Option<LinkId>,
        payload: impl Into<Vec<u8>>,
    ) -> Self {
        Self {
            at,
            payload: ObservableEventPayload::NetworkDelivered {
                link,
                payload: payload.into(),
            },
        }
    }

    /// Builds a console-output observation.
    #[must_use]
    pub fn console_output(at: VirtualTime, node: NodeId, bytes: impl Into<Vec<u8>>) -> Self {
        Self {
            at,
            payload: ObservableEventPayload::ConsoleOutput {
                node,
                bytes: bytes.into(),
            },
        }
    }

    /// Builds a TCG-exec basic-block coverage observation.
    #[must_use]
    pub fn coverage_block(
        execution_icount: Icount,
        node: NodeId,
        guest_pc: u64,
        block_len: u32,
    ) -> Self {
        Self {
            at: VirtualTime {
                ticks: execution_icount.retired,
            },
            payload: ObservableEventPayload::CoverageBlock {
                execution_icount,
                node,
                guest_pc,
                block_len,
            },
        }
    }

    /// Builds a deterministic memory/register sample observation.
    #[must_use]
    pub fn memory_sample(
        at: VirtualTime,
        sample_icount: Icount,
        node: NodeId,
        place: ResolvedMemPlace,
        value: u64,
    ) -> Self {
        Self {
            at,
            payload: ObservableEventPayload::MemorySample {
                sample_icount,
                node,
                place,
                value,
            },
        }
    }

    /// Builds a deterministic I/O completion observation.
    #[must_use]
    pub fn io_completion(
        at: VirtualTime,
        node: NodeId,
        kind: IoEventKind,
        payload: impl Into<Vec<u8>>,
    ) -> Self {
        Self {
            at,
            payload: ObservableEventPayload::IoCompletion {
                node,
                kind,
                payload: payload.into(),
            },
        }
    }

    /// Builds a node-lifecycle observation.
    #[must_use]
    pub fn node_state(at: VirtualTime, node: NodeId, state: NodeLifecycle) -> Self {
        Self {
            at,
            payload: ObservableEventPayload::NodeState { node, state },
        }
    }

    /// Builds a causal assertion-state-change observation.
    #[must_use]
    pub fn assertion_state_changed(
        at: VirtualTime,
        name: AssertionId,
        state: AssertionPhase,
    ) -> Self {
        Self {
            at,
            payload: ObservableEventPayload::AssertionStateChanged { name, state },
        }
    }

    /// Builds an optional white-box guest-marker observation.
    #[must_use]
    pub fn guest_marker(retired_icount: Icount, node: NodeId, marker: MarkerId) -> Self {
        Self {
            at: VirtualTime {
                ticks: retired_icount.retired,
            },
            payload: ObservableEventPayload::GuestMarker {
                retired_icount,
                node,
                marker,
            },
        }
    }

    /// Builds an optional white-box assertion-marker observation.
    #[must_use]
    pub fn guest_assertion_marker(
        retired_icount: Icount,
        node: NodeId,
        marker: GuestAssertionMarker,
    ) -> Self {
        Self {
            at: VirtualTime {
                ticks: retired_icount.retired,
            },
            payload: ObservableEventPayload::GuestAssertionMarker {
                retired_icount,
                node,
                marker,
            },
        }
    }

    /// Returns the deterministic virtual-time coordinate of the observation.
    #[must_use]
    pub fn at(&self) -> VirtualTime {
        self.at
    }

    /// Returns the typed observable payload.
    #[must_use]
    pub fn payload(&self) -> &ObservableEventPayload {
        &self.payload
    }
}

/// Typed observable event payloads used by condition leaves.
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub enum ObservableEventPayload {
    /// A network frame was delivered at RESOLVE.
    NetworkDelivered {
        /// Link where the frame was delivered, when known.
        link: Option<LinkId>,
        /// Delivered frame payload bytes.
        payload: Vec<u8>,
    },
    /// Console or serial bytes were captured for a node.
    ConsoleOutput {
        /// Node whose console stream produced the bytes.
        node: NodeId,
        /// Captured console bytes.
        bytes: Vec<u8>,
    },
    /// A TCG-exec basic-block coverage observation became visible.
    CoverageBlock {
        /// Exact guest instruction count at which the block executed.
        execution_icount: Icount,
        /// Node that executed the block.
        node: NodeId,
        /// Guest program counter for the block.
        guest_pc: u64,
        /// Translated block length supplied by QEMU.
        block_len: u32,
    },
    /// A deterministic guest memory or register sample became visible.
    MemorySample {
        /// Exact guest instruction count at which the sample was taken.
        sample_icount: Icount,
        /// Node whose memory/register was sampled.
        node: NodeId,
        /// Host-resolved place that was sampled.
        place: ResolvedMemPlace,
        /// Unsigned sampled value.
        value: u64,
    },
    /// A deterministic device I/O completion became visible.
    IoCompletion {
        /// Node that observes the completion.
        node: NodeId,
        /// Completion class.
        kind: IoEventKind,
        /// Completion payload bytes.
        payload: Vec<u8>,
    },
    /// A node entered a lifecycle state.
    NodeState {
        /// Node whose lifecycle changed.
        node: NodeId,
        /// Lifecycle state entered by the node.
        state: NodeLifecycle,
    },
    /// A named assertion entered a terminal state.
    AssertionStateChanged {
        /// Assertion whose state changed.
        name: AssertionId,
        /// Terminal assertion state entered at this log point.
        state: AssertionPhase,
    },
    /// An optional white-box doorbell marker was observed.
    GuestMarker {
        /// Exact guest instruction count where the doorbell retired.
        retired_icount: Icount,
        /// Node that emitted the marker.
        node: NodeId,
        /// Stable marker identity carried by the doorbell payload.
        marker: MarkerId,
    },
    /// An optional white-box assertion marker was observed.
    GuestAssertionMarker {
        /// Exact guest instruction count where the doorbell retired.
        retired_icount: Icount,
        /// Node that emitted the marker.
        node: NodeId,
        /// Assertion marker payload carried by the doorbell.
        marker: GuestAssertionMarker,
    },
}

/// Assertion flavor carried by a white-box doorbell assertion marker.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum GuestAssertionKind {
    /// Invariant marker; any false observation violates the assertion.
    Always,
    /// Liveness marker; at least one true observation is required.
    Sometimes,
    /// Coverage marker; true observation satisfies reachability.
    Reachable,
    /// Unreachable dual; any true observation violates the assertion.
    Unreachable,
}

/// One structured key/value detail carried by a guest assertion marker.
#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct GuestAssertionDetail {
    /// Stable detail key.
    pub key: String,
    /// Stable detail value.
    pub value: String,
}

impl GuestAssertionDetail {
    /// Builds one guest assertion detail field.
    #[must_use]
    pub fn new(key: impl Into<String>, value: impl Into<String>) -> Self {
        Self {
            key: key.into(),
            value: value.into(),
        }
    }
}

/// Assertion payload carried by a white-box doorbell marker.
///
/// The payload is observational: it is stored in the event log and can drive
/// assertion finalization, but it does not feed scheduler decisions or node
/// fingerprints.
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub struct GuestAssertionMarker {
    /// Stable assertion id in the marker/assertion namespace.
    pub id: AssertionId,
    /// Human-readable assertion message.
    pub message: String,
    /// Quantifier flavor declared by the marker payload.
    pub kind: GuestAssertionKind,
    /// Boolean truth value observed at the doorbell retirement point.
    pub condition: bool,
    /// Whether this marker is catalog-declared and must be hit to avoid failure.
    pub must_hit: bool,
    /// Structured marker details for later violation records.
    pub details: Vec<GuestAssertionDetail>,
    /// Source location supplied by the guest emitter.
    pub location: String,
}

impl GuestAssertionMarker {
    /// Builds a white-box assertion marker payload.
    #[must_use]
    pub fn new(
        id: AssertionId,
        message: impl Into<String>,
        kind: GuestAssertionKind,
        condition: bool,
        must_hit: bool,
        details: Vec<GuestAssertionDetail>,
        location: impl Into<String>,
    ) -> Self {
        Self {
            id,
            message: message.into(),
            kind,
            condition,
            must_hit,
            details,
            location: location.into(),
        }
    }
}

/// One leaf predicate request made by the shared condition evaluator.
///
/// The shared evaluator centralizes leaf dispatch so assertions and triggers
/// cannot use different boolean composition code.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ConditionLeaf<'a> {
    /// A named host-side predicate resolved over the current event-log point.
    Named {
        /// Stable predicate name.
        name: &'a str,
        /// Declared nodes referenced by the predicate.
        nodes: &'a [NodeId],
    },
    /// A named white-box marker resolved over the current event-log point.
    GuestMarker {
        /// Stable marker identity.
        marker: &'a MarkerId,
    },
}

/// Oracle for condition leaves at one deterministic evaluation point.
pub trait ConditionLeafOracle {
    /// Returns whether one leaf predicate is true.
    fn leaf_is_true(&mut self, leaf: ConditionLeaf<'_>) -> bool;
}

impl<F> ConditionLeafOracle for F
where
    F: for<'leaf> FnMut(ConditionLeaf<'leaf>) -> bool,
{
    fn leaf_is_true(&mut self, leaf: ConditionLeaf<'_>) -> bool {
        self(leaf)
    }
}

/// Shared evaluator used by both assertion and trigger consumers.
pub trait ConditionEvaluator: condition_evaluator_sealed::Sealed {
    /// Returns the deterministic point where this evaluator observes the log.
    fn evaluation_point(&self) -> EventEvaluationPoint;

    /// Returns the event-log prefix identity observed by this evaluator.
    fn event_log_offset(&self) -> EventLogOffset;

    /// Resolves a leaf predicate at [`Self::evaluation_point`].
    fn leaf_is_true(&mut self, leaf: ConditionLeaf<'_>) -> bool;

    /// Returns the most recent firing time for an event, when known.
    fn last_event_firing(&self, event: &EventId) -> Option<VirtualTime> {
        let _ = event;
        None
    }

    /// Returns the virtual time where a timer fires, when armed and known.
    fn timer_fire_time(&self, timer: &TimerId) -> Option<VirtualTime> {
        let _ = timer;
        None
    }

    /// Returns the complete timer-fire map visible to `Timer` leaves.
    fn timer_fires(&self) -> BTreeMap<TimerId, VirtualTime> {
        BTreeMap::new()
    }

    /// Returns observable event-log entries visible at the evaluation point.
    fn observable_events(&self) -> &[ObservableEvent] {
        &[]
    }

    /// Returns scheduler-owned quiescence evidence for the evaluation point.
    fn scheduler_quiescence(&self) -> Option<&SchedulerQuiescence> {
        None
    }

    /// Returns the authoritative white-box opt-in policy for a node.
    fn white_box_policy_for_node(&self, node: &NodeId) -> Option<WhiteBoxPolicy> {
        let _ = node;
        None
    }

    /// Returns whether a `Once` predicate has already latched true.
    fn once_condition_is_latched(&self, condition: &Condition) -> bool;

    /// Records that a `Once` predicate has latched true.
    fn latch_once_condition(&mut self, condition: &Condition);

    /// Resolves an authored code point using host-side symbol metadata.
    fn resolve_code_point(&self, _node: &NodeId, point: &CodePoint) -> Option<ResolvedCodePoint> {
        match point {
            CodePoint::GuestAddress { address } => Some(ResolvedCodePoint::guest_address(*address)),
            CodePoint::Symbol { .. } => None,
        }
    }

    /// Resolves an authored memory place using host-side symbol metadata.
    fn resolve_mem_place(&self, _node: &NodeId, place: &MemPlace) -> Option<ResolvedMemPlace> {
        match place {
            MemPlace::PhysicalAddress { address, width } => {
                Some(ResolvedMemPlace::physical_address(*address, width.bytes()))
            }
            MemPlace::Register { name, width } => {
                Some(ResolvedMemPlace::register(name.clone(), width.bytes()))
            }
            MemPlace::VirtualAddress { .. } | MemPlace::Symbol { .. } => None,
        }
    }
}

mod condition_evaluator_sealed {
    pub trait Sealed {}
}

/// Error returned when constructing a deterministic condition-evaluation prefix.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ConditionEvaluationError {
    /// A scheduler event-log prefix contained no entries.
    EmptyEventLogPrefix,
    /// A scheduler event-log entry does not continue the dense prefix sequence.
    NonPrefixEventLogSequence {
        /// Sequence number expected at this prefix offset.
        expected: u64,
        /// Sequence number carried by the entry.
        actual: u64,
    },
    /// A scheduler event-log entry's content hash does not match its material.
    InvalidEventLogEntryHash {
        /// Sequence number carried by the invalid entry.
        sequence: u64,
    },
    /// An event-log entry occurs after the derived evaluation point.
    FutureEventLogEntry {
        /// Deterministic evaluation point.
        point: VirtualTime,
        /// Sequence number carried by the future entry.
        sequence: u64,
        /// Time of the future event-log entry.
        event_at: VirtualTime,
    },
}

impl fmt::Display for ConditionEvaluationError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::EmptyEventLogPrefix => write!(
                formatter,
                "scheduler event-log prefix must contain at least one entry"
            ),
            Self::NonPrefixEventLogSequence { expected, actual } => write!(
                formatter,
                "scheduler event-log prefix expected sequence {expected}, found {actual}"
            ),
            Self::InvalidEventLogEntryHash { sequence } => write!(
                formatter,
                "scheduler event-log entry {sequence} has an invalid content hash"
            ),
            Self::FutureEventLogEntry {
                point,
                sequence,
                event_at,
            } => write!(
                formatter,
                "event-log entry {sequence} at {} is after evaluation point {}",
                event_at.ticks, point.ticks
            ),
        }
    }
}

impl Error for ConditionEvaluationError {}

/// Observable event-log prefix visible at one deterministic evaluation point.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ConditionEventLogPrefix {
    point: EventEvaluationPoint,
    event_log_offset: EventLogOffset,
    prefix_offsets: BTreeMap<u64, EventLogOffset>,
    scheduler_entries: Vec<SchedulerEventLogEntry>,
    observable_events: Vec<ObservableEvent>,
    ordering_facts: Vec<ObservedOrderingFact>,
    fault_facts: Vec<ObservedFaultFact>,
}

impl ConditionEventLogPrefix {
    /// Builds the run-start genesis prefix.
    #[must_use]
    pub fn genesis() -> Self {
        Self {
            point: EventEvaluationPoint::genesis(),
            event_log_offset: EventLogOffset::default(),
            prefix_offsets: BTreeMap::new(),
            scheduler_entries: Vec::new(),
            observable_events: Vec::new(),
            ordering_facts: Vec::new(),
            fault_facts: Vec::new(),
        }
    }

    /// Builds a checked condition prefix from scheduler event-log entries.
    ///
    /// The evaluation point is derived from the final log entry: explicit
    /// scheduler evaluation-boundary payloads produce quantum or rendezvous
    /// points, while all other entries produce event-log-entry points. The
    /// observable prefix is likewise derived from `Observable` payloads rather
    /// than supplied by the caller.
    ///
    /// # Errors
    ///
    /// Returns [`ConditionEvaluationError::EmptyEventLogPrefix`] when no
    /// scheduler entries are supplied,
    /// [`ConditionEvaluationError::NonPrefixEventLogSequence`] when the entries
    /// are not a dense prefix starting at zero,
    /// [`ConditionEvaluationError::InvalidEventLogEntryHash`] when any entry's
    /// content hash does not match its canonical material, or
    /// [`ConditionEvaluationError::FutureEventLogEntry`] when an entry occurs
    /// after the derived evaluation point.
    pub(crate) fn from_scheduler_event_log_entries(
        entries: Vec<SchedulerEventLogEntry>,
    ) -> Result<Self, ConditionEvaluationError> {
        let Some(last) = entries.last() else {
            return Err(ConditionEvaluationError::EmptyEventLogPrefix);
        };
        let point = EventEvaluationPoint::event_log_entry(last);
        let mut observable_events = Vec::new();
        let mut ordering_facts = Vec::new();
        let mut fault_facts = Vec::new();
        for (offset, entry) in entries.iter().enumerate() {
            let expected = u64::try_from(offset).map_err(|_| {
                ConditionEvaluationError::NonPrefixEventLogSequence {
                    expected: u64::MAX,
                    actual: entry.sequence(),
                }
            })?;
            if entry.sequence() != expected {
                return Err(ConditionEvaluationError::NonPrefixEventLogSequence {
                    expected,
                    actual: entry.sequence(),
                });
            }
            if !entry.has_valid_content_hash() {
                return Err(ConditionEvaluationError::InvalidEventLogEntryHash {
                    sequence: entry.sequence(),
                });
            }
            if entry.at().ticks > point.at().ticks {
                return Err(ConditionEvaluationError::FutureEventLogEntry {
                    point: point.at(),
                    sequence: entry.sequence(),
                    event_at: entry.at(),
                });
            }
            push_observed_state_facts(
                entry,
                &mut observable_events,
                &mut ordering_facts,
                &mut fault_facts,
            );
        }
        Ok(Self {
            point,
            event_log_offset: EventLogOffset::new(
                ContentHash::default(),
                0,
                u64::try_from(entries.len()).map_err(|_| {
                    ConditionEvaluationError::NonPrefixEventLogSequence {
                        expected: u64::MAX,
                        actual: u64::MAX,
                    }
                })?,
            ),
            prefix_offsets: BTreeMap::new(),
            scheduler_entries: entries,
            observable_events,
            ordering_facts,
            fault_facts,
        })
    }

    pub(crate) fn with_event_log_offset(mut self, event_log_offset: EventLogOffset) -> Self {
        self.event_log_offset = event_log_offset;
        self
    }

    pub(crate) fn with_prefix_offsets(
        mut self,
        prefix_offsets: BTreeMap<u64, EventLogOffset>,
    ) -> Self {
        self.prefix_offsets = prefix_offsets;
        self
    }

    pub(crate) fn with_point(mut self, point: EventEvaluationPoint) -> Self {
        self.point = point;
        self
    }

    pub(crate) fn with_facts_through_point(&self, point: EventEvaluationPoint) -> Option<Self> {
        let through = point.at().ticks;
        let entries = self
            .scheduler_entries
            .iter()
            .take_while(|entry| entry.at().ticks <= through)
            .cloned()
            .collect::<Vec<_>>();
        let prefix_len = u64::try_from(entries.len()).ok()?;
        if entries.is_empty() {
            let mut prefix = Self::genesis();
            if !self.prefix_offsets.is_empty() {
                prefix = prefix.with_event_log_offset(*self.prefix_offsets.get(&prefix_len)?);
            }
            return Some(
                prefix
                    .with_prefix_offsets(self.prefix_offsets.clone())
                    .with_point(point),
            );
        }
        let mut prefix = Self::from_scheduler_event_log_entries(entries).ok()?;
        if !self.prefix_offsets.is_empty() {
            prefix = prefix.with_event_log_offset(*self.prefix_offsets.get(&prefix_len)?);
        }
        Some(
            prefix
                .with_prefix_offsets(self.prefix_offsets.clone())
                .with_point(point),
        )
    }

    /// Returns the deterministic evaluation point this prefix is visible at.
    #[must_use]
    pub fn point(&self) -> EventEvaluationPoint {
        self.point
    }

    /// Returns the event-log prefix identity this condition prefix was derived from.
    #[must_use]
    pub fn event_log_offset(&self) -> EventLogOffset {
        self.event_log_offset
    }

    /// Returns observable event-log entries visible at [`Self::point`].
    #[must_use]
    pub fn observable_events(&self) -> &[ObservableEvent] {
        &self.observable_events
    }

    /// Returns cross-node ordering facts visible at [`Self::point`].
    #[must_use]
    pub fn ordering_facts(&self) -> &[ObservedOrderingFact] {
        &self.ordering_facts
    }

    /// Returns fault activation, outcome, and heal facts visible at [`Self::point`].
    #[must_use]
    pub fn fault_facts(&self) -> &[ObservedFaultFact] {
        &self.fault_facts
    }

    /// Returns a read-only observed-state view materialized from this checked prefix.
    #[must_use]
    pub fn observed_state(&self) -> ObservedState<'_> {
        ObservedState {
            point: self.point,
            event_log_offset: self.event_log_offset,
            observable_events: &self.observable_events,
            ordering_facts: &self.ordering_facts,
            fault_facts: &self.fault_facts,
        }
    }
}

/// Read-only observable run state at one deterministic evaluation point.
///
/// The view is derived only from a checked scheduler event-log prefix. It
/// exposes black-box observable events plus explicit ordering and fault facts;
/// raw scheduler entries, RNG draws, app-random draws, host-worker state, and
/// wall-clock data are not part of this API.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ObservedState<'log> {
    point: EventEvaluationPoint,
    event_log_offset: EventLogOffset,
    observable_events: &'log [ObservableEvent],
    ordering_facts: &'log [ObservedOrderingFact],
    fault_facts: &'log [ObservedFaultFact],
}

impl<'log> ObservedState<'log> {
    /// Returns the deterministic evaluation point for this view.
    #[must_use]
    pub fn point(self) -> EventEvaluationPoint {
        self.point
    }

    /// Returns the virtual time where this view is evaluated.
    #[must_use]
    pub fn at(self) -> VirtualTime {
        self.point.at()
    }

    /// Returns the event-log prefix identity backing this view.
    #[must_use]
    pub fn event_log_offset(self) -> EventLogOffset {
        self.event_log_offset
    }

    /// Returns black-box observable events in deterministic log order.
    #[must_use]
    pub fn observable_events(self) -> &'log [ObservableEvent] {
        self.observable_events
    }

    /// Returns scheduler ordering facts in deterministic log order.
    #[must_use]
    pub fn ordering_facts(self) -> &'log [ObservedOrderingFact] {
        self.ordering_facts
    }

    /// Returns fault activation, outcome, and heal facts in deterministic log order.
    #[must_use]
    pub fn fault_facts(self) -> &'log [ObservedFaultFact] {
        self.fault_facts
    }
}

/// Cross-node ordering information exposed to property predicates.
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub enum ObservedOrderingFact {
    /// A scheduled event was resolved at this prefix position.
    ResolvedHappening {
        /// Dense event-log sequence where the fact was recorded.
        sequence: u64,
        /// Virtual time of the event-log entry.
        at: VirtualTime,
        /// Deterministic scheduler key for the resolved event.
        key: ScheduledEventKey,
        /// Resolve class without payload-specific data.
        class: ScheduledEventResolveClass,
    },
    /// A total delivery order was chosen for one virtual time.
    DeliveryOrder {
        /// Dense event-log sequence where the fact was recorded.
        sequence: u64,
        /// Virtual time of the event-log entry.
        at: VirtualTime,
        /// Ordered legacy event keys recorded by the delivery decision.
        order: Vec<EventKey>,
    },
}

/// Fault information exposed to property predicates.
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub enum ObservedFaultFact {
    /// A scheduled fault activation entered the event log.
    ScheduledActivation {
        /// Dense event-log sequence where the fact was recorded.
        sequence: u64,
        /// Virtual time of the event-log entry.
        at: VirtualTime,
        /// Fault whose activation was resolved.
        fault: FaultId,
    },
    /// A scheduled probabilistic fault choice entered the event log.
    ScheduledProbabilisticChoice {
        /// Dense event-log sequence where the fact was recorded.
        sequence: u64,
        /// Virtual time of the event-log entry.
        at: VirtualTime,
        /// Fault whose probabilistic choice was resolved.
        fault: FaultId,
    },
    /// A probabilistic fault outcome was decided.
    ProbabilisticOutcome {
        /// Dense event-log sequence where the fact was recorded.
        sequence: u64,
        /// Virtual time of the event-log entry.
        at: VirtualTime,
        /// Fault whose outcome was decided.
        fault: FaultId,
        /// Whether the probabilistic fault fired.
        fired: bool,
    },
    /// A control-plane full-taxonomy fault was injected.
    ControlInjected {
        /// Dense event-log sequence where the fact was recorded.
        sequence: u64,
        /// Virtual time of the event-log entry.
        at: VirtualTime,
        /// Monotone control operation sequence.
        control_sequence: u64,
        /// Stable fault tag.
        tag: FaultTag,
        /// Fault taxonomy value activated under `tag`.
        fault: Fault,
    },
    /// A control-plane full-taxonomy fault was healed.
    ControlHealed {
        /// Dense event-log sequence where the fact was recorded.
        sequence: u64,
        /// Virtual time of the event-log entry.
        at: VirtualTime,
        /// Monotone control operation sequence.
        control_sequence: u64,
        /// Stable fault tag.
        tag: FaultTag,
    },
    /// A trigger-owned membership fault was injected.
    TriggerInjected {
        /// Dense event-log sequence where the fact was recorded.
        sequence: u64,
        /// Virtual time of the event-log entry.
        at: VirtualTime,
        /// Monotone trigger action sequence.
        trigger_sequence: u64,
        /// Trigger event that produced the action.
        event: EventId,
        /// Stable fault tag.
        tag: FaultTag,
        /// Membership fault activated under `tag`.
        fault: MembershipFault,
    },
    /// A trigger-owned membership fault was healed.
    TriggerHealed {
        /// Dense event-log sequence where the fact was recorded.
        sequence: u64,
        /// Virtual time of the event-log entry.
        at: VirtualTime,
        /// Monotone trigger action sequence.
        trigger_sequence: u64,
        /// Trigger event that produced the action.
        event: EventId,
        /// Stable fault tag.
        tag: FaultTag,
    },
}

/// Host-side resolver for assertion leaves over materialized observed state.
///
/// Built-in black-box predicates are evaluated by the shared condition
/// evaluator from the checked event-log prefix. This oracle is called only for
/// host-authored named leaves that need harness logic over [`ObservedState`].
pub trait HostAssertionOracle {
    /// Returns whether one host-side assertion leaf is true at `observed`.
    fn leaf_is_true(&mut self, observed: ObservedState<'_>, leaf: ConditionLeaf<'_>) -> bool;
}

impl<F> HostAssertionOracle for F
where
    F: for<'log, 'leaf> FnMut(ObservedState<'log>, ConditionLeaf<'leaf>) -> bool,
{
    fn leaf_is_true(&mut self, observed: ObservedState<'_>, leaf: ConditionLeaf<'_>) -> bool {
        self(observed, leaf)
    }
}

/// Default zero-guest-cooperation assertion oracle.
///
/// The oracle supplies no named host predicates. Properties that use only the
/// built-in black-box observable vocabulary still evaluate through the checked
/// event-log prefix.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct BlackBoxHostOracle;

impl HostAssertionOracle for BlackBoxHostOracle {
    fn leaf_is_true(&mut self, _observed: ObservedState<'_>, leaf: ConditionLeaf<'_>) -> bool {
        match leaf {
            ConditionLeaf::Named { .. } | ConditionLeaf::GuestMarker { .. } => false,
        }
    }
}

/// Terminal kind for one host-side assertion outcome.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum HostAssertionOutcomeKind {
    /// The assertion completed successfully.
    Satisfied,
    /// The assertion failed and contributes to the run verdict.
    Violated,
    /// The assertion produced a non-failing diagnostic outcome.
    Warning,
    /// The assertion had no evaluation point in its declared scope.
    NeverEvaluated,
    /// The assertion's trigger never fired during the run.
    NeverTriggered,
    /// A warn-disposition reachability marker was never reached.
    NeverReachedWarn,
    /// A fail-disposition reachability marker was never reached.
    NeverReachedFail,
}

/// Terminal result for one host-side assertion.
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub struct HostAssertionOutcome {
    /// Assertion that produced the outcome.
    pub assertion: AssertionId,
    /// Deterministic virtual time where the outcome was recorded.
    pub at: VirtualTime,
    /// Terminal outcome kind.
    pub kind: HostAssertionOutcomeKind,
    /// Human-readable assertion message from the properties bundle.
    pub message: String,
    /// Stable assertion-layer reason.
    pub reason: String,
}

/// Final host-side assertion report for one run.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct HostAssertionReport {
    outcomes: Vec<HostAssertionOutcome>,
    verdict: AssertionRunVerdict,
}

impl HostAssertionReport {
    /// Returns terminal assertion outcomes in canonical assertion order.
    #[must_use]
    pub fn outcomes(&self) -> &[HostAssertionOutcome] {
        &self.outcomes
    }

    /// Returns the assertion-layer pass/fail verdict.
    #[must_use]
    pub fn verdict(&self) -> &AssertionRunVerdict {
        &self.verdict
    }
}

/// Deterministic trace artifact intended for external formal tooling.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ExternalFormalTraceExport {
    bytes: Vec<u8>,
    content_hash: ContentHash,
    entry_count: u64,
}

impl ExternalFormalTraceExport {
    /// Returns the stable export format label.
    #[must_use]
    pub fn format(&self) -> &'static str {
        "crucible.external-formal-trace.v1"
    }

    /// Returns deterministic trace bytes for external consumers.
    #[must_use]
    pub fn bytes(&self) -> &[u8] {
        &self.bytes
    }

    /// Returns the content address of [`Self::bytes`].
    #[must_use]
    pub fn content_hash(&self) -> ContentHash {
        self.content_hash
    }

    /// Returns the number of scheduler event-log entries exported.
    #[must_use]
    pub fn entry_count(&self) -> u64 {
        self.entry_count
    }
}

/// Exporter for external formal trace consumers.
///
/// This type only serializes a retained scheduler event log. It does not load,
/// interpret, or evaluate an external specification.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct ExternalFormalTraceExporter;

impl ExternalFormalTraceExporter {
    /// Exports a retained scheduler event log as deterministic trace bytes.
    ///
    /// # Errors
    ///
    /// Returns [`ConditionEvaluationError`] when the entries are not a dense,
    /// hash-valid scheduler log prefix.
    pub fn export_event_log(
        entries: &[SchedulerEventLogEntry],
    ) -> Result<ExternalFormalTraceExport, ConditionEvaluationError> {
        validate_recorded_event_log_entries(entries)?;
        let entry_count = u64::try_from(entries.len()).map_err(|_| {
            ConditionEvaluationError::NonPrefixEventLogSequence {
                expected: u64::MAX,
                actual: u64::MAX,
            }
        })?;
        let bytes = external_formal_trace_bytes(entries);
        let content_hash = ContentHash::from_bytes(&bytes);
        Ok(ExternalFormalTraceExport {
            bytes,
            content_hash,
            entry_count,
        })
    }
}

/// Offline assertion checker for a retained scheduler event log.
///
/// The checker never drives guests or scheduler state. It reconstructs checked
/// [`ConditionEventLogPrefix`] values from recorded [`SchedulerEventLogEntry`]
/// values and feeds them through [`HostAssertionEvaluator`], so amended property
/// sets can be graded against retained runs.
#[derive(Clone, Debug, Default)]
pub struct OfflineAssertionChecker {
    white_box_policies: BTreeMap<NodeId, WhiteBoxPolicy>,
    guest_assertion_catalog: Vec<GuestAssertionMarker>,
}

impl OfflineAssertionChecker {
    /// Builds an offline checker with no white-box marker policy.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Adds authoritative white-box opt-in policies for guest marker evaluation.
    #[must_use]
    pub fn with_white_box_policies(
        mut self,
        policies: impl IntoIterator<Item = (NodeId, WhiteBoxPolicy)>,
    ) -> Self {
        self.white_box_policies = policies.into_iter().collect();
        self
    }

    /// Adds authoritative white-box opt-in policies from a world definition.
    #[must_use]
    pub fn with_world_white_box_policies(self, world: &World) -> Self {
        self.with_white_box_policies(
            world
                .nodes()
                .iter()
                .map(|node| (node.id.clone(), node.white_box)),
        )
    }

    /// Adds catalog-declared guest assertion markers for offline finalization.
    #[must_use]
    pub fn with_guest_assertion_catalog(
        mut self,
        catalog: impl IntoIterator<Item = GuestAssertionMarker>,
    ) -> Self {
        self.guest_assertion_catalog = catalog.into_iter().collect();
        self
    }

    /// Grades `properties` against a retained event log using the black-box oracle.
    ///
    /// This entry point is for built-in black-box predicates and guest markers.
    /// Named host predicates that inspect [`ObservedState::event_log_offset`]
    /// should use [`Self::check_run_with_oracle`] with a [`RecordedAssertionLog`]
    /// carrying the exact recorded prefix offsets.
    ///
    /// # Errors
    ///
    /// Returns [`OfflineAssertionCheckError::ConditionEvaluation`] when the
    /// recorded entries are not a dense, hash-valid scheduler log prefix.
    pub fn check_run(
        &self,
        properties: &Properties,
        event_log: &[SchedulerEventLogEntry],
    ) -> Result<HostAssertionReport, OfflineAssertionCheckError> {
        let mut oracle = BlackBoxHostOracle;
        let recorded = RecordedAssertionLog::from_entries(event_log.to_vec());
        self.check_run_internal(properties, &recorded, &mut oracle, false)
    }

    /// Grades `properties` against a retained event log using `oracle`.
    ///
    /// The event log is read-only input. Evaluation observes every recorded
    /// event-log prefix except the terminal prefix, then lets
    /// [`HostAssertionEvaluator::finalize_prefix`] observe that terminal prefix
    /// exactly once before applying end-of-run policies. Each observed point is
    /// reconstructed as a [`ConditionEventLogPrefix`] before evaluation. The
    /// supplied [`RecordedAssertionLog`] should carry exact event-log offsets for
    /// every prefix that can be observed by a named host predicate. Intermediate
    /// prefixes without retained offsets are skipped for custom-oracle checks;
    /// the terminal prefix must always have an exact offset.
    ///
    /// # Errors
    ///
    /// Returns [`OfflineAssertionCheckError::ConditionEvaluation`] when the
    /// recorded entries are not a dense, hash-valid scheduler log prefix,
    /// [`OfflineAssertionCheckError::MissingEventLogOffset`] when the terminal
    /// prefix has no recorded offset, or
    /// [`OfflineAssertionCheckError::EventLogOffsetMismatch`] when a supplied
    /// offset's event count does not match the evaluated prefix length.
    pub fn check_run_with_oracle<O>(
        &self,
        properties: &Properties,
        recorded_log: &RecordedAssertionLog,
        oracle: &mut O,
    ) -> Result<HostAssertionReport, OfflineAssertionCheckError>
    where
        O: HostAssertionOracle + ?Sized,
    {
        self.check_run_internal(properties, recorded_log, oracle, true)
    }

    fn check_run_internal<O>(
        &self,
        properties: &Properties,
        recorded_log: &RecordedAssertionLog,
        oracle: &mut O,
        require_recorded_offsets: bool,
    ) -> Result<HostAssertionReport, OfflineAssertionCheckError>
    where
        O: HostAssertionOracle + ?Sized,
    {
        let mut evaluator = HostAssertionEvaluator::new(properties)
            .with_white_box_policies(self.white_box_policies.clone())
            .with_guest_assertion_catalog(self.guest_assertion_catalog.clone());
        let event_log = recorded_log.entries();
        let terminal_prefix_len = event_log.len();

        for index in 0..event_log.len() {
            let prefix_len = index + 1;
            if prefix_len == terminal_prefix_len {
                continue;
            }
            if require_recorded_offsets
                && recorded_log
                    .event_log_offset(u64::try_from(prefix_len).map_err(|_| {
                        OfflineAssertionCheckError::PrefixLengthOverflow { prefix_len }
                    })?)
                    .is_none()
            {
                continue;
            }
            let prefix = condition_prefix_from_recorded_log(
                recorded_log,
                prefix_len,
                require_recorded_offsets,
            )?;
            evaluator.observe_prefix(&prefix, oracle);
        }

        let terminal_prefix = condition_prefix_from_recorded_log(
            recorded_log,
            terminal_prefix_len,
            require_recorded_offsets,
        )?;
        Ok(evaluator.finalize_prefix(&terminal_prefix, oracle))
    }
}

/// Retained assertion-checking view of a recorded scheduler event log.
///
/// Custom host predicate oracles can inspect [`ObservedState::event_log_offset`].
/// To make those predicates byte-identical online and offline, this value stores
/// the scheduler entries plus offsets reconstructed from retained event-log
/// segments using the scheduler's canonical segment and prefix hashing.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct RecordedAssertionLog {
    entries: Vec<SchedulerEventLogEntry>,
    prefix_offsets: BTreeMap<u64, EventLogOffset>,
}

impl RecordedAssertionLog {
    /// Builds a recorded log from scheduler entries without segment offsets.
    ///
    /// This is sufficient for [`OfflineAssertionChecker::check_run`], whose
    /// default black-box oracle cannot inspect event-log offsets. Custom host
    /// oracles should use [`Self::from_segments`] so evaluated prefixes carry the
    /// same offsets the scheduler observed online.
    #[must_use]
    pub fn from_entries(entries: Vec<SchedulerEventLogEntry>) -> Self {
        Self {
            entries,
            prefix_offsets: BTreeMap::new(),
        }
    }

    /// Builds a recorded log from retained scheduler event-log segments.
    ///
    /// Each segment is folded in order with the same canonical segment bytes and
    /// prefix hash material used by scheduler EMIT. Offsets are recorded at every
    /// segment boundary, including the zero-entry genesis prefix.
    ///
    /// # Errors
    ///
    /// Returns [`OfflineAssertionCheckError::EventLogSegmentLengthOverflow`] when
    /// a segment byte length cannot fit in `u64`,
    /// [`OfflineAssertionCheckError::EventLogByteOffsetOverflow`] when cumulative
    /// bytes overflow, or [`OfflineAssertionCheckError::EventLogEventCountOverflow`]
    /// when cumulative event count overflows.
    pub fn from_segments(
        segments: impl IntoIterator<Item = Vec<SchedulerEventLogEntry>>,
    ) -> Result<Self, OfflineAssertionCheckError> {
        let mut entries = Vec::new();
        let mut prefix_offsets = BTreeMap::new();
        let mut prefix = scheduler_event_log_empty_prefix();
        let mut bytes = 0_u64;
        let mut events = 0_u64;
        prefix_offsets.insert(events, EventLogOffset::new(prefix, bytes, events));

        for segment in segments {
            if segment.is_empty() {
                continue;
            }
            let segment_bytes = scheduler_event_log_segment_bytes(prefix, &segment);
            let segment_hash = ContentHash::from_bytes(&segment_bytes);
            let appended_bytes = u64::try_from(segment_bytes.len()).map_err(|_| {
                OfflineAssertionCheckError::EventLogSegmentLengthOverflow {
                    segment_len: segment_bytes.len(),
                }
            })?;
            bytes = bytes.checked_add(appended_bytes).ok_or(
                OfflineAssertionCheckError::EventLogByteOffsetOverflow {
                    bytes,
                    appended_bytes,
                },
            )?;
            let appended_events = u64::try_from(segment.len()).map_err(|_| {
                OfflineAssertionCheckError::EventLogEventCountOverflow {
                    events,
                    appended_events: u64::MAX,
                }
            })?;
            events = events.checked_add(appended_events).ok_or(
                OfflineAssertionCheckError::EventLogEventCountOverflow {
                    events,
                    appended_events,
                },
            )?;
            let prefix_material = format!(
                "previous_prefix={}\nappended_segment={}\nbytes={bytes}\nevents={events}",
                prefix.to_hex(),
                segment_hash.to_hex(),
            );
            prefix = ContentHash::from_canonical_material(
                "crucible.scheduler.event-log.prefix.v1",
                &prefix_material,
            );
            prefix_offsets.insert(events, EventLogOffset::new(prefix, bytes, events));
            entries.extend(segment);
        }

        Ok(Self {
            entries,
            prefix_offsets,
        })
    }

    /// Returns retained scheduler event-log entries.
    #[must_use]
    pub fn entries(&self) -> &[SchedulerEventLogEntry] {
        &self.entries
    }

    /// Returns the reconstructed event-log offset for `prefix_len`, if retained.
    #[must_use]
    pub fn event_log_offset(&self, prefix_len: u64) -> Option<EventLogOffset> {
        self.prefix_offsets.get(&prefix_len).copied()
    }
}

/// Error returned by offline assertion checking.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum OfflineAssertionCheckError {
    /// A recorded scheduler prefix failed condition-prefix validation.
    ConditionEvaluation(ConditionEvaluationError),
    /// A custom-oracle check lacks the exact event-log offset for a prefix.
    MissingEventLogOffset {
        /// Number of scheduler entries visible in the evaluated prefix.
        prefix_len: u64,
    },
    /// A supplied event-log offset does not describe the evaluated prefix.
    EventLogOffsetMismatch {
        /// Number of scheduler entries visible in the evaluated prefix.
        prefix_len: u64,
        /// Event count stored in the supplied offset.
        offset_events: u64,
    },
    /// The platform prefix length could not be represented in the recorded format.
    PrefixLengthOverflow {
        /// Number of scheduler entries visible in the evaluated prefix.
        prefix_len: usize,
    },
    /// A retained event-log segment's canonical byte length exceeded `u64`.
    EventLogSegmentLengthOverflow {
        /// Segment byte length that could not be represented.
        segment_len: usize,
    },
    /// Cumulative event-log byte offsets overflowed.
    EventLogByteOffsetOverflow {
        /// Cumulative bytes before the segment was folded.
        bytes: u64,
        /// Bytes appended by the segment.
        appended_bytes: u64,
    },
    /// Cumulative event-log event counts overflowed.
    EventLogEventCountOverflow {
        /// Cumulative events before the segment was folded.
        events: u64,
        /// Events appended by the segment.
        appended_events: u64,
    },
}

impl fmt::Display for OfflineAssertionCheckError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::ConditionEvaluation(error) => write!(formatter, "{error}"),
            Self::MissingEventLogOffset { prefix_len } => write!(
                formatter,
                "offline assertion log is missing event-log offset for prefix length {prefix_len}"
            ),
            Self::EventLogOffsetMismatch {
                prefix_len,
                offset_events,
            } => write!(
                formatter,
                "offline assertion log offset for prefix length {prefix_len} carries event count {offset_events}"
            ),
            Self::PrefixLengthOverflow { prefix_len } => write!(
                formatter,
                "offline assertion log prefix length {prefix_len} does not fit in u64"
            ),
            Self::EventLogSegmentLengthOverflow { segment_len } => write!(
                formatter,
                "offline assertion log segment length {segment_len} does not fit in u64"
            ),
            Self::EventLogByteOffsetOverflow {
                bytes,
                appended_bytes,
            } => write!(
                formatter,
                "offline assertion log byte offset overflow: bytes={bytes} appended_bytes={appended_bytes}"
            ),
            Self::EventLogEventCountOverflow {
                events,
                appended_events,
            } => write!(
                formatter,
                "offline assertion log event count overflow: events={events} appended_events={appended_events}"
            ),
        }
    }
}

impl Error for OfflineAssertionCheckError {
    fn source(&self) -> Option<&(dyn Error + 'static)> {
        match self {
            Self::ConditionEvaluation(error) => Some(error),
            Self::MissingEventLogOffset { .. }
            | Self::EventLogOffsetMismatch { .. }
            | Self::PrefixLengthOverflow { .. }
            | Self::EventLogSegmentLengthOverflow { .. }
            | Self::EventLogByteOffsetOverflow { .. }
            | Self::EventLogEventCountOverflow { .. } => None,
        }
    }
}

impl From<ConditionEvaluationError> for OfflineAssertionCheckError {
    fn from(error: ConditionEvaluationError) -> Self {
        Self::ConditionEvaluation(error)
    }
}

/// Streaming host-side assertion evaluator over checked observable state.
#[derive(Clone, Debug)]
pub struct HostAssertionEvaluator {
    states: Vec<HostAssertionState>,
    guest_marker_states: Vec<GuestMarkerAssertionState>,
    once_latches: Vec<Condition>,
    white_box_policies: BTreeMap<NodeId, WhiteBoxPolicy>,
    last_prefix: Option<ConditionEventLogPrefix>,
}

impl HostAssertionEvaluator {
    /// Builds an evaluator for the assertions in canonical property order.
    #[must_use]
    pub fn new(properties: &Properties) -> Self {
        Self {
            states: properties
                .assertions()
                .iter()
                .map(HostAssertionState::new)
                .collect(),
            guest_marker_states: Vec::new(),
            once_latches: Vec::new(),
            white_box_policies: BTreeMap::new(),
            last_prefix: None,
        }
    }

    /// Adds authoritative white-box opt-in policies for guest marker evaluation.
    #[must_use]
    pub fn with_white_box_policies(
        mut self,
        policies: impl IntoIterator<Item = (NodeId, WhiteBoxPolicy)>,
    ) -> Self {
        self.white_box_policies = policies.into_iter().collect();
        self
    }

    /// Adds authoritative white-box opt-in policies from a world definition.
    #[must_use]
    pub fn with_world_white_box_policies(self, world: &World) -> Self {
        self.with_white_box_policies(
            world
                .nodes()
                .iter()
                .map(|node| (node.id.clone(), node.white_box)),
        )
    }

    /// Adds catalog-declared guest assertion markers before event-log evaluation.
    #[must_use]
    pub fn with_guest_assertion_catalog(
        mut self,
        catalog: impl IntoIterator<Item = GuestAssertionMarker>,
    ) -> Self {
        for marker in catalog {
            let _ = guest_marker_assertion_state_for(&mut self.guest_marker_states, &marker);
        }
        self
    }

    /// Observes one checked event-log prefix and returns newly terminal outcomes.
    pub fn observe_prefix<O>(
        &mut self,
        prefix: &ConditionEventLogPrefix,
        oracle: &mut O,
    ) -> Vec<HostAssertionOutcome>
    where
        O: HostAssertionOracle + ?Sized,
    {
        let mut outcomes = Vec::new();
        outcomes.extend(self.observe_due_eventually_deadlines(prefix, oracle));
        let once_latches = &mut self.once_latches;
        for state in &mut self.states {
            if let Some(outcome) = observe_host_assertion_state(
                state,
                prefix,
                oracle,
                once_latches,
                &self.white_box_policies,
            ) {
                outcomes.push(outcome);
            }
        }
        outcomes.extend(observe_guest_marker_assertions(
            &mut self.guest_marker_states,
            prefix,
            &self.white_box_policies,
        ));
        self.last_prefix = Some(prefix.clone());
        sort_host_assertion_outcomes(&mut outcomes);
        outcomes
    }

    fn observe_due_eventually_deadlines<O>(
        &mut self,
        prefix: &ConditionEventLogPrefix,
        oracle: &mut O,
    ) -> Vec<HostAssertionOutcome>
    where
        O: HostAssertionOracle + ?Sized,
    {
        let Some(previous_prefix) = self.last_prefix.clone() else {
            return Vec::new();
        };
        let previous_at = previous_prefix.point().at().ticks;
        let next_at = prefix.point().at().ticks;
        if next_at <= previous_at {
            return Vec::new();
        }

        let mut deadlines = BTreeSet::new();
        for state in &self.states {
            if state.terminal.is_some() {
                continue;
            }
            for obligation in &state.pending_eventually {
                if obligation.deadline.ticks > previous_at && obligation.deadline.ticks < next_at {
                    deadlines.insert(obligation.deadline);
                }
            }
        }

        let mut outcomes = Vec::new();
        for deadline in deadlines {
            let Some(deadline_prefix) =
                prefix.with_facts_through_point(EventEvaluationPoint::assertion_deadline(deadline))
            else {
                continue;
            };
            let once_latches = &mut self.once_latches;
            for state in &mut self.states {
                if let Some(outcome) = observe_eventually_deadline_state(
                    state,
                    &deadline_prefix,
                    oracle,
                    once_latches,
                    &self.white_box_policies,
                ) {
                    outcomes.push(outcome);
                }
            }
        }
        outcomes
    }

    /// Finalizes all assertions at the supplied terminal event-log prefix.
    pub fn finalize_prefix<O>(
        &mut self,
        prefix: &ConditionEventLogPrefix,
        oracle: &mut O,
    ) -> HostAssertionReport
    where
        O: HostAssertionOracle + ?Sized,
    {
        self.observe_prefix(prefix, oracle);
        let once_latches = &mut self.once_latches;
        for state in &mut self.states {
            finalize_host_assertion_state(
                state,
                prefix,
                oracle,
                once_latches,
                &self.white_box_policies,
            );
        }
        for state in &mut self.guest_marker_states {
            finalize_guest_marker_assertion_state(state, prefix.point().at());
        }
        let outcomes = self
            .states
            .iter()
            .filter_map(HostAssertionState::outcome)
            .chain(
                self.guest_marker_states
                    .iter()
                    .filter_map(GuestMarkerAssertionState::outcome),
            )
            .collect::<Vec<_>>();
        let mut outcomes = outcomes;
        sort_host_assertion_outcomes(&mut outcomes);
        let failures = outcomes
            .iter()
            .filter(|outcome| host_assertion_outcome_fails_run(outcome.kind))
            .map(|outcome| {
                AssertionVerdictFailure::new(
                    outcome.assertion.clone(),
                    outcome.at,
                    outcome.reason.clone(),
                )
            })
            .collect::<Vec<_>>();
        HostAssertionReport {
            outcomes,
            verdict: AssertionRunVerdict::failed(failures),
        }
    }
}

#[derive(Clone, Debug)]
struct HostAssertionState {
    assertion: AssertionDef,
    terminal: Option<HostAssertionTerminal>,
    evaluated: bool,
    eventually_triggered: bool,
    eventually_satisfied_at: Option<VirtualTime>,
    pending_eventually: Vec<EventuallyObligation>,
}

#[derive(Clone, Debug)]
struct GuestMarkerAssertionState {
    id: AssertionId,
    message: String,
    kind: GuestAssertionKind,
    must_hit: bool,
    details: Vec<GuestAssertionDetail>,
    location: String,
    observed_true: bool,
    terminal: Option<HostAssertionTerminal>,
}

impl GuestMarkerAssertionState {
    fn new(marker: &GuestAssertionMarker) -> Self {
        Self {
            id: marker.id.clone(),
            message: marker.message.clone(),
            kind: marker.kind,
            must_hit: marker.must_hit,
            details: marker.details.clone(),
            location: marker.location.clone(),
            observed_true: false,
            terminal: None,
        }
    }

    fn observe_payload(&mut self, marker: &GuestAssertionMarker) {
        self.must_hit |= marker.must_hit;
        self.message = marker.message.clone();
        self.location = marker.location.clone();
        self.details = marker.details.clone();
        if marker.condition {
            self.observed_true = true;
        }
    }

    fn outcome(&self) -> Option<HostAssertionOutcome> {
        self.terminal.as_ref().map(|terminal| HostAssertionOutcome {
            assertion: self.id.clone(),
            at: terminal.at,
            kind: terminal.kind,
            message: self.message.clone(),
            reason: terminal.reason.clone(),
        })
    }

    fn terminal(
        &mut self,
        kind: HostAssertionOutcomeKind,
        at: VirtualTime,
        reason: impl Into<String>,
    ) -> Option<HostAssertionOutcome> {
        if self.terminal.is_some() {
            return None;
        }
        self.terminal = Some(HostAssertionTerminal {
            kind,
            at,
            reason: reason.into(),
        });
        self.outcome()
    }
}

impl HostAssertionState {
    fn new(assertion: &AssertionDef) -> Self {
        Self {
            assertion: assertion.clone(),
            terminal: None,
            evaluated: false,
            eventually_triggered: false,
            eventually_satisfied_at: None,
            pending_eventually: Vec::new(),
        }
    }

    fn outcome(&self) -> Option<HostAssertionOutcome> {
        self.terminal.as_ref().map(|terminal| HostAssertionOutcome {
            assertion: self.assertion.id.clone(),
            at: terminal.at,
            kind: terminal.kind,
            message: self.assertion.message.clone(),
            reason: terminal.reason.clone(),
        })
    }

    fn terminal(
        &mut self,
        kind: HostAssertionOutcomeKind,
        at: VirtualTime,
        reason: impl Into<String>,
    ) -> Option<HostAssertionOutcome> {
        if self.terminal.is_some() {
            return None;
        }
        self.terminal = Some(HostAssertionTerminal {
            kind,
            at,
            reason: reason.into(),
        });
        self.outcome()
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
struct HostAssertionTerminal {
    kind: HostAssertionOutcomeKind,
    at: VirtualTime,
    reason: String,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
struct EventuallyObligation {
    triggered_at: VirtualTime,
    deadline: VirtualTime,
}

fn observe_host_assertion_state<O>(
    state: &mut HostAssertionState,
    prefix: &ConditionEventLogPrefix,
    oracle: &mut O,
    once_latches: &mut Vec<Condition>,
    white_box_policies: &BTreeMap<NodeId, WhiteBoxPolicy>,
) -> Option<HostAssertionOutcome>
where
    O: HostAssertionOracle + ?Sized,
{
    if state.terminal.is_some() {
        return None;
    }

    let at = prefix.point().at();
    let property = state.assertion.property.clone();
    match property {
        Property::Always { predicate } => {
            if prefix.event_log_offset().events == 0 {
                return None;
            }
            state.evaluated = true;
            if host_condition_is_true(prefix, &predicate, oracle, once_latches, white_box_policies)
            {
                None
            } else {
                state.terminal(
                    HostAssertionOutcomeKind::Violated,
                    at,
                    "always predicate was false",
                )
            }
        }
        Property::Sometimes { predicate } => {
            state.evaluated = true;
            if host_condition_is_true(prefix, &predicate, oracle, once_latches, white_box_policies)
            {
                state.terminal(
                    HostAssertionOutcomeKind::Satisfied,
                    at,
                    "sometimes predicate became true",
                )
            } else {
                None
            }
        }
        Property::Eventually {
            trigger,
            property,
            deadline,
        } => {
            let mut leaf_cache = HostConditionEvaluationCache::new();
            observe_eventually_assertion(
                state,
                prefix,
                oracle,
                &trigger,
                &property,
                deadline,
                once_latches,
                &mut leaf_cache,
                white_box_policies,
            )
        }
        Property::AfterQuiescence { .. } => None,
        Property::Reachable {
            predicate,
            expectation,
        } => observe_reachability_assertion(
            state,
            prefix,
            oracle,
            once_latches,
            white_box_policies,
            &predicate,
            expectation,
        ),
    }
}

fn observe_eventually_assertion<O>(
    state: &mut HostAssertionState,
    prefix: &ConditionEventLogPrefix,
    oracle: &mut O,
    trigger: &Condition,
    property: &Condition,
    deadline: VirtualTime,
    once_latches: &mut Vec<Condition>,
    leaf_cache: &mut HostConditionEvaluationCache,
    white_box_policies: &BTreeMap<NodeId, WhiteBoxPolicy>,
) -> Option<HostAssertionOutcome>
where
    O: HostAssertionOracle + ?Sized,
{
    let at = prefix.point().at();
    if let Some(expired) = state
        .pending_eventually
        .iter()
        .copied()
        .find(|obligation| at.ticks > obligation.deadline.ticks)
    {
        return state.terminal(
            HostAssertionOutcomeKind::Violated,
            expired.deadline,
            format!(
                "eventually deadline expired after trigger at {}",
                expired.triggered_at.ticks
            ),
        );
    }

    if !state.eventually_triggered
        && host_condition_is_true_with_cache(
            prefix,
            trigger,
            oracle,
            once_latches,
            leaf_cache,
            white_box_policies,
        )
    {
        state.eventually_triggered = true;
        state.pending_eventually.push(EventuallyObligation {
            triggered_at: at,
            deadline: eventually_deadline(at, deadline),
        });
    }

    if !state.pending_eventually.is_empty()
        && host_condition_is_true_with_cache(
            prefix,
            property,
            oracle,
            once_latches,
            leaf_cache,
            white_box_policies,
        )
    {
        state.pending_eventually.clear();
        state.eventually_satisfied_at = Some(at);
    } else if let Some(expired) = state
        .pending_eventually
        .iter()
        .copied()
        .find(|obligation| at.ticks >= obligation.deadline.ticks)
    {
        return state.terminal(
            HostAssertionOutcomeKind::Violated,
            expired.deadline,
            format!(
                "eventually deadline expired after trigger at {}",
                expired.triggered_at.ticks
            ),
        );
    }

    None
}

fn observe_eventually_deadline_state<O>(
    state: &mut HostAssertionState,
    prefix: &ConditionEventLogPrefix,
    oracle: &mut O,
    once_latches: &mut Vec<Condition>,
    white_box_policies: &BTreeMap<NodeId, WhiteBoxPolicy>,
) -> Option<HostAssertionOutcome>
where
    O: HostAssertionOracle + ?Sized,
{
    if state.terminal.is_some() || state.pending_eventually.is_empty() {
        return None;
    }

    let Property::Eventually { property, .. } = state.assertion.property.clone() else {
        return None;
    };
    let at = prefix.point().at();
    if host_condition_is_true(prefix, &property, oracle, once_latches, white_box_policies) {
        state.pending_eventually.clear();
        state.eventually_satisfied_at = Some(at);
        return None;
    }

    let Some(expired) = state
        .pending_eventually
        .iter()
        .copied()
        .find(|obligation| at.ticks >= obligation.deadline.ticks)
    else {
        return None;
    };
    state.terminal(
        HostAssertionOutcomeKind::Violated,
        expired.deadline,
        format!(
            "eventually deadline expired after trigger at {}",
            expired.triggered_at.ticks
        ),
    )
}

fn observe_reachability_assertion<O>(
    state: &mut HostAssertionState,
    prefix: &ConditionEventLogPrefix,
    oracle: &mut O,
    once_latches: &mut Vec<Condition>,
    white_box_policies: &BTreeMap<NodeId, WhiteBoxPolicy>,
    predicate: &Condition,
    expectation: ReachabilityExpectation,
) -> Option<HostAssertionOutcome>
where
    O: HostAssertionOracle + ?Sized,
{
    let reached =
        host_condition_is_true(prefix, predicate, oracle, once_latches, white_box_policies);
    match (expectation, reached) {
        (ReachabilityExpectation::Reachable { .. }, true) => state.terminal(
            HostAssertionOutcomeKind::Satisfied,
            prefix.point().at(),
            "reachable predicate became true",
        ),
        (ReachabilityExpectation::Unreachable, true) => state.terminal(
            HostAssertionOutcomeKind::Violated,
            prefix.point().at(),
            "unreachable predicate became true",
        ),
        (
            ReachabilityExpectation::Reachable { .. } | ReachabilityExpectation::Unreachable,
            false,
        ) => None,
    }
}

fn finalize_host_assertion_state<O>(
    state: &mut HostAssertionState,
    prefix: &ConditionEventLogPrefix,
    oracle: &mut O,
    once_latches: &mut Vec<Condition>,
    white_box_policies: &BTreeMap<NodeId, WhiteBoxPolicy>,
) where
    O: HostAssertionOracle + ?Sized,
{
    if state.terminal.is_some() {
        return;
    }

    let at = prefix.point().at();
    let property = state.assertion.property.clone();
    match property {
        Property::Always { .. } => {
            if state.evaluated {
                state.terminal(
                    HostAssertionOutcomeKind::Satisfied,
                    at,
                    "always predicate stayed true",
                );
            } else {
                state.terminal(
                    HostAssertionOutcomeKind::NeverEvaluated,
                    at,
                    "always predicate scope was never evaluated",
                );
            }
        }
        Property::Sometimes { .. } => {
            state.terminal(
                HostAssertionOutcomeKind::Violated,
                at,
                "sometimes predicate never became true",
            );
        }
        Property::Eventually { .. } => finalize_eventually_assertion(state, at),
        Property::AfterQuiescence { predicate } => {
            if host_condition_is_true(prefix, &predicate, oracle, once_latches, white_box_policies)
            {
                state.terminal(
                    HostAssertionOutcomeKind::Satisfied,
                    at,
                    "after-quiescence predicate was true",
                );
            } else {
                state.terminal(
                    HostAssertionOutcomeKind::Violated,
                    at,
                    "after-quiescence predicate was false",
                );
            }
        }
        Property::Reachable { expectation, .. } => match expectation {
            ReachabilityExpectation::Reachable { on_unreached } => match on_unreached {
                ReachableDisposition::Warn => {
                    state.terminal(
                        HostAssertionOutcomeKind::NeverReachedWarn,
                        at,
                        "reachable predicate was never reached",
                    );
                }
                ReachableDisposition::Fail => {
                    state.terminal(
                        HostAssertionOutcomeKind::NeverReachedFail,
                        at,
                        "reachable predicate was never reached",
                    );
                }
            },
            ReachabilityExpectation::Unreachable => {
                state.terminal(
                    HostAssertionOutcomeKind::Satisfied,
                    at,
                    "unreachable predicate stayed false",
                );
            }
        },
    }
}

fn finalize_eventually_assertion(state: &mut HostAssertionState, at: VirtualTime) {
    if let Some(expired) = state
        .pending_eventually
        .iter()
        .copied()
        .find(|obligation| at.ticks > obligation.deadline.ticks)
    {
        state.terminal(
            HostAssertionOutcomeKind::Violated,
            expired.deadline,
            format!(
                "eventually deadline expired after trigger at {}",
                expired.triggered_at.ticks
            ),
        );
    } else if !state.pending_eventually.is_empty() {
        state.terminal(
            HostAssertionOutcomeKind::Violated,
            at,
            "eventually run ended while triggered",
        );
    } else if let Some(satisfied_at) = state.eventually_satisfied_at {
        state.terminal(
            HostAssertionOutcomeKind::Satisfied,
            satisfied_at,
            "eventually predicate became true",
        );
    } else if state.eventually_triggered {
        state.terminal(
            HostAssertionOutcomeKind::Violated,
            at,
            "eventually trigger fired without a satisfiable obligation",
        );
    } else {
        state.terminal(
            HostAssertionOutcomeKind::NeverTriggered,
            at,
            "eventually trigger never fired",
        );
    }
}

fn eventually_deadline(triggered_at: VirtualTime, deadline: VirtualTime) -> VirtualTime {
    VirtualTime {
        ticks: triggered_at
            .ticks
            .checked_add(deadline.ticks)
            .unwrap_or(u64::MAX),
    }
}

fn condition_prefix_from_recorded_entries(
    entries: &[SchedulerEventLogEntry],
) -> Result<ConditionEventLogPrefix, ConditionEvaluationError> {
    if entries.is_empty() {
        Ok(ConditionEventLogPrefix::genesis())
    } else {
        ConditionEventLogPrefix::from_scheduler_event_log_entries(entries.to_vec())
    }
}

fn validate_recorded_event_log_entries(
    entries: &[SchedulerEventLogEntry],
) -> Result<(), ConditionEvaluationError> {
    if entries.is_empty() {
        return Ok(());
    }
    ConditionEventLogPrefix::from_scheduler_event_log_entries(entries.to_vec()).map(|_| ())
}

fn external_formal_trace_bytes(entries: &[SchedulerEventLogEntry]) -> Vec<u8> {
    let previous_prefix = scheduler_event_log_empty_prefix();
    let mut lines = Vec::new();
    lines.push(String::from("format=crucible.external-formal-trace.v1"));
    lines.push(format!(
        "scheduler_event_log_previous_prefix={}",
        previous_prefix.to_hex()
    ));
    lines.push(format!("entries={}", entries.len()));
    for entry in entries {
        lines.push(external_formal_trace_entry_material(entry));
    }
    lines.join("\n").into_bytes()
}

fn external_formal_trace_entry_material(entry: &SchedulerEventLogEntry) -> String {
    let mut lines = Vec::new();
    lines.push(String::from("entry_begin"));
    lines.push(format!("entry.sequence={}", entry.sequence()));
    lines.push(format!("entry.at_ticks={}", entry.at().ticks));
    lines.push(format!(
        "entry.class={}",
        external_scheduler_event_log_class_label(entry.class())
    ));
    lines.push(format!("entry.hash={}", entry.content_hash().to_hex()));
    lines.push(String::from("entry.payload_begin"));
    lines.push(external_scheduler_event_log_payload_material(
        entry.payload(),
    ));
    lines.push(String::from("entry.payload_end"));
    lines.push(String::from("entry_end"));
    lines.join("\n")
}

fn external_scheduler_event_log_class_label(class: SchedulerEventLogClass) -> &'static str {
    match class {
        SchedulerEventLogClass::Causal => "causal",
        SchedulerEventLogClass::Observational => "observational",
    }
}

fn external_scheduler_event_log_payload_material(payload: &SchedulerEventLogPayload) -> String {
    let mut lines = Vec::new();
    match payload {
        SchedulerEventLogPayload::ResolvedHappening(event) => {
            lines.push(String::from("payload=resolved-happening"));
            lines.push(external_scheduled_event_material(event));
        }
        SchedulerEventLogPayload::Decision(decision) => {
            lines.push(String::from("payload=decision"));
            lines.push(external_decision_material(decision));
        }
        SchedulerEventLogPayload::Observable(observable) => {
            lines.push(String::from("payload=observable"));
            lines.push(external_observable_event_payload_material(observable));
        }
        SchedulerEventLogPayload::EvaluationBoundary(kind) => {
            lines.push(String::from("payload=evaluation-boundary"));
            lines.push(format!(
                "boundary.kind={}",
                external_scheduler_evaluation_boundary_kind_label(*kind)
            ));
        }
        SchedulerEventLogPayload::TriggerFired(firing) => {
            lines.push(String::from("payload=trigger-fired"));
            lines.push(external_event_firing_material(firing));
        }
        SchedulerEventLogPayload::TriggerActionApplied(application) => {
            lines.push(String::from("payload=trigger-action-applied"));
            lines.push(external_trigger_action_application_material(application));
        }
    }
    lines.join("\n")
}

fn external_scheduled_event_material(event: &ScheduledEvent) -> String {
    let mut lines = Vec::new();
    lines.push(external_scheduled_event_key_material(&event.key));
    lines.push(format!(
        "event.resolve_class={}",
        external_scheduled_event_resolve_class_label(scheduled_event_resolve_class(event))
    ));
    lines.push(external_scheduled_event_payload_material(&event.payload));
    lines.join("\n")
}

fn external_scheduled_event_key_material(key: &ScheduledEventKey) -> String {
    let mut lines = Vec::new();
    lines.push(format!("event.time_ticks={}", key.virtual_time().ticks));
    lines.push(external_scheduler_node_material(
        "event.consumer",
        key.consumer(),
    ));
    lines.push(external_scheduler_node_material(
        "event.producer",
        key.producer(),
    ));
    lines.push(format!("event.sequence={}", key.sequence()));
    lines.join("\n")
}

fn external_scheduled_event_payload_material(payload: &ScheduledEventPayload) -> String {
    let mut lines = Vec::new();
    match payload {
        ScheduledEventPayload::BackendInput(input) => {
            lines.push(String::from("event.payload=backend-input"));
            lines.push(external_node_id_material("event.payload.node", &input.node));
            lines.push(format!(
                "event.payload.bytes={}",
                external_hex_bytes(&input.payload)
            ));
        }
        ScheduledEventPayload::IoCompletion(completion) => {
            lines.push(String::from("event.payload=io-completion"));
            lines.push(external_scheduler_node_material(
                "event.payload.sub_node",
                &completion.sub_node,
            ));
            lines.push(external_node_id_material(
                "event.payload.target",
                &completion.target,
            ));
            lines.push(format!(
                "event.payload.delivery_icount={}",
                completion.delivery_icount.retired
            ));
            lines.push(format!(
                "event.payload.bytes={}",
                external_hex_bytes(&completion.payload)
            ));
        }
        ScheduledEventPayload::FaultActivation(fault) => {
            lines.push(String::from("event.payload=fault-activation"));
            lines.push(external_fault_id_material("event.payload.fault", fault));
        }
        ScheduledEventPayload::ProbabilisticFault(choice) => {
            lines.push(String::from("event.payload=probabilistic-fault"));
            lines.push(external_fault_id_material(
                "event.payload.fault",
                &choice.fault,
            ));
            lines.push(external_rng_stream_material(
                "event.payload.stream",
                &choice.stream,
            ));
            lines.push(format!(
                "event.payload.rate_basis_points={}",
                choice.rate.basis_points()
            ));
        }
        ScheduledEventPayload::Control(operation) => {
            lines.push(String::from("event.payload=control"));
            lines.push(format!(
                "event.payload.control.sequence={}",
                operation.sequence
            ));
            lines.push(external_control_operation_kind_material(
                "event.payload.control.kind",
                &operation.kind,
            ));
        }
    }
    lines.join("\n")
}

fn external_decision_material(decision: &Decision) -> String {
    use Decision as D;

    let mut lines = Vec::new();
    match decision {
        D::DeliveryOrder(order) => {
            lines.push(String::from("decision=delivery-order"));
            lines.push(format!("decision.at_ticks={}", order.at.ticks));
            lines.push(format!("decision.events={}", order.order.len()));
            for (index, event) in order.order.iter().enumerate() {
                lines.push(external_event_key_material(
                    &format!("decision.event.{index}"),
                    event,
                ));
            }
        }
        D::FaultFires(fault) => {
            lines.push(String::from("decision=fault-fires"));
            lines.push(format!("decision.at_ticks={}", fault.at.ticks));
            lines.push(external_fault_id_material("decision.fault", &fault.fault));
            lines.push(format!("decision.fired={}", fault.fired));
        }
        D::RngDraw(draw) => {
            lines.push(String::from("decision=rng-draw"));
            lines.push(external_rng_stream_material(
                "decision.stream",
                &draw.stream,
            ));
            lines.push(format!("decision.value={}", draw.value));
        }
        D::Override(override_decision) => {
            lines.push(String::from("decision=override"));
            lines.push(external_string_material(
                "decision.point",
                &override_decision.point.key,
            ));
            lines.push(external_string_material(
                "decision.choice",
                &override_decision.choice.name,
            ));
        }
        D::Preemption(preemption) => {
            lines.push(String::from("decision=preemption"));
            lines.push(external_node_id_material("decision.node", &preemption.node));
            lines.push(format!("decision.at_retired={}", preemption.at.retired));
            lines.push(external_preemption_kind_material(
                "decision.preemption",
                &preemption.kind,
            ));
        }
        D::AppRandom(random) => {
            lines.push(String::from("decision=app-random"));
            lines.push(external_node_id_material("decision.node", &random.node));
            lines.push(external_rng_stream_material(
                "decision.stream",
                &random.stream,
            ));
            lines.push(format!("decision.request_id={}", random.request_id));
            lines.push(format!("decision.width={}", random.width));
            lines.push(format!("decision.value={}", random.value));
        }
        D::ControlFault(control) => {
            lines.push(String::from("decision=control-fault"));
            lines.push(format!("decision.at_ticks={}", control.at.ticks));
            lines.push(format!("decision.control.sequence={}", control.sequence));
            lines.push(external_control_fault_action_material(
                "decision.control.action",
                &control.action,
            ));
        }
    }
    lines.join("\n")
}

fn external_observable_event_payload_material(observable: &ObservableEventPayload) -> String {
    let mut lines = Vec::new();
    match observable {
        ObservableEventPayload::NetworkDelivered { link, payload } => {
            lines.push(String::from("observable=network-delivered"));
            lines.push(external_optional_link_material("observable.link", link));
            lines.push(format!(
                "observable.payload_bytes={}",
                external_hex_bytes(payload)
            ));
        }
        ObservableEventPayload::ConsoleOutput { node, bytes } => {
            lines.push(String::from("observable=console-output"));
            lines.push(external_node_id_material("observable.node", node));
            lines.push(format!("observable.bytes={}", external_hex_bytes(bytes)));
        }
        ObservableEventPayload::CoverageBlock {
            execution_icount,
            node,
            guest_pc,
            block_len,
        } => {
            lines.push(String::from("observable=coverage-block"));
            lines.push(format!(
                "observable.execution_icount={}",
                execution_icount.retired
            ));
            lines.push(external_node_id_material("observable.node", node));
            lines.push(format!("observable.guest_pc={guest_pc}"));
            lines.push(format!("observable.block_len={block_len}"));
        }
        ObservableEventPayload::MemorySample {
            sample_icount,
            node,
            place,
            value,
        } => {
            lines.push(String::from("observable=memory-sample"));
            lines.push(format!(
                "observable.sample_icount={}",
                sample_icount.retired
            ));
            lines.push(external_node_id_material("observable.node", node));
            lines.push(external_resolved_mem_place_material(
                "observable.place",
                place,
            ));
            lines.push(format!("observable.value={value}"));
        }
        ObservableEventPayload::IoCompletion {
            node,
            kind,
            payload,
        } => {
            lines.push(String::from("observable=io-completion"));
            lines.push(external_node_id_material("observable.node", node));
            lines.push(format!(
                "observable.kind={}",
                external_io_event_kind_label(*kind)
            ));
            lines.push(format!(
                "observable.payload_bytes={}",
                external_hex_bytes(payload)
            ));
        }
        ObservableEventPayload::NodeState { node, state } => {
            lines.push(String::from("observable=node-state"));
            lines.push(external_node_id_material("observable.node", node));
            lines.push(format!(
                "observable.state={}",
                external_node_lifecycle_label(*state)
            ));
        }
        ObservableEventPayload::AssertionStateChanged { name, state } => {
            lines.push(String::from("observable=assertion-state-changed"));
            lines.push(external_assertion_id_material("observable.assertion", name));
            lines.push(format!(
                "observable.state={}",
                external_assertion_phase_label(*state)
            ));
        }
        ObservableEventPayload::GuestMarker {
            retired_icount,
            node,
            marker,
        } => {
            lines.push(String::from("observable=guest-marker"));
            lines.push(format!(
                "observable.retired_icount={}",
                retired_icount.retired
            ));
            lines.push(external_node_id_material("observable.node", node));
            lines.push(external_marker_id_material("observable.marker", marker));
        }
        ObservableEventPayload::GuestAssertionMarker {
            retired_icount,
            node,
            marker,
        } => {
            lines.push(String::from("observable=guest-assertion-marker"));
            lines.push(format!(
                "observable.retired_icount={}",
                retired_icount.retired
            ));
            lines.push(external_node_id_material("observable.node", node));
            lines.push(external_assertion_id_material(
                "observable.marker.id",
                &marker.id,
            ));
            lines.push(external_string_material(
                "observable.marker.message",
                &marker.message,
            ));
            lines.push(format!(
                "observable.marker.kind={}",
                external_guest_assertion_kind_label(marker.kind)
            ));
            lines.push(format!("observable.marker.condition={}", marker.condition));
            lines.push(format!("observable.marker.must_hit={}", marker.must_hit));
            lines.push(format!(
                "observable.marker.details={}",
                marker.details.len()
            ));
            for (index, detail) in marker.details.iter().enumerate() {
                lines.push(format!(
                    "{}",
                    external_string_material(
                        &format!("observable.marker.detail.{index}.key"),
                        &detail.key,
                    )
                ));
                lines.push(format!(
                    "{}",
                    external_string_material(
                        &format!("observable.marker.detail.{index}.value"),
                        &detail.value,
                    )
                ));
            }
            lines.push(external_string_material(
                "observable.marker.location",
                &marker.location,
            ));
        }
    }
    lines.join("\n")
}

fn external_event_firing_material(firing: &EventFiring) -> String {
    let mut lines = Vec::new();
    lines.push(external_event_id_material("firing.event", firing.event()));
    lines.push(format!("firing.at_ticks={}", firing.at().ticks));
    lines.push(external_action_material("firing.action", firing.action()));
    lines.join("\n")
}

fn external_trigger_action_application_material(application: &TriggerActionApplication) -> String {
    let mut lines = Vec::new();
    lines.push(format!("application.sequence={}", application.sequence));
    lines.push(external_event_id_material(
        "application.event",
        &application.event,
    ));
    lines.push(format!("application.at_ticks={}", application.at.ticks));
    lines.push(format!("application.path_len={}", application.path.len()));
    for (index, path) in application.path.iter().enumerate() {
        lines.push(format!("application.path.{index}={path}"));
    }
    lines.push(external_action_material(
        "application.action",
        &application.action,
    ));
    lines.join("\n")
}

fn external_action_material(prefix: &str, action: &Action) -> String {
    let mut lines = Vec::new();
    match action {
        Action::InjectFault { tag, fault } => {
            lines.push(format!("{prefix}=inject-fault"));
            lines.push(external_fault_tag_material(&format!("{prefix}.tag"), tag));
            lines.push(external_membership_fault_material(
                &format!("{prefix}.fault"),
                fault,
            ));
        }
        Action::HealFault { tag } => {
            lines.push(format!("{prefix}=heal-fault"));
            lines.push(external_fault_tag_material(&format!("{prefix}.tag"), tag));
        }
        Action::ArmTimer { name, after } => {
            lines.push(format!("{prefix}=arm-timer"));
            lines.push(external_timer_id_material(&format!("{prefix}.timer"), name));
            lines.push(format!("{prefix}.after_nanos={}", after.nanos));
        }
        Action::CancelTimer { name } => {
            lines.push(format!("{prefix}=cancel-timer"));
            lines.push(external_timer_id_material(&format!("{prefix}.timer"), name));
        }
        Action::StartNode { node } => {
            lines.push(format!("{prefix}=start-node"));
            lines.push(external_node_id_material(&format!("{prefix}.node"), node));
        }
        Action::StopNode { node } => {
            lines.push(format!("{prefix}=stop-node"));
            lines.push(external_node_id_material(&format!("{prefix}.node"), node));
        }
        Action::CreateSavepoint { label } => {
            lines.push(format!("{prefix}=create-savepoint"));
            lines.push(external_optional_label_material(
                &format!("{prefix}.label"),
                label,
            ));
        }
        Action::Fork { label } => {
            lines.push(format!("{prefix}=fork"));
            lines.push(external_optional_label_material(
                &format!("{prefix}.label"),
                label,
            ));
        }
        Action::Pass => {
            lines.push(format!("{prefix}=pass"));
        }
        Action::Fail { reason } => {
            lines.push(format!("{prefix}=fail"));
            lines.push(external_string_material(
                &format!("{prefix}.reason"),
                reason,
            ));
        }
        Action::Log { level, message } => {
            lines.push(format!("{prefix}=log"));
            lines.push(format!(
                "{prefix}.level={}",
                external_log_level_label(*level)
            ));
            lines.push(external_string_material(
                &format!("{prefix}.message"),
                message,
            ));
        }
        Action::Group(actions) => {
            lines.push(format!("{prefix}=group"));
            lines.push(format!("{prefix}.actions={}", actions.len()));
            for (index, action) in actions.iter().enumerate() {
                lines.push(external_action_material(
                    &format!("{prefix}.action.{index}"),
                    action,
                ));
            }
        }
    }
    lines.join("\n")
}

fn external_membership_fault_material(prefix: &str, fault: &MembershipFault) -> String {
    let mut lines = Vec::new();
    match fault {
        MembershipFault::Crash { node, restart } => {
            lines.push(format!("{prefix}=crash"));
            lines.push(external_node_id_material(&format!("{prefix}.node"), node));
            lines.push(format!(
                "{prefix}.restart={}",
                external_restart_policy_label(*restart)
            ));
        }
        MembershipFault::Partition {
            endpoint_a,
            endpoint_b,
            direction,
        } => {
            lines.push(format!("{prefix}=partition"));
            lines.push(external_node_id_material(
                &format!("{prefix}.endpoint_a"),
                endpoint_a,
            ));
            lines.push(external_node_id_material(
                &format!("{prefix}.endpoint_b"),
                endpoint_b,
            ));
            lines.push(format!(
                "{prefix}.direction={}",
                external_partition_direction_label(*direction)
            ));
        }
        MembershipFault::Isolate { node } => {
            lines.push(format!("{prefix}=isolate"));
            lines.push(external_node_id_material(&format!("{prefix}.node"), node));
        }
        MembershipFault::NotYetJoined { node } => {
            lines.push(format!("{prefix}=not-yet-joined"));
            lines.push(external_node_id_material(&format!("{prefix}.node"), node));
        }
        MembershipFault::Taxonomy { fault } => {
            lines.push(format!("{prefix}=taxonomy"));
            lines.push(external_string_material(
                &format!("{prefix}.taxonomy_material"),
                &fault.canonical_material(),
            ));
        }
    }
    lines.join("\n")
}

fn external_control_fault_action_material(prefix: &str, action: &ControlFaultAction) -> String {
    let mut lines = Vec::new();
    match action {
        ControlFaultAction::Inject { tag, fault } => {
            lines.push(format!("{prefix}=inject-fault"));
            lines.push(external_fault_tag_material(&format!("{prefix}.tag"), tag));
            lines.push(external_string_material(
                &format!("{prefix}.fault_material"),
                &fault.canonical_material(),
            ));
        }
        ControlFaultAction::Heal { tag } => {
            lines.push(format!("{prefix}=heal-fault"));
            lines.push(external_fault_tag_material(&format!("{prefix}.tag"), tag));
        }
    }
    lines.join("\n")
}

fn external_control_operation_kind_material(prefix: &str, kind: &ControlOperationKind) -> String {
    let mut lines = Vec::new();
    match kind {
        ControlOperationKind::Pause => lines.push(format!("{prefix}=pause")),
        ControlOperationKind::Resume => lines.push(format!("{prefix}=resume")),
        ControlOperationKind::Step => lines.push(format!("{prefix}=step")),
        ControlOperationKind::Snapshot => lines.push(format!("{prefix}=snapshot")),
        ControlOperationKind::Fork => lines.push(format!("{prefix}=fork")),
        ControlOperationKind::Inject => lines.push(format!("{prefix}=inject")),
        ControlOperationKind::Query => lines.push(format!("{prefix}=query")),
        ControlOperationKind::InjectFault { tag, fault } => {
            lines.push(format!("{prefix}=inject-fault"));
            lines.push(external_fault_tag_material(&format!("{prefix}.tag"), tag));
            lines.push(external_string_material(
                &format!("{prefix}.fault_material"),
                &fault.canonical_material(),
            ));
        }
        ControlOperationKind::HealFault { tag } => {
            lines.push(format!("{prefix}=heal-fault"));
            lines.push(external_fault_tag_material(&format!("{prefix}.tag"), tag));
        }
    }
    lines.join("\n")
}

fn external_event_key_material(prefix: &str, key: &EventKey) -> String {
    let mut lines = Vec::new();
    lines.push(format!("{prefix}.time_ticks={}", key.virtual_time.ticks));
    lines.push(external_scheduler_node_material(
        &format!("{prefix}.consumer"),
        &key.consumer,
    ));
    lines.push(external_scheduler_node_material(
        &format!("{prefix}.producer"),
        &key.producer,
    ));
    lines.push(format!("{prefix}.sequence={}", key.sequence));
    lines.join("\n")
}

fn external_scheduler_node_material(prefix: &str, node: &SchedulerNodeId) -> String {
    format!(
        "{}\n{prefix}.kind={}",
        external_node_id_material(&format!("{prefix}.node"), &node.node),
        external_scheduling_node_kind_label(node.kind)
    )
}

fn external_node_id_material(prefix: &str, node: &NodeId) -> String {
    external_string_material(prefix, &node.name)
}

fn external_event_id_material(prefix: &str, id: &EventId) -> String {
    external_string_material(prefix, &id.name)
}

fn external_assertion_id_material(prefix: &str, id: &AssertionId) -> String {
    external_string_material(prefix, &id.name)
}

fn external_marker_id_material(prefix: &str, id: &MarkerId) -> String {
    external_string_material(prefix, &id.name)
}

fn external_fault_id_material(prefix: &str, id: &FaultId) -> String {
    external_string_material(prefix, &id.name)
}

fn external_fault_tag_material(prefix: &str, tag: &FaultTag) -> String {
    external_string_material(prefix, &tag.name)
}

fn external_timer_id_material(prefix: &str, id: &TimerId) -> String {
    external_string_material(prefix, &id.name)
}

fn external_rng_stream_material(prefix: &str, stream: &RngStreamId) -> String {
    format!(
        "{}\n{}",
        external_string_material(&format!("{prefix}.domain"), &stream.domain),
        external_string_material(&format!("{prefix}.name"), &stream.name)
    )
}

fn external_optional_label_material(prefix: &str, label: &Option<String>) -> String {
    match label {
        Some(label) => format!(
            "{prefix}.present=true\n{}",
            external_string_material(prefix, label)
        ),
        None => format!("{prefix}.present=false"),
    }
}

fn external_optional_link_material(prefix: &str, link: &Option<LinkId>) -> String {
    match link {
        Some(link) => format!(
            "{prefix}.present=true\n{}",
            external_link_id_material(prefix, link)
        ),
        None => format!("{prefix}.present=false"),
    }
}

fn external_link_id_material(prefix: &str, id: &LinkId) -> String {
    external_string_material(prefix, &id.name)
}

fn external_resolved_mem_place_material(prefix: &str, place: &ResolvedMemPlace) -> String {
    match place {
        ResolvedMemPlace::PhysicalAddress { address, bytes } => {
            format!("{prefix}=physical-address\n{prefix}.address={address}\n{prefix}.bytes={bytes}")
        }
        ResolvedMemPlace::VirtualAddress { address, bytes } => {
            format!("{prefix}=virtual-address\n{prefix}.address={address}\n{prefix}.bytes={bytes}")
        }
        ResolvedMemPlace::Register { name, bytes } => format!(
            "{prefix}=register\n{}\n{prefix}.bytes={bytes}",
            external_string_material(&format!("{prefix}.name"), name)
        ),
    }
}

fn external_string_material(prefix: &str, value: &str) -> String {
    format!(
        "{prefix}.bytes_len={}\n{prefix}.bytes={}",
        value.len(),
        external_hex_bytes(value.as_bytes())
    )
}

fn external_preemption_kind_material(prefix: &str, kind: &PreemptionKind) -> String {
    match kind {
        PreemptionKind::VcpuSwitch { from_vcpu, to_vcpu } => format!(
            "{prefix}=vcpu-switch\n{prefix}.from_vcpu={}\n{prefix}.to_vcpu={}",
            from_vcpu.index, to_vcpu.index
        ),
        PreemptionKind::InterruptAt { target_vcpu, irq } => format!(
            "{prefix}=interrupt-at\n{prefix}.target_vcpu={}\n{prefix}.irq={}",
            target_vcpu.index, irq.vector
        ),
    }
}

fn external_scheduler_evaluation_boundary_kind_label(
    kind: SchedulerEvaluationBoundaryKind,
) -> &'static str {
    match kind {
        SchedulerEvaluationBoundaryKind::Quantum => "quantum",
        SchedulerEvaluationBoundaryKind::Rendezvous => "rendezvous",
    }
}

fn external_scheduled_event_resolve_class_label(class: ScheduledEventResolveClass) -> &'static str {
    match class {
        ScheduledEventResolveClass::FrameDelivery => "frame-delivery",
        ScheduledEventResolveClass::IoCompletion => "io-completion",
        ScheduledEventResolveClass::FaultActivation => "fault-activation",
        ScheduledEventResolveClass::ProbabilisticFault => "probabilistic-fault",
        ScheduledEventResolveClass::Control => "control",
    }
}

fn external_scheduling_node_kind_label(kind: SchedulingNodeKind) -> &'static str {
    match kind {
        SchedulingNodeKind::Vm => "vm",
        SchedulingNodeKind::Disk => "disk",
        SchedulingNodeKind::NineP => "9p",
        SchedulingNodeKind::Network => "network",
        SchedulingNodeKind::ControlPlane => "control-plane",
    }
}

fn external_io_event_kind_label(kind: IoEventKind) -> &'static str {
    match kind {
        IoEventKind::Any => "any",
        IoEventKind::BlockRead => "block-read",
        IoEventKind::BlockWrite => "block-write",
        IoEventKind::Fsync => "fsync",
        IoEventKind::NineP => "9p",
        IoEventKind::Network => "network",
    }
}

fn external_node_lifecycle_label(state: NodeLifecycle) -> &'static str {
    match state {
        NodeLifecycle::Started => "started",
        NodeLifecycle::Crashed => "crashed",
        NodeLifecycle::Exited => "exited",
    }
}

fn external_assertion_phase_label(phase: AssertionPhase) -> &'static str {
    match phase {
        AssertionPhase::Satisfied => "satisfied",
        AssertionPhase::Violated => "violated",
    }
}

fn external_guest_assertion_kind_label(kind: GuestAssertionKind) -> &'static str {
    match kind {
        GuestAssertionKind::Always => "always",
        GuestAssertionKind::Sometimes => "sometimes",
        GuestAssertionKind::Reachable => "reachable",
        GuestAssertionKind::Unreachable => "unreachable",
    }
}

fn external_restart_policy_label(policy: RestartPolicy) -> &'static str {
    match policy {
        RestartPolicy::FromReadyPoint => "from-ready-point",
        RestartPolicy::FromLastCheckpoint => "from-last-checkpoint",
        RestartPolicy::StayDown => "stay-down",
    }
}

fn external_partition_direction_label(direction: PartitionDirection) -> &'static str {
    match direction {
        PartitionDirection::Bidirectional => "bidirectional",
        PartitionDirection::EndpointAToEndpointB => "endpoint-a-to-endpoint-b",
        PartitionDirection::EndpointBToEndpointA => "endpoint-b-to-endpoint-a",
    }
}

fn external_log_level_label(level: LogLevel) -> &'static str {
    match level {
        LogLevel::Debug => "debug",
        LogLevel::Info => "info",
        LogLevel::Warn => "warn",
        LogLevel::Error => "error",
    }
}

fn external_hex_bytes(bytes: &[u8]) -> String {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    let mut encoded = String::with_capacity(bytes.len().saturating_mul(2));
    for byte in bytes {
        encoded.push(HEX[(byte >> 4) as usize] as char);
        encoded.push(HEX[(byte & 0x0f) as usize] as char);
    }
    encoded
}

fn condition_prefix_from_recorded_log(
    recorded_log: &RecordedAssertionLog,
    prefix_len: usize,
    require_recorded_offset: bool,
) -> Result<ConditionEventLogPrefix, OfflineAssertionCheckError> {
    let entries = &recorded_log.entries()[..prefix_len];
    let prefix = condition_prefix_from_recorded_entries(entries)?
        .with_prefix_offsets(recorded_log.prefix_offsets.clone());
    let prefix_len = u64::try_from(prefix_len)
        .map_err(|_| OfflineAssertionCheckError::PrefixLengthOverflow { prefix_len })?;
    let Some(offset) = recorded_log.event_log_offset(prefix_len) else {
        return if require_recorded_offset {
            Err(OfflineAssertionCheckError::MissingEventLogOffset { prefix_len })
        } else {
            Ok(prefix)
        };
    };
    if offset.events != prefix_len {
        return Err(OfflineAssertionCheckError::EventLogOffsetMismatch {
            prefix_len,
            offset_events: offset.events,
        });
    }
    Ok(prefix.with_event_log_offset(offset))
}

fn observe_guest_marker_assertions(
    states: &mut Vec<GuestMarkerAssertionState>,
    prefix: &ConditionEventLogPrefix,
    white_box_policies: &BTreeMap<NodeId, WhiteBoxPolicy>,
) -> Vec<HostAssertionOutcome> {
    let mut outcomes = Vec::new();
    let at = prefix.point().at();
    for event in prefix.observable_events() {
        if event.at() != at {
            continue;
        }
        let ObservableEventPayload::GuestAssertionMarker {
            retired_icount: _,
            node,
            marker,
        } = event.payload()
        else {
            continue;
        };
        if white_box_policies.get(node) != Some(&WhiteBoxPolicy::Enabled) {
            continue;
        }
        let state = guest_marker_assertion_state_for(states, marker);
        if state.terminal.is_some() {
            continue;
        }
        state.observe_payload(marker);
        if let Some(outcome) = observe_guest_marker_assertion_state(state, at, marker) {
            outcomes.push(outcome);
        }
    }
    outcomes
}

fn guest_marker_assertion_state_for<'a>(
    states: &'a mut Vec<GuestMarkerAssertionState>,
    marker: &GuestAssertionMarker,
) -> &'a mut GuestMarkerAssertionState {
    match states.binary_search_by(|state| state.id.cmp(&marker.id)) {
        Ok(index) => &mut states[index],
        Err(index) => {
            states.insert(index, GuestMarkerAssertionState::new(marker));
            &mut states[index]
        }
    }
}

fn observe_guest_marker_assertion_state(
    state: &mut GuestMarkerAssertionState,
    at: VirtualTime,
    marker: &GuestAssertionMarker,
) -> Option<HostAssertionOutcome> {
    if state.terminal.is_some() {
        return None;
    }

    if marker.kind != state.kind {
        return state.terminal(
            HostAssertionOutcomeKind::Violated,
            at,
            guest_marker_payload_reason(
                marker,
                &format!(
                    "guest marker assertion kind mismatch: declared {:?}, observed {:?}",
                    state.kind, marker.kind
                ),
            ),
        );
    }

    match state.kind {
        GuestAssertionKind::Always if !marker.condition => state.terminal(
            HostAssertionOutcomeKind::Violated,
            at,
            guest_marker_payload_reason(marker, "guest always marker condition was false"),
        ),
        GuestAssertionKind::Sometimes if marker.condition => state.terminal(
            HostAssertionOutcomeKind::Satisfied,
            at,
            guest_marker_payload_reason(marker, "guest sometimes marker became true"),
        ),
        GuestAssertionKind::Reachable if marker.condition => state.terminal(
            HostAssertionOutcomeKind::Satisfied,
            at,
            guest_marker_payload_reason(marker, "guest reachable marker was reached"),
        ),
        GuestAssertionKind::Unreachable if marker.condition => state.terminal(
            HostAssertionOutcomeKind::Violated,
            at,
            guest_marker_payload_reason(marker, "guest unreachable marker was reached"),
        ),
        GuestAssertionKind::Always
        | GuestAssertionKind::Sometimes
        | GuestAssertionKind::Reachable
        | GuestAssertionKind::Unreachable => None,
    }
}

fn finalize_guest_marker_assertion_state(
    state: &mut GuestMarkerAssertionState,
    at: VirtualTime,
) -> Option<HostAssertionOutcome> {
    if state.terminal.is_some() {
        return None;
    }

    match state.kind {
        GuestAssertionKind::Always => state.terminal(
            HostAssertionOutcomeKind::Satisfied,
            at,
            guest_marker_reason(state, "guest always marker stayed true"),
        ),
        GuestAssertionKind::Sometimes => state.terminal(
            HostAssertionOutcomeKind::Violated,
            at,
            guest_marker_reason(state, "guest sometimes marker never became true"),
        ),
        GuestAssertionKind::Reachable if state.observed_true => state.terminal(
            HostAssertionOutcomeKind::Satisfied,
            at,
            guest_marker_reason(state, "guest reachable marker was reached"),
        ),
        GuestAssertionKind::Reachable if state.must_hit => state.terminal(
            HostAssertionOutcomeKind::NeverReachedFail,
            at,
            guest_marker_reason(state, "guest reachable marker was never reached"),
        ),
        GuestAssertionKind::Reachable => state.terminal(
            HostAssertionOutcomeKind::NeverReachedWarn,
            at,
            guest_marker_reason(state, "guest reachable marker was never reached"),
        ),
        GuestAssertionKind::Unreachable => state.terminal(
            HostAssertionOutcomeKind::Satisfied,
            at,
            guest_marker_reason(state, "guest unreachable marker stayed unreached"),
        ),
    }
}

fn guest_marker_reason(state: &GuestMarkerAssertionState, summary: &str) -> String {
    let details = details_reason(&state.details);
    format!("{summary}; location={}; details={details}", state.location)
}

fn guest_marker_payload_reason(marker: &GuestAssertionMarker, summary: &str) -> String {
    let details = details_reason(&marker.details);
    format!("{summary}; location={}; details={details}", marker.location)
}

fn details_reason(details: &[GuestAssertionDetail]) -> String {
    details
        .iter()
        .map(|detail| format!("{}={}", detail.key, detail.value))
        .collect::<Vec<_>>()
        .join(",")
}

fn sort_host_assertion_outcomes(outcomes: &mut [HostAssertionOutcome]) {
    outcomes.sort_by(|left, right| {
        left.assertion
            .cmp(&right.assertion)
            .then_with(|| left.at.cmp(&right.at))
            .then_with(|| {
                host_assertion_outcome_kind_rank(left.kind)
                    .cmp(&host_assertion_outcome_kind_rank(right.kind))
            })
            .then_with(|| left.reason.cmp(&right.reason))
    });
}

fn host_assertion_outcome_kind_rank(kind: HostAssertionOutcomeKind) -> u8 {
    match kind {
        HostAssertionOutcomeKind::Satisfied => 0,
        HostAssertionOutcomeKind::Warning => 1,
        HostAssertionOutcomeKind::NeverEvaluated => 2,
        HostAssertionOutcomeKind::NeverTriggered => 3,
        HostAssertionOutcomeKind::NeverReachedWarn => 4,
        HostAssertionOutcomeKind::NeverReachedFail => 5,
        HostAssertionOutcomeKind::Violated => 6,
    }
}

fn host_assertion_outcome_fails_run(kind: HostAssertionOutcomeKind) -> bool {
    matches!(
        kind,
        HostAssertionOutcomeKind::Violated | HostAssertionOutcomeKind::NeverReachedFail
    )
}

struct HostConditionEvaluation<'prefix, 'state, O: ?Sized> {
    observed: ObservedState<'prefix>,
    oracle: &'state mut O,
    once_latches: &'state mut Vec<Condition>,
    leaf_cache: &'state mut HostConditionEvaluationCache,
    white_box_policies: &'state BTreeMap<NodeId, WhiteBoxPolicy>,
}

type HostConditionEvaluationCache = BTreeMap<HostConditionLeafKey, bool>;

#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord)]
enum HostConditionLeafKey {
    Named { name: String, nodes: Vec<NodeId> },
    GuestMarker { marker: MarkerId },
}

impl HostConditionLeafKey {
    fn from_leaf(leaf: ConditionLeaf<'_>) -> Self {
        match leaf {
            ConditionLeaf::Named { name, nodes } => Self::Named {
                name: name.to_owned(),
                nodes: nodes.to_vec(),
            },
            ConditionLeaf::GuestMarker { marker } => Self::GuestMarker {
                marker: marker.clone(),
            },
        }
    }
}

impl<O> condition_evaluator_sealed::Sealed for HostConditionEvaluation<'_, '_, O> where
    O: HostAssertionOracle + ?Sized
{
}

impl<O> ConditionEvaluator for HostConditionEvaluation<'_, '_, O>
where
    O: HostAssertionOracle + ?Sized,
{
    fn evaluation_point(&self) -> EventEvaluationPoint {
        self.observed.point()
    }

    fn event_log_offset(&self) -> EventLogOffset {
        self.observed.event_log_offset()
    }

    fn leaf_is_true(&mut self, leaf: ConditionLeaf<'_>) -> bool {
        let key = HostConditionLeafKey::from_leaf(leaf);
        if let Some(value) = self.leaf_cache.get(&key).copied() {
            return value;
        }
        let value = HostAssertionOracle::leaf_is_true(self.oracle, self.observed, leaf);
        self.leaf_cache.insert(key, value);
        value
    }

    fn observable_events(&self) -> &[ObservableEvent] {
        self.observed.observable_events()
    }

    fn white_box_policy_for_node(&self, node: &NodeId) -> Option<WhiteBoxPolicy> {
        self.white_box_policies.get(node).copied()
    }

    fn once_condition_is_latched(&self, condition: &Condition) -> bool {
        self.once_latches.iter().any(|latched| latched == condition)
    }

    fn latch_once_condition(&mut self, condition: &Condition) {
        if !self.once_condition_is_latched(condition) {
            self.once_latches.push(condition.clone());
        }
    }
}

fn host_condition_is_true<O>(
    prefix: &ConditionEventLogPrefix,
    condition: &Condition,
    oracle: &mut O,
    once_latches: &mut Vec<Condition>,
    white_box_policies: &BTreeMap<NodeId, WhiteBoxPolicy>,
) -> bool
where
    O: HostAssertionOracle + ?Sized,
{
    let mut leaf_cache = HostConditionEvaluationCache::new();
    host_condition_is_true_with_cache(
        prefix,
        condition,
        oracle,
        once_latches,
        &mut leaf_cache,
        white_box_policies,
    )
}

fn host_condition_is_true_with_cache<O>(
    prefix: &ConditionEventLogPrefix,
    condition: &Condition,
    oracle: &mut O,
    once_latches: &mut Vec<Condition>,
    leaf_cache: &mut HostConditionEvaluationCache,
    white_box_policies: &BTreeMap<NodeId, WhiteBoxPolicy>,
) -> bool
where
    O: HostAssertionOracle + ?Sized,
{
    let mut evaluator = HostConditionEvaluation {
        observed: prefix.observed_state(),
        oracle,
        once_latches,
        leaf_cache,
        white_box_policies,
    };
    evaluate_condition(&mut evaluator, condition)
}

fn push_observed_state_facts(
    entry: &SchedulerEventLogEntry,
    observable_events: &mut Vec<ObservableEvent>,
    ordering_facts: &mut Vec<ObservedOrderingFact>,
    fault_facts: &mut Vec<ObservedFaultFact>,
) {
    match entry.payload() {
        SchedulerEventLogPayload::Observable(payload) => {
            observable_events.push(ObservableEvent {
                at: entry.at(),
                payload: payload.clone(),
            });
        }
        SchedulerEventLogPayload::ResolvedHappening(event) => {
            push_resolved_happening_observed_facts(
                entry.sequence(),
                entry.at(),
                event,
                ordering_facts,
                fault_facts,
            );
        }
        SchedulerEventLogPayload::Decision(Decision::DeliveryOrder(order)) => {
            ordering_facts.push(ObservedOrderingFact::DeliveryOrder {
                sequence: entry.sequence(),
                at: entry.at(),
                order: order.order.clone(),
            });
        }
        SchedulerEventLogPayload::Decision(Decision::FaultFires(fault)) => {
            fault_facts.push(ObservedFaultFact::ProbabilisticOutcome {
                sequence: entry.sequence(),
                at: entry.at(),
                fault: fault.fault.clone(),
                fired: fault.fired,
            });
        }
        SchedulerEventLogPayload::Decision(Decision::ControlFault(control)) => {
            push_control_fault_fact(
                entry.sequence(),
                entry.at(),
                control.sequence,
                &control.action,
                fault_facts,
            );
        }
        SchedulerEventLogPayload::TriggerActionApplied(application) => {
            push_trigger_fault_fact(entry.sequence(), entry.at(), application, fault_facts);
        }
        SchedulerEventLogPayload::Decision(
            Decision::RngDraw(_)
            | Decision::Override(_)
            | Decision::Preemption(_)
            | Decision::AppRandom(_),
        )
        | SchedulerEventLogPayload::EvaluationBoundary(_)
        | SchedulerEventLogPayload::TriggerFired(_) => {}
    }
}

fn push_resolved_happening_observed_facts(
    sequence: u64,
    at: VirtualTime,
    event: &ScheduledEvent,
    ordering_facts: &mut Vec<ObservedOrderingFact>,
    fault_facts: &mut Vec<ObservedFaultFact>,
) {
    ordering_facts.push(ObservedOrderingFact::ResolvedHappening {
        sequence,
        at,
        key: event.key.clone(),
        class: scheduled_event_resolve_class(event),
    });
    match &event.payload {
        ScheduledEventPayload::FaultActivation(fault) => {
            fault_facts.push(ObservedFaultFact::ScheduledActivation {
                sequence,
                at,
                fault: fault.clone(),
            });
        }
        ScheduledEventPayload::ProbabilisticFault(choice) => {
            fault_facts.push(ObservedFaultFact::ScheduledProbabilisticChoice {
                sequence,
                at,
                fault: choice.fault.clone(),
            });
        }
        ScheduledEventPayload::BackendInput(_)
        | ScheduledEventPayload::IoCompletion(_)
        | ScheduledEventPayload::Control(_) => {}
    }
}

fn push_control_fault_fact(
    sequence: u64,
    at: VirtualTime,
    control_sequence: u64,
    action: &ControlFaultAction,
    fault_facts: &mut Vec<ObservedFaultFact>,
) {
    match action {
        ControlFaultAction::Inject { tag, fault } => {
            fault_facts.push(ObservedFaultFact::ControlInjected {
                sequence,
                at,
                control_sequence,
                tag: tag.clone(),
                fault: fault.clone(),
            });
        }
        ControlFaultAction::Heal { tag } => {
            fault_facts.push(ObservedFaultFact::ControlHealed {
                sequence,
                at,
                control_sequence,
                tag: tag.clone(),
            });
        }
    }
}

fn push_trigger_fault_fact(
    sequence: u64,
    at: VirtualTime,
    application: &crate::scheduler::TriggerActionApplication,
    fault_facts: &mut Vec<ObservedFaultFact>,
) {
    match &application.action {
        Action::InjectFault { tag, fault } => {
            fault_facts.push(ObservedFaultFact::TriggerInjected {
                sequence,
                at,
                trigger_sequence: application.sequence,
                event: application.event.clone(),
                tag: tag.clone(),
                fault: fault.clone(),
            });
        }
        Action::HealFault { tag } => {
            fault_facts.push(ObservedFaultFact::TriggerHealed {
                sequence,
                at,
                trigger_sequence: application.sequence,
                event: application.event.clone(),
                tag: tag.clone(),
            });
        }
        Action::ArmTimer { .. }
        | Action::CancelTimer { .. }
        | Action::StartNode { .. }
        | Action::StopNode { .. }
        | Action::CreateSavepoint { .. }
        | Action::Fork { .. }
        | Action::Pass
        | Action::Fail { .. }
        | Action::Log { .. }
        | Action::Group(_) => {}
    }
}

/// Evaluates a condition through the shared assertion/trigger evaluator.
///
/// The recursive structure lives in this non-overridable function. Implementors
/// of [`ConditionEvaluator`] provide leaf truth, deterministic observation
/// sources, and `Once` latch storage at a deterministic evaluation point, so
/// assertion and trigger consumers cannot diverge on compound predicate
/// traversal.
pub(crate) fn evaluate_condition<E>(evaluator: &mut E, condition: &Condition) -> bool
where
    E: ConditionEvaluator + ?Sized,
{
    match condition {
        Condition::At { at } => evaluator.evaluation_point().at() == *at,
        Condition::After { duration, of } => evaluator
            .last_event_firing(of)
            .and_then(|fired_at| fired_at.ticks.checked_add(duration.nanos))
            .is_some_and(|fire_at| fire_at == evaluator.evaluation_point().at().ticks),
        Condition::Timer { name } => evaluator
            .timer_fire_time(name)
            .is_some_and(|fire_at| fire_at == evaluator.evaluation_point().at()),
        Condition::NetworkMatch { link, predicate } => observable_event_matches(
            evaluator.evaluation_point().at(),
            evaluator.observable_events(),
            |event| network_event_matches(event, link.as_ref(), predicate),
        ),
        Condition::ConsoleMatch { node, regex } => console_stream_matches(
            evaluator.evaluation_point().at(),
            evaluator.observable_events(),
            node,
            regex,
        ),
        Condition::CoveragePoint { node, point } => coverage_point_matches(evaluator, node, point),
        Condition::MemoryPredicate {
            node,
            place,
            cmp,
            value,
        } => memory_predicate_matches(evaluator, node, place, *cmp, *value),
        Condition::IoPattern { node, kind } => observable_event_matches(
            evaluator.evaluation_point().at(),
            evaluator.observable_events(),
            |event| io_event_matches(event, node, *kind),
        ),
        Condition::NodeState { node, state } => observable_event_matches(
            evaluator.evaluation_point().at(),
            evaluator.observable_events(),
            |event| node_state_event_matches(event, node, *state),
        ),
        Condition::AssertionState { name, state } => observable_event_matches(
            evaluator.evaluation_point().at(),
            evaluator.observable_events(),
            |event| assertion_state_event_matches(event, name, *state),
        ),
        Condition::Quiescent => evaluator
            .scheduler_quiescence()
            .is_some_and(SchedulerQuiescence::is_quiescent),
        Condition::Named { name, nodes } => evaluator.leaf_is_true(ConditionLeaf::Named {
            name: name.as_str(),
            nodes,
        }),
        Condition::GuestMarker { marker } => guest_marker_matches(evaluator, marker),
        Condition::AllOf { predicates } => {
            let mut all_true = true;
            for condition in predicates {
                all_true &= evaluate_condition(evaluator, condition);
            }
            all_true
        }
        Condition::AnyOf { predicates } => {
            let mut any_true = false;
            for condition in predicates {
                any_true |= evaluate_condition(evaluator, condition);
            }
            any_true
        }
        Condition::Once { predicate } => {
            if evaluator.once_condition_is_latched(predicate) {
                true
            } else if evaluate_condition(evaluator, predicate) {
                evaluator.latch_once_condition(predicate);
                true
            } else {
                false
            }
        }
        Condition::Not { predicate } => !evaluate_condition(evaluator, predicate),
    }
}

fn observable_event_matches(
    at: VirtualTime,
    events: &[ObservableEvent],
    matches_payload: impl Fn(&ObservableEventPayload) -> bool,
) -> bool {
    events
        .iter()
        .any(|event| event.at() == at && matches_payload(event.payload()))
}

fn network_event_matches(
    event: &ObservableEventPayload,
    expected_link: Option<&LinkId>,
    predicate: &FramePredicate,
) -> bool {
    let ObservableEventPayload::NetworkDelivered { link, payload } = event else {
        return false;
    };
    let link_matches = expected_link.is_none_or(|expected| link.as_ref() == Some(expected));
    link_matches && frame_predicate_matches(predicate, payload)
}

fn frame_predicate_matches(predicate: &FramePredicate, payload: &[u8]) -> bool {
    match predicate {
        FramePredicate::Any => true,
        FramePredicate::Exact(expected) => payload == expected,
        FramePredicate::Contains(needle) => {
            needle.is_empty()
                || payload
                    .windows(needle.len())
                    .any(|window| window == needle.as_slice())
        }
        FramePredicate::Prefix(prefix) => payload.starts_with(prefix),
    }
}

fn console_stream_matches(
    at: VirtualTime,
    events: &[ObservableEvent],
    expected_node: &NodeId,
    regex: &RegexProgram,
) -> bool {
    let Ok(program) = regex::bytes::Regex::new(&regex.pattern) else {
        return false;
    };
    let mut stream = Vec::new();
    let mut current_start = None;
    for event in events {
        let ObservableEventPayload::ConsoleOutput { node, bytes } = event.payload() else {
            continue;
        };
        if node != expected_node {
            continue;
        }
        if event.at() < at {
            stream.extend_from_slice(bytes);
        } else if event.at() == at {
            current_start.get_or_insert(stream.len());
            stream.extend_from_slice(bytes);
        }
    }
    let Some(current_start) = current_start else {
        return false;
    };
    program
        .find_iter(&stream)
        .any(|matched| matched.end() > current_start)
}

fn coverage_point_matches<E>(evaluator: &E, expected_node: &NodeId, point: &CodePoint) -> bool
where
    E: ConditionEvaluator + ?Sized,
{
    let Some(resolved) = evaluator.resolve_code_point(expected_node, point) else {
        return false;
    };
    let at = evaluator.evaluation_point().at();
    let events = evaluator.observable_events();
    let matches_current = events.iter().any(|event| {
        event.at() == at && coverage_event_matches(event.payload(), expected_node, resolved)
    });
    let seen_before = events.iter().any(|event| {
        event.at() < at && coverage_event_matches(event.payload(), expected_node, resolved)
    });
    matches_current && !seen_before
}

fn coverage_event_matches(
    event: &ObservableEventPayload,
    expected_node: &NodeId,
    expected_point: ResolvedCodePoint,
) -> bool {
    let ObservableEventPayload::CoverageBlock {
        execution_icount: _,
        node,
        guest_pc,
        block_len,
    } = event
    else {
        return false;
    };
    node == expected_node && block_contains_address(*guest_pc, *block_len, expected_point.address())
}

fn block_contains_address(guest_pc: u64, block_len: u32, address: u64) -> bool {
    let Some(end) = guest_pc.checked_add(u64::from(block_len)) else {
        return false;
    };
    guest_pc <= address && address < end
}

fn memory_predicate_matches<E>(
    evaluator: &E,
    expected_node: &NodeId,
    place: &MemPlace,
    cmp: MemoryCmp,
    expected_value: u64,
) -> bool
where
    E: ConditionEvaluator + ?Sized,
{
    let Some(resolved) = evaluator.resolve_mem_place(expected_node, place) else {
        return false;
    };
    observable_event_matches(
        evaluator.evaluation_point().at(),
        evaluator.observable_events(),
        |event| memory_event_matches(event, expected_node, &resolved, cmp, expected_value),
    )
}

fn memory_event_matches(
    event: &ObservableEventPayload,
    expected_node: &NodeId,
    expected_place: &ResolvedMemPlace,
    cmp: MemoryCmp,
    expected_value: u64,
) -> bool {
    let ObservableEventPayload::MemorySample {
        sample_icount: _,
        node,
        place,
        value,
    } = event
    else {
        return false;
    };
    node == expected_node
        && place == expected_place
        && memory_cmp_matches(cmp, *value, expected_value)
}

fn memory_cmp_matches(cmp: MemoryCmp, actual: u64, expected: u64) -> bool {
    match cmp {
        MemoryCmp::Eq => actual == expected,
        MemoryCmp::Ne => actual != expected,
        MemoryCmp::Lt => actual < expected,
        MemoryCmp::Le => actual <= expected,
        MemoryCmp::Gt => actual > expected,
        MemoryCmp::Ge => actual >= expected,
    }
}

fn io_event_matches(
    event: &ObservableEventPayload,
    expected_node: &NodeId,
    expected_kind: IoEventKind,
) -> bool {
    let ObservableEventPayload::IoCompletion { node, kind, .. } = event else {
        return false;
    };
    node == expected_node && (expected_kind == IoEventKind::Any || expected_kind == *kind)
}

fn node_state_event_matches(
    event: &ObservableEventPayload,
    expected_node: &NodeId,
    expected_state: NodeLifecycle,
) -> bool {
    let ObservableEventPayload::NodeState { node, state } = event else {
        return false;
    };
    node == expected_node && *state == expected_state
}

fn assertion_state_event_matches(
    event: &ObservableEventPayload,
    expected_name: &AssertionId,
    expected_state: AssertionPhase,
) -> bool {
    let ObservableEventPayload::AssertionStateChanged { name, state } = event else {
        return false;
    };
    name == expected_name && *state == expected_state
}

fn guest_marker_matches<E>(evaluator: &E, expected_marker: &MarkerId) -> bool
where
    E: ConditionEvaluator + ?Sized,
{
    observable_event_matches(
        evaluator.evaluation_point().at(),
        evaluator.observable_events(),
        |event| guest_marker_event_matches(evaluator, event, expected_marker),
    )
}

fn guest_marker_event_matches<E>(
    evaluator: &E,
    event: &ObservableEventPayload,
    expected_marker: &MarkerId,
) -> bool
where
    E: ConditionEvaluator + ?Sized,
{
    match event {
        ObservableEventPayload::GuestMarker {
            retired_icount: _,
            node,
            marker,
        } => {
            marker == expected_marker
                && evaluator.white_box_policy_for_node(node) == Some(WhiteBoxPolicy::Enabled)
        }
        ObservableEventPayload::GuestAssertionMarker { .. } => false,
        ObservableEventPayload::NetworkDelivered { .. }
        | ObservableEventPayload::ConsoleOutput { .. }
        | ObservableEventPayload::CoverageBlock { .. }
        | ObservableEventPayload::MemorySample { .. }
        | ObservableEventPayload::IoCompletion { .. }
        | ObservableEventPayload::NodeState { .. }
        | ObservableEventPayload::AssertionStateChanged { .. } => false,
    }
}

/// Condition evaluator backed by a leaf oracle.
#[derive(Clone, Debug)]
pub struct ConditionEvaluation<O> {
    point: EventEvaluationPoint,
    event_log_offset: EventLogOffset,
    oracle: O,
    event_firings: BTreeMap<EventId, VirtualTime>,
    timer_fires: BTreeMap<TimerId, VirtualTime>,
    observable_events: Vec<ObservableEvent>,
    ordering_facts: Vec<ObservedOrderingFact>,
    fault_facts: Vec<ObservedFaultFact>,
    scheduler_quiescence: Option<SchedulerQuiescence>,
    white_box_policies: BTreeMap<NodeId, WhiteBoxPolicy>,
    once_latches: Vec<Condition>,
    code_points: BTreeMap<(NodeId, CodePoint), ResolvedCodePoint>,
    mem_places: BTreeMap<(NodeId, MemPlace), ResolvedMemPlace>,
}

impl<O> ConditionEvaluation<O> {
    /// Builds a condition evaluator for one deterministic event-log prefix.
    #[must_use]
    pub fn from_log_prefix(prefix: ConditionEventLogPrefix, oracle: O) -> Self {
        Self {
            point: prefix.point,
            event_log_offset: prefix.event_log_offset,
            oracle,
            event_firings: BTreeMap::new(),
            timer_fires: BTreeMap::new(),
            observable_events: prefix.observable_events,
            ordering_facts: prefix.ordering_facts,
            fault_facts: prefix.fault_facts,
            scheduler_quiescence: None,
            white_box_policies: BTreeMap::new(),
            once_latches: Vec::new(),
            code_points: BTreeMap::new(),
            mem_places: BTreeMap::new(),
        }
    }

    /// Returns the deterministic point where this evaluator observes the log.
    #[must_use]
    pub fn point(&self) -> EventEvaluationPoint {
        self.point
    }

    /// Returns the event-log prefix identity visible to this evaluator.
    #[must_use]
    pub fn event_log_offset(&self) -> EventLogOffset {
        self.event_log_offset
    }

    /// Returns the read-only observed-state view for this evaluation pass.
    #[must_use]
    pub fn observed_state(&self) -> ObservedState<'_> {
        ObservedState {
            point: self.point,
            event_log_offset: self.event_log_offset,
            observable_events: &self.observable_events,
            ordering_facts: &self.ordering_facts,
            fault_facts: &self.fault_facts,
        }
    }

    /// Adds event firing history visible to `After` predicates.
    #[must_use]
    pub fn with_event_firings(mut self, event_firings: BTreeMap<EventId, VirtualTime>) -> Self {
        self.event_firings = event_firings;
        self
    }

    /// Adds timer fire times visible to `Timer` predicates.
    #[must_use]
    pub fn with_timer_fires(mut self, timer_fires: BTreeMap<TimerId, VirtualTime>) -> Self {
        self.timer_fires = timer_fires;
        self
    }

    /// Adds scheduler-owned quiescence evidence visible to `Quiescent` leaves.
    #[must_use]
    pub fn with_scheduler_quiescence(mut self, quiescence: SchedulerQuiescence) -> Self {
        self.scheduler_quiescence = Some(quiescence);
        self
    }

    /// Adds authoritative white-box opt-in policies for guest-marker leaves.
    #[must_use]
    pub fn with_white_box_policies(
        mut self,
        policies: impl IntoIterator<Item = (NodeId, WhiteBoxPolicy)>,
    ) -> Self {
        self.white_box_policies = policies.into_iter().collect();
        self
    }

    /// Adds authoritative white-box opt-in policies from a world definition.
    #[must_use]
    pub fn with_world_white_box_policies(self, world: &World) -> Self {
        self.with_white_box_policies(
            world
                .nodes()
                .iter()
                .map(|node| (node.id.clone(), node.white_box)),
        )
    }

    /// Adds host-side code point resolutions visible to coverage leaves.
    #[must_use]
    pub fn with_resolved_code_points(
        mut self,
        code_points: impl IntoIterator<Item = ((NodeId, CodePoint), ResolvedCodePoint)>,
    ) -> Self {
        self.code_points = code_points.into_iter().collect();
        self
    }

    /// Adds host-side memory place resolutions visible to memory predicates.
    #[must_use]
    pub fn with_resolved_mem_places(
        mut self,
        mem_places: impl IntoIterator<Item = ((NodeId, MemPlace), ResolvedMemPlace)>,
    ) -> Self {
        self.mem_places = mem_places.into_iter().collect();
        self
    }

    /// Evaluates a condition through the shared evaluator function.
    pub(crate) fn evaluate_condition(&mut self, condition: &Condition) -> bool
    where
        O: ConditionLeafOracle,
    {
        evaluate_condition(self, condition)
    }
}

/// Shared assertion/trigger condition-evaluation pass for one log prefix.
#[derive(Clone, Debug)]
pub struct ConditionEvaluationPass<O> {
    evaluation: ConditionEvaluation<O>,
}

impl<O> ConditionEvaluationPass<O> {
    /// Builds a shared pass over one deterministic event-log prefix.
    #[must_use]
    pub fn from_log_prefix(prefix: ConditionEventLogPrefix, oracle: O) -> Self {
        Self {
            evaluation: ConditionEvaluation::from_log_prefix(prefix, oracle),
        }
    }

    /// Adds event firing history visible to `After` predicates.
    #[must_use]
    pub fn with_event_firings(mut self, event_firings: BTreeMap<EventId, VirtualTime>) -> Self {
        self.evaluation = self.evaluation.with_event_firings(event_firings);
        self
    }

    /// Adds timer fire times visible to `Timer` predicates.
    #[must_use]
    pub fn with_timer_fires(mut self, timer_fires: BTreeMap<TimerId, VirtualTime>) -> Self {
        self.evaluation = self.evaluation.with_timer_fires(timer_fires);
        self
    }

    /// Adds scheduler-owned quiescence evidence visible to `Quiescent` leaves.
    #[must_use]
    pub fn with_scheduler_quiescence(mut self, quiescence: SchedulerQuiescence) -> Self {
        self.evaluation = self.evaluation.with_scheduler_quiescence(quiescence);
        self
    }

    /// Adds authoritative white-box opt-in policies for guest-marker leaves.
    #[must_use]
    pub fn with_white_box_policies(
        mut self,
        policies: impl IntoIterator<Item = (NodeId, WhiteBoxPolicy)>,
    ) -> Self {
        self.evaluation = self.evaluation.with_white_box_policies(policies);
        self
    }

    /// Adds authoritative white-box opt-in policies from a world definition.
    #[must_use]
    pub fn with_world_white_box_policies(mut self, world: &World) -> Self {
        self.evaluation = self.evaluation.with_world_white_box_policies(world);
        self
    }

    /// Adds host-side code point resolutions visible to coverage leaves.
    #[must_use]
    pub fn with_resolved_code_points(
        mut self,
        code_points: impl IntoIterator<Item = ((NodeId, CodePoint), ResolvedCodePoint)>,
    ) -> Self {
        self.evaluation = self.evaluation.with_resolved_code_points(code_points);
        self
    }

    /// Adds host-side memory place resolutions visible to memory predicates.
    #[must_use]
    pub fn with_resolved_mem_places(
        mut self,
        mem_places: impl IntoIterator<Item = ((NodeId, MemPlace), ResolvedMemPlace)>,
    ) -> Self {
        self.evaluation = self.evaluation.with_resolved_mem_places(mem_places);
        self
    }

    /// Returns the deterministic evaluation point for this pass.
    #[must_use]
    pub fn point(&self) -> EventEvaluationPoint {
        self.evaluation.point()
    }

    /// Returns the underlying condition evaluator.
    #[must_use]
    pub fn evaluator(&self) -> &ConditionEvaluation<O> {
        &self.evaluation
    }

    /// Returns the read-only observed-state view for this pass.
    #[must_use]
    pub fn observed_state(&self) -> ObservedState<'_> {
        self.evaluation.observed_state()
    }

    /// Evaluates an assertion predicate in this deterministic pass.
    pub fn evaluate_assertion_condition(&mut self, condition: &Condition) -> bool
    where
        O: ConditionLeafOracle,
    {
        self.evaluation.evaluate_condition(condition)
    }

    /// Evaluates trigger conditions in this deterministic pass.
    pub fn evaluate_event_graph(
        &mut self,
        graph: &EventGraph,
        state: &mut EventGraphState,
    ) -> EventFirings
    where
        O: ConditionLeafOracle,
    {
        state.evaluate(graph, &mut self.evaluation)
    }
}

impl<O> condition_evaluator_sealed::Sealed for ConditionEvaluation<O> where O: ConditionLeafOracle {}

impl<O> ConditionEvaluator for ConditionEvaluation<O>
where
    O: ConditionLeafOracle,
{
    fn evaluation_point(&self) -> EventEvaluationPoint {
        self.point
    }

    fn event_log_offset(&self) -> EventLogOffset {
        self.event_log_offset
    }

    fn leaf_is_true(&mut self, leaf: ConditionLeaf<'_>) -> bool {
        self.oracle.leaf_is_true(leaf)
    }

    fn last_event_firing(&self, event: &EventId) -> Option<VirtualTime> {
        self.event_firings.get(event).copied()
    }

    fn timer_fire_time(&self, timer: &TimerId) -> Option<VirtualTime> {
        self.timer_fires.get(timer).copied()
    }

    fn timer_fires(&self) -> BTreeMap<TimerId, VirtualTime> {
        self.timer_fires.clone()
    }

    fn observable_events(&self) -> &[ObservableEvent] {
        &self.observable_events
    }

    fn scheduler_quiescence(&self) -> Option<&SchedulerQuiescence> {
        self.scheduler_quiescence.as_ref()
    }

    fn white_box_policy_for_node(&self, node: &NodeId) -> Option<WhiteBoxPolicy> {
        self.white_box_policies.get(node).copied()
    }

    fn once_condition_is_latched(&self, condition: &Condition) -> bool {
        self.once_latches.iter().any(|latched| latched == condition)
    }

    fn latch_once_condition(&mut self, condition: &Condition) {
        if !self.once_condition_is_latched(condition) {
            self.once_latches.push(condition.clone());
        }
    }

    fn resolve_code_point(&self, node: &NodeId, point: &CodePoint) -> Option<ResolvedCodePoint> {
        match point {
            CodePoint::GuestAddress { address } => Some(ResolvedCodePoint::guest_address(*address)),
            CodePoint::Symbol { .. } => self
                .code_points
                .get(&(node.clone(), point.clone()))
                .copied(),
        }
    }

    fn resolve_mem_place(&self, node: &NodeId, place: &MemPlace) -> Option<ResolvedMemPlace> {
        match place {
            MemPlace::PhysicalAddress { address, width } => {
                Some(ResolvedMemPlace::physical_address(*address, width.bytes()))
            }
            MemPlace::Register { name, width } => {
                Some(ResolvedMemPlace::register(name.clone(), width.bytes()))
            }
            MemPlace::VirtualAddress { .. } | MemPlace::Symbol { .. } => {
                self.mem_places.get(&(node.clone(), place.clone())).cloned()
            }
        }
    }
}

/// Whether an event fires once or on each false-to-true trigger transition.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Hash)]
pub enum FirePolicy {
    /// Fire at most once, the first time the trigger is true.
    #[default]
    Once,
    /// Fire on every false-to-true trigger transition.
    Repeatable,
}

/// What an event does when it fires.
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub enum Action {
    /// Activate a membership fault under a stable tag.
    InjectFault {
        /// Tag used by later heal actions.
        tag: FaultTag,
        /// Membership fault to activate.
        fault: MembershipFault,
    },
    /// Heal a previously activated fault tag.
    HealFault {
        /// Tag to heal.
        tag: FaultTag,
    },
    /// Arm a named virtual-time timer.
    ArmTimer {
        /// Timer to arm.
        name: TimerId,
        /// Virtual duration from the firing point to the timer fire point.
        after: SimDuration,
    },
    /// Cancel a named timer.
    CancelTimer {
        /// Timer to cancel.
        name: TimerId,
    },
    /// Start a declared, baked node.
    StartNode {
        /// Node to schedule as started.
        node: NodeId,
    },
    /// Stop a declared node without removing it from the world.
    StopNode {
        /// Node to stop.
        node: NodeId,
    },
    /// Create a savepoint at the firing point.
    CreateSavepoint {
        /// Optional stable savepoint label.
        label: Option<String>,
    },
    /// Fork the temporal graph at the firing point.
    Fork {
        /// Optional stable fork label.
        label: Option<String>,
    },
    /// Declare the run passed.
    Pass,
    /// Declare the run failed.
    Fail {
        /// Stable failure reason.
        reason: String,
    },
    /// Append an observational diagnostic entry.
    Log {
        /// Diagnostic level.
        level: LogLevel,
        /// Stable diagnostic message.
        message: String,
    },
    /// Group multiple action payloads in declared order.
    Group(Vec<Action>),
}

impl Action {
    /// Builds an [`Action::InjectFault`] action.
    #[must_use]
    pub fn inject_fault(tag: FaultTag, fault: MembershipFault) -> Self {
        Self::InjectFault { tag, fault }
    }

    /// Builds an [`Action::HealFault`] action.
    #[must_use]
    pub fn heal_fault(tag: FaultTag) -> Self {
        Self::HealFault { tag }
    }

    /// Builds an [`Action::ArmTimer`] action.
    #[must_use]
    pub fn arm_timer(name: TimerId, after: SimDuration) -> Self {
        Self::ArmTimer { name, after }
    }

    /// Builds an [`Action::CancelTimer`] action.
    #[must_use]
    pub fn cancel_timer(name: TimerId) -> Self {
        Self::CancelTimer { name }
    }

    /// Builds an [`Action::StartNode`] action.
    #[must_use]
    pub fn start_node(node: NodeId) -> Self {
        Self::StartNode { node }
    }

    /// Builds an [`Action::StopNode`] action.
    #[must_use]
    pub fn stop_node(node: NodeId) -> Self {
        Self::StopNode { node }
    }

    /// Builds an [`Action::CreateSavepoint`] action.
    #[must_use]
    pub fn create_savepoint(label: Option<String>) -> Self {
        Self::CreateSavepoint { label }
    }

    /// Builds an [`Action::Fork`] action.
    #[must_use]
    pub fn fork(label: Option<String>) -> Self {
        Self::Fork { label }
    }

    /// Builds an [`Action::Pass`] action.
    #[must_use]
    pub const fn pass() -> Self {
        Self::Pass
    }

    /// Builds an [`Action::Fail`] action.
    #[must_use]
    pub fn fail(reason: impl Into<String>) -> Self {
        Self::Fail {
            reason: reason.into(),
        }
    }

    /// Builds an [`Action::Log`] action.
    #[must_use]
    pub fn log(level: LogLevel, message: impl Into<String>) -> Self {
        Self::Log {
            level,
            message: message.into(),
        }
    }

    /// Builds an [`Action::Group`] action.
    #[must_use]
    pub fn group(actions: Vec<Action>) -> Self {
        Self::Group(actions)
    }
}

/// Diagnostic level for an [`Action::Log`] payload.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum LogLevel {
    /// Fine-grained diagnostic output.
    Debug,
    /// Informational diagnostic output.
    Info,
    /// Warning diagnostic output.
    Warn,
    /// Error diagnostic output.
    Error,
}

/// One node in the event graph.
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub struct Event {
    /// Stable, author-assigned event identity.
    pub id: EventId,
    /// Trigger predicate; `None` is an entrypoint fired at genesis.
    pub trigger: Option<Condition>,
    /// Action emitted when the trigger fires.
    pub action: Action,
    /// Firing policy for this event.
    pub policy: FirePolicy,
}

impl Event {
    /// Builds a fire-once event.
    #[must_use]
    pub fn once(id: EventId, trigger: Option<Condition>, action: Action) -> Self {
        Self {
            id,
            trigger,
            action,
            policy: FirePolicy::Once,
        }
    }

    /// Builds a repeatable event.
    #[must_use]
    pub fn repeatable(id: EventId, trigger: Option<Condition>, action: Action) -> Self {
        Self {
            id,
            trigger,
            action,
            policy: FirePolicy::Repeatable,
        }
    }
}

/// Code-first event-graph authoring surface.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct EventGraphBuilder {
    events: Vec<Event>,
}

impl EventGraphBuilder {
    /// Starts declaring a new event.
    #[must_use]
    pub fn event(self, id: impl Into<String>) -> EventGraphEventBuilder {
        EventGraphEventBuilder {
            builder: self,
            id: EventId::from_name(id),
            trigger: None,
            policy: FirePolicy::Once,
        }
    }

    /// Adds an already-built event to the builder.
    #[must_use]
    pub fn push_event(mut self, event: Event) -> Self {
        self.events.push(event);
        self
    }

    /// Builds and validates the event graph with no world or assertion namespace.
    ///
    /// # Errors
    ///
    /// Returns the validation errors described by [`EventGraph::new`].
    pub fn build(self) -> Result<EventGraph, EventGraphError> {
        EventGraph::new(self.events)
    }

    /// Builds and validates the event graph with declared assertion ids.
    ///
    /// # Errors
    ///
    /// Returns the validation errors described by [`EventGraph::new_with_assertions`].
    pub fn build_with_assertions(
        self,
        assertions: impl IntoIterator<Item = AssertionId>,
    ) -> Result<EventGraph, EventGraphError> {
        EventGraph::new_with_assertions(self.events, assertions)
    }

    /// Builds and validates the event graph against a world namespace.
    ///
    /// # Errors
    ///
    /// Returns the validation errors described by [`EventGraph::new_for_world`].
    pub fn build_for_world(self, world: &World) -> Result<EventGraph, EventGraphError> {
        EventGraph::new_for_world(self.events, world)
    }

    /// Builds and validates the event graph against assertion and world namespaces.
    ///
    /// # Errors
    ///
    /// Returns the validation errors described by
    /// [`EventGraph::new_with_assertions_for_world`].
    pub fn build_with_assertions_for_world(
        self,
        assertions: impl IntoIterator<Item = AssertionId>,
        world: &World,
    ) -> Result<EventGraph, EventGraphError> {
        EventGraph::new_with_assertions_for_world(self.events, assertions, world)
    }
}

/// In-progress event declaration produced by [`EventGraphBuilder::event`].
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct EventGraphEventBuilder {
    builder: EventGraphBuilder,
    id: EventId,
    trigger: Option<Condition>,
    policy: FirePolicy,
}

impl EventGraphEventBuilder {
    /// Sets the trigger condition for this event.
    #[must_use]
    pub fn when(mut self, condition: Condition) -> Self {
        self.trigger = Some(condition);
        self
    }

    /// Marks this event as an entrypoint fired at genesis.
    #[must_use]
    pub fn entrypoint(mut self) -> Self {
        self.trigger = None;
        self
    }

    /// Sets this event's fire policy.
    #[must_use]
    pub fn policy(mut self, policy: FirePolicy) -> Self {
        self.policy = policy;
        self
    }

    /// Marks this event as repeatable.
    #[must_use]
    pub fn repeatable(self) -> Self {
        self.policy(FirePolicy::Repeatable)
    }

    /// Marks this event as fire-once.
    #[must_use]
    pub fn once(self) -> Self {
        self.policy(FirePolicy::Once)
    }

    /// Finishes this event with its action and returns to the graph builder.
    #[must_use]
    pub fn action(mut self, action: Action) -> EventGraphBuilder {
        self.builder.events.push(Event {
            id: self.id,
            trigger: self.trigger,
            action,
            policy: self.policy,
        });
        self.builder
    }
}

fn lower_plan_entry_to_event((index, entry): (usize, &PlanEntry)) -> Event {
    match entry {
        PlanEntry::Activate { at, tag, fault } => Event::once(
            lowered_plan_event_id(index, "activate", tag),
            Some(Condition::At { at: *at }),
            Action::InjectFault {
                tag: tag.clone(),
                fault: fault.clone(),
            },
        ),
        PlanEntry::Heal { at, tag } => Event::once(
            lowered_plan_event_id(index, "heal", tag),
            Some(Condition::At { at: *at }),
            Action::HealFault { tag: tag.clone() },
        ),
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
struct FaultPlanLoweredAction {
    at: VirtualTime,
    kind: &'static str,
    kind_order: u8,
    tag: FaultTag,
    material: String,
    action: Action,
}

fn lower_fault_plan_actions(entries: &[FaultPlanEntry]) -> Vec<FaultPlanLoweredAction> {
    let mut actions = Vec::new();
    for entry in entries {
        match entry {
            FaultPlanEntry::At {
                at,
                duration,
                tag,
                fault,
            } => {
                actions.push(inject_fault_plan_action(*at, tag, fault));
                if let Some(heal_at) = at.ticks.checked_add(duration.nanos()) {
                    actions.push(heal_fault_plan_action(
                        VirtualTime { ticks: heal_at },
                        "heal",
                        tag,
                    ));
                }
            }
            FaultPlanEntry::PermanentAt { at, tag, fault } => {
                actions.push(inject_fault_plan_action(*at, tag, fault));
            }
            FaultPlanEntry::Heal { at, tag } => {
                actions.push(heal_fault_plan_action(*at, "heal", tag));
            }
        }
    }
    actions.sort_by(|left, right| {
        left.at
            .cmp(&right.at)
            .then_with(|| left.kind_order.cmp(&right.kind_order))
            .then_with(|| left.material.cmp(&right.material))
    });
    actions
}

fn inject_fault_plan_action(
    at: VirtualTime,
    tag: &FaultTag,
    fault: &Fault,
) -> FaultPlanLoweredAction {
    FaultPlanLoweredAction {
        at,
        kind: "inject",
        kind_order: 0,
        tag: tag.clone(),
        material: format!(
            "inject\n{}\n{}",
            fault_tag_sort_material(tag),
            fault.canonical_material()
        ),
        action: Action::InjectFault {
            tag: tag.clone(),
            fault: MembershipFault::taxonomy(fault.clone()),
        },
    }
}

fn heal_fault_plan_action(
    at: VirtualTime,
    kind: &'static str,
    tag: &FaultTag,
) -> FaultPlanLoweredAction {
    FaultPlanLoweredAction {
        at,
        kind,
        kind_order: 1,
        tag: tag.clone(),
        material: format!("heal\n{}", fault_tag_sort_material(tag)),
        action: Action::HealFault { tag: tag.clone() },
    }
}

fn fault_tag_sort_material(tag: &FaultTag) -> String {
    format!("tag_len={}\ntag={}", tag.name.len(), tag.name)
}

fn lower_fault_plan_action_to_event((index, action): (usize, &FaultPlanLoweredAction)) -> Event {
    Event::once(
        lowered_plan_event_id(index, action.kind, &action.tag),
        Some(Condition::At { at: action.at }),
        action.action.clone(),
    )
}

fn lowered_plan_event_id(index: usize, kind: &str, tag: &FaultTag) -> EventId {
    EventId::from_name(format!("plan:{index:016}:{kind}:{}", tag.name))
}

fn plan_evaluation_times(entries: &[PlanEntry]) -> Vec<VirtualTime> {
    entries
        .iter()
        .map(|entry| match entry {
            PlanEntry::Activate { at, .. } | PlanEntry::Heal { at, .. } => *at,
        })
        .collect::<BTreeSet<_>>()
        .into_iter()
        .collect()
}

fn fault_plan_action_evaluation_times(actions: &[FaultPlanLoweredAction]) -> Vec<VirtualTime> {
    actions
        .iter()
        .map(|action| action.at)
        .collect::<BTreeSet<_>>()
        .into_iter()
        .collect()
}

/// Scenario control flow expressed as declared events.
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub struct EventGraph {
    events: Vec<Event>,
}

impl EventGraph {
    /// Starts code-first event-graph authoring.
    #[must_use]
    pub fn builder() -> EventGraphBuilder {
        EventGraphBuilder::default()
    }

    /// Builds an event graph with no declared assertion or white-box namespace.
    ///
    /// # Errors
    ///
    /// Returns [`EventGraphError::DuplicateEventId`] when two events carry the
    /// same stable id, [`EventGraphError::RepeatableEntrypoint`] when an
    /// entrypoint tries to use repeatable firing policy,
    /// [`EventGraphError::UnknownEventReference`] when an `After` predicate
    /// names no declared event, [`EventGraphError::UnknownTimerReference`] when
    /// a `Timer` predicate names no armable timer,
    /// [`EventGraphError::EmptyCompound`] when an `AllOf` or `AnyOf` predicate
    /// has no children, or [`EventGraphError::InvalidRegex`] when a console
    /// predicate has an invalid regex.
    ///
    /// This constructor has no world or assertion namespace, so it also returns
    /// [`EventGraphError::UnknownAssertionReference`] for assertion-state
    /// triggers, [`EventGraphError::GuestMarkerWithoutWhiteBoxOptIn`] for
    /// guest-marker triggers, [`EventGraphError::NodeReferenceRequiresWorld`]
    /// or [`EventGraphError::LinkReferenceRequiresWorld`] for topology-bearing
    /// references, and [`EventGraphError::NodeScheduleTargetRequiresWorld`] for
    /// `StartNode` or `StopNode`. It returns
    /// [`EventGraphError::UnknownFaultTagReference`] when a `HealFault` action
    /// names no injected tag in the graph, [`EventGraphError::NonRepeatableCycle`]
    /// for a hard dependency cycle among non-repeatable events, or
    /// [`EventGraphError::UnreachableEvent`] when an event cannot be reached
    /// from an entrypoint.
    pub fn new(events: Vec<Event>) -> Result<Self, EventGraphError> {
        Self::new_with_assertions_and_world(events, [], None)
    }

    /// Builds an event graph with declared assertion ids available to triggers.
    ///
    /// # Errors
    ///
    /// Returns the common event-id, trigger-reference, assertion-reference,
    /// compound, regex, fault-tag, cycle, and reachability errors described on
    /// [`Self::new`]. Because this constructor has no world namespace, it also
    /// returns [`EventGraphError::GuestMarkerWithoutWhiteBoxOptIn`] for
    /// guest-marker triggers, [`EventGraphError::NodeReferenceRequiresWorld`] or
    /// [`EventGraphError::LinkReferenceRequiresWorld`] for topology-bearing
    /// references, and [`EventGraphError::NodeScheduleTargetRequiresWorld`] when
    /// `StartNode` or `StopNode` is present.
    pub fn new_with_assertions(
        events: Vec<Event>,
        assertions: impl IntoIterator<Item = AssertionId>,
    ) -> Result<Self, EventGraphError> {
        Self::new_with_assertions_and_world(events, assertions, None)
    }

    /// Builds an event graph using white-box opt-in data from `world`.
    ///
    /// # Errors
    ///
    /// Returns the common event-id, trigger-reference, assertion-reference,
    /// compound, regex, fault-tag, cycle, and reachability errors described on
    /// [`Self::new`]. It also returns
    /// [`EventGraphError::GuestMarkerWithoutWhiteBoxOptIn`] when a guest-marker
    /// trigger is present but `world` has no white-box-enabled node,
    /// [`EventGraphError::UnknownNodeReference`] or
    /// [`EventGraphError::UnknownLinkReference`] for topology-bearing
    /// references outside `world`, [`EventGraphError::UndeclaredNodeScheduleTarget`]
    /// when `StartNode` or `StopNode` references a node outside `world`, or
    /// [`EventGraphError::UnbakedNodeScheduleTarget`] when that action references
    /// a declared node outside the world's bake set.
    pub fn new_for_world(events: Vec<Event>, world: &World) -> Result<Self, EventGraphError> {
        Self::new_with_assertions_and_world(events, [], Some(world))
    }

    /// Builds an event graph using assertion and white-box data from `world`.
    ///
    /// # Errors
    ///
    /// Returns the common event-id, trigger-reference, assertion-reference,
    /// compound, regex, fault-tag, cycle, and reachability errors described on
    /// [`Self::new`]. It also returns
    /// [`EventGraphError::GuestMarkerWithoutWhiteBoxOptIn`] when a guest-marker
    /// trigger is present but `world` has no white-box-enabled node,
    /// [`EventGraphError::UnknownNodeReference`] or
    /// [`EventGraphError::UnknownLinkReference`] for topology-bearing
    /// references outside `world`, [`EventGraphError::UndeclaredNodeScheduleTarget`]
    /// when `StartNode` or `StopNode` references a node outside `world`, or
    /// [`EventGraphError::UnbakedNodeScheduleTarget`] when that action references
    /// a declared node outside the world's bake set.
    pub fn new_with_assertions_for_world(
        events: Vec<Event>,
        assertions: impl IntoIterator<Item = AssertionId>,
        world: &World,
    ) -> Result<Self, EventGraphError> {
        Self::new_with_assertions_and_world(events, assertions, Some(world))
    }

    fn new_with_assertions_and_world(
        events: Vec<Event>,
        assertions: impl IntoIterator<Item = AssertionId>,
        world: Option<&World>,
    ) -> Result<Self, EventGraphError> {
        let assertion_ids = assertions.into_iter().collect::<BTreeSet<_>>();
        let white_box_nodes = world
            .map(enabled_white_box_nodes)
            .unwrap_or_default()
            .into_iter()
            .collect::<BTreeSet<_>>();
        let static_topology = world.map(World::static_topology);
        let topology = world.map(EventGraphTopology::from_world);
        let mut seen = BTreeSet::new();
        for event in &events {
            if !seen.insert(event.id.clone()) {
                return Err(EventGraphError::DuplicateEventId {
                    event: event.id.clone(),
                });
            }
            if event.trigger.is_none() && event.policy == FirePolicy::Repeatable {
                return Err(EventGraphError::RepeatableEntrypoint {
                    event: event.id.clone(),
                });
            }
        }
        let timer_names = armed_timer_names(&events);
        let injected_tags = injected_fault_tags(&events);
        for event in &events {
            if let Some(condition) = &event.trigger {
                validate_condition_references(
                    event,
                    condition,
                    &seen,
                    &timer_names,
                    &assertion_ids,
                    &white_box_nodes,
                    topology.as_ref(),
                )?;
            }
            validate_action_references(
                event,
                &event.action,
                static_topology.as_ref(),
                topology.as_ref(),
                &injected_tags,
            )?;
        }
        validate_event_graph_dependencies(&events, &timer_names)?;
        Ok(Self { events })
    }

    /// Returns the events in declared deterministic order.
    #[must_use]
    pub fn events(&self) -> &[Event] {
        &self.events
    }

    /// Returns whether the graph contains no events.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.events.is_empty()
    }
}

/// A deterministic point where event triggers are evaluated.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub struct EventEvaluationPoint {
    at: VirtualTime,
    kind: EventEvaluationKind,
}

impl EventEvaluationPoint {
    /// Returns the genesis evaluation point.
    #[must_use]
    pub const fn genesis() -> Self {
        Self {
            at: VirtualTime { ticks: 0 },
            kind: EventEvaluationKind::Genesis,
        }
    }

    /// Returns a deterministic event-log-entry boundary.
    #[must_use]
    pub(crate) const fn event_boundary(at: VirtualTime) -> Self {
        Self {
            at,
            kind: EventEvaluationKind::EventBoundary,
        }
    }

    /// Returns a deterministic event-log-entry boundary for `entry`.
    #[must_use]
    pub fn event_log_entry(entry: &SchedulerEventLogEntry) -> Self {
        match entry.payload() {
            SchedulerEventLogPayload::EvaluationBoundary(
                SchedulerEvaluationBoundaryKind::Quantum,
            ) => Self::quantum_boundary(entry.at()),
            SchedulerEventLogPayload::EvaluationBoundary(
                SchedulerEvaluationBoundaryKind::Rendezvous,
            ) => Self::rendezvous_boundary(entry.at()),
            _ => Self::event_boundary(entry.at()),
        }
    }

    /// Returns a deterministic quantum boundary.
    #[must_use]
    pub(crate) const fn quantum_boundary(at: VirtualTime) -> Self {
        Self {
            at,
            kind: EventEvaluationKind::QuantumBoundary,
        }
    }

    /// Returns a deterministic rendezvous boundary.
    #[must_use]
    pub(crate) const fn rendezvous_boundary(at: VirtualTime) -> Self {
        Self {
            at,
            kind: EventEvaluationKind::RendezvousBoundary,
        }
    }

    pub(crate) const fn assertion_deadline(at: VirtualTime) -> Self {
        Self {
            at,
            kind: EventEvaluationKind::AssertionDeadline,
        }
    }

    /// Returns the virtual time of the evaluation point.
    #[must_use]
    pub fn at(self) -> VirtualTime {
        self.at
    }

    /// Returns whether this is the genesis entrypoint evaluation.
    #[must_use]
    pub fn kind(self) -> EventEvaluationKind {
        self.kind
    }
}

/// Kind of deterministic evaluation point.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum EventEvaluationKind {
    /// The run-start genesis point; entrypoint events fire here.
    Genesis,
    /// A deterministic boundary produced by an event-log entry.
    EventBoundary,
    /// A deterministic scheduler quantum boundary.
    QuantumBoundary,
    /// A deterministic scheduler rendezvous boundary.
    RendezvousBoundary,
    /// A synthetic assertion deadline point derived from pending obligations.
    AssertionDeadline,
}

/// One action fired by the event graph at an evaluation point.
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub struct EventFiring {
    event: EventId,
    at: VirtualTime,
    action: Action,
}

/// Ordered trigger firings computed by one deterministic evaluation pass.
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub struct EventFirings {
    point: EventEvaluationPoint,
    event_log_offset: EventLogOffset,
    timer_fires: BTreeMap<TimerId, VirtualTime>,
    firings: Vec<EventFiring>,
}

impl EventFirings {
    pub(crate) fn new(
        point: EventEvaluationPoint,
        event_log_offset: EventLogOffset,
        timer_fires: BTreeMap<TimerId, VirtualTime>,
        firings: Vec<EventFiring>,
    ) -> Self {
        Self {
            point,
            event_log_offset,
            timer_fires,
            firings,
        }
    }

    /// Returns the deterministic point where these firings were computed.
    #[must_use]
    pub fn point(&self) -> EventEvaluationPoint {
        self.point
    }

    /// Returns the event-log prefix identity where these firings were computed.
    #[must_use]
    pub fn event_log_offset(&self) -> EventLogOffset {
        self.event_log_offset
    }

    /// Returns the timer-fire map visible when these firings were computed.
    #[must_use]
    pub fn timer_fires(&self) -> &BTreeMap<TimerId, VirtualTime> {
        &self.timer_fires
    }

    /// Returns the number of firings in the ordered batch.
    #[must_use]
    pub fn len(&self) -> usize {
        self.firings.len()
    }

    /// Returns whether no trigger fired in this pass.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.firings.is_empty()
    }

    /// Returns the ordered firings as a read-only slice.
    #[must_use]
    pub fn as_slice(&self) -> &[EventFiring] {
        &self.firings
    }

    /// Iterates over the ordered firings.
    pub fn iter(&self) -> std::slice::Iter<'_, EventFiring> {
        self.firings.iter()
    }
}

impl Deref for EventFirings {
    type Target = [EventFiring];

    fn deref(&self) -> &Self::Target {
        self.as_slice()
    }
}

impl EventFiring {
    /// Returns the event that fired.
    #[must_use]
    pub fn event(&self) -> &EventId {
        &self.event
    }

    /// Returns the virtual time where the event fired.
    #[must_use]
    pub fn at(&self) -> VirtualTime {
        self.at
    }

    /// Returns the action emitted by the event.
    #[must_use]
    pub fn action(&self) -> &Action {
        &self.action
    }
}

/// Stateful event-graph evaluator.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct EventGraphState {
    consumed_once: BTreeSet<EventId>,
    previous_truth: BTreeMap<EventId, bool>,
    last_firing: BTreeMap<EventId, VirtualTime>,
    once_latches: Vec<Condition>,
}

impl EventGraphState {
    /// Builds a fresh event-graph state with no prior firings.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Returns the last firing time for an event, when that event has fired.
    #[must_use]
    pub fn last_firing(&self, event: &EventId) -> Option<VirtualTime> {
        self.last_firing.get(event).copied()
    }

    /// Evaluates every event in declared order and returns fired actions.
    ///
    /// `evaluator` is the deterministic predicate evaluator for non-entrypoint
    /// conditions. This method is the single local producer of [`EventFiring`]
    /// values; callers apply the returned actions at the same quantum boundary.
    pub(crate) fn evaluate<E>(&mut self, graph: &EventGraph, evaluator: &mut E) -> EventFirings
    where
        E: ConditionEvaluator,
    {
        let mut firings = Vec::new();
        let point = evaluator.evaluation_point();
        let event_log_offset = evaluator.event_log_offset();
        let timer_fires = evaluator.timer_fires();
        for event in graph.events() {
            let truth = match &event.trigger {
                Some(condition) => {
                    let mut graph_evaluator = EventGraphConditionEvaluator {
                        state: self,
                        inner: evaluator,
                    };
                    evaluate_condition(&mut graph_evaluator, condition)
                }
                None => point.kind() == EventEvaluationKind::Genesis,
            };
            let previously_true = self
                .previous_truth
                .insert(event.id.clone(), truth)
                .unwrap_or(false);
            let should_fire = match event.policy {
                FirePolicy::Once => truth && !self.consumed_once.contains(&event.id),
                FirePolicy::Repeatable => truth && !previously_true,
            };
            if should_fire {
                if event.policy == FirePolicy::Once {
                    self.consumed_once.insert(event.id.clone());
                }
                firings.push(EventFiring {
                    event: event.id.clone(),
                    at: point.at(),
                    action: event.action.clone(),
                });
                self.last_firing.insert(event.id.clone(), point.at());
            }
        }
        EventFirings::new(point, event_log_offset, timer_fires, firings)
    }
}

struct EventGraphConditionEvaluator<'state, 'inner, E> {
    state: &'state mut EventGraphState,
    inner: &'inner mut E,
}

impl<E> condition_evaluator_sealed::Sealed for EventGraphConditionEvaluator<'_, '_, E> where
    E: ConditionEvaluator
{
}

impl<E> ConditionEvaluator for EventGraphConditionEvaluator<'_, '_, E>
where
    E: ConditionEvaluator,
{
    fn evaluation_point(&self) -> EventEvaluationPoint {
        self.inner.evaluation_point()
    }

    fn event_log_offset(&self) -> EventLogOffset {
        self.inner.event_log_offset()
    }

    fn leaf_is_true(&mut self, leaf: ConditionLeaf<'_>) -> bool {
        self.inner.leaf_is_true(leaf)
    }

    fn last_event_firing(&self, event: &EventId) -> Option<VirtualTime> {
        self.state
            .last_firing(event)
            .or_else(|| self.inner.last_event_firing(event))
    }

    fn timer_fire_time(&self, timer: &TimerId) -> Option<VirtualTime> {
        self.inner.timer_fire_time(timer)
    }

    fn timer_fires(&self) -> BTreeMap<TimerId, VirtualTime> {
        self.inner.timer_fires()
    }

    fn observable_events(&self) -> &[ObservableEvent] {
        self.inner.observable_events()
    }

    fn scheduler_quiescence(&self) -> Option<&SchedulerQuiescence> {
        self.inner.scheduler_quiescence()
    }

    fn white_box_policy_for_node(&self, node: &NodeId) -> Option<WhiteBoxPolicy> {
        self.inner.white_box_policy_for_node(node)
    }

    fn once_condition_is_latched(&self, condition: &Condition) -> bool {
        self.state
            .once_latches
            .iter()
            .any(|latched| latched == condition)
    }

    fn latch_once_condition(&mut self, condition: &Condition) {
        if !self
            .state
            .once_latches
            .iter()
            .any(|latched| latched == condition)
        {
            self.state.once_latches.push(condition.clone());
        }
    }

    fn resolve_code_point(&self, node: &NodeId, point: &CodePoint) -> Option<ResolvedCodePoint> {
        self.inner.resolve_code_point(node, point)
    }

    fn resolve_mem_place(&self, node: &NodeId, place: &MemPlace) -> Option<ResolvedMemPlace> {
        self.inner.resolve_mem_place(node, place)
    }
}

/// Event graph construction errors.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum EventGraphError {
    /// Two events declared the same stable id.
    DuplicateEventId {
        /// Duplicated event id.
        event: EventId,
    },
    /// An entrypoint attempted to fire more than once.
    RepeatableEntrypoint {
        /// Invalid entrypoint event id.
        event: EventId,
    },
    /// An `After` predicate references no declared event.
    UnknownEventReference {
        /// Event containing the invalid reference.
        event: EventId,
        /// Referenced event id.
        reference: EventId,
    },
    /// A `Timer` predicate references no timer that can be armed.
    UnknownTimerReference {
        /// Event containing the invalid timer reference.
        event: EventId,
        /// Referenced timer id.
        timer: TimerId,
    },
    /// An `AssertionState` predicate references no declared assertion.
    UnknownAssertionReference {
        /// Event containing the invalid assertion reference.
        event: EventId,
        /// Referenced assertion id.
        assertion: AssertionId,
    },
    /// An `AllOf` or `AnyOf` predicate has no children.
    EmptyCompound {
        /// Event containing the empty compound.
        event: EventId,
        /// Stable compound predicate kind.
        kind: &'static str,
    },
    /// A `GuestMarker` trigger was used without any white-box-enabled node.
    GuestMarkerWithoutWhiteBoxOptIn {
        /// Event containing the guest-marker trigger.
        event: EventId,
        /// Referenced guest marker.
        marker: MarkerId,
    },
    /// A topology-bearing node reference was used without a world.
    NodeReferenceRequiresWorld {
        /// Event containing the invalid reference.
        event: EventId,
        /// Referenced node id.
        node: NodeId,
    },
    /// A topology-bearing link reference was used without a world.
    LinkReferenceRequiresWorld {
        /// Event containing the invalid reference.
        event: EventId,
        /// Referenced link id.
        link: LinkId,
    },
    /// A topology-bearing node reference names no world participant.
    UnknownNodeReference {
        /// Event containing the invalid reference.
        event: EventId,
        /// Referenced node id.
        node: NodeId,
    },
    /// A topology-bearing link reference names no world link.
    UnknownLinkReference {
        /// Event containing the invalid reference.
        event: EventId,
        /// Referenced link id.
        link: LinkId,
    },
    /// A topology-bearing device reference names no declared world device.
    UnknownDeviceReference {
        /// Event containing the invalid reference.
        event: EventId,
        /// Referenced device id.
        device: DeviceId,
    },
    /// A `StartNode` or `StopNode` action was used without a world.
    NodeScheduleTargetRequiresWorld {
        /// Event containing the invalid action.
        event: EventId,
        /// Referenced node id.
        node: NodeId,
    },
    /// A `StartNode` or `StopNode` action references no world participant.
    UndeclaredNodeScheduleTarget {
        /// Event containing the invalid action.
        event: EventId,
        /// Referenced node id.
        node: NodeId,
    },
    /// A `StartNode` or `StopNode` action references no baked node.
    UnbakedNodeScheduleTarget {
        /// Event containing the invalid action.
        event: EventId,
        /// Referenced node id.
        node: NodeId,
    },
    /// A `HealFault` action references no tag injected by this graph.
    UnknownFaultTagReference {
        /// Event containing the invalid heal action.
        event: EventId,
        /// Referenced fault tag.
        tag: FaultTag,
    },
    /// Non-repeatable events contain a dependency cycle.
    NonRepeatableCycle {
        /// Participating event ids in deterministic DFS order.
        events: Vec<EventId>,
    },
    /// An event cannot be reached from any graph entrypoint.
    UnreachableEvent {
        /// Unreachable event id.
        event: EventId,
    },
    /// A console-match predicate contains an invalid regex program.
    InvalidRegex {
        /// Event containing the invalid regex.
        event: EventId,
        /// Regex pattern that failed validation.
        pattern: String,
        /// Stable validation failure text from the regex compiler.
        reason: String,
    },
}

impl fmt::Display for EventGraphError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::DuplicateEventId { event } => {
                write!(
                    formatter,
                    "event graph contains duplicate event `{}`",
                    event.name
                )
            }
            Self::RepeatableEntrypoint { event } => {
                write!(
                    formatter,
                    "event graph entrypoint `{}` cannot be repeatable",
                    event.name
                )
            }
            Self::UnknownEventReference { event, reference } => {
                write!(
                    formatter,
                    "event `{}` references unknown event `{}`",
                    event.name, reference.name
                )
            }
            Self::UnknownTimerReference { event, timer } => {
                write!(
                    formatter,
                    "event `{}` references unknown timer `{}`",
                    event.name, timer.name
                )
            }
            Self::UnknownAssertionReference { event, assertion } => {
                write!(
                    formatter,
                    "event `{}` references unknown assertion `{}`",
                    event.name, assertion.name
                )
            }
            Self::EmptyCompound { event, kind } => {
                write!(
                    formatter,
                    "event `{}` contains empty compound predicate `{kind}`",
                    event.name
                )
            }
            Self::GuestMarkerWithoutWhiteBoxOptIn { event, marker } => {
                write!(
                    formatter,
                    "event `{}` uses guest marker `{}` without a white-box-enabled node",
                    event.name, marker.name
                )
            }
            Self::NodeReferenceRequiresWorld { event, node } => {
                write!(
                    formatter,
                    "event `{}` references node `{}` without a world",
                    event.name, node.name
                )
            }
            Self::LinkReferenceRequiresWorld { event, link } => {
                write!(
                    formatter,
                    "event `{}` references link `{}` without a world",
                    event.name, link.name
                )
            }
            Self::UnknownNodeReference { event, node } => {
                write!(
                    formatter,
                    "event `{}` references unknown node `{}`",
                    event.name, node.name
                )
            }
            Self::UnknownLinkReference { event, link } => {
                write!(
                    formatter,
                    "event `{}` references unknown link `{}`",
                    event.name, link.name
                )
            }
            Self::UnknownDeviceReference { event, device } => {
                write!(
                    formatter,
                    "event `{}` references unknown device `{}`",
                    event.name, device.name
                )
            }
            Self::NodeScheduleTargetRequiresWorld { event, node } => {
                write!(
                    formatter,
                    "event `{}` schedules node `{}` without a world",
                    event.name, node.name
                )
            }
            Self::UndeclaredNodeScheduleTarget { event, node } => {
                write!(
                    formatter,
                    "event `{}` schedules undeclared node `{}`",
                    event.name, node.name
                )
            }
            Self::UnbakedNodeScheduleTarget { event, node } => {
                write!(
                    formatter,
                    "event `{}` schedules unbaked node `{}`",
                    event.name, node.name
                )
            }
            Self::UnknownFaultTagReference { event, tag } => {
                write!(
                    formatter,
                    "event `{}` heals unknown fault tag `{}`",
                    event.name, tag.name
                )
            }
            Self::NonRepeatableCycle { events } => {
                let names = events
                    .iter()
                    .map(|event| event.name.as_str())
                    .collect::<Vec<_>>()
                    .join(" -> ");
                write!(
                    formatter,
                    "event graph contains non-repeatable dependency cycle `{names}`"
                )
            }
            Self::UnreachableEvent { event } => {
                write!(formatter, "event `{}` is unreachable", event.name)
            }
            Self::InvalidRegex { event, reason, .. } => {
                write!(
                    formatter,
                    "event `{}` has invalid regex: {reason}",
                    event.name
                )
            }
        }
    }
}

impl Error for EventGraphError {}

#[derive(Clone, Debug)]
struct EventGraphTopology {
    nodes: BTreeSet<NodeId>,
    links: BTreeSet<LinkId>,
}

impl EventGraphTopology {
    fn from_world(world: &World) -> Self {
        Self {
            nodes: world
                .static_topology()
                .participants
                .into_iter()
                .collect::<BTreeSet<_>>(),
            links: event_graph_link_ids(world.links()),
        }
    }
}

fn event_graph_link_ids(links: &[LinkDef]) -> BTreeSet<LinkId> {
    let mut ids = BTreeSet::new();
    for link in links {
        ids.insert(canonical_link_id_for_world_link(link));
        ids.insert(legacy_link_id_for_world_link(link));
    }
    ids
}

fn canonical_link_id_for_world_link(link: &LinkDef) -> LinkId {
    let (endpoint_a, endpoint_b) = link.endpoints();
    LinkId::from_name(format!(
        "link_endpoint_a_len={}\nlink_endpoint_a={}\nlink_endpoint_b_len={}\nlink_endpoint_b={}",
        endpoint_a.name.len(),
        endpoint_a.name,
        endpoint_b.name.len(),
        endpoint_b.name
    ))
}

fn legacy_link_id_for_world_link(link: &LinkDef) -> LinkId {
    let (endpoint_a, endpoint_b) = link.endpoints();
    LinkId::from_name(format!("{}--{}", endpoint_a.name, endpoint_b.name))
}

fn link_id_for_endpoint_pair(left: &NodeId, right: &NodeId) -> LinkId {
    let (endpoint_a, endpoint_b) = if left <= right {
        (left, right)
    } else {
        (right, left)
    };
    LinkId::from_name(format!(
        "link_endpoint_a_len={}\nlink_endpoint_a={}\nlink_endpoint_b_len={}\nlink_endpoint_b={}",
        endpoint_a.name.len(),
        endpoint_a.name,
        endpoint_b.name.len(),
        endpoint_b.name
    ))
}

fn armed_timer_names(events: &[Event]) -> BTreeSet<TimerId> {
    let mut timers = BTreeSet::new();
    for event in events {
        collect_timer_names(&event.action, &mut timers);
    }
    timers
}

fn collect_timer_names(action: &Action, timers: &mut BTreeSet<TimerId>) {
    match action {
        Action::ArmTimer { name, .. } => {
            timers.insert(name.clone());
        }
        Action::Group(actions) => {
            for action in actions {
                collect_timer_names(action, timers);
            }
        }
        Action::InjectFault { .. }
        | Action::HealFault { .. }
        | Action::CancelTimer { .. }
        | Action::StartNode { .. }
        | Action::StopNode { .. }
        | Action::CreateSavepoint { .. }
        | Action::Fork { .. }
        | Action::Pass
        | Action::Fail { .. }
        | Action::Log { .. } => {}
    }
}

fn injected_fault_tags(events: &[Event]) -> BTreeSet<FaultTag> {
    let mut tags = BTreeSet::new();
    for event in events {
        collect_injected_fault_tags(&event.action, &mut tags);
    }
    tags
}

fn collect_injected_fault_tags(action: &Action, tags: &mut BTreeSet<FaultTag>) {
    match action {
        Action::InjectFault { tag, .. } => {
            tags.insert(tag.clone());
        }
        Action::Group(actions) => {
            for action in actions {
                collect_injected_fault_tags(action, tags);
            }
        }
        Action::HealFault { .. }
        | Action::ArmTimer { .. }
        | Action::CancelTimer { .. }
        | Action::StartNode { .. }
        | Action::StopNode { .. }
        | Action::CreateSavepoint { .. }
        | Action::Fork { .. }
        | Action::Pass
        | Action::Fail { .. }
        | Action::Log { .. } => {}
    }
}

fn validate_action_references(
    event: &Event,
    action: &Action,
    static_topology: Option<&WorldStaticTopology>,
    topology: Option<&EventGraphTopology>,
    injected_tags: &BTreeSet<FaultTag>,
) -> Result<(), EventGraphError> {
    match action {
        Action::InjectFault { fault, .. } => {
            validate_membership_fault_reference(event, fault, topology)
        }
        Action::HealFault { tag } => {
            if injected_tags.contains(tag) {
                Ok(())
            } else {
                Err(EventGraphError::UnknownFaultTagReference {
                    event: event.id.clone(),
                    tag: tag.clone(),
                })
            }
        }
        Action::StartNode { node } | Action::StopNode { node } => {
            let Some(static_topology) = static_topology else {
                return Err(EventGraphError::NodeScheduleTargetRequiresWorld {
                    event: event.id.clone(),
                    node: node.clone(),
                });
            };
            if !static_topology.participants.contains(node) {
                return Err(EventGraphError::UndeclaredNodeScheduleTarget {
                    event: event.id.clone(),
                    node: node.clone(),
                });
            }
            if !static_topology.bake_nodes.contains(node) {
                return Err(EventGraphError::UnbakedNodeScheduleTarget {
                    event: event.id.clone(),
                    node: node.clone(),
                });
            }
            Ok(())
        }
        Action::Group(actions) => {
            for action in actions {
                validate_action_references(
                    event,
                    action,
                    static_topology,
                    topology,
                    injected_tags,
                )?;
            }
            Ok(())
        }
        Action::ArmTimer { .. }
        | Action::CancelTimer { .. }
        | Action::CreateSavepoint { .. }
        | Action::Fork { .. }
        | Action::Pass
        | Action::Fail { .. }
        | Action::Log { .. } => Ok(()),
    }
}

fn validate_membership_fault_reference(
    event: &Event,
    fault: &MembershipFault,
    topology: Option<&EventGraphTopology>,
) -> Result<(), EventGraphError> {
    match fault {
        MembershipFault::Crash { node, .. }
        | MembershipFault::Isolate { node }
        | MembershipFault::NotYetJoined { node } => validate_node_reference(event, node, topology),
        MembershipFault::Partition {
            endpoint_a,
            endpoint_b,
            ..
        } => {
            validate_node_reference(event, endpoint_a, topology)?;
            validate_node_reference(event, endpoint_b, topology)?;
            validate_link_reference(
                event,
                &link_id_for_endpoint_pair(endpoint_a, endpoint_b),
                topology,
            )
        }
        MembershipFault::Taxonomy { fault } => {
            validate_taxonomy_fault_reference(event, fault, topology)
        }
    }
}

fn validate_taxonomy_fault_reference(
    event: &Event,
    fault: &Fault,
    topology: Option<&EventGraphTopology>,
) -> Result<(), EventGraphError> {
    match fault {
        Fault::Network(fault) => validate_network_fault_reference(event, fault, topology),
        Fault::Node(fault) => validate_node_fault_reference(event, fault, topology),
        Fault::Block(fault) => Err(EventGraphError::UnknownDeviceReference {
            event: event.id.clone(),
            device: block_fault_device(fault).clone(),
        }),
        Fault::NineP(fault) => Err(EventGraphError::UnknownDeviceReference {
            event: event.id.clone(),
            device: ninep_fault_device(fault).clone(),
        }),
    }
}

fn validate_network_fault_reference(
    event: &Event,
    fault: &NetworkFault,
    topology: Option<&EventGraphTopology>,
) -> Result<(), EventGraphError> {
    validate_link_reference(event, network_fault_link(fault), topology)
}

fn validate_node_fault_reference(
    event: &Event,
    fault: &NodeFault,
    topology: Option<&EventGraphTopology>,
) -> Result<(), EventGraphError> {
    validate_node_reference(event, node_fault_node(fault), topology)
}

fn network_fault_link(fault: &NetworkFault) -> &LinkId {
    match fault {
        NetworkFault::Partition { link, .. }
        | NetworkFault::Loss { link, .. }
        | NetworkFault::Reorder { link, .. }
        | NetworkFault::Duplicate { link, .. }
        | NetworkFault::Corruption { link, .. }
        | NetworkFault::Bandwidth { link, .. }
        | NetworkFault::LatencyBump { link, .. } => link,
    }
}

fn node_fault_node(fault: &NodeFault) -> &NodeId {
    match fault {
        NodeFault::Crash { node, .. }
        | NodeFault::Slow { node, .. }
        | NodeFault::ClockSkew { node, .. } => node,
    }
}

fn block_fault_device(fault: &BlockFault) -> &DeviceId {
    match fault {
        BlockFault::Latency { device, .. }
        | BlockFault::Failure { device, .. }
        | BlockFault::Reorder { device, .. }
        | BlockFault::Duplicate { device, .. }
        | BlockFault::Corruption { device, .. }
        | BlockFault::Bandwidth { device, .. } => device,
    }
}

fn ninep_fault_device(fault: &NinePFault) -> &DeviceId {
    match fault {
        NinePFault::Latency { device, .. }
        | NinePFault::Failure { device, .. }
        | NinePFault::Reorder { device, .. }
        | NinePFault::Duplicate { device, .. }
        | NinePFault::Corruption { device, .. }
        | NinePFault::Bandwidth { device, .. } => device,
    }
}

fn enabled_white_box_nodes(world: &World) -> BTreeSet<NodeId> {
    world
        .nodes()
        .iter()
        .filter(|node| node.white_box == WhiteBoxPolicy::Enabled)
        .map(|node| node.id.clone())
        .collect()
}

fn validate_condition_references(
    event: &Event,
    condition: &Condition,
    event_ids: &BTreeSet<EventId>,
    timer_names: &BTreeSet<TimerId>,
    assertion_ids: &BTreeSet<AssertionId>,
    white_box_nodes: &BTreeSet<NodeId>,
    topology: Option<&EventGraphTopology>,
) -> Result<(), EventGraphError> {
    match condition {
        Condition::After { of, .. } => {
            if event_ids.contains(of) {
                Ok(())
            } else {
                Err(EventGraphError::UnknownEventReference {
                    event: event.id.clone(),
                    reference: of.clone(),
                })
            }
        }
        Condition::Timer { name } => {
            if timer_names.contains(name) {
                Ok(())
            } else {
                Err(EventGraphError::UnknownTimerReference {
                    event: event.id.clone(),
                    timer: name.clone(),
                })
            }
        }
        Condition::NetworkMatch { link, .. } => match link {
            Some(link) => validate_link_reference(event, link, topology),
            None => Ok(()),
        },
        Condition::ConsoleMatch { node, regex } => {
            validate_node_reference(event, node, topology)?;
            validate_condition_regex(event, regex)
        }
        Condition::CoveragePoint { node, .. }
        | Condition::MemoryPredicate { node, .. }
        | Condition::IoPattern { node, .. }
        | Condition::NodeState { node, .. } => validate_node_reference(event, node, topology),
        Condition::Named { nodes, .. } => {
            for node in nodes {
                validate_node_reference(event, node, topology)?;
            }
            Ok(())
        }
        Condition::AssertionState { name, .. } => {
            if assertion_ids.contains(name) {
                Ok(())
            } else {
                Err(EventGraphError::UnknownAssertionReference {
                    event: event.id.clone(),
                    assertion: name.clone(),
                })
            }
        }
        Condition::GuestMarker { marker } => {
            if white_box_nodes.is_empty() {
                Err(EventGraphError::GuestMarkerWithoutWhiteBoxOptIn {
                    event: event.id.clone(),
                    marker: marker.clone(),
                })
            } else {
                Ok(())
            }
        }
        Condition::AllOf { predicates } => validate_compound_condition_references(
            event,
            "all-of",
            predicates,
            event_ids,
            timer_names,
            assertion_ids,
            white_box_nodes,
            topology,
        ),
        Condition::AnyOf { predicates } => validate_compound_condition_references(
            event,
            "any-of",
            predicates,
            event_ids,
            timer_names,
            assertion_ids,
            white_box_nodes,
            topology,
        ),
        Condition::Once { predicate } | Condition::Not { predicate } => {
            validate_condition_references(
                event,
                predicate,
                event_ids,
                timer_names,
                assertion_ids,
                white_box_nodes,
                topology,
            )
        }
        Condition::At { .. } | Condition::Quiescent => Ok(()),
    }
}

fn validate_compound_condition_references(
    event: &Event,
    kind: &'static str,
    predicates: &[Condition],
    event_ids: &BTreeSet<EventId>,
    timer_names: &BTreeSet<TimerId>,
    assertion_ids: &BTreeSet<AssertionId>,
    white_box_nodes: &BTreeSet<NodeId>,
    topology: Option<&EventGraphTopology>,
) -> Result<(), EventGraphError> {
    if predicates.is_empty() {
        return Err(EventGraphError::EmptyCompound {
            event: event.id.clone(),
            kind,
        });
    }

    for predicate in predicates {
        validate_condition_references(
            event,
            predicate,
            event_ids,
            timer_names,
            assertion_ids,
            white_box_nodes,
            topology,
        )?;
    }

    Ok(())
}

fn validate_node_reference(
    event: &Event,
    node: &NodeId,
    topology: Option<&EventGraphTopology>,
) -> Result<(), EventGraphError> {
    let Some(topology) = topology else {
        return Err(EventGraphError::NodeReferenceRequiresWorld {
            event: event.id.clone(),
            node: node.clone(),
        });
    };
    if topology.nodes.contains(node) {
        Ok(())
    } else {
        Err(EventGraphError::UnknownNodeReference {
            event: event.id.clone(),
            node: node.clone(),
        })
    }
}

fn validate_link_reference(
    event: &Event,
    link: &LinkId,
    topology: Option<&EventGraphTopology>,
) -> Result<(), EventGraphError> {
    let Some(topology) = topology else {
        return Err(EventGraphError::LinkReferenceRequiresWorld {
            event: event.id.clone(),
            link: link.clone(),
        });
    };
    if topology.links.contains(link) {
        Ok(())
    } else {
        Err(EventGraphError::UnknownLinkReference {
            event: event.id.clone(),
            link: link.clone(),
        })
    }
}

fn validate_condition_regex(event: &Event, regex: &RegexProgram) -> Result<(), EventGraphError> {
    regex::bytes::Regex::new(&regex.pattern)
        .map(|_| ())
        .map_err(|source| EventGraphError::InvalidRegex {
            event: event.id.clone(),
            pattern: regex.pattern.clone(),
            reason: source.to_string(),
        })
}

fn validate_event_graph_dependencies(
    events: &[Event],
    timer_names: &BTreeSet<TimerId>,
) -> Result<(), EventGraphError> {
    let armers = timer_armers(events);
    validate_non_repeatable_cycles(events, &armers)?;
    validate_event_reachability(events, timer_names, &armers)
}

fn timer_armers(events: &[Event]) -> BTreeMap<TimerId, BTreeSet<EventId>> {
    let mut armers = BTreeMap::new();
    for event in events {
        collect_timer_armers(&event.action, &event.id, &mut armers);
    }
    armers
}

fn collect_timer_armers(
    action: &Action,
    event: &EventId,
    armers: &mut BTreeMap<TimerId, BTreeSet<EventId>>,
) {
    match action {
        Action::ArmTimer { name, .. } => {
            armers
                .entry(name.clone())
                .or_default()
                .insert(event.clone());
        }
        Action::Group(actions) => {
            for action in actions {
                collect_timer_armers(action, event, armers);
            }
        }
        Action::InjectFault { .. }
        | Action::HealFault { .. }
        | Action::CancelTimer { .. }
        | Action::StartNode { .. }
        | Action::StopNode { .. }
        | Action::CreateSavepoint { .. }
        | Action::Fork { .. }
        | Action::Pass
        | Action::Fail { .. }
        | Action::Log { .. } => {}
    }
}

fn validate_non_repeatable_cycles(
    events: &[Event],
    armers: &BTreeMap<TimerId, BTreeSet<EventId>>,
) -> Result<(), EventGraphError> {
    let policies = events
        .iter()
        .map(|event| (event.id.clone(), event.policy))
        .collect::<BTreeMap<_, _>>();
    let mut graph = BTreeMap::<EventId, BTreeSet<EventId>>::new();
    for event in events {
        if event.policy == FirePolicy::Repeatable {
            continue;
        }
        let dependencies = event
            .trigger
            .as_ref()
            .map(|condition| hard_event_dependencies(condition, armers))
            .unwrap_or_default()
            .into_iter()
            .filter(|dependency| policies.get(dependency) != Some(&FirePolicy::Repeatable))
            .collect::<BTreeSet<_>>();
        graph.insert(event.id.clone(), dependencies);
    }

    let mut marks = BTreeMap::<EventId, DfsMark>::new();
    let mut stack = Vec::new();
    for event in events {
        if event.policy != FirePolicy::Repeatable {
            visit_non_repeatable_event(&event.id, &graph, &mut marks, &mut stack)?;
        }
    }
    Ok(())
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum DfsMark {
    Gray,
    Black,
}

fn visit_non_repeatable_event(
    event: &EventId,
    graph: &BTreeMap<EventId, BTreeSet<EventId>>,
    marks: &mut BTreeMap<EventId, DfsMark>,
    stack: &mut Vec<EventId>,
) -> Result<(), EventGraphError> {
    match marks.get(event) {
        Some(DfsMark::Black) => return Ok(()),
        Some(DfsMark::Gray) => {
            let start = stack
                .iter()
                .position(|stacked| stacked == event)
                .unwrap_or(0);
            let mut cycle = stack[start..].to_vec();
            cycle.push(event.clone());
            return Err(EventGraphError::NonRepeatableCycle { events: cycle });
        }
        None => {}
    }

    marks.insert(event.clone(), DfsMark::Gray);
    stack.push(event.clone());
    if let Some(dependencies) = graph.get(event) {
        for dependency in dependencies {
            if graph.contains_key(dependency) {
                visit_non_repeatable_event(dependency, graph, marks, stack)?;
            }
        }
    }
    stack.pop();
    marks.insert(event.clone(), DfsMark::Black);
    Ok(())
}

fn hard_event_dependencies(
    condition: &Condition,
    armers: &BTreeMap<TimerId, BTreeSet<EventId>>,
) -> BTreeSet<EventId> {
    match condition {
        Condition::After { of, .. } => BTreeSet::from([of.clone()]),
        Condition::Timer { name } => armers
            .get(name)
            .filter(|timer_armers| timer_armers.len() == 1)
            .cloned()
            .unwrap_or_default(),
        Condition::AllOf { predicates } => predicates
            .iter()
            .flat_map(|predicate| hard_event_dependencies(predicate, armers))
            .collect(),
        Condition::AnyOf { predicates } => {
            let mut iter = predicates
                .iter()
                .map(|predicate| hard_event_dependencies(predicate, armers));
            let Some(first) = iter.next() else {
                return BTreeSet::new();
            };
            iter.fold(first, |common, dependencies| {
                common.intersection(&dependencies).cloned().collect()
            })
        }
        Condition::Once { predicate } => hard_event_dependencies(predicate, armers),
        Condition::Not { .. }
        | Condition::At { .. }
        | Condition::NetworkMatch { .. }
        | Condition::ConsoleMatch { .. }
        | Condition::CoveragePoint { .. }
        | Condition::MemoryPredicate { .. }
        | Condition::IoPattern { .. }
        | Condition::NodeState { .. }
        | Condition::AssertionState { .. }
        | Condition::Quiescent
        | Condition::Named { .. }
        | Condition::GuestMarker { .. } => BTreeSet::new(),
    }
}

fn validate_event_reachability(
    events: &[Event],
    timer_names: &BTreeSet<TimerId>,
    armers: &BTreeMap<TimerId, BTreeSet<EventId>>,
) -> Result<(), EventGraphError> {
    let mut alternatives = BTreeMap::<EventId, Vec<BTreeSet<EventId>>>::new();
    for event in events {
        let event_alternatives = event
            .trigger
            .as_ref()
            .map(|condition| possible_dependency_alternatives(condition, timer_names, armers))
            .unwrap_or_else(|| vec![BTreeSet::new()]);
        alternatives.insert(event.id.clone(), event_alternatives);
    }

    let mut reachable = BTreeSet::<EventId>::new();
    loop {
        let mut changed = false;
        for event in events {
            if reachable.contains(&event.id) {
                continue;
            }
            let Some(event_alternatives) = alternatives.get(&event.id) else {
                continue;
            };
            if event_alternatives
                .iter()
                .any(|alternative| alternative.is_subset(&reachable))
            {
                reachable.insert(event.id.clone());
                changed = true;
            }
        }
        if !changed {
            break;
        }
    }

    for event in events {
        if !reachable.contains(&event.id) {
            return Err(EventGraphError::UnreachableEvent {
                event: event.id.clone(),
            });
        }
    }
    Ok(())
}

fn possible_dependency_alternatives(
    condition: &Condition,
    timer_names: &BTreeSet<TimerId>,
    armers: &BTreeMap<TimerId, BTreeSet<EventId>>,
) -> Vec<BTreeSet<EventId>> {
    match condition {
        Condition::After { of, .. } => vec![BTreeSet::from([of.clone()])],
        Condition::Timer { name } => timer_names
            .contains(name)
            .then(|| {
                armers
                    .get(name)
                    .into_iter()
                    .flat_map(|timer_armers| timer_armers.iter().cloned())
                    .map(|event| BTreeSet::from([event]))
                    .collect::<Vec<_>>()
            })
            .unwrap_or_default(),
        Condition::AllOf { predicates } => {
            let mut alternatives = vec![BTreeSet::new()];
            for predicate in predicates {
                let child_alternatives =
                    possible_dependency_alternatives(predicate, timer_names, armers);
                alternatives = combine_dependency_alternatives(&alternatives, &child_alternatives);
            }
            alternatives
        }
        Condition::AnyOf { predicates } => predicates
            .iter()
            .flat_map(|predicate| possible_dependency_alternatives(predicate, timer_names, armers))
            .collect(),
        Condition::Once { predicate } => {
            possible_dependency_alternatives(predicate, timer_names, armers)
        }
        Condition::Not { .. }
        | Condition::At { .. }
        | Condition::NetworkMatch { .. }
        | Condition::ConsoleMatch { .. }
        | Condition::CoveragePoint { .. }
        | Condition::MemoryPredicate { .. }
        | Condition::IoPattern { .. }
        | Condition::NodeState { .. }
        | Condition::AssertionState { .. }
        | Condition::Quiescent
        | Condition::Named { .. }
        | Condition::GuestMarker { .. } => vec![BTreeSet::new()],
    }
}

fn combine_dependency_alternatives(
    left: &[BTreeSet<EventId>],
    right: &[BTreeSet<EventId>],
) -> Vec<BTreeSet<EventId>> {
    let mut combined = Vec::new();
    for left_alternative in left {
        for right_alternative in right {
            let mut dependency_set = left_alternative.clone();
            dependency_set.extend(right_alternative.iter().cloned());
            combined.push(dependency_set);
        }
    }
    combined
}
