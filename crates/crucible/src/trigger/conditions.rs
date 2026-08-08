//! Observable events, condition leaves, log prefixes, state facts, and host oracles.

use super::*;
/// One observable event visible to condition evaluation.
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub struct ObservableEvent {
    pub(super) at: VirtualTime,
    pub(super) payload: ObservableEventPayload,
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

    /// Builds a white-box named coverage-marker observation.
    #[must_use]
    pub fn coverage_marker(retired_icount: Icount, node: NodeId, marker: MarkerId) -> Self {
        Self {
            at: VirtualTime {
                ticks: retired_icount.retired,
            },
            payload: ObservableEventPayload::CoverageMarker {
                retired_icount,
                node,
                marker,
            },
        }
    }

    /// Builds an assertion-proximity steering observation.
    #[must_use]
    pub fn assertion_proximity(
        at: VirtualTime,
        assertion: AssertionId,
        quantifier: AssertionQuantifierKind,
        distance: u128,
        node: Option<NodeId>,
    ) -> Self {
        Self {
            at,
            payload: ObservableEventPayload::AssertionProximity {
                assertion,
                quantifier,
                distance,
                node,
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

    /// Builds a causal assertion-evaluation observation.
    #[must_use]
    pub fn assertion_evaluated(
        at: VirtualTime,
        name: AssertionId,
        flavor: AssertionQuantifierKind,
        condition: bool,
        message: impl Into<String>,
        details: Vec<GuestAssertionDetail>,
    ) -> Self {
        Self {
            at,
            payload: ObservableEventPayload::AssertionEvaluated {
                name,
                flavor,
                condition,
                message: message.into(),
                details,
            },
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

    /// Moves a polled console observation forward to its unified scheduler boundary.
    pub(crate) fn normalize_backend_poll_boundary(mut self, boundary: VirtualTime) -> Self {
        if matches!(&self.payload, ObservableEventPayload::ConsoleOutput { .. }) {
            self.at = self.at.max(boundary);
        }
        self
    }

    /// Returns the typed observable payload.
    #[must_use]
    pub fn payload(&self) -> &ObservableEventPayload {
        &self.payload
    }

    /// Returns the required black-box surface category for this event, if any.
    #[must_use]
    pub fn black_box_observation_kind(&self) -> Option<BlackBoxObservationKind> {
        self.payload.black_box_observation_kind()
    }

    /// Returns the OS-agnostic black-box contract for this event, if any.
    #[must_use]
    pub fn black_box_observation_contract(&self) -> Option<BlackBoxObservationContract> {
        self.payload.black_box_observation_contract()
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
    /// A white-box named coverage marker became visible.
    CoverageMarker {
        /// Exact guest instruction count where the marker retired.
        retired_icount: Icount,
        /// Node that emitted the marker.
        node: NodeId,
        /// Stable marker identity carried by the doorbell payload.
        marker: MarkerId,
    },
    /// An assertion-proximity distance became visible as steering-only feedback.
    AssertionProximity {
        /// Assertion whose predicate produced this distance.
        assertion: AssertionId,
        /// Assertion quantifier that owns the steering obligation.
        quantifier: AssertionQuantifierKind,
        /// Non-negative structural distance; zero means satisfied.
        distance: u128,
        /// Optional node associated with the distance.
        node: Option<NodeId>,
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
    /// A named assertion was evaluated at this log point.
    AssertionEvaluated {
        /// Assertion whose predicate was evaluated.
        name: AssertionId,
        /// Assertion quantifier or marker flavor evaluated.
        flavor: AssertionQuantifierKind,
        /// Boolean condition value observed by the assertion fold.
        condition: bool,
        /// Human-readable assertion message.
        message: String,
        /// Structured assertion details retained for projections.
        details: Vec<GuestAssertionDetail>,
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

impl ObservableEventPayload {
    /// Returns the required black-box surface category for this payload, if any.
    #[must_use]
    pub fn black_box_observation_kind(&self) -> Option<BlackBoxObservationKind> {
        match self {
            Self::NetworkDelivered { .. } => Some(BlackBoxObservationKind::NetworkTraffic),
            Self::ConsoleOutput { .. } => Some(BlackBoxObservationKind::ConsoleSerialOutput),
            Self::CoverageBlock { .. } => Some(BlackBoxObservationKind::BasicBlockCoverage),
            Self::MemorySample { .. } => Some(BlackBoxObservationKind::ArchitecturalStateSample),
            Self::IoCompletion {
                kind:
                    IoEventKind::BlockRead
                    | IoEventKind::BlockWrite
                    | IoEventKind::Fsync
                    | IoEventKind::NineP,
                ..
            } => Some(BlackBoxObservationKind::DiskOrNinePIo),
            Self::IoCompletion {
                kind: IoEventKind::Network,
                ..
            } => Some(BlackBoxObservationKind::NetworkTraffic),
            Self::NodeState {
                state: NodeLifecycle::Started | NodeLifecycle::Exited,
                ..
            } => Some(BlackBoxObservationKind::RunOutcome),
            Self::NodeState {
                state: NodeLifecycle::Crashed | NodeLifecycle::Hung,
                ..
            } => Some(BlackBoxObservationKind::CrashOrHangDetection),
            Self::CoverageMarker { .. }
            | Self::AssertionProximity { .. }
            | Self::AssertionStateChanged { .. }
            | Self::AssertionEvaluated { .. }
            | Self::IoCompletion {
                kind: IoEventKind::Any,
                ..
            }
            | Self::GuestMarker { .. }
            | Self::GuestAssertionMarker { .. } => None,
        }
    }

    /// Returns the OS-agnostic black-box contract for this payload, if any.
    #[must_use]
    pub fn black_box_observation_contract(&self) -> Option<BlackBoxObservationContract> {
        self.black_box_observation_kind()
            .map(BlackBoxObservationKind::contract)
    }
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

/// Converts a decoded white-box doorbell marker payload into engine event-log semantics.
///
/// Assertion payloads become [`ObservableEvent::guest_assertion_marker`] events,
/// so the existing host assertion finalizer consumes the shared marker fields.
/// Coverage payloads become named coverage-marker observations. Diagnostic
/// event and lifecycle payloads become observational guest-marker identities, so
/// they do not masquerade as black-box node lifecycle observations. The in-band
/// random-request kind returns [`None`] because it is handled by the app-random
/// decision path instead of the observational marker path.
#[must_use]
pub fn observable_event_from_whitebox_marker_payload(
    retired_icount: Icount,
    node: NodeId,
    payload: &crucible_protocol::WhiteboxMarkerPayload,
) -> Option<ObservableEvent> {
    match payload {
        crucible_protocol::WhiteboxMarkerPayload::Assertion(assertion) => {
            Some(ObservableEvent::guest_assertion_marker(
                retired_icount,
                node,
                guest_assertion_marker_from_whitebox_body(assertion),
            ))
        }
        crucible_protocol::WhiteboxMarkerPayload::Lifecycle(event) => {
            Some(ObservableEvent::guest_marker(
                retired_icount,
                node,
                MarkerId::from_name(format!("lifecycle.{}", event.semantic_label())),
            ))
        }
        crucible_protocol::WhiteboxMarkerPayload::Event(event) => {
            Some(ObservableEvent::guest_marker(
                retired_icount,
                node,
                MarkerId::from_name(event.name.clone()),
            ))
        }
        crucible_protocol::WhiteboxMarkerPayload::Coverage(coverage) => {
            Some(ObservableEvent::coverage_marker(
                retired_icount,
                node,
                MarkerId::from_name(coverage.point.clone()),
            ))
        }
        crucible_protocol::WhiteboxMarkerPayload::RandomRequest(_) => None,
    }
}

pub(crate) fn guest_assertion_marker_from_whitebox_body(
    body: &crucible_protocol::WhiteboxAssertionMarkerBody,
) -> GuestAssertionMarker {
    GuestAssertionMarker::new(
        AssertionId::from_name(body.id.clone()),
        body.message.clone(),
        guest_assertion_kind_from_whitebox_flavor(body.flavor),
        body.condition,
        body.must_hit,
        body.details
            .iter()
            .map(|detail| GuestAssertionDetail::new(detail.key.clone(), detail.value.clone()))
            .collect(),
        body.location.clone(),
    )
}

pub(super) fn guest_assertion_kind_from_whitebox_flavor(
    flavor: crucible_protocol::WhiteboxAssertionMarkerFlavor,
) -> GuestAssertionKind {
    match flavor {
        crucible_protocol::WhiteboxAssertionMarkerFlavor::Always => GuestAssertionKind::Always,
        crucible_protocol::WhiteboxAssertionMarkerFlavor::Sometimes => {
            GuestAssertionKind::Sometimes
        }
        crucible_protocol::WhiteboxAssertionMarkerFlavor::Reachable => {
            GuestAssertionKind::Reachable
        }
        crucible_protocol::WhiteboxAssertionMarkerFlavor::Unreachable => {
            GuestAssertionKind::Unreachable
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

    /// Returns fault activation and heal facts visible at the evaluation point.
    fn fault_facts(&self) -> &[ObservedFaultFact] {
        &[]
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

pub(super) mod condition_evaluator_sealed {
    pub trait Sealed {}
}

/// Error returned when constructing a deterministic condition-evaluation prefix.
#[derive(Clone, Debug, PartialEq, Eq)]
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
    /// A required black-box observation regressed relative to the previous one.
    OutOfOrderEventLogEntry {
        /// Sequence number carried by the previous black-box observation entry.
        previous_sequence: u64,
        /// Time of the previous black-box observation entry.
        previous_at: VirtualTime,
        /// Sequence number carried by the out-of-order black-box observation.
        sequence: u64,
        /// Time of the out-of-order black-box observation.
        event_at: VirtualTime,
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
    /// A required black-box observation was not logged as observational.
    InvalidBlackBoxObservationClass {
        /// Sequence number carried by the invalid entry.
        sequence: u64,
        /// Required black-box surface kind reconstructed from the payload.
        kind: BlackBoxObservationKind,
        /// Class recorded by the event-log entry.
        class: SchedulerEventLogClass,
    },
    /// A required black-box observation's icount stamp does not match its payload.
    InvalidBlackBoxObservationStamp {
        /// Sequence number carried by the invalid entry.
        sequence: u64,
        /// Required black-box surface kind reconstructed from the payload.
        kind: BlackBoxObservationKind,
        /// Expected icount stamp for the payload at this event-log time.
        expected: EventLogIcountStamp,
        /// Icount stamp recorded by the event-log entry.
        actual: EventLogIcountStamp,
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
            Self::OutOfOrderEventLogEntry {
                previous_sequence,
                previous_at,
                sequence,
                event_at,
            } => write!(
                formatter,
                "black-box observation entry {sequence} at {} is before entry {previous_sequence} at {}",
                event_at.ticks, previous_at.ticks
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
            Self::InvalidBlackBoxObservationClass {
                sequence,
                kind,
                class,
            } => write!(
                formatter,
                "black-box observation {kind:?} at event-log entry {sequence} has class {class:?}"
            ),
            Self::InvalidBlackBoxObservationStamp {
                sequence,
                kind,
                expected,
                actual,
            } => write!(
                formatter,
                "black-box observation {kind:?} at event-log entry {sequence} has icount stamp {actual:?}, expected {expected:?}"
            ),
        }
    }
}

impl Error for ConditionEvaluationError {}

/// Observable event-log prefix visible at one deterministic evaluation point.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ConditionEventLogPrefix {
    pub(super) point: EventEvaluationPoint,
    pub(super) base_sequence: u64,
    pub(super) event_log_offset: EventLogOffset,
    pub(super) prefix_offsets: BTreeMap<u64, EventLogOffset>,
    pub(super) scheduler_entries: Vec<SchedulerEventLogEntry>,
    pub(super) observable_events: Vec<ObservableEvent>,
    pub(super) black_box_observation_kinds: BTreeSet<BlackBoxObservationKind>,
    pub(super) event_firings: BTreeMap<EventId, VirtualTime>,
    pub(super) timer_fires: BTreeMap<TimerId, VirtualTime>,
    pub(super) ordering_facts: Vec<ObservedOrderingFact>,
    pub(super) fault_facts: Vec<ObservedFaultFact>,
}

impl ConditionEventLogPrefix {
    /// Builds the run-start genesis prefix.
    #[must_use]
    pub fn genesis() -> Self {
        Self {
            point: EventEvaluationPoint::genesis(),
            base_sequence: 0,
            event_log_offset: EventLogOffset::default(),
            prefix_offsets: BTreeMap::new(),
            scheduler_entries: Vec::new(),
            observable_events: Vec::new(),
            black_box_observation_kinds: BTreeSet::new(),
            event_firings: BTreeMap::new(),
            timer_fires: BTreeMap::new(),
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
    /// content hash does not match its canonical material,
    /// [`ConditionEvaluationError::OutOfOrderEventLogEntry`] when required
    /// black-box observations are not ordered by event-log time,
    /// [`ConditionEvaluationError::FutureEventLogEntry`] when an entry occurs
    /// after the derived evaluation point, or a black-box observation error
    /// when a required surface observation is not observational or carries an
    /// invalid icount stamp.
    pub fn from_scheduler_event_log_entries(
        entries: Vec<SchedulerEventLogEntry>,
    ) -> Result<Self, ConditionEvaluationError> {
        Self::from_scheduler_event_log_entries_with_base(entries, 0)
    }

    /// Builds a checked condition prefix from a scheduler event-log segment.
    ///
    /// This is the same validation path as
    /// [`Self::from_scheduler_event_log_entries`], but the dense sequence check
    /// starts at `base_sequence`. It is intended for live consumers that hold the
    /// prefix length separately and evaluate a newly emitted segment at its
    /// deterministic boundary.
    ///
    /// # Errors
    ///
    /// Returns the same validation errors as
    /// [`Self::from_scheduler_event_log_entries`], with sequence-prefix checks
    /// relative to `base_sequence`.
    pub fn from_scheduler_event_log_entries_with_base_sequence(
        entries: Vec<SchedulerEventLogEntry>,
        base_sequence: u64,
    ) -> Result<Self, ConditionEvaluationError> {
        Self::from_scheduler_event_log_entries_with_base(entries, base_sequence)
    }

    /// Builds a checked condition prefix with an in-memory evaluation boundary.
    ///
    /// The supplied entries are treated as the canonical event-log prefix and the
    /// synthesized boundary is appended only for this evaluation pass. This lets
    /// live consumers evaluate scheduler-owned evidence for no-entry boundaries
    /// without mutating the canonical log.
    ///
    /// # Errors
    ///
    /// Returns the same validation errors as
    /// [`Self::from_scheduler_event_log_entries`] after appending the synthesized
    /// boundary entry.
    pub fn from_scheduler_event_log_entries_with_evaluation_boundary(
        mut entries: Vec<SchedulerEventLogEntry>,
        sequence: u64,
        at: VirtualTime,
        kind: SchedulerEvaluationBoundaryKind,
    ) -> Result<Self, ConditionEvaluationError> {
        entries.push(SchedulerEventLogEntry::evaluation_boundary(
            sequence, at, kind,
        ));
        Self::from_scheduler_event_log_entries_with_base(entries, 0).map(|prefix| {
            prefix.with_event_log_offset(EventLogOffset::new(ContentHash::default(), 0, sequence))
        })
    }

    /// Builds an in-memory evaluation-boundary prefix.
    ///
    /// This creates a checked boundary point for consumers that need to evaluate
    /// scheduler-owned evidence, such as quiescence, even when the scheduler did
    /// not append a canonical event-log entry at that boundary.
    ///
    /// # Errors
    ///
    /// Returns [`ConditionEvaluationError`] if the synthesized boundary entry is
    /// not a valid dense prefix at `sequence`.
    pub fn from_evaluation_boundary(
        sequence: u64,
        at: VirtualTime,
        kind: SchedulerEvaluationBoundaryKind,
    ) -> Result<Self, ConditionEvaluationError> {
        Self::from_scheduler_event_log_entries_with_base(
            vec![SchedulerEventLogEntry::evaluation_boundary(
                sequence, at, kind,
            )],
            sequence,
        )
        .map(|prefix| {
            prefix.with_event_log_offset(EventLogOffset::new(ContentHash::default(), 0, sequence))
        })
    }

    pub(crate) fn from_scheduler_event_log_entries_with_base(
        entries: Vec<SchedulerEventLogEntry>,
        base_sequence: u64,
    ) -> Result<Self, ConditionEvaluationError> {
        let Some(last) = entries.last() else {
            return Err(ConditionEvaluationError::EmptyEventLogPrefix);
        };
        let point = EventEvaluationPoint::event_log_entry(last);
        let mut observable_events = Vec::new();
        let mut black_box_observation_kinds = BTreeSet::new();
        let mut event_firings = BTreeMap::new();
        let mut timer_fires = BTreeMap::new();
        let mut ordering_facts = Vec::new();
        let mut fault_facts = Vec::new();
        let mut previous_black_box_observation: Option<&SchedulerEventLogEntry> = None;
        for (offset, entry) in entries.iter().enumerate() {
            let offset = u64::try_from(offset).map_err(|_| {
                ConditionEvaluationError::NonPrefixEventLogSequence {
                    expected: u64::MAX,
                    actual: entry.sequence(),
                }
            })?;
            let expected = base_sequence.checked_add(offset).ok_or(
                ConditionEvaluationError::NonPrefixEventLogSequence {
                    expected: u64::MAX,
                    actual: entry.sequence(),
                },
            )?;
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
            if scheduler_entry_black_box_observation_kind(entry).is_some() {
                if let Some(previous) = previous_black_box_observation
                    && entry.at().ticks < previous.at().ticks
                {
                    return Err(ConditionEvaluationError::OutOfOrderEventLogEntry {
                        previous_sequence: previous.sequence(),
                        previous_at: previous.at(),
                        sequence: entry.sequence(),
                        event_at: entry.at(),
                    });
                }
                previous_black_box_observation = Some(entry);
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
                &mut black_box_observation_kinds,
                &mut ordering_facts,
                &mut fault_facts,
            )?;
            push_condition_runtime_facts(entry, &mut event_firings, &mut timer_fires);
        }
        Ok(Self {
            point,
            base_sequence,
            event_log_offset: EventLogOffset::new(
                ContentHash::default(),
                0,
                base_sequence
                    .checked_add(u64::try_from(entries.len()).map_err(|_| {
                        ConditionEvaluationError::NonPrefixEventLogSequence {
                            expected: u64::MAX,
                            actual: u64::MAX,
                        }
                    })?)
                    .ok_or(ConditionEvaluationError::NonPrefixEventLogSequence {
                        expected: u64::MAX,
                        actual: u64::MAX,
                    })?,
            ),
            prefix_offsets: BTreeMap::new(),
            scheduler_entries: entries,
            observable_events,
            black_box_observation_kinds,
            event_firings,
            timer_fires,
            ordering_facts,
            fault_facts,
        })
    }

    pub(crate) fn with_event_log_offset(mut self, event_log_offset: EventLogOffset) -> Self {
        self.event_log_offset = event_log_offset;
        self
    }

    fn with_base_sequence(mut self, base_sequence: u64) -> Self {
        self.base_sequence = base_sequence;
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
                let prefix_events = self.base_sequence.checked_add(prefix_len)?;
                prefix = prefix.with_event_log_offset(*self.prefix_offsets.get(&prefix_events)?);
            }
            return Some(
                prefix
                    .with_base_sequence(self.base_sequence)
                    .with_prefix_offsets(self.prefix_offsets.clone())
                    .with_point(point),
            );
        }
        let prefix_events = self.base_sequence.checked_add(prefix_len)?;
        let mut prefix =
            Self::from_scheduler_event_log_entries_with_base(entries, self.base_sequence).ok()?;
        if !self.prefix_offsets.is_empty() {
            prefix = prefix.with_event_log_offset(*self.prefix_offsets.get(&prefix_events)?);
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

    /// Returns the required black-box observation categories present in this prefix.
    #[must_use]
    pub fn black_box_observation_kinds(&self) -> &BTreeSet<BlackBoxObservationKind> {
        &self.black_box_observation_kinds
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
    pub(super) point: EventEvaluationPoint,
    pub(super) event_log_offset: EventLogOffset,
    pub(super) observable_events: &'log [ObservableEvent],
    pub(super) ordering_facts: &'log [ObservedOrderingFact],
    pub(super) fault_facts: &'log [ObservedFaultFact],
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

/// Host-authored resolver for assertion leaves over materialized observed state.
///
/// Implementations do not grade runs directly. Wrap them in
/// [`LintedHostAssertionOracle`] with a [`HostAssertionHarnessLint`] proof first,
/// so custom host predicate source cannot bypass `gate:harness-lint`.
pub trait HostAssertionPredicate {
    /// Returns whether one host-side assertion leaf is true at `observed`.
    fn leaf_is_true(&self, observed: ObservedState<'_>, leaf: ConditionLeaf<'_>) -> bool;
}

impl<F> HostAssertionPredicate for F
where
    F: for<'log, 'leaf> Fn(ObservedState<'log>, ConditionLeaf<'leaf>) -> bool,
{
    fn leaf_is_true(&self, observed: ObservedState<'_>, leaf: ConditionLeaf<'_>) -> bool {
        self(observed, leaf)
    }
}

/// Lint proof for host-authored assertion harness source.
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub struct HostAssertionHarnessLint {
    source_len: usize,
}

impl HostAssertionHarnessLint {
    /// Returns the byte length of the linted harness source.
    #[must_use]
    pub const fn source_len(&self) -> usize {
        self.source_len
    }
}

/// Custom host assertion oracle paired with a successful harness-lint proof.
#[derive(Clone, Debug)]
pub struct LintedHostAssertionOracle<O> {
    oracle: O,
    lint: HostAssertionHarnessLint,
}

impl<O> LintedHostAssertionOracle<O> {
    fn new(oracle: O, lint: HostAssertionHarnessLint) -> Self {
        Self { oracle, lint }
    }

    /// Returns the wrapped oracle.
    #[must_use]
    pub fn oracle(&self) -> &O {
        &self.oracle
    }

    /// Returns the wrapped oracle mutably.
    #[must_use]
    pub fn oracle_mut(&mut self) -> &mut O {
        &mut self.oracle
    }

    /// Consumes this wrapper and returns the wrapped oracle.
    #[must_use]
    pub fn into_inner(self) -> O {
        self.oracle
    }

    /// Returns the lint proof used to authorize this oracle.
    #[must_use]
    pub const fn lint(&self) -> &HostAssertionHarnessLint {
        &self.lint
    }
}

#[cfg(any(debug_assertions, feature = "test-support"))]
pub(crate) fn unchecked_host_assertion_oracle_for_test<O>(oracle: O) -> LintedHostAssertionOracle<O>
where
    O: HostAssertionPredicate,
{
    LintedHostAssertionOracle::new(oracle, HostAssertionHarnessLint { source_len: 0 })
}

mod host_assertion_oracle_sealed {
    pub trait Sealed {}
}

/// Assertion oracle accepted by the evaluator.
///
/// This trait is sealed so external host predicate code must flow through
/// [`LintedHostAssertionOracle`] instead of implementing the evaluator-facing
/// oracle directly.
pub trait HostAssertionOracle: host_assertion_oracle_sealed::Sealed {
    /// Returns whether one host-side assertion leaf is true at `observed`.
    fn leaf_is_true(&mut self, observed: ObservedState<'_>, leaf: ConditionLeaf<'_>) -> bool;
}

/// Default zero-guest-cooperation assertion oracle.
///
/// The oracle supplies no named host predicates. Properties that use only the
/// built-in black-box observable vocabulary still evaluate through the checked
/// event-log prefix.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct BlackBoxHostOracle;

impl host_assertion_oracle_sealed::Sealed for BlackBoxHostOracle {}

impl HostAssertionOracle for BlackBoxHostOracle {
    fn leaf_is_true(&mut self, _observed: ObservedState<'_>, leaf: ConditionLeaf<'_>) -> bool {
        match leaf {
            ConditionLeaf::Named { .. } | ConditionLeaf::GuestMarker { .. } => false,
        }
    }
}

/// Data-only key for a named predicate over search-reconstructed schedule facts.
#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct SearchScheduleNamedPredicateKey {
    name: String,
    nodes: Vec<NodeId>,
    active_fault_tags: Vec<FaultTag>,
}

impl SearchScheduleNamedPredicateKey {
    /// Builds a canonical named-predicate key.
    #[must_use]
    pub fn new(
        name: impl Into<String>,
        nodes: Vec<NodeId>,
        mut active_fault_tags: Vec<FaultTag>,
    ) -> Self {
        active_fault_tags.sort();
        active_fault_tags.dedup();
        Self {
            name: name.into(),
            nodes,
            active_fault_tags,
        }
    }

    /// Returns the named predicate identity.
    #[must_use]
    pub fn name(&self) -> &str {
        &self.name
    }

    /// Returns the declared node references for the named predicate.
    #[must_use]
    pub fn nodes(&self) -> &[NodeId] {
        &self.nodes
    }

    /// Returns schedule-derived fault tags active at the evaluated prefix.
    #[must_use]
    pub fn active_fault_tags(&self) -> &[FaultTag] {
        &self.active_fault_tags
    }
}

/// Deterministic truth table for search-time named predicate lowering.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct SearchScheduleNamedPredicateTruths {
    truths: BTreeMap<SearchScheduleNamedPredicateKey, bool>,
}

impl SearchScheduleNamedPredicateTruths {
    /// Builds an empty truth table.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Adds one deterministic named-predicate truth entry.
    #[must_use]
    pub fn with_truth(mut self, key: SearchScheduleNamedPredicateKey, value: bool) -> Self {
        self.insert_truth(key, value);
        self
    }

    /// Inserts one deterministic named-predicate truth entry.
    pub fn insert_truth(&mut self, key: SearchScheduleNamedPredicateKey, value: bool) {
        self.truths.insert(key, value);
    }

    /// Returns the truth value for `key`, if the table declares one.
    #[must_use]
    pub fn truth_for(&self, key: &SearchScheduleNamedPredicateKey) -> Option<bool> {
        self.truths.get(key).copied()
    }

    /// Returns whether the table has no declared named-predicate truths.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.truths.is_empty()
    }
}

pub(crate) struct SearchScheduleNamedPredicateHostOracle<'truths> {
    truths: &'truths SearchScheduleNamedPredicateTruths,
    missing_truths: BTreeSet<SearchScheduleNamedPredicateKey>,
}

impl<'truths> SearchScheduleNamedPredicateHostOracle<'truths> {
    pub(crate) const fn new(truths: &'truths SearchScheduleNamedPredicateTruths) -> Self {
        Self {
            truths,
            missing_truths: BTreeSet::new(),
        }
    }

    pub(crate) fn clear_missing_truths(&mut self) {
        self.missing_truths.clear();
    }

    pub(crate) fn has_missing_truths(&self) -> bool {
        !self.missing_truths.is_empty()
    }
}

impl host_assertion_oracle_sealed::Sealed for SearchScheduleNamedPredicateHostOracle<'_> {}

impl HostAssertionOracle for SearchScheduleNamedPredicateHostOracle<'_> {
    fn leaf_is_true(&mut self, observed: ObservedState<'_>, leaf: ConditionLeaf<'_>) -> bool {
        match leaf {
            ConditionLeaf::Named { name, nodes } => {
                let key = SearchScheduleNamedPredicateKey::new(
                    name.to_owned(),
                    nodes.to_vec(),
                    active_search_fault_tags(observed.fault_facts()),
                );
                match self.truths.truth_for(&key) {
                    Some(value) => value,
                    None => {
                        self.missing_truths.insert(key);
                        false
                    }
                }
            }
            ConditionLeaf::GuestMarker { .. } => false,
        }
    }
}

pub(super) fn active_search_fault_tags(facts: &[ObservedFaultFact]) -> Vec<FaultTag> {
    let mut active = BTreeSet::new();
    for fact in facts {
        match fact {
            ObservedFaultFact::TriggerInjected { tag, .. } => {
                active.insert(tag.clone());
            }
            ObservedFaultFact::TriggerHealed { tag, .. } => {
                active.remove(tag);
            }
        }
    }
    active.into_iter().collect()
}

impl<O> host_assertion_oracle_sealed::Sealed for LintedHostAssertionOracle<O> where
    O: HostAssertionPredicate
{
}

impl<O> HostAssertionOracle for LintedHostAssertionOracle<O>
where
    O: HostAssertionPredicate,
{
    fn leaf_is_true(&mut self, observed: ObservedState<'_>, leaf: ConditionLeaf<'_>) -> bool {
        HostAssertionPredicate::leaf_is_true(&self.oracle, observed, leaf)
    }
}

/// One banned host assertion harness pattern found by linting.
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub struct HostAssertionHarnessLintViolation {
    /// Source token or path fragment that matched.
    pub pattern: String,
    /// Determinism contract violated by the matched pattern.
    pub reason: String,
}

/// Error returned when host assertion harness source fails determinism linting.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct HostAssertionHarnessLintError {
    violations: Vec<HostAssertionHarnessLintViolation>,
}

impl HostAssertionHarnessLintError {
    /// Returns every banned host assertion source pattern that was found.
    #[must_use]
    pub fn violations(&self) -> &[HostAssertionHarnessLintViolation] {
        &self.violations
    }
}

impl fmt::Display for HostAssertionHarnessLintError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            formatter,
            "host assertion harness source contains {} banned determinism pattern(s)",
            self.violations.len()
        )
    }
}

impl Error for HostAssertionHarnessLintError {}

/// Lints host-authored assertion predicate source for banned nondeterminism.
///
/// This helper is the assertion layer's `gate:harness-lint` hook. It catches
/// host wall-clock reads, thread RNG, unordered-map/set use, filesystem/process
/// access, and `unsafe` blocks in host predicate harness source before those
/// predicates can grade a run.
///
/// # Errors
///
/// Returns [`HostAssertionHarnessLintError`] with every matched banned pattern.
pub fn lint_host_assertion_harness_source(
    source: &str,
) -> Result<HostAssertionHarnessLint, HostAssertionHarnessLintError> {
    const BANNED_PATTERNS: &[(&str, &str)] = &[
        (
            "HashMap",
            "unordered map iteration can perturb outcome order",
        ),
        (
            "HashSet",
            "unordered set iteration can perturb outcome order",
        ),
        ("SystemTime", "host wall-clock reads are nondeterministic"),
        ("Instant", "host wall-clock reads are nondeterministic"),
        ("std::time", "host wall-clock reads are nondeterministic"),
        ("chrono::", "host wall-clock reads are nondeterministic"),
        (
            "OffsetDateTime::now",
            "host wall-clock reads are nondeterministic",
        ),
        ("getrandom", "direct host RNG access is nondeterministic"),
        ("OsRng", "direct host RNG access is nondeterministic"),
        ("thread_rng", "thread-local RNG is nondeterministic"),
        ("rand::", "direct host RNG access is nondeterministic"),
        ("rand::rng", "direct host RNG access is nondeterministic"),
        ("rand::random", "direct host RNG access is nondeterministic"),
        ("from_entropy", "host entropy seeding is nondeterministic"),
        (
            "DefaultHasher",
            "randomized hash seeding can perturb outcome order",
        ),
        (
            "RandomState",
            "randomized hash seeding can perturb outcome order",
        ),
        (
            "std::env",
            "environment access is outside the recorded observed state",
        ),
        (
            "env::",
            "environment access is outside the recorded observed state",
        ),
        (
            "std::thread",
            "host thread access is outside the deterministic evaluator",
        ),
        (
            "thread::",
            "host thread access is outside the deterministic evaluator",
        ),
        (
            "thread_local!",
            "host thread-local state is outside the recorded observed state",
        ),
        (
            "std::fs",
            "filesystem access is outside the recorded observed state",
        ),
        (
            "std::{fs",
            "filesystem access is outside the recorded observed state",
        ),
        (
            "fs::",
            "filesystem access is outside the recorded observed state",
        ),
        (
            "std::process",
            "process access is outside the recorded observed state",
        ),
        (
            "std::{process",
            "process access is outside the recorded observed state",
        ),
        (
            "process::Command",
            "process access is outside the recorded observed state",
        ),
        (
            "Command::new",
            "process access is outside the recorded observed state",
        ),
        (
            "std::net",
            "network access is outside the recorded observed state",
        ),
        (
            "TcpStream",
            "network access is outside the recorded observed state",
        ),
        (
            "UdpSocket",
            "network access is outside the recorded observed state",
        ),
        ("std::io", "host I/O is outside the recorded observed state"),
        ("stdin", "host I/O is outside the recorded observed state"),
        ("stdout", "host I/O is outside the recorded observed state"),
        ("stderr", "host I/O is outside the recorded observed state"),
        (
            "println!",
            "host I/O is outside the recorded observed state",
        ),
        (
            "eprintln!",
            "host I/O is outside the recorded observed state",
        ),
        (
            "OpenOptions",
            "filesystem access is outside the recorded observed state",
        ),
        (
            "File::",
            "filesystem access is outside the recorded observed state",
        ),
        (
            "tokio::select",
            "host scheduling races are nondeterministic",
        ),
        ("tokio::spawn", "host task scheduling is nondeterministic"),
        ("select!", "host scheduling races are nondeterministic"),
        (
            "Atomic",
            "shared host state can make predicate output order-dependent",
        ),
        (
            "Mutex",
            "shared host state can make predicate output order-dependent",
        ),
        (
            "RwLock",
            "shared host state can make predicate output order-dependent",
        ),
        (
            "OnceLock",
            "shared host state can make predicate output order-dependent",
        ),
        (
            "LazyLock",
            "shared host state can make predicate output order-dependent",
        ),
        (
            "OnceCell",
            "shared host state can make predicate output order-dependent",
        ),
        (
            "lazy_static",
            "shared host state can make predicate output order-dependent",
        ),
        (
            "Cell<",
            "interior mutability can make predicate output order-dependent",
        ),
        (
            "RefCell",
            "interior mutability can make predicate output order-dependent",
        ),
        (
            "UnsafeCell",
            "interior mutability can make predicate output order-dependent",
        ),
        (
            "borrow_mut",
            "interior mutability can make predicate output order-dependent",
        ),
        (
            "parking_lot",
            "shared host state can make predicate output order-dependent",
        ),
        (
            "crossbeam",
            "shared host state can make predicate output order-dependent",
        ),
        (
            "unsafe",
            "unsafe host predicates bypass the read-only state contract",
        ),
    ];
    let violations = BANNED_PATTERNS
        .iter()
        .filter(|(pattern, _reason)| source.contains(pattern))
        .map(|(pattern, reason)| HostAssertionHarnessLintViolation {
            pattern: (*pattern).to_owned(),
            reason: (*reason).to_owned(),
        })
        .collect::<Vec<_>>();
    if violations.is_empty() {
        Ok(HostAssertionHarnessLint {
            source_len: source.len(),
        })
    } else {
        Err(HostAssertionHarnessLintError { violations })
    }
}
