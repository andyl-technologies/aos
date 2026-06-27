//! Single-scheduler quantum-loop boundary.
//!
//! The module owns the L3 interface that all virtual-time advancement and
//! cross-node event resolution must pass through. It intentionally defines the
//! boundary and ordering vocabulary without implementing the full scheduler
//! algorithm; the detailed PICK/RUN/RESOLVE/EMIT/STEP behavior lands in the
//! scheduler tasks that build on this API.

use std::error::Error;
use std::fmt;
use std::sync::mpsc::{self, Receiver, Sender, TryRecvError};

use crate::{
    BackendError, BackendInput, Configuration, Decision, DecisionRngState, DeliveryOrderDecision,
    EventKey, FaultId, Icount, NodeCounter, NodeId, RngStreamId, RngStreamPosition, ScenarioDef,
    Shift, SimDuration, SimInstant, TimeConversionError, VirtualTime, WorldLookaheadEdge, step,
};

const SCHEDULER_ACTOR_RNG_DOMAIN: &str = "crucible.scheduler.actor";
const SCHEDULER_QUANTUM_STREAM: &str = "quantum";

/// Advances the system by one scheduler quantum.
///
/// Implementations own the PICK/RUN/RESOLVE/EMIT/STEP boundary: callers may ask
/// for one quantum, but they do not advance backend clocks or deliver
/// cross-node inputs directly.
pub trait QuantumLoop {
    /// Drives exactly one scheduler quantum.
    ///
    /// # Errors
    ///
    /// Returns [`SchedulerError`] when the quantum cannot be driven or when the
    /// scheduler detects an invalid boundary condition.
    fn drive_quantum(&mut self, request: QuantumRequest) -> Result<QuantumOutcome, SchedulerError>;
}

/// Input supplied by the session actor at a quantum boundary.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct QuantumRequest {
    /// The configuration to advance from.
    pub configuration: Configuration,
    /// Control operations admitted at this boundary before the next PICK.
    pub control: Vec<ControlOperation>,
}

/// Output produced by one scheduler quantum.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct QuantumOutcome {
    /// The configuration after all decisions from this quantum have been
    /// appended.
    pub configuration: Configuration,
    /// The virtual-time frontier reached by the quantum.
    pub frontier: VirtualTime,
    /// The node selected by PICK, if any node was runnable.
    pub advanced_node: Option<SchedulerNodeId>,
    /// The events resolved by RESOLVE in canonical total order.
    pub resolved_events: Vec<ScheduledEvent>,
    /// Decisions appended by STEP in canonical order.
    pub decisions: Vec<Decision>,
}

/// A read-only copy of the state owned by the scheduler actor.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SchedulerActorStateSnapshot {
    /// The current frontier configuration.
    pub configuration: Configuration,
    /// Per-node counters in canonical scheduler-node order.
    pub node_counters: Vec<(SchedulerNodeId, NodeCounter)>,
    /// Number of cross-node events still owned by the scheduler.
    pub pending_event_count: usize,
    /// Number of control operations waiting for the next quantum boundary.
    pub pending_control_count: usize,
    /// Decision-RNG cursor positions owned by the scheduler.
    pub decision_rng_cursor: DecisionRngState,
    /// Number of quantum boundaries at which the scheduler yielded to control.
    pub boundary_yields: u64,
}

/// A message-only scheduler actor that owns the authoritative scheduler state.
#[derive(Debug)]
pub struct SchedulerActor {
    scheduler: SingleScheduler,
    inbox: Receiver<SchedulerActorMessage>,
}

/// A clonable sender for scheduler actor messages.
#[derive(Clone, Debug)]
pub struct SchedulerActorHandle {
    inbox: Sender<SchedulerActorMessage>,
}

/// A typed reply receiver for scheduler actor requests.
#[derive(Debug)]
pub struct SchedulerActorReply<T> {
    receiver: Receiver<T>,
}

enum SchedulerActorMessage {
    QueueControl(ControlOperation),
    DriveQuantum {
        request: QuantumRequest,
        reply: Sender<Result<QuantumOutcome, SchedulerError>>,
    },
    Snapshot {
        reply: Sender<SchedulerActorStateSnapshot>,
    },
}

impl fmt::Debug for SchedulerActorMessage {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::QueueControl(operation) => formatter
                .debug_tuple("QueueControl")
                .field(operation)
                .finish(),
            Self::DriveQuantum { request, .. } => formatter
                .debug_struct("DriveQuantum")
                .field("request", request)
                .finish_non_exhaustive(),
            Self::Snapshot { .. } => formatter.debug_struct("Snapshot").finish_non_exhaustive(),
        }
    }
}

impl SchedulerActor {
    /// Builds a scheduler actor and the handle used to send it messages.
    ///
    /// # Errors
    ///
    /// Returns [`SchedulerError`] when the scheduler cannot be built from
    /// `scenario`.
    pub fn new(
        scenario: SchedulerLivenessScenario,
    ) -> Result<(SchedulerActorHandle, Self), SchedulerError> {
        let (sender, receiver) = mpsc::channel();
        Ok((
            SchedulerActorHandle { inbox: sender },
            Self {
                scheduler: SingleScheduler::new(scenario)?,
                inbox: receiver,
            },
        ))
    }

    /// Processes one queued actor message, if one is available.
    ///
    /// # Errors
    ///
    /// Returns [`SchedulerActorError`] when the actor mailbox is closed or when
    /// a caller drops a reply receiver before the actor sends the result.
    pub fn run_once(&mut self) -> Result<bool, SchedulerActorError> {
        match self.inbox.try_recv() {
            Ok(message) => {
                self.apply_message(message)?;
                Ok(true)
            }
            Err(TryRecvError::Empty) => Ok(false),
            Err(TryRecvError::Disconnected) => Err(SchedulerActorError::MailboxClosed),
        }
    }

    /// Processes queued actor messages until the mailbox is temporarily empty.
    ///
    /// # Errors
    ///
    /// Returns [`SchedulerActorError`] when the actor mailbox is closed or when
    /// a caller drops a reply receiver before the actor sends the result.
    pub fn run_until_idle(&mut self) -> Result<usize, SchedulerActorError> {
        let mut processed = 0usize;
        while self.run_once()? {
            processed += 1;
        }
        Ok(processed)
    }

    fn apply_message(&mut self, message: SchedulerActorMessage) -> Result<(), SchedulerActorError> {
        match message {
            SchedulerActorMessage::QueueControl(operation) => {
                self.scheduler.queue_control(operation);
                Ok(())
            }
            SchedulerActorMessage::DriveQuantum { request, reply } => reply
                .send(self.scheduler.drive_quantum(request))
                .map_err(|_| SchedulerActorError::ReplyDropped),
            SchedulerActorMessage::Snapshot { reply } => reply
                .send(self.scheduler.actor_state_snapshot())
                .map_err(|_| SchedulerActorError::ReplyDropped),
        }
    }
}

impl SchedulerActorHandle {
    /// Queues a control operation for the scheduler actor.
    ///
    /// # Errors
    ///
    /// Returns [`SchedulerActorError::MailboxClosed`] when the actor has already
    /// stopped receiving messages.
    pub fn queue_control(&self, operation: ControlOperation) -> Result<(), SchedulerActorError> {
        self.send(SchedulerActorMessage::QueueControl(operation))
    }

    /// Requests one scheduler quantum through the actor mailbox.
    ///
    /// # Errors
    ///
    /// Returns [`SchedulerActorError::MailboxClosed`] when the actor has already
    /// stopped receiving messages.
    pub fn drive_quantum(
        &self,
        request: QuantumRequest,
    ) -> Result<SchedulerActorReply<Result<QuantumOutcome, SchedulerError>>, SchedulerActorError>
    {
        let (sender, receiver) = mpsc::channel();
        self.send(SchedulerActorMessage::DriveQuantum {
            request,
            reply: sender,
        })?;
        Ok(SchedulerActorReply { receiver })
    }

    /// Requests a read-only scheduler state snapshot through the actor mailbox.
    ///
    /// # Errors
    ///
    /// Returns [`SchedulerActorError::MailboxClosed`] when the actor has already
    /// stopped receiving messages.
    pub fn snapshot(
        &self,
    ) -> Result<SchedulerActorReply<SchedulerActorStateSnapshot>, SchedulerActorError> {
        let (sender, receiver) = mpsc::channel();
        self.send(SchedulerActorMessage::Snapshot { reply: sender })?;
        Ok(SchedulerActorReply { receiver })
    }

    fn send(&self, message: SchedulerActorMessage) -> Result<(), SchedulerActorError> {
        self.inbox
            .send(message)
            .map_err(|_| SchedulerActorError::MailboxClosed)
    }
}

impl<T> SchedulerActorReply<T> {
    /// Receives a scheduler actor reply.
    ///
    /// # Errors
    ///
    /// Returns [`SchedulerActorError::ReplyDropped`] when the actor drops before
    /// replying to the request.
    pub fn recv(self) -> Result<T, SchedulerActorError> {
        self.receiver
            .recv()
            .map_err(|_| SchedulerActorError::ReplyDropped)
    }
}

/// An error produced by the scheduler actor mailbox.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum SchedulerActorError {
    /// The actor mailbox is closed.
    MailboxClosed,
    /// A request reply was dropped before delivery.
    ReplyDropped,
}

impl fmt::Display for SchedulerActorError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::MailboxClosed => formatter.write_str("scheduler actor mailbox is closed"),
            Self::ReplyDropped => formatter.write_str("scheduler actor reply was dropped"),
        }
    }
}

impl Error for SchedulerActorError {}

/// A control-plane operation admitted only at a quantum boundary.
#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct ControlOperation {
    /// The session-local sequence number for this control operation.
    pub sequence: u64,
    /// The requested control action.
    pub kind: ControlOperationKind,
}

/// A session control action that can be handled between quanta.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum ControlOperationKind {
    /// Pause after the current boundary.
    Pause,
    /// Resume a paused session.
    Resume,
    /// Drive one quantum.
    Step,
    /// Capture a checkpoint at the boundary.
    Snapshot,
    /// Fork from the boundary configuration.
    Fork,
    /// Inject a control-plane fault or input at the boundary.
    Inject,
    /// Query boundary state without mutating the engine.
    Query,
}

/// A scheduler graph node, including VM nodes and deterministic I/O sub-nodes.
#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct SchedulerNodeId {
    /// The scenario node that owns this scheduler node.
    pub node: NodeId,
    /// The kind of scheduler node.
    pub kind: SchedulingNodeKind,
}

/// The kind of node participating in the scheduler graph.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum SchedulingNodeKind {
    /// A VM backend node.
    Vm,
    /// A deterministic disk sub-node.
    Disk,
    /// A deterministic 9p sub-node.
    NineP,
    /// A deterministic network-link sub-node.
    Network,
    /// The session actor boundary.
    ControlPlane,
}

/// One unresolved cross-node dependency that can constrain conservative advance.
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub struct UnresolvedCrossNodeDependency {
    /// The peer that produced the cross-node event.
    pub producer: SchedulerNodeId,
    /// The scheduler node that must consume the event.
    pub consumer: SchedulerNodeId,
    /// The exact virtual time at which the event becomes visible.
    pub virtual_time: SimInstant,
    /// The producer-local sequence number used for deterministic ordering.
    pub sequence: u64,
}

impl UnresolvedCrossNodeDependency {
    /// Extracts a cross-node dependency from a scheduled backend-input event.
    #[must_use]
    pub fn from_event(event: &ScheduledEvent) -> Option<Self> {
        let producer = event.key.producer();
        let consumer = event.key.consumer();
        if producer == consumer || !matches!(event.payload, ScheduledEventPayload::BackendInput(_))
        {
            return None;
        }

        Some(Self {
            producer: producer.clone(),
            consumer: consumer.clone(),
            virtual_time: SimInstant {
                nanos: event.key.virtual_time().ticks,
            },
            sequence: event.key.sequence(),
        })
    }
}

/// The conservative-PDES authorization for one requested node advance.
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub struct ConservativeAdvanceAuthorization {
    /// The node whose clock may advance.
    pub node: SchedulerNodeId,
    /// The node's current virtual time before the advance.
    pub current_time: SimInstant,
    /// The target requested by the horizon calculator.
    pub requested_target: SimInstant,
    /// The target authorized after applying unresolved cross-node dependencies.
    pub authorized_target: SimInstant,
    /// The dependency that capped the target, if any.
    pub blocking_dependency: Option<UnresolvedCrossNodeDependency>,
}

/// Returns unresolved cross-node dependencies that target `node`.
#[must_use]
pub fn unresolved_cross_node_dependencies(
    node: &SchedulerNodeId,
    events: &[ScheduledEvent],
) -> Vec<UnresolvedCrossNodeDependency> {
    let mut dependencies = events
        .iter()
        .filter_map(UnresolvedCrossNodeDependency::from_event)
        .filter(|dependency| &dependency.consumer == node)
        .collect::<Vec<_>>();
    dependencies.sort_by(|left, right| {
        left.virtual_time
            .cmp(&right.virtual_time)
            .then_with(|| left.consumer.cmp(&right.consumer))
            .then_with(|| left.producer.cmp(&right.producer))
            .then_with(|| left.sequence.cmp(&right.sequence))
    });
    dependencies
}

/// Authorizes one conservative-PDES node advance.
///
/// The returned target never crosses the earliest unresolved cross-node
/// dependency for `node`. Rollback requests and already-due cross-node
/// dependencies fail loudly instead of speculating.
///
/// # Errors
///
/// Returns [`SchedulerError::BoundaryViolation`] when `requested_target` is
/// before `current_time`, or when an unresolved cross-node dependency for `node`
/// is already due at or before `current_time`.
pub fn authorize_conservative_advance(
    node: &SchedulerNodeId,
    current_time: SimInstant,
    requested_target: SimInstant,
    pending_events: &[ScheduledEvent],
) -> Result<ConservativeAdvanceAuthorization, SchedulerError> {
    if requested_target < current_time {
        return Err(SchedulerError::BoundaryViolation {
            message: format!(
                "conservative PDES rejected rollback for {}:{:?}: current={} requested={}",
                node.node.name, node.kind, current_time.nanos, requested_target.nanos
            ),
        });
    }

    let dependency = unresolved_cross_node_dependencies(node, pending_events)
        .into_iter()
        .next();
    let (authorized_target, blocking_dependency) = match dependency {
        Some(dependency) if dependency.virtual_time <= current_time => {
            return Err(SchedulerError::BoundaryViolation {
                message: format!(
                    "conservative PDES rejected advance for {}:{:?}: unresolved cross-node dependency is due at {}",
                    node.node.name, node.kind, dependency.virtual_time.nanos
                ),
            });
        }
        Some(dependency) if dependency.virtual_time <= requested_target => {
            (dependency.virtual_time, Some(dependency))
        }
        _ => (requested_target, None),
    };

    Ok(ConservativeAdvanceAuthorization {
        node: node.clone(),
        current_time,
        requested_target,
        authorized_target,
        blocking_dependency,
    })
}

/// Conservative network lookahead for one scheduler node.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum NetworkLookahead {
    /// The node has at least one inbound live network edge.
    Finite(SimDuration),
    /// The node has no inbound live network edge and is network-unbounded.
    Infinite,
}

impl NetworkLookahead {
    /// Returns the finite duration when this lookahead is bounded by a network edge.
    #[must_use]
    pub fn finite_duration(self) -> Option<SimDuration> {
        match self {
            Self::Finite(duration) => Some(duration),
            Self::Infinite => None,
        }
    }

    /// Returns whether this lookahead is positive infinity.
    #[must_use]
    pub fn is_infinite(self) -> bool {
        matches!(self, Self::Infinite)
    }
}

/// One directed live edge used for scheduler network lookahead.
#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct SchedulerLookaheadEdge {
    /// The scheduler node that can produce a future network event.
    pub from: SchedulerNodeId,
    /// The scheduler node that can receive the future network event.
    pub to: SchedulerNodeId,
    /// The minimum one-way latency that bounds conservative network lookahead.
    pub minimum_latency: SimDuration,
}

impl SchedulerLookaheadEdge {
    /// Builds one directed scheduler lookahead edge.
    #[must_use]
    pub fn new(from: SchedulerNodeId, to: SchedulerNodeId, minimum_latency: SimDuration) -> Self {
        Self {
            from,
            to,
            minimum_latency,
        }
    }

    /// Converts a static world lookahead edge into a VM-to-VM scheduler edge.
    #[must_use]
    pub fn from_world_edge(edge: &WorldLookaheadEdge) -> Self {
        Self {
            from: SchedulerNodeId {
                node: edge.from.clone(),
                kind: SchedulingNodeKind::Vm,
            },
            to: SchedulerNodeId {
                node: edge.to.clone(),
                kind: SchedulingNodeKind::Vm,
            },
            minimum_latency: edge.minimum_latency,
        }
    }
}

/// Canonical directed edge set used to compute scheduler network lookahead.
#[derive(Clone, Debug, Default, PartialEq, Eq, Hash)]
pub struct SchedulerLookaheadGraph {
    edges: Vec<SchedulerLookaheadEdge>,
}

impl SchedulerLookaheadGraph {
    /// Builds a canonical graph from the current effective scheduler edge set.
    ///
    /// The caller supplies the effective topology. This constructor only
    /// canonicalizes directed edges and collapses exact duplicate edges; dynamic
    /// topology recompute and partition/heal semantics are layered on top by the
    /// later scheduler tasks.
    #[must_use]
    pub fn from_edges<I>(edges: I) -> Self
    where
        I: IntoIterator<Item = SchedulerLookaheadEdge>,
    {
        let mut edges = edges.into_iter().collect::<Vec<_>>();
        edges.sort();
        edges.dedup();
        Self { edges }
    }

    /// Builds a scheduler graph from the static world lookahead graph.
    ///
    /// Static world edges are VM-to-VM edges. Faults and partitions may later
    /// provide a smaller effective edge set before calling [`Self::from_edges`].
    #[must_use]
    pub fn from_world_edges(edges: &[WorldLookaheadEdge]) -> Self {
        Self::from_edges(edges.iter().map(SchedulerLookaheadEdge::from_world_edge))
    }

    /// Returns the canonical effective edges used by this graph.
    #[must_use]
    pub fn edges(&self) -> &[SchedulerLookaheadEdge] {
        &self.edges
    }

    /// Computes `lookahead(node)` as the minimum inbound live-link latency.
    #[must_use]
    pub fn lookahead(&self, node: &SchedulerNodeId) -> NetworkLookahead {
        lookahead_for_node(&self.edges, node)
    }
}

/// Computes `lookahead(node)` over an effective directed scheduler edge set.
///
/// Inbound edges from other scheduler nodes contribute their minimum one-way
/// latency. When no inbound edge targets `node`, the result is
/// [`NetworkLookahead::Infinite`].
#[must_use]
pub fn lookahead_for_node(
    edges: &[SchedulerLookaheadEdge],
    node: &SchedulerNodeId,
) -> NetworkLookahead {
    match edges
        .iter()
        .filter(|edge| &edge.to == node && &edge.from != node)
        .map(|edge| edge.minimum_latency)
        .min()
    {
        Some(duration) => NetworkLookahead::Finite(duration),
        None => NetworkLookahead::Infinite,
    }
}

/// Shared virtual-timeline projection used by scheduler ordering.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub struct SharedTimeline {
    shift: Shift,
}

impl SharedTimeline {
    /// Builds a shared timeline using one fixed scenario shift.
    ///
    /// # Errors
    ///
    /// Returns [`TimeConversionError::InvalidShift`] when `shift` cannot name a
    /// `u64` power-of-two scale.
    pub fn new(shift: Shift) -> Result<Self, TimeConversionError> {
        NodeCounter::default().to_virtual(shift)?;
        Ok(Self { shift })
    }

    /// Returns the fixed scenario shift used by every node projection.
    #[must_use]
    pub fn shift(&self) -> Shift {
        self.shift
    }

    /// Projects a VM icount or deterministic I/O counter onto the shared axis.
    ///
    /// # Errors
    ///
    /// Returns [`TimeConversionError`] when the counter cannot be converted to a
    /// virtual-time point under this timeline's fixed shift.
    pub fn project_counter(
        &self,
        node: SchedulerNodeId,
        counter: NodeCounter,
    ) -> Result<NodeTimelineProjection, TimeConversionError> {
        Ok(NodeTimelineProjection {
            node,
            counter,
            virtual_time: counter.to_virtual(self.shift)?,
        })
    }

    /// Projects a node counter into a scheduler ordering key.
    ///
    /// # Errors
    ///
    /// Returns [`TimeConversionError`] when the counter cannot be converted to a
    /// virtual-time point under this timeline's fixed shift.
    pub fn timeline_key(
        &self,
        node: SchedulerNodeId,
        counter: NodeCounter,
        sequence: u64,
    ) -> Result<SharedTimelineKey, TimeConversionError> {
        let projection = self.project_counter(node, counter)?;
        Ok(projection.timeline_key(sequence))
    }
}

/// A node-local counter projected onto the shared virtual timeline.
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub struct NodeTimelineProjection {
    /// The VM node or deterministic I/O sub-node owning the counter.
    pub node: SchedulerNodeId,
    /// The node-local counter before projection.
    pub counter: NodeCounter,
    /// The derived point on the shared virtual timeline.
    pub virtual_time: SimInstant,
}

impl NodeTimelineProjection {
    /// Returns the scheduler ordering key for an event from this projection.
    #[must_use]
    pub fn timeline_key(&self, sequence: u64) -> SharedTimelineKey {
        SharedTimelineKey {
            virtual_time: self.virtual_time,
            node: self.node.clone(),
            sequence,
        }
    }
}

/// Canonical key for shared-timeline scheduler ordering.
#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct SharedTimelineKey {
    /// The icount-derived point on the shared virtual timeline.
    pub virtual_time: SimInstant,
    /// The VM node or deterministic I/O sub-node ordered on that timeline.
    pub node: SchedulerNodeId,
    /// The node-local sequence number used to resolve simultaneity.
    pub sequence: u64,
}

/// Returns shared-timeline keys in canonical deterministic scheduler order.
#[must_use]
pub fn ordered_timeline_keys(keys: &[SharedTimelineKey]) -> Vec<&SharedTimelineKey> {
    let mut ordered = keys.iter().collect::<Vec<_>>();

    ordered.sort();

    ordered
}

/// Canonical key for resolving due events in one total order.
///
/// The key consumes the shared timeline projection first, then refines
/// simultaneity with the producer node before the sequence number. This preserves
/// the same-icount producer tie-break while making the scheduler event order
/// explicitly depend on `(virtual_time, consumer node, sequence)` from the
/// shared timeline.
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub struct ScheduledEventKey {
    /// The shared-timeline consumer ordering key.
    pub timeline: SharedTimelineKey,
    /// The event producer.
    pub producer: SchedulerNodeId,
}

impl ScheduledEventKey {
    /// Builds a scheduled-event key from the shared timeline and producer.
    #[must_use]
    pub fn new(timeline: SharedTimelineKey, producer: SchedulerNodeId) -> Self {
        Self { timeline, producer }
    }

    /// Builds a scheduled-event key from legacy event-ordering parts.
    #[must_use]
    pub fn from_parts(
        virtual_time: VirtualTime,
        consumer: SchedulerNodeId,
        producer: SchedulerNodeId,
        sequence: u64,
    ) -> Self {
        Self {
            timeline: SharedTimelineKey {
                virtual_time: SimInstant {
                    nanos: virtual_time.ticks,
                },
                node: consumer,
                sequence,
            },
            producer,
        }
    }

    /// Returns the shared virtual time at which the event is due.
    #[must_use]
    pub fn virtual_time(&self) -> VirtualTime {
        VirtualTime {
            ticks: self.timeline.virtual_time.nanos,
        }
    }

    /// Returns the event consumer.
    #[must_use]
    pub fn consumer(&self) -> &SchedulerNodeId {
        &self.timeline.node
    }

    /// Returns the event producer.
    #[must_use]
    pub fn producer(&self) -> &SchedulerNodeId {
        &self.producer
    }

    /// Returns the producer-local sequence number.
    #[must_use]
    pub fn sequence(&self) -> u64 {
        self.timeline.sequence
    }
}

impl Ord for ScheduledEventKey {
    fn cmp(&self, other: &Self) -> std::cmp::Ordering {
        self.timeline
            .virtual_time
            .cmp(&other.timeline.virtual_time)
            .then_with(|| self.timeline.node.cmp(&other.timeline.node))
            .then_with(|| self.producer.cmp(&other.producer))
            .then_with(|| self.timeline.sequence.cmp(&other.timeline.sequence))
    }
}

impl PartialOrd for ScheduledEventKey {
    fn partial_cmp(&self, other: &Self) -> Option<std::cmp::Ordering> {
        Some(self.cmp(other))
    }
}

/// A due event resolved by the scheduler.
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub struct ScheduledEvent {
    /// The canonical ordering key.
    pub key: ScheduledEventKey,
    /// The resolved event payload.
    pub payload: ScheduledEventPayload,
}

/// Returns scheduled events in the canonical deterministic resolution order.
#[must_use]
pub fn ordered_scheduled_events(events: &[ScheduledEvent]) -> Vec<&ScheduledEvent> {
    let mut ordered = events.iter().collect::<Vec<_>>();

    ordered.sort_by(|left, right| left.key.cmp(&right.key));

    ordered
}

/// Payload carried by a scheduler-resolved event.
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub enum ScheduledEventPayload {
    /// A backend input delivered at the scheduler-selected point.
    BackendInput(BackendInput),
    /// A deterministic I/O completion from a disk, 9p, or network sub-node.
    IoCompletion(IoCompletion),
    /// A fault activation resolved at the boundary.
    FaultActivation(FaultId),
    /// A control operation admitted at a quantum boundary.
    Control(ControlOperation),
}

/// A deterministic I/O completion emitted by a scheduling sub-node.
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub struct IoCompletion {
    /// The sub-node that produced the completion.
    pub sub_node: SchedulerNodeId,
    /// The target node that observes the completion.
    pub target: NodeId,
    /// The target instruction count where the completion becomes visible.
    pub delivery_icount: Icount,
    /// The deterministic completion payload.
    pub payload: Vec<u8>,
}

/// A node-local exact event supplied by the backend while the node is idle.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum ExactLocalEvent {
    /// The node has no armed guest timer.
    NoArmedTimer,
    /// The node has an armed guest timer at an exact virtual-time point.
    TimerDeadline {
        /// The exact virtual-time deadline from the backend's virtual clock.
        virtual_time: SimInstant,
    },
}

/// Converts an exact virtual timer deadline report into a scheduler local event.
///
/// `Some(deadline_ns)` is an absolute virtual-clock timestamp from the backend's
/// exact deadline capability. `None` means the backend reported no armed
/// virtual-clock timer.
#[must_use]
pub fn exact_local_event_from_timer_deadline_ns(deadline_ns: Option<u64>) -> ExactLocalEvent {
    match deadline_ns {
        Some(nanos) => ExactLocalEvent::TimerDeadline {
            virtual_time: SimInstant { nanos },
        },
        None => ExactLocalEvent::NoArmedTimer,
    }
}

/// The source that selected a scheduler horizon.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum SchedulerHorizonSource {
    /// The conservative network lookahead selected the horizon.
    NetworkLookahead,
    /// An exact local guest timer selected the horizon.
    ExactLocalTimer,
}

/// A scheduler horizon and its matching icount ceiling.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub struct SchedulerHorizon {
    /// The selected virtual-time horizon.
    pub virtual_time: SimInstant,
    /// The icount ceiling computed with the fixed-shift `ceil` conversion.
    pub ceiling: Icount,
    /// The input that selected the horizon.
    pub source: SchedulerHorizonSource,
}

/// Computes the scheduler horizon from network lookahead and the exact local event.
///
/// The exact local timer deadline is consumed as a local horizon candidate. A
/// node with no armed timer uses the conservative network horizon. The selected
/// virtual-time horizon is converted to the node's target icount with
/// `SimInstant::to_icount_ceil`.
///
/// # Errors
///
/// Returns [`SchedulerError::TimeConversion`] when the selected horizon cannot
/// be converted under `shift`.
pub fn horizon_from_exact_local_event(
    network_horizon: SimInstant,
    exact_local_event: ExactLocalEvent,
    shift: Shift,
) -> Result<SchedulerHorizon, SchedulerError> {
    let (virtual_time, source) = match exact_local_event {
        ExactLocalEvent::NoArmedTimer => {
            (network_horizon, SchedulerHorizonSource::NetworkLookahead)
        }
        ExactLocalEvent::TimerDeadline { virtual_time } if virtual_time <= network_horizon => {
            (virtual_time, SchedulerHorizonSource::ExactLocalTimer)
        }
        ExactLocalEvent::TimerDeadline { .. } => {
            (network_horizon, SchedulerHorizonSource::NetworkLookahead)
        }
    };
    Ok(SchedulerHorizon {
        virtual_time,
        ceiling: virtual_time.to_icount_ceil(shift)?,
        source,
    })
}

/// One generated node consumed by the scheduler liveness gate.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SchedulerScenarioNode {
    /// The scheduler graph node to advance.
    pub id: SchedulerNodeId,
    /// The node-local counter at the start of the run.
    pub counter: NodeCounter,
    /// Whether the node starts runnable or already idle.
    pub activity: SchedulerNodeActivity,
    /// The conservative cross-node lookahead horizon for this node.
    pub network_horizon: SimInstant,
    /// The exact local timer or idle report for this node.
    pub exact_local_event: ExactLocalEvent,
}

/// The generated liveness activity state for one scheduler node.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum SchedulerNodeActivity {
    /// The node has work and may be selected by PICK.
    Runnable,
    /// The node is idle, has no local timer or I/O work, and cannot advance.
    Idle,
}

/// A finite scheduler scenario for checking quantum-loop liveness.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SchedulerLivenessScenario {
    /// The configuration whose schedule records scheduler decisions.
    pub configuration: Configuration,
    /// The fixed icount-to-virtual-time shift for every node in the scenario.
    pub shift: Shift,
    /// The maximum number of quanta allowed before the scenario time-limits.
    pub quantum_budget: u64,
    /// The virtual-time limit that also terminates the scenario.
    pub time_limit: SimInstant,
    /// The generated nodes driven by the authoritative scheduler.
    ///
    /// A runnable generated node becomes [`SchedulerNodeActivity::Idle`] once it
    /// reaches the horizon selected from its exact local event and network
    /// lookahead.
    pub nodes: Vec<SchedulerScenarioNode>,
    /// Cross-node, I/O, fault, and control events waiting for scheduler delivery.
    pub pending_events: Vec<ScheduledEvent>,
}

impl SchedulerLivenessScenario {
    /// Builds a scheduler scenario with a deterministic synthetic configuration.
    #[must_use]
    pub fn from_canonical_material(
        material: &str,
        shift: Shift,
        quantum_budget: u64,
        time_limit: SimInstant,
        nodes: Vec<SchedulerScenarioNode>,
        pending_events: Vec<ScheduledEvent>,
    ) -> Self {
        Self {
            configuration: Configuration::genesis(ScenarioDef::from_canonical_material(
                "crucible.scheduler-liveness.scenario",
                material,
            )),
            shift,
            quantum_budget,
            time_limit,
            nodes,
            pending_events,
        }
    }
}

/// The terminal scheduler condition reached by a liveness run.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum SchedulerTerminal {
    /// No node can advance and no scheduler event remains pending.
    Quiescent,
    /// The run reached its virtual-time or quantum budget.
    TimeLimitReached,
}

/// Evidence produced by a successful scheduler liveness run.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SchedulerLivenessReport {
    /// The terminal condition reached by the scheduler.
    pub terminal: SchedulerTerminal,
    /// The number of scheduler quanta driven.
    pub quanta: u64,
    /// The shared-timeline frontier after the last quantum.
    pub frontier: VirtualTime,
    /// The nodes advanced, in scheduler order.
    pub advanced_nodes: Vec<SchedulerNodeId>,
    /// The number of events resolved by the scheduler.
    pub resolved_events: usize,
    /// Whether every node advance happened after yielding the scheduler lock.
    pub yielded_between_quanta: bool,
    /// The final configuration with scheduler decisions appended.
    pub final_configuration: Configuration,
}

/// A liveness failure reported by the scheduler gate.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum SchedulerLivenessError {
    /// A scenario with no nodes cannot exercise scheduler progress.
    EmptyScenario,
    /// The scheduler reached a non-quiescent state with no advanceable node.
    Deadlock {
        /// The shared-timeline frontier at the deadlock.
        frontier: VirtualTime,
        /// The number of events still waiting for delivery.
        pending_events: usize,
    },
    /// A runnable node remained non-quiescent but no quantum could advance it.
    Livelock {
        /// The zero-based quantum index that failed to make progress.
        quantum: u64,
        /// The stalled scheduler node.
        node: SchedulerNodeId,
        /// The counter at which the node stalled.
        counter: NodeCounter,
    },
    /// A scheduler implementation held its internal lock across node advance.
    LockHeldAcrossAdvance {
        /// The zero-based quantum index that violated the yield contract.
        quantum: u64,
        /// The node advanced while the scheduler lock was still held.
        node: SchedulerNodeId,
    },
    /// The scheduler boundary returned an operational error.
    Scheduler(SchedulerError),
}

impl fmt::Display for SchedulerLivenessError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::EmptyScenario => f.write_str("scheduler liveness scenario has no nodes"),
            Self::Deadlock {
                frontier,
                pending_events,
            } => write!(
                f,
                "scheduler deadlocked at virtual time {} with {pending_events} pending events",
                frontier.ticks
            ),
            Self::Livelock {
                quantum,
                node,
                counter,
            } => write!(
                f,
                "scheduler livelock at quantum {quantum} on {}:{:?} counter {}",
                node.node.name, node.kind, counter.ticks
            ),
            Self::LockHeldAcrossAdvance { quantum, node } => write!(
                f,
                "scheduler held its lock across node advance at quantum {quantum} on {}:{:?}",
                node.node.name, node.kind
            ),
            Self::Scheduler(error) => write!(f, "scheduler liveness check failed: {error}"),
        }
    }
}

impl Error for SchedulerLivenessError {}

impl From<SchedulerError> for SchedulerLivenessError {
    fn from(error: SchedulerError) -> Self {
        Self::Scheduler(error)
    }
}

/// The single authoritative scheduler used by the liveness gate.
#[derive(Clone, Debug)]
pub struct SingleScheduler {
    configuration: Configuration,
    timeline: SharedTimeline,
    quantum_budget: u64,
    time_limit: SimInstant,
    nodes: Vec<RuntimeSchedulerNode>,
    pending_events: Vec<ScheduledEvent>,
    control_inbox: Vec<ControlOperation>,
    decision_rng_cursor: DecisionRngState,
    frontier: VirtualTime,
    quanta: u64,
    boundary_yields: u64,
    lock_held: bool,
    last_advance: Option<NodeAdvance>,
}

impl SingleScheduler {
    /// Builds a scheduler from a finite generated liveness scenario.
    ///
    /// # Errors
    ///
    /// Returns [`SchedulerError`] when the fixed timeline shift cannot be
    /// represented or when an initial node counter cannot be projected onto the
    /// shared virtual timeline.
    pub fn new(scenario: SchedulerLivenessScenario) -> Result<Self, SchedulerError> {
        let timeline = SharedTimeline::new(scenario.shift)?;
        let mut nodes = scenario
            .nodes
            .into_iter()
            .map(RuntimeSchedulerNode::from)
            .collect::<Vec<_>>();
        nodes.sort_by(|left, right| left.id.cmp(&right.id));

        let frontier = frontier_for(&nodes, scenario.shift)?;

        Ok(Self {
            configuration: scenario.configuration,
            timeline,
            quantum_budget: scenario.quantum_budget,
            time_limit: scenario.time_limit,
            nodes,
            pending_events: scenario.pending_events,
            control_inbox: Vec::new(),
            decision_rng_cursor: DecisionRngState::empty(),
            frontier,
            quanta: 0,
            boundary_yields: 0,
            lock_held: false,
            last_advance: None,
        })
    }

    /// Returns the current scheduler configuration.
    #[must_use]
    pub fn configuration(&self) -> &Configuration {
        &self.configuration
    }

    /// Returns the current shared-timeline frontier.
    #[must_use]
    pub fn frontier(&self) -> VirtualTime {
        self.frontier
    }

    /// Returns the number of quanta already driven.
    #[must_use]
    pub fn quanta(&self) -> u64 {
        self.quanta
    }

    fn queue_control(&mut self, operation: ControlOperation) {
        self.control_inbox.push(operation);
    }

    fn actor_state_snapshot(&self) -> SchedulerActorStateSnapshot {
        SchedulerActorStateSnapshot {
            configuration: self.configuration.clone(),
            node_counters: self
                .nodes
                .iter()
                .map(|node| (node.id.clone(), node.counter))
                .collect(),
            pending_event_count: self.pending_events.len(),
            pending_control_count: self.control_inbox.len(),
            decision_rng_cursor: self.decision_rng_cursor.clone(),
            boundary_yields: self.boundary_yields,
        }
    }

    fn is_empty(&self) -> bool {
        self.nodes.is_empty()
    }

    fn is_quiescent(&self) -> bool {
        self.pending_events.is_empty()
            && self
                .nodes
                .iter()
                .all(|node| node.activity == SchedulerNodeActivity::Idle)
    }

    fn reached_time_limit(&self) -> bool {
        let mut saw_runnable = false;

        for node in &self.nodes {
            if node.activity == SchedulerNodeActivity::Runnable {
                saw_runnable = true;
                let Ok(current_time) = node.counter.to_virtual(self.timeline.shift()) else {
                    return false;
                };
                if current_time < self.time_limit {
                    return false;
                }
            }
        }

        saw_runnable
    }

    fn exhausted_quantum_budget(&self) -> bool {
        self.quanta >= self.quantum_budget
    }

    fn pick_global_minimum_horizon_node(&self) -> Result<Option<AdvanceCandidate>, SchedulerError> {
        let mut candidates = Vec::new();

        for (index, node) in self.nodes.iter().enumerate() {
            if let Some(candidate) = self.advance_candidate(index, node)? {
                candidates.push(candidate);
            }
        }

        candidates.sort_by(|left, right| {
            left.target_time
                .cmp(&right.target_time)
                .then_with(|| left.key.node.cmp(&right.key.node))
                .then_with(|| left.key.virtual_time.cmp(&right.key.virtual_time))
                .then_with(|| left.index.cmp(&right.index))
        });

        Ok(candidates.into_iter().next())
    }

    fn advance_candidate(
        &self,
        index: usize,
        node: &RuntimeSchedulerNode,
    ) -> Result<Option<AdvanceCandidate>, SchedulerError> {
        if node.activity == SchedulerNodeActivity::Idle {
            return Ok(None);
        }

        let current_time = node.counter.to_virtual(self.timeline.shift())?;
        let window = self.advance_window(node, current_time)?;

        if current_time >= window.target_time {
            return Ok(None);
        }

        Ok(Some(AdvanceCandidate {
            index,
            key: self
                .timeline
                .timeline_key(node.id.clone(), node.counter, index as u64)?,
            target_time: window.target_time,
            quiescent_horizon: window.quiescent_horizon,
            conservative_dependency: window.conservative_dependency,
        }))
    }

    fn advance_window(
        &self,
        node: &RuntimeSchedulerNode,
        current_time: SimInstant,
    ) -> Result<AdvanceWindow, SchedulerError> {
        let horizon = horizon_from_exact_local_event(
            node.network_horizon,
            node.exact_local_event,
            self.timeline.shift(),
        )?;
        let requested_target = min_instant(horizon.virtual_time, self.time_limit);
        let authorization = authorize_conservative_advance(
            &node.id,
            current_time,
            requested_target,
            &self.pending_events,
        )?;
        let mut target_time = authorization.authorized_target;
        let conservative_dependency = authorization.blocking_dependency;

        for event in &self.pending_events {
            if event.key.consumer() == &node.id {
                let event_time = SimInstant {
                    nanos: event.key.virtual_time().ticks,
                };
                if event_time > current_time && event_time < target_time {
                    target_time = event_time;
                }
            }
        }

        Ok(AdvanceWindow {
            target_time,
            quiescent_horizon: horizon.virtual_time,
            conservative_dependency,
        })
    }

    fn drive_authoritative_quantum(
        &mut self,
        request: QuantumRequest,
    ) -> Result<QuantumOutcome, SchedulerError> {
        if request.configuration != self.configuration {
            return Err(SchedulerError::BoundaryViolation {
                message: String::from(
                    "quantum request configuration is not the scheduler frontier",
                ),
            });
        }

        self.last_advance = None;

        self.yield_to_control_inbox(request.control);
        let mut resolved_events = self.drain_control_events();
        let candidate = match self.pick_global_minimum_horizon_node()? {
            Some(candidate) => candidate,
            None => {
                return Ok(QuantumOutcome {
                    configuration: self.configuration.clone(),
                    frontier: self.frontier,
                    advanced_node: None,
                    resolved_events,
                    decisions: Vec::new(),
                });
            }
        };

        let plan = {
            let critical_section = SchedulerCriticalSection::enter(self);
            critical_section.advance_plan(candidate)?
        };

        let selected_node = plan.node.clone();
        let before = plan.before;
        let (after, after_time, yielded_before_advance) = self.advance_node_after_yield(&plan)?;
        resolved_events.extend(self.resolve_events_for(&selected_node, after_time));

        let decision = Decision::DeliveryOrder(DeliveryOrderDecision {
            at: VirtualTime {
                ticks: after_time.nanos,
            },
            order: resolved_events
                .iter()
                .map(|event| EventKey {
                    sequence: event.key.sequence(),
                })
                .collect(),
        });
        self.advance_decision_rng_cursor();
        let configuration = step(&self.configuration, decision.clone());

        self.configuration = configuration.clone();
        self.frontier = frontier_for(&self.nodes, self.timeline.shift())?;
        self.quanta = self.quanta.saturating_add(1);
        self.last_advance = Some(NodeAdvance {
            node: selected_node.clone(),
            before,
            after,
            yielded_before_advance,
        });

        Ok(QuantumOutcome {
            configuration,
            frontier: self.frontier,
            advanced_node: Some(selected_node),
            resolved_events,
            decisions: vec![decision],
        })
    }

    fn yield_to_control_inbox(&mut self, control: Vec<ControlOperation>) {
        self.control_inbox.extend(control);
        self.boundary_yields = self.boundary_yields.saturating_add(1);
    }

    fn drain_control_events(&mut self) -> Vec<ScheduledEvent> {
        let mut control = std::mem::take(&mut self.control_inbox);
        control.sort();
        let node = SchedulerNodeId {
            node: NodeId {
                name: String::from("control-plane"),
            },
            kind: SchedulingNodeKind::ControlPlane,
        };

        control
            .into_iter()
            .map(|operation| ScheduledEvent {
                key: ScheduledEventKey::from_parts(
                    self.frontier,
                    node.clone(),
                    node.clone(),
                    operation.sequence,
                ),
                payload: ScheduledEventPayload::Control(operation),
            })
            .collect()
    }

    fn advance_decision_rng_cursor(&mut self) {
        let stream = RngStreamId::new(SCHEDULER_ACTOR_RNG_DOMAIN, SCHEDULER_QUANTUM_STREAM);
        let position = self
            .decision_rng_cursor
            .positions
            .entry(stream)
            .or_insert_with(|| RngStreamPosition::new(0));
        position.draws = position.draws.saturating_add(1);
    }

    fn resolve_events_for(
        &mut self,
        node: &SchedulerNodeId,
        advanced_to: SimInstant,
    ) -> Vec<ScheduledEvent> {
        let mut resolved = Vec::new();
        let mut pending = Vec::new();

        for event in self.pending_events.drain(..) {
            let due = SimInstant {
                nanos: event.key.virtual_time().ticks,
            };
            if event.key.consumer() == node && due <= advanced_to {
                resolved.push(event);
            } else {
                pending.push(event);
            }
        }

        self.pending_events = pending;
        ordered_scheduled_events(&resolved)
            .into_iter()
            .cloned()
            .collect()
    }

    fn advance_node_after_yield(
        &mut self,
        plan: &AdvancePlan,
    ) -> Result<(NodeCounter, SimInstant, bool), SchedulerError> {
        if self.lock_held {
            return Err(SchedulerError::BoundaryViolation {
                message: String::from("scheduler lock spans node advance"),
            });
        }

        let after = NodeCounter {
            ticks: plan.target_counter,
        };
        self.nodes[plan.index].counter = after;
        let after_time = after.to_virtual(self.timeline.shift())?;
        if after_time >= plan.quiescent_horizon {
            self.nodes[plan.index].activity = SchedulerNodeActivity::Idle;
        }

        Ok((after, after_time, true))
    }

    fn stalled_active_node(&self) -> Option<&RuntimeSchedulerNode> {
        self.nodes
            .iter()
            .find(|node| node.activity == SchedulerNodeActivity::Runnable)
    }
}

impl QuantumLoop for SingleScheduler {
    fn drive_quantum(&mut self, request: QuantumRequest) -> Result<QuantumOutcome, SchedulerError> {
        self.drive_authoritative_quantum(request)
    }
}

/// Drives the authoritative scheduler until it terminates or fails liveness.
///
/// # Errors
///
/// Returns [`SchedulerLivenessError`] when the scenario has no nodes, when the
/// scheduler detects deadlock or livelock, when it holds a lock across a node
/// advance, or when a lower-level scheduler operation fails.
pub fn check_scheduler_liveness(
    scenario: SchedulerLivenessScenario,
) -> Result<SchedulerLivenessReport, SchedulerLivenessError> {
    let mut scheduler = SingleScheduler::new(scenario)?;
    if scheduler.is_empty() {
        return Err(SchedulerLivenessError::EmptyScenario);
    }

    let mut advanced_nodes = Vec::new();
    let mut resolved_events = 0usize;
    let mut yielded_between_quanta = true;

    loop {
        if scheduler.reached_time_limit() || scheduler.exhausted_quantum_budget() {
            return Ok(SchedulerLivenessReport {
                terminal: SchedulerTerminal::TimeLimitReached,
                quanta: scheduler.quanta(),
                frontier: scheduler.frontier(),
                advanced_nodes,
                resolved_events,
                yielded_between_quanta,
                final_configuration: scheduler.configuration().clone(),
            });
        }

        if scheduler.is_quiescent() {
            return Ok(SchedulerLivenessReport {
                terminal: SchedulerTerminal::Quiescent,
                quanta: scheduler.quanta(),
                frontier: scheduler.frontier(),
                advanced_nodes,
                resolved_events,
                yielded_between_quanta,
                final_configuration: scheduler.configuration().clone(),
            });
        }

        let request = QuantumRequest {
            configuration: scheduler.configuration().clone(),
            control: Vec::new(),
        };
        let outcome = scheduler.drive_quantum(request)?;

        match &scheduler.last_advance {
            Some(advance) => {
                if advance.after <= advance.before {
                    return Err(SchedulerLivenessError::Livelock {
                        quantum: scheduler.quanta().saturating_sub(1),
                        node: advance.node.clone(),
                        counter: advance.before,
                    });
                }
                if !advance.yielded_before_advance {
                    return Err(SchedulerLivenessError::LockHeldAcrossAdvance {
                        quantum: scheduler.quanta().saturating_sub(1),
                        node: advance.node.clone(),
                    });
                }
                yielded_between_quanta &= advance.yielded_before_advance;
                advanced_nodes.push(advance.node.clone());
            }
            None => {
                if let Some(node) = scheduler.stalled_active_node() {
                    return Err(SchedulerLivenessError::Livelock {
                        quantum: scheduler.quanta(),
                        node: node.id.clone(),
                        counter: node.counter,
                    });
                }

                return Err(SchedulerLivenessError::Deadlock {
                    frontier: scheduler.frontier(),
                    pending_events: scheduler.pending_events.len(),
                });
            }
        }

        resolved_events += outcome.resolved_events.len();
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
struct RuntimeSchedulerNode {
    id: SchedulerNodeId,
    counter: NodeCounter,
    activity: SchedulerNodeActivity,
    network_horizon: SimInstant,
    exact_local_event: ExactLocalEvent,
}

impl From<SchedulerScenarioNode> for RuntimeSchedulerNode {
    fn from(node: SchedulerScenarioNode) -> Self {
        Self {
            id: node.id,
            counter: node.counter,
            activity: node.activity,
            network_horizon: node.network_horizon,
            exact_local_event: node.exact_local_event,
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
struct AdvanceCandidate {
    index: usize,
    key: SharedTimelineKey,
    target_time: SimInstant,
    quiescent_horizon: SimInstant,
    conservative_dependency: Option<UnresolvedCrossNodeDependency>,
}

#[derive(Clone, Debug, PartialEq, Eq)]
struct AdvanceWindow {
    target_time: SimInstant,
    quiescent_horizon: SimInstant,
    conservative_dependency: Option<UnresolvedCrossNodeDependency>,
}

#[derive(Clone, Debug, PartialEq, Eq)]
struct AdvancePlan {
    index: usize,
    node: SchedulerNodeId,
    before: NodeCounter,
    target_counter: u64,
    quiescent_horizon: SimInstant,
}

#[derive(Clone, Debug, PartialEq, Eq)]
struct NodeAdvance {
    node: SchedulerNodeId,
    before: NodeCounter,
    after: NodeCounter,
    yielded_before_advance: bool,
}

struct SchedulerCriticalSection<'a> {
    scheduler: &'a mut SingleScheduler,
}

impl<'a> SchedulerCriticalSection<'a> {
    fn enter(scheduler: &'a mut SingleScheduler) -> Self {
        scheduler.lock_held = true;
        Self { scheduler }
    }

    fn advance_plan(self, candidate: AdvanceCandidate) -> Result<AdvancePlan, SchedulerError> {
        let selected_index = candidate.index;
        let selected_node = self.scheduler.nodes[selected_index].id.clone();
        let before = self.scheduler.nodes[selected_index].counter;
        let target_counter = candidate
            .target_time
            .to_icount_ceil(self.scheduler.timeline.shift())?
            .retired;
        if let Some(dependency) = &candidate.conservative_dependency {
            let projected_target = NodeCounter {
                ticks: target_counter,
            }
            .to_virtual(self.scheduler.timeline.shift())?;
            if projected_target > dependency.virtual_time {
                return Err(SchedulerError::BoundaryViolation {
                    message: format!(
                        "conservative PDES rejected icount ceiling overshoot for {}:{:?}: dependency_at={} projected_target={}",
                        selected_node.node.name,
                        selected_node.kind,
                        dependency.virtual_time.nanos,
                        projected_target.nanos
                    ),
                });
            }
        }

        Ok(AdvancePlan {
            index: selected_index,
            node: selected_node,
            before,
            target_counter,
            quiescent_horizon: candidate.quiescent_horizon,
        })
    }
}

impl Drop for SchedulerCriticalSection<'_> {
    fn drop(&mut self) {
        self.scheduler.lock_held = false;
    }
}

fn frontier_for(
    nodes: &[RuntimeSchedulerNode],
    shift: Shift,
) -> Result<VirtualTime, SchedulerError> {
    let mut frontier = None;

    for node in nodes {
        let virtual_time = node.counter.to_virtual(shift)?;
        frontier = Some(match frontier {
            Some(current) => min_instant(current, virtual_time),
            None => virtual_time,
        });
    }

    Ok(VirtualTime {
        ticks: frontier.unwrap_or(SimInstant::EPOCH).nanos,
    })
}

fn min_instant(left: SimInstant, right: SimInstant) -> SimInstant {
    if left <= right { left } else { right }
}

/// An error produced by the scheduler boundary.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum SchedulerError {
    /// The scheduler behavior has not landed yet.
    NotImplemented {
        /// The deferred operation.
        operation: &'static str,
    },
    /// A backend operation failed while driven by the scheduler.
    Backend(BackendError),
    /// A component attempted to bypass the scheduler boundary.
    BoundaryViolation {
        /// Deterministic diagnostic text.
        message: String,
    },
    /// Virtual-time conversion failed while computing a scheduler horizon.
    TimeConversion(TimeConversionError),
}

impl fmt::Display for SchedulerError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::NotImplemented { operation } => {
                write!(f, "scheduler operation {operation} is not implemented yet")
            }
            Self::Backend(error) => write!(f, "backend failed under scheduler control: {error}"),
            Self::BoundaryViolation { message } => f.write_str(message),
            Self::TimeConversion(error) => {
                write!(f, "scheduler virtual-time conversion failed: {error}")
            }
        }
    }
}

impl Error for SchedulerError {}

impl From<BackendError> for SchedulerError {
    fn from(error: BackendError) -> Self {
        Self::Backend(error)
    }
}

impl From<TimeConversionError> for SchedulerError {
    fn from(error: TimeConversionError) -> Self {
        Self::TimeConversion(error)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{ScenarioDef, step};

    #[test]
    fn quantum_loop_trait_is_object_safe() {
        struct StubLoop;

        impl QuantumLoop for StubLoop {
            fn drive_quantum(
                &mut self,
                request: QuantumRequest,
            ) -> Result<QuantumOutcome, SchedulerError> {
                Ok(QuantumOutcome {
                    configuration: request.configuration,
                    frontier: VirtualTime { ticks: 0 },
                    advanced_node: None,
                    resolved_events: Vec::new(),
                    decisions: Vec::new(),
                })
            }
        }

        let config = Configuration::genesis(ScenarioDef::from_canonical_material(
            "crucible.test.scheduler.quantum-loop",
            "scenario=stub",
        ));
        let request = QuantumRequest {
            configuration: config.clone(),
            control: Vec::new(),
        };
        let mut loop_impl = StubLoop;
        let object: &mut dyn QuantumLoop = &mut loop_impl;

        let outcome = object.drive_quantum(request);

        assert_eq!(
            outcome.as_ref().map(|outcome| &outcome.configuration),
            Ok(&config)
        );
    }

    #[test]
    fn scheduled_event_keys_define_total_order() {
        let vm_a = scheduler_node("a", SchedulingNodeKind::Vm);
        let vm_b = scheduler_node("b", SchedulingNodeKind::Vm);
        let disk_a = scheduler_node("a", SchedulingNodeKind::Disk);
        let mut keys = [
            event_key(2, &vm_b, &vm_a, 0),
            event_key(1, &vm_b, &disk_a, 1),
            event_key(1, &vm_a, &disk_a, 2),
            event_key(1, &vm_a, &disk_a, 1),
        ];

        keys.sort();

        assert_eq!(
            keys,
            [
                event_key(1, &vm_a, &disk_a, 1),
                event_key(1, &vm_a, &disk_a, 2),
                event_key(1, &vm_b, &disk_a, 1),
                event_key(2, &vm_b, &vm_a, 0),
            ]
        );
    }

    #[test]
    fn scheduled_event_keys_cover_producer_tie_break() {
        let vm_a = scheduler_node("a", SchedulingNodeKind::Vm);
        let disk_a = scheduler_node("a", SchedulingNodeKind::Disk);
        let network_a = scheduler_node("a", SchedulingNodeKind::Network);
        let mut keys = [
            event_key(1, &vm_a, &network_a, 1),
            event_key(1, &vm_a, &disk_a, 1),
        ];

        keys.sort();

        assert_eq!(
            keys,
            [
                event_key(1, &vm_a, &disk_a, 1),
                event_key(1, &vm_a, &network_a, 1),
            ]
        );
    }

    #[test]
    fn scheduled_events_resolve_by_key_not_arrival_order() {
        let vm_a = scheduler_node("a", SchedulingNodeKind::Vm);
        let vm_b = scheduler_node("b", SchedulingNodeKind::Vm);
        let disk_a = scheduler_node("a", SchedulingNodeKind::Disk);
        let network_a = scheduler_node("a", SchedulingNodeKind::Network);
        let mut events = vec![
            event(1, &vm_b, &disk_a, 0, b"third"),
            event(2, &vm_a, &disk_a, 0, b"fourth"),
            event(1, &vm_a, &network_a, 1, b"second"),
            event(1, &vm_a, &disk_a, 7, b"first"),
        ];

        let payloads = ordered_scheduled_events(&events)
            .iter()
            .map(|event| match &event.payload {
                ScheduledEventPayload::BackendInput(input) => input.payload.clone(),
                _ => panic!("test event should carry a backend input"),
            })
            .collect::<Vec<_>>();

        assert_eq!(
            payloads,
            [
                b"first".to_vec(),
                b"second".to_vec(),
                b"third".to_vec(),
                b"fourth".to_vec(),
            ]
        );

        events.reverse();

        let reversed_payloads = ordered_scheduled_events(&events)
            .iter()
            .map(|event| match &event.payload {
                ScheduledEventPayload::BackendInput(input) => input.payload.clone(),
                _ => panic!("test event should carry a backend input"),
            })
            .collect::<Vec<_>>();

        assert_eq!(reversed_payloads, payloads);
    }

    #[test]
    fn shared_timeline_projects_vm_and_io_counters_uniformly() {
        let timeline = shared_timeline(2);
        let vm = scheduler_node("a", SchedulingNodeKind::Vm);
        let disk = scheduler_node("a", SchedulingNodeKind::Disk);
        let network = scheduler_node("link-a-b", SchedulingNodeKind::Network);

        let vm_projection = project_counter(
            &timeline,
            vm.clone(),
            NodeCounter::from_icount(Icount { retired: 7 }),
        );
        let disk_projection = project_counter(&timeline, disk.clone(), NodeCounter { ticks: 7 });
        let network_projection =
            project_counter(&timeline, network.clone(), NodeCounter { ticks: 11 });

        assert_eq!(vm_projection.node, vm);
        assert_eq!(vm_projection.counter, NodeCounter { ticks: 7 });
        assert_eq!(vm_projection.virtual_time, SimInstant { nanos: 28 });
        assert_eq!(disk_projection.node, disk);
        assert_eq!(disk_projection.virtual_time, SimInstant { nanos: 28 });
        assert_eq!(network_projection.node, network);
        assert_eq!(network_projection.virtual_time, SimInstant { nanos: 44 });
    }

    #[test]
    fn shared_timeline_keys_order_by_time_node_and_sequence() {
        let timeline = shared_timeline(1);
        let vm_a = scheduler_node("a", SchedulingNodeKind::Vm);
        let vm_b = scheduler_node("b", SchedulingNodeKind::Vm);
        let disk_a = scheduler_node("a", SchedulingNodeKind::Disk);
        let arrival_order = vec![
            timeline_key(&timeline, vm_b, 2, 0),
            timeline_key(&timeline, vm_a.clone(), 1, 5),
            timeline_key(&timeline, disk_a, 1, 2),
            timeline_key(&timeline, vm_a, 1, 1),
        ];

        let ordered = ordered_timeline_keys(&arrival_order);

        assert_eq!(
            ordered
                .iter()
                .map(|key| {
                    (
                        key.virtual_time.nanos,
                        key.node.node.name.as_str(),
                        key.node.kind,
                        key.sequence,
                    )
                })
                .collect::<Vec<_>>(),
            vec![
                (2, "a", SchedulingNodeKind::Vm, 1),
                (2, "a", SchedulingNodeKind::Vm, 5),
                (2, "a", SchedulingNodeKind::Disk, 2),
                (4, "b", SchedulingNodeKind::Vm, 0),
            ]
        );
    }

    #[test]
    fn scheduled_event_keys_consume_shared_timeline_and_refine_by_producer() {
        let timeline = shared_timeline(0);
        let vm_a = scheduler_node("a", SchedulingNodeKind::Vm);
        let disk_a = scheduler_node("a", SchedulingNodeKind::Disk);
        let network_a = scheduler_node("a", SchedulingNodeKind::Network);
        let mut keys = [
            ScheduledEventKey::new(
                timeline_key(&timeline, vm_a.clone(), 8, 9),
                network_a.clone(),
            ),
            ScheduledEventKey::new(timeline_key(&timeline, vm_a.clone(), 8, 3), disk_a.clone()),
            ScheduledEventKey::new(timeline_key(&timeline, vm_a.clone(), 8, 1), network_a),
        ];

        keys.sort();

        assert_eq!(
            keys.iter()
                .map(|key| (key.producer.kind, key.sequence()))
                .collect::<Vec<_>>(),
            vec![
                (SchedulingNodeKind::Disk, 3),
                (SchedulingNodeKind::Network, 1),
                (SchedulingNodeKind::Network, 9),
            ]
        );
    }

    #[test]
    fn quantum_outcome_carries_step_decisions() {
        let config = Configuration::genesis(ScenarioDef::from_canonical_material(
            "crucible.test.scheduler.quantum-outcome",
            "scenario=stub",
        ));
        let decision = crate::Decision::RngDraw(crate::RngDecision {
            stream: crate::RngStreamId::from_name("scheduler"),
            value: 7,
        });
        let child = step(&config, decision.clone());
        let outcome = QuantumOutcome {
            configuration: child,
            frontier: VirtualTime { ticks: 1 },
            advanced_node: Some(scheduler_node("node-a", SchedulingNodeKind::Vm)),
            resolved_events: Vec::new(),
            decisions: vec![decision.clone()],
        };

        assert_eq!(outcome.configuration.schedule.decisions(), &[decision]);
    }

    #[test]
    fn exact_local_deadline_selects_scheduler_horizon_and_ceiling() {
        let horizon = horizon_from_exact_local_event(
            SimInstant { nanos: 100 },
            ExactLocalEvent::TimerDeadline {
                virtual_time: SimInstant { nanos: 41 },
            },
            shift(3),
        );

        assert_eq!(
            horizon,
            Ok(SchedulerHorizon {
                virtual_time: SimInstant { nanos: 41 },
                ceiling: Icount { retired: 6 },
                source: SchedulerHorizonSource::ExactLocalTimer,
            })
        );
    }

    #[test]
    fn no_armed_timer_uses_network_horizon() {
        let horizon = horizon_from_exact_local_event(
            SimInstant { nanos: 64 },
            ExactLocalEvent::NoArmedTimer,
            shift(3),
        );

        assert_eq!(
            horizon,
            Ok(SchedulerHorizon {
                virtual_time: SimInstant { nanos: 64 },
                ceiling: Icount { retired: 8 },
                source: SchedulerHorizonSource::NetworkLookahead,
            })
        );
    }

    #[test]
    fn later_exact_deadline_does_not_extend_network_horizon() {
        let horizon = horizon_from_exact_local_event(
            SimInstant { nanos: 50 },
            ExactLocalEvent::TimerDeadline {
                virtual_time: SimInstant { nanos: 90 },
            },
            shift(2),
        );

        assert_eq!(
            horizon,
            Ok(SchedulerHorizon {
                virtual_time: SimInstant { nanos: 50 },
                ceiling: Icount { retired: 13 },
                source: SchedulerHorizonSource::NetworkLookahead,
            })
        );
    }

    #[test]
    fn exact_deadline_report_maps_to_scheduler_local_event() {
        assert_eq!(
            exact_local_event_from_timer_deadline_ns(Some(124_456)),
            ExactLocalEvent::TimerDeadline {
                virtual_time: SimInstant { nanos: 124_456 },
            }
        );
        assert_eq!(
            exact_local_event_from_timer_deadline_ns(None),
            ExactLocalEvent::NoArmedTimer
        );
    }

    #[test]
    fn scheduler_errors_render_all_variants_deterministically() {
        let backend = SchedulerError::from(BackendError::Rejected {
            message: String::from("backend refused"),
        });
        let boundary = SchedulerError::BoundaryViolation {
            message: String::from("bypassed scheduler boundary"),
        };
        let not_implemented = SchedulerError::NotImplemented { operation: "pick" };
        let conversion = SchedulerError::from(TimeConversionError::InvalidShift {
            shift: Shift { bits: 64 },
        });

        assert_eq!(
            not_implemented.to_string(),
            "scheduler operation pick is not implemented yet"
        );
        assert_eq!(
            backend.to_string(),
            "backend failed under scheduler control: backend refused"
        );
        assert_eq!(boundary.to_string(), "bypassed scheduler boundary");
        assert_eq!(
            conversion.to_string(),
            "scheduler virtual-time conversion failed: icount shift 64 cannot be represented as u64"
        );
    }

    fn scheduler_node(name: &str, kind: SchedulingNodeKind) -> SchedulerNodeId {
        SchedulerNodeId {
            node: NodeId {
                name: name.to_string(),
            },
            kind,
        }
    }

    fn shared_timeline(bits: u8) -> SharedTimeline {
        match SharedTimeline::new(shift(bits)) {
            Ok(timeline) => timeline,
            Err(error) => panic!("test timeline should be valid: {error}"),
        }
    }

    fn shift(bits: u8) -> Shift {
        match Shift::new(bits) {
            Ok(shift) => shift,
            Err(error) => panic!("test shift should be valid: {error}"),
        }
    }

    fn project_counter(
        timeline: &SharedTimeline,
        node: SchedulerNodeId,
        counter: NodeCounter,
    ) -> NodeTimelineProjection {
        match timeline.project_counter(node, counter) {
            Ok(projection) => projection,
            Err(error) => panic!("test counter should project: {error}"),
        }
    }

    fn timeline_key(
        timeline: &SharedTimeline,
        node: SchedulerNodeId,
        counter: u64,
        sequence: u64,
    ) -> SharedTimelineKey {
        match timeline.timeline_key(node, NodeCounter { ticks: counter }, sequence) {
            Ok(key) => key,
            Err(error) => panic!("test timeline key should project: {error}"),
        }
    }

    fn event_key(
        virtual_time: u64,
        consumer: &SchedulerNodeId,
        producer: &SchedulerNodeId,
        sequence: u64,
    ) -> ScheduledEventKey {
        ScheduledEventKey::from_parts(
            VirtualTime {
                ticks: virtual_time,
            },
            consumer.clone(),
            producer.clone(),
            sequence,
        )
    }

    fn event(
        virtual_time: u64,
        consumer: &SchedulerNodeId,
        producer: &SchedulerNodeId,
        sequence: u64,
        payload: &[u8],
    ) -> ScheduledEvent {
        ScheduledEvent {
            key: event_key(virtual_time, consumer, producer, sequence),
            payload: ScheduledEventPayload::BackendInput(BackendInput {
                node: consumer.node.clone(),
                payload: payload.to_vec(),
            }),
        }
    }
}
