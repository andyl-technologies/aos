//! Single-scheduler quantum-loop boundary.
//!
//! The module owns the L3 interface that all virtual-time advancement and
//! cross-node event resolution must pass through. It intentionally defines the
//! boundary and ordering vocabulary, implements the authoritative
//! PICK/RUN/RESOLVE/EMIT/STEP quantum boundary, and materializes scheduler
//! EMIT output as dense, content-addressed event-log segment bytes before STEP
//! advances the frontier.

use std::collections::VecDeque;
use std::error::Error;
use std::fmt;
use std::sync::mpsc::{self, Receiver, Sender, TryRecvError};

use crate::{
    BackendError, BackendInput, Configuration, ContentHash, Decision, DecisionRecorder,
    DecisionRngState, DeliveryOrderDecision, EventKey, EventLogOffset, EventSequenceState, FaultId,
    Icount, NodeCounter, NodeId, PreemptionKind, RngStreamId, RngStreamPosition, ScenarioDef,
    SchedulerNodeId, SchedulingNodeKind, Shift, SimDuration, SimInstant, TimeConversionError,
    VcpuId, VirtualTime, WorldLookaheadEdge, step,
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

/// Advances one bounded host-concurrent scheduler round.
///
/// Implementations may dispatch multiple independent RUN phases before
/// serializing their RESOLVE/EMIT/STEP completions through the scheduler.
pub trait ConcurrentQuantumLoop: QuantumLoop {
    /// Drives one bounded host-concurrent scheduler round.
    ///
    /// # Errors
    ///
    /// Returns [`SchedulerError`] when the round cannot be driven or when the
    /// scheduler detects an invalid boundary condition.
    fn drive_concurrent_quantum(
        &mut self,
        request: QuantumRequest,
        max_host_workers: usize,
    ) -> Result<SchedulerConcurrentQuantumOutcome, SchedulerError>;
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
    /// Event-log entries appended by EMIT in deterministic order.
    pub event_log_entries: Vec<SchedulerEventLogEntry>,
    /// Canonical bytes of the event-log segment appended by this quantum.
    pub event_log_segment_bytes: Vec<u8>,
    /// Content address of `event_log_segment_bytes`, when this quantum emitted a segment.
    pub event_log_segment_hash: Option<ContentHash>,
    /// Event-log offset after this quantum's EMIT segment.
    pub event_log_offset: EventLogOffset,
}

/// Output produced by one bounded host-concurrent scheduler round.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SchedulerConcurrentQuantumOutcome {
    /// RUN set selected from the same scheduler boundary before host dispatch.
    pub run_set: SchedulerConcurrentRunSet,
    /// Serialized scheduler completions for the dispatched RUN set.
    pub outcomes: Vec<QuantumOutcome>,
}

/// Deterministic set of RUNs eligible for host-level concurrent dispatch.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SchedulerConcurrentRunSet {
    /// Caller-supplied maximum host workers for this round.
    pub max_host_workers: usize,
    /// RUN candidates selected in deterministic scheduler completion order.
    pub candidates: Vec<SchedulerConcurrentRunCandidate>,
}

/// One node RUN selected for bounded host-level concurrent dispatch.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SchedulerConcurrentRunCandidate {
    /// Scheduler node selected by PICK for this concurrent round.
    pub node: SchedulerNodeId,
    /// Node-local virtual time before RUN.
    pub current_time: SimInstant,
    /// Conservative lookahead-bounded virtual time for this RUN.
    pub target_time: SimInstant,
    /// Icount ceiling published before host dispatch.
    pub max_advance_icount: u64,
}

/// One scheduler-emitted entry in the unified event log.
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub struct SchedulerEventLogEntry {
    /// Dense per-run sequence number assigned by the scheduler append path.
    pub sequence: u64,
    /// Virtual-time coordinate at which the entry occurred.
    pub at: VirtualTime,
    /// Causal-vs-observational class recorded by the typed append path.
    pub class: SchedulerEventLogClass,
    /// Typed payload carried by the event-log entry.
    pub payload: SchedulerEventLogPayload,
    /// Content address of this entry's canonical material.
    pub content_hash: ContentHash,
}

/// Determinism class for a scheduler event-log entry.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum SchedulerEventLogClass {
    /// Causal entries participate in deterministic replay comparison.
    Causal,
    /// Observational entries are descriptive and excluded from causal comparison.
    Observational,
}

/// Payload variants emitted by the scheduler EMIT phase.
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub enum SchedulerEventLogPayload {
    /// A resolved scheduler happening made visible this quantum.
    ResolvedHappening(ScheduledEvent),
    /// A decision taken and appended to the schedule this quantum.
    Decision(Decision),
}

/// Result of appending one scheduler quantum to the event log.
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub struct SchedulerEventLogAppend {
    /// Entries appended for this quantum.
    pub entries: Vec<SchedulerEventLogEntry>,
    /// Canonical bytes appended for this quantum's event-log segment.
    pub segment_bytes: Vec<u8>,
    /// Content address of `segment_bytes`, when a segment was appended.
    pub segment_hash: Option<ContentHash>,
    /// Offset reached after appending this quantum's segment.
    pub offset: EventLogOffset,
}

/// The single max-advance ceiling published for one RUN phase.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SchedulerRunCeilingPublication {
    /// Monotone index of this publication in the scheduler's publication log.
    pub sequence: u64,
    /// The quantum that published this ceiling.
    pub quantum: u64,
    /// The node selected by PICK for the RUN.
    pub node: SchedulerNodeId,
    /// The node counter observed before publishing the ceiling.
    pub current_icount: NodeCounter,
    /// The scheduler-published `max_advance_icount` ABI field value.
    pub max_advance_icount: u64,
    /// The fixed icount shift used to convert `target_time` into the ceiling.
    pub icount_shift: Shift,
    /// The virtual-time horizon that produced `max_advance_icount`.
    pub target_time: SimInstant,
}

/// Deterministic vCPU RR policy for one scheduler node.
#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct SchedulerRunSubdivisionPolicy {
    /// Scheduler node whose RUN budget is subdivided internally.
    pub node: SchedulerNodeId,
    /// Number of vCPUs hosted by the node.
    pub vcpu_count: u32,
    /// Fixed retired-instruction quantum used before rotating to the next vCPU.
    pub rr_switch_quantum: u64,
}

impl SchedulerRunSubdivisionPolicy {
    /// Builds a validated RR subdivision policy.
    ///
    /// # Errors
    ///
    /// Returns [`SchedulerError::BoundaryViolation`] when `vcpu_count` or
    /// `rr_switch_quantum` is zero.
    pub fn new(
        node: SchedulerNodeId,
        vcpu_count: u32,
        rr_switch_quantum: u64,
    ) -> Result<Self, SchedulerError> {
        validate_scheduler_rr_policy(vcpu_count, rr_switch_quantum)?;
        Ok(Self {
            node,
            vcpu_count,
            rr_switch_quantum,
        })
    }
}

/// One plugin-internal vCPU slice inside a node-level RUN.
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub struct SchedulerRunSubdivisionSlice {
    /// vCPU selected for this slice.
    pub vcpu: VcpuId,
    /// Node-local counter at which the slice starts.
    pub start_icount: NodeCounter,
    /// Node-local counter at which the slice ends.
    pub end_icount: NodeCounter,
}

/// Evidence that a node-level RUN used deterministic RR subdivision internally.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SchedulerRunSubdivisionRecord {
    /// Monotone scheduler-local subdivision record sequence.
    pub sequence: u64,
    /// Scheduler quantum whose RUN was subdivided.
    pub quantum: u64,
    /// Policy used to subdivide this RUN.
    pub policy: SchedulerRunSubdivisionPolicy,
    /// The single scheduler-published node ceiling for this RUN.
    pub ceiling: SchedulerRunCeilingPublication,
    /// Per-vCPU slices in plugin execution order.
    pub slices: Vec<SchedulerRunSubdivisionSlice>,
}

/// The virtual-time clock value used for scheduler lookahead decisions.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SchedulerEffectiveClock {
    /// The scheduler graph node whose clock was projected.
    pub node: SchedulerNodeId,
    /// The node's currently published virtual time.
    pub current_time: SimInstant,
    /// The effective clock used by the scheduler for lookahead and PICK.
    pub effective_time: SimInstant,
    /// The reason the effective clock has this value.
    pub source: SchedulerEffectiveClockSource,
}

/// The source of a scheduler effective-clock projection.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum SchedulerEffectiveClockSource {
    /// The node's effective clock is its current virtual time.
    Current,
    /// An idle node's effective clock is its exact wake time.
    IdleWake,
}

/// The scheduler-side cause for a boundary topology recompute.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum SchedulerTopologyChangeTrigger {
    /// A fault activation changed the effective topology or latency table.
    FaultActivation,
    /// A heal restored effective topology or latency state.
    Heal,
    /// A latency mutation changed the conservative lookahead bound.
    LatencyChange,
}

/// The topology effect applied at a scheduler quantum boundary.
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub enum SchedulerTopologyChangeEffect {
    /// Replaces the complete effective edge set.
    ReplaceEffectiveEdges(Vec<SchedulerLookaheadEdge>),
    /// Removes effective edges matching the listed directed endpoints.
    RemoveEffectiveEdges(Vec<SchedulerLookaheadEdgeEndpoint>),
    /// Restores effective edges into the current edge set.
    RestoreEffectiveEdges(Vec<SchedulerLookaheadEdge>),
}

/// A boundary-applied effective-topology mutation.
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub struct SchedulerTopologyChange {
    /// Session-local sequence number used to order same-boundary changes.
    pub sequence: u64,
    /// The reason this change requires a lookahead recompute.
    pub trigger: SchedulerTopologyChangeTrigger,
    /// Exact virtual time at which a fault-timed topology change takes effect.
    pub activation_time: Option<SimInstant>,
    /// The effective-topology effect to apply at the boundary.
    pub effect: SchedulerTopologyChangeEffect,
}

impl SchedulerTopologyChange {
    /// Builds a topology change from a complete effective edge-set replacement.
    #[must_use]
    pub fn new(
        sequence: u64,
        trigger: SchedulerTopologyChangeTrigger,
        effective_edges: Vec<SchedulerLookaheadEdge>,
    ) -> Self {
        Self {
            sequence,
            trigger,
            activation_time: None,
            effect: SchedulerTopologyChangeEffect::ReplaceEffectiveEdges(effective_edges),
        }
    }

    /// Builds a partition change that removes directed effective edges.
    #[must_use]
    pub fn partition(sequence: u64, removed_edges: Vec<SchedulerLookaheadEdgeEndpoint>) -> Self {
        Self {
            sequence,
            trigger: SchedulerTopologyChangeTrigger::FaultActivation,
            activation_time: None,
            effect: SchedulerTopologyChangeEffect::RemoveEffectiveEdges(removed_edges),
        }
    }

    /// Builds a heal change that restores directed effective edges.
    #[must_use]
    pub fn heal(sequence: u64, restored_edges: Vec<SchedulerLookaheadEdge>) -> Self {
        Self {
            sequence,
            trigger: SchedulerTopologyChangeTrigger::Heal,
            activation_time: None,
            effect: SchedulerTopologyChangeEffect::RestoreEffectiveEdges(restored_edges),
        }
    }

    /// Sets the exact activation virtual time for a fault-timed topology change.
    #[must_use]
    pub fn with_activation_time(mut self, activation_time: SimInstant) -> Self {
        self.activation_time = Some(activation_time);
        self
    }
}

fn topology_change_order(
    left: &SchedulerTopologyChange,
    right: &SchedulerTopologyChange,
) -> std::cmp::Ordering {
    left.sequence
        .cmp(&right.sequence)
        .then_with(|| left.trigger.cmp(&right.trigger))
        .then_with(|| left.activation_time.cmp(&right.activation_time))
}

/// One node lookahead value recomputed by a topology change.
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub struct SchedulerTopologyLookaheadUpdate {
    /// The scheduler node whose network lookahead was recomputed.
    pub node: SchedulerNodeId,
    /// The lookahead value used before the boundary change.
    pub previous_lookahead: NetworkLookahead,
    /// The lookahead value derived from the new effective edge set.
    pub recomputed_lookahead: NetworkLookahead,
}

/// Evidence that a topology change was applied at a quantum boundary.
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub struct SchedulerTopologyChangeApplication {
    /// Monotone scheduler topology epoch after this application.
    pub topology_epoch: u64,
    /// Session-local sequence number of the applied topology change.
    pub sequence: u64,
    /// The reason this change required a lookahead recompute.
    pub trigger: SchedulerTopologyChangeTrigger,
    /// Exact activation rendezvous time, when the change was fault-timed.
    pub activation_time: Option<SimInstant>,
    /// Per-node lookahead updates in canonical scheduler-node order.
    pub updates: Vec<SchedulerTopologyLookaheadUpdate>,
}

/// Authorization for emitting one cross-node frame under the current topology.
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub struct SchedulerSendAuthorization {
    /// The producer scheduler node.
    pub producer: SchedulerNodeId,
    /// The consumer scheduler node.
    pub consumer: SchedulerNodeId,
    /// The topology epoch under which this send was authorized.
    pub topology_epoch: u64,
}

/// Authorizes cross-node frame emission against scheduler topology state.
pub trait SchedulerSendAuthorizer {
    /// Authorizes one producer-to-consumer frame under the current topology.
    ///
    /// # Errors
    ///
    /// Returns [`SchedulerError`] when sends are frozen by a pending topology
    /// change or the effective edge set does not contain the requested edge.
    fn authorize_cross_node_send(
        &self,
        producer: &SchedulerNodeId,
        consumer: &SchedulerNodeId,
    ) -> Result<SchedulerSendAuthorization, SchedulerError>;
}

#[cfg(feature = "test-double")]
impl SchedulerRunCeilingPublication {
    /// Converts this scheduler publication to the shared-memory ABI ceiling.
    ///
    /// # Errors
    ///
    /// Returns [`crucible_shmem::LookaheadGateError`] when the publication is not
    /// a valid max-advance ceiling under the shared-memory lookahead gate.
    pub fn to_shmem_ceiling(
        &self,
    ) -> Result<crucible_shmem::AdvanceCeiling, crucible_shmem::LookaheadGateError> {
        crucible_shmem::authorize_advance_ceiling(
            self.current_icount.ticks,
            self.max_advance_icount,
            None,
        )
    }

    /// Publishes pending inputs, this ceiling, and the wake through shmem.
    ///
    /// Pending inputs are appended to their directed inboxes before the node
    /// slot ceiling is release-stored and its futex word is incremented.
    ///
    /// # Errors
    ///
    /// Returns [`SchedulerRunCeilingHandoffError`] when the publication cannot
    /// be authorized as a shared-memory ceiling, or when the shared-memory
    /// region rejects an inbox, ceiling, or wake publication.
    pub fn publish_to_shmem_after_inputs(
        &self,
        region: &mut crucible_shmem::RegionAllocation,
        dst_slot: u32,
        pending_inputs: &[crucible_shmem::PendingInputPublication],
    ) -> Result<crucible_shmem::SchedulerWakePublication, SchedulerRunCeilingHandoffError> {
        let ceiling = self.to_shmem_ceiling()?;
        Ok(region.publish_scheduler_inputs_and_ceiling(dst_slot, pending_inputs, ceiling)?)
    }
}

/// An error produced while handing a scheduler RUN ceiling to shmem.
#[cfg(feature = "test-double")]
#[derive(Clone, Debug, thiserror::Error, PartialEq, Eq)]
pub enum SchedulerRunCeilingHandoffError {
    /// The scheduler publication did not authorize as an ABI ceiling.
    #[error("scheduler RUN ceiling could not be authorized for shared memory")]
    Authorization {
        /// Underlying lookahead-gate error.
        #[from]
        source: crucible_shmem::LookaheadGateError,
    },
    /// The shared-memory region rejected the ordered publication.
    #[error("scheduler RUN ceiling shared-memory publication failed")]
    Publication {
        /// Underlying shared-memory publication error.
        #[from]
        source: crucible_shmem::SchedulerWakePublicationError,
    },
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
    /// Boundary-applied control operations in scheduler application order.
    pub control_applications: Vec<SchedulerControlApplication>,
    /// Number of quantum boundaries at which the scheduler yielded to control.
    pub boundary_yields: u64,
}

/// A message-only scheduler actor that owns the authoritative scheduler state.
#[derive(Debug)]
pub struct SchedulerActor {
    scheduler: SingleScheduler,
    inbox: Receiver<SchedulerActorMessage>,
    deferred: VecDeque<SchedulerActorMessage>,
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
    QueueTopologyChange(SchedulerTopologyChange),
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
            Self::QueueTopologyChange(change) => formatter
                .debug_tuple("QueueTopologyChange")
                .field(change)
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
                deferred: VecDeque::new(),
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
        if let Some(message) = self.deferred.pop_front() {
            self.apply_message(message)?;
            return Ok(true);
        }

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
            SchedulerActorMessage::QueueTopologyChange(change) => {
                self.scheduler.queue_topology_change(change);
                Ok(())
            }
            SchedulerActorMessage::DriveQuantum { request, reply } => {
                self.drain_boundary_messages_before_quantum();
                reply
                    .send(self.scheduler.drive_quantum(request))
                    .map_err(|_| SchedulerActorError::ReplyDropped)
            }
            SchedulerActorMessage::Snapshot { reply } => reply
                .send(self.scheduler.actor_state_snapshot())
                .map_err(|_| SchedulerActorError::ReplyDropped),
        }
    }

    fn drain_boundary_messages_before_quantum(&mut self) {
        loop {
            match self.inbox.try_recv() {
                Ok(SchedulerActorMessage::QueueControl(operation)) => {
                    self.scheduler.queue_control(operation);
                }
                Ok(SchedulerActorMessage::QueueTopologyChange(change)) => {
                    self.scheduler.queue_topology_change(change);
                }
                Ok(message) => {
                    self.deferred.push_back(message);
                }
                Err(TryRecvError::Empty | TryRecvError::Disconnected) => break,
            }
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

    /// Queues a topology change for the next scheduler quantum boundary.
    ///
    /// Fault, heal, and latency-control paths use this message to freeze
    /// cross-node sends until the actor applies the new effective edge set and
    /// recomputes lookahead before the next PICK.
    ///
    /// # Errors
    ///
    /// Returns [`SchedulerActorError::MailboxClosed`] when the actor has already
    /// stopped receiving messages.
    pub fn queue_topology_change(
        &self,
        change: SchedulerTopologyChange,
    ) -> Result<(), SchedulerActorError> {
        self.send(SchedulerActorMessage::QueueTopologyChange(change))
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

/// Maximum allowed scheduler-side control application latency in quanta.
pub const SCHEDULER_CONTROL_RESPONSE_BOUND_QUANTA: u64 = 1;

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

/// Evidence that one scheduler control operation applied at a quantum boundary.
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub struct SchedulerControlApplication {
    /// Monotone scheduler-local control application sequence.
    pub sequence: u64,
    /// Control operation that was applied by the scheduler boundary.
    pub operation: ControlOperation,
    /// Scheduler quantum count visible when the operation was accepted.
    pub accepted_after_quanta: u64,
    /// Scheduler quantum count whose boundary applied the operation.
    pub applied_in_quantum: u64,
    /// Application latency measured in scheduler quanta.
    pub application_delta_quanta: u64,
    /// Boundary yield count visible when the operation was accepted.
    pub accepted_after_boundary_yield: u64,
    /// Boundary yield count whose boundary applied the operation.
    pub applied_at_boundary_yield: u64,
    /// Scheduler event key emitted for the applied control operation.
    pub event_key: ScheduledEventKey,
}

#[derive(Clone, Debug, PartialEq, Eq)]
struct SchedulerControlAdmission {
    operation: ControlOperation,
    accepted_after_quanta: u64,
    accepted_after_boundary_yield: u64,
}

#[derive(Clone, Debug, PartialEq, Eq)]
struct SchedulerControlDrain {
    events: Vec<ScheduledEvent>,
    applications: Vec<SchedulerControlApplication>,
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

/// Directed endpoint identity for one scheduler lookahead edge.
#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct SchedulerLookaheadEdgeEndpoint {
    /// The scheduler node that can produce a future network event.
    pub from: SchedulerNodeId,
    /// The scheduler node that can receive the future network event.
    pub to: SchedulerNodeId,
}

impl SchedulerLookaheadEdgeEndpoint {
    /// Builds one directed scheduler lookahead edge endpoint.
    #[must_use]
    pub fn new(from: SchedulerNodeId, to: SchedulerNodeId) -> Self {
        Self { from, to }
    }
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

    /// Returns this edge's directed endpoint identity.
    #[must_use]
    pub fn endpoint(&self) -> SchedulerLookaheadEdgeEndpoint {
        SchedulerLookaheadEdgeEndpoint {
            from: self.from.clone(),
            to: self.to.clone(),
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

    /// Returns whether the current effective edge set allows `from -> to`.
    #[must_use]
    pub fn has_edge(&self, from: &SchedulerNodeId, to: &SchedulerNodeId) -> bool {
        self.edges
            .iter()
            .any(|edge| &edge.from == from && &edge.to == to)
    }

    /// Removes all edges matching the listed directed endpoints.
    #[must_use]
    pub fn remove_effective_edges<I>(&self, endpoints: I) -> Self
    where
        I: IntoIterator<Item = SchedulerLookaheadEdgeEndpoint>,
    {
        let mut endpoints = endpoints.into_iter().collect::<Vec<_>>();
        endpoints.sort();
        endpoints.dedup();
        Self::from_edges(
            self.edges
                .iter()
                .filter(|edge| endpoints.binary_search(&edge.endpoint()).is_err())
                .cloned(),
        )
    }

    /// Restores directed edges into the current effective edge set.
    #[must_use]
    pub fn restore_effective_edges<I>(&self, restored_edges: I) -> Self
    where
        I: IntoIterator<Item = SchedulerLookaheadEdge>,
    {
        Self::from_edges(self.edges.iter().cloned().chain(restored_edges))
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

    /// Converts a finite scheduler horizon to a node max-advance icount.
    ///
    /// This is the SCHED-34/TIME-4 boundary: horizon arithmetic stays in
    /// virtual time, and the timeline's fixed shift maps that horizon to the
    /// first icount boundary at or after it.
    ///
    /// # Errors
    ///
    /// Returns [`TimeConversionError::InvalidShift`] when the fixed shift cannot
    /// name a `u64` power-of-two scale.
    pub fn max_advance_icount_for_horizon(
        &self,
        horizon: SimInstant,
    ) -> Result<Icount, TimeConversionError> {
        horizon.to_icount_ceil(self.shift)
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
/// explicitly depend on `(virtual_time, consumer node, producer node, sequence)`.
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

/// Allocates a scheduled-event key from saved producer/consumer sequence state.
///
/// # Errors
///
/// Returns [`SchedulerError::BoundaryViolation`] when the next sequence number
/// for the producer/consumer pair cannot be incremented.
pub fn next_scheduled_event_key(
    sequences: &mut EventSequenceState,
    virtual_time: VirtualTime,
    consumer: SchedulerNodeId,
    producer: SchedulerNodeId,
) -> Result<ScheduledEventKey, SchedulerError> {
    let sequence = sequences.next_sequence(&producer, &consumer);
    let next = sequence
        .checked_add(1)
        .ok_or_else(|| SchedulerError::BoundaryViolation {
            message: format!(
                "scheduled event sequence overflow for producer {} consumer {}",
                producer.node.name, consumer.node.name
            ),
        })?;
    sequences.set_next_sequence(producer.clone(), consumer.clone(), next);
    Ok(ScheduledEventKey::from_parts(
        virtual_time,
        consumer,
        producer,
        sequence,
    ))
}

/// A due event resolved by the scheduler.
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub struct ScheduledEvent {
    /// The canonical ordering key.
    pub key: ScheduledEventKey,
    /// The resolved event payload.
    pub payload: ScheduledEventPayload,
}

/// The RESOLVE payload class for a scheduled event.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum ScheduledEventResolveClass {
    /// A deterministic frame or backend input delivery.
    FrameDelivery,
    /// A deterministic I/O completion from a scheduler sub-node.
    IoCompletion,
    /// A planned fault activation.
    FaultActivation,
    /// A probabilistic fault choice resolved by the scheduler.
    ProbabilisticFault,
    /// A control-plane operation admitted at the boundary.
    Control,
}

/// A probabilistic fault choice attached to a scheduled RESOLVE event.
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub struct SchedulerResolveFaultChoice {
    /// The fault whose probabilistic outcome is being resolved.
    pub fault: FaultId,
    /// The seeded decision-RNG stream used for this choice.
    pub stream: RngStreamId,
    /// The raw draw threshold below which the fault fires.
    pub fire_below: u64,
}

/// The decisions recorded while resolving probabilistic RESOLVE choices.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SchedulerResolveDecisionRecord {
    /// The configuration after all recorded probabilistic decisions.
    pub configuration: Configuration,
    /// The decisions appended while resolving probabilistic choices.
    pub decisions: Vec<Decision>,
}

/// Returns scheduled events in the canonical deterministic resolution order.
#[must_use]
pub fn ordered_scheduled_events(events: &[ScheduledEvent]) -> Vec<&ScheduledEvent> {
    let mut ordered = events.iter().collect::<Vec<_>>();

    ordered.sort_by(|left, right| left.key.cmp(&right.key));

    ordered
}

/// Returns the RESOLVE payload class for `event`.
#[must_use]
pub fn scheduled_event_resolve_class(event: &ScheduledEvent) -> ScheduledEventResolveClass {
    match event.payload {
        ScheduledEventPayload::BackendInput(_) => ScheduledEventResolveClass::FrameDelivery,
        ScheduledEventPayload::IoCompletion(_) => ScheduledEventResolveClass::IoCompletion,
        ScheduledEventPayload::FaultActivation(_) => ScheduledEventResolveClass::FaultActivation,
        ScheduledEventPayload::ProbabilisticFault(_) => {
            ScheduledEventResolveClass::ProbabilisticFault
        }
        ScheduledEventPayload::Control(_) => ScheduledEventResolveClass::Control,
    }
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
    /// A probabilistic fault outcome resolved at the boundary.
    ProbabilisticFault(SchedulerResolveFaultChoice),
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

/// A node-local exact event supplied by host-held scheduler state.
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub enum ExactLocalEvent {
    /// The node has no exact local wakeup.
    NoArmedTimer,
    /// The node has an armed guest timer at an exact virtual-time point.
    TimerDeadline {
        /// The exact virtual-time deadline from the backend's virtual clock.
        virtual_time: SimInstant,
    },
    /// The node has an in-flight deterministic I/O completion.
    IoCompletion {
        /// The exact virtual-time completion point.
        virtual_time: SimInstant,
        /// The sub-node that computed the deterministic completion.
        sub_node: SchedulerNodeId,
    },
    /// The node has a locally scheduled fault activation.
    FaultActivation {
        /// The exact virtual-time activation point.
        virtual_time: SimInstant,
        /// The fault that will activate locally.
        fault: FaultId,
    },
}

impl ExactLocalEvent {
    /// Returns this event's exact virtual-time point, if it has one.
    #[must_use]
    pub fn virtual_time(&self) -> Option<SimInstant> {
        match self {
            Self::NoArmedTimer => None,
            Self::TimerDeadline { virtual_time }
            | Self::IoCompletion { virtual_time, .. }
            | Self::FaultActivation { virtual_time, .. } => Some(*virtual_time),
        }
    }
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

/// Builds an exact local deterministic I/O completion event.
///
/// # Errors
///
/// Returns [`SchedulerError::TimeConversion`] when `delivery_icount` cannot be
/// converted under `shift`.
pub fn exact_local_event_from_io_completion(
    completion: &IoCompletion,
    shift: Shift,
) -> Result<ExactLocalEvent, SchedulerError> {
    Ok(ExactLocalEvent::IoCompletion {
        virtual_time: completion.delivery_icount.to_virtual(shift)?,
        sub_node: completion.sub_node.clone(),
    })
}

/// Extracts a target-local exact event from a scheduled event.
///
/// Backend input is intentionally excluded because guest-to-guest network input
/// is the conservative lookahead term, not an exact local wakeup.
///
/// # Errors
///
/// Returns [`SchedulerError::TimeConversion`] when an I/O completion delivery
/// icount cannot be converted under `shift`, or
/// [`SchedulerError::BoundaryViolation`] when a completion key disagrees with
/// its payload target or delivery point.
pub fn exact_local_event_from_scheduled_event(
    node: &SchedulerNodeId,
    event: &ScheduledEvent,
    shift: Shift,
) -> Result<Option<ExactLocalEvent>, SchedulerError> {
    if event.key.consumer() != node {
        return Ok(None);
    }

    match &event.payload {
        ScheduledEventPayload::IoCompletion(completion) => {
            if completion.target != node.node {
                return Err(SchedulerError::BoundaryViolation {
                    message: format!(
                        "I/O completion key consumer {} does not match payload target {}",
                        node.node.name, completion.target.name
                    ),
                });
            }
            let exact = exact_local_event_from_io_completion(completion, shift)?;
            let expected_time =
                exact
                    .virtual_time()
                    .ok_or_else(|| SchedulerError::BoundaryViolation {
                        message: String::from(
                            "I/O completion did not produce an exact local event",
                        ),
                    })?;
            let key_time = SimInstant {
                nanos: event.key.virtual_time().ticks,
            };
            if key_time != expected_time {
                return Err(SchedulerError::BoundaryViolation {
                    message: format!(
                        "I/O completion key time {} does not match delivery icount time {}",
                        key_time.nanos, expected_time.nanos
                    ),
                });
            }
            Ok(Some(exact))
        }
        ScheduledEventPayload::FaultActivation(fault) => {
            Ok(Some(ExactLocalEvent::FaultActivation {
                virtual_time: SimInstant {
                    nanos: event.key.virtual_time().ticks,
                },
                fault: fault.clone(),
            }))
        }
        ScheduledEventPayload::BackendInput(_)
        | ScheduledEventPayload::ProbabilisticFault(_)
        | ScheduledEventPayload::Control(_) => Ok(None),
    }
}

/// Returns the exact virtual time at which a scheduled event becomes visible.
///
/// # Errors
///
/// Returns [`SchedulerError::TimeConversion`] when an I/O completion delivery
/// icount cannot be converted under `shift`, or
/// [`SchedulerError::BoundaryViolation`] when the event key and payload disagree
/// about the consumer or exact delivery point.
pub fn scheduled_event_delivery_time(
    event: &ScheduledEvent,
    shift: Shift,
) -> Result<SimInstant, SchedulerError> {
    match &event.payload {
        ScheduledEventPayload::BackendInput(input) => {
            if input.node != event.key.consumer().node {
                return Err(SchedulerError::BoundaryViolation {
                    message: format!(
                        "backend input key consumer {} does not match payload target {}",
                        event.key.consumer().node.name,
                        input.node.name
                    ),
                });
            }
            Ok(SimInstant {
                nanos: event.key.virtual_time().ticks,
            })
        }
        ScheduledEventPayload::IoCompletion(_) => {
            let exact = exact_local_event_from_scheduled_event(event.key.consumer(), event, shift)?
                .ok_or_else(|| SchedulerError::BoundaryViolation {
                    message: String::from(
                        "I/O completion did not produce a RESOLVE visibility time",
                    ),
                })?;
            exact
                .virtual_time()
                .ok_or_else(|| SchedulerError::BoundaryViolation {
                    message: String::from("I/O completion visibility time was empty"),
                })
        }
        ScheduledEventPayload::FaultActivation(_)
        | ScheduledEventPayload::ProbabilisticFault(_)
        | ScheduledEventPayload::Control(_) => Ok(SimInstant {
            nanos: event.key.virtual_time().ticks,
        }),
    }
}

/// Drains every event due for `consumer` and returns it in RESOLVE order.
///
/// Events are due when their exact delivery time is exactly `advanced_to`.
/// Returned events are ordered by the canonical key `(virtual_time, consumer
/// node, producer node, sequence)` and removed from `pending_events`; all other
/// events remain queued. If an event for `consumer` is already behind
/// `advanced_to`, the scheduler rejects it rather than delivering it late.
///
/// # Errors
///
/// Returns [`SchedulerError`] when a due event cannot prove the exact virtual
/// time at which it becomes visible to its consumer, or when an event's exact
/// delivery time is before `advanced_to`.
pub fn resolve_due_scheduled_events(
    pending_events: &mut Vec<ScheduledEvent>,
    consumer: &SchedulerNodeId,
    advanced_to: SimInstant,
    shift: Shift,
) -> Result<Vec<ScheduledEvent>, SchedulerError> {
    let mut resolved = Vec::new();
    let mut pending = Vec::with_capacity(pending_events.len());

    for event in pending_events.iter() {
        if event.key.consumer() == consumer {
            let key_time = SimInstant {
                nanos: event.key.virtual_time().ticks,
            };
            if key_time <= advanced_to {
                let delivery_time = scheduled_event_delivery_time(event, shift)?;
                if delivery_time < advanced_to {
                    return Err(SchedulerError::BoundaryViolation {
                        message: format!(
                            "late scheduled event for {}:{:?}: delivery={} advanced_to={} producer={}:{:?} sequence={}",
                            consumer.node.name,
                            consumer.kind,
                            delivery_time.nanos,
                            advanced_to.nanos,
                            event.key.producer().node.name,
                            event.key.producer().kind,
                            event.key.sequence(),
                        ),
                    });
                }
                if delivery_time == advanced_to {
                    resolved.push(event.clone());
                    continue;
                }
            }
        }
        pending.push(event.clone());
    }

    let ordered = ordered_scheduled_events(&resolved)
        .into_iter()
        .cloned()
        .collect();
    *pending_events = pending;

    Ok(ordered)
}

/// Records every probabilistic RESOLVE choice in canonical event order.
///
/// Only [`ScheduledEventPayload::ProbabilisticFault`] payloads produce decisions.
/// For each such event, this helper draws from the payload's seeded stream and
/// records the raw [`Decision::RngDraw`] followed by the derived
/// [`Decision::FaultFires`] outcome. Non-probabilistic events are ignored.
#[must_use]
pub fn resolve_probabilistic_decisions(
    configuration: Configuration,
    resolved_events: &[ScheduledEvent],
) -> SchedulerResolveDecisionRecord {
    let mut recorder = DecisionRecorder::new(configuration);
    let mut decisions = Vec::new();

    for event in ordered_scheduled_events(resolved_events) {
        let ScheduledEventPayload::ProbabilisticFault(choice) = &event.payload else {
            continue;
        };

        let before = recorder.schedule().len();
        recorder.decide_fault(
            event.key.virtual_time(),
            choice.fault.clone(),
            choice.stream.clone(),
            choice.fire_below,
        );
        decisions.extend_from_slice(&recorder.schedule().decisions()[before..]);
    }

    SchedulerResolveDecisionRecord {
        configuration: recorder.into_configuration(),
        decisions,
    }
}

/// Selects the earliest exact local event for `node`.
///
/// The inputs are exact, host-computed wakeups: an optional timer deadline plus
/// scheduled deterministic I/O completions and locally scheduled faults.
///
/// # Errors
///
/// Returns [`SchedulerError::TimeConversion`] when an I/O completion delivery
/// icount cannot be converted under `shift`, or
/// [`SchedulerError::BoundaryViolation`] when an I/O completion key disagrees
/// with its payload target or delivery point.
pub fn next_exact_local_event(
    node: &SchedulerNodeId,
    timer_deadline: ExactLocalEvent,
    scheduled_events: &[ScheduledEvent],
    shift: Shift,
) -> Result<ExactLocalEvent, SchedulerError> {
    let mut candidates = Vec::new();
    if !matches!(timer_deadline, ExactLocalEvent::NoArmedTimer) {
        candidates.push(timer_deadline);
    }

    for event in scheduled_events {
        if let Some(candidate) = exact_local_event_from_scheduled_event(node, event, shift)? {
            candidates.push(candidate);
        }
    }

    candidates.sort_by(|left, right| {
        left.virtual_time()
            .cmp(&right.virtual_time())
            .then_with(|| exact_local_event_rank(left).cmp(&exact_local_event_rank(right)))
            .then_with(|| {
                exact_local_event_source_key(left).cmp(&exact_local_event_source_key(right))
            })
    });

    Ok(candidates
        .into_iter()
        .next()
        .unwrap_or(ExactLocalEvent::NoArmedTimer))
}

fn exact_local_event_rank(event: &ExactLocalEvent) -> u8 {
    match event {
        ExactLocalEvent::NoArmedTimer => 0,
        ExactLocalEvent::TimerDeadline { .. } => 1,
        ExactLocalEvent::IoCompletion { .. } => 2,
        ExactLocalEvent::FaultActivation { .. } => 3,
    }
}

fn exact_local_event_source_key(event: &ExactLocalEvent) -> &str {
    match event {
        ExactLocalEvent::NoArmedTimer | ExactLocalEvent::TimerDeadline { .. } => "",
        ExactLocalEvent::IoCompletion { sub_node, .. } => &sub_node.node.name,
        ExactLocalEvent::FaultActivation { fault, .. } => &fault.name,
    }
}

/// The source that selected a scheduler horizon.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum SchedulerHorizonSource {
    /// The conservative network lookahead selected the horizon.
    NetworkLookahead,
    /// An exact local guest timer selected the horizon.
    ExactLocalTimer,
    /// An exact local deterministic I/O completion selected the horizon.
    ExactLocalIoCompletion,
    /// An exact local scheduled fault selected the horizon.
    ExactLocalFault,
}

/// The scheduler rendezvous frequency knob.
///
/// A rendezvous is a common exact cap used for global bookkeeping work. It may
/// split node advancement into more quanta, but it is not an event-delivery clock
/// and must not add canonical schedule material by itself.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Hash)]
pub struct SchedulerRendezvous {
    interval: Option<SimDuration>,
}

impl SchedulerRendezvous {
    /// Builds a disabled rendezvous policy.
    #[must_use]
    pub fn disabled() -> Self {
        Self { interval: None }
    }

    /// Builds a fixed-interval rendezvous policy.
    ///
    /// # Errors
    ///
    /// Returns [`SchedulerError::BoundaryViolation`] when `interval` is zero,
    /// because a zero-width rendezvous cannot advance the shared timeline.
    pub fn every(interval: SimDuration) -> Result<Self, SchedulerError> {
        if interval.nanos == 0 {
            return Err(SchedulerError::BoundaryViolation {
                message: String::from("scheduler rendezvous interval must be nonzero"),
            });
        }
        Ok(Self {
            interval: Some(interval),
        })
    }

    /// Returns the configured fixed interval, if rendezvous is enabled.
    #[must_use]
    pub fn interval(self) -> Option<SimDuration> {
        self.interval
    }

    /// Returns the next rendezvous boundary after `current_time`.
    ///
    /// # Errors
    ///
    /// Returns [`SchedulerError::BoundaryViolation`] if the next fixed interval
    /// boundary cannot be represented as a `u64` virtual-time point.
    pub fn next_after(
        self,
        current_time: SimInstant,
    ) -> Result<Option<SimInstant>, SchedulerError> {
        rendezvous_cap_for(current_time, self)
    }
}

/// The only scheduler-visible purposes that may use a global rendezvous.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum SchedulerRendezvousPurpose {
    /// Drains the assertion engine at a globally consistent virtual time.
    AssertionDrain,
    /// Evaluates global triggers at a globally consistent virtual time.
    TriggerEvaluation,
    /// Swaps effective topology at an exact activation virtual time.
    TopologySwap,
    /// Captures or coordinates a globally consistent snapshot.
    SnapshotControl,
}

/// One active node observed at a scheduler rendezvous.
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub struct SchedulerRendezvousNode {
    /// The scheduler graph node participating in the rendezvous.
    pub node: SchedulerNodeId,
    /// The exact virtual time observed for the node.
    pub virtual_time: SimInstant,
}

/// Evidence that an allowed scheduler rendezvous occurred.
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub struct SchedulerRendezvousRecord {
    /// Monotone scheduler-local rendezvous record sequence.
    pub sequence: u64,
    /// The scheduler-visible reason this rendezvous was used.
    pub purpose: SchedulerRendezvousPurpose,
    /// The exact shared virtual time for the rendezvous.
    pub virtual_time: SimInstant,
    /// Active nodes observed at the exact rendezvous time.
    pub nodes: Vec<SchedulerRendezvousNode>,
}

/// Computes the exact rendezvous cap after `current_time`.
///
/// # Errors
///
/// Returns [`SchedulerError::BoundaryViolation`] if the next fixed interval
/// boundary cannot be represented as a `u64` virtual-time point.
pub fn rendezvous_cap_for(
    current_time: SimInstant,
    rendezvous: SchedulerRendezvous,
) -> Result<Option<SimInstant>, SchedulerError> {
    let Some(interval) = rendezvous.interval() else {
        return Ok(None);
    };
    let tick = current_time.nanos / interval.nanos;
    let next_tick = tick
        .checked_add(1)
        .ok_or_else(|| SchedulerError::BoundaryViolation {
            message: String::from("scheduler rendezvous tick overflow"),
        })?;
    let nanos =
        next_tick
            .checked_mul(interval.nanos)
            .ok_or_else(|| SchedulerError::BoundaryViolation {
                message: String::from("scheduler rendezvous virtual-time overflow"),
            })?;
    Ok(Some(SimInstant { nanos }))
}

/// Computes plugin-internal RR slices for one node-level RUN ceiling.
///
/// The returned slices are ordered exactly as the plugin should execute them.
/// The scheduler still publishes only the node-level `max_advance_icount`;
/// these slices are evidence for the deterministic internal vCPU rotation.
///
/// # Errors
///
/// Returns [`SchedulerError::BoundaryViolation`] when the RR policy is invalid,
/// the target is before the current counter, or the next RR boundary overflows.
pub fn scheduler_rr_run_subdivision(
    current_icount: NodeCounter,
    max_advance_icount: u64,
    vcpu_count: u32,
    rr_switch_quantum: u64,
) -> Result<Vec<SchedulerRunSubdivisionSlice>, SchedulerError> {
    validate_scheduler_rr_policy(vcpu_count, rr_switch_quantum)?;
    if max_advance_icount < current_icount.ticks {
        return Err(SchedulerError::BoundaryViolation {
            message: format!(
                "scheduler RR subdivision target precedes current icount: current={} target={}",
                current_icount.ticks, max_advance_icount
            ),
        });
    }
    if vcpu_count == 1 {
        if current_icount.ticks == max_advance_icount {
            return Ok(Vec::new());
        }
        return Ok(vec![SchedulerRunSubdivisionSlice {
            vcpu: VcpuId { index: 0 },
            start_icount: current_icount,
            end_icount: NodeCounter {
                ticks: max_advance_icount,
            },
        }]);
    }

    let mut slices = Vec::new();
    let mut cursor = current_icount.ticks;
    while cursor < max_advance_icount {
        let rr_slot = cursor / rr_switch_quantum;
        let vcpu = VcpuId {
            index: (rr_slot % u64::from(vcpu_count)) as u32,
        };
        let next_rr_boundary = rr_slot
            .checked_add(1)
            .and_then(|slot| slot.checked_mul(rr_switch_quantum))
            .ok_or_else(|| SchedulerError::BoundaryViolation {
                message: String::from("scheduler RR subdivision boundary overflow"),
            })?;
        let end = std::cmp::min(next_rr_boundary, max_advance_icount);
        slices.push(SchedulerRunSubdivisionSlice {
            vcpu,
            start_icount: NodeCounter { ticks: cursor },
            end_icount: NodeCounter { ticks: end },
        });
        cursor = end;
    }

    Ok(slices)
}

fn validate_scheduler_rr_policy(
    vcpu_count: u32,
    rr_switch_quantum: u64,
) -> Result<(), SchedulerError> {
    if vcpu_count == 0 {
        return Err(SchedulerError::BoundaryViolation {
            message: String::from("scheduler RR subdivision vCPU count must be nonzero"),
        });
    }
    if rr_switch_quantum == 0 {
        return Err(SchedulerError::BoundaryViolation {
            message: String::from("scheduler RR subdivision quantum must be nonzero"),
        });
    }
    Ok(())
}

/// A scheduler horizon and its matching icount ceiling.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub struct SchedulerHorizon {
    /// The selected horizon limit.
    pub limit: SchedulerHorizonLimit,
    /// The input that selected the horizon.
    pub source: SchedulerHorizonSource,
}

impl SchedulerHorizon {
    /// Builds a finite horizon and its matching icount ceiling.
    ///
    /// # Errors
    ///
    /// Returns [`SchedulerError::TimeConversion`] when `virtual_time` cannot be
    /// converted under `shift`.
    pub fn finite(
        virtual_time: SimInstant,
        source: SchedulerHorizonSource,
        shift: Shift,
    ) -> Result<Self, SchedulerError> {
        let timeline = SharedTimeline::new(shift)?;
        Ok(Self {
            limit: SchedulerHorizonLimit::Finite {
                virtual_time,
                ceiling: timeline.max_advance_icount_for_horizon(virtual_time)?,
            },
            source,
        })
    }

    /// Builds an unbounded horizon selected by the network-lookahead term.
    #[must_use]
    pub fn infinite_network() -> Self {
        Self {
            limit: SchedulerHorizonLimit::Infinite,
            source: SchedulerHorizonSource::NetworkLookahead,
        }
    }

    /// Returns the finite virtual-time horizon, if one exists.
    #[must_use]
    pub fn virtual_time(self) -> Option<SimInstant> {
        match self.limit {
            SchedulerHorizonLimit::Finite { virtual_time, .. } => Some(virtual_time),
            SchedulerHorizonLimit::Infinite => None,
        }
    }

    /// Returns the finite icount ceiling, if one exists.
    #[must_use]
    pub fn ceiling(self) -> Option<Icount> {
        match self.limit {
            SchedulerHorizonLimit::Finite { ceiling, .. } => Some(ceiling),
            SchedulerHorizonLimit::Infinite => None,
        }
    }
}

/// A finite or unbounded scheduler horizon limit.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum SchedulerHorizonLimit {
    /// The node must synchronize at a finite virtual-time point.
    Finite {
        /// The selected virtual-time horizon.
        virtual_time: SimInstant,
        /// The icount ceiling computed with the fixed-shift `ceil` conversion.
        ceiling: Icount,
    },
    /// The network term is unbounded because no inbound live link exists.
    Infinite,
}

/// Computes the network horizon limit from current virtual time and lookahead.
///
/// # Errors
///
/// Returns [`SchedulerError::TimeConversion`] when the finite network horizon
/// cannot be converted under `shift`.
pub fn network_horizon_from_lookahead(
    current_time: SimInstant,
    network_lookahead: NetworkLookahead,
    shift: Shift,
) -> Result<SchedulerHorizonLimit, SchedulerError> {
    match network_lookahead {
        NetworkLookahead::Finite(duration) => {
            let virtual_time = current_time + duration;
            let timeline = SharedTimeline::new(shift)?;
            Ok(SchedulerHorizonLimit::Finite {
                virtual_time,
                ceiling: timeline.max_advance_icount_for_horizon(virtual_time)?,
            })
        }
        NetworkLookahead::Infinite => Ok(SchedulerHorizonLimit::Infinite),
    }
}

/// Computes `horizon(n) = min(next_exact_local_event(n), vt(n) + lookahead(n))`.
///
/// The exact-local term is used as an absolute virtual-time point with no
/// conservative slack. The network term is derived only from the conservative
/// guest-to-guest [`NetworkLookahead`].
///
/// # Errors
///
/// Returns [`SchedulerError::TimeConversion`] when the selected finite horizon
/// cannot be converted under `shift`.
pub fn horizon_from_network_lookahead(
    current_time: SimInstant,
    network_lookahead: NetworkLookahead,
    exact_local_event: ExactLocalEvent,
    shift: Shift,
) -> Result<SchedulerHorizon, SchedulerError> {
    let network_limit = network_horizon_from_lookahead(current_time, network_lookahead, shift)?;
    let exact_time = exact_local_event.virtual_time();
    match (exact_time, network_limit) {
        (None, SchedulerHorizonLimit::Infinite) => Ok(SchedulerHorizon::infinite_network()),
        (None, SchedulerHorizonLimit::Finite { virtual_time, .. }) => SchedulerHorizon::finite(
            virtual_time,
            SchedulerHorizonSource::NetworkLookahead,
            shift,
        ),
        (Some(virtual_time), SchedulerHorizonLimit::Infinite) => SchedulerHorizon::finite(
            virtual_time,
            exact_local_event_horizon_source(&exact_local_event),
            shift,
        ),
        (
            Some(virtual_time),
            SchedulerHorizonLimit::Finite {
                virtual_time: network_time,
                ..
            },
        ) if virtual_time <= network_time => SchedulerHorizon::finite(
            virtual_time,
            exact_local_event_horizon_source(&exact_local_event),
            shift,
        ),
        (
            Some(_),
            SchedulerHorizonLimit::Finite {
                virtual_time: network_time,
                ..
            },
        ) => SchedulerHorizon::finite(
            network_time,
            SchedulerHorizonSource::NetworkLookahead,
            shift,
        ),
    }
}

fn exact_local_event_horizon_source(event: &ExactLocalEvent) -> SchedulerHorizonSource {
    match event {
        ExactLocalEvent::TimerDeadline { .. } => SchedulerHorizonSource::ExactLocalTimer,
        ExactLocalEvent::IoCompletion { .. } => SchedulerHorizonSource::ExactLocalIoCompletion,
        ExactLocalEvent::FaultActivation { .. } => SchedulerHorizonSource::ExactLocalFault,
        ExactLocalEvent::NoArmedTimer => SchedulerHorizonSource::NetworkLookahead,
    }
}

fn horizon_source_allows_ceiling_past_target(source: SchedulerHorizonSource) -> bool {
    matches!(
        source,
        SchedulerHorizonSource::ExactLocalTimer
            | SchedulerHorizonSource::ExactLocalIoCompletion
            | SchedulerHorizonSource::ExactLocalFault
    )
}

fn scheduler_ceiling_overshoot_error(
    node: &SchedulerNodeId,
    boundary_label: &str,
    boundary_time: SimInstant,
    projected_target: SimInstant,
) -> SchedulerError {
    SchedulerError::BoundaryViolation {
        message: format!(
            "conservative PDES rejected icount ceiling overshoot for {}:{:?}: {boundary_label}={} projected_target={}",
            node.node.name, node.kind, boundary_time.nanos, projected_target.nanos
        ),
    }
}

/// Computes the scheduler horizon from network lookahead and the exact local event.
///
/// Exact local timer, I/O completion, and fault activation deadlines are
/// consumed as local horizon candidates. A node with no exact local event uses
/// the conservative network horizon. The selected virtual-time horizon is
/// converted to the node's target icount with `SimInstant::to_icount_ceil`.
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
    horizon_from_network_lookahead(
        SimInstant::EPOCH,
        NetworkLookahead::Finite(network_horizon.duration_since(SimInstant::EPOCH)),
        exact_local_event,
        shift,
    )
}

/// One generated node consumed by the scheduler liveness gate.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SchedulerScenarioNode {
    /// The scheduler graph node to advance.
    pub id: SchedulerNodeId,
    /// The node-local counter at the start of the run.
    pub counter: NodeCounter,
    /// The node's effective scheduling state at the start of the run.
    pub activity: SchedulerNodeActivity,
    /// The conservative cross-node lookahead for this node.
    pub network_lookahead: NetworkLookahead,
    /// The exact local timer, I/O completion, fault, or idle report for this node.
    pub exact_local_event: ExactLocalEvent,
}

/// The generated liveness activity state for one scheduler node.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum SchedulerNodeActivity {
    /// The node has work and may be selected by PICK.
    Runnable,
    /// The node is idle, has no local timer or I/O work, and cannot advance.
    Idle,
    /// The node is halted and contributes an infinite effective horizon.
    Halted,
    /// The node is complete and is never selected by PICK.
    Done,
}

/// A finite scheduler scenario for checking quantum-loop liveness.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SchedulerLivenessScenario {
    /// Author-supplied scenario material that names this generated scenario.
    pub authored_material: String,
    /// The configuration whose schedule records scheduler decisions.
    pub configuration: Configuration,
    /// The fixed icount-to-virtual-time shift for every node in the scenario.
    pub shift: Shift,
    /// The maximum number of quanta allowed before the scenario time-limits.
    pub quantum_budget: u64,
    /// The virtual-time limit that also terminates the scenario.
    pub time_limit: SimInstant,
    /// The exact shared rendezvous cap policy.
    pub rendezvous: SchedulerRendezvous,
    /// The current effective scheduler edge set, when known to this scenario.
    pub effective_topology: SchedulerLookaheadGraph,
    /// The generated nodes driven by the authoritative scheduler.
    ///
    /// A runnable generated node becomes [`SchedulerNodeActivity::Idle`] once it
    /// reaches the horizon selected from its exact local event and network
    /// lookahead.
    pub nodes: Vec<SchedulerScenarioNode>,
    /// Boundary-applied topology changes waiting for the scheduler.
    pub topology_changes: Vec<SchedulerTopologyChange>,
    /// Optional deterministic RR subdivision policies keyed by scheduler node.
    pub run_subdivision_policies: Vec<SchedulerRunSubdivisionPolicy>,
    /// Cross-node, I/O, fault, and control events waiting for scheduler delivery.
    pub pending_events: Vec<ScheduledEvent>,
    /// Saved per-producer/consumer sequence counters for newly emitted events.
    pub event_sequences: EventSequenceState,
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
        let mut scenario = Self {
            authored_material: material.to_owned(),
            configuration: Configuration::genesis(ScenarioDef::from_canonical_material_with_seed(
                "crucible.scheduler-liveness.authored",
                material,
                crate::Seed::default(),
            )),
            shift,
            quantum_budget,
            time_limit,
            rendezvous: SchedulerRendezvous::disabled(),
            effective_topology: SchedulerLookaheadGraph::default(),
            nodes,
            topology_changes: Vec::new(),
            run_subdivision_policies: Vec::new(),
            pending_events,
            event_sequences: EventSequenceState::empty(),
        };
        scenario.refresh_configuration();
        scenario
    }

    /// Builds the effective scheduler configuration from scenario-owned state.
    #[must_use]
    pub fn canonical_configuration(&self) -> Configuration {
        Configuration {
            def: ScenarioDef::from_canonical_material_with_seed(
                "crucible.scheduler-liveness.scenario.v1",
                &scheduler_liveness_scenario_material(self),
                self.configuration.def.seed(),
            ),
            schedule: self.configuration.schedule.clone(),
        }
    }

    /// Enables fixed-interval rendezvous caps for this scenario.
    ///
    /// # Errors
    ///
    /// Returns [`SchedulerError::BoundaryViolation`] when `interval` is zero.
    pub fn with_rendezvous_interval(
        mut self,
        interval: SimDuration,
    ) -> Result<Self, SchedulerError> {
        self.rendezvous = SchedulerRendezvous::every(interval)?;
        self.refresh_configuration();
        Ok(self)
    }

    /// Replaces the scenario's effective topology and recomputes node lookahead.
    #[must_use]
    pub fn with_effective_topology_edges(mut self, edges: Vec<SchedulerLookaheadEdge>) -> Self {
        self.effective_topology = SchedulerLookaheadGraph::from_edges(edges);
        recompute_scenario_node_lookahead(&mut self.nodes, &self.effective_topology);
        self.refresh_configuration();
        self
    }

    /// Queues a topology change for the next quantum boundary.
    #[must_use]
    pub fn with_topology_change(mut self, change: SchedulerTopologyChange) -> Self {
        self.topology_changes.push(change);
        self.topology_changes.sort_by(topology_change_order);
        self.refresh_configuration();
        self
    }

    /// Sets the deterministic RR subdivision policy for one scheduler node.
    #[must_use]
    pub fn with_run_subdivision_policy(mut self, policy: SchedulerRunSubdivisionPolicy) -> Self {
        self.run_subdivision_policies
            .retain(|existing| existing.node != policy.node);
        self.run_subdivision_policies.push(policy);
        self.run_subdivision_policies.sort();
        self.refresh_configuration();
        self
    }

    fn refresh_configuration(&mut self) {
        self.configuration = self.canonical_configuration();
    }
}

fn scheduler_liveness_scenario_material(scenario: &SchedulerLivenessScenario) -> String {
    let mut lines = Vec::new();
    lines.push(format!(
        "authored_material_len={}",
        scenario.authored_material.len()
    ));
    lines.push(format!("authored_material={}", scenario.authored_material));
    lines.push(format!("shift_bits={}", scenario.shift.bits));
    lines.push(format!("quantum_budget={}", scenario.quantum_budget));
    lines.push(format!("time_limit_ns={}", scenario.time_limit.nanos));
    lines.push(format!(
        "effective_topology_edges={}",
        scenario.effective_topology.edges().len()
    ));
    lines.extend(
        scenario
            .effective_topology
            .edges()
            .iter()
            .map(scheduler_lookahead_edge_material),
    );
    let mut nodes = scenario.nodes.clone();
    nodes.sort_by(|left, right| left.id.cmp(&right.id));
    lines.push(format!("nodes={}", nodes.len()));
    lines.extend(nodes.iter().map(scheduler_scenario_node_material));

    let mut topology_changes = scenario.topology_changes.clone();
    topology_changes.sort_by(topology_change_order);
    lines.push(format!("topology_changes={}", topology_changes.len()));
    lines.extend(topology_changes.iter().map(topology_change_material));

    let mut run_subdivision_policies = scenario.run_subdivision_policies.clone();
    run_subdivision_policies.sort();
    lines.push(format!(
        "run_subdivision_policies={}",
        run_subdivision_policies.len()
    ));
    lines.extend(
        run_subdivision_policies
            .iter()
            .map(run_subdivision_policy_material),
    );

    let pending = ordered_scheduled_events(&scenario.pending_events);
    lines.push(format!("pending_events={}", pending.len()));
    lines.extend(pending.into_iter().map(scheduled_event_material));

    lines.push(format!(
        "event_sequences={}",
        scenario.event_sequences.next.len()
    ));
    for (key, next) in &scenario.event_sequences.next {
        lines.push(format!(
            "sequence_producer:\n{}\nsequence_consumer:\n{}\nsequence_next={next}",
            scheduler_node_material(&key.producer),
            scheduler_node_material(&key.consumer),
        ));
    }

    lines.join("\n")
}

fn recompute_scenario_node_lookahead(
    nodes: &mut [SchedulerScenarioNode],
    topology: &SchedulerLookaheadGraph,
) {
    for node in nodes {
        node.network_lookahead = topology.lookahead(&node.id);
    }
}

fn scheduler_scenario_node_material(node: &SchedulerScenarioNode) -> String {
    format!(
        "node:\n{}\ncounter_ticks={}\nactivity={}\n{}\n{}",
        scheduler_node_material(&node.id),
        node.counter.ticks,
        scheduler_node_activity_label(node.activity),
        network_lookahead_material(node.network_lookahead),
        exact_local_event_material(&node.exact_local_event),
    )
}

fn run_subdivision_policy_material(policy: &SchedulerRunSubdivisionPolicy) -> String {
    format!(
        "run_subdivision_policy:\n{}\nvcpu_count={}\nrr_switch_quantum={}",
        scheduler_node_material(&policy.node),
        policy.vcpu_count,
        policy.rr_switch_quantum,
    )
}

fn scheduler_lookahead_edge_material(edge: &SchedulerLookaheadEdge) -> String {
    format!(
        "edge:\nedge_from:\n{}\nedge_to:\n{}\nedge_minimum_latency_ns={}",
        scheduler_node_material(&edge.from),
        scheduler_node_material(&edge.to),
        edge.minimum_latency.nanos,
    )
}

fn topology_change_material(change: &SchedulerTopologyChange) -> String {
    let mut lines = Vec::new();
    lines.push(format!("topology_change_sequence={}", change.sequence));
    lines.push(format!(
        "topology_change_trigger={}",
        topology_change_trigger_label(change.trigger)
    ));
    lines.push(match change.activation_time {
        Some(activation_time) => format!(
            "topology_change_activation_time_ns={}",
            activation_time.nanos
        ),
        None => String::from("topology_change_activation_time_ns=none"),
    });
    match &change.effect {
        SchedulerTopologyChangeEffect::ReplaceEffectiveEdges(effective_edges) => {
            let graph = SchedulerLookaheadGraph::from_edges(effective_edges.clone());
            lines.push(String::from(
                "topology_change_effect=replace-effective-edges",
            ));
            lines.push(format!(
                "topology_change_effective_edges={}",
                graph.edges().len()
            ));
            lines.extend(graph.edges().iter().map(scheduler_lookahead_edge_material));
        }
        SchedulerTopologyChangeEffect::RemoveEffectiveEdges(endpoints) => {
            let mut endpoints = endpoints.clone();
            endpoints.sort();
            endpoints.dedup();
            lines.push(String::from(
                "topology_change_effect=remove-effective-edges",
            ));
            lines.push(format!("topology_change_removed_edges={}", endpoints.len()));
            lines.extend(
                endpoints
                    .iter()
                    .map(scheduler_lookahead_edge_endpoint_material),
            );
        }
        SchedulerTopologyChangeEffect::RestoreEffectiveEdges(restored_edges) => {
            let graph = SchedulerLookaheadGraph::from_edges(restored_edges.clone());
            lines.push(String::from(
                "topology_change_effect=restore-effective-edges",
            ));
            lines.push(format!(
                "topology_change_restored_edges={}",
                graph.edges().len()
            ));
            lines.extend(graph.edges().iter().map(scheduler_lookahead_edge_material));
        }
    }
    lines.join("\n")
}

fn topology_change_trigger_label(trigger: SchedulerTopologyChangeTrigger) -> &'static str {
    match trigger {
        SchedulerTopologyChangeTrigger::FaultActivation => "fault-activation",
        SchedulerTopologyChangeTrigger::Heal => "heal",
        SchedulerTopologyChangeTrigger::LatencyChange => "latency-change",
    }
}

fn scheduler_node_material(node: &SchedulerNodeId) -> String {
    format!(
        "node_name_len={}\nnode_name={}\nnode_kind={}",
        node.node.name.len(),
        node.node.name,
        scheduling_node_kind_label(node.kind),
    )
}

fn scheduler_lookahead_edge_endpoint_material(endpoint: &SchedulerLookaheadEdgeEndpoint) -> String {
    format!(
        "edge_endpoint:\nedge_from:\n{}\nedge_to:\n{}",
        scheduler_node_material(&endpoint.from),
        scheduler_node_material(&endpoint.to),
    )
}

fn scheduler_node_activity_label(activity: SchedulerNodeActivity) -> &'static str {
    match activity {
        SchedulerNodeActivity::Runnable => "runnable",
        SchedulerNodeActivity::Idle => "idle",
        SchedulerNodeActivity::Halted => "halted",
        SchedulerNodeActivity::Done => "done",
    }
}

fn scheduling_node_kind_label(kind: SchedulingNodeKind) -> &'static str {
    match kind {
        SchedulingNodeKind::Vm => "vm",
        SchedulingNodeKind::Disk => "disk",
        SchedulingNodeKind::NineP => "9p",
        SchedulingNodeKind::Network => "network",
        SchedulingNodeKind::ControlPlane => "control-plane",
    }
}

fn network_lookahead_material(lookahead: NetworkLookahead) -> String {
    match lookahead {
        NetworkLookahead::Finite(duration) => {
            format!(
                "network_lookahead=finite\nnetwork_lookahead_ns={}",
                duration.nanos
            )
        }
        NetworkLookahead::Infinite => String::from("network_lookahead=infinite"),
    }
}

fn exact_local_event_material(event: &ExactLocalEvent) -> String {
    match event {
        ExactLocalEvent::NoArmedTimer => String::from("exact_local_event=none"),
        ExactLocalEvent::TimerDeadline { virtual_time } => {
            format!(
                "exact_local_event=timer\nexact_local_event_ns={}",
                virtual_time.nanos
            )
        }
        ExactLocalEvent::IoCompletion {
            virtual_time,
            sub_node,
        } => format!(
            "exact_local_event=io\nexact_local_event_ns={}\nexact_local_sub_node:\n{}",
            virtual_time.nanos,
            scheduler_node_material(sub_node),
        ),
        ExactLocalEvent::FaultActivation {
            virtual_time,
            fault,
        } => format!(
            "exact_local_event=fault\nexact_local_event_ns={}\nfault_name_len={}\nfault_name={}",
            virtual_time.nanos,
            fault.name.len(),
            fault.name,
        ),
    }
}

fn scheduled_event_material(event: &ScheduledEvent) -> String {
    format!(
        "event:\n{}\n{}",
        scheduled_event_key_material(&event.key),
        scheduled_event_payload_material(&event.payload),
    )
}

fn scheduled_event_key_material(key: &ScheduledEventKey) -> String {
    format!(
        "event_time={}\nevent_consumer:\n{}\nevent_producer:\n{}\nevent_sequence={}",
        key.virtual_time().ticks,
        scheduler_node_material(key.consumer()),
        scheduler_node_material(key.producer()),
        key.sequence(),
    )
}

fn scheduled_event_payload_material(payload: &ScheduledEventPayload) -> String {
    match payload {
        ScheduledEventPayload::BackendInput(input) => format!(
            "payload=backend-input\npayload_node_len={}\npayload_node={}\npayload_bytes={}",
            input.node.name.len(),
            input.node.name,
            hex_bytes(&input.payload),
        ),
        ScheduledEventPayload::IoCompletion(completion) => format!(
            "payload=io-completion\npayload_sub_node:\n{}\npayload_target_len={}\npayload_target={}\npayload_delivery_icount={}\npayload_bytes={}",
            scheduler_node_material(&completion.sub_node),
            completion.target.name.len(),
            completion.target.name,
            completion.delivery_icount.retired,
            hex_bytes(&completion.payload),
        ),
        ScheduledEventPayload::FaultActivation(fault) => format!(
            "payload=fault-activation\npayload_fault_len={}\npayload_fault={}",
            fault.name.len(),
            fault.name,
        ),
        ScheduledEventPayload::ProbabilisticFault(choice) => format!(
            "payload=probabilistic-fault\npayload_fault_len={}\npayload_fault={}\npayload_stream_domain_len={}\npayload_stream_domain={}\npayload_stream_name_len={}\npayload_stream_name={}\npayload_fire_below={}",
            choice.fault.name.len(),
            choice.fault.name,
            choice.stream.domain.len(),
            choice.stream.domain,
            choice.stream.name.len(),
            choice.stream.name,
            choice.fire_below,
        ),
        ScheduledEventPayload::Control(operation) => format!(
            "payload=control\ncontrol_sequence={}\ncontrol_kind={}",
            operation.sequence,
            control_operation_kind_label(operation.kind),
        ),
    }
}

fn control_operation_kind_label(kind: ControlOperationKind) -> &'static str {
    match kind {
        ControlOperationKind::Pause => "pause",
        ControlOperationKind::Resume => "resume",
        ControlOperationKind::Step => "step",
        ControlOperationKind::Snapshot => "snapshot",
        ControlOperationKind::Fork => "fork",
        ControlOperationKind::Inject => "inject",
        ControlOperationKind::Query => "query",
    }
}

fn hex_bytes(bytes: &[u8]) -> String {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    let mut encoded = String::with_capacity(bytes.len().saturating_mul(2));
    for byte in bytes {
        encoded.push(HEX[(byte >> 4) as usize] as char);
        encoded.push(HEX[(byte & 0x0f) as usize] as char);
    }
    encoded
}

fn scheduler_event_log_empty_prefix() -> ContentHash {
    ContentHash::from_canonical_material("crucible.scheduler.event-log.prefix.v1", "empty=true")
}

fn scheduler_event_log_sequence(base: u64, offset: usize) -> Result<u64, SchedulerError> {
    let offset = u64::try_from(offset).map_err(|_| SchedulerError::BoundaryViolation {
        message: String::from("scheduler event-log entry offset exceeds u64"),
    })?;
    base.checked_add(offset)
        .ok_or_else(|| SchedulerError::BoundaryViolation {
            message: String::from("scheduler event-log sequence overflow"),
        })
}

fn scheduler_event_log_entry(
    sequence: u64,
    at: VirtualTime,
    payload: SchedulerEventLogPayload,
) -> SchedulerEventLogEntry {
    let content_hash = ContentHash::from_canonical_material(
        "crucible.scheduler.event-log.entry.v1",
        &scheduler_event_log_entry_material(sequence, at, &payload),
    );
    SchedulerEventLogEntry {
        sequence,
        at,
        class: SchedulerEventLogClass::Causal,
        payload,
        content_hash,
    }
}

fn scheduler_event_log_entry_material(
    sequence: u64,
    at: VirtualTime,
    payload: &SchedulerEventLogPayload,
) -> String {
    let mut lines = Vec::new();
    lines.push(format!("sequence={sequence}"));
    lines.push(format!("at_ticks={}", at.ticks));
    lines.push(String::from("class=causal"));
    match payload {
        SchedulerEventLogPayload::ResolvedHappening(event) => {
            lines.push(String::from("payload=resolved-happening"));
            lines.push(scheduled_event_material(event));
        }
        SchedulerEventLogPayload::Decision(decision) => {
            lines.push(String::from("payload=decision"));
            lines.push(scheduler_decision_material(decision));
        }
    }
    lines.join("\n")
}

fn scheduler_event_log_segment_bytes(
    previous_prefix: ContentHash,
    entries: &[SchedulerEventLogEntry],
) -> Vec<u8> {
    let mut lines = Vec::new();
    lines.push(String::from(
        "format=crucible.scheduler.event-log.segment.v1",
    ));
    lines.push(format!("previous_prefix={}", previous_prefix.to_hex()));
    lines.push(format!("entries={}", entries.len()));
    for entry in entries {
        let entry_material =
            scheduler_event_log_entry_material(entry.sequence, entry.at, &entry.payload);
        lines.push(format!("entry.sequence={}", entry.sequence));
        lines.push(format!("entry.at_ticks={}", entry.at.ticks));
        lines.push(format!("entry.hash={}", entry.content_hash.to_hex()));
        lines.push(format!("entry.bytes={}", entry_material.len()));
        lines.push(String::from("entry.material_begin"));
        lines.push(entry_material);
        lines.push(String::from("entry.material_end"));
    }
    lines.join("\n").into_bytes()
}

fn scheduler_decision_event_log_time(decision: &Decision, fallback: SimInstant) -> VirtualTime {
    match decision {
        Decision::DeliveryOrder(order) => order.at,
        Decision::FaultFires(fault) => fault.at,
        Decision::RngDraw(_)
        | Decision::Override(_)
        | Decision::Preemption(_)
        | Decision::AppRandom(_) => VirtualTime {
            ticks: fallback.nanos,
        },
    }
}

fn scheduler_decision_material(decision: &Decision) -> String {
    let mut lines = Vec::new();
    match decision {
        Decision::DeliveryOrder(order) => {
            lines.push(String::from("decision=delivery-order"));
            lines.push(format!("decision_at={}", order.at.ticks));
            lines.push(format!("decision_events={}", order.order.len()));
            for event in &order.order {
                lines.push(format!("event_time={}", event.virtual_time.ticks));
                lines.push(format!(
                    "event_consumer:\n{}",
                    scheduler_node_material(&event.consumer)
                ));
                lines.push(format!(
                    "event_producer:\n{}",
                    scheduler_node_material(&event.producer)
                ));
                lines.push(format!("event_sequence={}", event.sequence));
            }
        }
        Decision::FaultFires(fault) => {
            lines.push(String::from("decision=fault-fires"));
            lines.push(format!("decision_at={}", fault.at.ticks));
            lines.push(format!("fault_name_len={}", fault.fault.name.len()));
            lines.push(format!("fault_name={}", fault.fault.name));
            lines.push(format!("fired={}", fault.fired));
        }
        Decision::RngDraw(draw) => {
            lines.push(String::from("decision=rng-draw"));
            lines.push(format!("stream_domain_len={}", draw.stream.domain.len()));
            lines.push(format!("stream_domain={}", draw.stream.domain));
            lines.push(format!("stream_name_len={}", draw.stream.name.len()));
            lines.push(format!("stream_name={}", draw.stream.name));
            lines.push(format!("value={}", draw.value));
        }
        Decision::Override(override_decision) => {
            lines.push(String::from("decision=override"));
            lines.push(format!("point_len={}", override_decision.point.key.len()));
            lines.push(format!("point={}", override_decision.point.key));
            lines.push(format!(
                "choice_len={}",
                override_decision.choice.name.len()
            ));
            lines.push(format!("choice={}", override_decision.choice.name));
        }
        Decision::Preemption(preemption) => {
            lines.push(String::from("decision=preemption"));
            lines.push(format!("node_len={}", preemption.node.name.len()));
            lines.push(format!("node={}", preemption.node.name));
            lines.push(format!("at_retired={}", preemption.at.retired));
            match &preemption.kind {
                PreemptionKind::VcpuSwitch { from_vcpu, to_vcpu } => {
                    lines.push(String::from("preemption_kind=vcpu-switch"));
                    lines.push(format!("from_vcpu={}", from_vcpu.index));
                    lines.push(format!("to_vcpu={}", to_vcpu.index));
                }
                PreemptionKind::InterruptAt { target_vcpu, irq } => {
                    lines.push(String::from("preemption_kind=interrupt-at"));
                    lines.push(format!("target_vcpu={}", target_vcpu.index));
                    lines.push(format!("irq={}", irq.vector));
                }
            }
        }
        Decision::AppRandom(random) => {
            lines.push(String::from("decision=app-random"));
            lines.push(format!("node_len={}", random.node.name.len()));
            lines.push(format!("node={}", random.node.name));
            lines.push(format!("stream_domain_len={}", random.stream.domain.len()));
            lines.push(format!("stream_domain={}", random.stream.domain));
            lines.push(format!("stream_name_len={}", random.stream.name.len()));
            lines.push(format!("stream_name={}", random.stream.name));
            lines.push(format!("request_id={}", random.request_id));
            lines.push(format!("width={}", random.width));
            lines.push(format!("value={}", random.value));
        }
    }
    lines.join("\n")
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
    /// The number of event-log entries emitted by the scheduler.
    pub event_log_entries: usize,
    /// The final event-log offset reached by the scheduler.
    pub event_log_offset: EventLogOffset,
    /// Content hashes of emitted entries in append order.
    pub event_log_entry_hashes: Vec<ContentHash>,
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

/// Deterministic quiescence evidence computed from scheduler-owned state.
#[derive(Clone, Debug, Default, PartialEq, Eq, Hash)]
pub struct SchedulerQuiescence {
    /// Authoritative scheduler-state reasons the system is not quiescent.
    pub blockers: Vec<SchedulerQuiescenceBlocker>,
}

impl SchedulerQuiescence {
    /// Returns whether no scheduler-state blocker remains.
    #[must_use]
    pub fn is_quiescent(&self) -> bool {
        self.blockers.is_empty()
    }
}

/// One scheduler-owned state component that prevents quiescence.
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub enum SchedulerQuiescenceBlocker {
    /// A node is still runnable and may be selected by PICK.
    RunnableNode {
        /// The runnable scheduler graph node.
        node: SchedulerNodeId,
    },
    /// A scheduler-resolved delivery, I/O completion, fault, or control event is queued.
    PendingEvent {
        /// The canonical key of the queued event.
        key: ScheduledEventKey,
    },
    /// A control operation is waiting for the next quantum boundary.
    PendingControl {
        /// The queued control operation.
        operation: ControlOperation,
    },
    /// A topology change is waiting for the next boundary recompute.
    PendingTopologyChange {
        /// Session-local sequence number of the queued topology change.
        sequence: u64,
        /// The reason this change requires a lookahead recompute.
        trigger: SchedulerTopologyChangeTrigger,
        /// Exact activation rendezvous time, when the change is fault-timed.
        activation_time: Option<SimInstant>,
    },
    /// A scheduler node still has an exact local wakeup.
    PendingExactLocalEvent {
        /// The scheduler graph node with the exact wakeup.
        node: SchedulerNodeId,
        /// The exact local event that prevents terminal quiescence.
        event: ExactLocalEvent,
    },
}

/// The single authoritative scheduler used by the liveness gate.
#[derive(Clone, Debug)]
pub struct SingleScheduler {
    configuration: Configuration,
    timeline: SharedTimeline,
    quantum_budget: u64,
    time_limit: SimInstant,
    rendezvous: SchedulerRendezvous,
    effective_topology: SchedulerLookaheadGraph,
    nodes: Vec<RuntimeSchedulerNode>,
    topology_changes: Vec<SchedulerTopologyChange>,
    run_subdivision_policies: Vec<SchedulerRunSubdivisionPolicy>,
    run_subdivision_records: Vec<SchedulerRunSubdivisionRecord>,
    control_admissions: Vec<SchedulerControlAdmission>,
    control_applications: Vec<SchedulerControlApplication>,
    pending_events: Vec<ScheduledEvent>,
    event_sequences: EventSequenceState,
    control_inbox: Vec<ControlOperation>,
    decision_rng_cursor: DecisionRngState,
    event_log_prefix: ContentHash,
    event_log_bytes: u64,
    event_log_events: u64,
    frontier: VirtualTime,
    quanta: u64,
    topology_epoch: u64,
    topology_change_applications: Vec<SchedulerTopologyChangeApplication>,
    rendezvous_records: Vec<SchedulerRendezvousRecord>,
    boundary_yields: u64,
    ceiling_publications: Vec<SchedulerRunCeilingPublication>,
    lock_held: bool,
    last_advance: Option<NodeAdvance>,
    last_topology_recompute: bool,
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
        let configuration = scenario.canonical_configuration();
        let mut nodes = scenario
            .nodes
            .into_iter()
            .map(RuntimeSchedulerNode::from)
            .collect::<Vec<_>>();
        nodes.sort_by(|left, right| left.id.cmp(&right.id));
        let mut run_subdivision_policies = scenario.run_subdivision_policies;
        run_subdivision_policies.sort();

        let frontier = frontier_for(&nodes, scenario.shift)?;

        Ok(Self {
            configuration,
            timeline,
            quantum_budget: scenario.quantum_budget,
            time_limit: scenario.time_limit,
            rendezvous: scenario.rendezvous,
            effective_topology: scenario.effective_topology,
            nodes,
            topology_changes: scenario.topology_changes,
            run_subdivision_policies,
            run_subdivision_records: Vec::new(),
            control_admissions: Vec::new(),
            control_applications: Vec::new(),
            pending_events: scenario.pending_events,
            event_sequences: scenario.event_sequences,
            control_inbox: Vec::new(),
            decision_rng_cursor: DecisionRngState::empty(),
            event_log_prefix: scheduler_event_log_empty_prefix(),
            event_log_bytes: 0,
            event_log_events: 0,
            frontier,
            quanta: 0,
            topology_epoch: 0,
            topology_change_applications: Vec::new(),
            rendezvous_records: Vec::new(),
            boundary_yields: 0,
            ceiling_publications: Vec::new(),
            lock_held: false,
            last_advance: None,
            last_topology_recompute: false,
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

    /// Returns the event-log offset reached by completed scheduler EMIT phases.
    #[must_use]
    pub fn event_log_offset(&self) -> EventLogOffset {
        EventLogOffset::new(
            self.event_log_prefix,
            self.event_log_bytes,
            self.event_log_events,
        )
    }

    /// Returns the RUN max-advance ceilings published by this scheduler.
    #[must_use]
    pub fn run_ceiling_publications(&self) -> &[SchedulerRunCeilingPublication] {
        &self.ceiling_publications
    }

    /// Returns plugin-internal RR subdivision evidence for completed RUNs.
    #[must_use]
    pub fn run_subdivision_records(&self) -> &[SchedulerRunSubdivisionRecord] {
        &self.run_subdivision_records
    }

    /// Returns topology changes applied at completed scheduler boundaries.
    #[must_use]
    pub fn topology_change_applications(&self) -> &[SchedulerTopologyChangeApplication] {
        &self.topology_change_applications
    }

    /// Returns allowed rendezvous records completed at scheduler boundaries.
    #[must_use]
    pub fn rendezvous_records(&self) -> &[SchedulerRendezvousRecord] {
        &self.rendezvous_records
    }

    /// Returns scheduler-side control applications completed at boundaries.
    #[must_use]
    pub fn control_applications(&self) -> &[SchedulerControlApplication] {
        &self.control_applications
    }

    /// Returns the deterministic RUN set eligible for host-level concurrency.
    ///
    /// The set is bounded by both the scheduler's conservative horizon
    /// computation and `max_host_workers`. RESOLVE and EMIT are not performed by
    /// this read-only query.
    ///
    /// # Errors
    ///
    /// Returns [`SchedulerError`] if `max_host_workers` is zero or if horizon
    /// projection discovers inconsistent scheduler state.
    pub fn concurrent_run_set(
        &self,
        max_host_workers: usize,
    ) -> Result<SchedulerConcurrentRunSet, SchedulerError> {
        self.validate_max_host_workers(max_host_workers)?;
        let candidates = self.advance_candidates()?;
        self.concurrent_run_set_from_candidates(max_host_workers, &candidates)
    }

    /// Authorizes one cross-node frame emission under the current topology.
    ///
    /// Backends use this as the scheduler-side send freeze: when a topology
    /// change is pending, no new cross-node frame may be emitted until the next
    /// boundary recomputes lookahead. The authorization also proves the
    /// producer-to-consumer edge is live in the current effective edge set.
    ///
    /// # Errors
    ///
    /// Returns [`SchedulerError::BoundaryViolation`] when a topology change is
    /// waiting for the boundary recompute, or when the producer-to-consumer edge
    /// is absent from the current effective topology.
    pub fn authorize_cross_node_send(
        &self,
        producer: &SchedulerNodeId,
        consumer: &SchedulerNodeId,
    ) -> Result<SchedulerSendAuthorization, SchedulerError> {
        if !self.topology_changes.is_empty() {
            return Err(SchedulerError::BoundaryViolation {
                message: format!(
                    "cross-node sends frozen while topology change is pending: producer={}:{:?} consumer={}:{:?}",
                    producer.node.name, producer.kind, consumer.node.name, consumer.kind
                ),
            });
        }
        if !self.effective_topology.has_edge(producer, consumer) {
            return Err(SchedulerError::BoundaryViolation {
                message: format!(
                    "cross-node send has no effective topology edge: producer={}:{:?} consumer={}:{:?}",
                    producer.node.name, producer.kind, consumer.node.name, consumer.kind
                ),
            });
        }

        Ok(SchedulerSendAuthorization {
            producer: producer.clone(),
            consumer: consumer.clone(),
            topology_epoch: self.topology_epoch,
        })
    }

    /// Returns per-node effective clocks in canonical scheduler-node order.
    ///
    /// Runnable, halted, and done nodes use their current virtual time. Idle nodes
    /// with a finite exact wake project to that wake time, so they do not hold
    /// back peers whose clocks are still behind the wake.
    ///
    /// # Errors
    ///
    /// Returns [`SchedulerError`] when projecting a node counter or reducing an
    /// idle wake discovers inconsistent scheduler state.
    pub fn effective_clocks(&self) -> Result<Vec<SchedulerEffectiveClock>, SchedulerError> {
        self.nodes
            .iter()
            .map(|node| self.effective_clock_for_node(node))
            .collect()
    }

    /// Computes terminal quiescence from authoritative scheduler state only.
    ///
    /// The predicate is independent of host wall-clock time. A system is
    /// quiescent only when no node is runnable, no exact local wakeup remains
    /// armed, no scheduler event remains queued, and no control operation is
    /// waiting at the boundary.
    ///
    /// # Errors
    ///
    /// Returns [`SchedulerError`] when exact local event projection discovers
    /// inconsistent scheduler state, such as a scheduled I/O completion whose
    /// key and payload disagree.
    pub fn quiescence(&self) -> Result<SchedulerQuiescence, SchedulerError> {
        let mut blockers = Vec::new();

        let mut control = self.control_inbox.clone();
        control.sort();
        blockers.extend(
            control
                .into_iter()
                .map(|operation| SchedulerQuiescenceBlocker::PendingControl { operation }),
        );

        let mut topology_changes = self.topology_changes.clone();
        topology_changes.sort_by(topology_change_order);
        blockers.extend(topology_changes.into_iter().map(|change| {
            SchedulerQuiescenceBlocker::PendingTopologyChange {
                sequence: change.sequence,
                trigger: change.trigger,
                activation_time: change.activation_time,
            }
        }));

        blockers.extend(
            ordered_scheduled_events(&self.pending_events)
                .into_iter()
                .map(|event| SchedulerQuiescenceBlocker::PendingEvent {
                    key: event.key.clone(),
                }),
        );

        for node in &self.nodes {
            match node.activity {
                SchedulerNodeActivity::Runnable => {
                    blockers.push(SchedulerQuiescenceBlocker::RunnableNode {
                        node: node.id.clone(),
                    });
                }
                SchedulerNodeActivity::Idle => {}
                SchedulerNodeActivity::Halted | SchedulerNodeActivity::Done => continue,
            }

            let exact_local_event = next_exact_local_event(
                &node.id,
                node.exact_local_event.clone(),
                &self.pending_events,
                self.timeline.shift(),
            )?;
            if !matches!(exact_local_event, ExactLocalEvent::NoArmedTimer) {
                blockers.push(SchedulerQuiescenceBlocker::PendingExactLocalEvent {
                    node: node.id.clone(),
                    event: exact_local_event,
                });
            }
        }

        Ok(SchedulerQuiescence { blockers })
    }

    fn queue_control(&mut self, operation: ControlOperation) {
        self.accept_control_at_boundary(operation);
    }

    fn validate_max_host_workers(&self, max_host_workers: usize) -> Result<(), SchedulerError> {
        if max_host_workers == 0 {
            return Err(SchedulerError::BoundaryViolation {
                message: String::from("concurrent scheduler max_host_workers must be positive"),
            });
        }
        Ok(())
    }

    /// Queues a topology change for the next quantum boundary.
    pub fn queue_topology_change(&mut self, change: SchedulerTopologyChange) {
        self.topology_changes.push(change);
        self.topology_changes.sort_by(topology_change_order);
    }

    fn apply_topology_changes_at_boundary(&mut self) -> Result<bool, SchedulerError> {
        if self.topology_changes.is_empty() {
            return Ok(false);
        }

        let mut changes = std::mem::take(&mut self.topology_changes);
        changes.sort_by(topology_change_order);
        let mut deferred = Vec::new();
        let mut applied = false;

        for change in changes {
            if let Some(activation_time) = change.activation_time {
                if !self.topology_activation_ready(activation_time)? {
                    deferred.push(change);
                    continue;
                }
            }

            let SchedulerTopologyChange {
                sequence,
                trigger,
                activation_time,
                effect,
            } = change;
            if let Some(activation_time) = activation_time {
                self.record_rendezvous(SchedulerRendezvousPurpose::TopologySwap, activation_time)?;
            }
            let graph = match effect {
                SchedulerTopologyChangeEffect::ReplaceEffectiveEdges(effective_edges) => {
                    SchedulerLookaheadGraph::from_edges(effective_edges)
                }
                SchedulerTopologyChangeEffect::RemoveEffectiveEdges(endpoints) => {
                    self.effective_topology.remove_effective_edges(endpoints)
                }
                SchedulerTopologyChangeEffect::RestoreEffectiveEdges(restored_edges) => self
                    .effective_topology
                    .restore_effective_edges(restored_edges),
            };
            let mut updates = Vec::with_capacity(self.nodes.len());
            for node in &mut self.nodes {
                let previous_lookahead = node.network_lookahead;
                let recomputed_lookahead = graph.lookahead(&node.id);
                node.network_lookahead = recomputed_lookahead;
                updates.push(SchedulerTopologyLookaheadUpdate {
                    node: node.id.clone(),
                    previous_lookahead,
                    recomputed_lookahead,
                });
            }

            self.effective_topology = graph;
            self.topology_epoch = self.topology_epoch.checked_add(1).ok_or_else(|| {
                SchedulerError::BoundaryViolation {
                    message: String::from("scheduler topology epoch overflow"),
                }
            })?;
            self.topology_change_applications
                .push(SchedulerTopologyChangeApplication {
                    topology_epoch: self.topology_epoch,
                    sequence,
                    trigger,
                    activation_time,
                    updates,
                });
            applied = true;
        }

        deferred.sort_by(topology_change_order);
        self.topology_changes = deferred;

        Ok(applied)
    }

    fn record_rendezvous(
        &mut self,
        purpose: SchedulerRendezvousPurpose,
        virtual_time: SimInstant,
    ) -> Result<(), SchedulerError> {
        let mut nodes = Vec::new();
        for node in &self.nodes {
            if matches!(
                node.activity,
                SchedulerNodeActivity::Halted | SchedulerNodeActivity::Done
            ) {
                continue;
            }

            let current_time = node.counter.to_virtual(self.timeline.shift())?;
            if current_time != virtual_time {
                return Err(SchedulerError::BoundaryViolation {
                    message: format!(
                        "scheduler {:?} rendezvous requires zero skew for {}:{:?}: current={} rendezvous={}",
                        purpose,
                        node.id.node.name,
                        node.id.kind,
                        current_time.nanos,
                        virtual_time.nanos
                    ),
                });
            }
            nodes.push(SchedulerRendezvousNode {
                node: node.id.clone(),
                virtual_time: current_time,
            });
        }

        self.rendezvous_records.push(SchedulerRendezvousRecord {
            sequence: self.rendezvous_records.len() as u64,
            purpose,
            virtual_time,
            nodes,
        });
        Ok(())
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
            control_applications: self.control_applications.clone(),
            boundary_yields: self.boundary_yields,
        }
    }

    fn is_empty(&self) -> bool {
        self.nodes.is_empty()
    }

    fn reached_time_limit(&self) -> Result<bool, SchedulerError> {
        let mut saw_time_limited_state = false;

        for node in &self.nodes {
            let has_finite_projection = match node.activity {
                SchedulerNodeActivity::Runnable => true,
                SchedulerNodeActivity::Idle => self.idle_wake_time(node)?.is_some(),
                SchedulerNodeActivity::Halted | SchedulerNodeActivity::Done => false,
            };
            if has_finite_projection {
                saw_time_limited_state = true;
                let current_time = node.counter.to_virtual(self.timeline.shift())?;
                if current_time < self.time_limit {
                    return Ok(false);
                }
            }
        }

        Ok(saw_time_limited_state)
    }

    fn exhausted_quantum_budget(&self) -> bool {
        self.quanta >= self.quantum_budget
    }

    fn pick_global_minimum_horizon_node(&self) -> Result<Option<AdvanceCandidate>, SchedulerError> {
        Ok(self.advance_candidates()?.into_iter().next())
    }

    fn advance_candidates(&self) -> Result<Vec<AdvanceCandidate>, SchedulerError> {
        let mut candidates = Vec::new();
        let rendezvous_cap = self.shared_rendezvous_cap()?;
        let topology_activation_cap = self.pending_topology_activation_cap()?;

        for (index, node) in self.nodes.iter().enumerate() {
            if let Some(candidate) =
                self.advance_candidate(index, node, rendezvous_cap, topology_activation_cap)?
            {
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

        Ok(candidates)
    }

    fn concurrent_run_set_from_candidates(
        &self,
        max_host_workers: usize,
        candidates: &[AdvanceCandidate],
    ) -> Result<SchedulerConcurrentRunSet, SchedulerError> {
        self.validate_max_host_workers(max_host_workers)?;
        let mut selected = Vec::new();
        let frontier = SimInstant {
            nanos: self.frontier.ticks,
        };
        let target_time = candidates.first().map(|candidate| candidate.target_time);

        for candidate in candidates.iter() {
            if selected.len() >= max_host_workers {
                break;
            }
            if Some(candidate.target_time) != target_time {
                break;
            }
            let draft = self.advance_plan_draft(candidate)?;
            let current_time = draft.before.to_virtual(self.timeline.shift())?;
            if current_time != frontier {
                continue;
            }
            selected.push(SchedulerConcurrentRunCandidate {
                node: draft.node,
                current_time,
                target_time: candidate.target_time,
                max_advance_icount: draft.target_counter,
            });
        }

        Ok(SchedulerConcurrentRunSet {
            max_host_workers,
            candidates: selected,
        })
    }

    fn advance_plan_draft(
        &self,
        candidate: &AdvanceCandidate,
    ) -> Result<AdvancePlanDraft, SchedulerError> {
        let selected_index = candidate.index;
        let selected_node = self.nodes[selected_index].id.clone();
        let before = self.nodes[selected_index].counter;
        let target_counter = self
            .timeline
            .max_advance_icount_for_horizon(candidate.target_time)?
            .retired;
        let projected_target = NodeCounter {
            ticks: target_counter,
        }
        .to_virtual(self.timeline.shift())?;
        if !candidate.allow_ceil_past_target && projected_target > candidate.target_time {
            return Err(scheduler_ceiling_overshoot_error(
                &selected_node,
                "target_at",
                candidate.target_time,
                projected_target,
            ));
        }
        if projected_target > candidate.target_time {
            let current_time = before.to_virtual(self.timeline.shift())?;
            let selected_runtime_node = &self.nodes[selected_index];
            if let NetworkLookahead::Finite(duration) = selected_runtime_node.network_lookahead {
                let network_target = current_time + duration;
                if network_target > candidate.target_time && projected_target > network_target {
                    return Err(scheduler_ceiling_overshoot_error(
                        &selected_node,
                        "network_cap_at",
                        network_target,
                        projected_target,
                    ));
                }
            }
            if self.time_limit > candidate.target_time && projected_target > self.time_limit {
                return Err(scheduler_ceiling_overshoot_error(
                    &selected_node,
                    "time_limit_at",
                    self.time_limit,
                    projected_target,
                ));
            }
            if let Some(cap) = self.shared_rendezvous_cap()?
                && cap > candidate.target_time
                && projected_target > cap
            {
                return Err(scheduler_ceiling_overshoot_error(
                    &selected_node,
                    "rendezvous_at",
                    cap,
                    projected_target,
                ));
            }
            if let Some(dependency) =
                unresolved_cross_node_dependencies(&selected_node, &self.pending_events)
                    .into_iter()
                    .find(|dependency| {
                        dependency.virtual_time > candidate.target_time
                            && projected_target > dependency.virtual_time
                    })
            {
                return Err(scheduler_ceiling_overshoot_error(
                    &selected_node,
                    "dependency_at",
                    dependency.virtual_time,
                    projected_target,
                ));
            }
            for event in &self.pending_events {
                if event.key.consumer() == &selected_node {
                    let event_time = SimInstant {
                        nanos: event.key.virtual_time().ticks,
                    };
                    if event_time > candidate.target_time && projected_target > event_time {
                        return Err(scheduler_ceiling_overshoot_error(
                            &selected_node,
                            "pending_event_at",
                            event_time,
                            projected_target,
                        ));
                    }
                }
            }
        } else if let Some(dependency) = &candidate.conservative_dependency
            && projected_target > dependency.virtual_time
        {
            return Err(scheduler_ceiling_overshoot_error(
                &selected_node,
                "dependency_at",
                dependency.virtual_time,
                projected_target,
            ));
        }

        Ok(AdvancePlanDraft {
            index: selected_index,
            node: selected_node,
            before,
            target_counter,
            quiescent_horizon: candidate.quiescent_horizon,
        })
    }

    fn advance_candidate(
        &self,
        index: usize,
        node: &RuntimeSchedulerNode,
        rendezvous_cap: Option<SimInstant>,
        topology_activation_cap: Option<SimInstant>,
    ) -> Result<Option<AdvanceCandidate>, SchedulerError> {
        let current_time = node.counter.to_virtual(self.timeline.shift())?;
        let EffectiveHorizonProjection::Finite {
            target_time,
            quiescent_horizon,
            conservative_dependency,
            allow_ceil_past_target,
        } = self.effective_horizon(node, current_time, rendezvous_cap, topology_activation_cap)?
        else {
            return Ok(None);
        };

        if current_time >= target_time {
            return Ok(None);
        }

        Ok(Some(AdvanceCandidate {
            index,
            key: self
                .timeline
                .timeline_key(node.id.clone(), node.counter, index as u64)?,
            target_time,
            quiescent_horizon,
            conservative_dependency,
            allow_ceil_past_target,
        }))
    }

    fn effective_horizon(
        &self,
        node: &RuntimeSchedulerNode,
        current_time: SimInstant,
        rendezvous_cap: Option<SimInstant>,
        topology_activation_cap: Option<SimInstant>,
    ) -> Result<EffectiveHorizonProjection, SchedulerError> {
        match node.activity {
            SchedulerNodeActivity::Runnable => {
                let window = self.advance_window(
                    node,
                    current_time,
                    rendezvous_cap,
                    topology_activation_cap,
                )?;
                Ok(EffectiveHorizonProjection::Finite {
                    target_time: window.target_time,
                    quiescent_horizon: window.quiescent_horizon,
                    conservative_dependency: window.conservative_dependency,
                    allow_ceil_past_target: window.allow_ceil_past_target,
                })
            }
            SchedulerNodeActivity::Idle => {
                self.idle_advance_candidate(node, rendezvous_cap, topology_activation_cap)
            }
            SchedulerNodeActivity::Halted | SchedulerNodeActivity::Done => {
                Ok(EffectiveHorizonProjection::Infinite)
            }
        }
    }

    fn idle_advance_candidate(
        &self,
        node: &RuntimeSchedulerNode,
        rendezvous_cap: Option<SimInstant>,
        topology_activation_cap: Option<SimInstant>,
    ) -> Result<EffectiveHorizonProjection, SchedulerError> {
        let projection = self.effective_clock_for_node(node)?;
        if projection.source != SchedulerEffectiveClockSource::IdleWake {
            if let Some(activation_time) = topology_activation_cap {
                let requested_target = rendezvous_cap.unwrap_or(activation_time);
                let target_time = min_instant(requested_target, self.time_limit);
                if projection.current_time < target_time {
                    return Ok(EffectiveHorizonProjection::Finite {
                        target_time,
                        quiescent_horizon: None,
                        conservative_dependency: None,
                        allow_ceil_past_target: false,
                    });
                }
            }
            return Ok(EffectiveHorizonProjection::Infinite);
        }
        let Some(wake_target) = self.idle_wake_target(node)? else {
            return Ok(EffectiveHorizonProjection::Infinite);
        };
        let mut wake_time = wake_target.wake_time;
        let mut allow_ceil_past_target = wake_target.allow_ceil_past_target;
        wake_time = min_instant(wake_time, self.time_limit);
        if self.time_limit <= wake_target.wake_time {
            allow_ceil_past_target = false;
        }
        if let Some(cap) = rendezvous_cap {
            if cap <= wake_time {
                allow_ceil_past_target = false;
            }
            wake_time = min_instant(wake_time, cap);
        }

        Ok(EffectiveHorizonProjection::Finite {
            target_time: wake_time,
            quiescent_horizon: Some(wake_time),
            conservative_dependency: None,
            allow_ceil_past_target,
        })
    }

    fn effective_clock_for_node(
        &self,
        node: &RuntimeSchedulerNode,
    ) -> Result<SchedulerEffectiveClock, SchedulerError> {
        let current_time = node.counter.to_virtual(self.timeline.shift())?;
        let (effective_time, source) = match node.activity {
            SchedulerNodeActivity::Idle => match self.idle_wake_time(node)? {
                Some(wake_time) if wake_time > current_time => {
                    (wake_time, SchedulerEffectiveClockSource::IdleWake)
                }
                _ => (current_time, SchedulerEffectiveClockSource::Current),
            },
            SchedulerNodeActivity::Runnable
            | SchedulerNodeActivity::Halted
            | SchedulerNodeActivity::Done => (current_time, SchedulerEffectiveClockSource::Current),
        };

        Ok(SchedulerEffectiveClock {
            node: node.id.clone(),
            current_time,
            effective_time,
            source,
        })
    }

    fn idle_wake_time(
        &self,
        node: &RuntimeSchedulerNode,
    ) -> Result<Option<SimInstant>, SchedulerError> {
        Ok(self.idle_wake_target(node)?.map(|target| target.wake_time))
    }

    fn idle_wake_target(
        &self,
        node: &RuntimeSchedulerNode,
    ) -> Result<Option<IdleWakeTarget>, SchedulerError> {
        let exact_local_event = next_exact_local_event(
            &node.id,
            node.exact_local_event.clone(),
            &self.pending_events,
            self.timeline.shift(),
        )?;
        let mut target = exact_local_event
            .virtual_time()
            .map(|wake_time| IdleWakeTarget {
                wake_time,
                allow_ceil_past_target: horizon_source_allows_ceiling_past_target(
                    exact_local_event_horizon_source(&exact_local_event),
                ),
            });

        for event in &self.pending_events {
            if event.key.consumer() == &node.id {
                let event_time = SimInstant {
                    nanos: event.key.virtual_time().ticks,
                };
                match target {
                    Some(current) if current.wake_time < event_time => {}
                    Some(current) if current.wake_time == event_time => {
                        target = Some(IdleWakeTarget {
                            wake_time: current.wake_time,
                            allow_ceil_past_target: false,
                        });
                    }
                    _ => {
                        target = Some(IdleWakeTarget {
                            wake_time: event_time,
                            allow_ceil_past_target: false,
                        });
                    }
                }
            }
        }

        Ok(target)
    }

    fn advance_window(
        &self,
        node: &RuntimeSchedulerNode,
        current_time: SimInstant,
        rendezvous_cap: Option<SimInstant>,
        topology_activation_cap: Option<SimInstant>,
    ) -> Result<AdvanceWindow, SchedulerError> {
        let exact_local_event = next_exact_local_event(
            &node.id,
            node.exact_local_event.clone(),
            &self.pending_events,
            self.timeline.shift(),
        )?;
        let horizon = horizon_from_network_lookahead(
            current_time,
            node.network_lookahead,
            exact_local_event,
            self.timeline.shift(),
        )?;
        let finite_horizon = horizon.virtual_time().unwrap_or(self.time_limit);
        let mut allow_ceil_past_target = horizon
            .virtual_time()
            .is_some_and(|_| horizon_source_allows_ceiling_past_target(horizon.source));
        if let NetworkLookahead::Finite(duration) = node.network_lookahead {
            let network_target = current_time + duration;
            if network_target <= finite_horizon {
                allow_ceil_past_target = false;
            }
        }
        let mut requested_target = min_instant(finite_horizon, self.time_limit);
        if self.time_limit <= finite_horizon {
            allow_ceil_past_target = false;
        }
        if let Some(cap) = rendezvous_cap {
            if cap <= requested_target {
                allow_ceil_past_target = false;
            }
            requested_target = min_instant(requested_target, cap);
        }
        let authorization = authorize_conservative_advance(
            &node.id,
            current_time,
            requested_target,
            &self.pending_events,
        )?;
        let mut target_time = authorization.authorized_target;
        let conservative_dependency = authorization.blocking_dependency;
        if conservative_dependency.is_some() {
            allow_ceil_past_target = false;
        }

        for event in &self.pending_events {
            if event.key.consumer() == &node.id {
                let event_time = SimInstant {
                    nanos: event.key.virtual_time().ticks,
                };
                if event_time > current_time && event_time <= target_time {
                    if event_time < target_time {
                        target_time = event_time;
                    }
                    allow_ceil_past_target = false;
                }
            }
        }

        let mut quiescent_horizon = horizon.virtual_time();
        if let (Some(horizon_time), Some(activation_time)) =
            (quiescent_horizon, topology_activation_cap)
        {
            if current_time < activation_time && horizon_time < activation_time {
                quiescent_horizon = None;
            }
        }

        Ok(AdvanceWindow {
            target_time,
            quiescent_horizon,
            conservative_dependency,
            allow_ceil_past_target,
        })
    }

    fn publish_run_ceiling(
        &mut self,
        node: SchedulerNodeId,
        current_icount: NodeCounter,
        max_advance_icount: u64,
        target_time: SimInstant,
    ) -> Result<SchedulerRunCeilingPublication, SchedulerError> {
        if max_advance_icount < current_icount.ticks {
            return Err(SchedulerError::BoundaryViolation {
                message: format!(
                    "RUN max-advance ceiling for {}:{:?} is before current icount: current={} ceiling={}",
                    node.node.name, node.kind, current_icount.ticks, max_advance_icount
                ),
            });
        }

        let publication = SchedulerRunCeilingPublication {
            sequence: self.ceiling_publications.len() as u64,
            quantum: self.quanta,
            node,
            current_icount,
            max_advance_icount,
            icount_shift: self.timeline.shift(),
            target_time,
        };
        self.ceiling_publications.push(publication.clone());
        Ok(publication)
    }

    fn planned_run_subdivision(
        &self,
        node: &SchedulerNodeId,
        current_icount: NodeCounter,
        max_advance_icount: u64,
    ) -> Result<Option<PlannedRunSubdivision>, SchedulerError> {
        let Some(policy) = self
            .run_subdivision_policies
            .iter()
            .find(|policy| &policy.node == node)
        else {
            return Ok(None);
        };
        let slices = scheduler_rr_run_subdivision(
            current_icount,
            max_advance_icount,
            policy.vcpu_count,
            policy.rr_switch_quantum,
        )?;

        Ok(Some(PlannedRunSubdivision {
            policy: policy.clone(),
            slices,
        }))
    }

    fn record_run_subdivision(
        &mut self,
        planned: PlannedRunSubdivision,
        ceiling: SchedulerRunCeilingPublication,
    ) {
        self.run_subdivision_records
            .push(SchedulerRunSubdivisionRecord {
                sequence: self.run_subdivision_records.len() as u64,
                quantum: ceiling.quantum,
                policy: planned.policy,
                ceiling,
                slices: planned.slices,
            });
    }

    fn topology_activation_ready(
        &self,
        activation_time: SimInstant,
    ) -> Result<bool, SchedulerError> {
        for node in &self.nodes {
            if matches!(
                node.activity,
                SchedulerNodeActivity::Halted | SchedulerNodeActivity::Done
            ) {
                continue;
            }

            let current_time = node.counter.to_virtual(self.timeline.shift())?;
            if current_time > activation_time {
                return Err(SchedulerError::BoundaryViolation {
                    message: format!(
                        "topology activation rendezvous missed exact virtual time for {}:{:?}: current={} activation={}",
                        node.id.node.name, node.id.kind, current_time.nanos, activation_time.nanos
                    ),
                });
            }
            if current_time < activation_time {
                return Ok(false);
            }
        }

        Ok(true)
    }

    fn pending_topology_activation_cap(&self) -> Result<Option<SimInstant>, SchedulerError> {
        let mut cap = None;

        for change in &self.topology_changes {
            let Some(activation_time) = change.activation_time else {
                continue;
            };
            if self.topology_activation_ready(activation_time)? {
                continue;
            }

            cap = Some(match cap {
                Some(current) => min_instant(current, activation_time),
                None => activation_time,
            });
        }

        Ok(cap)
    }

    fn shared_rendezvous_cap(&self) -> Result<Option<SimInstant>, SchedulerError> {
        let fixed_cap = rendezvous_cap_for(
            SimInstant {
                nanos: self.frontier.ticks,
            },
            self.rendezvous,
        )?;
        let topology_cap = self.pending_topology_activation_cap()?;

        Ok(match (fixed_cap, topology_cap) {
            (Some(fixed_cap), Some(topology_cap)) => Some(min_instant(fixed_cap, topology_cap)),
            (Some(fixed_cap), None) => Some(fixed_cap),
            (None, Some(topology_cap)) => Some(topology_cap),
            (None, None) => None,
        })
    }

    fn drive_concurrent_authoritative_quantum(
        &mut self,
        request: QuantumRequest,
        max_host_workers: usize,
    ) -> Result<SchedulerConcurrentQuantumOutcome, SchedulerError> {
        self.validate_max_host_workers(max_host_workers)?;
        if request.configuration != self.configuration {
            return Err(SchedulerError::BoundaryViolation {
                message: String::from(
                    "quantum request configuration is not the scheduler frontier",
                ),
            });
        }

        self.last_advance = None;
        self.last_topology_recompute = false;

        self.admit_control_at_boundary(request.control);
        let SchedulerControlDrain {
            events: mut boundary_resolved_events,
            applications: mut boundary_control_applications,
        } = self.drain_control_events()?;
        let topology_recomputed = self.apply_topology_changes_at_boundary()?;
        self.last_topology_recompute = topology_recomputed;

        let candidates = self.advance_candidates()?;
        let run_set = self.concurrent_run_set_from_candidates(max_host_workers, &candidates)?;
        let selected_candidates = candidates
            .into_iter()
            .filter(|candidate| {
                run_set
                    .candidates
                    .iter()
                    .any(|run| run.node == self.nodes[candidate.index].id)
            })
            .collect::<Vec<_>>();

        if selected_candidates.is_empty() {
            let at = SimInstant {
                nanos: self.frontier.ticks,
            };
            let decisions = self.emit_quantum_decisions(&boundary_resolved_events, at);
            let event_log =
                self.emit_quantum_event_log(&boundary_resolved_events, &decisions, at)?;
            let configuration = self.step_quantum(&decisions);
            if !decisions.is_empty() {
                self.configuration = configuration.clone();
                self.quanta = self.quanta.saturating_add(1);
                self.yield_to_control_inbox();
            } else if topology_recomputed {
                self.quanta = self.quanta.saturating_add(1);
                self.yield_to_control_inbox();
            }
            self.commit_control_applications(boundary_control_applications);
            let outcome = QuantumOutcome {
                configuration,
                frontier: self.frontier,
                advanced_node: None,
                resolved_events: boundary_resolved_events,
                decisions,
                event_log_entries: event_log.entries,
                event_log_segment_bytes: event_log.segment_bytes,
                event_log_segment_hash: event_log.segment_hash,
                event_log_offset: event_log.offset,
            };
            return Ok(SchedulerConcurrentQuantumOutcome {
                run_set,
                outcomes: vec![outcome],
            });
        }

        let mut plans = Vec::with_capacity(selected_candidates.len());
        for candidate in selected_candidates {
            let plan = {
                let critical_section = SchedulerCriticalSection::enter(self);
                critical_section.advance_plan(candidate)?
            };
            plans.push(plan);
        }

        let mut outcomes = Vec::with_capacity(plans.len());
        for plan in plans {
            let selected_node = plan.node.clone();
            let before = plan.before;
            let (after, after_time, yielded_before_advance) =
                self.advance_node_after_yield(&plan)?;
            let mut resolved_events = if outcomes.is_empty() {
                std::mem::take(&mut boundary_resolved_events)
            } else {
                Vec::new()
            };
            let control_applications = if outcomes.is_empty() {
                std::mem::take(&mut boundary_control_applications)
            } else {
                Vec::new()
            };
            let shift = self.timeline.shift();
            resolved_events.extend(resolve_due_scheduled_events(
                &mut self.pending_events,
                &selected_node,
                after_time,
                shift,
            )?);

            let decisions = self.emit_quantum_decisions(&resolved_events, after_time);
            let event_log =
                self.emit_quantum_event_log(&resolved_events, &decisions, after_time)?;
            let configuration = self.step_quantum(&decisions);
            let frontier = frontier_for(&self.nodes, self.timeline.shift())?;

            self.configuration = configuration.clone();
            self.frontier = frontier;
            self.quanta = self.quanta.saturating_add(1);
            self.last_advance = Some(NodeAdvance {
                node: selected_node.clone(),
                before,
                after,
                ceiling: plan.ceiling.clone(),
                yielded_before_advance,
            });
            self.yield_to_control_inbox();
            self.commit_control_applications(control_applications);
            if let Some(subdivision) = plan.subdivision {
                self.record_run_subdivision(subdivision, plan.ceiling.clone());
            }

            outcomes.push(QuantumOutcome {
                configuration,
                frontier: self.frontier,
                advanced_node: Some(selected_node),
                resolved_events,
                decisions,
                event_log_entries: event_log.entries,
                event_log_segment_bytes: event_log.segment_bytes,
                event_log_segment_hash: event_log.segment_hash,
                event_log_offset: event_log.offset,
            });
        }

        Ok(SchedulerConcurrentQuantumOutcome { run_set, outcomes })
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
        self.last_topology_recompute = false;

        // Boundary admission phase: accept control exposed by the previous STEP yield.
        self.admit_control_at_boundary(request.control);
        let SchedulerControlDrain {
            events: mut resolved_events,
            applications: mut control_applications,
        } = self.drain_control_events()?;
        let topology_recomputed = self.apply_topology_changes_at_boundary()?;
        self.last_topology_recompute = topology_recomputed;
        // PICK phase: select the next effective-horizon candidate once.
        let candidate = match self.pick_global_minimum_horizon_node()? {
            Some(candidate) => candidate,
            None => {
                // Control-only EMIT/STEP: no node RUN occurs.
                let decisions = self.emit_quantum_decisions(
                    &resolved_events,
                    SimInstant {
                        nanos: self.frontier.ticks,
                    },
                );
                let event_log = self.emit_quantum_event_log(
                    &resolved_events,
                    &decisions,
                    SimInstant {
                        nanos: self.frontier.ticks,
                    },
                )?;
                let configuration = self.step_quantum(&decisions);
                if !decisions.is_empty() {
                    self.configuration = configuration.clone();
                    self.quanta = self.quanta.saturating_add(1);
                    // STEP yield phase: expose the control inbox before the next PICK.
                    self.yield_to_control_inbox();
                } else if topology_recomputed {
                    self.quanta = self.quanta.saturating_add(1);
                    self.yield_to_control_inbox();
                }
                self.commit_control_applications(std::mem::take(&mut control_applications));
                return Ok(QuantumOutcome {
                    configuration,
                    frontier: self.frontier,
                    advanced_node: None,
                    resolved_events,
                    decisions,
                    event_log_entries: event_log.entries,
                    event_log_segment_bytes: event_log.segment_bytes,
                    event_log_segment_hash: event_log.segment_hash,
                    event_log_offset: event_log.offset,
                });
            }
        };

        // RUN phase: compute one plan under the scheduler lock, then advance after yield.
        let plan = {
            let critical_section = SchedulerCriticalSection::enter(self);
            critical_section.advance_plan(candidate)?
        };

        let selected_node = plan.node.clone();
        let before = plan.before;
        let (after, after_time, yielded_before_advance) = self.advance_node_after_yield(&plan)?;
        // RESOLVE phase: collect due events for the node that just advanced.
        let shift = self.timeline.shift();
        resolved_events.extend(resolve_due_scheduled_events(
            &mut self.pending_events,
            &selected_node,
            after_time,
            shift,
        )?);

        // EMIT phase: convert happenings into decisions and append event-log entries.
        let decisions = self.emit_quantum_decisions(&resolved_events, after_time);
        let event_log = self.emit_quantum_event_log(&resolved_events, &decisions, after_time)?;
        // STEP phase: apply the emitted decisions to the frontier configuration.
        let configuration = self.step_quantum(&decisions);
        let frontier = frontier_for(&self.nodes, self.timeline.shift())?;

        self.configuration = configuration.clone();
        self.frontier = frontier;
        self.quanta = self.quanta.saturating_add(1);
        self.last_advance = Some(NodeAdvance {
            node: selected_node.clone(),
            before,
            after,
            ceiling: plan.ceiling.clone(),
            yielded_before_advance,
        });
        // STEP yield phase: expose the control inbox before the next PICK.
        self.yield_to_control_inbox();
        self.commit_control_applications(std::mem::take(&mut control_applications));
        if let Some(subdivision) = plan.subdivision {
            self.record_run_subdivision(subdivision, plan.ceiling.clone());
        }

        Ok(QuantumOutcome {
            configuration,
            frontier: self.frontier,
            advanced_node: Some(selected_node),
            resolved_events,
            decisions,
            event_log_entries: event_log.entries,
            event_log_segment_bytes: event_log.segment_bytes,
            event_log_segment_hash: event_log.segment_hash,
            event_log_offset: event_log.offset,
        })
    }

    fn emit_quantum_decisions(
        &mut self,
        resolved_events: &[ScheduledEvent],
        at: SimInstant,
    ) -> Vec<Decision> {
        if resolved_events.is_empty() {
            return Vec::new();
        }

        let decision = Decision::DeliveryOrder(DeliveryOrderDecision {
            at: VirtualTime { ticks: at.nanos },
            order: resolved_events
                .iter()
                .map(|event| EventKey {
                    virtual_time: event.key.virtual_time(),
                    consumer: event.key.consumer().clone(),
                    producer: event.key.producer().clone(),
                    sequence: event.key.sequence(),
                })
                .collect(),
        });
        self.advance_decision_rng_cursor();
        let mut decisions = vec![decision];
        let probabilistic =
            resolve_probabilistic_decisions(self.configuration.clone(), resolved_events);
        for decision in &probabilistic.decisions {
            if let Decision::RngDraw(draw) = decision {
                self.advance_decision_rng_cursor_for(draw.stream.clone());
            }
        }
        decisions.extend(probabilistic.decisions);
        decisions
    }

    fn emit_quantum_event_log(
        &mut self,
        resolved_events: &[ScheduledEvent],
        decisions: &[Decision],
        at: SimInstant,
    ) -> Result<SchedulerEventLogAppend, SchedulerError> {
        let mut entries = Vec::with_capacity(resolved_events.len() + decisions.len());

        for event in ordered_scheduled_events(resolved_events) {
            let sequence = scheduler_event_log_sequence(self.event_log_events, entries.len())?;
            entries.push(scheduler_event_log_entry(
                sequence,
                event.key.virtual_time(),
                SchedulerEventLogPayload::ResolvedHappening(event.clone()),
            ));
        }
        for decision in decisions {
            let sequence = scheduler_event_log_sequence(self.event_log_events, entries.len())?;
            entries.push(scheduler_event_log_entry(
                sequence,
                scheduler_decision_event_log_time(decision, at),
                SchedulerEventLogPayload::Decision(decision.clone()),
            ));
        }

        if entries.is_empty() {
            return Ok(SchedulerEventLogAppend {
                entries,
                segment_bytes: Vec::new(),
                segment_hash: None,
                offset: self.event_log_offset(),
            });
        }

        let segment_bytes = scheduler_event_log_segment_bytes(self.event_log_prefix, &entries);
        let segment_hash = ContentHash::from_bytes(&segment_bytes);
        let appended_bytes =
            u64::try_from(segment_bytes.len()).map_err(|_| SchedulerError::BoundaryViolation {
                message: String::from("scheduler event-log segment length exceeds u64"),
            })?;
        let appended_events =
            u64::try_from(entries.len()).map_err(|_| SchedulerError::BoundaryViolation {
                message: String::from("scheduler event-log entry count exceeds u64"),
            })?;
        let bytes = self
            .event_log_bytes
            .checked_add(appended_bytes)
            .ok_or_else(|| SchedulerError::BoundaryViolation {
                message: String::from("scheduler event-log byte offset overflow"),
            })?;
        let events = self
            .event_log_events
            .checked_add(appended_events)
            .ok_or_else(|| SchedulerError::BoundaryViolation {
                message: String::from("scheduler event-log sequence overflow"),
            })?;

        let offset = EventLogOffset::with_appended_segment(
            self.event_log_prefix,
            bytes,
            events,
            segment_hash,
        );
        let prefix_material = format!(
            "previous_prefix={}\nappended_segment={}\nbytes={bytes}\nevents={events}",
            self.event_log_prefix.to_hex(),
            segment_hash.to_hex(),
        );
        self.event_log_prefix = ContentHash::from_canonical_material(
            "crucible.scheduler.event-log.prefix.v1",
            &prefix_material,
        );
        self.event_log_bytes = bytes;
        self.event_log_events = events;

        Ok(SchedulerEventLogAppend {
            entries,
            segment_bytes,
            segment_hash: Some(segment_hash),
            offset,
        })
    }

    fn step_quantum(&self, decisions: &[Decision]) -> Configuration {
        let mut configuration = self.configuration.clone();
        for decision in decisions {
            configuration = step(&configuration, decision.clone());
        }
        configuration
    }

    fn admit_control_at_boundary(&mut self, control: Vec<ControlOperation>) {
        for operation in control {
            self.accept_control_at_boundary(operation);
        }
    }

    fn accept_control_at_boundary(&mut self, operation: ControlOperation) {
        self.control_admissions.push(SchedulerControlAdmission {
            operation: operation.clone(),
            accepted_after_quanta: self.quanta,
            accepted_after_boundary_yield: self.boundary_yields,
        });
        self.control_inbox.push(operation);
    }

    fn yield_to_control_inbox(&mut self) {
        self.boundary_yields = self.boundary_yields.saturating_add(1);
    }

    fn take_control_admission(
        &mut self,
        operation: &ControlOperation,
    ) -> Result<SchedulerControlAdmission, SchedulerError> {
        let Some(index) = self
            .control_admissions
            .iter()
            .position(|admission| &admission.operation == operation)
        else {
            return Err(SchedulerError::BoundaryViolation {
                message: format!(
                    "scheduler control operation missing boundary admission: sequence={} kind={}",
                    operation.sequence,
                    control_operation_kind_label(operation.kind)
                ),
            });
        };

        Ok(self.control_admissions.remove(index))
    }

    fn commit_control_applications(&mut self, mut applications: Vec<SchedulerControlApplication>) {
        self.control_applications.append(&mut applications);
    }

    fn drain_control_events(&mut self) -> Result<SchedulerControlDrain, SchedulerError> {
        let mut control = std::mem::take(&mut self.control_inbox);
        control.sort();
        let node = SchedulerNodeId {
            node: NodeId {
                name: String::from("control-plane"),
            },
            kind: SchedulingNodeKind::ControlPlane,
        };

        let mut events = Vec::with_capacity(control.len());
        let mut applications = Vec::with_capacity(control.len());
        for operation in control {
            let admission = self.take_control_admission(&operation)?;
            let key = next_scheduled_event_key(
                &mut self.event_sequences,
                self.frontier,
                node.clone(),
                node.clone(),
            )?;
            let application_delta_quanta = self
                .quanta
                .checked_sub(admission.accepted_after_quanta)
                .ok_or_else(|| SchedulerError::BoundaryViolation {
                    message: format!(
                        "scheduler control operation applied before admission: sequence={} kind={}",
                        operation.sequence,
                        control_operation_kind_label(operation.kind)
                    ),
                })?;
            if application_delta_quanta > SCHEDULER_CONTROL_RESPONSE_BOUND_QUANTA {
                return Err(SchedulerError::BoundaryViolation {
                    message: format!(
                        "scheduler control operation exceeded quantum response bound: sequence={} kind={} delta={} bound={}",
                        operation.sequence,
                        control_operation_kind_label(operation.kind),
                        application_delta_quanta,
                        SCHEDULER_CONTROL_RESPONSE_BOUND_QUANTA
                    ),
                });
            }
            applications.push(SchedulerControlApplication {
                sequence: (self.control_applications.len() + applications.len()) as u64,
                operation: operation.clone(),
                accepted_after_quanta: admission.accepted_after_quanta,
                applied_in_quantum: self.quanta,
                application_delta_quanta,
                accepted_after_boundary_yield: admission.accepted_after_boundary_yield,
                applied_at_boundary_yield: self.boundary_yields,
                event_key: key.clone(),
            });
            events.push(ScheduledEvent {
                key,
                payload: ScheduledEventPayload::Control(operation),
            });
        }
        Ok(SchedulerControlDrain {
            events,
            applications,
        })
    }

    fn advance_decision_rng_cursor(&mut self) {
        let stream = RngStreamId::new(SCHEDULER_ACTOR_RNG_DOMAIN, SCHEDULER_QUANTUM_STREAM);
        self.advance_decision_rng_cursor_for(stream);
    }

    fn advance_decision_rng_cursor_for(&mut self, stream: RngStreamId) {
        let position = self
            .decision_rng_cursor
            .positions
            .entry(stream)
            .or_insert_with(|| RngStreamPosition::new(0));
        position.draws = position.draws.saturating_add(1);
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
        if plan.ceiling.max_advance_icount != plan.target_counter {
            return Err(SchedulerError::BoundaryViolation {
                message: format!(
                    "RUN target for {}:{:?} diverged from published max-advance ceiling: target={} ceiling={}",
                    plan.node.node.name,
                    plan.node.kind,
                    plan.target_counter,
                    plan.ceiling.max_advance_icount
                ),
            });
        }

        let after = NodeCounter {
            ticks: plan.target_counter,
        };
        self.nodes[plan.index].counter = after;
        let after_time = after.to_virtual(self.timeline.shift())?;
        if self.nodes[plan.index]
            .exact_local_event
            .virtual_time()
            .is_some_and(|virtual_time| after_time >= virtual_time)
        {
            self.nodes[plan.index].exact_local_event = ExactLocalEvent::NoArmedTimer;
        }
        if plan
            .quiescent_horizon
            .is_some_and(|horizon| after_time >= horizon)
        {
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

impl SchedulerSendAuthorizer for SingleScheduler {
    fn authorize_cross_node_send(
        &self,
        producer: &SchedulerNodeId,
        consumer: &SchedulerNodeId,
    ) -> Result<SchedulerSendAuthorization, SchedulerError> {
        SingleScheduler::authorize_cross_node_send(self, producer, consumer)
    }
}

impl QuantumLoop for SingleScheduler {
    fn drive_quantum(&mut self, request: QuantumRequest) -> Result<QuantumOutcome, SchedulerError> {
        self.drive_authoritative_quantum(request)
    }
}

impl ConcurrentQuantumLoop for SingleScheduler {
    fn drive_concurrent_quantum(
        &mut self,
        request: QuantumRequest,
        max_host_workers: usize,
    ) -> Result<SchedulerConcurrentQuantumOutcome, SchedulerError> {
        self.drive_concurrent_authoritative_quantum(request, max_host_workers)
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
    let mut event_log_entry_hashes = Vec::new();
    let mut yielded_between_quanta = true;

    loop {
        if scheduler.quiescence()?.is_quiescent() {
            return Ok(SchedulerLivenessReport {
                terminal: SchedulerTerminal::Quiescent,
                quanta: scheduler.quanta(),
                frontier: scheduler.frontier(),
                advanced_nodes,
                resolved_events,
                event_log_entries: event_log_entry_hashes.len(),
                event_log_offset: scheduler.event_log_offset(),
                event_log_entry_hashes,
                yielded_between_quanta,
                final_configuration: scheduler.configuration().clone(),
            });
        }

        if scheduler.reached_time_limit()? || scheduler.exhausted_quantum_budget() {
            return Ok(SchedulerLivenessReport {
                terminal: SchedulerTerminal::TimeLimitReached,
                quanta: scheduler.quanta(),
                frontier: scheduler.frontier(),
                advanced_nodes,
                resolved_events,
                event_log_entries: event_log_entry_hashes.len(),
                event_log_offset: scheduler.event_log_offset(),
                event_log_entry_hashes,
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
                if scheduler.last_topology_recompute {
                    continue;
                }
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
        event_log_entry_hashes.extend(
            outcome
                .event_log_entries
                .iter()
                .map(|entry| entry.content_hash),
        );
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
struct RuntimeSchedulerNode {
    id: SchedulerNodeId,
    counter: NodeCounter,
    activity: SchedulerNodeActivity,
    network_lookahead: NetworkLookahead,
    exact_local_event: ExactLocalEvent,
}

impl From<SchedulerScenarioNode> for RuntimeSchedulerNode {
    fn from(node: SchedulerScenarioNode) -> Self {
        Self {
            id: node.id,
            counter: node.counter,
            activity: node.activity,
            network_lookahead: node.network_lookahead,
            exact_local_event: node.exact_local_event,
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
struct AdvanceCandidate {
    index: usize,
    key: SharedTimelineKey,
    target_time: SimInstant,
    quiescent_horizon: Option<SimInstant>,
    conservative_dependency: Option<UnresolvedCrossNodeDependency>,
    allow_ceil_past_target: bool,
}

#[derive(Clone, Debug, PartialEq, Eq)]
enum EffectiveHorizonProjection {
    Infinite,
    Finite {
        target_time: SimInstant,
        quiescent_horizon: Option<SimInstant>,
        conservative_dependency: Option<UnresolvedCrossNodeDependency>,
        allow_ceil_past_target: bool,
    },
}

#[derive(Clone, Debug, PartialEq, Eq)]
struct AdvanceWindow {
    target_time: SimInstant,
    quiescent_horizon: Option<SimInstant>,
    conservative_dependency: Option<UnresolvedCrossNodeDependency>,
    allow_ceil_past_target: bool,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
struct IdleWakeTarget {
    wake_time: SimInstant,
    allow_ceil_past_target: bool,
}

#[derive(Clone, Debug, PartialEq, Eq)]
struct AdvancePlan {
    index: usize,
    node: SchedulerNodeId,
    before: NodeCounter,
    target_counter: u64,
    ceiling: SchedulerRunCeilingPublication,
    subdivision: Option<PlannedRunSubdivision>,
    quiescent_horizon: Option<SimInstant>,
}

#[derive(Clone, Debug, PartialEq, Eq)]
struct AdvancePlanDraft {
    index: usize,
    node: SchedulerNodeId,
    before: NodeCounter,
    target_counter: u64,
    quiescent_horizon: Option<SimInstant>,
}

#[derive(Clone, Debug, PartialEq, Eq)]
struct PlannedRunSubdivision {
    policy: SchedulerRunSubdivisionPolicy,
    slices: Vec<SchedulerRunSubdivisionSlice>,
}

#[derive(Clone, Debug, PartialEq, Eq)]
struct NodeAdvance {
    node: SchedulerNodeId,
    before: NodeCounter,
    after: NodeCounter,
    ceiling: SchedulerRunCeilingPublication,
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
        let draft = self.scheduler.advance_plan_draft(&candidate)?;
        let subdivision = self.scheduler.planned_run_subdivision(
            &draft.node,
            draft.before,
            draft.target_counter,
        )?;
        let ceiling = self.scheduler.publish_run_ceiling(
            draft.node.clone(),
            draft.before,
            draft.target_counter,
            candidate.target_time,
        )?;
        Ok(AdvancePlan {
            index: draft.index,
            node: draft.node,
            before: draft.before,
            target_counter: draft.target_counter,
            ceiling,
            subdivision,
            quiescent_horizon: draft.quiescent_horizon,
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
                    event_log_entries: Vec::new(),
                    event_log_segment_bytes: Vec::new(),
                    event_log_segment_hash: None,
                    event_log_offset: EventLogOffset::default(),
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
            event_log_entries: Vec::new(),
            event_log_segment_bytes: Vec::new(),
            event_log_segment_hash: None,
            event_log_offset: EventLogOffset::default(),
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
                limit: SchedulerHorizonLimit::Finite {
                    virtual_time: SimInstant { nanos: 41 },
                    ceiling: Icount { retired: 6 },
                },
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
                limit: SchedulerHorizonLimit::Finite {
                    virtual_time: SimInstant { nanos: 64 },
                    ceiling: Icount { retired: 8 },
                },
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
                limit: SchedulerHorizonLimit::Finite {
                    virtual_time: SimInstant { nanos: 50 },
                    ceiling: Icount { retired: 13 },
                },
                source: SchedulerHorizonSource::NetworkLookahead,
            })
        );
    }

    #[test]
    fn finite_lookahead_is_added_to_current_virtual_time() {
        let horizon = horizon_from_network_lookahead(
            SimInstant { nanos: 20 },
            NetworkLookahead::Finite(SimDuration { nanos: 7 }),
            ExactLocalEvent::NoArmedTimer,
            shift(0),
        );

        assert_eq!(
            horizon,
            Ok(SchedulerHorizon {
                limit: SchedulerHorizonLimit::Finite {
                    virtual_time: SimInstant { nanos: 27 },
                    ceiling: Icount { retired: 27 },
                },
                source: SchedulerHorizonSource::NetworkLookahead,
            })
        );
    }

    #[test]
    fn infinite_network_lookahead_without_local_event_is_unbounded() {
        let horizon = horizon_from_network_lookahead(
            SimInstant { nanos: 20 },
            NetworkLookahead::Infinite,
            ExactLocalEvent::NoArmedTimer,
            shift(0),
        );

        assert_eq!(horizon, Ok(SchedulerHorizon::infinite_network()));
    }

    #[test]
    fn exact_local_event_bounds_infinite_network_lookahead() {
        let horizon = horizon_from_network_lookahead(
            SimInstant { nanos: 20 },
            NetworkLookahead::Infinite,
            ExactLocalEvent::TimerDeadline {
                virtual_time: SimInstant { nanos: 23 },
            },
            shift(0),
        );

        assert_eq!(
            horizon,
            Ok(SchedulerHorizon {
                limit: SchedulerHorizonLimit::Finite {
                    virtual_time: SimInstant { nanos: 23 },
                    ceiling: Icount { retired: 23 },
                },
                source: SchedulerHorizonSource::ExactLocalTimer,
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
    fn scheduler_quiescence_detects_all_idle_authoritative_state() {
        let scheduler = test_scheduler(
            vec![test_scenario_node(
                "node-a",
                0,
                SchedulerNodeActivity::Idle,
                NetworkLookahead::Infinite,
                ExactLocalEvent::NoArmedTimer,
            )],
            Vec::new(),
        );

        let quiescence = scheduler
            .quiescence()
            .unwrap_or_else(|error| panic!("quiescence should compute: {error}"));

        assert!(quiescence.is_quiescent());
        assert_eq!(quiescence.blockers, Vec::new());
    }

    #[test]
    fn scheduler_quiescence_blocks_on_runnable_node_pending_event_and_control() {
        let consumer = scheduler_node("node-a", SchedulingNodeKind::Vm);
        let producer = scheduler_node("node-b", SchedulingNodeKind::Vm);
        let mut scheduler = test_scheduler(
            vec![test_scenario_node(
                "node-a",
                0,
                SchedulerNodeActivity::Runnable,
                NetworkLookahead::Infinite,
                ExactLocalEvent::NoArmedTimer,
            )],
            vec![event(7, &consumer, &producer, 3, b"pending")],
        );
        let control = ControlOperation {
            sequence: 11,
            kind: ControlOperationKind::Query,
        };
        scheduler.queue_control(control.clone());

        let quiescence = scheduler
            .quiescence()
            .unwrap_or_else(|error| panic!("quiescence should compute: {error}"));

        assert!(!quiescence.is_quiescent());
        assert!(
            quiescence
                .blockers
                .contains(&SchedulerQuiescenceBlocker::PendingControl { operation: control })
        );
        assert!(
            quiescence
                .blockers
                .contains(&SchedulerQuiescenceBlocker::PendingEvent {
                    key: event_key(7, &consumer, &producer, 3),
                })
        );
        assert!(
            quiescence
                .blockers
                .contains(&SchedulerQuiescenceBlocker::RunnableNode { node: consumer })
        );
    }

    #[test]
    fn scheduler_quiescence_blocks_idle_nodes_with_exact_local_wakeups() {
        let node = scheduler_node("node-a", SchedulingNodeKind::Vm);
        let scheduler = test_scheduler(
            vec![test_scenario_node(
                "node-a",
                0,
                SchedulerNodeActivity::Idle,
                NetworkLookahead::Infinite,
                ExactLocalEvent::TimerDeadline {
                    virtual_time: SimInstant { nanos: 23 },
                },
            )],
            Vec::new(),
        );

        let quiescence = scheduler
            .quiescence()
            .unwrap_or_else(|error| panic!("quiescence should compute: {error}"));

        assert_eq!(
            quiescence.blockers,
            vec![SchedulerQuiescenceBlocker::PendingExactLocalEvent {
                node,
                event: ExactLocalEvent::TimerDeadline {
                    virtual_time: SimInstant { nanos: 23 },
                },
            }]
        );
    }

    #[test]
    fn scheduler_quiescence_fast_forwards_idle_exact_wakeup_without_deadlock() {
        let scenario = SchedulerLivenessScenario::from_canonical_material(
            "idle-exact-wakeup",
            shift(0),
            8,
            SimInstant { nanos: 64 },
            vec![test_scenario_node(
                "node-a",
                0,
                SchedulerNodeActivity::Idle,
                NetworkLookahead::Infinite,
                ExactLocalEvent::TimerDeadline {
                    virtual_time: SimInstant { nanos: 23 },
                },
            )],
            Vec::new(),
        );

        let report = check_scheduler_liveness(scenario)
            .unwrap_or_else(|error| panic!("idle exact wakeup should not deadlock: {error}"));

        assert_eq!(report.terminal, SchedulerTerminal::Quiescent);
        assert_eq!(report.frontier, VirtualTime { ticks: 23 });
        assert_eq!(
            report.advanced_nodes,
            vec![scheduler_node("node-a", SchedulingNodeKind::Vm)]
        );
    }

    #[test]
    fn scheduler_quiescence_idle_exact_wakeup_after_time_limit_stops_at_limit() {
        let scenario = SchedulerLivenessScenario::from_canonical_material(
            "idle-exact-wakeup-after-limit",
            shift(0),
            8,
            SimInstant { nanos: 64 },
            vec![test_scenario_node(
                "node-a",
                0,
                SchedulerNodeActivity::Idle,
                NetworkLookahead::Infinite,
                ExactLocalEvent::TimerDeadline {
                    virtual_time: SimInstant { nanos: 100 },
                },
            )],
            Vec::new(),
        );

        let report = check_scheduler_liveness(scenario)
            .unwrap_or_else(|error| panic!("idle exact wakeup should respect limit: {error}"));

        assert_eq!(report.terminal, SchedulerTerminal::TimeLimitReached);
        assert_eq!(report.frontier, VirtualTime { ticks: 64 });
        assert_eq!(
            report.advanced_nodes,
            vec![scheduler_node("node-a", SchedulingNodeKind::Vm)]
        );
    }

    #[test]
    fn scheduler_quiescence_fast_forwards_idle_pending_delivery_without_deadlock() {
        let consumer = scheduler_node("node-a", SchedulingNodeKind::Vm);
        let producer = scheduler_node("node-b", SchedulingNodeKind::Vm);
        let scenario = SchedulerLivenessScenario::from_canonical_material(
            "idle-pending-delivery",
            shift(0),
            8,
            SimInstant { nanos: 64 },
            vec![test_scenario_node(
                "node-a",
                0,
                SchedulerNodeActivity::Idle,
                NetworkLookahead::Infinite,
                ExactLocalEvent::NoArmedTimer,
            )],
            vec![event(17, &consumer, &producer, 0, b"wake")],
        );

        let report = check_scheduler_liveness(scenario)
            .unwrap_or_else(|error| panic!("idle pending delivery should not deadlock: {error}"));

        assert_eq!(report.terminal, SchedulerTerminal::Quiescent);
        assert_eq!(report.frontier, VirtualTime { ticks: 17 });
        assert_eq!(report.resolved_events, 1);
    }

    #[test]
    fn scheduler_quiescence_blocks_future_io_and_fault_events() {
        let consumer = scheduler_node("node-a", SchedulingNodeKind::Vm);
        let disk = scheduler_node("node-a", SchedulingNodeKind::Disk);
        let control_plane = scheduler_node("plan", SchedulingNodeKind::ControlPlane);
        let fault = FaultId {
            name: String::from("planned-fault"),
        };
        let scheduler = test_scheduler(
            vec![test_scenario_node(
                "node-a",
                0,
                SchedulerNodeActivity::Idle,
                NetworkLookahead::Infinite,
                ExactLocalEvent::NoArmedTimer,
            )],
            vec![
                io_completion_event(5, &consumer, &disk, 1, b"io"),
                fault_event(9, &consumer, &control_plane, 2, fault),
            ],
        );

        let quiescence = scheduler
            .quiescence()
            .unwrap_or_else(|error| panic!("quiescence should compute: {error}"));

        assert!(!quiescence.is_quiescent());
        assert!(
            quiescence
                .blockers
                .contains(&SchedulerQuiescenceBlocker::PendingEvent {
                    key: event_key(5, &consumer, &disk, 1),
                })
        );
        assert!(
            quiescence
                .blockers
                .contains(&SchedulerQuiescenceBlocker::PendingEvent {
                    key: event_key(9, &consumer, &control_plane, 2),
                })
        );
        assert!(quiescence.blockers.contains(
            &SchedulerQuiescenceBlocker::PendingExactLocalEvent {
                node: consumer,
                event: ExactLocalEvent::IoCompletion {
                    virtual_time: SimInstant { nanos: 5 },
                    sub_node: disk,
                },
            }
        ));
    }

    #[test]
    fn scheduler_quiescence_ignores_idle_nodes_when_peer_can_advance() {
        let runner = scheduler_node("runner", SchedulingNodeKind::Vm);
        let mut scheduler = test_scheduler(
            vec![
                test_scenario_node(
                    "idle",
                    0,
                    SchedulerNodeActivity::Idle,
                    NetworkLookahead::Finite(SimDuration { nanos: 1 }),
                    ExactLocalEvent::TimerDeadline {
                        virtual_time: SimInstant { nanos: 100 },
                    },
                ),
                test_scenario_node(
                    "runner",
                    0,
                    SchedulerNodeActivity::Runnable,
                    NetworkLookahead::Finite(SimDuration { nanos: 4 }),
                    ExactLocalEvent::NoArmedTimer,
                ),
            ],
            Vec::new(),
        );

        let quiescence = scheduler
            .quiescence()
            .unwrap_or_else(|error| panic!("quiescence should compute: {error}"));
        let request = QuantumRequest {
            configuration: scheduler.configuration().clone(),
            control: Vec::new(),
        };
        let outcome = scheduler
            .drive_quantum(request)
            .unwrap_or_else(|error| panic!("runnable peer should advance: {error}"));

        assert_eq!(
            quiescence.blockers,
            vec![
                SchedulerQuiescenceBlocker::PendingExactLocalEvent {
                    node: scheduler_node("idle", SchedulingNodeKind::Vm),
                    event: ExactLocalEvent::TimerDeadline {
                        virtual_time: SimInstant { nanos: 100 },
                    },
                },
                SchedulerQuiescenceBlocker::RunnableNode {
                    node: runner.clone(),
                },
            ]
        );
        assert_eq!(outcome.advanced_node, Some(runner));
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

    fn test_scheduler(
        nodes: Vec<SchedulerScenarioNode>,
        pending_events: Vec<ScheduledEvent>,
    ) -> SingleScheduler {
        SingleScheduler::new(SchedulerLivenessScenario::from_canonical_material(
            "test-scheduler-quiescence",
            shift(0),
            16,
            SimInstant { nanos: 64 },
            nodes,
            pending_events,
        ))
        .unwrap_or_else(|error| panic!("test scheduler should build: {error}"))
    }

    fn test_scenario_node(
        name: &str,
        counter: u64,
        activity: SchedulerNodeActivity,
        network_lookahead: NetworkLookahead,
        exact_local_event: ExactLocalEvent,
    ) -> SchedulerScenarioNode {
        SchedulerScenarioNode {
            id: scheduler_node(name, SchedulingNodeKind::Vm),
            counter: NodeCounter { ticks: counter },
            activity,
            network_lookahead,
            exact_local_event,
        }
    }

    fn io_completion_event(
        virtual_time: u64,
        consumer: &SchedulerNodeId,
        producer: &SchedulerNodeId,
        sequence: u64,
        payload: &[u8],
    ) -> ScheduledEvent {
        ScheduledEvent {
            key: event_key(virtual_time, consumer, producer, sequence),
            payload: ScheduledEventPayload::IoCompletion(IoCompletion {
                sub_node: producer.clone(),
                target: consumer.node.clone(),
                delivery_icount: Icount {
                    retired: virtual_time,
                },
                payload: payload.to_vec(),
            }),
        }
    }

    fn fault_event(
        virtual_time: u64,
        consumer: &SchedulerNodeId,
        producer: &SchedulerNodeId,
        sequence: u64,
        fault: FaultId,
    ) -> ScheduledEvent {
        ScheduledEvent {
            key: event_key(virtual_time, consumer, producer, sequence),
            payload: ScheduledEventPayload::FaultActivation(fault),
        }
    }
}
