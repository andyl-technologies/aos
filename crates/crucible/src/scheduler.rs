//! Single-scheduler quantum-loop boundary.
//!
//! The module owns the L3 interface that all virtual-time advancement and
//! cross-node event resolution must pass through. It intentionally defines the
//! boundary and ordering vocabulary, implements the authoritative
//! PICK/RUN/RESOLVE/EMIT/STEP quantum boundary, and materializes scheduler
//! EMIT output as dense, content-addressed event-log segment bytes before STEP
//! advances the frontier.

use std::collections::BTreeMap;
use std::collections::BTreeSet;
use std::collections::VecDeque;
use std::error::Error;
use std::fmt;
use std::sync::Arc;
use std::sync::mpsc::{self, Receiver, Sender, TryRecvError};

use crate::device::{
    NetworkFaultApplication, NetworkLinkDirection, apply_combined_network_faults_to_scheduler,
    block_faults_from_combined_block, heal_combined_network_faults_to_scheduler,
    ninep_faults_from_combined_ninep,
};
use crate::model::{DagStore, MemoryDagStore, Schedule};
use crate::node_fault::{
    NodeTimingFaults, NodeTimingProjection, node_timing_faults_from_combined_node,
};
use crate::trigger::{
    Action, ConditionEvaluationPass, ConditionEventLogPrefix, ConditionLeafOracle, EventFiring,
    EventFirings, EventGraph, EventGraphState, HostAssertionReport, LogLevel, ObservableEvent,
    ObservableEventPayload, OfflineAssertionCheckError, RecordedAssertionLog,
};
use crate::{
    AssertionId, AssertionPhase, AssertionQuantifierKind, BackendError, BackendInput,
    CombinedFaults, CombinedNetworkFaults, CombinedNodeFaults, CombinedPartitionFault,
    Configuration, ContentHash, ControlFaultAction, ControlFaultDecision, Decision,
    DecisionRecorder, DecisionRngState, DeliveryOrderDecision, EventId, EventKey, EventLogOffset,
    EventSequenceState, Fault, FaultDecision, FaultId, FaultRateBasisPoints, FaultTag,
    FingerprintSample, GdbAttachInfo, GdbListen, Icount, LinkId, MarkerId, MembershipFault,
    NodeCounter, NodeId, NodeLifecycle, PartitionDirection, PendingFrame, PreemptionDecision,
    PreemptionKind, RestartPolicy, RngDecision, RngStreamId, RngStreamPosition, ScenarioDef,
    SchedulerNodeId, SchedulerState, SchedulingNodeKind, SearchFrontierChoices, Shift, SimDuration,
    SimInstant, SimulationBackend, TimeConversionError, TimerId, VcpuId, VirtualTime, World,
    WorldLookaheadEdge, WorldStaticTopology, step,
};

const SCHEDULER_ACTOR_RNG_DOMAIN: &str = "crucible.scheduler.actor";
const SCHEDULER_QUANTUM_STREAM: &str = "quantum";
const EVENT_LOG_SEGMENT_BINARY_MAGIC: &[u8; 16] = b"CRUCIBLE-ELOGSEG";
const EVENT_LOG_SEGMENT_BINARY_VERSION: u32 = 1;
const EVENT_LOG_SEGMENT_NODE_ABSENT: u8 = 0;
const EVENT_LOG_SEGMENT_NODE_PRESENT: u8 = 1;
const EVENT_LOG_LEVEL_TRACE: u8 = 0;
const EVENT_LOG_LEVEL_DEBUG: u8 = 1;
const EVENT_LOG_LEVEL_INFO: u8 = 2;
const EVENT_LOG_LEVEL_WARN: u8 = 3;
const EVENT_LOG_LEVEL_ERROR: u8 = 4;
const EVENT_LOG_CLASS_CAUSAL: u8 = 0;
const EVENT_LOG_CLASS_OBSERVATIONAL: u8 = 1;

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

    /// Samples a deterministic execution fingerprint for `node`.
    ///
    /// Backends that do not own concrete VM state use the default unsupported
    /// implementation. Backend-backed loops should delegate to their
    /// [`SimulationBackend`] so control-plane verification compares real
    /// icount/register/memory evidence rather than API observation summaries.
    ///
    /// # Errors
    ///
    /// Returns [`SchedulerError`] when the wrapped backend cannot sample the
    /// requested node or does not support execution fingerprints.
    fn sample_fingerprint(&mut self, node: NodeId) -> Result<FingerprintSample, SchedulerError> {
        let _ = node;
        Err(BackendError::Unsupported {
            capability: "sample_fingerprint",
        }
        .into())
    }

    /// Applies scheduler-owned control at the current boundary.
    ///
    /// This hook is for control operations that must take effect without
    /// advancing another scheduler quantum, such as interactive fault injection
    /// acknowledged at a session boundary. Pure model loops can use the default
    /// implementation when they have no scheduler-owned control state.
    ///
    /// # Errors
    ///
    /// Returns [`SchedulerError`] when a control operation cannot be admitted or
    /// applied at the boundary.
    fn apply_control_at_boundary(
        &mut self,
        control: Vec<ControlOperation>,
    ) -> Result<Vec<SchedulerEventLogEntry>, SchedulerError> {
        let _ = control;
        Ok(Vec::new())
    }

    /// Opens the optional backend gdbstub channel outside scheduler order.
    ///
    /// Pure loops and backends without a real mediated gdbstub use the default
    /// unsupported capability error.
    ///
    /// # Errors
    ///
    /// Returns [`SchedulerError`] when the wrapped backend rejects or does not
    /// support the gdbstub capability.
    fn open_gdbstub(
        &mut self,
        node: NodeId,
        listen: GdbListen,
    ) -> Result<GdbAttachInfo, SchedulerError> {
        let _ = node;
        let _ = listen;
        Err(BackendError::Unsupported {
            capability: "open_gdbstub",
        }
        .into())
    }

    /// Shuts down scheduler/backend resources owned by this quantum loop.
    ///
    /// Implementations that own live backends should override this hook and
    /// perform idempotent cleanup. Pure model loops can use the default no-op.
    ///
    /// # Errors
    ///
    /// Returns [`SchedulerError`] when shutdown cannot complete cleanly.
    fn shutdown(&mut self) -> Result<(), SchedulerError> {
        Ok(())
    }
}

/// Quantum-loop adapter that exposes optional capabilities from a live backend.
///
/// The authoritative scheduler loop remains responsible for virtual-time
/// ordering and control admission. The backend is used only for backend-owned
/// capabilities that do not belong in the pure scheduler, such as opening a
/// mediated gdbstub endpoint.
#[derive(Clone, Debug)]
pub struct BackendQuantumLoop<L, B> {
    loop_impl: L,
    backend: B,
}

impl<L, B> BackendQuantumLoop<L, B> {
    /// Builds an adapter from an authoritative quantum loop and backend.
    #[must_use]
    pub const fn new(loop_impl: L, backend: B) -> Self {
        Self { loop_impl, backend }
    }

    /// Returns the wrapped quantum loop.
    #[must_use]
    pub const fn loop_impl(&self) -> &L {
        &self.loop_impl
    }

    /// Returns the wrapped backend.
    #[must_use]
    pub const fn backend(&self) -> &B {
        &self.backend
    }

    /// Returns mutable access to the wrapped backend.
    #[must_use]
    pub fn backend_mut(&mut self) -> &mut B {
        &mut self.backend
    }

    /// Consumes the adapter and returns its parts.
    #[must_use]
    pub fn into_parts(self) -> (L, B) {
        (self.loop_impl, self.backend)
    }
}

impl<L, B> QuantumLoop for BackendQuantumLoop<L, B>
where
    L: QuantumLoop,
    B: SimulationBackend,
{
    fn drive_quantum(&mut self, request: QuantumRequest) -> Result<QuantumOutcome, SchedulerError> {
        self.loop_impl.drive_quantum(request)
    }

    fn sample_fingerprint(&mut self, node: NodeId) -> Result<FingerprintSample, SchedulerError> {
        self.backend.fingerprint(node).map_err(Into::into)
    }

    fn apply_control_at_boundary(
        &mut self,
        control: Vec<ControlOperation>,
    ) -> Result<Vec<SchedulerEventLogEntry>, SchedulerError> {
        self.loop_impl.apply_control_at_boundary(control)
    }

    fn open_gdbstub(
        &mut self,
        node: NodeId,
        listen: GdbListen,
    ) -> Result<GdbAttachInfo, SchedulerError> {
        self.backend.open_gdbstub(node, listen).map_err(Into::into)
    }

    fn shutdown(&mut self) -> Result<(), SchedulerError> {
        let loop_result = self.loop_impl.shutdown();
        let backend_result = self.backend.shutdown().map_err(SchedulerError::from);
        loop_result?;
        backend_result
    }
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
    /// Human-readable text projection derived from `event_log_segment_bytes`.
    pub event_log_segment_text: String,
    /// Content address of `event_log_segment_bytes`, when this quantum emitted a segment.
    pub event_log_segment_hash: Option<ContentHash>,
    /// Event-log offset after this quantum's EMIT segment.
    pub event_log_offset: EventLogOffset,
    /// Scheduler-owned quiescence evidence at this quantum boundary, when available.
    pub scheduler_quiescence: Option<SchedulerQuiescence>,
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

/// Per-node retired-instruction stamp attached to an event-log time.
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub struct EventLogIcountStamp {
    /// Node whose retired-instruction counter was sampled, when node-local.
    pub node: Option<NodeId>,
    /// Retired-instruction count at the event boundary.
    pub icount: Icount,
}

/// Virtual-time coordinate enriched with a deterministic icount stamp.
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub struct EventLogTime {
    /// Scheduler virtual time at which the entry occurred.
    pub virtual_time: VirtualTime,
    /// Retired-instruction coordinate at the same boundary.
    pub icount: EventLogIcountStamp,
}

impl EventLogTime {
    /// Builds a time coordinate using virtual time as the scheduler-boundary icount.
    #[must_use]
    pub const fn from_virtual_time(virtual_time: VirtualTime) -> Self {
        Self {
            virtual_time,
            icount: EventLogIcountStamp {
                node: None,
                icount: Icount {
                    retired: virtual_time.ticks,
                },
            },
        }
    }

    /// Adds a per-node icount stamp to this coordinate.
    #[must_use]
    pub fn with_icount(mut self, node: NodeId, icount: Icount) -> Self {
        self.icount = EventLogIcountStamp {
            node: Some(node),
            icount,
        };
        self
    }
}

/// Closed origin set for unified event-log entries.
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub enum EventSource {
    /// A scenario-defined temporal event or fault.
    Scenario {
        /// Stable event-graph id that produced the entry.
        event: EventId,
    },
    /// The scheduler, temporal graph, fault subsystem, or assertion engine.
    Engine,
    /// A VM node or deterministic I/O sub-node.
    Node {
        /// Scenario node that originated the entry.
        node: NodeId,
    },
    /// Guest-observed marker or black-box guest signal.
    Guest {
        /// Scenario node whose guest produced the entry.
        node: NodeId,
    },
    /// A control-plane command and its client correlation id.
    Command {
        /// Session-local command correlation id.
        command_id: u64,
    },
}

/// Display verbosity for an event-log entry.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum EventLevel {
    /// Highest-frequency internal state.
    Trace,
    /// Routine diagnostic detail.
    Debug,
    /// User-meaningful state change.
    Info,
    /// Unusual but non-fatal condition.
    Warn,
    /// Failure or assertion violation.
    Error,
}

/// Typed value carried by an open-set event payload attribute.
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub enum EventAttributeValue {
    /// Boolean attribute.
    Bool(bool),
    /// Unsigned integer attribute.
    U64(u64),
    /// Wide unsigned integer attribute.
    U128(u128),
    /// Stable string attribute.
    String(String),
    /// Raw byte attribute.
    Bytes(Vec<u8>),
    /// Scenario node identifier attribute.
    Node(NodeId),
    /// Event-graph identifier attribute.
    Event(EventId),
    /// Fault identifier attribute.
    Fault(FaultId),
    /// Virtual-time attribute.
    VirtualTime(VirtualTime),
    /// Retired-instruction count attribute.
    Icount(Icount),
    /// Display-level attribute.
    Level(EventLevel),
}

/// Open-set event payload read by observability projections.
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub struct EventPayload {
    kind: String,
    attributes: BTreeMap<String, EventAttributeValue>,
}

impl EventPayload {
    /// Builds an open-set payload with typed named attributes.
    #[must_use]
    pub fn new(kind: impl Into<String>, attributes: BTreeMap<String, EventAttributeValue>) -> Self {
        Self {
            kind: kind.into(),
            attributes,
        }
    }

    /// Builds the diagnostic escape-hatch payload.
    #[must_use]
    pub fn diagnostic(
        name: impl Into<String>,
        mut details: BTreeMap<String, EventAttributeValue>,
    ) -> Self {
        details.insert(
            String::from("name"),
            EventAttributeValue::String(name.into()),
        );
        Self::new("diagnostic", details)
    }

    /// Returns the open-set payload kind.
    #[must_use]
    pub fn kind(&self) -> &str {
        &self.kind
    }

    /// Returns all typed attributes keyed by name.
    #[must_use]
    pub fn attributes(&self) -> &BTreeMap<String, EventAttributeValue> {
        &self.attributes
    }

    /// Returns one typed attribute by name.
    #[must_use]
    pub fn attribute(&self, name: &str) -> Option<&EventAttributeValue> {
        self.attributes.get(name)
    }

    /// Returns a string attribute by name.
    #[must_use]
    pub fn string(&self, name: &str) -> Option<&str> {
        match self.attribute(name) {
            Some(EventAttributeValue::String(value)) => Some(value),
            _ => None,
        }
    }

    /// Returns a boolean attribute by name.
    #[must_use]
    pub fn bool(&self, name: &str) -> Option<bool> {
        match self.attribute(name) {
            Some(EventAttributeValue::Bool(value)) => Some(*value),
            _ => None,
        }
    }

    /// Returns an unsigned integer attribute by name.
    #[must_use]
    pub fn u64(&self, name: &str) -> Option<u64> {
        match self.attribute(name) {
            Some(EventAttributeValue::U64(value)) => Some(*value),
            _ => None,
        }
    }

    /// Returns a wide unsigned integer attribute by name.
    #[must_use]
    pub fn u128(&self, name: &str) -> Option<u128> {
        match self.attribute(name) {
            Some(EventAttributeValue::U128(value)) => Some(*value),
            _ => None,
        }
    }

    /// Returns a byte-string attribute by name.
    #[must_use]
    pub fn bytes(&self, name: &str) -> Option<&[u8]> {
        match self.attribute(name) {
            Some(EventAttributeValue::Bytes(value)) => Some(value),
            _ => None,
        }
    }

    /// Returns a node-id attribute by name.
    #[must_use]
    pub fn node(&self, name: &str) -> Option<&NodeId> {
        match self.attribute(name) {
            Some(EventAttributeValue::Node(value)) => Some(value),
            _ => None,
        }
    }

    /// Returns an event-id attribute by name.
    #[must_use]
    pub fn event(&self, name: &str) -> Option<&EventId> {
        match self.attribute(name) {
            Some(EventAttributeValue::Event(value)) => Some(value),
            _ => None,
        }
    }

    /// Returns a fault-id attribute by name.
    #[must_use]
    pub fn fault(&self, name: &str) -> Option<&FaultId> {
        match self.attribute(name) {
            Some(EventAttributeValue::Fault(value)) => Some(value),
            _ => None,
        }
    }

    /// Returns a virtual-time attribute by name.
    #[must_use]
    pub fn virtual_time(&self, name: &str) -> Option<VirtualTime> {
        match self.attribute(name) {
            Some(EventAttributeValue::VirtualTime(value)) => Some(*value),
            _ => None,
        }
    }

    /// Returns an icount attribute by name.
    #[must_use]
    pub fn icount(&self, name: &str) -> Option<Icount> {
        match self.attribute(name) {
            Some(EventAttributeValue::Icount(value)) => Some(*value),
            _ => None,
        }
    }

    /// Returns a display-level attribute by name.
    #[must_use]
    pub fn level(&self, name: &str) -> Option<EventLevel> {
        match self.attribute(name) {
            Some(EventAttributeValue::Level(value)) => Some(*value),
            _ => None,
        }
    }
}

/// One scheduler-emitted entry in the unified event log.
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub struct SchedulerEventLogEntry {
    /// Dense per-run sequence number assigned by the scheduler append path.
    sequence: u64,
    /// Virtual-time coordinate, optionally enriched with per-node icount.
    at: EventLogTime,
    /// Closed source that identifies where the entry originated.
    source: EventSource,
    /// Display verbosity, orthogonal to determinism class.
    level: EventLevel,
    /// Causal-vs-observational class recorded by the typed append path.
    class: SchedulerEventLogClass,
    /// Open-set payload kind and typed named attributes.
    event_payload: EventPayload,
    /// Typed payload carried by the event-log entry.
    payload: SchedulerEventLogPayload,
    /// Content address of this entry's canonical material.
    content_hash: ContentHash,
    provenance: SchedulerEventLogEntryProvenance,
}

/// Compatibility name for entries in the unified event log.
pub type LogEntry = SchedulerEventLogEntry;

/// Compatibility name for the causal-vs-observational event class.
pub type EventClass = SchedulerEventLogClass;

#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
struct SchedulerEventLogEntryProvenance;

impl SchedulerEventLogEntry {
    /// Builds a scheduler-owned assertion-state observation for deterministic
    /// test-double loops.
    ///
    /// Callers must pass the next dense per-run event-log sequence number for
    /// the segment they are constructing. This constructor is for trusted
    /// scheduler loop implementations that already own event-log offset
    /// accounting; it must not be used to rewrite replayed logs or bypass
    /// replay-oracle validation.
    #[must_use]
    pub fn assertion_state_observation(
        sequence: u64,
        at: VirtualTime,
        name: AssertionId,
        state: AssertionPhase,
    ) -> Self {
        scheduler_event_log_entry(
            sequence,
            at,
            SchedulerEventLogPayload::Observable(ObservableEventPayload::AssertionStateChanged {
                name,
                state,
            }),
        )
    }

    /// Builds a scheduler-owned guest-marker observation for deterministic
    /// test-double loops.
    ///
    /// Callers must pass the next dense per-run event-log sequence number for
    /// the segment they are constructing. This constructor is for trusted
    /// scheduler loop implementations that already own event-log offset
    /// accounting; it must not be used to rewrite replayed logs or bypass
    /// replay-oracle validation.
    #[must_use]
    pub fn guest_marker_observation(
        sequence: u64,
        retired_icount: Icount,
        node: NodeId,
        marker: MarkerId,
    ) -> Self {
        scheduler_event_log_entry(
            sequence,
            VirtualTime {
                ticks: retired_icount.retired,
            },
            SchedulerEventLogPayload::Observable(ObservableEventPayload::GuestMarker {
                retired_icount,
                node,
                marker,
            }),
        )
    }

    /// Builds an observable condition entry as if appended by scheduler EMIT.
    #[must_use]
    pub(crate) fn observable(
        sequence: u64,
        at: VirtualTime,
        payload: ObservableEventPayload,
    ) -> Self {
        scheduler_event_log_entry(sequence, at, SchedulerEventLogPayload::Observable(payload))
    }

    /// Builds a deterministic condition-evaluation boundary entry.
    #[must_use]
    pub(crate) fn evaluation_boundary(
        sequence: u64,
        at: VirtualTime,
        kind: SchedulerEvaluationBoundaryKind,
    ) -> Self {
        scheduler_event_log_entry(
            sequence,
            at,
            SchedulerEventLogPayload::EvaluationBoundary(kind),
        )
    }

    /// Builds an observational diagnostic entry as if appended by scheduler EMIT.
    #[must_use]
    pub fn diagnostic(sequence: u64, at: VirtualTime, diagnostic: EventDiagnosticPayload) -> Self {
        scheduler_event_log_entry(
            sequence,
            at,
            SchedulerEventLogPayload::Diagnostic(diagnostic),
        )
    }

    /// Builds a causal catalog `fork` marker with debug-specific attributes.
    #[must_use]
    pub(crate) fn fork_marker(
        sequence: u64,
        at: VirtualTime,
        from_checkpoint_id: ContentHash,
        schedule_delta: ContentHash,
        mut attributes: BTreeMap<String, EventAttributeValue>,
    ) -> Self {
        attributes.insert(
            String::from("from_checkpoint_id"),
            EventAttributeValue::String(from_checkpoint_id.to_hex()),
        );
        attributes.insert(
            String::from("schedule_delta"),
            EventAttributeValue::String(schedule_delta.to_hex()),
        );
        scheduler_event_log_entry_with_class(
            sequence,
            at,
            SchedulerEventLogClass::Causal,
            EventPayload::new("fork", attributes.clone()),
            SchedulerEventLogPayload::Diagnostic(EventDiagnosticPayload::new(
                "debug.non_canonical_fork",
                EventLevel::Info,
                attributes,
            )),
        )
    }

    /// Returns the dense event-log sequence number assigned by scheduler EMIT.
    #[must_use]
    pub fn sequence(&self) -> u64 {
        self.sequence
    }

    /// Returns the virtual-time coordinate at which the entry occurred.
    #[must_use]
    pub fn at(&self) -> VirtualTime {
        self.at.virtual_time
    }

    /// Returns the full event-log time coordinate.
    #[must_use]
    pub fn time(&self) -> &EventLogTime {
        &self.at
    }

    /// Returns the closed event source.
    #[must_use]
    pub fn source(&self) -> &EventSource {
        &self.source
    }

    /// Returns the display verbosity level.
    #[must_use]
    pub fn level(&self) -> EventLevel {
        self.level
    }

    /// Returns the open-set payload view for projection consumers.
    #[must_use]
    pub fn event_payload(&self) -> &EventPayload {
        &self.event_payload
    }

    /// Returns the causal-vs-observational class recorded for this entry.
    #[must_use]
    pub fn class(&self) -> SchedulerEventLogClass {
        self.class
    }

    /// Returns the typed payload carried by this event-log entry.
    #[must_use]
    pub fn payload(&self) -> &SchedulerEventLogPayload {
        &self.payload
    }

    /// Returns the content address of this entry's canonical material.
    #[must_use]
    pub fn content_hash(&self) -> ContentHash {
        self.content_hash
    }

    /// Returns whether this entry's content hash matches its canonical material.
    #[must_use]
    pub fn has_valid_content_hash(&self) -> bool {
        if !self.class_matches_catalog() {
            return false;
        }
        self.content_hash
            == ContentHash::from_canonical_material(
                "crucible.scheduler.event-log.entry.v1",
                &scheduler_event_log_entry_material(
                    self.sequence,
                    &self.at,
                    &self.source,
                    self.level,
                    self.class,
                    &self.event_payload,
                    &self.payload,
                ),
            )
    }

    /// Returns whether the recorded class matches the event-kind catalog.
    #[must_use]
    pub fn class_matches_catalog(&self) -> bool {
        match event_kind_catalog_class(&self.event_payload) {
            Some(class) => self.class == class,
            None => false,
        }
    }

    #[cfg(any(debug_assertions, feature = "test-support"))]
    pub(crate) fn with_content_hash_for_test(mut self, content_hash: ContentHash) -> Self {
        self.content_hash = content_hash;
        self
    }

    #[cfg(any(debug_assertions, feature = "test-support"))]
    pub(crate) fn with_payload_for_test(
        sequence: u64,
        at: VirtualTime,
        payload: SchedulerEventLogPayload,
    ) -> Self {
        scheduler_event_log_entry(sequence, at, payload)
    }

    #[cfg(any(debug_assertions, feature = "test-support"))]
    pub(crate) fn with_open_payload_for_test(
        sequence: u64,
        at: VirtualTime,
        class: SchedulerEventLogClass,
        event_payload: EventPayload,
        payload: SchedulerEventLogPayload,
    ) -> Self {
        scheduler_event_log_entry_with_class(sequence, at, class, event_payload, payload)
    }

    #[cfg(any(debug_assertions, feature = "test-support"))]
    pub(crate) fn with_time_for_test(self, at: EventLogTime) -> Self {
        scheduler_event_log_entry_with_material(
            self.sequence,
            at,
            self.source,
            self.level,
            self.class,
            self.event_payload,
            self.payload,
        )
    }
}

#[derive(Clone)]
struct EventLogSegmentStore {
    store: Arc<dyn DagStore>,
}

impl EventLogSegmentStore {
    fn memory() -> Self {
        Self {
            store: Arc::new(MemoryDagStore::new()),
        }
    }

    fn from_store(store: Arc<dyn DagStore>) -> Self {
        Self { store }
    }

    fn put_segment(&self, bytes: &[u8]) -> Result<ContentHash, SchedulerError> {
        let expected = ContentHash::from_bytes(bytes);
        let stored = self
            .store
            .put(bytes)
            .map_err(|error| SchedulerError::BoundaryViolation {
                message: format!(
                    "event-log segment store rejected canonical segment bytes: {error}"
                ),
            })?;
        if stored != expected {
            return Err(SchedulerError::BoundaryViolation {
                message: format!(
                    "event-log segment store returned {}, expected {}",
                    stored.to_hex(),
                    expected.to_hex()
                ),
            });
        }
        Ok(stored)
    }
}

impl fmt::Debug for EventLogSegmentStore {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("EventLogSegmentStore { store: <content-addressed> }")
    }
}

/// The single unified event log for one run.
///
/// `EventLog` is the owner of append sequencing, prefix content-addressing, and
/// the condition-evaluation prefix derived from the same retained entries. All
/// observability consumers take projections of this one stream.
#[derive(Clone, Debug)]
pub struct EventLog {
    segment_store: EventLogSegmentStore,
    prefix: ContentHash,
    offset: EventLogOffset,
    bytes: u64,
    events: u64,
    condition_entries: Vec<LogEntry>,
    condition_base_events: u64,
    condition_prefix: ConditionEventLogPrefix,
}

impl EventLog {
    /// Builds an empty unified event log.
    #[must_use]
    pub fn new() -> Self {
        Self::from_segment_store(EventLogSegmentStore::memory())
    }

    /// Builds an empty unified event log backed by `store`.
    ///
    /// Sharing the same store between a temporal graph and forked event logs
    /// makes appended segment objects BLAKE3-keyed and idempotently deduplicated
    /// by the same content-addressed store used for checkpoint closure objects.
    #[must_use]
    pub fn with_segment_store(store: Arc<dyn DagStore>) -> Self {
        Self::from_segment_store(EventLogSegmentStore::from_store(store))
    }

    fn from_segment_store(segment_store: EventLogSegmentStore) -> Self {
        let prefix = scheduler_event_log_empty_prefix();
        Self::from_offset_and_segment_store(EventLogOffset::new(prefix, 0, 0), segment_store)
    }

    /// Builds a unified event log resumed from `offset`.
    #[must_use]
    pub fn from_offset(offset: EventLogOffset) -> Self {
        Self::from_offset_and_segment_store(offset, EventLogSegmentStore::memory())
    }

    /// Builds a unified event log resumed from `offset` and backed by `store`.
    ///
    /// The next append continues after the event count and byte offset recorded
    /// in `offset`, using the reconstructed full prefix as the new segment's
    /// shared prefix.
    #[must_use]
    pub fn from_offset_with_segment_store(
        offset: EventLogOffset,
        store: Arc<dyn DagStore>,
    ) -> Self {
        Self::from_offset_and_segment_store(offset, EventLogSegmentStore::from_store(store))
    }

    fn from_offset_and_segment_store(
        offset: EventLogOffset,
        segment_store: EventLogSegmentStore,
    ) -> Self {
        let prefix = scheduler_event_log_prefix_for_resume(offset);
        Self {
            segment_store,
            prefix,
            offset,
            bytes: offset.bytes,
            events: offset.events,
            condition_entries: Vec::new(),
            condition_base_events: offset.events,
            condition_prefix: ConditionEventLogPrefix::genesis().with_event_log_offset(offset),
        }
    }

    /// Returns the current shared-prefix offset.
    #[must_use]
    pub fn offset(&self) -> EventLogOffset {
        self.offset
    }

    /// Returns the condition-evaluation projection over the retained log prefix.
    #[must_use]
    pub fn condition_prefix(&self) -> &ConditionEventLogPrefix {
        &self.condition_prefix
    }

    /// Appends black-box observable condition facts to this event log.
    ///
    /// # Errors
    ///
    /// Returns [`SchedulerError`] when assigning dense event-log sequences or
    /// appending the event-log segment would overflow scheduler offsets, or when
    /// the resulting checked condition prefix is invalid.
    pub fn append_observable_events(
        &mut self,
        events: impl IntoIterator<Item = ObservableEvent>,
    ) -> Result<SchedulerEventLogAppend, SchedulerError> {
        let mut entries = Vec::new();
        for event in events {
            let sequence = self.next_sequence(entries.len())?;
            entries.push(scheduler_event_log_entry(
                sequence,
                event.at(),
                SchedulerEventLogPayload::Observable(event.payload().clone()),
            ));
        }
        self.append_entries(entries)
    }

    /// Appends a deterministic trigger/assertion evaluation boundary.
    ///
    /// # Errors
    ///
    /// Returns [`SchedulerError`] when assigning the dense event-log sequence or
    /// appending the event-log segment would overflow scheduler offsets, or when
    /// the boundary would make the checked condition prefix invalid.
    pub fn append_evaluation_boundary(
        &mut self,
        at: VirtualTime,
        kind: SchedulerEvaluationBoundaryKind,
    ) -> Result<SchedulerEventLogAppend, SchedulerError> {
        let sequence = self.next_sequence(0)?;
        self.append_entries(vec![scheduler_event_log_entry(
            sequence,
            at,
            SchedulerEventLogPayload::EvaluationBoundary(kind),
        )])
    }

    /// Returns the next dense sequence number after `offset` pending entries.
    ///
    /// # Errors
    ///
    /// Returns [`SchedulerError::BoundaryViolation`] when the pending offset or
    /// resulting event-log sequence cannot fit in `u64`.
    pub fn next_sequence(&self, offset: usize) -> Result<u64, SchedulerError> {
        scheduler_event_log_sequence(self.events, offset)
    }

    /// Appends entries through the unified event-log path.
    ///
    /// # Errors
    ///
    /// Returns [`SchedulerError::BoundaryViolation`] when an entry sequence is
    /// not dense from the current log offset, the recorded class does not match
    /// the event-kind catalog, segment byte counts, event counts, or the derived
    /// condition prefix overflow or become invalid.
    pub fn append_entries(
        &mut self,
        entries: Vec<LogEntry>,
    ) -> Result<SchedulerEventLogAppend, SchedulerError> {
        if entries.is_empty() {
            return Ok(SchedulerEventLogAppend {
                entries,
                segment_bytes: Vec::new(),
                segment_text: String::new(),
                segment_hash: None,
                offset: self.offset(),
            });
        }

        for (offset, entry) in entries.iter().enumerate() {
            let expected = self.next_sequence(offset)?;
            if entry.sequence() != expected {
                return Err(SchedulerError::BoundaryViolation {
                    message: format!(
                        "event-log entry sequence {} does not match expected dense sequence {expected}",
                        entry.sequence()
                    ),
                });
            }
            if !entry.class_matches_catalog() {
                let Some(expected) = event_kind_catalog_class(entry.event_payload()) else {
                    return Err(SchedulerError::BoundaryViolation {
                        message: format!(
                            "event-log entry {} payload kind {} is not in the event-kind catalog",
                            entry.sequence(),
                            entry.event_payload().kind()
                        ),
                    });
                };
                return Err(SchedulerError::BoundaryViolation {
                    message: format!(
                        "event-log entry {} class {} does not match catalog class {} for payload kind {}",
                        entry.sequence(),
                        event_class_label(entry.class()),
                        event_class_label(expected),
                        entry.event_payload().kind()
                    ),
                });
            }
        }

        let segment_bytes = scheduler_event_log_segment_bytes(self.prefix, &entries);
        let segment_text = decode_scheduler_event_log_segment(&segment_bytes)
            .map(|segment| segment.text_view())
            .map_err(|error| SchedulerError::BoundaryViolation {
                message: format!(
                    "event-log segment canonical bytes did not decode after encode: {error:?}"
                ),
            })?;
        let segment_hash = self.segment_store.put_segment(&segment_bytes)?;
        let appended_bytes =
            u64::try_from(segment_bytes.len()).map_err(|_| SchedulerError::BoundaryViolation {
                message: String::from("event-log segment length exceeds u64"),
            })?;
        let appended_events =
            u64::try_from(entries.len()).map_err(|_| SchedulerError::BoundaryViolation {
                message: String::from("event-log entry count exceeds u64"),
            })?;
        let bytes = self.bytes.checked_add(appended_bytes).ok_or_else(|| {
            SchedulerError::BoundaryViolation {
                message: String::from("event-log byte offset overflow"),
            }
        })?;
        let events = self.events.checked_add(appended_events).ok_or_else(|| {
            SchedulerError::BoundaryViolation {
                message: String::from("event-log sequence overflow"),
            }
        })?;

        let current_offset =
            EventLogOffset::with_appended_segment(self.prefix, bytes, events, segment_hash);
        let prefix =
            scheduler_event_log_prefix_after_append(self.prefix, segment_hash, bytes, events);
        let mut condition_entries = self.condition_entries.clone();
        condition_entries.extend(entries.iter().cloned());
        let condition_prefix = ConditionEventLogPrefix::from_scheduler_event_log_entries_with_base(
            condition_entries.clone(),
            self.condition_base_events,
        )
        .map_err(|error| SchedulerError::BoundaryViolation {
            message: format!("scheduler emitted invalid condition event-log prefix: {error:?}"),
        })?
        .with_event_log_offset(current_offset);

        self.prefix = prefix;
        self.offset = current_offset;
        self.bytes = bytes;
        self.events = events;
        self.condition_entries = condition_entries;
        self.condition_prefix = condition_prefix;

        Ok(SchedulerEventLogAppend {
            entries,
            segment_bytes,
            segment_text,
            segment_hash: Some(segment_hash),
            offset: current_offset,
        })
    }
}

/// One causal entry retained by the event-log determinism projection.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct EventLogCausalProjectionEntry {
    /// Index of the entry in the original unified event log before filtering.
    pub raw_index: usize,
    /// Renumbered causal entry used for canonical comparison.
    pub entry: SchedulerEventLogEntry,
}

/// Canonical causal-subsequence projection used by determinism gates.
///
/// The projection strips observational entries, renumbers surviving causal
/// entries from zero, and serializes those renumbered entries with the same
/// versioned binary segment encoder used for stored event-log segments.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct EventLogCausalProjection {
    entries: Vec<EventLogCausalProjectionEntry>,
    canonical_bytes: Vec<u8>,
    content_hash: ContentHash,
}

impl EventLogCausalProjection {
    /// Returns the renumbered causal entries retained by the projection.
    #[must_use]
    pub fn entries(&self) -> &[EventLogCausalProjectionEntry] {
        &self.entries
    }

    /// Returns the canonical binary bytes compared by determinism gates.
    #[must_use]
    pub fn canonical_bytes(&self) -> &[u8] {
        &self.canonical_bytes
    }

    /// Returns the content hash of [`Self::canonical_bytes`].
    #[must_use]
    pub fn content_hash(&self) -> ContentHash {
        self.content_hash
    }

    /// Returns the number of causal entries retained by the projection.
    #[must_use]
    pub fn len(&self) -> usize {
        self.entries.len()
    }

    /// Returns whether the projection contains no causal entries.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.entries.is_empty()
    }
}

/// Event-log coordinate for the first differing causal entry.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct EventLogCausalDivergencePoint {
    /// Index of the entry in the original unified event log before filtering.
    pub raw_index: usize,
    /// Icount-stamped location that pins the divergence to a node, when node-local.
    pub at: EventLogIcountStamp,
    /// Closed source that emitted the differing entry.
    pub source: EventSource,
    /// Open-set payload kind for the differing entry.
    pub kind: String,
}

/// First causal-subsequence difference found by an event-log comparison.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct EventLogDeterminismMismatch {
    /// Renumbered causal index at which comparison first diverged.
    pub causal_index: usize,
    /// Raw unified-log index on the expected side, when present.
    pub expected_raw_index: Option<usize>,
    /// Raw unified-log index on the reproduced side, when present.
    pub reproduced_raw_index: Option<usize>,
    /// Expected-side coordinate for the first differing causal entry.
    pub expected_location: Option<EventLogCausalDivergencePoint>,
    /// Reproduced-side coordinate for the first differing causal entry.
    pub reproduced_location: Option<EventLogCausalDivergencePoint>,
    /// Expected renumbered causal entry at `causal_index`, when present.
    pub expected_entry: Option<SchedulerEventLogEntry>,
    /// Reproduced renumbered causal entry at `causal_index`, when present.
    pub reproduced_entry: Option<SchedulerEventLogEntry>,
}

impl EventLogDeterminismMismatch {
    /// Returns the first available side-specific event-log localization point.
    #[must_use]
    pub fn first_location(&self) -> Option<&EventLogCausalDivergencePoint> {
        self.expected_location
            .as_ref()
            .or(self.reproduced_location.as_ref())
    }
}

/// Result of comparing two unified event logs for deterministic equality.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct EventLogDeterminismComparison {
    expected: EventLogCausalProjection,
    reproduced: EventLogCausalProjection,
    byte_identical: bool,
    mismatch: Option<EventLogDeterminismMismatch>,
}

impl EventLogDeterminismComparison {
    /// Returns the expected run's causal projection.
    #[must_use]
    pub fn expected(&self) -> &EventLogCausalProjection {
        &self.expected
    }

    /// Returns the reproduced run's causal projection.
    #[must_use]
    pub fn reproduced(&self) -> &EventLogCausalProjection {
        &self.reproduced
    }

    /// Returns whether both canonical causal projections are byte-identical.
    #[must_use]
    pub fn byte_identical(&self) -> bool {
        self.byte_identical
    }

    /// Returns the first entry-level causal mismatch, when one is localized.
    #[must_use]
    pub fn mismatch(&self) -> Option<&EventLogDeterminismMismatch> {
        self.mismatch.as_ref()
    }

    /// Returns whether both causal projections are byte-identical.
    #[must_use]
    pub fn passes(&self) -> bool {
        self.byte_identical
    }
}

/// Builds the canonical causal-subsequence projection for `entries`.
#[must_use]
pub fn event_log_causal_projection(entries: &[SchedulerEventLogEntry]) -> EventLogCausalProjection {
    let entries = entries
        .iter()
        .enumerate()
        .filter(|(_, entry)| entry.class == SchedulerEventLogClass::Causal)
        .enumerate()
        .map(
            |(causal_index, (raw_index, entry))| EventLogCausalProjectionEntry {
                raw_index,
                entry: scheduler_event_log_entry_with_material(
                    causal_index as u64,
                    entry.at.clone(),
                    entry.source.clone(),
                    entry.level,
                    SchedulerEventLogClass::Causal,
                    entry.event_payload.clone(),
                    entry.payload.clone(),
                ),
            },
        )
        .collect::<Vec<_>>();
    let canonical_entries = entries
        .iter()
        .map(|entry| entry.entry.clone())
        .collect::<Vec<_>>();
    let canonical_bytes =
        scheduler_event_log_segment_bytes(scheduler_event_log_empty_prefix(), &canonical_entries);
    let content_hash = ContentHash::from_bytes(&canonical_bytes);
    EventLogCausalProjection {
        entries,
        canonical_bytes,
        content_hash,
    }
}

/// Compares two unified event logs by their canonical causal subsequence.
///
/// Observational entries are excluded before comparison. Surviving causal
/// entries are renumbered independently on both sides, so different
/// observational interleavings do not perturb the comparison.
#[must_use]
pub fn compare_event_log_determinism(
    expected: &[SchedulerEventLogEntry],
    reproduced: &[SchedulerEventLogEntry],
) -> EventLogDeterminismComparison {
    let expected = event_log_causal_projection(expected);
    let reproduced = event_log_causal_projection(reproduced);
    let byte_identical = expected.canonical_bytes == reproduced.canonical_bytes;
    let mismatch = if byte_identical {
        None
    } else {
        event_log_determinism_mismatch(&expected, &reproduced)
    };
    EventLogDeterminismComparison {
        expected,
        reproduced,
        byte_identical,
        mismatch,
    }
}

fn event_log_determinism_mismatch(
    expected: &EventLogCausalProjection,
    reproduced: &EventLogCausalProjection,
) -> Option<EventLogDeterminismMismatch> {
    let max_len = expected.entries.len().max(reproduced.entries.len());
    for causal_index in 0..max_len {
        let expected_entry = expected.entries.get(causal_index);
        let reproduced_entry = reproduced.entries.get(causal_index);
        let entries_match = match (expected_entry, reproduced_entry) {
            (Some(expected), Some(reproduced)) => expected.entry == reproduced.entry,
            (None, None) => true,
            (Some(_), None) | (None, Some(_)) => false,
        };
        if !entries_match {
            return Some(EventLogDeterminismMismatch {
                causal_index,
                expected_raw_index: expected_entry.map(|entry| entry.raw_index),
                reproduced_raw_index: reproduced_entry.map(|entry| entry.raw_index),
                expected_location: expected_entry.map(event_log_causal_divergence_point),
                reproduced_location: reproduced_entry.map(event_log_causal_divergence_point),
                expected_entry: expected_entry.map(|entry| entry.entry.clone()),
                reproduced_entry: reproduced_entry.map(|entry| entry.entry.clone()),
            });
        }
    }
    None
}

fn event_log_causal_divergence_point(
    entry: &EventLogCausalProjectionEntry,
) -> EventLogCausalDivergencePoint {
    EventLogCausalDivergencePoint {
        raw_index: entry.raw_index,
        at: entry.entry.time().icount.clone(),
        source: entry.entry.source().clone(),
        kind: entry.entry.event_payload().kind().to_owned(),
    }
}

impl Default for EventLog {
    fn default() -> Self {
        Self::new()
    }
}

/// One coverage observation retained by the event-log coverage projection.
#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum EventLogCoverageObservation {
    /// A TCG basic-block execution observation.
    BasicBlock {
        /// Node that executed the block.
        node: NodeId,
        /// Guest program counter for the translated block.
        guest_pc: u64,
        /// Translated block length supplied by QEMU.
        block_len: u32,
    },
    /// A white-box named coverage marker observation.
    Named {
        /// Node that emitted the marker.
        node: NodeId,
        /// Stable marker identity carried by the doorbell payload.
        marker: MarkerId,
    },
}

/// One event-log entry retained by the coverage projection.
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub struct EventLogCoverageProjectionEntry {
    /// Index of the entry in the original unified event log before filtering.
    pub raw_index: usize,
    /// Icount-stamped location where the coverage observation occurred.
    pub at: EventLogIcountStamp,
    /// Closed source that emitted the coverage entry.
    pub source: EventSource,
    /// Coverage observation carried by this entry.
    pub observation: EventLogCoverageObservation,
}

/// Coverage projection used by search/fuzzing feedback and checkpoint fingerprints.
///
/// The projection keeps coverage entries in event-log order for consumers that
/// need stream context, while the content hash is computed from the sorted unique
/// observation set so duplicate basic-block hits do not perturb feedback identity.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct EventLogCoverageProjection {
    entries: Vec<EventLogCoverageProjectionEntry>,
    content_hash: ContentHash,
}

impl EventLogCoverageProjection {
    /// Returns coverage entries in original event-log order.
    #[must_use]
    pub fn entries(&self) -> &[EventLogCoverageProjectionEntry] {
        &self.entries
    }

    /// Returns the deterministic coverage fingerprint for this projection.
    #[must_use]
    pub fn content_hash(&self) -> ContentHash {
        self.content_hash
    }

    /// Returns the number of coverage entries retained by the projection.
    #[must_use]
    pub fn len(&self) -> usize {
        self.entries.len()
    }

    /// Returns whether the projection contains no coverage entries.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.entries.is_empty()
    }
}

/// Builds the coverage projection for `entries`.
#[must_use]
pub fn event_log_coverage_projection(
    entries: &[SchedulerEventLogEntry],
) -> EventLogCoverageProjection {
    let entries = entries
        .iter()
        .enumerate()
        .filter_map(|(raw_index, entry)| event_log_coverage_entry(raw_index, entry))
        .collect::<Vec<_>>();
    let unique_material = entries
        .iter()
        .map(event_log_coverage_observation_material)
        .collect::<BTreeSet<_>>();
    let content_hash = if unique_material.is_empty() {
        ContentHash::default()
    } else {
        ContentHash::from_canonical_material(
            "crucible.scheduler.event-log.coverage-projection.v1",
            &unique_material.into_iter().collect::<Vec<_>>().join("\n"),
        )
    };
    EventLogCoverageProjection {
        entries,
        content_hash,
    }
}

/// Returns the checkpoint coverage fingerprint derived from `entries`.
#[must_use]
pub fn coverage_fingerprint_from_event_log(entries: &[SchedulerEventLogEntry]) -> ContentHash {
    event_log_coverage_projection(entries).content_hash()
}

/// A consumer of the shared event-log coverage feedback signal.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum EventLogCoverageFeedbackConsumer {
    /// State-space search frontier ordering.
    Search,
    /// Coverage-guided fuzzing corpus and energy decisions.
    CoverageGuidedFuzzing,
}

/// The single coverage feedback signal read by search and fuzzing.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct EventLogCoverageFeedback {
    projection: EventLogCoverageProjection,
}

impl EventLogCoverageFeedback {
    /// Builds coverage feedback from the unified event log.
    #[must_use]
    pub fn from_event_log(entries: &[SchedulerEventLogEntry]) -> Self {
        Self {
            projection: event_log_coverage_projection(entries),
        }
    }

    /// Returns the shared coverage projection backing every consumer view.
    #[must_use]
    pub const fn projection(&self) -> &EventLogCoverageProjection {
        &self.projection
    }

    /// Returns the deterministic coverage fingerprint.
    #[must_use]
    pub fn fingerprint(&self) -> ContentHash {
        self.projection.content_hash()
    }

    /// Returns the deterministic feedback fingerprint for one consumer.
    ///
    /// Search and coverage-guided fuzzing intentionally receive the same digest:
    /// both are readers of the event-log coverage projection, not owners of a
    /// parallel coverage record.
    #[must_use]
    pub fn fingerprint_for(&self, consumer: EventLogCoverageFeedbackConsumer) -> ContentHash {
        match consumer {
            EventLogCoverageFeedbackConsumer::Search
            | EventLogCoverageFeedbackConsumer::CoverageGuidedFuzzing => self.fingerprint(),
        }
    }
}

/// One event-log entry retained by the assertion-proximity projection.
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub struct EventLogAssertionProximityProjectionEntry {
    /// Index of the entry in the original unified event log before filtering.
    pub raw_index: usize,
    /// Icount-stamped location where the proximity observation occurred.
    pub at: EventLogIcountStamp,
    /// Closed source that emitted the proximity entry.
    pub source: EventSource,
    /// Assertion whose predicate produced this distance.
    pub assertion: AssertionId,
    /// Assertion quantifier that owns the steering obligation.
    pub quantifier: AssertionQuantifierKind,
    /// Non-negative structural distance; zero means satisfied.
    pub distance: u128,
    /// Optional node associated with the distance.
    pub node: Option<NodeId>,
}

/// Assertion-proximity projection used by guided-search steering feedback.
///
/// The projection keeps every `assertion_proximity` entry in event-log order for
/// consumers that need stream context. Its content hash is derived from the
/// minimum distance per `(assertion, quantifier, node)` tuple, making it the
/// deterministic per-checkpoint steering fingerprint.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct EventLogAssertionProximityProjection {
    entries: Vec<EventLogAssertionProximityProjectionEntry>,
    content_hash: ContentHash,
}

impl EventLogAssertionProximityProjection {
    /// Returns assertion-proximity entries in original event-log order.
    #[must_use]
    pub fn entries(&self) -> &[EventLogAssertionProximityProjectionEntry] {
        &self.entries
    }

    /// Returns the deterministic assertion-proximity fingerprint.
    #[must_use]
    pub fn content_hash(&self) -> ContentHash {
        self.content_hash
    }

    /// Returns the number of proximity entries retained by the projection.
    #[must_use]
    pub fn len(&self) -> usize {
        self.entries.len()
    }

    /// Returns whether the projection contains no proximity entries.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.entries.is_empty()
    }
}

/// Builds the assertion-proximity projection for `entries`.
#[must_use]
pub fn event_log_assertion_proximity_projection(
    entries: &[SchedulerEventLogEntry],
) -> EventLogAssertionProximityProjection {
    let entries = entries
        .iter()
        .enumerate()
        .filter_map(|(raw_index, entry)| event_log_assertion_proximity_entry(raw_index, entry))
        .collect::<Vec<_>>();
    let mut minimums = BTreeMap::new();
    for entry in &entries {
        let key = (
            entry.assertion.clone(),
            entry.quantifier,
            entry.node.clone(),
        );
        match minimums.get(&key) {
            Some(current) if assertion_proximity_entry_is_better(entry, current) => {
                minimums.insert(key, entry.clone());
            }
            None => {
                minimums.insert(key, entry.clone());
            }
            Some(_) => {}
        }
    }
    let content_hash = if minimums.is_empty() {
        ContentHash::default()
    } else {
        ContentHash::from_canonical_material(
            "crucible.scheduler.event-log.assertion-proximity-projection.v1",
            &minimums
                .values()
                .map(event_log_assertion_proximity_minimum_material)
                .collect::<Vec<_>>()
                .join("\n"),
        )
    };
    EventLogAssertionProximityProjection {
        entries,
        content_hash,
    }
}

/// Returns the checkpoint assertion-proximity fingerprint derived from `entries`.
#[must_use]
pub fn assertion_proximity_fingerprint_from_event_log(
    entries: &[SchedulerEventLogEntry],
) -> ContentHash {
    event_log_assertion_proximity_projection(entries).content_hash()
}

fn event_log_coverage_entry(
    raw_index: usize,
    entry: &SchedulerEventLogEntry,
) -> Option<EventLogCoverageProjectionEntry> {
    let observation = match entry.payload() {
        SchedulerEventLogPayload::Observable(ObservableEventPayload::CoverageBlock {
            node,
            guest_pc,
            block_len,
            ..
        }) => EventLogCoverageObservation::BasicBlock {
            node: node.clone(),
            guest_pc: *guest_pc,
            block_len: *block_len,
        },
        SchedulerEventLogPayload::Observable(ObservableEventPayload::CoverageMarker {
            node,
            marker,
            ..
        }) => EventLogCoverageObservation::Named {
            node: node.clone(),
            marker: marker.clone(),
        },
        SchedulerEventLogPayload::ResolvedHappening(_)
        | SchedulerEventLogPayload::Decision(_)
        | SchedulerEventLogPayload::Observable(_)
        | SchedulerEventLogPayload::EvaluationBoundary(_)
        | SchedulerEventLogPayload::TriggerFired(_)
        | SchedulerEventLogPayload::TriggerActionApplied(_)
        | SchedulerEventLogPayload::Diagnostic(_) => return None,
    };
    Some(EventLogCoverageProjectionEntry {
        raw_index,
        at: entry.time().icount.clone(),
        source: entry.source().clone(),
        observation,
    })
}

fn event_log_assertion_proximity_entry(
    raw_index: usize,
    entry: &SchedulerEventLogEntry,
) -> Option<EventLogAssertionProximityProjectionEntry> {
    let SchedulerEventLogPayload::Observable(ObservableEventPayload::AssertionProximity {
        assertion,
        quantifier,
        distance,
        node,
    }) = entry.payload()
    else {
        return None;
    };
    Some(EventLogAssertionProximityProjectionEntry {
        raw_index,
        at: entry.time().icount.clone(),
        source: entry.source().clone(),
        assertion: assertion.clone(),
        quantifier: *quantifier,
        distance: *distance,
        node: node.clone(),
    })
}

fn assertion_proximity_entry_is_better(
    candidate: &EventLogAssertionProximityProjectionEntry,
    current: &EventLogAssertionProximityProjectionEntry,
) -> bool {
    candidate
        .distance
        .cmp(&current.distance)
        .then_with(|| candidate.at.icount.retired.cmp(&current.at.icount.retired))
        .then_with(|| candidate.raw_index.cmp(&current.raw_index))
        .is_lt()
}

fn event_log_assertion_proximity_minimum_material(
    entry: &EventLogAssertionProximityProjectionEntry,
) -> String {
    let node_material = match &entry.node {
        Some(node) => format!(
            "node=some\nnode_len={}\nnode={}",
            node.name.len(),
            node.name
        ),
        None => String::from("node=none"),
    };
    format!(
        "assertion_len={}\nassertion={}\nquantifier={}\ndistance={}\n{}",
        entry.assertion.name.len(),
        entry.assertion.name,
        assertion_quantifier_kind_label(entry.quantifier),
        entry.distance,
        node_material,
    )
}

fn event_log_coverage_observation_material(entry: &EventLogCoverageProjectionEntry) -> String {
    match &entry.observation {
        EventLogCoverageObservation::BasicBlock {
            node,
            guest_pc,
            block_len,
        } => format!(
            "kind=basic_block\nnode_len={}\nnode={}\nguest_pc={guest_pc}\nblock_len={block_len}",
            node.name.len(),
            node.name
        ),
        EventLogCoverageObservation::Named { node, marker } => format!(
            "kind=named\nnode_len={}\nnode={}\nid_len={}\nid={}",
            node.name.len(),
            node.name,
            marker.name.len(),
            marker.name
        ),
    }
}

/// Determinism class for a scheduler event-log entry.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum SchedulerEventLogClass {
    /// Causal entries participate in deterministic replay comparison.
    Causal,
    /// Observational entries are descriptive and excluded from causal comparison.
    Observational,
}

/// Deterministic scheduler boundary that may trigger condition evaluation.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum SchedulerEvaluationBoundaryKind {
    /// A quantum boundary keyed by virtual time / icount.
    Quantum,
    /// A rendezvous boundary keyed by virtual time / icount.
    Rendezvous,
}

/// Observational diagnostic payload used as the open-set escape hatch.
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub struct EventDiagnosticPayload {
    /// Stable diagnostic name.
    pub name: String,
    /// Display level for this diagnostic.
    pub level: EventLevel,
    /// Typed diagnostic details keyed by stable field name.
    pub details: BTreeMap<String, EventAttributeValue>,
}

impl EventDiagnosticPayload {
    /// Builds a diagnostic payload.
    #[must_use]
    pub fn new(
        name: impl Into<String>,
        level: EventLevel,
        details: BTreeMap<String, EventAttributeValue>,
    ) -> Self {
        Self {
            name: name.into(),
            level,
            details,
        }
    }

    /// Returns this diagnostic as an open-set event payload.
    #[must_use]
    pub fn event_payload(&self) -> EventPayload {
        EventPayload::diagnostic(self.name.clone(), self.details.clone())
    }
}

/// Payload variants emitted by the scheduler EMIT phase.
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub enum SchedulerEventLogPayload {
    /// A resolved scheduler happening made visible this quantum.
    ResolvedHappening(ScheduledEvent),
    /// A decision taken and appended to the schedule this quantum.
    Decision(Decision),
    /// An observable condition fact appended to the event log.
    Observable(ObservableEventPayload),
    /// A deterministic evaluation boundary appended to the event log.
    EvaluationBoundary(SchedulerEvaluationBoundaryKind),
    /// A deterministic trigger firing computed from a checked condition prefix.
    TriggerFired(EventFiring),
    /// A deterministic trigger action effect applied at the firing boundary.
    TriggerActionApplied(TriggerActionApplication),
    /// An observational diagnostic escape-hatch entry.
    Diagnostic(EventDiagnosticPayload),
}

/// Scheduler-owned state produced by deterministic trigger action application.
#[derive(Clone, Debug, Default, PartialEq, Eq, Hash)]
pub struct TriggerActionState {
    /// Every non-group action applied by triggers in deterministic application order.
    pub applications: Vec<TriggerActionApplication>,
    /// Active membership faults keyed by their stable trigger tag.
    pub active_faults: BTreeMap<crate::FaultTag, MembershipFault>,
    /// Active full-taxonomy faults keyed by their stable trigger tag.
    pub active_taxonomy_faults: BTreeMap<crate::FaultTag, Fault>,
    /// Trigger timers armed by name with their absolute virtual-time fire point.
    pub armed_timers: BTreeMap<TimerId, VirtualTime>,
    /// Trigger-scheduled node lifecycle overrides keyed by declared node.
    pub node_states: BTreeMap<NodeId, NodeLifecycle>,
    /// Savepoint requests raised by trigger actions.
    pub savepoints: Vec<TriggerLabelRecord>,
    /// Fork requests raised by trigger actions.
    pub forks: Vec<TriggerLabelRecord>,
    /// Latest pass verdict or first sticky fail verdict raised by a trigger action.
    pub verdict: Option<TriggerVerdict>,
    /// Whether a trigger pass/fail action requested run termination.
    pub termination_requested: bool,
    /// Observational diagnostics raised by trigger log actions.
    pub diagnostics: Vec<TriggerDiagnosticRecord>,
}

impl TriggerActionState {
    /// Combines every active full-taxonomy fault currently owned by triggers.
    #[must_use]
    pub fn combined_faults(&self) -> CombinedFaults {
        CombinedFaults::from_membership_faults(self.active_faults.values())
    }

    /// Composes trigger pass/fail state with the final assertion-layer verdict.
    ///
    /// Assertion failures and explicit trigger failures both fail the run. An
    /// explicit trigger pass is retained only when the assertion layer passed and
    /// no trigger failure fired.
    #[must_use]
    pub fn compose_run_verdict(&self, assertions: AssertionRunVerdict) -> ComposedRunVerdict {
        let mut assertion_failures = assertions.failures().to_vec();
        assertion_failures.sort();
        let mut failures = assertion_failures
            .into_iter()
            .map(ComposedRunVerdictFailure::Assertion)
            .collect::<Vec<_>>();
        if let Some(trigger) = self
            .verdict
            .as_ref()
            .filter(|verdict| verdict.failed_reason.is_some())
        {
            failures.push(ComposedRunVerdictFailure::Trigger(trigger.clone()));
        }
        if failures.is_empty() {
            ComposedRunVerdict::Passed {
                trigger: self.verdict.clone(),
            }
        } else {
            ComposedRunVerdict::Failed { failures }
        }
    }

    /// Composes a run verdict by replaying trigger verdict actions from event-log entries.
    ///
    /// # Errors
    ///
    /// Returns [`SchedulerError::BoundaryViolation`] when any supplied event-log
    /// entry has a content hash that does not match its canonical material.
    pub fn compose_run_verdict_from_event_log(
        entries: &[SchedulerEventLogEntry],
        assertions: AssertionRunVerdict,
    ) -> Result<ComposedRunVerdict, SchedulerError> {
        let mut state = Self::default();
        for entry in entries {
            if !entry.has_valid_content_hash() {
                return Err(SchedulerError::BoundaryViolation {
                    message: format!(
                        "event-log entry {} has invalid content hash during trigger verdict replay",
                        entry.sequence()
                    ),
                });
            }
            if let SchedulerEventLogPayload::TriggerActionApplied(application) = entry.payload() {
                apply_trigger_verdict_effect(&mut state, application);
            }
        }
        Ok(state.compose_run_verdict(assertions))
    }
}

/// One deterministic non-group trigger action application.
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub struct TriggerActionApplication {
    /// Monotone scheduler-local trigger action sequence.
    pub sequence: u64,
    /// Event whose firing produced this action.
    pub event: crate::EventId,
    /// Virtual time at which the action was applied.
    pub at: VirtualTime,
    /// Path through nested `Group` actions, in declared zero-based indexes.
    pub path: Vec<u64>,
    /// Non-group action applied at this path.
    pub action: Action,
}

impl TriggerActionApplication {
    /// Returns whether this action application is observational rather than causal.
    #[must_use]
    pub fn is_observational(&self) -> bool {
        matches!(self.action, Action::Log { .. })
    }
}

/// One trigger request to label a temporal graph boundary.
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub struct TriggerLabelRecord {
    /// Trigger action sequence that raised the request.
    pub sequence: u64,
    /// Event whose firing produced the request.
    pub event: crate::EventId,
    /// Virtual time at which the request was raised.
    pub at: VirtualTime,
    /// Optional stable author label.
    pub label: Option<String>,
}

/// A trigger-sourced pass/fail verdict request.
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub struct TriggerVerdict {
    /// Trigger action sequence that raised the verdict.
    pub sequence: u64,
    /// Event whose firing produced the verdict.
    pub event: crate::EventId,
    /// Virtual time at which the verdict was raised.
    pub at: VirtualTime,
    /// Failure reason when this is a fail verdict; absent for pass.
    pub failed_reason: Option<String>,
}

/// Final assertion-layer verdict supplied to trigger verdict composition.
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub enum AssertionRunVerdict {
    /// The assertion layer finalized without failing properties.
    Passed,
    /// One or more assertion properties failed.
    Failed {
        /// Assertion failures supplied by the assertion layer.
        ///
        /// [`Self::failed`] sorts this list when constructing the verdict, and
        /// final run-verdict composition normalizes it before emitting failure
        /// causes.
        failures: Vec<AssertionVerdictFailure>,
    },
}

impl AssertionRunVerdict {
    /// Builds a passed assertion verdict.
    #[must_use]
    pub const fn passed() -> Self {
        Self::Passed
    }

    /// Builds a failed assertion verdict with deterministic failure ordering.
    ///
    /// Empty failure lists normalize to [`Self::Passed`].
    #[must_use]
    pub fn failed(mut failures: Vec<AssertionVerdictFailure>) -> Self {
        if failures.is_empty() {
            return Self::Passed;
        }
        failures.sort();
        Self::Failed { failures }
    }

    /// Returns true when the assertion layer failed the run.
    #[must_use]
    pub const fn is_failed(&self) -> bool {
        matches!(self, Self::Failed { .. })
    }

    /// Returns the assertion failures stored in this verdict.
    ///
    /// Use [`Self::failed`] or final run-verdict composition when deterministic
    /// failure ordering is required.
    #[must_use]
    pub fn failures(&self) -> &[AssertionVerdictFailure] {
        match self {
            Self::Passed => &[],
            Self::Failed { failures } => failures,
        }
    }
}

/// One assertion failure participating in final run-verdict composition.
#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct AssertionVerdictFailure {
    /// Assertion that failed.
    pub assertion: AssertionId,
    /// Deterministic virtual time where the failure was observed.
    pub at: VirtualTime,
    /// Stable failure detail from the assertion layer.
    pub reason: String,
}

impl AssertionVerdictFailure {
    /// Builds an assertion-failure record.
    #[must_use]
    pub fn new(assertion: AssertionId, at: VirtualTime, reason: impl Into<String>) -> Self {
        Self {
            assertion,
            at,
            reason: reason.into(),
        }
    }
}

/// Final run verdict after composing trigger and assertion outcomes.
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub enum ComposedRunVerdict {
    /// No trigger or assertion failure occurred.
    Passed {
        /// Optional explicit trigger pass request.
        trigger: Option<TriggerVerdict>,
    },
    /// At least one trigger or assertion failure occurred.
    Failed {
        /// Deterministically ordered failure causes.
        failures: Vec<ComposedRunVerdictFailure>,
    },
}

impl ComposedRunVerdict {
    /// Returns true when the composed verdict failed the run.
    #[must_use]
    pub const fn is_failed(&self) -> bool {
        matches!(self, Self::Failed { .. })
    }

    /// Returns the composed failure causes.
    #[must_use]
    pub fn failures(&self) -> &[ComposedRunVerdictFailure] {
        match self {
            Self::Passed { .. } => &[],
            Self::Failed { failures } => failures,
        }
    }
}

/// One failure cause in the composed run verdict.
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub enum ComposedRunVerdictFailure {
    /// Failure from the assertion layer.
    Assertion(AssertionVerdictFailure),
    /// Failure from an explicit trigger `Fail` action.
    Trigger(TriggerVerdict),
}

/// One observational diagnostic emitted by a trigger log action.
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub struct TriggerDiagnosticRecord {
    /// Trigger action sequence that emitted the diagnostic.
    pub sequence: u64,
    /// Event whose firing produced the diagnostic.
    pub event: crate::EventId,
    /// Virtual time at which the diagnostic was emitted.
    pub at: VirtualTime,
    /// Diagnostic severity level.
    pub level: LogLevel,
    /// Stable diagnostic message.
    pub message: String,
}

/// Result of appending one scheduler quantum to the event log.
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub struct SchedulerEventLogAppend {
    /// Entries appended for this quantum.
    pub entries: Vec<SchedulerEventLogEntry>,
    /// Canonical bytes appended for this quantum's event-log segment.
    pub segment_bytes: Vec<u8>,
    /// Human-readable text projection derived from `segment_bytes`.
    pub segment_text: String,
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

/// Evidence that an explorer-supplied preemption was applied by RESOLVE.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SchedulerPreemptionApplication {
    /// Monotone scheduler-local preemption application sequence.
    pub sequence: u64,
    /// Scheduler quantum whose RUN admitted this preemption.
    pub quantum: u64,
    /// Scheduler node selected for the RUN that admitted the preemption.
    pub node: SchedulerNodeId,
    /// Explorer-supplied preemption decision recorded in the schedule.
    pub decision: PreemptionDecision,
    /// Scheduler-axis virtual time at the preemption's retired-instruction point.
    pub virtual_time: SimInstant,
    /// Inclusive lower icount bound for this RUN's authorized window.
    pub deadline_icount: Icount,
    /// Inclusive upper icount bound for this RUN's authorized window.
    pub horizon_icount: Icount,
    /// The single scheduler-published node ceiling for this RUN.
    pub ceiling: SchedulerRunCeilingPublication,
}

/// One vCPU's scheduler-visible idle snapshot inside an N-vCPU VM node.
#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct SchedulerVcpuIdleState {
    /// The vCPU described by this snapshot.
    pub vcpu: VcpuId,
    /// Whether the vCPU is halted at the scheduler boundary.
    pub halted: bool,
    /// The vCPU's next exact timer deadline, when one is armed.
    pub next_deadline: Option<SimInstant>,
    /// Whether input is already pending for this vCPU.
    pub pending_input: bool,
}

/// Per-vCPU idle evidence for one scheduler VM node.
#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct SchedulerNodeVcpuIdleSnapshot {
    /// Scheduler node whose vCPU idle state is reported.
    pub node: SchedulerNodeId,
    /// Total number of vCPUs hosted by the node.
    pub vcpu_count: u32,
    /// Per-vCPU states in canonical vCPU-index order.
    pub vcpus: Vec<SchedulerVcpuIdleState>,
}

impl SchedulerNodeVcpuIdleSnapshot {
    /// Builds a validated per-node vCPU idle snapshot.
    ///
    /// # Errors
    ///
    /// Returns [`SchedulerError::BoundaryViolation`] when the snapshot declares
    /// zero vCPUs, does not cover every vCPU exactly once, or targets a non-VM
    /// scheduler node.
    pub fn new(
        node: SchedulerNodeId,
        vcpu_count: u32,
        mut vcpus: Vec<SchedulerVcpuIdleState>,
    ) -> Result<Self, SchedulerError> {
        validate_vcpu_idle_snapshot(&node, vcpu_count, &mut vcpus)?;
        Ok(Self {
            node,
            vcpu_count,
            vcpus,
        })
    }
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
    /// Updates matching directed edges without restoring absent edges.
    UpdateEffectiveEdges(Vec<SchedulerLookaheadEdge>),
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

    /// Builds a latency change that updates existing directed effective edges.
    ///
    /// The updated edges replace only matching endpoints that are still present in
    /// the current effective topology. This preserves pending partition effects:
    /// a latency refresh cannot re-add an edge that a partition removed.
    #[must_use]
    pub fn update_effective_edges(
        sequence: u64,
        trigger: SchedulerTopologyChangeTrigger,
        updated_edges: Vec<SchedulerLookaheadEdge>,
    ) -> Self {
        Self {
            sequence,
            trigger,
            activation_time: None,
            effect: SchedulerTopologyChangeEffect::UpdateEffectiveEdges(updated_edges),
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

/// One scheduler-owned event discarded by node crash handling.
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub struct SchedulerDiscardedEvent {
    /// The event's deterministic scheduler key.
    pub key: ScheduledEventKey,
    /// The resolved event class that would have been emitted if it survived.
    pub class: ScheduledEventResolveClass,
}

/// One scheduler-owned device completion discarded by node crash handling.
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub struct SchedulerDiscardedIoCompletion {
    /// The scheduler sub-node that produced the completion.
    pub sub_node: SchedulerNodeId,
    /// The target VM node that would have observed the completion.
    pub target: NodeId,
    /// The target instruction count where the completion would become visible.
    pub delivery_icount: Icount,
    /// The device-core source id in the completion delivery key.
    pub source_node: u32,
    /// The device-core sequence number in the completion delivery key.
    pub sequence: u32,
    /// The deterministic completion payload.
    pub payload: Vec<u8>,
}

/// Scheduler-side checkpoint anchor for one VM node.
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub struct SchedulerNodeCheckpoint {
    /// The checkpointed VM node.
    pub node: NodeId,
    /// The VM counter captured by the checkpoint.
    pub counter: NodeCounter,
    /// Scheduler-time projection of `counter` when the checkpoint was recorded.
    pub at: SimInstant,
}

/// Evidence that a VM node crash was applied to scheduler-owned state.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SchedulerNodeCrashApplication {
    /// Session-local sequence number of the applied crash.
    pub sequence: u64,
    /// The crashed VM node.
    pub node: NodeId,
    /// Restart policy recorded by the crash fault.
    pub restart: RestartPolicy,
    /// Scheduler-time point observed for the node at crash activation.
    pub at: SimInstant,
    /// Node counter captured at crash activation.
    pub counter: NodeCounter,
    /// Runtime activity the node had before the crash stopped it.
    pub previous_activity: SchedulerNodeActivity,
    /// Scheduler events deterministically discarded by the crash.
    pub discarded_events: Vec<SchedulerDiscardedEvent>,
    /// Device completions deterministically voided by the crash.
    pub discarded_io: Vec<SchedulerDiscardedIoCompletion>,
    /// Effective topology edges incident to the crashed node and removed.
    pub removed_edges: Vec<SchedulerLookaheadEdge>,
    /// Last checkpoint anchor available to checkpoint-based restart.
    pub checkpoint: Option<SchedulerNodeCheckpoint>,
}

/// Evidence that a crashed VM node was healed or kept down.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SchedulerNodeRestartApplication {
    /// Session-local sequence number of the heal/restart application.
    pub sequence: u64,
    /// The VM node whose crash fault healed.
    pub node: NodeId,
    /// Restart policy that governed the heal.
    pub restart: RestartPolicy,
    /// Scheduler frontier point used as the restart anchor.
    pub at: SimInstant,
    /// Whether the node resumed execution automatically.
    pub restarted: bool,
    /// Node counter after applying the restart policy.
    pub counter: NodeCounter,
    /// Effective topology edges queued for restoration.
    pub restored_edges: Vec<SchedulerLookaheadEdge>,
    /// Checkpoint anchor used by [`RestartPolicy::FromLastCheckpoint`].
    pub checkpoint: Option<SchedulerNodeCheckpoint>,
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
    /// Explorer-supplied preemptions applied by completed RESOLVE phases.
    pub preemption_applications: Vec<SchedulerPreemptionApplication>,
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
#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
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
    /// Inject or replace a full-taxonomy fault at the boundary.
    InjectFault {
        /// Stable handle used for later healing.
        tag: FaultTag,
        /// Full fault taxonomy value to activate.
        fault: Fault,
    },
    /// Heal a full-taxonomy fault at the boundary.
    HealFault {
        /// Stable handle naming the active fault.
        tag: FaultTag,
    },
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

    /// Updates existing directed edges by endpoint, without adding absent edges.
    #[must_use]
    pub fn update_effective_edges<I>(&self, updated_edges: I) -> Self
    where
        I: IntoIterator<Item = SchedulerLookaheadEdge>,
    {
        let updates = updated_edges
            .into_iter()
            .map(|edge| (edge.endpoint(), edge))
            .collect::<BTreeMap<_, _>>();
        let mut emitted = BTreeSet::new();
        let mut edges = Vec::new();
        for edge in &self.edges {
            if let Some(updated) = updates.get(&edge.endpoint()) {
                if emitted.insert(edge.endpoint()) {
                    edges.push(updated.clone());
                }
            } else {
                edges.push(edge.clone());
            }
        }
        Self::from_edges(edges)
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
    /// The basis-point rate whose exact integer Bernoulli decision is resolved.
    pub rate: FaultRateBasisPoints,
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

/// Merges frame deliveries with device I/O completions in the §8.6 total order.
///
/// Frame (backend-input) deliveries and device [`IoCompletion`] events are both
/// cross-node happenings resolved at a node's advanced frontier; this folds them
/// into one canonically ordered list keyed by `(virtual_time, consumer, producer,
/// sequence)` ([SCHED-29], [SCHED-33]). When no device completion is due the
/// frame list is returned unchanged, so the no-device path is byte-identical to
/// before the device seam existed.
#[must_use]
fn merge_node_deliveries(
    frames: Vec<ScheduledEvent>,
    device: Vec<ScheduledEvent>,
) -> Vec<ScheduledEvent> {
    if device.is_empty() {
        return frames;
    }
    let mut merged = frames;
    merged.extend(device);
    ordered_scheduled_events(&merged)
        .into_iter()
        .cloned()
        .collect()
}

fn pending_frames_from_scheduled_events(
    events: &[ScheduledEvent],
) -> BTreeMap<NodeId, Vec<PendingFrame>> {
    let mut pending_frames: BTreeMap<NodeId, Vec<PendingFrame>> = BTreeMap::new();
    for event in events {
        let ScheduledEventPayload::BackendInput(input) = &event.payload else {
            continue;
        };
        pending_frames
            .entry(event.key.consumer().node.clone())
            .or_default()
            .push(PendingFrame {
                source: event.key.producer().node.clone(),
                sequence: event.key.sequence(),
                delivery_icount: Icount {
                    retired: event.key.virtual_time().ticks,
                },
                payload: ContentHash::from_bytes(&input.payload),
            });
    }
    pending_frames
}

fn search_frontier_choices_from_scheduled_events(
    _configuration: Configuration,
    events: &[ScheduledEvent],
) -> SearchFrontierChoices {
    let mut choices = Vec::new();
    for event in ordered_scheduled_events(events) {
        let ScheduledEventPayload::ProbabilisticFault(choice) = &event.payload else {
            continue;
        };
        if choice.rate.basis_points() > 0 {
            choices.push(probabilistic_fault_search_choice(event, choice, 0, true));
        }
        if u32::from(choice.rate.basis_points()) < FaultRateBasisPoints::DENOMINATOR {
            choices.push(probabilistic_fault_search_choice(
                event,
                choice,
                u64::from(choice.rate.basis_points()),
                false,
            ));
        }
    }
    SearchFrontierChoices::from_decision_sequences(choices)
}

fn probabilistic_fault_search_choice(
    event: &ScheduledEvent,
    choice: &SchedulerResolveFaultChoice,
    value: u64,
    fired: bool,
) -> Vec<Decision> {
    vec![
        Decision::RngDraw(RngDecision {
            stream: choice.stream.clone(),
            value,
        }),
        Decision::FaultFires(FaultDecision {
            at: event.key.virtual_time(),
            fault: choice.fault.clone(),
            fired,
        }),
    ]
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
        recorder.decide_fault_basis_points(
            event.key.virtual_time(),
            choice.fault.clone(),
            choice.stream.clone(),
            choice.rate,
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
                exact_local_event_source_key(left).cmp(exact_local_event_source_key(right))
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

fn validate_vcpu_idle_snapshot(
    node: &SchedulerNodeId,
    vcpu_count: u32,
    vcpus: &mut [SchedulerVcpuIdleState],
) -> Result<(), SchedulerError> {
    if node.kind != SchedulingNodeKind::Vm {
        return Err(SchedulerError::BoundaryViolation {
            message: format!(
                "scheduler vCPU idle snapshot targets non-VM node: {}:{:?}",
                node.node.name, node.kind
            ),
        });
    }
    if vcpu_count == 0 {
        return Err(SchedulerError::BoundaryViolation {
            message: format!(
                "scheduler vCPU idle snapshot for {}:{:?} must declare at least one vCPU",
                node.node.name, node.kind
            ),
        });
    }
    if vcpus.len() != vcpu_count as usize {
        return Err(SchedulerError::BoundaryViolation {
            message: format!(
                "scheduler vCPU idle snapshot for {}:{:?} must cover all {} vCPUs: saw {}",
                node.node.name,
                node.kind,
                vcpu_count,
                vcpus.len()
            ),
        });
    }

    vcpus.sort();
    for (expected, state) in (0..vcpu_count).zip(vcpus.iter()) {
        if state.vcpu.index != expected {
            return Err(SchedulerError::BoundaryViolation {
                message: format!(
                    "scheduler vCPU idle snapshot for {}:{:?} must cover contiguous vCPUs 0..{}: saw vCPU {} at slot {}",
                    node.node.name, node.kind, vcpu_count, state.vcpu.index, expected
                ),
            });
        }
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
    /// Explorer-supplied preemption decisions waiting for the owning node RUN.
    pub preemption_requests: Vec<PreemptionDecision>,
    /// Per-vCPU idle snapshots keyed by scheduler VM node.
    pub vcpu_idle_snapshots: Vec<SchedulerNodeVcpuIdleSnapshot>,
    /// Cross-node, I/O, fault, and control events waiting for scheduler delivery.
    pub pending_events: Vec<ScheduledEvent>,
    /// Saved per-producer/consumer sequence counters for newly emitted events.
    pub event_sequences: EventSequenceState,
    /// Static world products used to validate trigger node scheduling actions.
    pub trigger_static_topology: Option<WorldStaticTopology>,
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
            preemption_requests: Vec::new(),
            vcpu_idle_snapshots: Vec::new(),
            pending_events,
            event_sequences: EventSequenceState::empty(),
            trigger_static_topology: None,
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

    /// Sets the world-derived static topology used to validate trigger actions.
    #[must_use]
    pub fn with_trigger_world(mut self, world: &World) -> Self {
        self.trigger_static_topology = Some(world.static_topology());
        self.refresh_configuration();
        self
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

    /// Adds an explorer-supplied preemption request to the scheduler queue.
    #[must_use]
    pub fn with_preemption_request(mut self, decision: PreemptionDecision) -> Self {
        self.preemption_requests.push(decision);
        self.preemption_requests.sort_by(preemption_decision_order);
        self.refresh_configuration();
        self
    }

    /// Sets per-vCPU idle evidence for one scheduler VM node.
    ///
    /// # Errors
    ///
    /// Returns [`SchedulerError::BoundaryViolation`] when the snapshot is
    /// internally invalid.
    pub fn with_vcpu_idle_snapshot(
        mut self,
        mut snapshot: SchedulerNodeVcpuIdleSnapshot,
    ) -> Result<Self, SchedulerError> {
        validate_vcpu_idle_snapshot(&snapshot.node, snapshot.vcpu_count, &mut snapshot.vcpus)?;
        self.vcpu_idle_snapshots
            .retain(|existing| existing.node != snapshot.node);
        self.vcpu_idle_snapshots.push(snapshot);
        self.vcpu_idle_snapshots.sort();
        self.refresh_configuration();
        Ok(self)
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
    match &scenario.trigger_static_topology {
        Some(topology) => {
            lines.push(String::from("trigger_static_topology=present"));
            lines.push(world_static_topology_material(topology));
        }
        None => lines.push(String::from("trigger_static_topology=absent")),
    }
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

    let mut preemption_requests = scenario.preemption_requests.clone();
    preemption_requests.sort_by(preemption_decision_order);
    lines.push(format!("preemption_requests={}", preemption_requests.len()));
    lines.extend(preemption_requests.iter().map(preemption_decision_material));

    let mut vcpu_idle_snapshots = scenario.vcpu_idle_snapshots.clone();
    vcpu_idle_snapshots.sort();
    lines.push(format!("vcpu_idle_snapshots={}", vcpu_idle_snapshots.len()));
    lines.extend(vcpu_idle_snapshots.iter().map(vcpu_idle_snapshot_material));

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

fn preemption_decision_order(
    left: &PreemptionDecision,
    right: &PreemptionDecision,
) -> std::cmp::Ordering {
    left.at
        .cmp(&right.at)
        .then_with(|| left.node.name.cmp(&right.node.name))
        .then_with(|| preemption_kind_order(&left.kind).cmp(&preemption_kind_order(&right.kind)))
}

fn preemption_kind_order(kind: &PreemptionKind) -> (u8, u32, u32, u32) {
    match kind {
        PreemptionKind::VcpuSwitch { from_vcpu, to_vcpu } => (0, from_vcpu.index, to_vcpu.index, 0),
        PreemptionKind::InterruptAt { target_vcpu, irq } => (1, target_vcpu.index, irq.vector, 0),
    }
}

fn preemption_decision_material(preemption: &PreemptionDecision) -> String {
    let mut lines = Vec::new();
    lines.push(String::from("preemption_request:"));
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
    lines.join("\n")
}

fn vcpu_idle_snapshot_material(snapshot: &SchedulerNodeVcpuIdleSnapshot) -> String {
    let mut vcpus = snapshot.vcpus.clone();
    vcpus.sort();
    let mut lines = Vec::new();
    lines.push(String::from("vcpu_idle_snapshot:"));
    lines.push(scheduler_node_material(&snapshot.node));
    lines.push(format!("vcpu_count={}", snapshot.vcpu_count));
    lines.push(format!("vcpu_idle_states={}", vcpus.len()));
    for state in vcpus {
        lines.push(format!("vcpu={}", state.vcpu.index));
        lines.push(format!("halted={}", state.halted));
        match state.next_deadline {
            Some(deadline) => lines.push(format!("next_deadline_ns={}", deadline.nanos)),
            None => lines.push(String::from("next_deadline_ns=none")),
        }
        lines.push(format!("pending_input={}", state.pending_input));
    }
    lines.join("\n")
}

fn scheduler_lookahead_edge_material(edge: &SchedulerLookaheadEdge) -> String {
    format!(
        "edge:\nedge_from:\n{}\nedge_to:\n{}\nedge_minimum_latency_ns={}",
        scheduler_node_material(&edge.from),
        scheduler_node_material(&edge.to),
        edge.minimum_latency.nanos,
    )
}

fn world_static_topology_material(topology: &WorldStaticTopology) -> String {
    let mut participants = topology.participants.clone();
    participants.sort();
    let mut rng_streams = topology.rng_streams.clone();
    rng_streams.sort();
    let mut lookahead_graph = topology.lookahead_graph.clone();
    lookahead_graph.sort();
    let mut bake_nodes = topology.bake_nodes.clone();
    bake_nodes.sort();

    let mut lines = Vec::new();
    lines.push(format!("participants={}", participants.len()));
    for node in participants {
        lines.push(trigger_node_material("participant", &node));
    }
    lines.push(format!("rng_streams={}", rng_streams.len()));
    for stream in rng_streams {
        lines.push(format!("rng_stream_domain_len={}", stream.domain.len()));
        lines.push(format!("rng_stream_domain={}", stream.domain));
        lines.push(format!("rng_stream_name_len={}", stream.name.len()));
        lines.push(format!("rng_stream_name={}", stream.name));
    }
    lines.push(format!("world_lookahead_edges={}", lookahead_graph.len()));
    for edge in lookahead_graph {
        lines.push(world_lookahead_edge_material(&edge));
    }
    lines.push(format!("bake_nodes={}", bake_nodes.len()));
    for node in bake_nodes {
        lines.push(trigger_node_material("bake_node", &node));
    }
    lines.join("\n")
}

fn world_lookahead_edge_material(edge: &WorldLookaheadEdge) -> String {
    format!(
        "world_edge_from_len={}\nworld_edge_from={}\nworld_edge_to_len={}\nworld_edge_to={}\nworld_edge_minimum_latency_ns={}",
        edge.from.name.len(),
        edge.from.name,
        edge.to.name.len(),
        edge.to.name,
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
        SchedulerTopologyChangeEffect::UpdateEffectiveEdges(updated_edges) => {
            let graph = SchedulerLookaheadGraph::from_edges(updated_edges.clone());
            lines.push(String::from(
                "topology_change_effect=update-effective-edges",
            ));
            lines.push(format!(
                "topology_change_updated_edges={}",
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
            "payload=probabilistic-fault\npayload_fault_len={}\npayload_fault={}\npayload_stream_domain_len={}\npayload_stream_domain={}\npayload_stream_name_len={}\npayload_stream_name={}\npayload_rate_basis_points={}",
            choice.fault.name.len(),
            choice.fault.name,
            choice.stream.domain.len(),
            choice.stream.domain,
            choice.stream.name.len(),
            choice.stream.name,
            choice.rate.basis_points(),
        ),
        ScheduledEventPayload::Control(operation) => {
            format!("payload=control\n{}", control_operation_material(operation))
        }
    }
}

fn control_operation_material(operation: &ControlOperation) -> String {
    let mut lines = Vec::new();
    lines.push(format!("control_sequence={}", operation.sequence));
    lines.push(format!(
        "control_kind={}",
        control_operation_kind_label(&operation.kind)
    ));
    match &operation.kind {
        ControlOperationKind::InjectFault { tag, fault } => {
            lines.push(trigger_fault_tag_material("control_tag", tag));
            lines.push(fault.canonical_material());
        }
        ControlOperationKind::HealFault { tag } => {
            lines.push(trigger_fault_tag_material("control_tag", tag));
        }
        ControlOperationKind::Pause
        | ControlOperationKind::Resume
        | ControlOperationKind::Step
        | ControlOperationKind::Snapshot
        | ControlOperationKind::Fork
        | ControlOperationKind::Inject
        | ControlOperationKind::Query => {}
    }
    lines.join("\n")
}

fn control_operation_kind_label(kind: &ControlOperationKind) -> &'static str {
    match kind {
        ControlOperationKind::Pause => "pause",
        ControlOperationKind::Resume => "resume",
        ControlOperationKind::Step => "step",
        ControlOperationKind::Snapshot => "snapshot",
        ControlOperationKind::Fork => "fork",
        ControlOperationKind::Inject => "inject",
        ControlOperationKind::InjectFault { .. } => "inject-fault",
        ControlOperationKind::HealFault { .. } => "heal-fault",
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

pub(crate) fn scheduler_event_log_empty_prefix() -> ContentHash {
    ContentHash::from_canonical_material("crucible.scheduler.event-log.prefix.v1", "empty=true")
}

fn scheduler_event_log_prefix_for_resume(offset: EventLogOffset) -> ContentHash {
    match offset.appended_segment {
        Some(appended_segment) => scheduler_event_log_prefix_after_append(
            offset.prefix,
            appended_segment,
            offset.bytes,
            offset.events,
        ),
        None => offset.prefix,
    }
}

fn scheduler_event_log_prefix_after_append(
    previous_prefix: ContentHash,
    appended_segment: ContentHash,
    bytes: u64,
    events: u64,
) -> ContentHash {
    let prefix_material = format!(
        "previous_prefix={}\nappended_segment={}\nbytes={bytes}\nevents={events}",
        previous_prefix.to_hex(),
        appended_segment.to_hex(),
    );
    ContentHash::from_canonical_material("crucible.scheduler.event-log.prefix.v1", &prefix_material)
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

/// Builds a retained assertion log from a search configuration schedule.
///
/// # Errors
///
/// Returns [`OfflineAssertionCheckError`] when the schedule length cannot be
/// represented as event-log sequence numbers.
pub(crate) fn recorded_assertion_log_from_schedule_for_search(
    schedule: &Schedule,
) -> Result<RecordedAssertionLog, OfflineAssertionCheckError> {
    let mut entries = Vec::with_capacity(schedule.len().saturating_add(1));
    let mut terminal_ticks = 0_u64;
    for (index, decision) in schedule.decisions().iter().enumerate() {
        let sequence = u64::try_from(index)
            .map_err(|_| OfflineAssertionCheckError::PrefixLengthOverflow { prefix_len: index })?;
        let at = search_schedule_decision_event_time(decision, sequence);
        terminal_ticks = terminal_ticks.max(at.ticks);
        entries.push(scheduler_event_log_entry(
            sequence,
            at,
            SchedulerEventLogPayload::Decision(decision.clone()),
        ));
    }

    let boundary_index = entries.len();
    let boundary_sequence = u64::try_from(boundary_index).map_err(|_| {
        OfflineAssertionCheckError::PrefixLengthOverflow {
            prefix_len: boundary_index,
        }
    })?;
    let boundary_ticks = if entries.is_empty() {
        terminal_ticks
    } else {
        terminal_ticks.saturating_add(1)
    };
    entries.push(scheduler_event_log_entry(
        boundary_sequence,
        VirtualTime {
            ticks: boundary_ticks,
        },
        SchedulerEventLogPayload::EvaluationBoundary(SchedulerEvaluationBoundaryKind::Quantum),
    ));

    RecordedAssertionLog::from_segments(vec![entries])
}

fn search_schedule_decision_event_time(decision: &Decision, fallback_sequence: u64) -> VirtualTime {
    match decision {
        Decision::DeliveryOrder(order) => order.at,
        Decision::FaultFires(fault) => fault.at,
        Decision::ControlFault(control) => control.at,
        Decision::Preemption(preemption) => VirtualTime {
            ticks: preemption.at.retired,
        },
        Decision::RngDraw(_) | Decision::Override(_) | Decision::AppRandom(_) => VirtualTime {
            ticks: fallback_sequence,
        },
    }
}

fn scheduler_event_log_entry(
    sequence: u64,
    at: VirtualTime,
    payload: SchedulerEventLogPayload,
) -> SchedulerEventLogEntry {
    let event_payload = event_payload_from_scheduler_payload(&payload);
    let class = event_kind_catalog_class_for_entry_construction(&event_payload);
    scheduler_event_log_entry_with_class(sequence, at, class, event_payload, payload)
}

fn scheduler_event_log_entry_with_class(
    sequence: u64,
    at: VirtualTime,
    class: SchedulerEventLogClass,
    event_payload: EventPayload,
    payload: SchedulerEventLogPayload,
) -> SchedulerEventLogEntry {
    let time = scheduler_event_log_time(at, &payload);
    let source = scheduler_event_log_payload_source(&payload);
    let level = scheduler_event_log_payload_level(&payload);
    let content_hash = ContentHash::from_canonical_material(
        "crucible.scheduler.event-log.entry.v1",
        &scheduler_event_log_entry_material(
            sequence,
            &time,
            &source,
            level,
            class,
            &event_payload,
            &payload,
        ),
    );
    SchedulerEventLogEntry {
        sequence,
        at: time,
        source,
        level,
        class,
        event_payload,
        payload,
        content_hash,
        provenance: SchedulerEventLogEntryProvenance,
    }
}

fn scheduler_event_log_entry_with_material(
    sequence: u64,
    at: EventLogTime,
    source: EventSource,
    level: EventLevel,
    class: SchedulerEventLogClass,
    event_payload: EventPayload,
    payload: SchedulerEventLogPayload,
) -> SchedulerEventLogEntry {
    let content_hash = ContentHash::from_canonical_material(
        "crucible.scheduler.event-log.entry.v1",
        &scheduler_event_log_entry_material(
            sequence,
            &at,
            &source,
            level,
            class,
            &event_payload,
            &payload,
        ),
    );
    SchedulerEventLogEntry {
        sequence,
        at,
        source,
        level,
        class,
        event_payload,
        payload,
        content_hash,
        provenance: SchedulerEventLogEntryProvenance,
    }
}

fn scheduler_event_log_entry_material(
    sequence: u64,
    at: &EventLogTime,
    source: &EventSource,
    level: EventLevel,
    class: SchedulerEventLogClass,
    event_payload: &EventPayload,
    payload: &SchedulerEventLogPayload,
) -> String {
    let mut lines = Vec::new();
    lines.push(format!("sequence={sequence}"));
    lines.push(format!("at_virtual_time_ticks={}", at.virtual_time.ticks));
    lines.push(format!("at_icount_retired={}", at.icount.icount.retired));
    match &at.icount.node {
        Some(node) => {
            lines.push(String::from("at_icount_node=some"));
            lines.push(format!("at_icount_node_len={}", node.name.len()));
            lines.push(format!("at_icount_node_name={}", node.name));
        }
        None => lines.push(String::from("at_icount_node=none")),
    }
    lines.push(scheduler_event_log_source_material("source", source));
    lines.push(format!("level={}", event_level_label(level)));
    lines.push(format!("class={}", event_class_label(class)));
    lines.push(event_payload_material("event_payload", event_payload));
    match payload {
        SchedulerEventLogPayload::ResolvedHappening(event) => {
            lines.push(String::from("payload=resolved-happening"));
            lines.push(scheduled_event_material(event));
        }
        SchedulerEventLogPayload::Decision(decision) => {
            lines.push(String::from("payload=decision"));
            lines.push(scheduler_decision_material(decision));
        }
        SchedulerEventLogPayload::Observable(observable) => {
            lines.push(String::from("payload=observable"));
            lines.push(format!("observable={observable:?}"));
        }
        SchedulerEventLogPayload::EvaluationBoundary(kind) => {
            lines.push(String::from("payload=evaluation-boundary"));
            lines.push(format!("kind={kind:?}"));
        }
        SchedulerEventLogPayload::TriggerFired(firing) => {
            lines.push(String::from("payload=trigger_fired"));
            lines.push(trigger_firing_material(firing));
        }
        SchedulerEventLogPayload::TriggerActionApplied(application) => {
            lines.push(String::from("payload=trigger_action_applied"));
            lines.push(trigger_action_application_material(application));
        }
        SchedulerEventLogPayload::Diagnostic(diagnostic) => {
            lines.push(String::from("payload=diagnostic"));
            lines.push(diagnostic_payload_material(diagnostic));
        }
    }
    lines.join("\n")
}

fn event_payload_from_scheduler_payload(payload: &SchedulerEventLogPayload) -> EventPayload {
    match payload {
        SchedulerEventLogPayload::ResolvedHappening(event) => {
            resolved_happening_event_payload(event)
        }
        SchedulerEventLogPayload::Decision(decision) => decision_event_payload(decision),
        SchedulerEventLogPayload::Observable(observable) => observable_event_payload(observable),
        SchedulerEventLogPayload::EvaluationBoundary(kind) => {
            let mut attributes = BTreeMap::new();
            attributes.insert(
                String::from("boundary"),
                EventAttributeValue::String(evaluation_boundary_kind_label(*kind).to_owned()),
            );
            EventPayload::new("evaluation_boundary", attributes)
        }
        SchedulerEventLogPayload::TriggerFired(firing) => {
            let mut attributes = BTreeMap::new();
            attributes.insert(
                String::from("event"),
                EventAttributeValue::Event(firing.event().clone()),
            );
            attributes.insert(
                String::from("condition"),
                EventAttributeValue::String(firing.condition_summary().to_owned()),
            );
            attributes.insert(
                String::from("at"),
                EventAttributeValue::VirtualTime(firing.at()),
            );
            attributes.insert(
                String::from("action"),
                EventAttributeValue::String(trigger_action_kind_label(firing.action()).to_owned()),
            );
            EventPayload::new("trigger_fired", attributes)
        }
        SchedulerEventLogPayload::TriggerActionApplied(application) => {
            trigger_action_application_event_payload(application)
        }
        SchedulerEventLogPayload::Diagnostic(diagnostic) => diagnostic.event_payload(),
    }
}

fn resolved_happening_event_payload(event: &ScheduledEvent) -> EventPayload {
    let mut attributes = BTreeMap::new();
    attributes.insert(
        String::from("virtual_time"),
        EventAttributeValue::VirtualTime(event.key.virtual_time()),
    );
    attributes.insert(
        String::from("consumer"),
        EventAttributeValue::Node(event.key.consumer().node.clone()),
    );
    attributes.insert(
        String::from("producer"),
        EventAttributeValue::Node(event.key.producer().node.clone()),
    );
    attributes.insert(
        String::from("sequence"),
        EventAttributeValue::U64(event.key.sequence()),
    );
    match &event.payload {
        ScheduledEventPayload::BackendInput(input) => {
            attributes.insert(
                String::from("node"),
                EventAttributeValue::Node(input.node.clone()),
            );
            attributes.insert(
                String::from("payload"),
                EventAttributeValue::Bytes(input.payload.clone()),
            );
            EventPayload::new("backend_input", attributes)
        }
        ScheduledEventPayload::IoCompletion(completion) => {
            attributes.insert(
                String::from("node"),
                EventAttributeValue::Node(completion.target.clone()),
            );
            attributes.insert(
                String::from("delivery_icount"),
                EventAttributeValue::Icount(completion.delivery_icount),
            );
            attributes.insert(
                String::from("payload"),
                EventAttributeValue::Bytes(completion.payload.clone()),
            );
            EventPayload::new("io_completion", attributes)
        }
        ScheduledEventPayload::FaultActivation(fault) => {
            attributes.insert(
                String::from("fault"),
                EventAttributeValue::Fault(fault.clone()),
            );
            EventPayload::new("fault_activation", attributes)
        }
        ScheduledEventPayload::ProbabilisticFault(choice) => {
            attributes.insert(
                String::from("fault"),
                EventAttributeValue::Fault(choice.fault.clone()),
            );
            attributes.insert(
                String::from("stream_domain"),
                EventAttributeValue::String(choice.stream.domain.clone()),
            );
            attributes.insert(
                String::from("stream_name"),
                EventAttributeValue::String(choice.stream.name.clone()),
            );
            attributes.insert(
                String::from("rate_basis_points"),
                EventAttributeValue::U64(u64::from(choice.rate.basis_points())),
            );
            EventPayload::new("probabilistic_fault", attributes)
        }
        ScheduledEventPayload::Control(operation) => {
            attributes.insert(
                String::from("command_id"),
                EventAttributeValue::U64(operation.sequence),
            );
            attributes.insert(
                String::from("command"),
                EventAttributeValue::String(
                    control_operation_kind_label(&operation.kind).to_owned(),
                ),
            );
            EventPayload::new("control", attributes)
        }
    }
}

fn decision_event_payload(decision: &Decision) -> EventPayload {
    let mut attributes = BTreeMap::new();
    match decision {
        Decision::DeliveryOrder(order) => {
            attributes.insert(
                String::from("at"),
                EventAttributeValue::VirtualTime(order.at),
            );
            attributes.insert(
                String::from("events"),
                EventAttributeValue::U64(order.order.len() as u64),
            );
            EventPayload::new("delivery_order", attributes)
        }
        Decision::FaultFires(fault) => {
            attributes.insert(
                String::from("at"),
                EventAttributeValue::VirtualTime(fault.at),
            );
            attributes.insert(
                String::from("fault"),
                EventAttributeValue::Fault(fault.fault.clone()),
            );
            attributes.insert(
                String::from("fired"),
                EventAttributeValue::Bool(fault.fired),
            );
            EventPayload::new("fault_fires", attributes)
        }
        Decision::RngDraw(draw) => {
            attributes.insert(
                String::from("stream_domain"),
                EventAttributeValue::String(draw.stream.domain.clone()),
            );
            attributes.insert(
                String::from("stream_name"),
                EventAttributeValue::String(draw.stream.name.clone()),
            );
            attributes.insert(String::from("value"), EventAttributeValue::U64(draw.value));
            EventPayload::new("rng_draw", attributes)
        }
        Decision::Override(override_decision) => {
            attributes.insert(
                String::from("point"),
                EventAttributeValue::String(override_decision.point.key.clone()),
            );
            attributes.insert(
                String::from("choice"),
                EventAttributeValue::String(override_decision.choice.name.clone()),
            );
            EventPayload::new("override", attributes)
        }
        Decision::Preemption(preemption) => {
            attributes.insert(
                String::from("node"),
                EventAttributeValue::Node(preemption.node.clone()),
            );
            attributes.insert(
                String::from("at"),
                EventAttributeValue::Icount(preemption.at),
            );
            attributes.insert(
                String::from("kind"),
                EventAttributeValue::String(preemption_kind_label(&preemption.kind).to_owned()),
            );
            EventPayload::new("preemption", attributes)
        }
        Decision::AppRandom(random) => {
            attributes.insert(
                String::from("node"),
                EventAttributeValue::Node(random.node.clone()),
            );
            attributes.insert(
                String::from("stream_domain"),
                EventAttributeValue::String(random.stream.domain.clone()),
            );
            attributes.insert(
                String::from("stream_name"),
                EventAttributeValue::String(random.stream.name.clone()),
            );
            attributes.insert(
                String::from("request_id"),
                EventAttributeValue::U64(random.request_id),
            );
            attributes.insert(
                String::from("width"),
                EventAttributeValue::U64(u64::from(random.width)),
            );
            attributes.insert(
                String::from("value"),
                EventAttributeValue::U64(random.value),
            );
            EventPayload::new("app_random", attributes)
        }
        Decision::ControlFault(control) => {
            attributes.insert(
                String::from("at"),
                EventAttributeValue::VirtualTime(control.at),
            );
            attributes.insert(
                String::from("command_id"),
                EventAttributeValue::U64(control.sequence),
            );
            attributes.insert(
                String::from("action"),
                EventAttributeValue::String(control_fault_action_label(&control.action).to_owned()),
            );
            EventPayload::new("control_fault", attributes)
        }
    }
}

fn observable_event_payload(observable: &ObservableEventPayload) -> EventPayload {
    let mut attributes = BTreeMap::new();
    match observable {
        ObservableEventPayload::NetworkDelivered { link, payload } => {
            if let Some(link) = link {
                attributes.insert(
                    String::from("link"),
                    EventAttributeValue::String(link.name.clone()),
                );
            }
            attributes.insert(
                String::from("payload"),
                EventAttributeValue::Bytes(payload.clone()),
            );
            EventPayload::new("network_delivered", attributes)
        }
        ObservableEventPayload::ConsoleOutput { node, bytes } => {
            attributes.insert(
                String::from("node"),
                EventAttributeValue::Node(node.clone()),
            );
            attributes.insert(
                String::from("bytes"),
                EventAttributeValue::Bytes(bytes.clone()),
            );
            EventPayload::new("console_output", attributes)
        }
        ObservableEventPayload::CoverageBlock {
            execution_icount,
            node,
            guest_pc,
            block_len,
        } => {
            attributes.insert(
                String::from("kind"),
                EventAttributeValue::String(String::from("basic_block")),
            );
            attributes.insert(
                String::from("node"),
                EventAttributeValue::Node(node.clone()),
            );
            attributes.insert(
                String::from("execution_icount"),
                EventAttributeValue::Icount(*execution_icount),
            );
            attributes.insert(
                String::from("guest_pc"),
                EventAttributeValue::U64(*guest_pc),
            );
            attributes.insert(
                String::from("block_len"),
                EventAttributeValue::U64(u64::from(*block_len)),
            );
            attributes.insert(
                String::from("block"),
                EventAttributeValue::String(format!("{guest_pc:#x}+{block_len:#x}")),
            );
            EventPayload::new("coverage", attributes)
        }
        ObservableEventPayload::CoverageMarker {
            retired_icount,
            node,
            marker,
        } => {
            attributes.insert(
                String::from("kind"),
                EventAttributeValue::String(String::from("named")),
            );
            attributes.insert(
                String::from("node"),
                EventAttributeValue::Node(node.clone()),
            );
            attributes.insert(
                String::from("retired_icount"),
                EventAttributeValue::Icount(*retired_icount),
            );
            attributes.insert(
                String::from("id"),
                EventAttributeValue::String(marker.name.clone()),
            );
            EventPayload::new("coverage", attributes)
        }
        ObservableEventPayload::AssertionProximity {
            assertion,
            quantifier,
            distance,
            node,
        } => {
            attributes.insert(
                String::from("id"),
                EventAttributeValue::String(assertion.name.clone()),
            );
            attributes.insert(
                String::from("quantifier"),
                EventAttributeValue::String(
                    assertion_quantifier_kind_label(*quantifier).to_owned(),
                ),
            );
            attributes.insert(
                String::from("distance"),
                EventAttributeValue::U128(*distance),
            );
            if let Some(node) = node {
                attributes.insert(
                    String::from("node"),
                    EventAttributeValue::Node(node.clone()),
                );
            }
            EventPayload::new("assertion_proximity", attributes)
        }
        ObservableEventPayload::MemorySample {
            sample_icount,
            node,
            place,
            value,
        } => {
            attributes.insert(
                String::from("node"),
                EventAttributeValue::Node(node.clone()),
            );
            attributes.insert(
                String::from("sample_icount"),
                EventAttributeValue::Icount(*sample_icount),
            );
            attributes.insert(
                String::from("place"),
                EventAttributeValue::String(format!("{place:?}")),
            );
            attributes.insert(String::from("value"), EventAttributeValue::U64(*value));
            EventPayload::new("memory_sample", attributes)
        }
        ObservableEventPayload::IoCompletion {
            node,
            kind,
            payload,
        } => {
            attributes.insert(
                String::from("node"),
                EventAttributeValue::Node(node.clone()),
            );
            attributes.insert(
                String::from("kind"),
                EventAttributeValue::String(format!("{kind:?}")),
            );
            attributes.insert(
                String::from("payload"),
                EventAttributeValue::Bytes(payload.clone()),
            );
            EventPayload::new("observed_io_completion", attributes)
        }
        ObservableEventPayload::NodeState { node, state } => {
            attributes.insert(
                String::from("node"),
                EventAttributeValue::Node(node.clone()),
            );
            attributes.insert(
                String::from("state"),
                EventAttributeValue::String(format!("{state:?}")),
            );
            EventPayload::new("node_state", attributes)
        }
        ObservableEventPayload::AssertionStateChanged { name, state } => {
            attributes.insert(
                String::from("id"),
                EventAttributeValue::String(name.name.clone()),
            );
            attributes.insert(
                String::from("new_state"),
                EventAttributeValue::String(format!("{state:?}")),
            );
            EventPayload::new("assertion_state_changed", attributes)
        }
        ObservableEventPayload::AssertionEvaluated {
            name,
            flavor,
            condition,
            message,
            details,
        } => {
            attributes.insert(
                String::from("id"),
                EventAttributeValue::String(name.name.clone()),
            );
            attributes.insert(
                String::from("flavor"),
                EventAttributeValue::String(format!("{flavor:?}")),
            );
            attributes.insert(
                String::from("condition"),
                EventAttributeValue::Bool(*condition),
            );
            attributes.insert(
                String::from("message"),
                EventAttributeValue::String(message.clone()),
            );
            insert_guest_assertion_details(&mut attributes, details);
            EventPayload::new("assertion_evaluated", attributes)
        }
        ObservableEventPayload::GuestMarker {
            retired_icount,
            node,
            marker,
        } => {
            attributes.insert(
                String::from("marker_kind"),
                EventAttributeValue::String(String::from("event")),
            );
            attributes.insert(
                String::from("node"),
                EventAttributeValue::Node(node.clone()),
            );
            attributes.insert(
                String::from("marker"),
                EventAttributeValue::String(marker.name.clone()),
            );
            attributes.insert(
                String::from("retired_icount"),
                EventAttributeValue::Icount(*retired_icount),
            );
            EventPayload::new("guest_marker", attributes)
        }
        ObservableEventPayload::GuestAssertionMarker {
            retired_icount,
            node,
            marker,
        } => {
            attributes.insert(
                String::from("marker_kind"),
                EventAttributeValue::String(String::from("assert")),
            );
            attributes.insert(
                String::from("node"),
                EventAttributeValue::Node(node.clone()),
            );
            attributes.insert(
                String::from("retired_icount"),
                EventAttributeValue::Icount(*retired_icount),
            );
            attributes.insert(
                String::from("assertion"),
                EventAttributeValue::String(marker.id.name.clone()),
            );
            attributes.insert(
                String::from("flavor"),
                EventAttributeValue::String(format!("{:?}", marker.kind)),
            );
            attributes.insert(
                String::from("condition"),
                EventAttributeValue::Bool(marker.condition),
            );
            attributes.insert(
                String::from("must_hit"),
                EventAttributeValue::Bool(marker.must_hit),
            );
            attributes.insert(
                String::from("message"),
                EventAttributeValue::String(marker.message.clone()),
            );
            attributes.insert(
                String::from("location"),
                EventAttributeValue::String(marker.location.clone()),
            );
            insert_guest_assertion_details(&mut attributes, &marker.details);
            EventPayload::new("guest_marker", attributes)
        }
    }
}

fn insert_guest_assertion_details(
    attributes: &mut BTreeMap<String, EventAttributeValue>,
    details: &[crate::trigger::GuestAssertionDetail],
) {
    let details_len = u64::try_from(details.len()).unwrap_or(u64::MAX);
    attributes.insert(
        String::from("details_len"),
        EventAttributeValue::U64(details_len),
    );
    for (index, detail) in details.iter().enumerate() {
        attributes.insert(
            format!("detail.{index}.key"),
            EventAttributeValue::String(detail.key.clone()),
        );
        attributes.insert(
            format!("detail.{index}.value"),
            EventAttributeValue::String(detail.value.clone()),
        );
    }
}

fn trigger_action_application_event_payload(
    application: &TriggerActionApplication,
) -> EventPayload {
    if let Action::Log { level, message } = &application.action {
        let mut details = BTreeMap::new();
        details.insert(
            String::from("event"),
            EventAttributeValue::Event(application.event.clone()),
        );
        details.insert(
            String::from("level"),
            EventAttributeValue::Level(event_level_from_trigger_log(*level)),
        );
        details.insert(
            String::from("message"),
            EventAttributeValue::String(message.clone()),
        );
        return EventPayload::diagnostic("trigger.log", details);
    }

    let mut attributes = BTreeMap::new();
    attributes.insert(
        String::from("event"),
        EventAttributeValue::Event(application.event.clone()),
    );
    attributes.insert(
        String::from("at"),
        EventAttributeValue::VirtualTime(application.at),
    );
    attributes.insert(
        String::from("sequence"),
        EventAttributeValue::U64(application.sequence),
    );
    attributes.insert(
        String::from("action"),
        EventAttributeValue::String(trigger_action_kind_label(&application.action).to_owned()),
    );
    EventPayload::new("trigger_action_applied", attributes)
}

fn scheduler_event_log_time(at: VirtualTime, payload: &SchedulerEventLogPayload) -> EventLogTime {
    EventLogTime {
        virtual_time: at,
        icount: scheduler_event_log_payload_icount(at, payload),
    }
}

fn scheduler_event_log_payload_icount(
    at: VirtualTime,
    payload: &SchedulerEventLogPayload,
) -> EventLogIcountStamp {
    match payload {
        SchedulerEventLogPayload::ResolvedHappening(event) => {
            scheduled_event_payload_icount(at, &event.payload)
        }
        SchedulerEventLogPayload::Decision(decision) => decision_icount(at, decision),
        SchedulerEventLogPayload::Observable(observable) => {
            observable_payload_icount(at, observable)
        }
        SchedulerEventLogPayload::EvaluationBoundary(_)
        | SchedulerEventLogPayload::TriggerFired(_)
        | SchedulerEventLogPayload::TriggerActionApplied(_)
        | SchedulerEventLogPayload::Diagnostic(_) => boundary_icount(at),
    }
}

fn scheduled_event_payload_icount(
    at: VirtualTime,
    payload: &ScheduledEventPayload,
) -> EventLogIcountStamp {
    match payload {
        ScheduledEventPayload::BackendInput(input) => node_boundary_icount(at, &input.node),
        ScheduledEventPayload::IoCompletion(completion) => EventLogIcountStamp {
            node: Some(completion.target.clone()),
            icount: completion.delivery_icount,
        },
        ScheduledEventPayload::FaultActivation(_)
        | ScheduledEventPayload::ProbabilisticFault(_)
        | ScheduledEventPayload::Control(_) => boundary_icount(at),
    }
}

fn decision_icount(at: VirtualTime, decision: &Decision) -> EventLogIcountStamp {
    match decision {
        Decision::Preemption(preemption) => EventLogIcountStamp {
            node: Some(preemption.node.clone()),
            icount: preemption.at,
        },
        Decision::AppRandom(random) => node_boundary_icount(at, &random.node),
        Decision::DeliveryOrder(_)
        | Decision::FaultFires(_)
        | Decision::RngDraw(_)
        | Decision::Override(_)
        | Decision::ControlFault(_) => boundary_icount(at),
    }
}

fn observable_payload_icount(
    at: VirtualTime,
    observable: &ObservableEventPayload,
) -> EventLogIcountStamp {
    match observable {
        ObservableEventPayload::ConsoleOutput { node, .. }
        | ObservableEventPayload::IoCompletion { node, .. }
        | ObservableEventPayload::NodeState { node, .. } => node_boundary_icount(at, node),
        ObservableEventPayload::CoverageBlock {
            execution_icount,
            node,
            ..
        }
        | ObservableEventPayload::CoverageMarker {
            retired_icount: execution_icount,
            node,
            ..
        } => EventLogIcountStamp {
            node: Some(node.clone()),
            icount: *execution_icount,
        },
        ObservableEventPayload::MemorySample {
            sample_icount,
            node,
            ..
        } => EventLogIcountStamp {
            node: Some(node.clone()),
            icount: *sample_icount,
        },
        ObservableEventPayload::GuestMarker {
            retired_icount,
            node,
            ..
        }
        | ObservableEventPayload::GuestAssertionMarker {
            retired_icount,
            node,
            ..
        } => EventLogIcountStamp {
            node: Some(node.clone()),
            icount: *retired_icount,
        },
        ObservableEventPayload::NetworkDelivered { .. }
        | ObservableEventPayload::AssertionProximity { .. }
        | ObservableEventPayload::AssertionStateChanged { .. }
        | ObservableEventPayload::AssertionEvaluated { .. } => boundary_icount(at),
    }
}

fn boundary_icount(at: VirtualTime) -> EventLogIcountStamp {
    EventLogIcountStamp {
        node: None,
        icount: Icount { retired: at.ticks },
    }
}

fn node_boundary_icount(at: VirtualTime, node: &NodeId) -> EventLogIcountStamp {
    EventLogIcountStamp {
        node: Some(node.clone()),
        icount: Icount { retired: at.ticks },
    }
}

fn scheduler_event_log_payload_source(payload: &SchedulerEventLogPayload) -> EventSource {
    match payload {
        SchedulerEventLogPayload::ResolvedHappening(event) => scheduled_event_source(event),
        SchedulerEventLogPayload::Decision(decision) => decision_source(decision),
        SchedulerEventLogPayload::Observable(observable) => observable_payload_source(observable),
        SchedulerEventLogPayload::EvaluationBoundary(_) => EventSource::Engine,
        SchedulerEventLogPayload::TriggerFired(firing) => EventSource::Scenario {
            event: firing.event().clone(),
        },
        SchedulerEventLogPayload::TriggerActionApplied(application) => EventSource::Scenario {
            event: application.event.clone(),
        },
        SchedulerEventLogPayload::Diagnostic(_) => EventSource::Engine,
    }
}

fn scheduled_event_source(event: &ScheduledEvent) -> EventSource {
    match &event.payload {
        ScheduledEventPayload::Control(operation) => EventSource::Command {
            command_id: operation.sequence,
        },
        payload => scheduled_event_payload_source(payload),
    }
}

fn scheduled_event_payload_source(payload: &ScheduledEventPayload) -> EventSource {
    match payload {
        ScheduledEventPayload::BackendInput(input) => EventSource::Node {
            node: input.node.clone(),
        },
        ScheduledEventPayload::IoCompletion(completion) => EventSource::Node {
            node: completion.target.clone(),
        },
        ScheduledEventPayload::FaultActivation(fault) => EventSource::Scenario {
            event: EventId::from_name(fault.name.clone()),
        },
        ScheduledEventPayload::ProbabilisticFault(choice) => EventSource::Scenario {
            event: EventId::from_name(choice.fault.name.clone()),
        },
        ScheduledEventPayload::Control(operation) => EventSource::Command {
            command_id: operation.sequence,
        },
    }
}

fn decision_source(decision: &Decision) -> EventSource {
    match decision {
        Decision::Preemption(preemption) => EventSource::Node {
            node: preemption.node.clone(),
        },
        Decision::AppRandom(random) => EventSource::Guest {
            node: random.node.clone(),
        },
        Decision::ControlFault(control) => EventSource::Command {
            command_id: control.sequence,
        },
        Decision::DeliveryOrder(_)
        | Decision::FaultFires(_)
        | Decision::RngDraw(_)
        | Decision::Override(_) => EventSource::Engine,
    }
}

fn observable_payload_source(observable: &ObservableEventPayload) -> EventSource {
    match observable {
        ObservableEventPayload::ConsoleOutput { node, .. }
        | ObservableEventPayload::MemorySample { node, .. }
        | ObservableEventPayload::IoCompletion { node, .. }
        | ObservableEventPayload::NodeState { node, .. } => {
            EventSource::Node { node: node.clone() }
        }
        ObservableEventPayload::GuestMarker { node, .. }
        | ObservableEventPayload::CoverageMarker { node, .. }
        | ObservableEventPayload::GuestAssertionMarker { node, .. } => {
            EventSource::Guest { node: node.clone() }
        }
        ObservableEventPayload::NetworkDelivered { .. }
        | ObservableEventPayload::CoverageBlock { .. }
        | ObservableEventPayload::AssertionProximity { .. }
        | ObservableEventPayload::AssertionStateChanged { .. }
        | ObservableEventPayload::AssertionEvaluated { .. } => EventSource::Engine,
    }
}

fn scheduler_event_log_payload_level(payload: &SchedulerEventLogPayload) -> EventLevel {
    match payload {
        SchedulerEventLogPayload::ResolvedHappening(_) => EventLevel::Info,
        SchedulerEventLogPayload::Decision(Decision::RngDraw(_)) => EventLevel::Trace,
        SchedulerEventLogPayload::Decision(_) => EventLevel::Debug,
        SchedulerEventLogPayload::Observable(observable) => observable_payload_level(observable),
        SchedulerEventLogPayload::EvaluationBoundary(_) => EventLevel::Trace,
        SchedulerEventLogPayload::TriggerFired(_) => EventLevel::Debug,
        SchedulerEventLogPayload::TriggerActionApplied(application) => {
            trigger_action_application_level(application)
        }
        SchedulerEventLogPayload::Diagnostic(diagnostic) => diagnostic.level,
    }
}

fn observable_payload_level(observable: &ObservableEventPayload) -> EventLevel {
    match observable {
        ObservableEventPayload::CoverageBlock { .. } => EventLevel::Trace,
        ObservableEventPayload::MemorySample { .. } => EventLevel::Debug,
        ObservableEventPayload::AssertionProximity { .. } => EventLevel::Debug,
        ObservableEventPayload::ConsoleOutput { .. }
        | ObservableEventPayload::NetworkDelivered { .. }
        | ObservableEventPayload::IoCompletion { .. }
        | ObservableEventPayload::NodeState { .. }
        | ObservableEventPayload::AssertionStateChanged { .. }
        | ObservableEventPayload::AssertionEvaluated { .. }
        | ObservableEventPayload::CoverageMarker { .. }
        | ObservableEventPayload::GuestMarker { .. }
        | ObservableEventPayload::GuestAssertionMarker { .. } => EventLevel::Info,
    }
}

fn trigger_action_application_level(application: &TriggerActionApplication) -> EventLevel {
    match &application.action {
        Action::Log { level, .. } => event_level_from_trigger_log(*level),
        Action::Fail { .. } => EventLevel::Error,
        Action::InjectFault { .. }
        | Action::HealFault { .. }
        | Action::ArmTimer { .. }
        | Action::CancelTimer { .. }
        | Action::StartNode { .. }
        | Action::StopNode { .. }
        | Action::CreateSavepoint { .. }
        | Action::Fork { .. }
        | Action::Pass
        | Action::Group(_) => EventLevel::Info,
    }
}

fn event_level_from_trigger_log(level: LogLevel) -> EventLevel {
    match level {
        LogLevel::Debug => EventLevel::Debug,
        LogLevel::Info => EventLevel::Info,
        LogLevel::Warn => EventLevel::Warn,
        LogLevel::Error => EventLevel::Error,
    }
}

fn scheduler_event_log_source_material(prefix: &str, source: &EventSource) -> String {
    match source {
        EventSource::Scenario { event } => format!(
            "{prefix}=scenario\n{prefix}.event_len={}\n{prefix}.event={}",
            event.name.len(),
            event.name
        ),
        EventSource::Engine => format!("{prefix}=engine"),
        EventSource::Node { node } => format!(
            "{prefix}=node\n{prefix}.node_len={}\n{prefix}.node={}",
            node.name.len(),
            node.name
        ),
        EventSource::Guest { node } => format!(
            "{prefix}=guest\n{prefix}.node_len={}\n{prefix}.node={}",
            node.name.len(),
            node.name
        ),
        EventSource::Command { command_id } => {
            format!("{prefix}=command\n{prefix}.command_id={command_id}")
        }
    }
}

fn event_level_label(level: EventLevel) -> &'static str {
    match level {
        EventLevel::Trace => "trace",
        EventLevel::Debug => "debug",
        EventLevel::Info => "info",
        EventLevel::Warn => "warn",
        EventLevel::Error => "error",
    }
}

fn assertion_quantifier_kind_label(kind: AssertionQuantifierKind) -> &'static str {
    match kind {
        AssertionQuantifierKind::Always => "always",
        AssertionQuantifierKind::Sometimes => "sometimes",
        AssertionQuantifierKind::Eventually => "eventually",
        AssertionQuantifierKind::AfterQuiescence => "after-quiescence",
        AssertionQuantifierKind::Reachable => "reachable",
        AssertionQuantifierKind::GuestAlways => "guest-always",
        AssertionQuantifierKind::GuestSometimes => "guest-sometimes",
        AssertionQuantifierKind::GuestReachable => "guest-reachable",
        AssertionQuantifierKind::GuestUnreachable => "guest-unreachable",
    }
}

fn event_class_label(class: SchedulerEventLogClass) -> &'static str {
    match class {
        SchedulerEventLogClass::Causal => "causal",
        SchedulerEventLogClass::Observational => "observational",
    }
}

fn event_payload_material(prefix: &str, payload: &EventPayload) -> String {
    let mut lines = Vec::new();
    lines.push(format!("{prefix}.kind_len={}", payload.kind().len()));
    lines.push(format!("{prefix}.kind={}", payload.kind()));
    lines.push(format!(
        "{prefix}.attributes={}",
        payload.attributes().len()
    ));
    for (name, value) in payload.attributes() {
        lines.push(format!("{prefix}.attribute.{name}.name_len={}", name.len()));
        lines.push(format!("{prefix}.attribute.{name}.name={name}"));
        lines.push(event_attribute_value_material(
            &format!("{prefix}.attribute.{name}.value"),
            value,
        ));
    }
    lines.join("\n")
}

fn event_attribute_value_material(prefix: &str, value: &EventAttributeValue) -> String {
    match value {
        EventAttributeValue::Bool(value) => format!("{prefix}.type=bool\n{prefix}.value={value}"),
        EventAttributeValue::U64(value) => format!("{prefix}.type=u64\n{prefix}.value={value}"),
        EventAttributeValue::U128(value) => format!("{prefix}.type=u128\n{prefix}.value={value}"),
        EventAttributeValue::String(value) => format!(
            "{prefix}.type=string\n{prefix}.len={}\n{prefix}.value={value}",
            value.len()
        ),
        EventAttributeValue::Bytes(value) => format!(
            "{prefix}.type=bytes\n{prefix}.len={}\n{prefix}.value={}",
            value.len(),
            hex_bytes(value)
        ),
        EventAttributeValue::Node(value) => format!(
            "{prefix}.type=node\n{prefix}.name_len={}\n{prefix}.name={}",
            value.name.len(),
            value.name
        ),
        EventAttributeValue::Event(value) => format!(
            "{prefix}.type=event\n{prefix}.name_len={}\n{prefix}.name={}",
            value.name.len(),
            value.name
        ),
        EventAttributeValue::Fault(value) => format!(
            "{prefix}.type=fault\n{prefix}.name_len={}\n{prefix}.name={}",
            value.name.len(),
            value.name
        ),
        EventAttributeValue::VirtualTime(value) => {
            format!("{prefix}.type=virtual-time\n{prefix}.ticks={}", value.ticks)
        }
        EventAttributeValue::Icount(value) => {
            format!("{prefix}.type=icount\n{prefix}.retired={}", value.retired)
        }
        EventAttributeValue::Level(value) => {
            format!(
                "{prefix}.type=level\n{prefix}.value={}",
                event_level_label(*value)
            )
        }
    }
}

fn diagnostic_payload_material(diagnostic: &EventDiagnosticPayload) -> String {
    let mut lines = Vec::new();
    lines.push(format!("diagnostic.name_len={}", diagnostic.name.len()));
    lines.push(format!("diagnostic.name={}", diagnostic.name));
    lines.push(format!(
        "diagnostic.level={}",
        event_level_label(diagnostic.level)
    ));
    lines.push(event_payload_material(
        "diagnostic.event_payload",
        &diagnostic.event_payload(),
    ));
    lines.join("\n")
}

fn evaluation_boundary_kind_label(kind: SchedulerEvaluationBoundaryKind) -> &'static str {
    match kind {
        SchedulerEvaluationBoundaryKind::Quantum => "quantum",
        SchedulerEvaluationBoundaryKind::Rendezvous => "rendezvous",
    }
}

fn preemption_kind_label(kind: &PreemptionKind) -> &'static str {
    match kind {
        PreemptionKind::VcpuSwitch { .. } => "vcpu-switch",
        PreemptionKind::InterruptAt { .. } => "interrupt-at",
    }
}

fn control_fault_action_label(action: &ControlFaultAction) -> &'static str {
    match action {
        ControlFaultAction::Inject { .. } => "inject",
        ControlFaultAction::Heal { .. } => "heal",
    }
}

fn trigger_action_kind_label(action: &Action) -> &'static str {
    match action {
        Action::InjectFault { .. } => "inject-fault",
        Action::HealFault { .. } => "heal-fault",
        Action::ArmTimer { .. } => "arm-timer",
        Action::CancelTimer { .. } => "cancel-timer",
        Action::StartNode { .. } => "start-node",
        Action::StopNode { .. } => "stop-node",
        Action::CreateSavepoint { .. } => "create-savepoint",
        Action::Fork { .. } => "fork",
        Action::Pass => "pass",
        Action::Fail { .. } => "fail",
        Action::Log { .. } => "log",
        Action::Group(_) => "group",
    }
}

fn event_kind_catalog_class_for_entry_construction(
    payload: &EventPayload,
) -> SchedulerEventLogClass {
    match event_kind_catalog_class(payload) {
        Some(class) => class,
        None => SchedulerEventLogClass::Observational,
    }
}

fn event_kind_catalog_class(payload: &EventPayload) -> Option<SchedulerEventLogClass> {
    crate::event_catalog::event_kind_catalog_class(payload.kind())
}

fn trigger_action_application_material(application: &TriggerActionApplication) -> String {
    let mut lines = Vec::new();
    lines.push(format!("trigger_action_sequence={}", application.sequence));
    lines.push(format!("event_len={}", application.event.name.len()));
    lines.push(format!("event={}", application.event.name));
    lines.push(format!("applied_at_ticks={}", application.at.ticks));
    lines.push(format!("path_len={}", application.path.len()));
    for (depth, index) in application.path.iter().enumerate() {
        lines.push(format!("path.{depth}={index}"));
    }
    lines.push(trigger_action_material("action", &application.action));
    lines.join("\n")
}

fn trigger_firing_material(firing: &EventFiring) -> String {
    let mut lines = Vec::new();
    lines.push(format!("event_len={}", firing.event().name.len()));
    lines.push(format!("event={}", firing.event().name));
    lines.push(format!("fired_at_ticks={}", firing.at().ticks));
    lines.push(format!(
        "condition_summary_len={}",
        firing.condition_summary().len()
    ));
    lines.push(format!("condition_summary={}", firing.condition_summary()));
    lines.push(trigger_action_material("action", firing.action()));
    lines.join("\n")
}

fn trigger_action_material(prefix: &str, action: &Action) -> String {
    let mut lines = Vec::new();
    match action {
        Action::InjectFault { tag, fault } => {
            lines.push(format!("{prefix}.kind=inject-fault"));
            lines.push(trigger_fault_tag_material(&format!("{prefix}.tag"), tag));
            lines.push(trigger_membership_fault_material(
                &format!("{prefix}.fault"),
                fault,
            ));
        }
        Action::HealFault { tag } => {
            lines.push(format!("{prefix}.kind=heal-fault"));
            lines.push(trigger_fault_tag_material(&format!("{prefix}.tag"), tag));
        }
        Action::ArmTimer { name, after } => {
            lines.push(format!("{prefix}.kind=arm-timer"));
            lines.push(trigger_timer_material(&format!("{prefix}.timer"), name));
            lines.push(format!("{prefix}.after_nanos={}", after.nanos));
        }
        Action::CancelTimer { name } => {
            lines.push(format!("{prefix}.kind=cancel-timer"));
            lines.push(trigger_timer_material(&format!("{prefix}.timer"), name));
        }
        Action::StartNode { node } => {
            lines.push(format!("{prefix}.kind=start-node"));
            lines.push(trigger_node_material(&format!("{prefix}.node"), node));
        }
        Action::StopNode { node } => {
            lines.push(format!("{prefix}.kind=stop-node"));
            lines.push(trigger_node_material(&format!("{prefix}.node"), node));
        }
        Action::CreateSavepoint { label } => {
            lines.push(format!("{prefix}.kind=create-savepoint"));
            lines.push(trigger_optional_label_material(
                &format!("{prefix}.label"),
                label,
            ));
        }
        Action::Fork { label } => {
            lines.push(format!("{prefix}.kind=fork"));
            lines.push(trigger_optional_label_material(
                &format!("{prefix}.label"),
                label,
            ));
        }
        Action::Pass => {
            lines.push(format!("{prefix}.kind=pass"));
        }
        Action::Fail { reason } => {
            lines.push(format!("{prefix}.kind=fail"));
            lines.push(format!("{prefix}.reason_len={}", reason.len()));
            lines.push(format!("{prefix}.reason={reason}"));
        }
        Action::Log { level, message } => {
            lines.push(format!("{prefix}.kind=log"));
            lines.push(format!(
                "{prefix}.level={}",
                trigger_log_level_label(*level)
            ));
            lines.push(format!("{prefix}.message_len={}", message.len()));
            lines.push(format!("{prefix}.message={message}"));
        }
        Action::Group(actions) => {
            lines.push(format!("{prefix}.kind=group"));
            lines.push(format!("{prefix}.actions={}", actions.len()));
            for (index, action) in actions.iter().enumerate() {
                lines.push(trigger_action_material(
                    &format!("{prefix}.action.{index}"),
                    action,
                ));
            }
        }
    }
    lines.join("\n")
}

fn trigger_membership_fault_material(prefix: &str, fault: &MembershipFault) -> String {
    let mut lines = Vec::new();
    match fault {
        MembershipFault::Crash { node, restart } => {
            lines.push(format!("{prefix}.kind=crash"));
            lines.push(trigger_node_material(&format!("{prefix}.node"), node));
            lines.push(format!(
                "{prefix}.restart={}",
                trigger_restart_policy_label(*restart)
            ));
        }
        MembershipFault::Partition {
            endpoint_a,
            endpoint_b,
            direction,
        } => {
            lines.push(format!("{prefix}.kind=partition"));
            lines.push(trigger_node_material(
                &format!("{prefix}.endpoint_a"),
                endpoint_a,
            ));
            lines.push(trigger_node_material(
                &format!("{prefix}.endpoint_b"),
                endpoint_b,
            ));
            lines.push(format!(
                "{prefix}.direction={}",
                trigger_partition_direction_label(*direction)
            ));
        }
        MembershipFault::Isolate { node } => {
            lines.push(format!("{prefix}.kind=isolate"));
            lines.push(trigger_node_material(&format!("{prefix}.node"), node));
        }
        MembershipFault::NotYetJoined { node } => {
            lines.push(format!("{prefix}.kind=not-yet-joined"));
            lines.push(trigger_node_material(&format!("{prefix}.node"), node));
        }
        MembershipFault::Taxonomy { fault } => {
            lines.push(format!("{prefix}.kind=taxonomy"));
            lines.push(fault.canonical_material());
        }
    }
    lines.join("\n")
}

fn trigger_fault_tag_material(prefix: &str, tag: &crate::FaultTag) -> String {
    format!("{prefix}.len={}\n{prefix}={}", tag.name.len(), tag.name)
}

fn trigger_node_material(prefix: &str, node: &NodeId) -> String {
    format!("{prefix}.len={}\n{prefix}={}", node.name.len(), node.name)
}

fn trigger_timer_material(prefix: &str, timer: &TimerId) -> String {
    format!("{prefix}.len={}\n{prefix}={}", timer.name.len(), timer.name)
}

fn trigger_optional_label_material(prefix: &str, label: &Option<String>) -> String {
    match label {
        Some(label) => format!(
            "{prefix}.present=true\n{prefix}.len={}\n{prefix}={label}",
            label.len()
        ),
        None => format!("{prefix}.present=false"),
    }
}

fn trigger_restart_policy_label(policy: RestartPolicy) -> &'static str {
    match policy {
        RestartPolicy::FromReadyPoint => "from-ready-point",
        RestartPolicy::FromLastCheckpoint => "from-last-checkpoint",
        RestartPolicy::StayDown => "stay-down",
    }
}

fn trigger_partition_direction_label(direction: PartitionDirection) -> &'static str {
    match direction {
        PartitionDirection::Bidirectional => "bidirectional",
        PartitionDirection::EndpointAToEndpointB => "endpoint-a-to-endpoint-b",
        PartitionDirection::EndpointBToEndpointA => "endpoint-b-to-endpoint-a",
    }
}

fn trigger_log_level_label(level: LogLevel) -> &'static str {
    match level {
        LogLevel::Debug => "debug",
        LogLevel::Info => "info",
        LogLevel::Warn => "warn",
        LogLevel::Error => "error",
    }
}

fn network_partitions(
    network: &BTreeMap<LinkId, CombinedNetworkFaults>,
) -> BTreeMap<LinkId, CombinedPartitionFault> {
    network
        .iter()
        .filter_map(|(link, faults)| faults.partition.map(|partition| (link.clone(), partition)))
        .collect()
}

fn world_edge_removed_by_network_faults(
    edge: &WorldLookaheadEdge,
    network: &BTreeMap<LinkId, CombinedNetworkFaults>,
) -> bool {
    let Some(partition) = scheduler_link_ids_for_nodes(&edge.from, &edge.to)
        .into_iter()
        .find_map(|link| network.get(&link).and_then(|faults| faults.partition))
    else {
        return false;
    };
    if edge.from <= edge.to {
        partition.endpoint_a_to_endpoint_b
    } else {
        partition.endpoint_b_to_endpoint_a
    }
}

fn network_direction_is_partitioned(
    direction: NetworkLinkDirection,
    partition: &CombinedPartitionFault,
) -> bool {
    match direction {
        NetworkLinkDirection::EndpointAToEndpointB => partition.endpoint_a_to_endpoint_b,
        NetworkLinkDirection::EndpointBToEndpointA => partition.endpoint_b_to_endpoint_a,
    }
}

fn scheduler_link_ids_for_nodes(left: &NodeId, right: &NodeId) -> [LinkId; 2] {
    let (endpoint_a, endpoint_b) = if left <= right {
        (left, right)
    } else {
        (right, left)
    };
    [
        LinkId::from_name(format!(
            "link_endpoint_a_len={}\nlink_endpoint_a={}\nlink_endpoint_b_len={}\nlink_endpoint_b={}",
            endpoint_a.name.len(),
            endpoint_a.name,
            endpoint_b.name.len(),
            endpoint_b.name
        )),
        LinkId::from_name(format!("{}--{}", endpoint_a.name, endpoint_b.name)),
    ]
}

fn combined_network_faults_for_link(
    network: &BTreeMap<LinkId, CombinedNetworkFaults>,
    link_id: &LinkId,
    endpoint_a: &NodeId,
    endpoint_b: &NodeId,
) -> CombinedNetworkFaults {
    std::iter::once(link_id.clone())
        .chain(scheduler_link_ids_for_nodes(endpoint_a, endpoint_b))
        .find_map(|candidate| network.get(&candidate).cloned())
        .unwrap_or_default()
}

fn apply_trigger_action(
    state: &mut TriggerActionState,
    static_topology: Option<&WorldStaticTopology>,
    firing: &EventFiring,
    action: &Action,
    path: &mut Vec<u64>,
    entries: &mut Vec<TriggerActionApplication>,
) -> Result<(), SchedulerError> {
    match action {
        Action::Group(actions) => {
            for (index, action) in actions.iter().enumerate() {
                let index =
                    u64::try_from(index).map_err(|_| SchedulerError::BoundaryViolation {
                        message: String::from("trigger action group index exceeds u64"),
                    })?;
                path.push(index);
                apply_trigger_action(state, static_topology, firing, action, path, entries)?;
                path.pop();
            }
            Ok(())
        }
        Action::InjectFault { .. }
        | Action::HealFault { .. }
        | Action::ArmTimer { .. }
        | Action::CancelTimer { .. }
        | Action::StartNode { .. }
        | Action::StopNode { .. }
        | Action::CreateSavepoint { .. }
        | Action::Fork { .. }
        | Action::Pass
        | Action::Fail { .. }
        | Action::Log { .. } => {
            let sequence = u64::try_from(state.applications.len()).map_err(|_| {
                SchedulerError::BoundaryViolation {
                    message: String::from("trigger action sequence exceeds u64"),
                }
            })?;
            let application = TriggerActionApplication {
                sequence,
                event: firing.event().clone(),
                at: firing.at(),
                path: path.clone(),
                action: action.clone(),
            };
            apply_trigger_effect(state, static_topology, &application)?;
            state.applications.push(application.clone());
            entries.push(application);
            Ok(())
        }
    }
}

fn apply_trigger_effect(
    state: &mut TriggerActionState,
    static_topology: Option<&WorldStaticTopology>,
    application: &TriggerActionApplication,
) -> Result<(), SchedulerError> {
    match &application.action {
        Action::InjectFault { tag, fault } => {
            activate_fault_tag(state, tag, fault);
        }
        Action::HealFault { tag } => {
            heal_fault_tag(state, tag);
        }
        Action::ArmTimer { name, after } => {
            let ticks = application
                .at
                .ticks
                .checked_add(after.nanos)
                .ok_or_else(|| SchedulerError::BoundaryViolation {
                    message: format!(
                        "trigger timer `{}` overflows virtual time at {} + {}",
                        name.name, application.at.ticks, after.nanos
                    ),
                })?;
            state
                .armed_timers
                .insert(name.clone(), VirtualTime { ticks });
        }
        Action::CancelTimer { name } => {
            state.armed_timers.remove(name);
        }
        Action::StartNode { node } => {
            validate_trigger_node_schedule_target(static_topology, node)?;
            state
                .node_states
                .insert(node.clone(), NodeLifecycle::Started);
        }
        Action::StopNode { node } => {
            validate_trigger_node_schedule_target(static_topology, node)?;
            state
                .node_states
                .insert(node.clone(), NodeLifecycle::Exited);
        }
        Action::CreateSavepoint { label } => {
            state.savepoints.push(TriggerLabelRecord {
                sequence: application.sequence,
                event: application.event.clone(),
                at: application.at,
                label: label.clone(),
            });
        }
        Action::Fork { label } => {
            state.forks.push(TriggerLabelRecord {
                sequence: application.sequence,
                event: application.event.clone(),
                at: application.at,
                label: label.clone(),
            });
        }
        Action::Pass => {
            apply_trigger_verdict_effect(state, application);
        }
        Action::Fail { .. } => {
            apply_trigger_verdict_effect(state, application);
        }
        Action::Log { level, message } => {
            state.diagnostics.push(TriggerDiagnosticRecord {
                sequence: application.sequence,
                event: application.event.clone(),
                at: application.at,
                level: *level,
                message: message.clone(),
            });
        }
        Action::Group(_) => {
            return Err(SchedulerError::BoundaryViolation {
                message: String::from("trigger group action must be flattened before application"),
            });
        }
    }
    Ok(())
}

fn apply_trigger_verdict_effect(
    state: &mut TriggerActionState,
    application: &TriggerActionApplication,
) {
    match &application.action {
        Action::Pass => {
            state.termination_requested = true;
            if !matches!(
                state.verdict.as_ref(),
                Some(verdict) if verdict.failed_reason.is_some()
            ) {
                state.verdict = Some(TriggerVerdict {
                    sequence: application.sequence,
                    event: application.event.clone(),
                    at: application.at,
                    failed_reason: None,
                });
            }
        }
        Action::Fail { reason } => {
            state.termination_requested = true;
            if !matches!(
                state.verdict.as_ref(),
                Some(verdict) if verdict.failed_reason.is_some()
            ) {
                state.verdict = Some(TriggerVerdict {
                    sequence: application.sequence,
                    event: application.event.clone(),
                    at: application.at,
                    failed_reason: Some(reason.clone()),
                });
            }
        }
        _ => {}
    }
}

fn activate_fault_tag(state: &mut TriggerActionState, tag: &FaultTag, fault: &MembershipFault) {
    state.active_taxonomy_faults.remove(tag);
    if let Some(fault) = fault.as_taxonomy_fault() {
        state
            .active_taxonomy_faults
            .insert(tag.clone(), fault.clone());
    }
    state.active_faults.insert(tag.clone(), fault.clone());
}

fn heal_fault_tag(state: &mut TriggerActionState, tag: &FaultTag) {
    state.active_taxonomy_faults.remove(tag);
    state.active_faults.remove(tag);
}

fn control_fault_action_for_operation(operation: &ControlOperation) -> Option<ControlFaultAction> {
    match &operation.kind {
        ControlOperationKind::InjectFault { tag, fault } => Some(ControlFaultAction::Inject {
            tag: tag.clone(),
            fault: fault.clone(),
        }),
        ControlOperationKind::HealFault { tag } => {
            Some(ControlFaultAction::Heal { tag: tag.clone() })
        }
        ControlOperationKind::Pause
        | ControlOperationKind::Resume
        | ControlOperationKind::Step
        | ControlOperationKind::Snapshot
        | ControlOperationKind::Fork
        | ControlOperationKind::Inject
        | ControlOperationKind::Query => None,
    }
}

fn apply_control_fault_action(state: &mut TriggerActionState, action: &ControlFaultAction) {
    match action {
        ControlFaultAction::Inject { tag, fault } => {
            activate_fault_tag(state, tag, &MembershipFault::taxonomy(fault.clone()));
        }
        ControlFaultAction::Heal { tag } => heal_fault_tag(state, tag),
    }
}

fn trigger_action_state_from_control_fault_decisions(
    decisions: &[Decision],
) -> (TriggerActionState, Option<u64>) {
    let mut state = TriggerActionState::default();
    let mut sequence = None;
    for decision in decisions {
        let Decision::ControlFault(control) = decision else {
            continue;
        };
        apply_control_fault_action(&mut state, &control.action);
        sequence = Some(control.sequence);
    }
    (state, sequence)
}

fn validate_trigger_node_schedule_target(
    static_topology: Option<&WorldStaticTopology>,
    node: &NodeId,
) -> Result<(), SchedulerError> {
    let Some(static_topology) = static_topology else {
        return Err(SchedulerError::BoundaryViolation {
            message: format!(
                "trigger node scheduling action for `{}` has no world static topology",
                node.name
            ),
        });
    };
    if !static_topology.participants.contains(node) {
        return Err(SchedulerError::BoundaryViolation {
            message: format!(
                "trigger node scheduling action references undeclared node `{}`",
                node.name
            ),
        });
    }
    if !static_topology.bake_nodes.contains(node) {
        return Err(SchedulerError::BoundaryViolation {
            message: format!(
                "trigger node scheduling action references unbaked node `{}`",
                node.name
            ),
        });
    }
    Ok(())
}

#[derive(Clone, Debug, PartialEq, Eq)]
struct SchedulerEventLogSegmentMaterial {
    previous_prefix: ContentHash,
    entries: Vec<SchedulerEventLogSegmentEntryMaterial>,
}

impl SchedulerEventLogSegmentMaterial {
    fn encode(&self) -> Vec<u8> {
        let mut bytes = Vec::new();
        bytes.extend_from_slice(EVENT_LOG_SEGMENT_BINARY_MAGIC);
        bytes.extend_from_slice(&EVENT_LOG_SEGMENT_BINARY_VERSION.to_le_bytes());
        bytes.extend_from_slice(&self.previous_prefix.bytes);
        write_u64_le(&mut bytes, self.entries.len() as u64);
        for entry in &self.entries {
            write_u64_le(&mut bytes, entry.sequence);
            write_u64_le(&mut bytes, entry.at_virtual_time_ticks);
            write_u64_le(&mut bytes, entry.at_icount_retired);
            write_optional_string(&mut bytes, entry.at_icount_node.as_deref());
            write_string(&mut bytes, &entry.source_material);
            bytes.push(event_level_code(entry.level));
            bytes.push(event_class_code(entry.class));
            write_string(&mut bytes, &entry.payload_kind);
            write_u64_le(&mut bytes, entry.payload_attribute_count);
            bytes.extend_from_slice(&entry.content_hash.bytes);
            write_string(&mut bytes, &entry.entry_material);
        }
        bytes
    }

    fn text_view(&self) -> String {
        let mut lines = Vec::new();
        lines.push(String::from(
            "format=crucible.scheduler.event-log.segment-text.v1",
        ));
        lines.push(String::from(
            "canonical_format=crucible.scheduler.event-log.segment.v1",
        ));
        lines.push(format!("schema_version={EVENT_LOG_SEGMENT_BINARY_VERSION}"));
        lines.push(format!("previous_prefix={}", self.previous_prefix.to_hex()));
        lines.push(format!("entries={}", self.entries.len()));
        for entry in &self.entries {
            lines.push(format!("entry.sequence={}", entry.sequence));
            lines.push(format!(
                "entry.at_virtual_time_ticks={}",
                entry.at_virtual_time_ticks
            ));
            lines.push(format!(
                "entry.at_icount_retired={}",
                entry.at_icount_retired
            ));
            match &entry.at_icount_node {
                Some(node) => {
                    lines.push(String::from("entry.at_icount_node=some"));
                    lines.push(format!("entry.at_icount_node_name={node}"));
                }
                None => lines.push(String::from("entry.at_icount_node=none")),
            }
            lines.push(entry.source_material.clone());
            lines.push(format!("entry.level={}", event_level_label(entry.level)));
            lines.push(format!("entry.class={}", event_class_label(entry.class)));
            lines.push(format!("entry.payload.kind={}", entry.payload_kind));
            lines.push(format!(
                "entry.payload.attributes={}",
                entry.payload_attribute_count
            ));
            lines.push(format!("entry.hash={}", entry.content_hash.to_hex()));
            lines.push(format!("entry.bytes={}", entry.entry_material.len()));
            lines.push(String::from("entry.material_begin"));
            lines.push(entry.entry_material.clone());
            lines.push(String::from("entry.material_end"));
        }
        lines.join("\n")
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
struct SchedulerEventLogSegmentEntryMaterial {
    sequence: u64,
    at_virtual_time_ticks: u64,
    at_icount_retired: u64,
    at_icount_node: Option<String>,
    source_material: String,
    level: EventLevel,
    class: SchedulerEventLogClass,
    payload_kind: String,
    payload_attribute_count: u64,
    content_hash: ContentHash,
    entry_material: String,
}

#[derive(Clone, Debug, PartialEq, Eq)]
enum SchedulerEventLogSegmentDecodeError {
    InvalidMagic,
    UnsupportedVersion { version: u32 },
    Truncated { field: &'static str },
    InvalidUtf8 { field: &'static str },
    InvalidFlag { field: &'static str, value: u8 },
    InvalidLevel { value: u8 },
    InvalidClass { value: u8 },
    LengthTooLarge { field: &'static str, len: u64 },
    TrailingBytes { remaining: usize },
}

struct SchedulerEventLogSegmentCursor<'a> {
    bytes: &'a [u8],
    offset: usize,
}

impl<'a> SchedulerEventLogSegmentCursor<'a> {
    fn new(bytes: &'a [u8]) -> Self {
        Self { bytes, offset: 0 }
    }

    fn read_exact(
        &mut self,
        field: &'static str,
        len: usize,
    ) -> Result<&'a [u8], SchedulerEventLogSegmentDecodeError> {
        let end = self.offset.checked_add(len).ok_or(
            SchedulerEventLogSegmentDecodeError::LengthTooLarge {
                field,
                len: len as u64,
            },
        )?;
        let Some(slice) = self.bytes.get(self.offset..end) else {
            return Err(SchedulerEventLogSegmentDecodeError::Truncated { field });
        };
        self.offset = end;
        Ok(slice)
    }

    fn read_u8(&mut self, field: &'static str) -> Result<u8, SchedulerEventLogSegmentDecodeError> {
        Ok(self.read_exact(field, 1)?[0])
    }

    fn read_u32_le(
        &mut self,
        field: &'static str,
    ) -> Result<u32, SchedulerEventLogSegmentDecodeError> {
        let mut word = [0; 4];
        word.copy_from_slice(self.read_exact(field, 4)?);
        Ok(u32::from_le_bytes(word))
    }

    fn read_u64_le(
        &mut self,
        field: &'static str,
    ) -> Result<u64, SchedulerEventLogSegmentDecodeError> {
        let mut word = [0; 8];
        word.copy_from_slice(self.read_exact(field, 8)?);
        Ok(u64::from_le_bytes(word))
    }

    fn read_string(
        &mut self,
        field: &'static str,
    ) -> Result<String, SchedulerEventLogSegmentDecodeError> {
        let len = self.read_u64_le(field)?;
        let len = usize::try_from(len)
            .map_err(|_| SchedulerEventLogSegmentDecodeError::LengthTooLarge { field, len })?;
        let bytes = self.read_exact(field, len)?;
        std::str::from_utf8(bytes)
            .map(str::to_owned)
            .map_err(|_| SchedulerEventLogSegmentDecodeError::InvalidUtf8 { field })
    }

    fn read_optional_string(
        &mut self,
        field: &'static str,
    ) -> Result<Option<String>, SchedulerEventLogSegmentDecodeError> {
        match self.read_u8(field)? {
            EVENT_LOG_SEGMENT_NODE_ABSENT => Ok(None),
            EVENT_LOG_SEGMENT_NODE_PRESENT => Ok(Some(self.read_string(field)?)),
            value => Err(SchedulerEventLogSegmentDecodeError::InvalidFlag { field, value }),
        }
    }

    fn read_content_hash(
        &mut self,
        field: &'static str,
    ) -> Result<ContentHash, SchedulerEventLogSegmentDecodeError> {
        let mut bytes = [0; 32];
        bytes.copy_from_slice(self.read_exact(field, 32)?);
        Ok(ContentHash { bytes })
    }

    fn finish(&self) -> Result<(), SchedulerEventLogSegmentDecodeError> {
        if self.offset == self.bytes.len() {
            Ok(())
        } else {
            Err(SchedulerEventLogSegmentDecodeError::TrailingBytes {
                remaining: self.bytes.len() - self.offset,
            })
        }
    }
}

pub(crate) fn scheduler_event_log_segment_bytes(
    previous_prefix: ContentHash,
    entries: &[SchedulerEventLogEntry],
) -> Vec<u8> {
    let bytes = scheduler_event_log_segment_material(previous_prefix, entries).encode();
    debug_assert!(
        decode_scheduler_event_log_segment(&bytes)
            .map(|decoded| decoded.encode() == bytes)
            .unwrap_or(false)
    );
    bytes
}

fn scheduler_event_log_segment_material(
    previous_prefix: ContentHash,
    entries: &[SchedulerEventLogEntry],
) -> SchedulerEventLogSegmentMaterial {
    let entries = entries
        .iter()
        .map(|entry| {
            let entry_material = scheduler_event_log_entry_material(
                entry.sequence,
                &entry.at,
                &entry.source,
                entry.level,
                entry.class,
                &entry.event_payload,
                &entry.payload,
            );
            SchedulerEventLogSegmentEntryMaterial {
                sequence: entry.sequence,
                at_virtual_time_ticks: entry.at.virtual_time.ticks,
                at_icount_retired: entry.at.icount.icount.retired,
                at_icount_node: entry.at.icount.node.as_ref().map(|node| node.name.clone()),
                source_material: scheduler_event_log_source_material("entry.source", &entry.source),
                level: entry.level,
                class: entry.class,
                payload_kind: entry.event_payload.kind().to_owned(),
                payload_attribute_count: entry.event_payload.attributes().len() as u64,
                content_hash: entry.content_hash,
                entry_material,
            }
        })
        .collect();
    SchedulerEventLogSegmentMaterial {
        previous_prefix,
        entries,
    }
}

fn decode_scheduler_event_log_segment(
    bytes: &[u8],
) -> Result<SchedulerEventLogSegmentMaterial, SchedulerEventLogSegmentDecodeError> {
    let mut cursor = SchedulerEventLogSegmentCursor::new(bytes);
    if cursor.read_exact("magic", EVENT_LOG_SEGMENT_BINARY_MAGIC.len())?
        != EVENT_LOG_SEGMENT_BINARY_MAGIC
    {
        return Err(SchedulerEventLogSegmentDecodeError::InvalidMagic);
    }
    let version = cursor.read_u32_le("version")?;
    if version != EVENT_LOG_SEGMENT_BINARY_VERSION {
        return Err(SchedulerEventLogSegmentDecodeError::UnsupportedVersion { version });
    }
    let previous_prefix = cursor.read_content_hash("previous_prefix")?;
    let entry_count = cursor.read_u64_le("entries")?;
    let entry_count = usize::try_from(entry_count).map_err(|_| {
        SchedulerEventLogSegmentDecodeError::LengthTooLarge {
            field: "entries",
            len: entry_count,
        }
    })?;
    let mut entries = Vec::with_capacity(entry_count);
    for _ in 0..entry_count {
        entries.push(SchedulerEventLogSegmentEntryMaterial {
            sequence: cursor.read_u64_le("entry.sequence")?,
            at_virtual_time_ticks: cursor.read_u64_le("entry.at_virtual_time_ticks")?,
            at_icount_retired: cursor.read_u64_le("entry.at_icount_retired")?,
            at_icount_node: cursor.read_optional_string("entry.at_icount_node")?,
            source_material: cursor.read_string("entry.source")?,
            level: event_level_from_code(cursor.read_u8("entry.level")?)?,
            class: event_class_from_code(cursor.read_u8("entry.class")?)?,
            payload_kind: cursor.read_string("entry.payload.kind")?,
            payload_attribute_count: cursor.read_u64_le("entry.payload.attributes")?,
            content_hash: cursor.read_content_hash("entry.hash")?,
            entry_material: cursor.read_string("entry.material")?,
        });
    }
    cursor.finish()?;
    Ok(SchedulerEventLogSegmentMaterial {
        previous_prefix,
        entries,
    })
}

fn write_u64_le(bytes: &mut Vec<u8>, value: u64) {
    bytes.extend_from_slice(&value.to_le_bytes());
}

fn write_string(bytes: &mut Vec<u8>, value: &str) {
    write_u64_le(bytes, value.len() as u64);
    bytes.extend_from_slice(value.as_bytes());
}

fn write_optional_string(bytes: &mut Vec<u8>, value: Option<&str>) {
    match value {
        Some(value) => {
            bytes.push(EVENT_LOG_SEGMENT_NODE_PRESENT);
            write_string(bytes, value);
        }
        None => bytes.push(EVENT_LOG_SEGMENT_NODE_ABSENT),
    }
}

fn event_level_code(level: EventLevel) -> u8 {
    match level {
        EventLevel::Trace => EVENT_LOG_LEVEL_TRACE,
        EventLevel::Debug => EVENT_LOG_LEVEL_DEBUG,
        EventLevel::Info => EVENT_LOG_LEVEL_INFO,
        EventLevel::Warn => EVENT_LOG_LEVEL_WARN,
        EventLevel::Error => EVENT_LOG_LEVEL_ERROR,
    }
}

fn event_level_from_code(value: u8) -> Result<EventLevel, SchedulerEventLogSegmentDecodeError> {
    match value {
        EVENT_LOG_LEVEL_TRACE => Ok(EventLevel::Trace),
        EVENT_LOG_LEVEL_DEBUG => Ok(EventLevel::Debug),
        EVENT_LOG_LEVEL_INFO => Ok(EventLevel::Info),
        EVENT_LOG_LEVEL_WARN => Ok(EventLevel::Warn),
        EVENT_LOG_LEVEL_ERROR => Ok(EventLevel::Error),
        value => Err(SchedulerEventLogSegmentDecodeError::InvalidLevel { value }),
    }
}

fn event_class_code(class: SchedulerEventLogClass) -> u8 {
    match class {
        SchedulerEventLogClass::Causal => EVENT_LOG_CLASS_CAUSAL,
        SchedulerEventLogClass::Observational => EVENT_LOG_CLASS_OBSERVATIONAL,
    }
}

fn event_class_from_code(
    value: u8,
) -> Result<SchedulerEventLogClass, SchedulerEventLogSegmentDecodeError> {
    match value {
        EVENT_LOG_CLASS_CAUSAL => Ok(SchedulerEventLogClass::Causal),
        EVENT_LOG_CLASS_OBSERVATIONAL => Ok(SchedulerEventLogClass::Observational),
        value => Err(SchedulerEventLogSegmentDecodeError::InvalidClass { value }),
    }
}

fn scheduler_ordered_decisions(
    decisions: Vec<Decision>,
    fallback: SimInstant,
    shift: Shift,
    preemption_times: &[(PreemptionDecision, SimInstant)],
) -> Result<Vec<Decision>, SchedulerError> {
    let mut keyed = Vec::with_capacity(decisions.len());
    for (index, decision) in decisions.into_iter().enumerate() {
        keyed.push((
            scheduler_decision_event_log_time(&decision, fallback, shift, preemption_times)?,
            index,
            decision,
        ));
    }
    keyed.sort_by(|left, right| {
        left.0
            .ticks
            .cmp(&right.0.ticks)
            .then_with(|| left.1.cmp(&right.1))
    });

    Ok(keyed.into_iter().map(|(_, _, decision)| decision).collect())
}

fn scheduler_decision_event_log_time(
    decision: &Decision,
    fallback: SimInstant,
    shift: Shift,
    preemption_times: &[(PreemptionDecision, SimInstant)],
) -> Result<VirtualTime, SchedulerError> {
    match decision {
        Decision::DeliveryOrder(order) => Ok(order.at),
        Decision::FaultFires(fault) => Ok(fault.at),
        Decision::ControlFault(control) => Ok(control.at),
        Decision::Preemption(preemption) => {
            if let Some((_, virtual_time)) = preemption_times
                .iter()
                .find(|(decision, _)| decision == preemption)
            {
                Ok(VirtualTime {
                    ticks: virtual_time.nanos,
                })
            } else {
                Ok(VirtualTime {
                    ticks: preemption.at.to_virtual(shift)?.nanos,
                })
            }
        }
        Decision::RngDraw(_) | Decision::Override(_) | Decision::AppRandom(_) => Ok(VirtualTime {
            ticks: fallback.nanos,
        }),
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
        Decision::ControlFault(control) => {
            lines.push(String::from("decision=control-fault"));
            lines.push(format!("decision_at={}", control.at.ticks));
            lines.push(format!("control_sequence={}", control.sequence));
            lines.push(control_fault_action_material("control", &control.action));
        }
    }
    lines.join("\n")
}

fn control_fault_action_material(prefix: &str, action: &ControlFaultAction) -> String {
    let mut lines = Vec::new();
    match action {
        ControlFaultAction::Inject { tag, fault } => {
            lines.push(format!("{prefix}.kind=inject-fault"));
            lines.push(trigger_fault_tag_material(&format!("{prefix}.tag"), tag));
            lines.push(fault.canonical_material());
        }
        ControlFaultAction::Heal { tag } => {
            lines.push(format!("{prefix}.kind=heal-fault"));
            lines.push(trigger_fault_tag_material(&format!("{prefix}.tag"), tag));
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
    /// An explorer-supplied preemption is waiting for its node RUN.
    PendingPreemption {
        /// The queued preemption decision.
        decision: PreemptionDecision,
    },
    /// A vCPU inside an N-vCPU node is still running.
    ActiveVcpu {
        /// The owning scheduler VM node.
        node: SchedulerNodeId,
        /// The vCPU that is not halted.
        vcpu: VcpuId,
    },
    /// A vCPU inside an N-vCPU node has an armed timer.
    PendingVcpuTimer {
        /// The owning scheduler VM node.
        node: SchedulerNodeId,
        /// The vCPU whose timer is armed.
        vcpu: VcpuId,
        /// The exact virtual-time timer deadline.
        deadline: SimInstant,
    },
    /// A vCPU inside an N-vCPU node has pending input.
    PendingVcpuInput {
        /// The owning scheduler VM node.
        node: SchedulerNodeId,
        /// The vCPU with pending input.
        vcpu: VcpuId,
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
    /// A device sub-node still holds an undelivered I/O completion.
    ///
    /// A completion not yet delivered to its requester is a future happening, so
    /// the system is not quiescent while any is in flight even if every node is
    /// parked `Idle` ([SCHED-22], [SCHED-29]).
    DeviceCompletionInFlight {
        /// The VM node that still owes the completion.
        target: NodeId,
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
    preemption_requests: Vec<PreemptionDecision>,
    preemption_applications: Vec<SchedulerPreemptionApplication>,
    control_admissions: Vec<SchedulerControlAdmission>,
    control_applications: Vec<SchedulerControlApplication>,
    pending_events: Vec<ScheduledEvent>,
    event_sequences: EventSequenceState,
    /// I/O scheduling sub-nodes (disk/9p/net) keyed by the VM node they target.
    ///
    /// Each [`DeviceSchedulingSubNode`](crate::device_subnode::DeviceSchedulingSubNode)
    /// holds an L1 `crucible-device` whose in-flight completions become the owning
    /// node's exact I/O-completion horizon term and are delivered at their exact
    /// icount through [`SingleScheduler::resolve_device_completions`] ([IO-1],
    /// [IO-3], [SCHED-29]).
    device_sub_nodes: BTreeMap<NodeId, Vec<crate::device_subnode::DeviceSchedulingSubNode>>,
    /// The earliest undelivered device-completion virtual time per target node,
    /// recomputed each quantum by
    /// [`refresh_device_horizons`](SingleScheduler::refresh_device_horizons).
    ///
    /// This is the separate exact I/O-completion horizon TERM the scheduler folds
    /// into a node's effective exact local event ([IO-3], [SCHED-10]) — it bounds
    /// the requester's horizon without injecting a deliverable event, so delivery
    /// happens solely on the RESOLVE path through
    /// [`resolve_device_completions`](SingleScheduler::resolve_device_completions)
    /// and is never double-counted.
    device_horizons: BTreeMap<NodeId, SimInstant>,
    /// Test-only fault injection: when `true`,
    /// [`resolve_device_completions`](SingleScheduler::resolve_device_completions)
    /// stamps each I/O completion's key with the consumer's *frontier* icount
    /// instead of the completion's exact `delivery_icount`, modeling the
    /// freeze-time / transport-timing bug RFC-0010 forbids ([IO-2], [DET-19]).
    /// Used by `gate:layer1-injection` falsifiability tests to prove the gates go
    /// red when delivery is not icount-exact. It is never set in production.
    #[cfg(test)]
    broken_device_delivery_stamp: bool,
    control_inbox: Vec<ControlOperation>,
    decision_rng_cursor: DecisionRngState,
    event_log: EventLog,
    trigger_actions: TriggerActionState,
    trigger_static_topology: Option<WorldStaticTopology>,
    frontier: VirtualTime,
    quanta: u64,
    topology_epoch: u64,
    topology_change_applications: Vec<SchedulerTopologyChangeApplication>,
    node_crash_applications: Vec<SchedulerNodeCrashApplication>,
    node_restart_applications: Vec<SchedulerNodeRestartApplication>,
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
        Self::new_with_event_log(scenario, EventLog::new())
    }

    /// Builds a scheduler whose event log writes segments into `store`.
    ///
    /// Use this constructor when the scheduler and temporal graph share one
    /// content-addressed store: every non-empty EMIT appends canonical binary
    /// segment bytes at their BLAKE3 key before the quantum outcome is returned.
    ///
    /// # Errors
    ///
    /// Returns [`SchedulerError`] when the fixed timeline shift cannot be
    /// represented or when an initial node counter cannot be projected onto the
    /// shared virtual timeline.
    pub fn new_with_event_log_segment_store(
        scenario: SchedulerLivenessScenario,
        store: Arc<dyn DagStore>,
    ) -> Result<Self, SchedulerError> {
        Self::new_with_event_log(scenario, EventLog::with_segment_store(store))
    }

    /// Builds a scheduler resumed from `event_log_offset` and backed by `store`.
    ///
    /// The next EMIT append starts at the recorded byte and event offsets, and
    /// uses the reconstructed content prefix from `event_log_offset` as the
    /// parent prefix for the new segment.
    ///
    /// # Errors
    ///
    /// Returns [`SchedulerError`] when the fixed timeline shift cannot be
    /// represented or when an initial node counter cannot be projected onto the
    /// shared virtual timeline.
    pub fn new_with_event_log_offset_and_segment_store(
        scenario: SchedulerLivenessScenario,
        event_log_offset: EventLogOffset,
        store: Arc<dyn DagStore>,
    ) -> Result<Self, SchedulerError> {
        Self::new_with_event_log(
            scenario,
            EventLog::from_offset_with_segment_store(event_log_offset, store),
        )
    }

    fn new_with_event_log(
        scenario: SchedulerLivenessScenario,
        event_log: EventLog,
    ) -> Result<Self, SchedulerError> {
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
        let mut preemption_requests = scenario.preemption_requests;
        preemption_requests.sort_by(preemption_decision_order);
        let mut vcpu_idle_snapshots = scenario.vcpu_idle_snapshots;
        assign_vcpu_idle_snapshots(
            &mut nodes,
            &mut vcpu_idle_snapshots,
            &run_subdivision_policies,
        )?;

        let frontier = frontier_for(&nodes, scenario.shift)?;
        let (trigger_actions, replay_fault_sequence) =
            trigger_action_state_from_control_fault_decisions(configuration.schedule.decisions());

        let mut scheduler = Self {
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
            preemption_requests,
            preemption_applications: Vec::new(),
            control_admissions: Vec::new(),
            control_applications: Vec::new(),
            pending_events: scenario.pending_events,
            event_sequences: scenario.event_sequences,
            device_sub_nodes: BTreeMap::new(),
            device_horizons: BTreeMap::new(),
            #[cfg(test)]
            broken_device_delivery_stamp: false,
            control_inbox: Vec::new(),
            decision_rng_cursor: DecisionRngState::empty(),
            event_log,
            trigger_actions,
            trigger_static_topology: scenario.trigger_static_topology,
            frontier,
            quanta: 0,
            topology_epoch: 0,
            topology_change_applications: Vec::new(),
            node_crash_applications: Vec::new(),
            node_restart_applications: Vec::new(),
            rendezvous_records: Vec::new(),
            boundary_yields: 0,
            ceiling_publications: Vec::new(),
            lock_held: false,
            last_advance: None,
            last_topology_recompute: false,
        };
        scheduler.hydrate_control_fault_schedule_prefix(replay_fault_sequence)?;
        Ok(scheduler)
    }

    /// Returns the current scheduler configuration.
    #[must_use]
    pub fn configuration(&self) -> &Configuration {
        &self.configuration
    }

    /// Installs a deterministic I/O sub-node (disk/9p/net) on its target VM node
    /// (RFC-0010 [IO-1], [IO-3], §15.1).
    ///
    /// The sub-node's in-flight head delivery icount is the **real** source of the
    /// owning node's exact I/O-completion horizon term, so an otherwise-idle
    /// requester is fast-forwarded to the scheduler-time projection of its next
    /// exact I/O completion ([IO-3], [SCHED-10]), and
    /// [`SingleScheduler::resolve_device_completions`] delivers the completion at
    /// that exact delivery icount's scheduler-time projection in the canonical
    /// `(delivery_icount, src_node, seq)` order ([SCHED-29]). Several sub-nodes
    /// may target one VM node; their horizon terms are folded with `min`.
    ///
    /// Submit requests through the returned sub-node before driving the scheduler;
    /// fold the device's live in-flight head into the node's horizon with
    /// [`SingleScheduler::refresh_device_horizons`].
    #[must_use]
    pub fn with_device_sub_node(
        mut self,
        sub_node: crate::device_subnode::DeviceSchedulingSubNode,
    ) -> Self {
        self.device_sub_nodes
            .entry(sub_node.target().clone())
            .or_default()
            .push(sub_node);
        self
    }

    /// Returns a mutable view of the I/O sub-nodes targeting `node`, if any.
    ///
    /// Used by a driver to submit device requests between quanta; the next horizon
    /// refresh folds the device's in-flight head into the node's horizon.
    pub fn device_sub_nodes_for_mut(
        &mut self,
        node: &NodeId,
    ) -> Option<&mut Vec<crate::device_subnode::DeviceSchedulingSubNode>> {
        self.device_sub_nodes.get_mut(node)
    }

    /// **Test-only.** Forces I/O completions to be stamped at the consumer's
    /// frontier icount instead of their exact `delivery_icount`, modeling the
    /// freeze-time bug ([IO-2], [DET-19]).
    ///
    /// Exists solely to prove the determinism gates are falsifiable: with this
    /// set, a scenario whose requester reaches a completion at a frontier
    /// *different* from the completion's exact icount produces a different
    /// resolved order, so the gate goes red. Never used in production.
    #[cfg(test)]
    pub(crate) fn with_broken_device_delivery_stamp(mut self) -> Self {
        self.broken_device_delivery_stamp = true;
        self
    }

    /// Returns whether any device sub-node holds an undelivered completion.
    ///
    /// While any I/O completion is still in flight the system is not quiescent,
    /// even when every node is parked `Idle` ([SCHED-22], [SCHED-29]).
    #[must_use]
    pub fn has_undelivered_device_completion(&self) -> bool {
        self.device_sub_nodes
            .values()
            .flatten()
            .any(|sub_node| sub_node.next_exact_local_event().is_some())
    }

    /// Returns the earliest undelivered device completion for `node` due
    /// **strictly after** `instant`, if any ([SCHED-29]).
    ///
    /// Scans every targeting sub-node's next exact local event; used to keep a
    /// requester `Runnable` when it still owes a later completion, so an idle park
    /// can never strand a sequential read.
    ///
    /// # Errors
    ///
    /// Returns [`SchedulerError::TimeConversion`] when a completion delivery
    /// icount cannot be converted under the timeline shift.
    pub fn device_completion_due_after(
        &self,
        node: &SchedulerNodeId,
        instant: SimInstant,
    ) -> Result<Option<SimInstant>, SchedulerError> {
        let Some(sub_nodes) = self.device_sub_nodes.get(&node.node) else {
            return Ok(None);
        };
        let mut earliest: Option<SimInstant> = None;
        for sub_node in sub_nodes {
            if let Some(delivery_icount) = sub_node.next_exact_local_event() {
                let due = self.vm_delivery_time_for_icount(
                    &node.node,
                    Icount {
                        retired: delivery_icount,
                    },
                )?;
                if due > instant {
                    earliest = Some(match earliest {
                        Some(current) => current.min(due),
                        None => due,
                    });
                }
            }
        }
        Ok(earliest)
    }

    /// Folds every device sub-node's in-flight head into its target node's exact
    /// I/O-completion horizon term and re-activates a parked target that still
    /// owes a completion ([IO-3], [SCHED-9], [SCHED-10], [SCHED-29]).
    ///
    /// Called at the start of each quantum so the horizon the scheduler reads is
    /// the device's *current* next completion — the real exact local event with no
    /// conservative slack. The earliest undelivered completion per target is
    /// recorded in `device_horizons`, which `effective_exact_local_event` mins into
    /// the node's effective horizon. No deliverable event is injected, so delivery
    /// stays solely on the RESOLVE path through
    /// [`resolve_device_completions`](Self::resolve_device_completions) and is
    /// never double-counted; the term is recomputed from scratch so a refresh is
    /// idempotent.
    ///
    /// # Re-activation of an idle requester
    ///
    /// A node parks `Idle` at one completion's exact icount; its *next* sequential
    /// completion is a fresh exact local event it must still advance to. So
    /// whenever a targeting sub-node has an undelivered completion this flips the
    /// node back to `Runnable`, so it is re-PICKed and advanced to the next
    /// completion — without this an idle requester would silently drop a normal
    /// sequential read ([SCHED-29]).
    ///
    /// # Errors
    ///
    /// Returns [`SchedulerError::TimeConversion`] when a completion delivery
    /// icount cannot be converted under the timeline shift.
    pub fn refresh_device_horizons(&mut self) -> Result<(), SchedulerError> {
        // Recompute the earliest undelivered completion per target; the in-flight
        // queues are the single source of truth. Ordered by `NodeId` (BTreeMap
        // iteration) so the refresh is deterministic.
        let mut earliest_by_target: Vec<(NodeId, SimInstant)> = Vec::new();
        for (target, sub_nodes) in &self.device_sub_nodes {
            if self.is_node_down(target) {
                continue;
            }
            let mut earliest: Option<SimInstant> = None;
            for sub_node in sub_nodes {
                if let Some(delivery_icount) = sub_node.next_exact_local_event() {
                    let instant = self.vm_delivery_time_for_icount(
                        target,
                        Icount {
                            retired: delivery_icount,
                        },
                    )?;
                    earliest = Some(match earliest {
                        Some(current) => current.min(instant),
                        None => instant,
                    });
                }
            }
            if let Some(instant) = earliest {
                earliest_by_target.push((target.clone(), instant));
            }
        }

        self.device_horizons.clear();
        for (target, instant) in earliest_by_target {
            self.device_horizons.insert(target.clone(), instant);
            // Re-activate a parked requester so the next sequential completion is
            // observed ([SCHED-29]); a `Runnable` node is left as-is.
            if let Some(runtime) = self
                .nodes
                .iter_mut()
                .find(|runtime| runtime.id.node == target)
                && runtime.crash.is_none()
                && runtime.stopped_crash.is_none()
                && runtime.activity == SchedulerNodeActivity::Idle
            {
                runtime.activity = SchedulerNodeActivity::Runnable;
            }
        }
        Ok(())
    }

    /// RESOLVEs every device completion for `node` due at or before
    /// `consumer_icount` (RFC-0010 [SCHED-29], [SCHED-30], §8.9.4).
    ///
    /// Drains each targeting sub-node's due completions in the canonical
    /// `(delivery_icount, src_node, seq)` order, mints each event's `sequence`
    /// from the live [`EventSequenceState`] for its `(sub_node, target)` pair
    /// ([SCHED-18]), and returns the [`IoCompletion`] events plus the fault
    /// [`Decision`]s they drew, all in delivery order. The completion is made
    /// visible at the scheduler-time projection of **exactly** its
    /// `delivery_icount` ([SCHED-29], [IO-2]), never the consumer's
    /// `consumer_icount` frontier.
    ///
    /// # Errors
    ///
    /// This currently never returns an error; the `Result` is kept for forward
    /// compatibility with sequence-exhaustion guards.
    pub fn resolve_device_completions(
        &mut self,
        node: &SchedulerNodeId,
        consumer_icount: u64,
    ) -> Result<(Vec<ScheduledEvent>, Vec<Decision>), SchedulerError> {
        let mut events = Vec::new();
        let mut decisions = Vec::new();
        let Some(sub_nodes) = self.device_sub_nodes.get_mut(&node.node) else {
            return Ok((events, decisions));
        };
        // Collect every due completion across this node's sub-nodes first (the
        // borrow of `sub_nodes` ends here), then mint sequences against the
        // scheduler-owned counter on the live RESOLVE path.
        let mut due: Vec<crate::device_subnode::DeviceDelivery> = Vec::new();
        for sub_node in sub_nodes.iter_mut() {
            due.extend(sub_node.deliver_due(consumer_icount));
        }
        // Canonical (delivery_icount, then producer sub-node id) order so the
        // resolved order is a pure function of the keys, not host iteration.
        due.sort_by(|left, right| {
            (
                left.delivery_icount,
                &left.sub_node,
                left.source_node,
                left.sequence,
            )
                .cmp(&(
                    right.delivery_icount,
                    &right.sub_node,
                    right.source_node,
                    right.sequence,
                ))
        });
        for delivery in due {
            let completion_decisions =
                self.project_device_decisions_for_vm_time(&node.node, delivery.decisions)?;
            decisions.extend(completion_decisions);

            let Some(completion) = delivery.completion else {
                continue;
            };
            let producer = completion.sub_node.clone();
            let consumer = SchedulerNodeId {
                node: completion.target.clone(),
                kind: SchedulingNodeKind::Vm,
            };
            // SCHED-18 on the LIVE path: the sequence comes from the owned counter.
            let sequence = self.event_sequences.next_sequence(&producer, &consumer);
            self.event_sequences.set_next_sequence(
                producer.clone(),
                consumer.clone(),
                sequence + 1,
            );
            // The completion is made visible at the scheduler-time projection of
            // EXACTLY its delivery icount ([SCHED-29], [IO-2]) — never the
            // consumer's frontier. The test-only broken stamp models the
            // freeze-time bug to prove the gates catch it.
            let stamp_icount = completion.delivery_icount.retired;
            #[cfg(test)]
            let stamp_icount = if self.broken_device_delivery_stamp {
                consumer_icount
            } else {
                stamp_icount
            };
            let instant = self.vm_delivery_time_for_icount(
                &completion.target,
                Icount {
                    retired: stamp_icount,
                },
            )?;
            let virtual_time = VirtualTime {
                ticks: instant.nanos,
            };
            let key = ScheduledEventKey::from_parts(virtual_time, consumer, producer, sequence);
            events.push(ScheduledEvent {
                key,
                payload: ScheduledEventPayload::IoCompletion(completion),
            });
        }
        // Reconcile the cached device horizon term with the in-flight queues now
        // that this target's due completions have drained: a delivered head is no
        // longer a future exact local event, so the term must drop or fall back to
        // the next in-flight head IMMEDIATELY (not wait for the next pre-PICK
        // refresh). Otherwise a stale term would keep the node non-quiescent and
        // distort its effective horizon after the completion was already resolved.
        let next_head = self
            .device_sub_nodes
            .get(&node.node)
            .into_iter()
            .flatten()
            .filter_map(|sub_node| sub_node.next_exact_local_event())
            .map(|delivery_icount| {
                self.vm_delivery_time_for_icount(
                    &node.node,
                    Icount {
                        retired: delivery_icount,
                    },
                )
            })
            .collect::<Result<Vec<_>, _>>()?
            .into_iter()
            .min();
        match next_head {
            Some(instant) => {
                self.device_horizons.insert(node.node.clone(), instant);
            }
            None => {
                self.device_horizons.remove(&node.node);
            }
        }
        Ok((events, decisions))
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
        self.event_log.offset()
    }

    /// Returns the scheduler-owned condition-evaluation prefix.
    #[must_use]
    pub fn condition_event_log_prefix(&self) -> &ConditionEventLogPrefix {
        self.event_log.condition_prefix()
    }

    /// Returns the scheduler-owned trigger action state.
    #[must_use]
    pub fn trigger_actions(&self) -> &TriggerActionState {
        &self.trigger_actions
    }

    /// Captures the scheduler-owned state that must survive a materialized checkpoint.
    #[must_use]
    pub fn materialized_scheduler_state(&self) -> SchedulerState {
        let mut state = SchedulerState::empty();
        state.pending_frames = pending_frames_from_scheduled_events(&self.pending_events);
        state.event_sequences = self.event_sequences.clone();
        state.active_fault_tags = self.trigger_actions.active_faults.clone();
        state.recompute_active_fault_table();
        state.search_frontier = search_frontier_choices_from_scheduled_events(
            self.configuration.clone(),
            &self.pending_events,
        );
        state
    }

    /// Returns the world-derived static topology used for trigger action validation.
    #[must_use]
    pub fn trigger_static_topology(&self) -> Option<&WorldStaticTopology> {
        self.trigger_static_topology.as_ref()
    }

    /// Appends black-box observable condition facts to the scheduler event log.
    ///
    /// # Errors
    ///
    /// Returns [`SchedulerError`] when assigning dense event-log sequences or
    /// appending the event-log segment would overflow the scheduler offsets, or
    /// when the resulting condition prefix is invalid.
    pub fn append_observable_events(
        &mut self,
        events: impl IntoIterator<Item = ObservableEvent>,
    ) -> Result<SchedulerEventLogAppend, SchedulerError> {
        self.event_log.append_observable_events(events)
    }

    /// Appends assertion-proximity steering feedback to the scheduler event log.
    ///
    /// `report` remains a transient assertion-layer view. The persisted steering
    /// facts are appended as typed observational `assertion_proximity` entries in
    /// the unified log, so downstream projections read one log instead of a
    /// parallel proximity record.
    ///
    /// # Errors
    ///
    /// Returns [`SchedulerError`] when assigning dense event-log sequences or
    /// appending the event-log segment would overflow the scheduler offsets, or
    /// when the resulting condition prefix is invalid.
    pub fn append_assertion_proximity_events(
        &mut self,
        report: &HostAssertionReport,
    ) -> Result<SchedulerEventLogAppend, SchedulerError> {
        self.append_observable_events(report.proximities().iter().map(|proximity| {
            ObservableEvent::assertion_proximity(
                proximity.at,
                proximity.assertion.clone(),
                proximity.quantifier,
                proximity.distance,
                None,
            )
        }))
    }

    /// Appends a deterministic trigger/assertion evaluation boundary.
    ///
    /// # Errors
    ///
    /// Returns [`SchedulerError`] when assigning the dense event-log sequence or
    /// appending the event-log segment would overflow the scheduler offsets, or
    /// when the boundary would make the checked condition prefix invalid.
    pub fn append_evaluation_boundary(
        &mut self,
        at: VirtualTime,
        kind: SchedulerEvaluationBoundaryKind,
    ) -> Result<SchedulerEventLogAppend, SchedulerError> {
        self.event_log.append_evaluation_boundary(at, kind)
    }

    /// Evaluates an event graph over this scheduler's current condition prefix.
    ///
    /// Armed trigger timers are made visible to `Timer` leaves from the
    /// scheduler-owned [`TriggerActionState`], so a timer fires exactly at the
    /// virtual time produced by the `ArmTimer` action that armed it.
    pub fn evaluate_event_graph<O>(
        &self,
        graph: &EventGraph,
        state: &mut EventGraphState,
        oracle: O,
    ) -> EventFirings
    where
        O: ConditionLeafOracle,
    {
        let mut pass = ConditionEvaluationPass::from_log_prefix(
            self.event_log.condition_prefix().clone(),
            oracle,
        )
        .with_timer_fires(self.trigger_actions.armed_timers.clone());
        pass.evaluate_event_graph(graph, state)
    }

    /// Appends deterministic trigger firings as causal event-log entries.
    ///
    /// # Errors
    ///
    /// Returns [`SchedulerError`] when the firings were computed at a different
    /// condition prefix than the scheduler's current prefix, or when appending the
    /// event-log segment would overflow the event-log offsets.
    pub fn append_trigger_firings(
        &mut self,
        firings: &EventFirings,
    ) -> Result<SchedulerEventLogAppend, SchedulerError> {
        self.validate_trigger_firings(firings)?;
        let entries = self.trigger_firing_entries(firings)?;
        self.event_log.append_entries(entries)
    }

    /// Applies deterministic trigger firings and their action effects atomically.
    ///
    /// # Errors
    ///
    /// Returns [`SchedulerError`] when the firings were computed at a different
    /// condition prefix than the scheduler's current prefix, when a timer action
    /// would overflow virtual time, when a node scheduling action references a
    /// node outside the scheduler's world-derived static topology, or when
    /// appending the event-log segment would overflow the event-log offsets.
    pub fn apply_trigger_firings(
        &mut self,
        firings: &EventFirings,
    ) -> Result<SchedulerEventLogAppend, SchedulerError> {
        self.validate_trigger_firings(firings)?;
        let mut entries = self.trigger_firing_entries(firings)?;
        let previous_faults = self.trigger_actions.combined_faults();
        let mut trigger_actions = self.trigger_actions.clone();
        let mut action_entries = Vec::new();
        for firing in firings.iter() {
            let mut path = Vec::new();
            apply_trigger_action(
                &mut trigger_actions,
                self.trigger_static_topology.as_ref(),
                firing,
                firing.action(),
                &mut path,
                &mut action_entries,
            )?;
        }
        let next_faults = trigger_actions.combined_faults();
        let fault_sequence = u64::try_from(trigger_actions.applications.len()).map_err(|_| {
            SchedulerError::BoundaryViolation {
                message: String::from("trigger fault application sequence exceeds u64"),
            }
        })?;
        self.apply_trigger_taxonomy_faults(fault_sequence, &previous_faults, &next_faults)?;
        for application in action_entries {
            let sequence = self.event_log.next_sequence(entries.len())?;
            entries.push(scheduler_event_log_entry(
                sequence,
                application.at,
                SchedulerEventLogPayload::TriggerActionApplied(application),
            ));
        }
        let append = self.event_log.append_entries(entries)?;
        self.trigger_actions = trigger_actions;
        Ok(append)
    }

    /// Applies active trigger-owned network faults to one live directed link.
    ///
    /// Trigger action application owns the deterministic fault set and the
    /// scheduler-owned topology effects, while the concrete [`crucible_device::NetLink`]
    /// fault table is owned by the caller's network device. This bridge reads the
    /// current trigger taxonomy projection for `link_id`, installs the resulting
    /// [`crucible_device::LinkFaults`] on `link`, queues any partition topology
    /// change through the scheduler, and consumes any link latency recompute signal
    /// when the directed edge is still live.
    ///
    /// Pass `restored_edges` when this call follows a heal that may restore edges
    /// previously removed by a partition. For ordinary activation or non-partition
    /// updates, pass an empty vector.
    ///
    /// # Errors
    ///
    /// Returns [`SchedulerError`] when the scheduler rejects a topology or latency
    /// recompute queued by the applied network fault set.
    // crucible-lint: allow rust-allow -- local exception is documented at the allow site.
    #[allow(clippy::too_many_arguments)]
    pub fn apply_trigger_network_faults_to_link(
        &mut self,
        sequence: u64,
        link_id: &LinkId,
        endpoint_a: SchedulerNodeId,
        endpoint_b: SchedulerNodeId,
        link: &mut crucible_device::NetLink,
        direction: NetworkLinkDirection,
        restored_edges: Vec<SchedulerLookaheadEdge>,
    ) -> Result<NetworkFaultApplication, SchedulerError> {
        let combined = self.trigger_actions.combined_faults();
        let faults = combined_network_faults_for_link(
            &combined.network,
            link_id,
            &endpoint_a.node,
            &endpoint_b.node,
        );
        let has_restored_edges = !restored_edges.is_empty();
        let application = if has_restored_edges {
            heal_combined_network_faults_to_scheduler(
                sequence,
                endpoint_a.clone(),
                endpoint_b.clone(),
                link,
                &faults,
                direction,
                restored_edges,
                self,
            )?
        } else {
            apply_combined_network_faults_to_scheduler(
                sequence,
                endpoint_a.clone(),
                endpoint_b.clone(),
                link,
                &faults,
                direction,
                self,
            )?
        };

        let partitioned = faults
            .partition
            .as_ref()
            .is_some_and(|partition| network_direction_is_partitioned(direction, partition));
        if !partitioned && !has_restored_edges {
            let _ = self.schedule_link_latency_recompute(sequence, endpoint_a, endpoint_b, link)?;
        }

        Ok(application)
    }

    fn apply_trigger_taxonomy_faults(
        &mut self,
        sequence: u64,
        previous: &CombinedFaults,
        next: &CombinedFaults,
    ) -> Result<(), SchedulerError> {
        if previous == next {
            return Ok(());
        }

        self.apply_trigger_node_faults(sequence, previous, next)?;
        self.apply_trigger_network_partitions(sequence, previous, next)?;
        self.apply_trigger_device_faults(next)?;
        Ok(())
    }

    fn hydrate_control_fault_schedule_prefix(
        &mut self,
        sequence: Option<u64>,
    ) -> Result<(), SchedulerError> {
        let Some(sequence) = sequence else {
            return Ok(());
        };
        let previous = CombinedFaults::default();
        let next = self.trigger_actions.combined_faults();
        if previous == next {
            return Ok(());
        }

        self.apply_trigger_node_faults(sequence, &previous, &next)?;
        self.hydrate_network_partition_faults(sequence, &next)?;
        self.apply_trigger_device_faults(&next)
    }

    fn hydrate_network_partition_faults(
        &mut self,
        sequence: u64,
        next: &CombinedFaults,
    ) -> Result<(), SchedulerError> {
        if network_partitions(&next.network).is_empty() {
            return Ok(());
        }
        let Some(static_topology) = &self.trigger_static_topology else {
            return Ok(());
        };
        let effective_edges = static_topology
            .lookahead_graph
            .iter()
            .filter(|edge| !world_edge_removed_by_network_faults(edge, &next.network))
            .map(SchedulerLookaheadEdge::from_world_edge)
            .collect::<Vec<_>>();
        let graph = SchedulerLookaheadGraph::from_edges(effective_edges);
        let graph = self.suppress_down_edges(graph);
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
                trigger: SchedulerTopologyChangeTrigger::FaultActivation,
                activation_time: None,
                updates,
            });
        Ok(())
    }

    fn apply_trigger_node_faults(
        &mut self,
        sequence: u64,
        previous: &CombinedFaults,
        next: &CombinedFaults,
    ) -> Result<(), SchedulerError> {
        let mut nodes = previous.node.keys().cloned().collect::<BTreeSet<_>>();
        nodes.extend(next.node.keys().cloned());
        for node in nodes {
            let previous_faults = previous.node.get(&node).cloned().unwrap_or_default();
            let next_faults = next.node.get(&node).cloned().unwrap_or_default();
            let previous_crashed = previous_faults.is_crashed();
            let next_crashed = next_faults.is_crashed();
            if !previous_crashed && next_crashed {
                if let Some(restart) = next_faults.crash_restart {
                    self.apply_node_crash(sequence, &node, restart)?;
                }
            } else if previous_crashed && !next_crashed {
                let _ = self.heal_node_crash(sequence, &node)?;
            }
            self.apply_combined_node_timing_faults(&node, &next_faults)?;
        }
        Ok(())
    }

    fn apply_trigger_network_partitions(
        &mut self,
        sequence: u64,
        previous: &CombinedFaults,
        next: &CombinedFaults,
    ) -> Result<(), SchedulerError> {
        if network_partitions(&previous.network) == network_partitions(&next.network) {
            return Ok(());
        }
        let Some(static_topology) = &self.trigger_static_topology else {
            return Ok(());
        };
        let trigger = if network_partitions(&next.network).is_empty() {
            SchedulerTopologyChangeTrigger::Heal
        } else {
            SchedulerTopologyChangeTrigger::FaultActivation
        };
        let effective_edges = static_topology
            .lookahead_graph
            .iter()
            .filter(|edge| !world_edge_removed_by_network_faults(edge, &next.network))
            .map(SchedulerLookaheadEdge::from_world_edge)
            .collect::<Vec<_>>();
        self.schedule_topology_change(SchedulerTopologyChange::new(
            sequence,
            trigger,
            effective_edges,
        ))
    }

    fn apply_trigger_device_faults(&mut self, next: &CombinedFaults) -> Result<(), SchedulerError> {
        for sub_nodes in self.device_sub_nodes.values_mut() {
            for sub_node in sub_nodes {
                match sub_node.sub_node().kind {
                    SchedulingNodeKind::Disk => {
                        let faults = next.block.get(sub_node.device_id());
                        let table = faults.map_or_else(
                            crucible_device::IoFaults::none,
                            block_faults_from_combined_block,
                        );
                        sub_node.set_io_faults(table);
                    }
                    SchedulingNodeKind::NineP => {
                        let faults = next.ninep.get(sub_node.device_id());
                        let table = faults.map_or_else(
                            crucible_device::IoFaults::none,
                            ninep_faults_from_combined_ninep,
                        );
                        sub_node.set_io_faults(table);
                    }
                    SchedulingNodeKind::Vm
                    | SchedulingNodeKind::Network
                    | SchedulingNodeKind::ControlPlane => {}
                }
            }
        }
        self.refresh_device_horizons()
    }

    fn validate_trigger_firings(&self, firings: &EventFirings) -> Result<(), SchedulerError> {
        let current_point = self.event_log.condition_prefix().point();
        let current_offset = self.event_log_offset();
        if firings.point() != current_point {
            return Err(SchedulerError::BoundaryViolation {
                message: format!(
                    "trigger firings were evaluated at {:?}, but scheduler condition prefix is {:?}",
                    firings.point(),
                    current_point
                ),
            });
        }
        if firings.event_log_offset() != current_offset {
            return Err(SchedulerError::BoundaryViolation {
                message: format!(
                    "trigger firings were evaluated at event-log offset {:?}, but scheduler offset is {:?}",
                    firings.event_log_offset(),
                    current_offset
                ),
            });
        }
        if firings.timer_fires() != &self.trigger_actions.armed_timers {
            return Err(SchedulerError::BoundaryViolation {
                message: String::from(
                    "trigger firings were evaluated with timer state that does not match scheduler trigger action state",
                ),
            });
        }
        Ok(())
    }

    fn trigger_firing_entries(
        &self,
        firings: &EventFirings,
    ) -> Result<Vec<SchedulerEventLogEntry>, SchedulerError> {
        let mut entries = Vec::with_capacity(firings.len());
        for firing in firings.iter() {
            let sequence = self.event_log.next_sequence(entries.len())?;
            entries.push(scheduler_event_log_entry(
                sequence,
                firing.at(),
                SchedulerEventLogPayload::TriggerFired(firing.clone()),
            ));
        }
        Ok(entries)
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

    /// Returns explorer-supplied preemptions applied by completed RESOLVE phases.
    #[must_use]
    pub fn preemption_applications(&self) -> &[SchedulerPreemptionApplication] {
        &self.preemption_applications
    }

    /// Returns topology changes applied at completed scheduler boundaries.
    #[must_use]
    pub fn topology_change_applications(&self) -> &[SchedulerTopologyChangeApplication] {
        &self.topology_change_applications
    }

    /// Returns node crash applications completed by this scheduler.
    #[must_use]
    pub fn node_crash_applications(&self) -> &[SchedulerNodeCrashApplication] {
        &self.node_crash_applications
    }

    /// Returns node heal/restart applications completed by this scheduler.
    #[must_use]
    pub fn node_restart_applications(&self) -> &[SchedulerNodeRestartApplication] {
        &self.node_restart_applications
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

    /// Applies combined node timing faults to a VM scheduler node.
    ///
    /// Slowdown is installed as an anchored counter-to-virtual-time projection
    /// at the node's current counter, preserving continuity on the scheduler
    /// axis. Clock skew is stored only in the node's guest-visible timing
    /// projection. Crash and restart effects are intentionally outside this
    /// timing-only entry point.
    ///
    /// # Errors
    ///
    /// Returns [`SchedulerError::BoundaryViolation`] when `node` does not name a
    /// VM scheduler node in this scheduler, or [`SchedulerError::TimeConversion`]
    /// when the current timing projection cannot be computed.
    pub fn apply_combined_node_timing_faults(
        &mut self,
        node: &NodeId,
        faults: &CombinedNodeFaults,
    ) -> Result<NodeTimingFaults, SchedulerError> {
        let index = self.vm_node_index(node)?;
        let anchor_counter = self.nodes[index].counter;
        let anchor_time = self.node_current_time(&self.nodes[index])?;
        let timing_faults =
            node_timing_faults_from_combined_node(faults, anchor_counter, anchor_time);
        self.nodes[index].timing_faults = timing_faults;
        self.frontier = frontier_for(&self.nodes, self.timeline.shift())?;
        Ok(timing_faults)
    }

    /// Applies a crash fault to a VM scheduler node.
    ///
    /// The crash stops the runtime, removes all incident effective topology
    /// edges, clears exact local wakeups, discards scheduler-owned events whose
    /// producer or consumer is the crashed node, and voids all in-flight device
    /// completions targeting the node. The returned application records the
    /// deterministic discard set used for replay.
    ///
    /// # Errors
    ///
    /// Returns [`SchedulerError::BoundaryViolation`] when `node` does not name a
    /// VM scheduler node or the node is already crashed. Returns
    /// [`SchedulerError::TimeConversion`] when the crash activation time cannot
    /// be projected.
    pub fn apply_node_crash(
        &mut self,
        sequence: u64,
        node: &NodeId,
        restart: RestartPolicy,
    ) -> Result<SchedulerNodeCrashApplication, SchedulerError> {
        let index = self.vm_node_index(node)?;
        if self.node_execution_stopped(&self.nodes[index]) {
            return Err(SchedulerError::BoundaryViolation {
                message: format!("node crash or stop already active for {}", node.name),
            });
        }

        let scheduler_node = self.nodes[index].id.clone();
        let at = self.node_current_time(&self.nodes[index])?;
        let counter = self.nodes[index].counter;
        let previous_activity = self.nodes[index].activity;
        let timing_faults_at_crash = self.nodes[index].timing_faults;
        let checkpoint = self.nodes[index].last_checkpoint.clone();
        let removed_edges = self.incident_effective_edges(&scheduler_node);
        let removed_endpoints = removed_edges
            .iter()
            .map(SchedulerLookaheadEdge::endpoint)
            .collect::<Vec<_>>();
        let discarded_events = self.discard_pending_events_for_node(&scheduler_node);
        let discarded_io = self.discard_device_completions_for_node(node);
        self.preemption_requests
            .retain(|decision| decision.node != *node);
        self.device_horizons.remove(node);

        self.nodes[index].crash = Some(RuntimeNodeCrashState {
            activation_sequence: sequence,
            restart,
            previous_activity,
            counter_at_crash: counter,
            timing_faults_at_crash,
            removed_edges: removed_edges.clone(),
            checkpoint: checkpoint.clone(),
        });
        self.nodes[index].activity = SchedulerNodeActivity::Halted;
        self.nodes[index].exact_local_event = ExactLocalEvent::NoArmedTimer;
        self.nodes[index].vcpu_idle_states.clear();

        if !removed_endpoints.is_empty() {
            self.schedule_topology_change(SchedulerTopologyChange::partition(
                sequence,
                removed_endpoints,
            ))?;
        }
        self.frontier = frontier_for(&self.nodes, self.timeline.shift())?;

        let application = SchedulerNodeCrashApplication {
            sequence,
            node: node.clone(),
            restart,
            at,
            counter,
            previous_activity,
            discarded_events,
            discarded_io,
            removed_edges,
            checkpoint,
        };
        self.node_crash_applications.push(application.clone());
        Ok(application)
    }

    /// Records the current VM node counter as its last checkpoint anchor.
    ///
    /// This scheduler-side anchor is the crash/restart contract needed by
    /// [`RestartPolicy::FromLastCheckpoint`]. Materialized VM/device state lives
    /// in the temporal graph; the scheduler records the counter/time identity
    /// that a checkpoint restore must resume from.
    ///
    /// # Errors
    ///
    /// Returns [`SchedulerError::BoundaryViolation`] when `node` does not name a
    /// VM scheduler node or that node is currently stopped by a crash. Returns
    /// [`SchedulerError::TimeConversion`] when the checkpoint time cannot be
    /// projected.
    pub fn record_node_checkpoint(
        &mut self,
        node: &NodeId,
    ) -> Result<SchedulerNodeCheckpoint, SchedulerError> {
        let index = self.vm_node_index(node)?;
        if self.node_execution_stopped(&self.nodes[index]) {
            return Err(SchedulerError::BoundaryViolation {
                message: format!("cannot checkpoint stopped node {}", node.name),
            });
        }
        let checkpoint = SchedulerNodeCheckpoint {
            node: node.clone(),
            counter: self.nodes[index].counter,
            at: self.node_current_time(&self.nodes[index])?,
        };
        self.nodes[index].last_checkpoint = Some(checkpoint.clone());
        Ok(checkpoint)
    }

    /// Heals an active crash fault and applies the node's restart policy.
    ///
    /// [`RestartPolicy::FromReadyPoint`] reboots the node from counter zero at
    /// the current scheduler frontier. [`RestartPolicy::FromLastCheckpoint`]
    /// resumes from the node's last recorded pre-crash checkpoint. Both policies
    /// re-anchor the node's active timing projection at the current frontier and
    /// queue restoration of the edges removed by the crash.
    /// [`RestartPolicy::StayDown`] records the heal but leaves the node stopped
    /// until a future explicit restart command.
    ///
    /// # Errors
    ///
    /// Returns [`SchedulerError::BoundaryViolation`] when `node` does not name a
    /// VM scheduler node or no crash is active for the node.
    pub fn heal_node_crash(
        &mut self,
        sequence: u64,
        node: &NodeId,
    ) -> Result<SchedulerNodeRestartApplication, SchedulerError> {
        let index = self.vm_node_index(node)?;
        let Some(state) = self.nodes[index].crash.clone() else {
            return Err(SchedulerError::BoundaryViolation {
                message: format!("node crash is not active for {}", node.name),
            });
        };
        if state.restart == RestartPolicy::FromLastCheckpoint && state.checkpoint.is_none() {
            return Err(SchedulerError::BoundaryViolation {
                message: format!(
                    "checkpoint restart requested for {} without a recorded pre-crash checkpoint",
                    node.name
                ),
            });
        }
        let Some(state) = self.nodes[index].crash.take() else {
            return Err(SchedulerError::BoundaryViolation {
                message: format!("node crash is not active for {}", node.name),
            });
        };

        let restart_time = SimInstant {
            nanos: self.frontier.ticks,
        };
        if state.restart == RestartPolicy::StayDown {
            self.nodes[index].stopped_crash = Some(RuntimeNodeStoppedState {
                activation_sequence: state.activation_sequence,
                previous_activity: state.previous_activity,
                timing_faults_at_stop: state.timing_faults_at_crash,
                removed_edges: state.removed_edges,
            });
            let application = SchedulerNodeRestartApplication {
                sequence,
                node: node.clone(),
                restart: state.restart,
                at: restart_time,
                restarted: false,
                counter: self.nodes[index].counter,
                restored_edges: Vec::new(),
                checkpoint: state.checkpoint,
            };
            self.node_restart_applications.push(application.clone());
            return Ok(application);
        }

        let checkpoint = match state.restart {
            RestartPolicy::FromLastCheckpoint => state.checkpoint.clone(),
            RestartPolicy::FromReadyPoint | RestartPolicy::StayDown => state.checkpoint.clone(),
        };
        let counter = match state.restart {
            RestartPolicy::FromReadyPoint => NodeCounter::default(),
            RestartPolicy::FromLastCheckpoint => checkpoint
                .as_ref()
                .map(|checkpoint| checkpoint.counter)
                .ok_or_else(|| SchedulerError::BoundaryViolation {
                    message: format!(
                        "checkpoint restart requested for {} without a recorded pre-crash checkpoint",
                        node.name
                    ),
                })?,
            RestartPolicy::StayDown => state.counter_at_crash,
        };
        let mut timing_faults = state.timing_faults_at_crash;
        timing_faults.anchor_counter = counter;
        timing_faults.anchor_time = restart_time;

        self.nodes[index].counter = counter;
        self.nodes[index].timing_faults = timing_faults;
        self.nodes[index].activity = state.previous_activity;
        self.nodes[index].exact_local_event = ExactLocalEvent::NoArmedTimer;
        self.nodes[index].vcpu_idle_states.clear();
        if state.restart == RestartPolicy::FromReadyPoint {
            self.nodes[index].last_checkpoint = None;
        }

        if !state.removed_edges.is_empty() {
            self.schedule_topology_change(SchedulerTopologyChange::heal(
                sequence,
                state.removed_edges.clone(),
            ))?;
        }
        self.frontier = frontier_for(&self.nodes, self.timeline.shift())?;

        let application = SchedulerNodeRestartApplication {
            sequence,
            node: node.clone(),
            restart: state.restart,
            at: restart_time,
            restarted: true,
            counter,
            restored_edges: state.removed_edges,
            checkpoint,
        };
        self.node_restart_applications.push(application.clone());
        Ok(application)
    }

    /// Explicitly restarts a node left stopped by [`RestartPolicy::StayDown`].
    ///
    /// The restart uses the baked ready-point counter and restores the effective
    /// topology edges that were suppressed while the node was down.
    ///
    /// # Errors
    ///
    /// Returns [`SchedulerError::BoundaryViolation`] when `node` does not name a
    /// VM scheduler node or the node is not waiting in the StayDown stopped
    /// state.
    pub fn restart_stopped_node(
        &mut self,
        sequence: u64,
        node: &NodeId,
    ) -> Result<SchedulerNodeRestartApplication, SchedulerError> {
        let index = self.vm_node_index(node)?;
        let Some(state) = self.nodes[index].stopped_crash.take() else {
            return Err(SchedulerError::BoundaryViolation {
                message: format!("node is not stopped after crash: {}", node.name),
            });
        };

        let restart_time = SimInstant {
            nanos: self.frontier.ticks,
        };
        let counter = NodeCounter::default();
        let mut timing_faults = state.timing_faults_at_stop;
        timing_faults.anchor_counter = counter;
        timing_faults.anchor_time = restart_time;

        self.nodes[index].counter = counter;
        self.nodes[index].timing_faults = timing_faults;
        self.nodes[index].activity = state.previous_activity;
        self.nodes[index].exact_local_event = ExactLocalEvent::NoArmedTimer;
        self.nodes[index].vcpu_idle_states.clear();
        self.nodes[index].last_checkpoint = None;

        if !state.removed_edges.is_empty() {
            self.schedule_topology_change(SchedulerTopologyChange::heal(
                sequence,
                state.removed_edges.clone(),
            ))?;
        }
        self.frontier = frontier_for(&self.nodes, self.timeline.shift())?;

        let application = SchedulerNodeRestartApplication {
            sequence,
            node: node.clone(),
            restart: RestartPolicy::StayDown,
            at: restart_time,
            restarted: true,
            counter,
            restored_edges: state.removed_edges,
            checkpoint: None,
        };
        self.node_restart_applications.push(application.clone());
        Ok(application)
    }

    /// Returns whether a VM node is currently crashed.
    #[must_use]
    pub fn is_node_crashed(&self, node: &NodeId) -> bool {
        self.nodes.iter().any(|runtime| {
            runtime.id.node == *node
                && runtime.id.kind == SchedulingNodeKind::Vm
                && runtime.crash.is_some()
        })
    }

    /// Returns whether a VM node is stopped after a healed StayDown crash.
    #[must_use]
    pub fn is_node_stopped_after_crash(&self, node: &NodeId) -> bool {
        self.nodes.iter().any(|runtime| {
            runtime.id.node == *node
                && runtime.id.kind == SchedulingNodeKind::Vm
                && runtime.stopped_crash.is_some()
        })
    }

    /// Projects one VM node's current counter under active timing faults.
    ///
    /// # Errors
    ///
    /// Returns [`SchedulerError::BoundaryViolation`] when `node` does not name a
    /// VM scheduler node in this scheduler, or [`SchedulerError::TimeConversion`]
    /// when the projection cannot be computed.
    pub fn node_timing_projection(
        &self,
        node: &NodeId,
    ) -> Result<NodeTimingProjection, SchedulerError> {
        let index = self.vm_node_index(node)?;
        self.nodes[index]
            .timing_faults
            .project(self.nodes[index].counter, self.timeline.shift())
            .map_err(SchedulerError::from)
    }

    /// Returns one VM node's guest-visible time under active clock skew.
    ///
    /// # Errors
    ///
    /// Returns [`SchedulerError`] when the node cannot be found or its timing
    /// projection cannot be computed.
    pub fn guest_visible_time_for_node(&self, node: &NodeId) -> Result<SimInstant, SchedulerError> {
        Ok(self.node_timing_projection(node)?.guest_visible_time)
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

        let mut preemptions = self.preemption_requests.clone();
        preemptions.sort_by(preemption_decision_order);
        blockers.extend(
            preemptions
                .into_iter()
                .map(|decision| SchedulerQuiescenceBlocker::PendingPreemption { decision }),
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

        // An in-flight device completion is a future happening ([SCHED-29]); the
        // system is not quiescent while one is undelivered, even when every node
        // is parked `Idle`. Ordered by target `NodeId` (BTreeMap iteration).
        for (target, sub_nodes) in &self.device_sub_nodes {
            if self.is_node_down(target) {
                continue;
            }
            if sub_nodes
                .iter()
                .any(|sub_node| sub_node.next_exact_local_event().is_some())
            {
                blockers.push(SchedulerQuiescenceBlocker::DeviceCompletionInFlight {
                    target: target.clone(),
                });
            }
        }

        for node in &self.nodes {
            blockers.extend(self.vcpu_quiescence_blockers(node));

            match self.effective_node_activity(node) {
                SchedulerNodeActivity::Runnable => {
                    blockers.push(SchedulerQuiescenceBlocker::RunnableNode {
                        node: node.id.clone(),
                    });
                }
                SchedulerNodeActivity::Idle => {}
                SchedulerNodeActivity::Halted | SchedulerNodeActivity::Done => continue,
            }

            let exact_local_event = self.effective_exact_local_event(node)?;
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

    fn vm_node_index(&self, node: &NodeId) -> Result<usize, SchedulerError> {
        self.nodes
            .iter()
            .position(|candidate| {
                candidate.id.node == *node && candidate.id.kind == SchedulingNodeKind::Vm
            })
            .ok_or_else(|| SchedulerError::BoundaryViolation {
                message: format!("node timing fault targets missing VM node: {}", node.name),
            })
    }

    fn node_current_time(&self, node: &RuntimeSchedulerNode) -> Result<SimInstant, SchedulerError> {
        self.node_time_for_counter(node, node.counter)
    }

    fn node_time_for_counter(
        &self,
        node: &RuntimeSchedulerNode,
        counter: NodeCounter,
    ) -> Result<SimInstant, SchedulerError> {
        if node.id.kind == SchedulingNodeKind::Vm {
            node.timing_faults
                .faulted_virtual_time(counter, self.timeline.shift())
                .map_err(SchedulerError::from)
        } else {
            counter
                .to_virtual(self.timeline.shift())
                .map_err(SchedulerError::from)
        }
    }

    fn node_counter_for_time_ceil(
        &self,
        node: &RuntimeSchedulerNode,
        target_time: SimInstant,
    ) -> Result<NodeCounter, SchedulerError> {
        if node.id.kind == SchedulingNodeKind::Vm {
            node.timing_faults
                .counter_for_faulted_virtual_time_ceil(target_time, self.timeline.shift())
                .map_err(SchedulerError::from)
        } else {
            Ok(NodeCounter {
                ticks: self
                    .timeline
                    .max_advance_icount_for_horizon(target_time)?
                    .retired,
            })
        }
    }

    fn node_timeline_key(
        &self,
        node: &RuntimeSchedulerNode,
        sequence: u64,
    ) -> Result<SharedTimelineKey, SchedulerError> {
        Ok(SharedTimelineKey {
            virtual_time: self.node_current_time(node)?,
            node: node.id.clone(),
            sequence,
        })
    }

    fn vm_delivery_time_for_icount(
        &self,
        node: &NodeId,
        icount: Icount,
    ) -> Result<SimInstant, SchedulerError> {
        let index = self.vm_node_index(node)?;
        self.node_time_for_counter(&self.nodes[index], NodeCounter::from_icount(icount))
    }

    fn project_device_decisions_for_vm_time(
        &self,
        node: &NodeId,
        decisions: Vec<Decision>,
    ) -> Result<Vec<Decision>, SchedulerError> {
        decisions
            .into_iter()
            .map(|decision| match decision {
                Decision::FaultFires(mut fault) => {
                    let virtual_time = self.vm_delivery_time_for_icount(
                        node,
                        Icount {
                            retired: fault.at.ticks,
                        },
                    )?;
                    fault.at = VirtualTime {
                        ticks: virtual_time.nanos,
                    };
                    Ok(Decision::FaultFires(fault))
                }
                decision => Ok(decision),
            })
            .collect()
    }

    fn effective_node_activity(&self, node: &RuntimeSchedulerNode) -> SchedulerNodeActivity {
        if self.node_execution_stopped(node) {
            SchedulerNodeActivity::Halted
        } else if node.activity == SchedulerNodeActivity::Idle
            && node
                .vcpu_idle_states
                .iter()
                .any(|state| !state.halted || state.pending_input)
        {
            SchedulerNodeActivity::Runnable
        } else {
            node.activity
        }
    }

    fn is_node_down(&self, node: &NodeId) -> bool {
        self.nodes.iter().any(|runtime| {
            runtime.id.node == *node
                && runtime.id.kind == SchedulingNodeKind::Vm
                && self.node_execution_stopped(runtime)
        })
    }

    fn node_execution_stopped(&self, node: &RuntimeSchedulerNode) -> bool {
        node.crash.is_some() || node.stopped_crash.is_some()
    }

    fn incident_effective_edges(&self, node: &SchedulerNodeId) -> Vec<SchedulerLookaheadEdge> {
        self.effective_topology
            .edges()
            .iter()
            .filter(|edge| &edge.from == node || &edge.to == node)
            .cloned()
            .collect()
    }

    fn discard_pending_events_for_node(
        &mut self,
        node: &SchedulerNodeId,
    ) -> Vec<SchedulerDiscardedEvent> {
        let mut pending = Vec::with_capacity(self.pending_events.len());
        let mut discarded = Vec::new();
        for event in std::mem::take(&mut self.pending_events) {
            if event.key.consumer() == node || event.key.producer() == node {
                let class = scheduled_event_resolve_class(&event);
                discarded.push(SchedulerDiscardedEvent {
                    key: event.key,
                    class,
                });
            } else {
                pending.push(event);
            }
        }
        discarded.sort_by(|left, right| left.key.cmp(&right.key));
        self.pending_events = pending;
        discarded
    }

    fn discard_device_completions_for_node(
        &mut self,
        node: &NodeId,
    ) -> Vec<SchedulerDiscardedIoCompletion> {
        let Some(sub_nodes) = self.device_sub_nodes.get_mut(node) else {
            return Vec::new();
        };
        let mut discarded = Vec::new();
        for sub_node in sub_nodes {
            discarded.extend(sub_node.discard_in_flight());
        }
        discarded.sort_by(|left, right| {
            left.delivery_icount
                .cmp(&right.delivery_icount)
                .then_with(|| left.sub_node.cmp(&right.sub_node))
                .then_with(|| left.source_node.cmp(&right.source_node))
                .then_with(|| left.sequence.cmp(&right.sequence))
                .then_with(|| left.target.cmp(&right.target))
                .then_with(|| left.payload.cmp(&right.payload))
        });
        discarded
    }

    fn suppress_down_edges(&mut self, graph: SchedulerLookaheadGraph) -> SchedulerLookaheadGraph {
        let down = self
            .nodes
            .iter()
            .filter(|node| self.node_execution_stopped(node))
            .map(|node| node.id.clone())
            .collect::<BTreeSet<_>>();
        if down.is_empty() {
            return graph;
        }
        let mut live_edges = Vec::new();
        for edge in graph.edges() {
            if down.contains(&edge.from) || down.contains(&edge.to) {
                self.remember_suppressed_down_edge(edge);
            } else {
                live_edges.push(edge.clone());
            }
        }
        SchedulerLookaheadGraph::from_edges(live_edges)
    }

    fn replace_suppressed_down_edges(&mut self, edges: &[SchedulerLookaheadEdge]) {
        for node in &mut self.nodes {
            if node.crash.is_none() && node.stopped_crash.is_none() {
                continue;
            }
            let incident = canonical_edges_by_endpoint(
                edges
                    .iter()
                    .filter(|edge| edge.from == node.id || edge.to == node.id)
                    .cloned(),
            );
            if let Some(state) = &mut node.crash {
                state.removed_edges = incident.clone();
            }
            if let Some(state) = &mut node.stopped_crash {
                state.removed_edges = incident.clone();
            }
        }
    }

    fn remove_suppressed_down_edges(
        &mut self,
        sequence: u64,
        endpoints: &[SchedulerLookaheadEdgeEndpoint],
    ) {
        let endpoints = endpoints.iter().cloned().collect::<BTreeSet<_>>();
        for node in &mut self.nodes {
            if let Some(state) = &mut node.crash
                && state.activation_sequence != sequence
            {
                state
                    .removed_edges
                    .retain(|edge| !endpoints.contains(&edge.endpoint()));
            }
            if let Some(state) = &mut node.stopped_crash
                && state.activation_sequence != sequence
            {
                state
                    .removed_edges
                    .retain(|edge| !endpoints.contains(&edge.endpoint()));
            }
        }
    }

    fn update_suppressed_down_edges(&mut self, updated_edges: &[SchedulerLookaheadEdge]) {
        let updates = updated_edges
            .iter()
            .map(|edge| (edge.endpoint(), edge.clone()))
            .collect::<BTreeMap<_, _>>();
        for node in &mut self.nodes {
            if let Some(state) = &mut node.crash {
                replace_existing_edges_by_endpoint(&mut state.removed_edges, &updates);
            }
            if let Some(state) = &mut node.stopped_crash {
                replace_existing_edges_by_endpoint(&mut state.removed_edges, &updates);
            }
        }
    }

    fn suppressed_down_edge_exists(&self, endpoint: &SchedulerLookaheadEdgeEndpoint) -> bool {
        let has_endpoint = |edges: &[SchedulerLookaheadEdge]| {
            edges.iter().any(|edge| edge.endpoint() == *endpoint)
        };
        self.nodes.iter().any(|node| {
            node.crash
                .as_ref()
                .is_some_and(|state| has_endpoint(&state.removed_edges))
                || node
                    .stopped_crash
                    .as_ref()
                    .is_some_and(|state| has_endpoint(&state.removed_edges))
        })
    }

    fn remember_suppressed_down_edge(&mut self, edge: &SchedulerLookaheadEdge) {
        for node in &mut self.nodes {
            if node.id != edge.from && node.id != edge.to {
                continue;
            }
            if let Some(state) = &mut node.crash {
                upsert_edge_by_endpoint(&mut state.removed_edges, edge.clone());
            }
            if let Some(state) = &mut node.stopped_crash {
                upsert_edge_by_endpoint(&mut state.removed_edges, edge.clone());
            }
        }
    }

    fn vcpu_quiescence_blockers(
        &self,
        node: &RuntimeSchedulerNode,
    ) -> Vec<SchedulerQuiescenceBlocker> {
        let mut states = node.vcpu_idle_states.clone();
        states.sort();
        let mut blockers = Vec::new();
        for state in states {
            if !state.halted {
                blockers.push(SchedulerQuiescenceBlocker::ActiveVcpu {
                    node: node.id.clone(),
                    vcpu: state.vcpu,
                });
            }
            if let Some(deadline) = state.next_deadline {
                blockers.push(SchedulerQuiescenceBlocker::PendingVcpuTimer {
                    node: node.id.clone(),
                    vcpu: state.vcpu,
                    deadline,
                });
            }
            if state.pending_input {
                blockers.push(SchedulerQuiescenceBlocker::PendingVcpuInput {
                    node: node.id.clone(),
                    vcpu: state.vcpu,
                });
            }
        }
        blockers
    }

    /// Queues a topology change for the next quantum boundary.
    ///
    /// This is the infallible legacy entry point and is signature-compatible with
    /// its prior form. A change armed at an activation virtual time the run has
    /// already passed (`at < frontier`) cannot apply — its activation cap can never
    /// reach an instant below the frontier. Rather than wedge the run with a vague,
    /// repeating per-node "missed exact virtual time" boundary error at apply time,
    /// such a change is still enqueued but the next boundary surfaces a clear,
    /// localized [`SchedulerError::TopologyActivationInPast`] (see
    /// `SingleScheduler::apply_topology_changes_at_boundary`). Callers that can
    /// observe a `Result` should prefer [`SingleScheduler::schedule_topology_change`],
    /// which rejects the same condition at enqueue time.
    pub fn queue_topology_change(&mut self, change: SchedulerTopologyChange) {
        self.topology_changes.push(change);
        self.topology_changes.sort_by(topology_change_order);
    }

    /// Consumes a network-link latency recompute signal and schedules lookahead refresh.
    ///
    /// `crucible-device` owns the live network-link fault table. When a link's
    /// conservative minimum-latency bound changes, [`crucible_device::NetLink`]
    /// raises a one-shot recompute flag. This adapter consumes that flag and, when
    /// set, queues a [`SchedulerTopologyChangeTrigger::LatencyChange`] that updates
    /// exactly the directed scheduler edge `from -> to`, when that edge is still
    /// present, with the link's current
    /// [`crucible_device::NetLink::effective_latency_ns`] value. The existing
    /// topology-change path then applies the new edge set at the next quantum
    /// boundary before PICK, preserving the scheduler's boundary invariant while
    /// making live I/O fault latency changes visible to lookahead ([IO-33]).
    ///
    /// Returns `Ok(true)` when a change was queued and `Ok(false)` when the link
    /// had no pending recompute flag.
    ///
    /// # Errors
    ///
    /// Returns [`SchedulerError::BoundaryViolation`] if the link reports a zero
    /// effective latency or if the directed edge is absent from the current
    /// effective topology or from a topology edge suppressed by a crashed or
    /// stopped node. Returns [`SchedulerError::TopologyActivationInPast`] if
    /// enqueue-time validation observes an impossible activation time, which does
    /// not occur for this no-activation latency-change path but is propagated from
    /// [`SingleScheduler::schedule_topology_change`] for uniformity.
    pub fn schedule_link_latency_recompute(
        &mut self,
        sequence: u64,
        from: SchedulerNodeId,
        to: SchedulerNodeId,
        link: &mut crucible_device::NetLink,
    ) -> Result<bool, SchedulerError> {
        if !link.lookahead_recompute_pending() {
            return Ok(false);
        }
        let effective_latency_ns = link.effective_latency_ns();
        if effective_latency_ns == 0 {
            return Err(SchedulerError::BoundaryViolation {
                message: String::from("network link effective latency must be strictly positive"),
            });
        }
        let endpoint = SchedulerLookaheadEdgeEndpoint::new(from.clone(), to.clone());
        let mut found = false;
        let updated_edge = SchedulerLookaheadEdge::new(
            from.clone(),
            to.clone(),
            SimDuration {
                nanos: effective_latency_ns,
            },
        );
        for edge in self.effective_topology.edges() {
            if edge.endpoint() == endpoint {
                found = true;
                break;
            }
        }
        if !found {
            found = self.suppressed_down_edge_exists(&endpoint);
        }
        if !found {
            return Err(SchedulerError::BoundaryViolation {
                message: format!(
                    "network link latency recompute has no effective topology edge: producer={}:{:?} consumer={}:{:?}",
                    from.node.name, from.kind, to.node.name, to.kind
                ),
            });
        }
        self.schedule_topology_change(SchedulerTopologyChange::update_effective_edges(
            sequence,
            SchedulerTopologyChangeTrigger::LatencyChange,
            vec![updated_edge],
        ))?;
        let consumed = link.take_lookahead_recompute();
        if !consumed {
            return Err(SchedulerError::BoundaryViolation {
                message: String::from("network link recompute flag disappeared before queueing"),
            });
        }
        Ok(true)
    }

    /// Schedules a topology change for the next quantum boundary, validating the
    /// activation time at enqueue time.
    ///
    /// An activation-timed change is enqueued when `at` is at or above the current
    /// frontier and applied at the next quantum boundary once every node has
    /// converged on the activation instant (via the activation cap); it is rejected
    /// at enqueue time when `at` is strictly below the frontier, since the
    /// activation cap could never move a node backwards onto a passed instant.
    /// Changes with no activation time are always enqueued.
    ///
    /// # Errors
    ///
    /// Returns [`SchedulerError::TopologyActivationInPast`] when `change`'s
    /// activation virtual time is strictly below the current frontier.
    pub fn schedule_topology_change(
        &mut self,
        change: SchedulerTopologyChange,
    ) -> Result<(), SchedulerError> {
        if let Some(activation_time) = change.activation_time {
            let frontier = SimInstant {
                nanos: self.frontier.ticks,
            };
            if activation_time < frontier {
                return Err(SchedulerError::TopologyActivationInPast {
                    at: activation_time.nanos,
                    frontier: frontier.nanos,
                });
            }
        }
        self.topology_changes.push(change);
        self.topology_changes.sort_by(topology_change_order);
        Ok(())
    }

    /// Applies queued topology changes at the current scheduler boundary.
    ///
    /// This is the topology-only portion of the authoritative quantum boundary.
    /// Callers that already own a checked event-log boundary can use it after
    /// deterministic trigger actions enqueue crash, heal, partition, or latency
    /// topology changes, without also running PICK/RUN/RESOLVE for a synthetic
    /// scheduler quantum.
    ///
    /// # Errors
    ///
    /// Returns the errors documented by the scheduler topology boundary,
    /// including topology activations armed in the past or inconsistent
    /// activation rendezvous state.
    pub fn apply_queued_topology_changes_at_boundary(&mut self) -> Result<bool, SchedulerError> {
        self.apply_topology_changes_at_boundary()
    }

    fn apply_topology_changes_at_boundary(&mut self) -> Result<bool, SchedulerError> {
        if self.topology_changes.is_empty() {
            return Ok(false);
        }

        let mut changes = std::mem::take(&mut self.topology_changes);
        changes.sort_by(topology_change_order);
        let mut deferred = Vec::new();
        let mut applied = false;

        let frontier = SimInstant {
            nanos: self.frontier.ticks,
        };
        for change in changes {
            if let Some(activation_time) = change.activation_time {
                // Fail loud and localized for a change armed in the past. The
                // infallible `queue_topology_change` entry point cannot reject at
                // enqueue time, so an `at < frontier` change reaches here; surface a
                // clear `TopologyActivationInPast` rather than deferring it forever
                // (a silent wedge) or letting `topology_activation_ready` report a
                // vague per-node skew error.
                if activation_time < frontier {
                    return Err(SchedulerError::TopologyActivationInPast {
                        at: activation_time.nanos,
                        frontier: frontier.nanos,
                    });
                }
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
                    self.replace_suppressed_down_edges(&effective_edges);
                    SchedulerLookaheadGraph::from_edges(effective_edges)
                }
                SchedulerTopologyChangeEffect::RemoveEffectiveEdges(endpoints) => {
                    self.remove_suppressed_down_edges(sequence, &endpoints);
                    self.effective_topology.remove_effective_edges(endpoints)
                }
                SchedulerTopologyChangeEffect::UpdateEffectiveEdges(updated_edges) => {
                    self.update_suppressed_down_edges(&updated_edges);
                    self.effective_topology
                        .update_effective_edges(updated_edges)
                }
                SchedulerTopologyChangeEffect::RestoreEffectiveEdges(restored_edges) => self
                    .effective_topology
                    .restore_effective_edges(restored_edges),
            };
            let graph = self.suppress_down_edges(graph);
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

            let current_time = self.node_current_time(node)?;
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
            preemption_applications: self.preemption_applications.clone(),
            boundary_yields: self.boundary_yields,
        }
    }

    fn is_empty(&self) -> bool {
        self.nodes.is_empty()
    }

    fn reached_time_limit(&self) -> Result<bool, SchedulerError> {
        let mut saw_time_limited_state = false;

        for node in &self.nodes {
            let has_finite_projection = match self.effective_node_activity(node) {
                SchedulerNodeActivity::Runnable => true,
                SchedulerNodeActivity::Idle => self.idle_wake_time(node)?.is_some(),
                SchedulerNodeActivity::Halted | SchedulerNodeActivity::Done => false,
            };
            if has_finite_projection {
                saw_time_limited_state = true;
                let current_time = self.node_current_time(node)?;
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
            let current_time =
                self.node_time_for_counter(&self.nodes[draft.index], draft.before)?;
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
        let selected_runtime_node = &self.nodes[selected_index];
        let target_counter = self
            .node_counter_for_time_ceil(selected_runtime_node, candidate.target_time)?
            .ticks;
        let projected_target = self.node_time_for_counter(
            selected_runtime_node,
            NodeCounter {
                ticks: target_counter,
            },
        )?;
        if !candidate.allow_ceil_past_target && projected_target > candidate.target_time {
            return Err(scheduler_ceiling_overshoot_error(
                &selected_node,
                "target_at",
                candidate.target_time,
                projected_target,
            ));
        }
        if projected_target > candidate.target_time {
            let current_time = self.node_time_for_counter(selected_runtime_node, before)?;
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
            projected_target_time: projected_target,
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
        let current_time = self.node_current_time(node)?;
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
            key: self.node_timeline_key(node, index as u64)?,
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
        match self.effective_node_activity(node) {
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
        let current_time = self.node_current_time(node)?;
        let (effective_time, source) = match self.effective_node_activity(node) {
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

    fn effective_exact_local_event(
        &self,
        node: &RuntimeSchedulerNode,
    ) -> Result<ExactLocalEvent, SchedulerError> {
        let mut exact_local_event = next_exact_local_event(
            &node.id,
            node.exact_local_event.clone(),
            &self.pending_events,
            self.timeline.shift(),
        )?;
        // Fold the device sub-node's in-flight head into the node's exact horizon
        // ([IO-3], [SCHED-10]): the requester is fast-forwarded EXACTLY to its next
        // device completion, with no conservative slack. The term wins only when it
        // is at or before any timer/pending term already selected.
        if let Some(device_time) = self.device_horizons.get(&node.id.node).copied() {
            let device_event = ExactLocalEvent::IoCompletion {
                virtual_time: device_time,
                sub_node: node.id.clone(),
            };
            match exact_local_event.virtual_time() {
                Some(current) if current <= device_time => {}
                _ => exact_local_event = device_event,
            }
        }
        if let Some(vcpu_deadline) = self.earliest_vcpu_deadline(node) {
            match exact_local_event.virtual_time() {
                Some(current) if current <= vcpu_deadline => {}
                _ => {
                    exact_local_event = ExactLocalEvent::TimerDeadline {
                        virtual_time: vcpu_deadline,
                    };
                }
            }
        }
        Ok(exact_local_event)
    }

    fn idle_wake_target(
        &self,
        node: &RuntimeSchedulerNode,
    ) -> Result<Option<IdleWakeTarget>, SchedulerError> {
        let exact_local_event = self.effective_exact_local_event(node)?;
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
                merge_idle_wake_target(&mut target, event_time, false);
            }
        }

        Ok(target)
    }

    fn earliest_vcpu_deadline(&self, node: &RuntimeSchedulerNode) -> Option<SimInstant> {
        node.vcpu_idle_states
            .iter()
            .filter_map(|state| state.next_deadline)
            .min()
    }

    fn advance_window(
        &self,
        node: &RuntimeSchedulerNode,
        current_time: SimInstant,
        rendezvous_cap: Option<SimInstant>,
        topology_activation_cap: Option<SimInstant>,
    ) -> Result<AdvanceWindow, SchedulerError> {
        let exact_local_event = self.effective_exact_local_event(node)?;
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
        // A node bound by the conservative network-lookahead term *derived from a
        // live effective topology* is held at a *moving* cap (`vt(n) +
        // lookahead(n)`), not a genuine local quiescence point: as the global
        // frontier climbs, that bound climbs with it. Parking such a node `Idle` is
        // the freeze defect of RFC-0010 [SCHED-7]/[SCHED-8] — the only
        // `Idle -> Runnable` re-promotion path (`effective_node_activity`) requires
        // a non-halted or pending-input vCPU, so a network/disk sub-node, or a VM
        // whose vCPUs are all halted with no pending input, would never be re-PICKed
        // and the run would freeze. Only a genuine local stop (an exact-local timer
        // / I/O completion / fault, the same set that
        // `horizon_source_allows_ceiling_past_target` admits) is a quiescence
        // point. A node held at the moving network cap keeps no `quiescent_horizon`,
        // so it stays `Runnable` and is re-PICKed for the next interval (iterative
        // conservative-PDES advance, [SCHED-5]).
        //
        // The gate on a non-empty `effective_topology` mirrors the synthetic-
        // liveness exemption: when no live edge set is installed, the per-node
        // `network_lookahead` is a pre-supplied fixed parking point rather than a
        // frontier-tracking CMB bound, so the legacy idle-on-reach behavior is
        // retained.
        let network_bounded = !self.effective_topology.edges().is_empty()
            && horizon.source == SchedulerHorizonSource::NetworkLookahead;
        if network_bounded {
            quiescent_horizon = None;
        }
        if let (Some(horizon_time), Some(activation_time)) =
            (quiescent_horizon, topology_activation_cap)
            && current_time < activation_time
            && horizon_time < activation_time
        {
            quiescent_horizon = None;
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

    fn planned_preemptions_for_run(
        &self,
        node: &SchedulerNodeId,
        current_icount: NodeCounter,
        ceiling: &SchedulerRunCeilingPublication,
    ) -> Result<Vec<PlannedPreemptionApplication>, SchedulerError> {
        let Some(runtime_node) = self.nodes.iter().find(|runtime| &runtime.id == node) else {
            return Err(SchedulerError::BoundaryViolation {
                message: format!(
                    "preemption targets missing scheduler node: {}:{:?}",
                    node.node.name, node.kind
                ),
            });
        };
        let deadline_icount = Icount {
            retired: current_icount.ticks,
        };
        let horizon_icount = Icount {
            retired: ceiling.max_advance_icount,
        };
        let mut decisions = self
            .preemption_requests
            .iter()
            .filter(|decision| decision.node == node.node && node.kind == SchedulingNodeKind::Vm)
            .cloned()
            .collect::<Vec<_>>();
        decisions.sort_by(preemption_decision_order);
        if decisions.len() > 1 {
            return Err(SchedulerError::BoundaryViolation {
                message: format!(
                    "multiple explorer preemptions for one RUN are not supported: node={} count={}",
                    node.node.name,
                    decisions.len()
                ),
            });
        }

        let mut planned = Vec::with_capacity(decisions.len());
        for decision in decisions {
            if decision.at < deadline_icount || decision.at > horizon_icount {
                return Err(SchedulerError::BoundaryViolation {
                    message: format!(
                        "explorer preemption for {} outside authorized window: at={} deadline={} horizon={} ceiling={}",
                        decision.node.name,
                        decision.at.retired,
                        deadline_icount.retired,
                        horizon_icount.retired,
                        ceiling.max_advance_icount
                    ),
                });
            }
            let virtual_time =
                self.node_time_for_counter(runtime_node, NodeCounter::from_icount(decision.at))?;
            planned.push(PlannedPreemptionApplication {
                node: node.clone(),
                decision,
                virtual_time,
                deadline_icount,
                horizon_icount,
                ceiling: ceiling.clone(),
            });
        }

        Ok(planned)
    }

    fn commit_preemption_applications(&mut self, planned: Vec<PlannedPreemptionApplication>) {
        for planned in planned {
            if let Some(index) = self
                .preemption_requests
                .iter()
                .position(|decision| decision == &planned.decision)
            {
                self.preemption_requests.remove(index);
            }
            self.preemption_applications
                .push(SchedulerPreemptionApplication {
                    sequence: self.preemption_applications.len() as u64,
                    quantum: planned.ceiling.quantum,
                    node: planned.node,
                    decision: planned.decision,
                    virtual_time: planned.virtual_time,
                    deadline_icount: planned.deadline_icount,
                    horizon_icount: planned.horizon_icount,
                    ceiling: planned.ceiling,
                });
        }
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

            let current_time = self.node_current_time(node)?;
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

        // Fold each device sub-node's in-flight head into its target node's exact
        // I/O-completion horizon term BEFORE PICK, so a requester's horizon is the
        // device's real next completion ([IO-3], [SCHED-10]).
        self.refresh_device_horizons()?;

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
            let decisions = self.emit_quantum_decisions(&boundary_resolved_events, &[], &[], at)?;
            let emit_boundary = !decisions.is_empty() || topology_recomputed;
            let event_log = self.emit_quantum_event_log(
                &boundary_resolved_events,
                &decisions,
                &[],
                at,
                emit_boundary,
            )?;
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
                event_log_segment_text: event_log.segment_text,
                event_log_segment_hash: event_log.segment_hash,
                event_log_offset: event_log.offset,
                scheduler_quiescence: Some(self.quiescence()?),
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

        let plan_preemptions = plans
            .iter()
            .map(|plan| self.planned_preemptions_for_run(&plan.node, plan.before, &plan.ceiling))
            .collect::<Result<Vec<_>, _>>()?;
        let mut ordered_plans = plans
            .into_iter()
            .zip(plan_preemptions.into_iter())
            .enumerate()
            .map(|(index, (plan, preemptions))| {
                Ok((
                    concurrent_completion_order_key(&plan, &preemptions, self.timeline.shift())?,
                    index,
                    plan,
                    preemptions,
                ))
            })
            .collect::<Result<Vec<_>, SchedulerError>>()?;
        ordered_plans.sort_by(|left, right| {
            left.0
                .ticks
                .cmp(&right.0.ticks)
                .then_with(|| left.1.cmp(&right.1))
        });

        let mut outcomes = Vec::with_capacity(ordered_plans.len());
        for (_, _, plan, preemptions) in ordered_plans {
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
            let frame_deliveries = resolve_due_scheduled_events(
                &mut self.pending_events,
                &selected_node,
                after_time,
                shift,
            )?;

            // Device I/O completions are cross-node events too: drain each
            // targeting sub-node's due completions at the exact delivery icount
            // ([SCHED-29]), minting their sequence from the owned counter on the
            // LIVE RESOLVE path ([SCHED-18]), and append the fault decisions they
            // drew ([SCHED-30]).
            let (device_events, device_decisions) =
                self.resolve_device_completions(&selected_node, after.ticks)?;
            // Order (frame ++ device) deliveries together by the §8.6 key, keeping
            // the control/boundary events prefixed exactly as the no-device path
            // does ([SCHED-33]).
            resolved_events.extend(merge_node_deliveries(frame_deliveries, device_events));

            let decisions = self.emit_quantum_decisions(
                &resolved_events,
                &preemptions,
                &device_decisions,
                after_time,
            )?;
            let event_log = self.emit_quantum_event_log(
                &resolved_events,
                &decisions,
                &preemptions,
                after_time,
                true,
            )?;
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
            self.commit_preemption_applications(preemptions);

            outcomes.push(QuantumOutcome {
                configuration,
                frontier: self.frontier,
                advanced_node: Some(selected_node),
                resolved_events,
                decisions,
                event_log_entries: event_log.entries,
                event_log_segment_bytes: event_log.segment_bytes,
                event_log_segment_text: event_log.segment_text,
                event_log_segment_hash: event_log.segment_hash,
                event_log_offset: event_log.offset,
                scheduler_quiescence: Some(self.quiescence()?),
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

        // Fold each device sub-node's in-flight head into its target node's exact
        // I/O-completion horizon term BEFORE PICK, so the requester's horizon is
        // the device's real next completion ([IO-3], [SCHED-10]).
        self.refresh_device_horizons()?;

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
                    &[],
                    &[],
                    SimInstant {
                        nanos: self.frontier.ticks,
                    },
                )?;
                let emit_boundary = !decisions.is_empty() || topology_recomputed;
                let event_log = self.emit_quantum_event_log(
                    &resolved_events,
                    &decisions,
                    &[],
                    SimInstant {
                        nanos: self.frontier.ticks,
                    },
                    emit_boundary,
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
                    event_log_segment_text: event_log.segment_text,
                    event_log_segment_hash: event_log.segment_hash,
                    event_log_offset: event_log.offset,
                    scheduler_quiescence: Some(self.quiescence()?),
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
        let preemptions =
            self.planned_preemptions_for_run(&selected_node, before, &plan.ceiling)?;
        let (after, after_time, yielded_before_advance) = self.advance_node_after_yield(&plan)?;
        // RESOLVE phase: collect due events for the node that just advanced.
        let shift = self.timeline.shift();
        let frame_deliveries = resolve_due_scheduled_events(
            &mut self.pending_events,
            &selected_node,
            after_time,
            shift,
        )?;

        // Device I/O completions are cross-node events too: drain each targeting
        // sub-node's due completions at the exact delivery icount ([SCHED-29]),
        // minting their sequence from the owned counter on the LIVE RESOLVE path
        // ([SCHED-18]), and append the fault decisions they drew ([SCHED-30]).
        let (device_events, device_decisions) =
            self.resolve_device_completions(&selected_node, after.ticks)?;
        // Order (frame ++ device) deliveries together by the §8.6 key, keeping the
        // control events prefixed exactly as the no-device path does ([SCHED-33]).
        resolved_events.extend(merge_node_deliveries(frame_deliveries, device_events));

        // EMIT phase: convert happenings into decisions and append event-log entries.
        let decisions = self.emit_quantum_decisions(
            &resolved_events,
            &preemptions,
            &device_decisions,
            after_time,
        )?;
        let event_log = self.emit_quantum_event_log(
            &resolved_events,
            &decisions,
            &preemptions,
            after_time,
            true,
        )?;
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
        self.commit_preemption_applications(preemptions);

        Ok(QuantumOutcome {
            configuration,
            frontier: self.frontier,
            advanced_node: Some(selected_node),
            resolved_events,
            decisions,
            event_log_entries: event_log.entries,
            event_log_segment_bytes: event_log.segment_bytes,
            event_log_segment_text: event_log.segment_text,
            event_log_segment_hash: event_log.segment_hash,
            event_log_offset: event_log.offset,
            scheduler_quiescence: Some(self.quiescence()?),
        })
    }

    fn emit_quantum_decisions(
        &mut self,
        resolved_events: &[ScheduledEvent],
        preemptions: &[PlannedPreemptionApplication],
        device_decisions: &[Decision],
        at: SimInstant,
    ) -> Result<Vec<Decision>, SchedulerError> {
        let mut decisions = Vec::new();
        if !resolved_events.is_empty() {
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
            decisions.push(decision);
            let probabilistic =
                resolve_probabilistic_decisions(self.configuration.clone(), resolved_events);
            for decision in &probabilistic.decisions {
                if let Decision::RngDraw(draw) = decision {
                    self.advance_decision_rng_cursor_for(draw.stream.clone());
                }
            }
            decisions.extend(probabilistic.decisions);
        }
        for event in ordered_scheduled_events(resolved_events) {
            let ScheduledEventPayload::Control(operation) = &event.payload else {
                continue;
            };
            if let Some(action) = control_fault_action_for_operation(operation) {
                decisions.push(Decision::ControlFault(ControlFaultDecision {
                    at: event.key.virtual_time(),
                    sequence: operation.sequence,
                    action,
                }));
            }
        }
        // Device I/O completions drew their fault decisions (RngDraw + FaultFires)
        // at COMPUTE and buffered them; they are appended on the LIVE RESOLVE path
        // in delivery order ([SCHED-30]). Each device RngDraw advances the owning
        // stream's decision-RNG cursor exactly as a probabilistic RESOLVE draw does.
        for decision in device_decisions {
            if let Decision::RngDraw(draw) = decision {
                self.advance_decision_rng_cursor_for(draw.stream.clone());
            }
        }
        decisions.extend(device_decisions.iter().cloned());
        decisions.extend(
            preemptions
                .iter()
                .map(|application| Decision::Preemption(application.decision.clone())),
        );
        let preemption_times = preemption_event_times(preemptions);
        scheduler_ordered_decisions(decisions, at, self.timeline.shift(), &preemption_times)
    }

    fn emit_quantum_event_log(
        &mut self,
        resolved_events: &[ScheduledEvent],
        decisions: &[Decision],
        preemptions: &[PlannedPreemptionApplication],
        at: SimInstant,
        emit_boundary: bool,
    ) -> Result<SchedulerEventLogAppend, SchedulerError> {
        let mut payloads = Vec::with_capacity(resolved_events.len() + decisions.len());
        let preemption_times = preemption_event_times(preemptions);

        for event in ordered_scheduled_events(resolved_events) {
            payloads.push((
                event.key.virtual_time(),
                SchedulerEventLogPayload::ResolvedHappening(event.clone()),
            ));
        }
        for decision in decisions {
            payloads.push((
                scheduler_decision_event_log_time(
                    decision,
                    at,
                    self.timeline.shift(),
                    &preemption_times,
                )?,
                SchedulerEventLogPayload::Decision(decision.clone()),
            ));
        }
        payloads.sort_by(|left, right| left.0.ticks.cmp(&right.0.ticks));

        let mut entries = Vec::with_capacity(payloads.len() + 1);
        for (entry_time, payload) in payloads {
            let sequence = self.event_log.next_sequence(entries.len())?;
            entries.push(scheduler_event_log_entry(sequence, entry_time, payload));
        }
        if emit_boundary {
            let sequence = self.event_log.next_sequence(entries.len())?;
            entries.push(scheduler_event_log_entry(
                sequence,
                VirtualTime { ticks: at.nanos },
                SchedulerEventLogPayload::EvaluationBoundary(
                    SchedulerEvaluationBoundaryKind::Quantum,
                ),
            ));
        }

        self.event_log.append_entries(entries)
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
                    control_operation_kind_label(&operation.kind)
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
                        control_operation_kind_label(&operation.kind)
                    ),
                })?;
            if application_delta_quanta > SCHEDULER_CONTROL_RESPONSE_BOUND_QUANTA {
                return Err(SchedulerError::BoundaryViolation {
                    message: format!(
                        "scheduler control operation exceeded quantum response bound: sequence={} kind={} delta={} bound={}",
                        operation.sequence,
                        control_operation_kind_label(&operation.kind),
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
        self.apply_control_faults_at_boundary(&applications)?;
        Ok(SchedulerControlDrain {
            events,
            applications,
        })
    }

    fn apply_control_faults_at_boundary(
        &mut self,
        applications: &[SchedulerControlApplication],
    ) -> Result<(), SchedulerError> {
        let previous_faults = self.trigger_actions.combined_faults();
        let mut trigger_actions = self.trigger_actions.clone();
        let mut fault_sequence = None;
        for application in applications {
            let Some(action) = control_fault_action_for_operation(&application.operation) else {
                continue;
            };
            apply_control_fault_action(&mut trigger_actions, &action);
            fault_sequence = Some(application.sequence);
        }
        let Some(fault_sequence) = fault_sequence else {
            return Ok(());
        };
        let next_faults = trigger_actions.combined_faults();
        self.apply_trigger_taxonomy_faults(fault_sequence, &previous_faults, &next_faults)?;
        self.trigger_actions = trigger_actions;
        Ok(())
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
        let after_time = self.node_time_for_counter(&self.nodes[plan.index], after)?;
        if self.nodes[plan.index]
            .exact_local_event
            .virtual_time()
            .is_some_and(|virtual_time| after_time >= virtual_time)
        {
            self.nodes[plan.index].exact_local_event = ExactLocalEvent::NoArmedTimer;
        }
        for state in &mut self.nodes[plan.index].vcpu_idle_states {
            if state
                .next_deadline
                .is_some_and(|deadline| after_time >= deadline)
            {
                state.next_deadline = None;
            }
        }
        if plan
            .quiescent_horizon
            .is_some_and(|horizon| after_time >= horizon)
        {
            // Don't park `Idle` if this node still owes a later device completion:
            // its next sequential completion is a fresh exact local event it must
            // advance to, so keep it `Runnable` ([SCHED-29]). The next quantum's
            // `refresh_device_horizons` re-activation also covers this; this guard
            // avoids a spurious one-quantum park.
            if self
                .device_completion_due_after(&plan.node, after_time)?
                .is_none()
            {
                self.nodes[plan.index].activity = SchedulerNodeActivity::Idle;
            }
        }

        Ok((after, after_time, true))
    }

    fn stalled_active_node(&self) -> Option<&RuntimeSchedulerNode> {
        self.nodes
            .iter()
            .find(|node| self.effective_node_activity(node) == SchedulerNodeActivity::Runnable)
    }
}

/// Applies combined node timing faults to a scheduler VM node.
///
/// This is the scheduler-facing bridge used by trigger/fault application code:
/// slow faults stretch the VM's counter-to-virtual-time map from the current
/// counter, and clock skew changes only the guest-visible time projection.
///
/// # Errors
///
/// Returns [`SchedulerError`] when the node is absent, is not a VM scheduler
/// node, or its current timing projection cannot be computed.
pub fn apply_combined_node_timing_faults_to_scheduler(
    scheduler: &mut SingleScheduler,
    node: &NodeId,
    faults: &CombinedNodeFaults,
) -> Result<NodeTimingFaults, SchedulerError> {
    scheduler.apply_combined_node_timing_faults(node, faults)
}

/// Applies the crash component of combined node faults to a scheduler VM node.
///
/// Returns `Ok(None)` when the combined fault set contains no active crash.
///
/// # Errors
///
/// Returns [`SchedulerError`] when the crash target cannot be applied by
/// [`SingleScheduler::apply_node_crash`].
pub fn apply_combined_node_crash_to_scheduler(
    scheduler: &mut SingleScheduler,
    sequence: u64,
    node: &NodeId,
    faults: &CombinedNodeFaults,
) -> Result<Option<SchedulerNodeCrashApplication>, SchedulerError> {
    faults
        .crash_restart
        .map(|restart| scheduler.apply_node_crash(sequence, node, restart))
        .transpose()
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

    fn apply_control_at_boundary(
        &mut self,
        control: Vec<ControlOperation>,
    ) -> Result<Vec<SchedulerEventLogEntry>, SchedulerError> {
        self.admit_control_at_boundary(control);
        let SchedulerControlDrain {
            events,
            applications,
        } = self.drain_control_events()?;
        let at = SimInstant {
            nanos: self.frontier.ticks,
        };
        let event_log = self.emit_quantum_event_log(&events, &[], &[], at, false)?;
        self.commit_control_applications(applications);
        self.yield_to_control_inbox();
        Ok(event_log.entries)
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
    timing_faults: NodeTimingFaults,
    last_checkpoint: Option<SchedulerNodeCheckpoint>,
    crash: Option<RuntimeNodeCrashState>,
    stopped_crash: Option<RuntimeNodeStoppedState>,
    activity: SchedulerNodeActivity,
    network_lookahead: NetworkLookahead,
    exact_local_event: ExactLocalEvent,
    vcpu_idle_states: Vec<SchedulerVcpuIdleState>,
}

#[derive(Clone, Debug, PartialEq, Eq)]
struct RuntimeNodeCrashState {
    activation_sequence: u64,
    restart: RestartPolicy,
    previous_activity: SchedulerNodeActivity,
    counter_at_crash: NodeCounter,
    timing_faults_at_crash: NodeTimingFaults,
    removed_edges: Vec<SchedulerLookaheadEdge>,
    checkpoint: Option<SchedulerNodeCheckpoint>,
}

#[derive(Clone, Debug, PartialEq, Eq)]
struct RuntimeNodeStoppedState {
    activation_sequence: u64,
    previous_activity: SchedulerNodeActivity,
    timing_faults_at_stop: NodeTimingFaults,
    removed_edges: Vec<SchedulerLookaheadEdge>,
}

impl From<SchedulerScenarioNode> for RuntimeSchedulerNode {
    fn from(node: SchedulerScenarioNode) -> Self {
        Self {
            id: node.id,
            counter: node.counter,
            timing_faults: NodeTimingFaults::default(),
            last_checkpoint: None,
            crash: None,
            stopped_crash: None,
            activity: node.activity,
            network_lookahead: node.network_lookahead,
            exact_local_event: node.exact_local_event,
            vcpu_idle_states: Vec::new(),
        }
    }
}

fn assign_vcpu_idle_snapshots(
    nodes: &mut [RuntimeSchedulerNode],
    snapshots: &mut Vec<SchedulerNodeVcpuIdleSnapshot>,
    run_subdivision_policies: &[SchedulerRunSubdivisionPolicy],
) -> Result<(), SchedulerError> {
    snapshots.sort();
    for pair in snapshots.windows(2) {
        if pair[0].node == pair[1].node {
            return Err(SchedulerError::BoundaryViolation {
                message: format!(
                    "scheduler vCPU idle snapshot repeated for {}:{:?}",
                    pair[0].node.node.name, pair[0].node.kind
                ),
            });
        }
    }

    for snapshot in snapshots {
        validate_vcpu_idle_snapshot(&snapshot.node, snapshot.vcpu_count, &mut snapshot.vcpus)?;
        if let Some(policy) = run_subdivision_policies
            .iter()
            .find(|policy| policy.node == snapshot.node)
            && policy.vcpu_count != snapshot.vcpu_count
        {
            return Err(SchedulerError::BoundaryViolation {
                message: format!(
                    "scheduler vCPU idle snapshot count for {}:{:?} does not match RR policy: snapshot={} policy={}",
                    snapshot.node.node.name,
                    snapshot.node.kind,
                    snapshot.vcpu_count,
                    policy.vcpu_count
                ),
            });
        }
        let Some(node) = nodes.iter_mut().find(|node| node.id == snapshot.node) else {
            return Err(SchedulerError::BoundaryViolation {
                message: format!(
                    "scheduler vCPU idle snapshot references missing node: {}:{:?}",
                    snapshot.node.node.name, snapshot.node.kind
                ),
            });
        };
        node.vcpu_idle_states = snapshot.vcpus.clone();
    }

    Ok(())
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

fn merge_idle_wake_target(
    target: &mut Option<IdleWakeTarget>,
    wake_time: SimInstant,
    allow_ceil_past_target: bool,
) {
    match target {
        Some(current) if current.wake_time < wake_time => {}
        Some(current) if current.wake_time == wake_time => {
            current.allow_ceil_past_target &= allow_ceil_past_target;
        }
        _ => {
            *target = Some(IdleWakeTarget {
                wake_time,
                allow_ceil_past_target,
            });
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
struct AdvancePlan {
    index: usize,
    node: SchedulerNodeId,
    before: NodeCounter,
    target_counter: u64,
    projected_target_time: SimInstant,
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
    projected_target_time: SimInstant,
    quiescent_horizon: Option<SimInstant>,
}

#[derive(Clone, Debug, PartialEq, Eq)]
struct PlannedRunSubdivision {
    policy: SchedulerRunSubdivisionPolicy,
    slices: Vec<SchedulerRunSubdivisionSlice>,
}

#[derive(Clone, Debug, PartialEq, Eq)]
struct PlannedPreemptionApplication {
    node: SchedulerNodeId,
    decision: PreemptionDecision,
    virtual_time: SimInstant,
    deadline_icount: Icount,
    horizon_icount: Icount,
    ceiling: SchedulerRunCeilingPublication,
}

fn preemption_event_times(
    preemptions: &[PlannedPreemptionApplication],
) -> Vec<(PreemptionDecision, SimInstant)> {
    preemptions
        .iter()
        .map(|application| (application.decision.clone(), application.virtual_time))
        .collect()
}

fn concurrent_completion_order_key(
    plan: &AdvancePlan,
    preemptions: &[PlannedPreemptionApplication],
    _shift: Shift,
) -> Result<VirtualTime, SchedulerError> {
    let mut key = plan.projected_target_time;
    for preemption in preemptions {
        key = min_instant(key, preemption.virtual_time);
    }
    Ok(VirtualTime { ticks: key.nanos })
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
            projected_target_time: draft.projected_target_time,
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
    let mut crashed_frontier = None;

    for node in nodes {
        let virtual_time = if node.id.kind == SchedulingNodeKind::Vm {
            node.timing_faults
                .faulted_virtual_time(node.counter, shift)?
        } else {
            node.counter.to_virtual(shift)?
        };
        if node.crash.is_some() || node.stopped_crash.is_some() {
            crashed_frontier = Some(match crashed_frontier {
                Some(current) => min_instant(current, virtual_time),
                None => virtual_time,
            });
            continue;
        }
        frontier = Some(match frontier {
            Some(current) => min_instant(current, virtual_time),
            None => virtual_time,
        });
    }

    Ok(VirtualTime {
        ticks: frontier
            .or(crashed_frontier)
            .unwrap_or(SimInstant::EPOCH)
            .nanos,
    })
}

fn min_instant(left: SimInstant, right: SimInstant) -> SimInstant {
    if left <= right { left } else { right }
}

fn upsert_edge_by_endpoint(edges: &mut Vec<SchedulerLookaheadEdge>, edge: SchedulerLookaheadEdge) {
    let endpoint = edge.endpoint();
    if let Some(index) = edges
        .iter()
        .position(|candidate| candidate.endpoint() == endpoint)
    {
        edges[index] = edge;
    } else {
        edges.push(edge);
    }
    edges.sort();
    edges.dedup();
}

fn canonical_edges_by_endpoint<I>(edges: I) -> Vec<SchedulerLookaheadEdge>
where
    I: IntoIterator<Item = SchedulerLookaheadEdge>,
{
    let mut canonical = Vec::new();
    for edge in edges {
        upsert_edge_by_endpoint(&mut canonical, edge);
    }
    canonical
}

fn replace_existing_edges_by_endpoint(
    edges: &mut Vec<SchedulerLookaheadEdge>,
    updates: &BTreeMap<SchedulerLookaheadEdgeEndpoint, SchedulerLookaheadEdge>,
) {
    for edge in edges.iter_mut() {
        if let Some(updated) = updates.get(&edge.endpoint()) {
            *edge = updated.clone();
        }
    }
    edges.sort();
    edges.dedup();
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
    /// A topology change was armed at an activation virtual time the run has
    /// already passed.
    ///
    /// The activation cap can never reach `at` because the frontier has already
    /// advanced beyond it, so the change could never apply. Rejected at enqueue
    /// time by [`SingleScheduler::schedule_topology_change`] rather than wedging
    /// the run with a repeating boundary error at apply time.
    TopologyActivationInPast {
        /// The armed activation virtual time, in ticks.
        at: u64,
        /// The current frontier virtual time, in ticks.
        frontier: u64,
    },
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
            Self::TopologyActivationInPast { at, frontier } => write!(
                f,
                "topology change armed at activation virtual time {at} is in the past: \
                 frontier already at {frontier}"
            ),
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
// crucible-lint: allow panic-shortcut -- test assertions use panic shortcuts for fixture setup and failure localization.
#[allow(clippy::expect_used)]
mod tests {
    use super::*;
    use crate::{RngDecision, ScenarioDef, step};

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
                    event_log_segment_text: String::new(),
                    event_log_segment_hash: None,
                    event_log_offset: EventLogOffset::default(),
                    scheduler_quiescence: None,
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
    fn backend_quantum_loop_routes_gdbstub_to_wrapped_backend() {
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
                    event_log_segment_text: String::new(),
                    event_log_segment_hash: None,
                    event_log_offset: EventLogOffset::default(),
                    scheduler_quiescence: None,
                })
            }
        }

        #[derive(Default)]
        struct GdbBackend {
            opened: Vec<(NodeId, String)>,
        }

        impl SimulationBackend for GdbBackend {
            fn step_to(
                &mut self,
                _ceiling: VirtualTime,
            ) -> Result<crate::StepObservation, BackendError> {
                Err(BackendError::NotImplemented {
                    operation: "step_to",
                })
            }

            fn apply(
                &mut self,
                _effect: &crate::BackendEffect,
                _at: VirtualTime,
            ) -> Result<(), BackendError> {
                Err(BackendError::NotImplemented { operation: "apply" })
            }

            fn snapshot(&mut self) -> Result<crate::BackendSnapshot, BackendError> {
                Err(BackendError::NotImplemented {
                    operation: "snapshot",
                })
            }

            fn restore(&mut self, _snapshot: &crate::BackendSnapshot) -> Result<(), BackendError> {
                Err(BackendError::NotImplemented {
                    operation: "restore",
                })
            }

            fn now(&self) -> VirtualTime {
                VirtualTime::default()
            }

            fn fingerprint(
                &mut self,
                _node: NodeId,
            ) -> Result<crate::FingerprintSample, BackendError> {
                Err(BackendError::NotImplemented {
                    operation: "fingerprint",
                })
            }

            fn open_gdbstub(
                &mut self,
                node: NodeId,
                listen: GdbListen,
            ) -> Result<GdbAttachInfo, BackendError> {
                self.opened.push((node.clone(), listen.as_str().to_owned()));
                GdbAttachInfo::new(node, "tcp:127.0.0.1:9001", listen)
            }

            fn shutdown(&mut self) -> Result<(), BackendError> {
                Ok(())
            }
        }

        let mut adapter = BackendQuantumLoop::new(StubLoop, GdbBackend::default());
        let info = adapter
            .open_gdbstub(
                NodeId {
                    name: String::from("vm-a"),
                },
                GdbListen::new("127.0.0.1:9000")
                    .unwrap_or_else(|error| panic!("test listen should be stable: {error}")),
            )
            .unwrap_or_else(|error| panic!("backend adapter should route gdbstub attach: {error}"));

        assert_eq!(info.qemu_endpoint, "tcp:127.0.0.1:9001");
        assert_eq!(
            adapter.backend().opened,
            vec![(
                NodeId {
                    name: String::from("vm-a"),
                },
                String::from("127.0.0.1:9000"),
            )]
        );
    }

    #[test]
    fn event_log_append_rejects_class_catalog_mismatch() {
        let mut entry = scheduler_event_log_entry(
            0,
            VirtualTime { ticks: 0 },
            SchedulerEventLogPayload::Decision(Decision::RngDraw(RngDecision {
                stream: RngStreamId::from_name("class-catalog-mismatch"),
                value: 17,
            })),
        );
        entry.class = SchedulerEventLogClass::Observational;

        let error = EventLog::new()
            .append_entries(vec![entry])
            .expect_err("append must reject class/catalog mismatches");

        assert!(matches!(
            error,
            SchedulerError::BoundaryViolation { message }
                if message.contains("class observational does not match catalog class causal")
                    && message.contains("payload kind rng_draw")
        ));
    }

    #[test]
    fn event_log_append_rejects_typed_kind_catalog_drift() {
        let mut entry = scheduler_event_log_entry(
            0,
            VirtualTime { ticks: 0 },
            SchedulerEventLogPayload::Decision(Decision::RngDraw(RngDecision {
                stream: RngStreamId::from_name("typed-kind-catalog-drift"),
                value: 23,
            })),
        );
        entry.event_payload =
            EventPayload::new("diagnostic", entry.event_payload.attributes().clone());

        let error = EventLog::new()
            .append_entries(vec![entry])
            .expect_err("append must reject typed payload kind/catalog drift");

        assert!(matches!(
            error,
            SchedulerError::BoundaryViolation { message }
                if message.contains("class causal does not match catalog class observational")
                    && message.contains("payload kind diagnostic")
        ));
    }

    #[test]
    fn event_log_append_rejects_unknown_typed_kind() {
        let mut entry = scheduler_event_log_entry(
            0,
            VirtualTime { ticks: 0 },
            SchedulerEventLogPayload::Decision(Decision::RngDraw(RngDecision {
                stream: RngStreamId::from_name("unknown-typed-kind"),
                value: 31,
            })),
        );
        entry.event_payload = EventPayload::new(
            "unregistered_kind",
            entry.event_payload.attributes().clone(),
        );

        let error = EventLog::new()
            .append_entries(vec![entry])
            .expect_err("append must reject unknown typed payload kinds");

        assert!(matches!(
            error,
            SchedulerError::BoundaryViolation { message }
                if message.contains("payload kind unregistered_kind is not in the event-kind catalog")
        ));
    }

    #[test]
    fn event_log_segment_binary_round_trips_to_same_bytes() {
        let previous_prefix = scheduler_event_log_empty_prefix();
        let entry = scheduler_event_log_entry(
            0,
            VirtualTime { ticks: 9 },
            SchedulerEventLogPayload::Decision(Decision::RngDraw(RngDecision {
                stream: RngStreamId::from_name("segment-round-trip"),
                value: 41,
            })),
        );
        let entries = vec![entry];
        let segment = scheduler_event_log_segment_material(previous_prefix, &entries);
        let bytes = segment.encode();

        let decoded = decode_scheduler_event_log_segment(&bytes)
            .unwrap_or_else(|error| panic!("segment should decode: {error:?}"));

        assert_eq!(decoded, segment);
        assert_eq!(decoded.encode(), bytes);
        assert_eq!(decoded.text_view(), segment.text_view());
        assert!(decoded.text_view().contains("entry.payload.kind=rng_draw"));
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
            event_log_segment_text: String::new(),
            event_log_segment_hash: None,
            event_log_offset: EventLogOffset::default(),
            scheduler_quiescence: None,
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
    fn search_frontier_choices_from_scheduled_events_captures_probabilistic_fault_branches() {
        let configuration = Configuration::genesis(ScenarioDef::from_canonical_material(
            "crucible.test.scheduler.search-frontier",
            "scenario=probabilistic-fault",
        ));
        let consumer = scheduler_node("vm-a", SchedulingNodeKind::Vm);
        let producer = scheduler_node("control", SchedulingNodeKind::ControlPlane);
        let fault = FaultId {
            name: String::from("packet-loss"),
        };
        let event = probabilistic_fault_event(13, &consumer, &producer, 0, fault.clone());

        let choices = search_frontier_choices_from_scheduled_events(configuration, &[event]);
        let outcomes = choices
            .decisions()
            .iter()
            .map(|decision| match decision {
                Decision::FaultFires(fired) if fired.fault == fault => fired.fired,
                other => panic!("unexpected search frontier decision: {other:?}"),
            })
            .collect::<BTreeSet<_>>();

        assert_eq!(choices.decisions().len(), 2);
        assert!(choices.choices().iter().all(|choice| {
            matches!(
                choice.decisions(),
                [Decision::RngDraw(_), Decision::FaultFires(_)]
            )
        }));
        assert_eq!(outcomes, BTreeSet::from([false, true]));
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

    fn probabilistic_fault_event(
        virtual_time: u64,
        consumer: &SchedulerNodeId,
        producer: &SchedulerNodeId,
        sequence: u64,
        fault: FaultId,
    ) -> ScheduledEvent {
        ScheduledEvent {
            key: event_key(virtual_time, consumer, producer, sequence),
            payload: ScheduledEventPayload::ProbabilisticFault(SchedulerResolveFaultChoice {
                fault,
                stream: RngStreamId::from_name("test-probabilistic-fault"),
                rate: FaultRateBasisPoints::from_basis_points(5_000)
                    .unwrap_or_else(|error| panic!("test rate should be valid: {error}")),
            }),
        }
    }

    /// Builds a fault-free disk scheduling sub-node targeting VM node `target`,
    /// with the given `(request_icount, count)` reads pre-submitted.
    fn disk_with_reads(
        target: &str,
        device_name: &str,
        reads: &[(u64, u32)],
    ) -> crate::device_subnode::DeviceSchedulingSubNode {
        use crucible_device::{BaseImage, BlockDevice, BlockLatency, BlockRequest, IoCore};

        let core = match IoCore::new(0, 1, 16, 16) {
            Ok(core) => core,
            Err(error) => panic!("io core should construct: {error}"),
        };
        let block = BlockDevice::new(
            core,
            BaseImage::new(vec![0x5a; 4096]),
            BlockLatency::default(),
        );
        let mut sub_node = crate::device_subnode::DeviceSchedulingSubNode::new(
            scheduler_node(device_name, SchedulingNodeKind::Disk),
            NodeId {
                name: target.to_string(),
            },
            crate::DeviceId {
                name: device_name.to_string(),
            },
            block,
            crate::Seed::from_u64(0x0d15_c0de),
        );
        for (index, (request_icount, count)) in reads.iter().enumerate() {
            let request_id = u32::try_from(index + 1).unwrap_or(u32::MAX);
            if let Err(error) =
                sub_node.submit(*request_icount, &BlockRequest::read(request_id, 0, *count))
            {
                panic!("disk submit should succeed: {error}");
            }
        }
        sub_node
    }

    #[test]
    fn resolve_device_completions_stamps_each_completion_at_its_exact_icount() {
        // The integration capstone ([SCHED-29], [IO-2]): two sequential disk reads
        // resolved at a single consumer frontier above the head completion are each
        // made visible at their OWN exact delivery icount, in canonical order — not
        // collapsed onto the consumer frontier.
        let mut scheduler = test_scheduler(
            vec![test_scenario_node(
                "a",
                0,
                SchedulerNodeActivity::Runnable,
                NetworkLookahead::Infinite,
                ExactLocalEvent::NoArmedTimer,
            )],
            Vec::new(),
        );
        scheduler =
            scheduler.with_device_sub_node(disk_with_reads("a", "disk-a", &[(0, 8), (2000, 8)]));

        assert!(
            scheduler.has_undelivered_device_completion(),
            "submitted reads must leave completions in flight"
        );

        let node = scheduler_node("a", SchedulingNodeKind::Vm);
        let (events, _decisions) = match scheduler.resolve_device_completions(&node, 3008) {
            Ok(resolved) => resolved,
            Err(error) => panic!("resolve should succeed: {error}"),
        };
        let stamped: Vec<u64> = events
            .iter()
            .map(|event| event.key.virtual_time().ticks)
            .collect();

        assert_eq!(
            stamped,
            vec![1008, 3008],
            "each completion is stamped at its own exact delivery icount"
        );
        assert!(
            !scheduler.has_undelivered_device_completion(),
            "both completions must be drained after RESOLVE"
        );
    }

    #[test]
    fn refresh_device_horizons_folds_the_inflight_head_into_the_node_horizon() {
        // [IO-3]/[SCHED-10]: the device sub-node's in-flight head delivery icount
        // becomes the owning node's exact I/O-completion horizon term (a horizon
        // TERM, not a deliverable pending event — delivery stays on the RESOLVE
        // path so it is never double-counted). A second refresh is idempotent.
        let mut scheduler = test_scheduler(
            vec![test_scenario_node(
                "a",
                0,
                SchedulerNodeActivity::Idle,
                NetworkLookahead::Infinite,
                ExactLocalEvent::NoArmedTimer,
            )],
            Vec::new(),
        );
        scheduler = scheduler.with_device_sub_node(disk_with_reads("a", "disk-a", &[(0, 8)]));

        scheduler
            .refresh_device_horizons()
            .unwrap_or_else(|error| panic!("refresh should succeed: {error}"));

        // No deliverable event was injected into the pending-event queue.
        assert!(
            !scheduler
                .pending_events
                .iter()
                .any(|event| matches!(event.payload, ScheduledEventPayload::IoCompletion(_))),
            "refresh must not inject a deliverable IoCompletion event"
        );

        // The in-flight head bounds the node's effective exact local event.
        let node_a = scheduler
            .nodes
            .iter()
            .find(|runtime| runtime.id.node.name == "a")
            .unwrap_or_else(|| panic!("node a should exist"));
        let exact = scheduler
            .effective_exact_local_event(node_a)
            .unwrap_or_else(|error| panic!("effective horizon should compute: {error}"));
        assert!(
            matches!(
                exact,
                ExactLocalEvent::IoCompletion { virtual_time, .. } if virtual_time.nanos == 1008
            ),
            "the in-flight head (icount 1008) must bound the node horizon, got {exact:?}"
        );

        // The idle requester is re-activated so it advances to the completion.
        assert!(
            scheduler
                .nodes
                .iter()
                .any(|runtime| runtime.id.node.name == "a"
                    && runtime.activity == SchedulerNodeActivity::Runnable),
            "an idle requester that owes a completion must be re-activated"
        );

        // A second refresh recomputes the same single horizon term (idempotent).
        scheduler
            .refresh_device_horizons()
            .unwrap_or_else(|error| panic!("second refresh should succeed: {error}"));
        assert_eq!(
            scheduler.device_horizons.len(),
            1,
            "refresh must be idempotent and record exactly one horizon term"
        );
    }

    #[test]
    fn device_completion_flows_through_live_drive_quantum_at_exact_icount() {
        // ITEM 1 teeth: a device completion submitted to a sub-node is delivered
        // through the LIVE `drive_quantum` (not the building blocks) at EXACTLY its
        // delivery icount ([SCHED-29], [IO-2]). The device horizon caps the
        // requester's advance so it is fast-forwarded to exactly the completion.
        // A time limit comfortably past the completion icount (1008) so the
        // requester can advance to it; budget large enough to reach it.
        let scenario = SchedulerLivenessScenario::from_canonical_material(
            "test-device-live-drive",
            shift(0),
            4_096,
            SimInstant { nanos: 4_096 },
            vec![test_scenario_node(
                "a",
                0,
                SchedulerNodeActivity::Runnable,
                NetworkLookahead::Infinite,
                ExactLocalEvent::NoArmedTimer,
            )],
            Vec::new(),
        );
        let mut scheduler = SingleScheduler::new(scenario)
            .unwrap_or_else(|error| panic!("scheduler should build: {error}"));
        scheduler = scheduler.with_device_sub_node(disk_with_reads("a", "disk-a", &[(0, 8)]));

        // Drive quanta until the run quiesces, recording the icount at which the
        // IoCompletion was resolved through the LIVE loop.
        let mut delivered = None;
        for _ in 0..16 {
            let outcome = scheduler
                .drive_quantum(QuantumRequest {
                    configuration: scheduler.configuration().clone(),
                    control: Vec::new(),
                })
                .unwrap_or_else(|error| panic!("drive_quantum should succeed: {error}"));
            if let Some(event) = outcome
                .resolved_events
                .iter()
                .find(|event| matches!(event.payload, ScheduledEventPayload::IoCompletion(_)))
            {
                delivered = Some(event.key.virtual_time().ticks);
            }
            if scheduler
                .quiescence()
                .unwrap_or_else(|error| panic!("quiescence should compute: {error}"))
                .is_quiescent()
            {
                break;
            }
        }

        assert_eq!(
            delivered,
            Some(1008),
            "the live loop must deliver the completion at its EXACT delivery icount"
        );
        // Once delivered, nothing remains in flight and the system quiesces.
        assert!(
            !scheduler.has_undelivered_device_completion(),
            "no device completion may remain in flight after delivery"
        );
        assert!(
            scheduler
                .quiescence()
                .unwrap_or_else(|error| panic!("quiescence should compute: {error}"))
                .is_quiescent(),
            "the run must quiesce once the completion has been delivered"
        );
    }

    #[test]
    fn broken_device_delivery_stamp_diverges_proving_gate_falsifiability() {
        // The falsifiability proof for the exact-icount property ([IO-2], [DET-19]).
        // Driving PRODUCTION `resolve_device_completions` at a frontier ABOVE the
        // head completion (the one configuration where exact and frontier provably
        // differ), the exact path stamps each completion at its OWN icount while the
        // freeze-time bug stamps BOTH at the shared consumer frontier — so the
        // resolved-icount vector diverges and a determinism gate would go red.
        let resolve_at_frontier = |broken: bool| -> Vec<u64> {
            let mut scheduler = test_scheduler(
                vec![test_scenario_node(
                    "a",
                    0,
                    SchedulerNodeActivity::Runnable,
                    NetworkLookahead::Infinite,
                    ExactLocalEvent::NoArmedTimer,
                )],
                Vec::new(),
            );
            scheduler = scheduler.with_device_sub_node(disk_with_reads(
                "a",
                "disk-a",
                &[(0, 8), (2000, 8)],
            ));
            if broken {
                scheduler = scheduler.with_broken_device_delivery_stamp();
            }
            let node = scheduler_node("a", SchedulingNodeKind::Vm);
            let (events, _decisions) = scheduler
                .resolve_device_completions(&node, 3008)
                .unwrap_or_else(|error| panic!("resolve should succeed: {error}"));
            events
                .iter()
                .map(|event| event.key.virtual_time().ticks)
                .collect()
        };

        assert_eq!(
            resolve_at_frontier(false),
            vec![1008, 3008],
            "exact stamps are each completion's own delivery icount"
        );
        assert_eq!(
            resolve_at_frontier(true),
            vec![3008, 3008],
            "the freeze-time bug collapses both onto the consumer frontier"
        );
        assert_ne!(
            resolve_at_frontier(false),
            resolve_at_frontier(true),
            "exact delivery must be distinguishable from frontier delivery"
        );
    }
}
