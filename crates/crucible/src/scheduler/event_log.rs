//! Quantum-loop contracts plus canonical scheduler event-log storage and projections.

use super::*;
mod backend_loop;
mod observation_append;
pub use backend_loop::BackendQuantumLoop;

/// Terminal verdict emitted by a scenario trigger at a quantum boundary.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum QuantumTerminalVerdict {
    /// The scenario's trigger graph reached its passing condition.
    Passed,
    /// The trigger graph produced one or more deterministic violations.
    Failed(Vec<String>),
}

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

    /// Returns the selected node's exact backend counter ceiling.
    ///
    /// The global frontier is expressed on the shared virtual timeline and is
    /// not generally interchangeable with a node-local retired-instruction
    /// counter. Pure and legacy loops inherit the frontier default; schedulers
    /// with an explicit RUN plan override this with the selected node's exact
    /// post-RUN counter.
    ///
    /// # Errors
    ///
    /// Returns [`SchedulerError`] when `outcome` is inconsistent with the
    /// loop's most recently completed RUN.
    fn backend_step_ceiling(
        &self,
        outcome: &QuantumOutcome,
    ) -> Result<VirtualTime, SchedulerError> {
        Ok(outcome.frontier)
    }

    /// Converts a scheduler event time into one node's backend counter.
    ///
    /// Pure and legacy loops use the shared virtual time directly. Schedulers
    /// that admit a VM at a nonzero ready-point counter override this conversion
    /// so backend effects retain the node's physical counter coordinate.
    ///
    /// # Errors
    ///
    /// Returns [`SchedulerError`] when `at` cannot be represented in the target
    /// node's backend counter coordinate.
    fn backend_effect_time(
        &self,
        node: &NodeId,
        at: VirtualTime,
    ) -> Result<VirtualTime, SchedulerError> {
        let _ = node;
        Ok(at)
    }

    /// Projects one guest network emission onto the shared scheduler timeline.
    ///
    /// Live adapters use this projection to retain frames produced beyond the
    /// conservative frontier until their source-local emission coordinate is
    /// globally committed. Pure and legacy loops use the raw instruction count
    /// as their virtual-time coordinate.
    ///
    /// # Errors
    ///
    /// Returns [`SchedulerError`] when `at` cannot be represented on the
    /// scheduler timeline for `node`.
    fn backend_network_output_time(
        &self,
        node: &NodeId,
        at: Icount,
    ) -> Result<VirtualTime, SchedulerError> {
        let _ = node;
        Ok(VirtualTime { ticks: at.retired })
    }

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

    /// Appends backend observations at the current completed boundary.
    ///
    /// Live backend adapters call this only after the scheduler quantum and the
    /// corresponding backend step have both completed. Pure loops may retain
    /// the default fail-loud implementation because they never produce backend
    /// observations.
    ///
    /// # Errors
    ///
    /// Returns [`SchedulerError`] when this loop has no unified event-log owner
    /// or when the observational append violates the log boundary.
    fn append_backend_observable_events(
        &mut self,
        _events: Vec<ObservableEvent>,
    ) -> Result<SchedulerEventLogAppend, SchedulerError> {
        Err(SchedulerError::BoundaryViolation {
            message: String::from(
                "quantum loop cannot append backend observations to a unified event log",
            ),
        })
    }

    /// Appends the evaluation boundary following live backend observations.
    ///
    /// Backend observations may describe execution earlier in the completed
    /// quantum while being appended after its causal scheduler segment. Live
    /// adapters call this after the observational batch so condition evaluation
    /// ends at the completed scheduler frontier.
    ///
    /// # Errors
    ///
    /// Returns [`SchedulerError`] when this loop has no unified event-log owner
    /// or the trailing boundary cannot be appended.
    fn append_backend_evaluation_boundary(
        &mut self,
        _at: VirtualTime,
    ) -> Result<SchedulerEventLogAppend, SchedulerError> {
        Err(SchedulerError::BoundaryViolation {
            message: String::from("quantum loop cannot append a live-backend evaluation boundary"),
        })
    }

    /// Atomically appends backend observations and their evaluation boundary.
    ///
    /// A live node may advance ahead of the shared conservative frontier. The
    /// adapter buffers those observations until `at` commits them, then appends
    /// the observations and boundary in one checked event-log segment so no
    /// intermediate prefix is evaluated at an earlier point.
    ///
    /// # Errors
    ///
    /// Returns [`SchedulerError`] when this loop has no unified event-log owner
    /// or the observational boundary batch is invalid.
    fn append_backend_observations_at_boundary(
        &mut self,
        _events: Vec<ObservableEvent>,
        _at: VirtualTime,
    ) -> Result<SchedulerEventLogAppend, SchedulerError> {
        Err(SchedulerError::BoundaryViolation {
            message: String::from(
                "quantum loop cannot append a live-backend observational boundary batch",
            ),
        })
    }

    /// Validates and appends causal decisions completed by a live backend.
    ///
    /// The returned tuple contains the canonical decisions actually appended
    /// (including any seeded RNG draw preceding an app-random decision), the
    /// updated frontier configuration, and their unified event-log append.
    ///
    /// # Errors
    ///
    /// Returns [`SchedulerError`] when this loop cannot admit backend decisions
    /// or when the values differ from the scenario-seeded decision source.
    fn append_backend_causal_decisions(
        &mut self,
        _decisions: Vec<Decision>,
    ) -> Result<(Vec<Decision>, Configuration, SchedulerEventLogAppend), SchedulerError> {
        Err(SchedulerError::BoundaryViolation {
            message: String::from("quantum loop cannot append causal backend decisions"),
        })
    }

    /// Routes guest-originated frames through scheduler-owned World links.
    ///
    /// The returned tuple contains the canonical network fault decisions
    /// appended while admitting the frames, the updated configuration, and the
    /// corresponding unified event-log append.
    ///
    /// # Errors
    ///
    /// Returns [`SchedulerError`] when an output names an undeclared or
    /// ambiguous route, violates its source boundary, or cannot be admitted by
    /// the modeled link.
    fn append_backend_network_outputs(
        &mut self,
        _outputs: Vec<BackendNetworkOutput>,
    ) -> Result<(Vec<Decision>, Configuration, SchedulerEventLogAppend), SchedulerError> {
        Err(SchedulerError::BoundaryViolation {
            message: String::from("quantum loop cannot route live-backend network outputs"),
        })
    }

    /// Returns the scheduler-derived choices available at the current boundary.
    ///
    /// Loops without state-space exploration support return an empty frontier.
    /// Live scheduler adapters override this with the same materialized frontier
    /// used by temporal-graph search.
    ///
    /// # Errors
    ///
    /// Returns [`SchedulerError`] when the loop cannot materialize its current
    /// search frontier.
    fn search_frontiers(&self) -> Result<Vec<SearchRuntimeFrontier>, SchedulerError> {
        Ok(Vec::new())
    }

    /// Returns the number of explorer-forced branch choices not yet consumed.
    ///
    /// Loops without externally installed runtime choices return zero.
    #[must_use]
    fn pending_search_branch_choices(&self) -> usize {
        0
    }

    /// Takes a terminal verdict emitted while driving the previous quantum.
    ///
    /// Live scenario loops override this when trigger evaluation can complete
    /// or fail a run independently of scheduler quiescence. The verdict is
    /// consumed exactly once by the session engine.
    fn take_terminal_verdict(&mut self) -> Option<QuantumTerminalVerdict> {
        None
    }

    /// Shuts down scheduler/backend resources and returns final log entries.
    ///
    /// Implementations that own live backends should override this hook and
    /// perform idempotent cleanup. Any observation drained during teardown must
    /// be returned so the session can publish the same canonical entries. The
    /// returned entries must continue the unified log's dense sequence in
    /// causal append order. Pure model loops can use the default empty result.
    ///
    /// # Errors
    ///
    /// Returns [`SchedulerError`] when shutdown cannot complete cleanly.
    fn shutdown(&mut self) -> Result<Vec<SchedulerEventLogEntry>, SchedulerError> {
        Ok(Vec::new())
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
    /// Canonical bytes of the final event-log segment appended by this quantum.
    ///
    /// A live backend may contribute a follow-up observational segment after
    /// the scheduler's causal segment; [`QuantumOutcome::event_log_entries`]
    /// contains entries from both in their canonical order.
    pub event_log_segment_bytes: Vec<u8>,
    /// Human-readable text projection of the final appended segment.
    pub event_log_segment_text: String,
    /// Content address of the final appended segment, when one was emitted.
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
    pub(super) kind: String,
    pub(super) attributes: BTreeMap<String, EventAttributeValue>,
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
    pub(super) sequence: u64,
    /// Virtual-time coordinate, optionally enriched with per-node icount.
    pub(super) at: EventLogTime,
    /// Closed source that identifies where the entry originated.
    pub(super) source: EventSource,
    /// Display verbosity, orthogonal to determinism class.
    pub(super) level: EventLevel,
    /// Causal-vs-observational class recorded by the typed append path.
    pub(super) class: SchedulerEventLogClass,
    /// Open-set payload kind and typed named attributes.
    pub(super) event_payload: EventPayload,
    /// Typed payload carried by the event-log entry.
    pub(super) payload: SchedulerEventLogPayload,
    /// Content address of this entry's canonical material.
    pub(super) content_hash: ContentHash,
    pub(super) provenance: SchedulerEventLogEntryProvenance,
}

/// Compatibility name for entries in the unified event log.
pub type LogEntry = SchedulerEventLogEntry;

/// Compatibility name for the causal-vs-observational event class.
pub type EventClass = SchedulerEventLogClass;

#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub(super) struct SchedulerEventLogEntryProvenance;

impl SchedulerEventLogEntry {
    /// Reconstructs one retained open-set event for offline evidence checking.
    ///
    /// This adapter accepts only event kinds whose causal/observational class
    /// matches the current catalog. The generic diagnostic payload preserves
    /// the exact open-set kind and attributes used by failure triage without
    /// granting the caller access to scheduler append ownership.
    ///
    /// # Errors
    ///
    /// Returns [`SchedulerError::BoundaryViolation`] when the retained event
    /// kind is unknown or its class disagrees with the catalog.
    pub fn from_retained_open_event(
        sequence: u64,
        at: EventLogTime,
        source: EventSource,
        level: EventLevel,
        class: SchedulerEventLogClass,
        event_payload: EventPayload,
    ) -> Result<Self, SchedulerError> {
        let diagnostic = EventDiagnosticPayload::new(
            event_payload.kind().to_owned(),
            level,
            event_payload.attributes().clone(),
        );
        let entry = scheduler_event_log_entry_with_material(
            sequence,
            at,
            source,
            level,
            class,
            event_payload,
            SchedulerEventLogPayload::Diagnostic(diagnostic),
        );
        if !entry.class_matches_catalog() {
            return Err(SchedulerError::BoundaryViolation {
                message: format!(
                    "retained event `{}` has an unknown or mismatched event class",
                    entry.event_payload().kind()
                ),
            });
        }
        Ok(entry)
    }

    /// Builds the scheduler-owned causal marker for an exhausted execution budget.
    ///
    /// The marker deliberately records only the stable budget domain. Numeric
    /// limits and observed counters belong in timeout report evidence and do not
    /// perturb the causal signature.
    #[must_use]
    pub fn execution_budget_exhausted(
        sequence: u64,
        at: VirtualTime,
        budget_kind: impl Into<String>,
    ) -> Self {
        Self::execution_budget_exhausted_with_time(
            sequence,
            EventLogTime::from_virtual_time(at),
            budget_kind,
        )
    }

    /// Builds an execution-budget marker with its exact retained coordinate.
    #[must_use]
    pub fn execution_budget_exhausted_with_time(
        sequence: u64,
        at: EventLogTime,
        budget_kind: impl Into<String>,
    ) -> Self {
        let mut attributes = BTreeMap::new();
        attributes.insert(
            String::from("budget_kind"),
            EventAttributeValue::String(budget_kind.into()),
        );
        let diagnostic = EventDiagnosticPayload::new(
            "execution_budget_exhausted",
            EventLevel::Error,
            attributes.clone(),
        );
        scheduler_event_log_entry_with_material(
            sequence,
            at,
            EventSource::Engine,
            EventLevel::Error,
            SchedulerEventLogClass::Causal,
            EventPayload::new("execution_budget_exhausted", attributes),
            SchedulerEventLogPayload::Diagnostic(diagnostic),
        )
    }

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

    /// Builds a scheduler-owned assertion-state observation with an exact
    /// retained event-log coordinate.
    #[must_use]
    pub fn assertion_state_observation_with_time(
        sequence: u64,
        at: EventLogTime,
        name: AssertionId,
        state: AssertionPhase,
    ) -> Self {
        let entry = Self::assertion_state_observation(sequence, at.virtual_time, name, state);
        scheduler_event_log_entry_with_material(
            sequence,
            at,
            entry.source,
            entry.level,
            entry.class,
            entry.event_payload,
            entry.payload,
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
pub(super) struct EventLogSegmentStore {
    pub(super) store: Arc<dyn DagStore>,
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
    pub(super) segment_store: EventLogSegmentStore,
    pub(super) prefix: ContentHash,
    pub(super) offset: EventLogOffset,
    pub(super) bytes: u64,
    pub(super) events: u64,
    pub(super) condition_entries: Vec<LogEntry>,
    pub(super) condition_base_events: u64,
    pub(super) condition_prefix: ConditionEventLogPrefix,
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
    pub(super) entries: Vec<EventLogCausalProjectionEntry>,
    pub(super) canonical_bytes: Vec<u8>,
    pub(super) content_hash: ContentHash,
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
    pub(super) expected: EventLogCausalProjection,
    pub(super) reproduced: EventLogCausalProjection,
    pub(super) byte_identical: bool,
    pub(super) mismatch: Option<EventLogDeterminismMismatch>,
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

pub(super) fn event_log_determinism_mismatch(
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

pub(super) fn event_log_causal_divergence_point(
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
    pub(super) entries: Vec<EventLogCoverageProjectionEntry>,
    pub(super) content_hash: ContentHash,
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
    pub(super) projection: EventLogCoverageProjection,
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
    pub(super) entries: Vec<EventLogAssertionProximityProjectionEntry>,
    pub(super) content_hash: ContentHash,
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

pub(super) fn event_log_coverage_entry(
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
        | SchedulerEventLogPayload::FaultObservation(_)
        | SchedulerEventLogPayload::Diagnostic(_) => return None,
    };
    Some(EventLogCoverageProjectionEntry {
        raw_index,
        at: entry.time().icount.clone(),
        source: entry.source().clone(),
        observation,
    })
}

pub(super) fn event_log_assertion_proximity_entry(
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

pub(super) fn assertion_proximity_entry_is_better(
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

pub(super) fn event_log_assertion_proximity_minimum_material(
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

pub(super) fn event_log_coverage_observation_material(
    entry: &EventLogCoverageProjectionEntry,
) -> String {
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
