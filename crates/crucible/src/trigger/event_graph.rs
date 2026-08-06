//! Event graph authoring, lowering, firing, state, and validation.

use super::*;
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

    pub(crate) fn from_unchecked_events_for_model(events: Vec<Event>) -> Self {
        Self { events }
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
    /// [`EventGraphError::NonRepeatableCycle`] for a hard dependency cycle among
    /// non-repeatable events, or
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
            validate_action_references(event, &event.action, static_topology.as_ref())?;
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
    condition_summary: String,
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

    /// Returns the stable condition summary recorded with the firing.
    #[must_use]
    pub fn condition_summary(&self) -> &str {
        &self.condition_summary
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
                    condition_summary: event
                        .trigger
                        .as_ref()
                        .map_or_else(|| String::from("entrypoint"), Condition::canonical_summary),
                    action: event.action.clone(),
                });
                self.last_firing.insert(event.id.clone(), point.at());
            }
        }
        EventFirings::new(point, event_log_offset, timer_fires, firings)
    }
}

pub(super) struct EventGraphConditionEvaluator<'state, 'inner, E> {
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

    fn fault_facts(&self) -> &[ObservedFaultFact] {
        self.inner.fault_facts()
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
    /// A taxonomy fault targets a declared device from the wrong I/O family.
    DeviceKindMismatch {
        /// Event containing the invalid reference.
        event: EventId,
        /// Referenced device id.
        device: DeviceId,
        /// Device family required by the taxonomy fault.
        expected: WorldDeviceKind,
        /// Device family declared by the world.
        actual: WorldDeviceKind,
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
            Self::DeviceKindMismatch {
                event,
                device,
                expected,
                actual,
            } => {
                write!(
                    formatter,
                    "event `{}` uses {} device `{}` as a {} device",
                    event.name,
                    world_device_kind_name(*actual),
                    device.name,
                    world_device_kind_name(*expected)
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
pub(super) struct EventGraphTopology {
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

pub(super) fn world_device_kind_name(kind: WorldDeviceKind) -> &'static str {
    match kind {
        WorldDeviceKind::Block => "block",
        WorldDeviceKind::NineP => "9p",
    }
}

pub(super) fn event_graph_link_ids(links: &[LinkDef]) -> BTreeSet<LinkId> {
    let mut ids = BTreeSet::new();
    let mut legacy_counts = BTreeMap::new();
    for link in links {
        ids.insert(canonical_link_id_for_world_link(link));
        let legacy = legacy_link_id_for_world_link(link);
        let count = legacy_counts.entry(legacy).or_insert(0_usize);
        *count = count.saturating_add(1);
    }
    for (legacy, count) in legacy_counts {
        if count == 1 {
            ids.insert(legacy);
        }
    }
    ids
}

pub(super) fn canonical_link_id_for_world_link(link: &LinkDef) -> LinkId {
    let (endpoint_a, endpoint_b) = link.endpoints();
    LinkId::from_name(format!(
        "link_endpoint_a_len={}\nlink_endpoint_a={}\nlink_endpoint_b_len={}\nlink_endpoint_b={}",
        endpoint_a.name.len(),
        endpoint_a.name,
        endpoint_b.name.len(),
        endpoint_b.name
    ))
}

pub(super) fn legacy_link_id_for_world_link(link: &LinkDef) -> LinkId {
    let (endpoint_a, endpoint_b) = link.endpoints();
    LinkId::from_name(format!("{}--{}", endpoint_a.name, endpoint_b.name))
}

pub(super) fn armed_timer_names(events: &[Event]) -> BTreeSet<TimerId> {
    let mut timers = BTreeSet::new();
    for event in events {
        collect_timer_names(&event.action, &mut timers);
    }
    timers
}

pub(super) fn collect_timer_names(action: &Action, timers: &mut BTreeSet<TimerId>) {
    match action {
        Action::ArmTimer { name, .. } => {
            timers.insert(name.clone());
        }
        Action::Group(actions) => {
            for action in actions {
                collect_timer_names(action, timers);
            }
        }
        Action::CancelTimer { .. }
        | Action::StartNode { .. }
        | Action::StopNode { .. }
        | Action::CreateSavepoint { .. }
        | Action::Fork { .. }
        | Action::Pass
        | Action::Fail { .. }
        | Action::Log { .. } => {}
    }
}

pub(super) fn validate_action_references(
    event: &Event,
    action: &Action,
    static_topology: Option<&WorldStaticTopology>,
) -> Result<(), EventGraphError> {
    match action {
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
                validate_action_references(event, action, static_topology)?;
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

pub(super) fn enabled_white_box_nodes(world: &World) -> BTreeSet<NodeId> {
    world
        .vm_nodes()
        .iter()
        .filter(|node| node.white_box == WhiteBoxPolicy::Enabled)
        .map(|node| node.id.clone())
        .collect()
}

pub(super) fn validate_condition_references(
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

pub(super) fn validate_compound_condition_references(
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

pub(super) fn validate_node_reference(
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

pub(super) fn validate_link_reference(
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

pub(super) fn validate_condition_regex(
    event: &Event,
    regex: &RegexProgram,
) -> Result<(), EventGraphError> {
    regex::bytes::Regex::new(&regex.pattern)
        .map(|_| ())
        .map_err(|source| EventGraphError::InvalidRegex {
            event: event.id.clone(),
            pattern: regex.pattern.clone(),
            reason: source.to_string(),
        })
}

pub(super) fn validate_event_graph_dependencies(
    events: &[Event],
    timer_names: &BTreeSet<TimerId>,
) -> Result<(), EventGraphError> {
    let armers = timer_armers(events);
    validate_non_repeatable_cycles(events, &armers)?;
    validate_event_reachability(events, timer_names, &armers)
}

pub(super) fn timer_armers(events: &[Event]) -> BTreeMap<TimerId, BTreeSet<EventId>> {
    let mut armers = BTreeMap::new();
    for event in events {
        collect_timer_armers(&event.action, &event.id, &mut armers);
    }
    armers
}

pub(super) fn collect_timer_armers(
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
        Action::CancelTimer { .. }
        | Action::StartNode { .. }
        | Action::StopNode { .. }
        | Action::CreateSavepoint { .. }
        | Action::Fork { .. }
        | Action::Pass
        | Action::Fail { .. }
        | Action::Log { .. } => {}
    }
}

pub(super) fn validate_non_repeatable_cycles(
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
pub(super) enum DfsMark {
    Gray,
    Black,
}

pub(super) fn visit_non_repeatable_event(
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

pub(super) fn hard_event_dependencies(
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

pub(super) fn validate_event_reachability(
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

pub(super) fn possible_dependency_alternatives(
    condition: &Condition,
    timer_names: &BTreeSet<TimerId>,
    armers: &BTreeMap<TimerId, BTreeSet<EventId>>,
) -> Vec<BTreeSet<EventId>> {
    match condition {
        Condition::After { of, .. } => vec![BTreeSet::from([of.clone()])],
        Condition::Timer { name } => {
            if timer_names.contains(name) {
                armers
                    .get(name)
                    .into_iter()
                    .flat_map(|timer_armers| timer_armers.iter().cloned())
                    .map(|event| BTreeSet::from([event]))
                    .collect::<Vec<_>>()
            } else {
                Vec::new()
            }
        }
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

pub(super) fn combine_dependency_alternatives(
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
