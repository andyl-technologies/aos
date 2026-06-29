//! Event-graph control-flow spine.
//!
//! RFC-0010 file 17a defines scenario control flow as a graph of events. This
//! module owns the first, condition-agnostic layer of that model: an [`Event`]
//! binds an optional [`Condition`] to an [`Action`] and a [`FirePolicy`], while
//! [`EventGraphState`] is the only local producer of fired actions. Later trigger
//! tasks extend the condition leaves, action application semantics, and legacy
//! `Plan` lowering without adding a separate scenario poke path.

use std::collections::{BTreeMap, BTreeSet};
use std::error::Error;
use std::fmt;

use crate::model::{FaultTag, MembershipFault, NodeId, SimDuration, TimerId, VirtualTime};

/// Stable identity of an event inside an [`EventGraph`].
#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct EventId {
    /// Canonical event name, unique within the graph.
    pub name: String,
}

impl EventId {
    /// Builds an event id from a canonical name.
    #[must_use]
    pub fn from_name(name: impl Into<String>) -> Self {
        Self { name: name.into() }
    }
}

/// A condition handle used by an event trigger.
///
/// The complete leaf vocabulary is implemented by later `T-TRIG-*` tasks. This
/// first slice intentionally treats conditions as stable named predicates so the
/// event graph and firing policy can be validated without introducing an
/// ad-hoc control path.
#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum Condition {
    /// A stable predicate resolved by the condition evaluator.
    Named {
        /// Canonical predicate name.
        name: String,
    },
}

impl Condition {
    /// Builds a named condition handle.
    #[must_use]
    pub fn named(name: impl Into<String>) -> Self {
        Self::Named { name: name.into() }
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

/// Scenario control flow expressed as declared events.
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub struct EventGraph {
    events: Vec<Event>,
}

impl EventGraph {
    /// Builds an event graph after checking event ids are unique.
    ///
    /// # Errors
    ///
    /// Returns [`EventGraphError::DuplicateEventId`] when two events carry the
    /// same stable id, or [`EventGraphError::RepeatableEntrypoint`] when an
    /// entrypoint tries to use repeatable firing policy.
    pub fn new(events: Vec<Event>) -> Result<Self, EventGraphError> {
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

    /// Returns a non-genesis event or rendezvous boundary.
    #[must_use]
    pub const fn boundary(at: VirtualTime) -> Self {
        Self {
            at,
            kind: EventEvaluationKind::Boundary,
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
    /// A deterministic event, quantum, or rendezvous boundary.
    Boundary,
}

/// One action fired by the event graph at an evaluation point.
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub struct EventFiring {
    event: EventId,
    at: VirtualTime,
    action: Action,
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
}

impl EventGraphState {
    /// Builds a fresh event-graph state with no prior firings.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Evaluates every event in declared order and returns fired actions.
    ///
    /// `condition_true` is the deterministic predicate evaluator for
    /// non-entrypoint conditions. This method is the single local producer of
    /// [`EventFiring`] values; callers apply the returned actions at the same
    /// quantum boundary.
    pub fn evaluate<F>(
        &mut self,
        graph: &EventGraph,
        point: EventEvaluationPoint,
        mut condition_true: F,
    ) -> Vec<EventFiring>
    where
        F: FnMut(&Condition) -> bool,
    {
        let mut firings = Vec::new();
        for event in graph.events() {
            let truth = match &event.trigger {
                Some(condition) => condition_true(condition),
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
            }
        }
        firings
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
        }
    }
}

impl Error for EventGraphError {}
