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
use std::ops::Deref;

use crate::model::{
    AssertionId, AssertionPhase, CodePoint, ContentHash, EventLogOffset, FaultTag, FramePredicate,
    Icount, IoEventKind, LinkId, MarkerId, MemPlace, MembershipFault, MemoryCmp, NodeId,
    NodeLifecycle, Predicate, RegexProgram, SimDuration, TimerId, VirtualTime, WhiteBoxPolicy,
    World, WorldStaticTopology,
};
use crate::scheduler::{
    SchedulerEvaluationBoundaryKind, SchedulerEventLogEntry, SchedulerEventLogPayload,
    SchedulerQuiescence,
};

pub use crate::model::EventId;

/// Shared predicate vocabulary used by both assertions and event triggers.
///
/// This is a public alias rather than a second enum: a predicate usable by the
/// assertion [`crate::model::Property`] layer is the same value accepted by an
/// event trigger.
pub type Condition = Predicate;

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
    observable_events: Vec<ObservableEvent>,
}

impl ConditionEventLogPrefix {
    /// Builds the run-start genesis prefix.
    #[must_use]
    pub fn genesis() -> Self {
        Self {
            point: EventEvaluationPoint::genesis(),
            event_log_offset: EventLogOffset::default(),
            observable_events: Vec::new(),
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
            if let SchedulerEventLogPayload::Observable(payload) = entry.payload() {
                observable_events.push(ObservableEvent {
                    at: entry.at(),
                    payload: payload.clone(),
                });
            }
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
            observable_events,
        })
    }

    pub(crate) fn with_event_log_offset(mut self, event_log_offset: EventLogOffset) -> Self {
        self.event_log_offset = event_log_offset;
        self
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
    let ObservableEventPayload::GuestMarker {
        retired_icount: _,
        node,
        marker,
    } = event
    else {
        return false;
    };
    marker == expected_marker
        && evaluator.white_box_policy_for_node(node) == Some(WhiteBoxPolicy::Enabled)
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
    /// Builds an event graph with no declared assertion or white-box namespace.
    ///
    /// # Errors
    ///
    /// Returns [`EventGraphError::DuplicateEventId`] when two events carry the
    /// same stable id, [`EventGraphError::RepeatableEntrypoint`] when an
    /// entrypoint tries to use repeatable firing policy,
    /// [`EventGraphError::UnknownEventReference`] when an `After` predicate
    /// names no declared event, [`EventGraphError::UnknownTimerReference`] when
    /// a `Timer` predicate names no armable timer, or
    /// [`EventGraphError::EmptyCompound`] when an `AllOf` or `AnyOf` predicate
    /// has no children.
    /// [`EventGraphError::UnknownAssertionReference`] is returned for any
    /// assertion-state trigger because this constructor has no assertion
    /// declarations to validate against; use [`Self::new_with_assertions`] for
    /// those graphs. [`EventGraphError::GuestMarkerWithoutWhiteBoxOptIn`] is
    /// returned for any guest-marker trigger because this constructor has no
    /// world to prove white-box opt-in; use [`Self::new_for_world`] for those
    /// graphs. [`EventGraphError::NodeScheduleTargetRequiresWorld`] is returned
    /// for any `StartNode` or `StopNode` action because this constructor has no
    /// world topology to validate against.
    pub fn new(events: Vec<Event>) -> Result<Self, EventGraphError> {
        Self::new_with_assertions_and_world(events, [], [], None)
    }

    /// Builds an event graph with declared assertion ids available to triggers.
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
    /// has no children,
    /// [`EventGraphError::UnknownAssertionReference`] when an
    /// `AssertionState` predicate names no declared assertion, or
    /// [`EventGraphError::GuestMarkerWithoutWhiteBoxOptIn`] when a guest-marker
    /// trigger is present but no white-box-enabled node namespace was supplied,
    /// or [`EventGraphError::NodeScheduleTargetRequiresWorld`] when `StartNode`
    /// or `StopNode` is present without a world topology.
    pub fn new_with_assertions(
        events: Vec<Event>,
        assertions: impl IntoIterator<Item = AssertionId>,
    ) -> Result<Self, EventGraphError> {
        Self::new_with_assertions_and_world(events, assertions, [], None)
    }

    /// Builds an event graph using white-box opt-in data from `world`.
    ///
    /// # Errors
    ///
    /// Returns the common event-id, trigger-reference, assertion-reference,
    /// guest-marker, and regex construction errors plus
    /// [`EventGraphError::GuestMarkerWithoutWhiteBoxOptIn`] when a guest-marker
    /// trigger is present but `world` has no white-box-enabled node,
    /// [`EventGraphError::UndeclaredNodeScheduleTarget`] when `StartNode` or
    /// `StopNode` references a node outside `world`, or
    /// [`EventGraphError::UnbakedNodeScheduleTarget`] when that action references
    /// a declared node outside the world's bake set.
    pub fn new_for_world(events: Vec<Event>, world: &World) -> Result<Self, EventGraphError> {
        let static_topology = world.static_topology();
        Self::new_with_assertions_and_world(
            events,
            [],
            enabled_white_box_nodes(world),
            Some(&static_topology),
        )
    }

    /// Builds an event graph using assertion and white-box data from `world`.
    ///
    /// # Errors
    ///
    /// Returns the common event-id, trigger-reference, assertion-reference,
    /// guest-marker, and regex construction errors plus
    /// [`EventGraphError::GuestMarkerWithoutWhiteBoxOptIn`] when a guest-marker
    /// trigger is present but `world` has no white-box-enabled node,
    /// [`EventGraphError::UndeclaredNodeScheduleTarget`] when `StartNode` or
    /// `StopNode` references a node outside `world`, or
    /// [`EventGraphError::UnbakedNodeScheduleTarget`] when that action references
    /// a declared node outside the world's bake set.
    pub fn new_with_assertions_for_world(
        events: Vec<Event>,
        assertions: impl IntoIterator<Item = AssertionId>,
        world: &World,
    ) -> Result<Self, EventGraphError> {
        let static_topology = world.static_topology();
        Self::new_with_assertions_and_world(
            events,
            assertions,
            enabled_white_box_nodes(world),
            Some(&static_topology),
        )
    }

    fn new_with_assertions_and_world(
        events: Vec<Event>,
        assertions: impl IntoIterator<Item = AssertionId>,
        white_box_nodes: impl IntoIterator<Item = NodeId>,
        static_topology: Option<&WorldStaticTopology>,
    ) -> Result<Self, EventGraphError> {
        let assertion_ids = assertions.into_iter().collect::<BTreeSet<_>>();
        let white_box_nodes = white_box_nodes.into_iter().collect::<BTreeSet<_>>();
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
                )?;
            }
            validate_action_references(event, &event.action, static_topology)?;
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

fn validate_action_references(
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
        Action::InjectFault { .. }
        | Action::HealFault { .. }
        | Action::ArmTimer { .. }
        | Action::CancelTimer { .. }
        | Action::CreateSavepoint { .. }
        | Action::Fork { .. }
        | Action::Pass
        | Action::Fail { .. }
        | Action::Log { .. } => Ok(()),
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
        ),
        Condition::AnyOf { predicates } => validate_compound_condition_references(
            event,
            "any-of",
            predicates,
            event_ids,
            timer_names,
            assertion_ids,
            white_box_nodes,
        ),
        Condition::Once { predicate } | Condition::Not { predicate } => {
            validate_condition_references(
                event,
                predicate,
                event_ids,
                timer_names,
                assertion_ids,
                white_box_nodes,
            )
        }
        Condition::ConsoleMatch { regex, .. } => validate_condition_regex(event, regex),
        Condition::At { .. }
        | Condition::NetworkMatch { .. }
        | Condition::CoveragePoint { .. }
        | Condition::MemoryPredicate { .. }
        | Condition::IoPattern { .. }
        | Condition::NodeState { .. }
        | Condition::Quiescent
        | Condition::Named { .. } => Ok(()),
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
        )?;
    }

    Ok(())
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
