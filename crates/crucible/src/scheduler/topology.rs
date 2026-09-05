//! Control admission, lookahead topology, timeline ordering, horizons, and rendezvous.

use super::*;
/// Maximum allowed scheduler-side control application latency in quanta.
pub const SCHEDULER_CONTROL_RESPONSE_BOUND_QUANTA: u64 = 1;

/// A control-plane operation admitted only at a quantum boundary.
#[derive(
    Clone, Debug, PartialEq, Eq, PartialOrd, Ord, Hash, serde::Serialize, serde::Deserialize,
)]
pub struct ControlOperation {
    /// The session-local sequence number for this control operation.
    pub sequence: u64,
    /// The requested control action.
    pub kind: ControlOperationKind,
}

/// A session control action that can be handled between quanta.
#[derive(
    Clone, Debug, PartialEq, Eq, PartialOrd, Ord, Hash, serde::Serialize, serde::Deserialize,
)]
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
    /// Query boundary state without mutating the engine.
    Query,
}

/// Evidence that one scheduler control operation applied at a quantum boundary.
#[derive(Clone, Debug, PartialEq, Eq, Hash, serde::Serialize, serde::Deserialize)]
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

#[derive(Clone, Debug, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub(super) struct SchedulerControlAdmission {
    pub(super) operation: ControlOperation,
    pub(super) accepted_after_quanta: u64,
    pub(super) accepted_after_boundary_yield: u64,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub(super) struct SchedulerControlDrain {
    pub(super) events: Vec<ScheduledEvent>,
    pub(super) applications: Vec<SchedulerControlApplication>,
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
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, serde::Serialize, serde::Deserialize)]
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
    pub(super) edges: Vec<SchedulerLookaheadEdge>,
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
    pub(super) shift: Shift,
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
#[derive(
    Clone, Debug, PartialEq, Eq, PartialOrd, Ord, Hash, serde::Serialize, serde::Deserialize,
)]
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
#[derive(Clone, Debug, PartialEq, Eq, Hash, serde::Serialize, serde::Deserialize)]
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
#[derive(Clone, Debug, PartialEq, Eq, Hash, serde::Serialize, serde::Deserialize)]
pub struct ScheduledEvent {
    /// The canonical ordering key.
    pub key: ScheduledEventKey,
    /// The resolved event payload.
    pub payload: ScheduledEventPayload,
}

/// The RESOLVE payload class for a scheduled event.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, serde::Serialize, serde::Deserialize)]
pub enum ScheduledEventResolveClass {
    /// A deterministic frame or backend input delivery.
    FrameDelivery,
    /// A deterministic I/O completion from a scheduler sub-node.
    IoCompletion,
    /// A control-plane operation admitted at the boundary.
    Control,
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
pub(super) fn merge_node_deliveries(
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

pub(super) fn pending_frames_from_scheduled_events(
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

/// Returns the RESOLVE payload class for `event`.
#[must_use]
pub fn scheduled_event_resolve_class(event: &ScheduledEvent) -> ScheduledEventResolveClass {
    match event.payload {
        ScheduledEventPayload::BackendInput(_) => ScheduledEventResolveClass::FrameDelivery,
        ScheduledEventPayload::IoCompletion(_) => ScheduledEventResolveClass::IoCompletion,
        ScheduledEventPayload::Control(_) => ScheduledEventResolveClass::Control,
    }
}

/// Payload carried by a scheduler-resolved event.
#[derive(Clone, Debug, PartialEq, Eq, Hash, serde::Serialize, serde::Deserialize)]
pub enum ScheduledEventPayload {
    /// A backend input delivered at the scheduler-selected point.
    BackendInput(BackendInput),
    /// A deterministic I/O completion from a disk, 9p, or network sub-node.
    IoCompletion(IoCompletion),
    /// A control operation admitted at a quantum boundary.
    Control(ControlOperation),
}

/// A deterministic I/O completion emitted by a scheduling sub-node.
#[derive(Clone, Debug, PartialEq, Eq, Hash, serde::Serialize, serde::Deserialize)]
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
#[derive(Clone, Debug, PartialEq, Eq, Hash, serde::Serialize, serde::Deserialize)]
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
    /// The signal-driven fault runtime requires an exact evaluation boundary.
    SignalFaultEvaluation {
        /// The exact global virtual-time boundary requested by the runtime.
        virtual_time: SimInstant,
    },
    /// The event graph requires an exact predicate-transition boundary.
    TriggerEvaluation {
        /// The exact global virtual-time transition requested by the graph.
        virtual_time: SimInstant,
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
            | Self::SignalFaultEvaluation { virtual_time }
            | Self::TriggerEvaluation { virtual_time } => Some(*virtual_time),
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
        ScheduledEventPayload::BackendInput(_) | ScheduledEventPayload::Control(_) => Ok(None),
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
        ScheduledEventPayload::Control(_) => Ok(SimInstant {
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

pub(super) fn exact_local_event_rank(event: &ExactLocalEvent) -> u8 {
    match event {
        ExactLocalEvent::NoArmedTimer => 0,
        ExactLocalEvent::TimerDeadline { .. } => 1,
        ExactLocalEvent::IoCompletion { .. } => 2,
        ExactLocalEvent::SignalFaultEvaluation { .. } => 3,
        ExactLocalEvent::TriggerEvaluation { .. } => 4,
    }
}

pub(super) fn exact_local_event_source_key(event: &ExactLocalEvent) -> &str {
    match event {
        ExactLocalEvent::NoArmedTimer
        | ExactLocalEvent::TimerDeadline { .. }
        | ExactLocalEvent::SignalFaultEvaluation { .. }
        | ExactLocalEvent::TriggerEvaluation { .. } => "",
        ExactLocalEvent::IoCompletion { sub_node, .. } => &sub_node.node.name,
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
    /// An exact signal-driven fault evaluation selected the horizon.
    SignalFaultEvaluation,
    /// An exact event-graph predicate transition selected the horizon.
    TriggerEvaluation,
}

/// The scheduler rendezvous frequency knob.
///
/// A rendezvous is a common exact cap used for global bookkeeping work. It may
/// split node advancement into more quanta, but it is not an event-delivery clock
/// and must not add canonical schedule material by itself.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Hash)]
pub struct SchedulerRendezvous {
    pub(super) interval: Option<SimDuration>,
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
#[derive(
    Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash, serde::Serialize, serde::Deserialize,
)]
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
#[derive(Clone, Debug, PartialEq, Eq, Hash, serde::Serialize, serde::Deserialize)]
pub struct SchedulerRendezvousNode {
    /// The scheduler graph node participating in the rendezvous.
    pub node: SchedulerNodeId,
    /// The exact virtual time observed for the node.
    pub virtual_time: SimInstant,
}

/// Evidence that an allowed scheduler rendezvous occurred.
#[derive(Clone, Debug, PartialEq, Eq, Hash, serde::Serialize, serde::Deserialize)]
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

pub(super) fn validate_scheduler_rr_policy(
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

pub(super) fn validate_vcpu_idle_snapshot(
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

pub(super) fn exact_local_event_horizon_source(event: &ExactLocalEvent) -> SchedulerHorizonSource {
    match event {
        ExactLocalEvent::TimerDeadline { .. } => SchedulerHorizonSource::ExactLocalTimer,
        ExactLocalEvent::IoCompletion { .. } => SchedulerHorizonSource::ExactLocalIoCompletion,
        ExactLocalEvent::SignalFaultEvaluation { .. } => {
            SchedulerHorizonSource::SignalFaultEvaluation
        }
        ExactLocalEvent::TriggerEvaluation { .. } => SchedulerHorizonSource::TriggerEvaluation,
        ExactLocalEvent::NoArmedTimer => SchedulerHorizonSource::NetworkLookahead,
    }
}

pub(super) fn horizon_source_allows_ceiling_past_target(source: SchedulerHorizonSource) -> bool {
    matches!(
        source,
        SchedulerHorizonSource::ExactLocalTimer | SchedulerHorizonSource::ExactLocalIoCompletion
    )
}

pub(super) fn scheduler_ceiling_overshoot_error(
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
