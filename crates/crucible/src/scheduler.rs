//! Single-scheduler quantum-loop boundary.
//!
//! The module owns the L3 interface that all virtual-time advancement and
//! cross-node event resolution must pass through. It intentionally defines the
//! boundary and ordering vocabulary without implementing the full scheduler
//! algorithm; the detailed PICK/RUN/RESOLVE/EMIT/STEP behavior lands in the
//! scheduler tasks that build on this API.

use std::error::Error;
use std::fmt;

use crate::{
    BackendError, BackendInput, Configuration, Decision, FaultId, Icount, NodeCounter, NodeId,
    Shift, SimInstant, TimeConversionError, VirtualTime,
};

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
}

impl fmt::Display for SchedulerError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::NotImplemented { operation } => {
                write!(f, "scheduler operation {operation} is not implemented yet")
            }
            Self::Backend(error) => write!(f, "backend failed under scheduler control: {error}"),
            Self::BoundaryViolation { message } => f.write_str(message),
        }
    }
}

impl Error for SchedulerError {}

impl From<BackendError> for SchedulerError {
    fn from(error: BackendError) -> Self {
        Self::Backend(error)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{ContentHash, ScenarioDef, step};

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

        let config = Configuration::genesis(ScenarioDef {
            id: ContentHash::default(),
        });
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
        let config = Configuration::genesis(ScenarioDef {
            id: ContentHash::default(),
        });
        let decision = crate::Decision::RngDraw(crate::RngDecision {
            stream: crate::RngStreamId {
                name: String::from("scheduler"),
            },
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
    fn scheduler_errors_render_all_variants_deterministically() {
        let backend = SchedulerError::from(BackendError::Rejected {
            message: String::from("backend refused"),
        });
        let boundary = SchedulerError::BoundaryViolation {
            message: String::from("bypassed scheduler boundary"),
        };
        let not_implemented = SchedulerError::NotImplemented { operation: "pick" };

        assert_eq!(
            not_implemented.to_string(),
            "scheduler operation pick is not implemented yet"
        );
        assert_eq!(
            backend.to_string(),
            "backend failed under scheduler control: backend refused"
        );
        assert_eq!(boundary.to_string(), "bypassed scheduler boundary");
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
        let shift = match Shift::new(bits) {
            Ok(shift) => shift,
            Err(error) => panic!("test shift should be valid: {error}"),
        };
        match SharedTimeline::new(shift) {
            Ok(timeline) => timeline,
            Err(error) => panic!("test timeline should be valid: {error}"),
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
