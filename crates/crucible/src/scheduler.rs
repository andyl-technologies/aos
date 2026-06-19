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
    BackendError, BackendInput, Configuration, Decision, FaultId, Icount, NodeId, VirtualTime,
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

/// Canonical key for resolving due events in one total order.
#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct ScheduledEventKey {
    /// The virtual time at which the event is due.
    pub virtual_time: VirtualTime,
    /// The event consumer.
    pub consumer: SchedulerNodeId,
    /// The event producer.
    pub producer: SchedulerNodeId,
    /// The producer-local sequence number.
    pub sequence: u64,
}

/// A due event resolved by the scheduler.
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub struct ScheduledEvent {
    /// The canonical ordering key.
    pub key: ScheduledEventKey,
    /// The resolved event payload.
    pub payload: ScheduledEventPayload,
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

    fn scheduler_node(name: &str, kind: SchedulingNodeKind) -> SchedulerNodeId {
        SchedulerNodeId {
            node: NodeId {
                name: name.to_string(),
            },
            kind,
        }
    }

    fn event_key(
        virtual_time: u64,
        consumer: &SchedulerNodeId,
        producer: &SchedulerNodeId,
        sequence: u64,
    ) -> ScheduledEventKey {
        ScheduledEventKey {
            virtual_time: VirtualTime {
                ticks: virtual_time,
            },
            consumer: consumer.clone(),
            producer: producer.clone(),
            sequence,
        }
    }
}
