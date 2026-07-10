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
    link_faults_from_combined_network, ninep_faults_from_combined_ninep,
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
    FingerprintSample, GdbAttachInfo, GdbListen, Icount, LinkDef, LinkId, MIN_LINK_LATENCY,
    MarkerId, MembershipFault, NetworkLinkPendingFrame, NodeCounter, NodeId, NodeLifecycle,
    PartitionDirection, PendingFrame, PreemptionDecision, PreemptionKind, RestartPolicy,
    RngDecision, RngStreamId, RngStreamPosition, ScenarioDef, SchedulerNodeId, SchedulerState,
    SchedulingNodeKind, SearchFrontierChoices, Seed, Shift, SimDuration, SimInstant,
    SimulationBackend, TimeConversionError, TimerId, VcpuId, VirtualTime, World,
    WorldIoInstantiationError, WorldIoLayoutPolicy, WorldLookaheadEdge, WorldStaticTopology,
    instantiate_world_io_sub_nodes, step,
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

include!("scheduler/event_log.rs");
include!("scheduler/control_state.rs");
include!("scheduler/topology.rs");
include!("scheduler/scenario.rs");
include!("scheduler/event_codec.rs");
include!("scheduler/runtime_state.rs");
include!("scheduler/single_scheduler_state.rs");
include!("scheduler/single_scheduler_drive.rs");
include!("scheduler/liveness.rs");

#[cfg(test)]
// crucible-lint: allow panic-shortcut -- test assertions use panic shortcuts for fixture setup and failure localization.
#[allow(clippy::expect_used)]
#[path = "scheduler/tests.rs"]
mod tests;
