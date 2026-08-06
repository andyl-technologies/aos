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

use crate::device::NetworkLinkDirection;
use crate::model::{DagStore, FaultObservation, FaultObservationKind, MemoryDagStore, Schedule};
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
    BackendNetworkOutput, BackendNetworkRoute, ChoiceTag, CombinedNodeFaults, Configuration,
    ContentHash, Decision, DecisionRecorder, DecisionRngState, DeliveryOrderDecision,
    EffectOutcomeDecision, EventId, EventKey, EventLogOffset, EventSequenceState, FaultId,
    FaultRateBasisPoints, FingerprintSample, GdbAttachInfo, GdbListen, Icount, LinkDef, LinkId,
    MIN_LINK_LATENCY, MarkerId, NetworkLinkPendingFrame, NodeCounter, NodeId, NodeLifecycle,
    OverrideDecision, PendingFrame, PreemptionDecision, PreemptionKind, RestartPolicy, RngDecision,
    RngStreamId, RngStreamPosition, ScenarioDef, SchedulerNodeId, SchedulerState,
    SchedulingNodeKind, SchedulingPoint, SearchFrontierChoices, SearchRuntimeFrontier, Seed, Shift,
    SimDuration, SimInstant, SimulationBackend, TimeConversionError, TimerId, VcpuId, VirtualTime,
    World, WorldIoInstantiationError, WorldIoLayoutPolicy, WorldLookaheadEdge, WorldStaticTopology,
    instantiate_world_io_sub_nodes, step,
};

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

mod backend_lifecycle;
mod branch_exploration;
mod control_state;
mod event_codec;
mod event_log;
mod liveness;
mod runtime_state;
mod scenario;
mod single_scheduler_drive;
mod single_scheduler_state;
mod topology;

pub use control_state::*;
pub(crate) use event_codec::*;
pub(crate) use event_codec::{
    recorded_assertion_log_from_schedule_for_search, scheduler_event_log_empty_prefix,
    scheduler_event_log_segment_bytes,
};
pub use event_log::*;
pub use liveness::*;
pub use runtime_state::*;
pub use scenario::*;
pub use topology::*;

#[cfg(test)]
// crucible-lint: allow panic-shortcut -- test assertions use panic shortcuts for fixture setup and failure localization.
#[allow(clippy::expect_used)]
#[path = "scheduler/tests.rs"]
mod tests;
