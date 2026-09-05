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
use crate::node_time::{NodeTimeMapping, NodeTimeProjection};
use crate::trigger::{
    Action, ConditionEvaluationPass, ConditionEventLogPrefix, ConditionLeafOracle, EventFiring,
    EventFirings, EventGraph, EventGraphState, GuestMeasurementEvent, GuestMeasurementValue,
    GuestSemanticMarkerDetail, HostAssertionReport, LogLevel, ObservableEvent,
    ObservableEventPayload, OfflineAssertionCheckError, RecordedAssertionLog,
};
use crate::{
    AssertionId, AssertionPhase, AssertionQuantifierKind, BackendError, BackendInput,
    BackendNetworkOutput, BackendNetworkRoute, ChoiceTag, Configuration, ContentHash,
    DebugRuntimeRepositionReport, DebugRuntimeRepositionRequest, Decision, DecisionRecorder,
    DecisionRngState, DeliveryOrderDecision, EventId, EventKey, EventLogOffset, EventSequenceState,
    FingerprintSample, GdbAttachInfo, GdbListen, Icount, LinkDef, LinkId, MIN_LINK_LATENCY,
    MarkerId, NetworkLinkPendingFrame, NodeCounter, NodeId, NodeLifecycle, OverrideDecision,
    PendingFrame, PreemptionDecision, PreemptionKind, RngStreamId, RngStreamPosition, ScenarioDef,
    SchedulerNodeId, SchedulerState, SchedulingNodeKind, SchedulingPoint, SearchFrontierChoices,
    SearchRuntimeFrontier, Seed, Shift, SimDuration, SimInstant, SimulationBackend,
    TimeConversionError, TimerId, VcpuId, VirtualTime, World, WorldIoInstantiationError,
    WorldIoLayoutPolicy, WorldLookaheadEdge, WorldStaticTopology, instantiate_world_io_sub_nodes,
    step,
};

const EVENT_LOG_SEGMENT_BINARY_MAGIC: &[u8; 16] = b"CRUCIBLE-ELOGSEG";
const EVENT_LOG_SEGMENT_BINARY_VERSION: u32 = 1;
const EVENT_LOG_SEGMENT_NODE_ABSENT: u8 = 0;
const EVENT_LOG_SEGMENT_NODE_PRESENT: u8 = 1;
const EVENT_LOG_LEVEL_TRACE: u8 = 0;
const EVENT_LOG_LEVEL_DEBUG: u8 = 1;

/// Returns whether an override belongs to the production live-network choice domain.
#[must_use]
pub fn is_supported_live_world_network_override(decision: &OverrideDecision) -> bool {
    decision.point.key.starts_with("live-world-network/")
        && liveness::is_live_network_branch_choice_name(&decision.choice.name)
}

/// Returns whether a live-network override names an exact link declared by `world`.
#[must_use]
pub fn live_world_network_override_matches_world(
    world: &World,
    decision: &OverrideDecision,
) -> bool {
    let Some(coordinate) = decision.point.key.strip_prefix("live-world-network/") else {
        return false;
    };
    let mut components = coordinate.rsplitn(4, '/');
    let (Some(rng_position), Some(frame_id), Some(direction), Some(link)) = (
        components.next(),
        components.next(),
        components.next(),
        components.next(),
    ) else {
        return false;
    };
    if rng_position.parse::<u64>().is_err()
        || frame_id.parse::<u64>().is_err()
        || !matches!(direction, "a-to-b" | "b-to-a")
    {
        return false;
    }
    world.links().iter().any(|definition| {
        scheduler_link_id_for_nodes(definition.endpoints().0, definition.endpoints().1).name == link
    })
}

/// Returns the exact live-network override prefixes declared by `world`.
#[must_use]
pub fn live_world_network_override_point_prefixes(world: &World) -> Vec<String> {
    let mut prefixes = Vec::with_capacity(world.links().len().saturating_mul(2));
    for definition in world.links() {
        let link =
            scheduler_link_id_for_nodes(definition.endpoints().0, definition.endpoints().1).name;
        for direction in ["a-to-b", "b-to-a"] {
            prefixes.push(format!("live-world-network/{link}/{direction}/"));
        }
    }
    prefixes
}

const EVENT_LOG_LEVEL_INFO: u8 = 2;
const EVENT_LOG_LEVEL_WARN: u8 = 3;
const EVENT_LOG_LEVEL_ERROR: u8 = 4;
const EVENT_LOG_CLASS_CAUSAL: u8 = 0;
const EVENT_LOG_CLASS_OBSERVATIONAL: u8 = 1;

mod backend_lifecycle;
mod branch_exploration;
mod checkpoint;
mod control_state;
mod event_codec;
mod event_log;
mod inactive_time;
mod liveness;
mod runtime_state;
mod scenario;
mod single_scheduler_drive;
mod single_scheduler_state;
mod topology;

pub use checkpoint::*;
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
