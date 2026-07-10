//! Event-graph control-flow spine.
//!
//! RFC-0010 file 17a defines scenario control flow as a graph of events. This
//! module owns the first, condition-agnostic layer of that model: an [`Event`]
//! binds an optional [`Condition`] to an [`Action`] and a [`FirePolicy`], while
//! [`EventGraphState`] is the only local producer of fired actions. The
//! code-first builder and graph-native plan serialization keep that control flow
//! as a content-addressed scenario component instead of a separate scenario poke
//! path.

use std::collections::{BTreeMap, BTreeSet};
use std::error::Error;
use std::fmt;
use std::ops::Deref;

use crate::model::{
    AssertionDef, AssertionId, AssertionPhase, BlockFault, CodePoint, ContentHash,
    ControlFaultAction, Decision, DeviceId, EngineError, EventKey, EventLogOffset, Fault, FaultId,
    FaultPlanEntry, FaultTag, FramePredicate, Icount, IoEventKind, LinkDef, LinkId, MarkerId,
    MemPlace, MembershipFault, MemoryCmp, NetworkFault, NinePFault, NodeFault, NodeId,
    NodeLifecycle, PartitionDirection, Plan, PlanEntry, Predicate, PreemptionKind, Properties,
    Property, ReachabilityExpectation, ReachableDisposition, ReadyPoint, RegexProgram,
    ReproductionArtifact, ReproductionReplay, RestartPolicy, RngStreamId, Schedule,
    SchedulerNodeId, SchedulingNodeKind, Shift, SimDuration, TimeConversionError, TimerId,
    VirtualTime, WhiteBoxPolicy, World, WorldDeviceKind, WorldStaticTopology,
};
use crate::scheduler::{
    AssertionRunVerdict, AssertionVerdictFailure, ControlOperationKind, EventAttributeValue,
    EventLevel, EventLogCausalDivergencePoint, EventLogIcountStamp, ScheduledEvent,
    ScheduledEventKey, ScheduledEventPayload, ScheduledEventResolveClass,
    SchedulerEvaluationBoundaryKind, SchedulerEventLogClass, SchedulerEventLogEntry,
    SchedulerEventLogPayload, SchedulerQuiescence, TriggerActionApplication,
    compare_event_log_determinism, scheduled_event_resolve_class, scheduler_event_log_empty_prefix,
    scheduler_event_log_segment_bytes,
};

pub use crate::model::EventId;

/// Shared predicate vocabulary used by both assertions and event triggers.
///
/// This is a public alias rather than a second enum: a predicate usable by the
/// assertion [`crate::model::Property`] layer is the same value accepted by an
/// event trigger.
pub type Condition = Predicate;

include!("trigger/observability.rs");
include!("trigger/conditions.rs");
include!("trigger/assertions.rs");
include!("trigger/evidence.rs");
include!("trigger/evaluation.rs");
include!("trigger/event_graph.rs");

#[cfg(test)]
// crucible-lint: allow panic-shortcut -- test assertions use panic shortcuts for fixture setup and failure localization.
#[allow(clippy::expect_used)]
#[path = "trigger/tests.rs"]
mod tests;
