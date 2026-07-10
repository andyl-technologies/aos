//! Session engine unit tests separated from the production actor implementation.

use super::*;

use crucible::{
    Action, AssertionId, AssertionPhase, BackendInput, Checkpoint, CheckpointKind, ChoiceTag,
    DebugNonCanonicalBranchAction, DebugNonCanonicalBranchTrigger, DebugOperatorControlKind,
    DebugReverseStepGrain, Decision, DeliveryOrderDecision, Event, EventGraph, EventGraphState,
    EventId, EventKey, GdbAttachInfo, GenesisCheckpoint, LogLevel, MembershipFault, NodeId,
    NodeLifecycle, NodeTemplate, OverrideDecision, Predicate, ReadyPoint, ScenarioDef,
    ScheduledEvent, ScheduledEventKey, SchedulerNodeId, SchedulingNodeKind, SchedulingPoint, Seed,
    TimerId, TriggerActionApplication, VirtualTime, VmArchitecture, WhiteBoxPolicy, World,
    WorldNode, bake, step, try_step,
};

include!("tests/engine_state.rs");
include!("tests/actor_runtime.rs");
