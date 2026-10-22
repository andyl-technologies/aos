//! Session engine unit tests separated from the production actor implementation.

use super::*;

use crucible_engine::{
    Action, AssertionId, AssertionPhase, BackendInput, Checkpoint, CheckpointKind, ChoiceTag,
    DebugNonCanonicalBranchAction, DebugNonCanonicalBranchTrigger, DebugOperatorControlKind,
    DebugReverseStepGrain, Decision, DeliveryOrderDecision, Event, EventGraph, EventGraphState,
    EventId, EventKey, GdbAttachInfo, GenesisCheckpoint, LogLevel, NodeId, NodeLifecycle,
    NodeTemplate, OverrideDecision, Predicate, ReadyPoint, ScenarioDef, ScheduledEvent,
    ScheduledEventKey, SchedulerNodeId, SchedulingNodeKind, SchedulingPoint, Seed, TimerId,
    TriggerActionApplication, VirtualTime, VmArchitecture, WhiteBoxPolicy, World, WorldNode, bake,
    try_step,
};

fn accepted_step(
    configuration: &crucible_engine::Configuration,
    decision: Decision,
) -> crucible_engine::Configuration {
    match try_step(configuration, decision) {
        Ok(configuration) => configuration,
        Err(error) => panic!("test configuration step should be accepted: {error}"),
    }
}

#[path = "tests/actor_runtime.rs"]
mod actor_runtime;
#[path = "tests/breakpoint_metadata.rs"]
mod breakpoint_metadata;
#[path = "tests/engine_state.rs"]
mod engine_state;
#[path = "tests/terminal_verdict.rs"]
mod terminal_verdict;

use actor_runtime::*;
