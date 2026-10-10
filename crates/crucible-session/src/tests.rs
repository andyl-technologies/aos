//! Session engine unit tests separated from the production actor implementation.

use super::*;

use crucible::{
    Action, AssertionId, AssertionPhase, BackendInput, Checkpoint, CheckpointKind, ChoiceTag,
    DebugNonCanonicalBranchAction, DebugNonCanonicalBranchTrigger, DebugOperatorControlKind,
    DebugReverseStepGrain, Decision, DeliveryOrderDecision, Event, EventGraph, EventGraphState,
    EventId, EventKey, GdbAttachInfo, GenesisCheckpoint, LogLevel, NodeId, NodeLifecycle,
    NodeTemplate, OverrideDecision, Predicate, ReadyPoint, ScenarioDef, ScheduledEvent,
    ScheduledEventKey, SchedulerNodeId, SchedulingNodeKind, SchedulingPoint, Seed, TimerId,
    TriggerActionApplication, VirtualTime, VmArchitecture, WhiteBoxPolicy, World, WorldNode, bake,
    try_step,
};

// Component fixtures author their own finite metadata envelope. This guard is
// used only around synchronous construction, never retained across an await.
fn fixture_metadata_scope() -> crucible::test_support::FixtureDecodeScope {
    crucible::test_support::fixture_decode_scope(64 * 1024 * 1024)
        .unwrap_or_else(|error| panic!("authored finite session component metadata: {error}"))
}

fn accepted_step(
    configuration: &crucible::Configuration,
    decision: Decision,
) -> crucible::Configuration {
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

/// Restores one finite component account for every synchronous future poll.
async fn admitted_fixture<F: std::future::Future>(future: F) -> F::Output {
    let budget = {
        let _scope = fixture_metadata_scope();
        crucible::owned_decode::current_budget()
            .unwrap_or_else(|| panic!("fixture scope retains its original budget"))
    };
    let mut future = std::pin::pin!(future);
    std::future::poll_fn(|context| {
        let _scope = budget.enter();
        future.as_mut().poll(context)
    })
    .await
}
