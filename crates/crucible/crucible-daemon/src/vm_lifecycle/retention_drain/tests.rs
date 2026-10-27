//! Tests that retention drains decline without side effects and match shutdown.

use super::*;

fn process_free_lifecycle() -> ProductionVmLifecycleLoop {
    production_permanently_failed_loop_for_test()
        .unwrap_or_else(|error| panic!("process-free lifecycle should build: {error}"))
        .1
}

#[test]
fn failed_lease_cleanup_declines_retention_without_settling() {
    let mut lifecycle = process_free_lifecycle();
    lifecycle.node_lease_cleanup_failed = true;
    let before = lifecycle.inner.loop_impl().event_log().offset();

    let drained = lifecycle
        .drain_final_boundary_for_retention()
        .unwrap_or_else(|error| panic!("an ineligible drain should not fail: {error}"));

    assert_eq!(
        drained,
        RetentionDrain::Declined(RetentionDrainRefusal::NodeLeaseCleanupFailed)
    );
    assert_eq!(lifecycle.inner.loop_impl().event_log().offset(), before);
}

#[test]
fn earliest_refusing_check_names_the_decline() {
    let mut lifecycle = process_free_lifecycle();
    lifecycle.node_lease_cleanup_failed = true;
    lifecycle.debug_gateway_teardown_required = true;

    let drained = lifecycle
        .drain_final_boundary_for_retention()
        .unwrap_or_else(|error| panic!("an ineligible drain should not fail: {error}"));

    assert_eq!(
        drained,
        RetentionDrain::Declined(RetentionDrainRefusal::DebugGatewayTeardown)
    );
}

#[test]
fn drained_boundary_leaves_nothing_for_shutdown() {
    let mut lifecycle = process_free_lifecycle();

    let drained = match lifecycle
        .drain_final_boundary_for_retention()
        .unwrap_or_else(|error| panic!("a clean boundary should drain: {error}"))
    {
        RetentionDrain::Settled(entries) => entries,
        RetentionDrain::Declined(refusal) => {
            panic!("a clean boundary should be retainable, declined {refusal:?}")
        }
    };
    let after_drain = lifecycle.inner.loop_impl().event_log().offset();
    let shutdown = lifecycle
        .shutdown()
        .unwrap_or_else(|error| panic!("shutdown after a drain should succeed: {error}"));

    assert!(drained.is_empty());
    assert!(shutdown.is_empty());
    assert_eq!(
        lifecycle.inner.loop_impl().event_log().offset(),
        after_drain
    );
}

#[test]
fn refusal_tokens_are_distinct_kebab_case() {
    let refusals = [
        RetentionDrainRefusal::PendingBranchEffectChoices,
        RetentionDrainRefusal::PendingSignalFaultBranches,
        RetentionDrainRefusal::DebugGateway,
        RetentionDrainRefusal::DebugAttach,
        RetentionDrainRefusal::DebugGatewayTeardown,
        RetentionDrainRefusal::IndeterminateDebugCandidate,
        RetentionDrainRefusal::NodeLeaseCleanupFailed,
        RetentionDrainRefusal::RetainedLogAfterGenesis,
        RetentionDrainRefusal::CampaignEffectReplayUnexhausted,
        RetentionDrainRefusal::FaultReplayUnexhausted,
        RetentionDrainRefusal::SearchOverridesUnconsumed,
        RetentionDrainRefusal::Boundary(
            crucible_engine::FinalBoundaryRefusal::PoisonedContinuation,
        ),
        RetentionDrainRefusal::Boundary(
            crucible_engine::FinalBoundaryRefusal::HeldGuestSelectableStop,
        ),
        RetentionDrainRefusal::Boundary(
            crucible_engine::FinalBoundaryRefusal::HeldCampaignMarkerStop,
        ),
        RetentionDrainRefusal::Boundary(crucible_engine::FinalBoundaryRefusal::HeldPeerEvidence),
        RetentionDrainRefusal::Boundary(crucible_engine::FinalBoundaryRefusal::PendingFixedInput),
        RetentionDrainRefusal::Boundary(
            crucible_engine::FinalBoundaryRefusal::RetainedDeviceGroupSelection,
        ),
        RetentionDrainRefusal::Boundary(
            crucible_engine::FinalBoundaryRefusal::LiveNetworkPreselection,
        ),
    ];

    let tokens = refusals
        .iter()
        .map(|refusal| refusal.token())
        .collect::<BTreeSet<_>>();

    assert_eq!(tokens.len(), refusals.len());
    for token in tokens {
        assert!(
            token
                .chars()
                .all(|character| character.is_ascii_lowercase() || character == '-'),
            "{token} is not a kebab-case token"
        );
    }
}
