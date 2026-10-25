//! Packaged lifecycle status across thin-attempt world retention.
//!
//! A world drained for retention stops running without a teardown. Its
//! status must move to post-processing at the drain and stay valid whether
//! the world becomes a retained source or is shut down after preparation
//! declines; only abandoning an unfinished lifecycle invalidates status.

use super::*;
use crate::QemuFinalBoundaryDrain;
use crate::managed_qemu_hot_fork_source_world_pool::test_support::advanced_published_root_source_for_test;
use crate::packaged_qemu_executor::status::{
    PackagedAttemptLifecycleLease, PackagedStatusLifecycle,
};
use crate::qemu_campaign_lifecycle::test_support::{RetentionFactory, Script};

type StatusLifecycle =
    PackagedStatusLifecycle<<RetentionFactory as QemuFreshAttemptLifecycleFactory>::Lifecycle>;

/// Starts one scripted attempt under a packaged status lease.
fn start_tracked(
    script: Script,
    execution_byte: u8,
) -> (
    PackagedStatusLifecycleFactory<RetentionFactory>,
    StatusLifecycle,
    PackagedWorldLifecycleTracker,
    PackagedAttemptLifecycleLease,
    ExecutionId,
) {
    let source = crucible::crash_restart_scenario()
        .expect("built-in scenario")
        .scenario;
    let scenario = source.scenario_def();
    let start = Configuration::genesis(scenario.clone());
    let execution = ExecutionId::from_bytes([execution_byte; 16]).expect("execution");
    let context = AttemptExecutionContext::new(
        resources(),
        ExecutionRetentionIntent::Discard,
        ExecutionCancellation::default(),
        ExecutionCheckpointRequest::default(),
        crucible_campaign::AttemptRetentionPolicyDisposition::Disabled,
    )
    .with_runtime_basis(AttemptExecutionRuntimeBasis::new(
        AttemptExecutionKey::new(
            CampaignLineageId::parse(&format!(
                "crucible.campaign.lineage@campaign-fact.1.{}",
                format!("{execution_byte:02x}").repeat(32)
            ))
            .expect("lineage"),
            AttemptId::parse(&format!(
                "crucible.campaign.attempt@campaign-fact.9.{}",
                format!("{execution_byte:02x}").repeat(32)
            ))
            .expect("attempt"),
        ),
        execution,
    ));

    let tracker = PackagedWorldLifecycleTracker::new();
    let lease = tracker.begin(execution);
    let mut factory = PackagedStatusLifecycleFactory {
        inner: RetentionFactory::new(Arc::new(Mutex::new(Vec::new())), script),
        lifecycles: tracker.clone(),
    };
    let lifecycle = factory
        .start_fresh_lifecycle(
            &scenario,
            &source,
            &start,
            &crucible::SignalFaultCampaignReplayPlan::empty(start.clone()),
            &context,
        )
        .expect("start tracked lifecycle");
    (factory, lifecycle, tracker, lease, execution)
}

fn phase(
    tracker: &PackagedWorldLifecycleTracker,
    execution: ExecutionId,
) -> Option<PackagedWorldLifecyclePhase> {
    tracker
        .snapshot()
        .expect("valid lifecycle status")
        .phases
        .get(&execution)
        .copied()
}

#[test]
fn retained_world_finishes_its_packaged_lifecycle_without_invalidation() {
    let world = advanced_published_root_source_for_test("status.retained");
    let (mut factory, mut lifecycle, tracker, lease, execution) = start_tracked(
        Script::new(QemuFinalBoundaryDrain::Retainable).preparing(world),
        0x71,
    );
    assert_eq!(
        phase(&tracker, execution),
        Some(PackagedWorldLifecyclePhase::Running)
    );

    assert_eq!(
        lifecycle
            .drain_final_events_for_retention()
            .expect("drain final boundary"),
        QemuFinalBoundaryDrain::Retainable
    );
    assert_eq!(
        phase(&tracker, execution),
        Some(PackagedWorldLifecyclePhase::PostProcessing)
    );

    let boundary = Configuration::genesis(
        crucible::crash_restart_scenario()
            .expect("built-in scenario")
            .scenario
            .scenario_def(),
    );
    let source = crucible::crash_restart_scenario()
        .expect("built-in scenario")
        .scenario;
    let crate::QemuRetainedSourcePreparation::Prepared(world) = factory.prepare_retained_source(
        lifecycle,
        &source,
        &boundary,
        &crucible::SignalFaultCampaignReplayPlan::empty(boundary.clone()),
    ) else {
        panic!("the scripted preparation yields a source world")
    };

    // Conversion finished the attempt's lifecycle, so the separated status
    // dropped cleanly and the lease can finish from post-processing.
    assert_eq!(
        phase(&tracker, execution),
        Some(PackagedWorldLifecyclePhase::PostProcessing)
    );
    lease.finish();
    assert_eq!(phase(&tracker, execution), None);
    world.retire().expect("retire retained world");
}

#[test]
fn declined_preparation_shuts_down_from_post_processing() {
    let (mut factory, mut lifecycle, tracker, lease, execution) =
        start_tracked(Script::new(QemuFinalBoundaryDrain::Retainable), 0x72);
    lifecycle
        .drain_final_events_for_retention()
        .expect("drain final boundary");

    let source = crucible::crash_restart_scenario()
        .expect("built-in scenario")
        .scenario;
    let boundary = Configuration::genesis(source.scenario_def());
    let crate::QemuRetainedSourcePreparation::Recovered(mut lifecycle) = factory
        .prepare_retained_source(
            lifecycle,
            &source,
            &boundary,
            &crucible::SignalFaultCampaignReplayPlan::empty(boundary.clone()),
        )
    else {
        panic!("the scripted preparation declines")
    };
    assert!(
        lifecycle
            .shutdown()
            .expect("shut down declined world")
            .is_empty()
    );
    drop(lifecycle);

    assert_eq!(
        phase(&tracker, execution),
        Some(PackagedWorldLifecyclePhase::PostProcessing)
    );
    lease.finish();
    assert_eq!(phase(&tracker, execution), None);
}

#[test]
fn abandoning_a_drained_lifecycle_invalidates_status() {
    let (_factory, mut lifecycle, tracker, _lease, _execution) =
        start_tracked(Script::new(QemuFinalBoundaryDrain::Retainable), 0x73);
    lifecycle
        .drain_final_events_for_retention()
        .expect("drain final boundary");

    drop(lifecycle);

    assert!(tracker.snapshot().is_none());
}
