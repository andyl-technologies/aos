//! Checks T-SCHED-27 scheduler-side control responsiveness.

#![forbid(unsafe_code)]
// crucible-lint: allow panic-shortcut -- test assertions use panic shortcuts for fixture setup and failure localization.
#![allow(clippy::expect_used, clippy::unwrap_used)]

use crucible::{
    ControlOperation, ControlOperationKind, ExactLocalEvent, NetworkLookahead, NodeCounter, NodeId,
    QuantumRequest, SCHEDULER_CONTROL_RESPONSE_BOUND_QUANTA, ScheduledEventPayload, SchedulerActor,
    SchedulerActorHandle, SchedulerActorStateSnapshot, SchedulerLivenessScenario,
    SchedulerNodeActivity, SchedulerNodeId, SchedulerScenarioNode, SchedulingNodeKind, Shift,
    SimDuration, SimInstant, VirtualTime,
};

#[test]
fn actor_control_submitted_before_drive_applies_at_next_boundary() {
    let (handle, mut actor) = scheduler_actor(SchedulerNodeActivity::Runnable);
    let before = actor_snapshot(&handle, &mut actor);
    let first = drive_actor_quantum(&handle, &mut actor, before, Vec::new());
    assert_eq!(first.boundary_yields, 1);
    assert!(first.control_applications.is_empty());

    handle
        .queue_control(control(7, ControlOperationKind::Snapshot))
        .expect("control message should enqueue");
    let reply = handle
        .drive_quantum(QuantumRequest {
            configuration: first.configuration,
            control: Vec::new(),
        })
        .expect("drive message should enqueue");

    actor
        .run_once()
        .expect("actor should accept queued control");
    actor.run_once().expect("actor should drive next quantum");
    let outcome = reply
        .recv()
        .expect("actor should reply")
        .expect("queued control should apply at the next boundary");
    let after = actor_snapshot(&handle, &mut actor);

    assert_eq!(after.pending_control_count, 0);
    assert_eq!(after.boundary_yields, 2);
    assert_eq!(after.control_applications.len(), 1);
    let application = &after.control_applications[0];
    assert_eq!(
        application.operation,
        control(7, ControlOperationKind::Snapshot)
    );
    assert_eq!(application.accepted_after_quanta, 1);
    assert_eq!(application.applied_in_quantum, 1);
    assert_eq!(application.application_delta_quanta, 0);
    assert!(application.application_delta_quanta <= SCHEDULER_CONTROL_RESPONSE_BOUND_QUANTA);
    assert_eq!(application.accepted_after_boundary_yield, 1);
    assert_eq!(application.applied_at_boundary_yield, 1);
    assert_eq!(
        control_event_keys(&outcome.resolved_events),
        vec![application.event_key.clone()]
    );
}

#[test]
fn request_control_applies_before_pick_in_same_quantum() {
    let (handle, mut actor) = scheduler_actor(SchedulerNodeActivity::Runnable);
    let before = actor_snapshot(&handle, &mut actor);
    let after = drive_actor_quantum(
        &handle,
        &mut actor,
        before,
        vec![control(3, ControlOperationKind::Query)],
    );

    assert_eq!(after.boundary_yields, 1);
    assert_eq!(after.control_applications.len(), 1);
    let application = &after.control_applications[0];
    assert_eq!(
        application.operation,
        control(3, ControlOperationKind::Query)
    );
    assert_eq!(application.accepted_after_quanta, 0);
    assert_eq!(application.applied_in_quantum, 0);
    assert_eq!(application.application_delta_quanta, 0);
    assert_eq!(application.accepted_after_boundary_yield, 0);
    assert_eq!(application.applied_at_boundary_yield, 0);
}

#[test]
fn queued_and_request_controls_apply_together_in_boundary_order() {
    let (handle, mut actor) = scheduler_actor(SchedulerNodeActivity::Runnable);
    handle
        .queue_control(control(9, ControlOperationKind::Snapshot))
        .expect("control message should enqueue");
    actor
        .run_once()
        .expect("actor should accept queued control");
    let before = actor_snapshot(&handle, &mut actor);
    let reply = handle
        .drive_quantum(QuantumRequest {
            configuration: before.configuration,
            control: vec![control(4, ControlOperationKind::Query)],
        })
        .expect("drive message should enqueue");

    actor.run_once().expect("actor should drive quantum");
    let outcome = reply
        .recv()
        .expect("actor should reply")
        .expect("mixed controls should apply at the same boundary");
    let after = actor_snapshot(&handle, &mut actor);

    assert_eq!(after.boundary_yields, 1);
    assert_eq!(
        applied_controls(&after),
        vec![
            control(4, ControlOperationKind::Query),
            control(9, ControlOperationKind::Snapshot),
        ]
    );
    assert_eq!(
        after
            .control_applications
            .iter()
            .map(|application| application.application_delta_quanta)
            .collect::<Vec<_>>(),
        vec![0, 0]
    );
    assert_eq!(
        after
            .control_applications
            .iter()
            .map(|application| application.applied_at_boundary_yield)
            .collect::<Vec<_>>(),
        vec![0, 0]
    );
    assert_eq!(
        control_event_keys(&outcome.resolved_events),
        after
            .control_applications
            .iter()
            .map(|application| application.event_key.clone())
            .collect::<Vec<_>>()
    );
}

#[test]
fn actor_drains_submitted_control_before_deferred_drive_messages() {
    let (handle, mut actor) = scheduler_actor(SchedulerNodeActivity::Runnable);
    let before = actor_snapshot(&handle, &mut actor);
    let first_reply = handle
        .drive_quantum(QuantumRequest {
            configuration: before.configuration.clone(),
            control: Vec::new(),
        })
        .expect("first drive message should enqueue");
    let second_reply = handle
        .drive_quantum(QuantumRequest {
            configuration: before.configuration,
            control: Vec::new(),
        })
        .expect("second drive message should enqueue");
    handle
        .queue_control(control(5, ControlOperationKind::Query))
        .expect("control message should enqueue behind drives");

    actor
        .run_once()
        .expect("actor should drain control before first drive");
    let first_outcome = first_reply
        .recv()
        .expect("actor should reply to first drive")
        .expect("first drive should succeed");
    assert_eq!(
        control_kinds(&first_outcome.resolved_events),
        vec![ControlOperationKind::Query]
    );

    actor
        .run_once()
        .expect("actor should process deferred stale drive");
    let stale_error = second_reply
        .recv()
        .expect("actor should reply to second drive")
        .expect_err("deferred drive carries the old frontier configuration");
    assert!(stale_error.to_string().contains("scheduler frontier"));

    let after = actor_snapshot(&handle, &mut actor);
    assert_eq!(
        applied_controls(&after),
        vec![control(5, ControlOperationKind::Query)]
    );
    assert_eq!(after.control_applications[0].application_delta_quanta, 0);
}

#[test]
fn queued_control_only_boundary_does_not_wait_for_runnable_node() {
    let (handle, mut actor) = scheduler_actor(SchedulerNodeActivity::Done);
    let before = actor_snapshot(&handle, &mut actor);
    handle
        .queue_control(control(11, ControlOperationKind::Fork))
        .expect("control message should enqueue");
    let reply = handle
        .drive_quantum(QuantumRequest {
            configuration: before.configuration,
            control: Vec::new(),
        })
        .expect("drive message should enqueue");

    actor
        .run_once()
        .expect("actor should accept queued control");
    actor
        .run_once()
        .expect("actor should drive control-only quantum");
    let outcome = reply
        .recv()
        .expect("actor should reply")
        .expect("control-only quantum should apply control");
    let after = actor_snapshot(&handle, &mut actor);

    assert_eq!(outcome.advanced_node, None);
    assert_eq!(outcome.frontier, VirtualTime { ticks: 0 });
    assert_eq!(after.boundary_yields, 1);
    assert_eq!(after.control_applications.len(), 1);
    let application = &after.control_applications[0];
    assert_eq!(
        application.operation,
        control(11, ControlOperationKind::Fork)
    );
    assert_eq!(application.application_delta_quanta, 0);
    assert_eq!(
        control_event_keys(&outcome.resolved_events),
        vec![application.event_key.clone()]
    );
}

fn drive_actor_quantum(
    handle: &SchedulerActorHandle,
    actor: &mut SchedulerActor,
    before: SchedulerActorStateSnapshot,
    control: Vec<ControlOperation>,
) -> SchedulerActorStateSnapshot {
    let reply = handle
        .drive_quantum(QuantumRequest {
            configuration: before.configuration,
            control,
        })
        .expect("drive message should enqueue");
    actor.run_once().expect("actor should drive quantum");
    reply
        .recv()
        .expect("actor should reply")
        .expect("scheduler actor should drive one quantum");
    actor_snapshot(handle, actor)
}

fn scheduler_actor(activity: SchedulerNodeActivity) -> (SchedulerActorHandle, SchedulerActor) {
    SchedulerActor::new(SchedulerLivenessScenario::from_canonical_material(
        "scheduler-control-responsive",
        shift(0),
        8,
        SimInstant { nanos: 12 },
        vec![SchedulerScenarioNode {
            id: scheduler_node("node-a"),
            counter: NodeCounter { ticks: 0 },
            activity,
            network_lookahead: finite_lookahead(4),
            exact_local_event: ExactLocalEvent::NoArmedTimer,
        }],
        Vec::new(),
    ))
    .expect("valid scheduler actor scenario")
}

fn actor_snapshot(
    handle: &SchedulerActorHandle,
    actor: &mut SchedulerActor,
) -> SchedulerActorStateSnapshot {
    let reply = handle.snapshot().expect("snapshot message should enqueue");
    actor.run_once().expect("actor should process snapshot");
    reply.recv().expect("actor should reply with snapshot")
}

fn control(sequence: u64, kind: ControlOperationKind) -> ControlOperation {
    ControlOperation { sequence, kind }
}

fn control_event_keys(events: &[crucible::ScheduledEvent]) -> Vec<crucible::ScheduledEventKey> {
    events
        .iter()
        .filter_map(|event| match &event.payload {
            ScheduledEventPayload::Control(_) => Some(event.key.clone()),
            _ => None,
        })
        .collect()
}

fn control_kinds(events: &[crucible::ScheduledEvent]) -> Vec<ControlOperationKind> {
    events
        .iter()
        .filter_map(|event| match &event.payload {
            ScheduledEventPayload::Control(operation) => Some(operation.kind.clone()),
            _ => None,
        })
        .collect()
}

fn applied_controls(snapshot: &SchedulerActorStateSnapshot) -> Vec<ControlOperation> {
    snapshot
        .control_applications
        .iter()
        .map(|application| application.operation.clone())
        .collect()
}

fn scheduler_node(name: &str) -> SchedulerNodeId {
    SchedulerNodeId {
        node: NodeId {
            name: name.to_owned(),
        },
        kind: SchedulingNodeKind::Vm,
    }
}

fn shift(bits: u8) -> Shift {
    Shift::new(bits).expect("test shift should be valid")
}

fn finite_lookahead(nanos: u64) -> NetworkLookahead {
    NetworkLookahead::Finite(SimDuration { nanos })
}
