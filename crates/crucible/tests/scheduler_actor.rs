//! Checks the T-SCHED-1 scheduler actor boundary.

#![forbid(unsafe_code)]
// crucible-lint: allow panic-shortcut -- test assertions use panic shortcuts for fixture setup and failure localization.
#![allow(clippy::expect_used, clippy::unwrap_used)]

use crucible::{
    Configuration, ControlOperation, ControlOperationKind, ExactLocalEvent, NetworkLookahead,
    NodeCounter, NodeId, QuantumRequest, RngStreamId, ScheduledEventPayload, SchedulerActor,
    SchedulerActorHandle, SchedulerActorStateSnapshot, SchedulerLivenessScenario,
    SchedulerNodeActivity, SchedulerNodeId, SchedulerScenarioNode, SchedulingNodeKind, Shift,
    SimDuration, SimInstant,
};

#[test]
fn scheduler_actor_drains_message_control_inbox_at_quantum_boundary() {
    let (handle, mut actor) = scheduler_actor();
    handle
        .queue_control(control(2, ControlOperationKind::Query))
        .expect("control message should enqueue");
    handle
        .queue_control(control(1, ControlOperationKind::Pause))
        .expect("control message should enqueue");
    actor.run_once().expect("actor should process query");
    actor.run_once().expect("actor should process pause");

    let before = actor_snapshot(&handle, &mut actor);
    assert_eq!(before.pending_control_count, 2);
    assert_eq!(before.boundary_yields, 0);

    let reply = handle
        .drive_quantum(QuantumRequest {
            configuration: before.configuration,
            control: vec![control(3, ControlOperationKind::Snapshot)],
        })
        .expect("drive message should enqueue");
    actor.run_once().expect("actor should drive quantum");
    let outcome = reply
        .recv()
        .expect("actor should reply")
        .expect("scheduler actor should drive one quantum");

    let after = actor_snapshot(&handle, &mut actor);
    assert_eq!(after.pending_control_count, 0);
    assert_eq!(after.boundary_yields, 1);
    assert_eq!(
        control_kinds(&outcome.resolved_events),
        vec![
            ControlOperationKind::Pause,
            ControlOperationKind::Query,
            ControlOperationKind::Snapshot,
        ]
    );
    assert_eq!(
        outcome
            .resolved_events
            .iter()
            .map(|event| event.key.sequence())
            .collect::<Vec<_>>(),
        vec![0, 1, 2]
    );
    assert!(outcome.advanced_node.is_some());
}

#[test]
fn scheduler_actor_owns_decision_rng_cursor_behind_mailbox() {
    let (handle, mut actor) = scheduler_actor();
    let before = actor_snapshot(&handle, &mut actor);
    assert!(before.decision_rng_cursor.positions.is_empty());

    let reply = handle
        .drive_quantum(QuantumRequest {
            configuration: before.configuration,
            control: vec![control(1, ControlOperationKind::Query)],
        })
        .expect("drive message should enqueue");
    actor.run_once().expect("actor should drive quantum");
    reply
        .recv()
        .expect("actor should reply")
        .expect("scheduler actor should advance");

    let after = actor_snapshot(&handle, &mut actor);
    let stream = RngStreamId::new("crucible.scheduler.actor", "quantum");
    assert_eq!(
        after
            .decision_rng_cursor
            .positions
            .get(&stream)
            .map(|position| position.draws),
        Some(1)
    );
}

#[test]
fn scheduler_actor_state_snapshot_is_read_only() {
    let (handle, mut actor) = scheduler_actor();
    let mut snapshot = actor_snapshot(&handle, &mut actor);
    snapshot.node_counters[0].1 = NodeCounter { ticks: 99 };
    snapshot.pending_control_count = 99;

    let fresh = actor_snapshot(&handle, &mut actor);
    assert_eq!(fresh.node_counters[0].1, NodeCounter { ticks: 0 });
    assert_eq!(fresh.pending_control_count, 0);
}

#[test]
fn scheduler_actor_rejects_non_frontier_message() {
    let (handle, mut actor) = scheduler_actor();
    let wrong = Configuration::genesis(crucible::ScenarioDef::from_canonical_material(
        "crucible.scheduler-actor.wrong",
        "wrong-frontier",
    ));

    let reply = handle
        .drive_quantum(QuantumRequest {
            configuration: wrong,
            control: Vec::new(),
        })
        .expect("drive message should enqueue");
    actor.run_once().expect("actor should process rejection");
    let error = reply
        .recv()
        .expect("actor should reply")
        .expect_err("scheduler actor must reject non-frontier callers");

    assert_eq!(
        error.to_string(),
        "quantum request configuration is not the scheduler frontier"
    );
}

fn scheduler_actor() -> (SchedulerActorHandle, SchedulerActor) {
    SchedulerActor::new(SchedulerLivenessScenario::from_canonical_material(
        "scheduler-actor",
        shift(0),
        8,
        SimInstant { nanos: 8 },
        vec![SchedulerScenarioNode {
            id: scheduler_node("node-a"),
            counter: NodeCounter { ticks: 0 },
            activity: SchedulerNodeActivity::Runnable,
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

fn scheduler_node(name: &str) -> SchedulerNodeId {
    SchedulerNodeId {
        node: NodeId {
            name: name.to_owned(),
        },
        kind: SchedulingNodeKind::Vm,
    }
}

fn control(sequence: u64, kind: ControlOperationKind) -> ControlOperation {
    ControlOperation { sequence, kind }
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

fn shift(bits: u8) -> Shift {
    Shift::new(bits).expect("test shift should be valid")
}

fn finite_lookahead(nanos: u64) -> NetworkLookahead {
    NetworkLookahead::Finite(SimDuration { nanos })
}
