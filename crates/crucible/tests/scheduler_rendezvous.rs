//! Checks the T-SCHED-7 rendezvous frequency/exactness split.

#![forbid(unsafe_code)]
// crucible-lint: allow panic-shortcut -- test assertions use panic shortcuts for fixture setup and failure localization.
#![allow(clippy::expect_used, clippy::unwrap_used)]

use crucible::{
    BackendInput, Decision, ExactLocalEvent, NetworkLookahead, NodeCounter, NodeId, QuantumLoop,
    QuantumRequest, ScheduledEvent, ScheduledEventKey, ScheduledEventPayload, SchedulerActor,
    SchedulerActorHandle, SchedulerActorStateSnapshot, SchedulerError, SchedulerLivenessReport,
    SchedulerLivenessScenario, SchedulerNodeActivity, SchedulerNodeId, SchedulerRendezvous,
    SchedulerScenarioNode, SchedulingNodeKind, Shift, SimDuration, SimInstant, SingleScheduler,
    VirtualTime, check_scheduler_liveness, rendezvous_cap_for,
};

#[test]
fn rendezvous_cap_uses_next_shared_boundary() {
    let rendezvous =
        SchedulerRendezvous::every(SimDuration { nanos: 5 }).expect("interval is nonzero");

    assert_eq!(
        rendezvous_cap_for(SimInstant { nanos: 0 }, rendezvous),
        Ok(Some(SimInstant { nanos: 5 }))
    );
    assert_eq!(
        rendezvous_cap_for(SimInstant { nanos: 5 }, rendezvous),
        Ok(Some(SimInstant { nanos: 10 }))
    );
    assert_eq!(
        rendezvous_cap_for(SimInstant { nanos: 12 }, rendezvous),
        Ok(Some(SimInstant { nanos: 15 }))
    );
    assert_eq!(
        rendezvous_cap_for(SimInstant { nanos: 12 }, SchedulerRendezvous::disabled()),
        Ok(None)
    );
}

#[test]
fn rendezvous_shared_cap_is_frontier_based_not_node_local() {
    let rendezvous =
        SchedulerRendezvous::every(SimDuration { nanos: 5 }).expect("interval is nonzero");

    let shared_frontier_cap = rendezvous_cap_for(SimInstant { nanos: 0 }, rendezvous)
        .expect("frontier cap should compute");
    let ahead_node_local_cap = rendezvous_cap_for(SimInstant { nanos: 7 }, rendezvous)
        .expect("node-local cap should compute");

    assert_eq!(shared_frontier_cap, Some(SimInstant { nanos: 5 }));
    assert_eq!(ahead_node_local_cap, Some(SimInstant { nanos: 10 }));
    assert_ne!(shared_frontier_cap, ahead_node_local_cap);
}

#[test]
fn rendezvous_rejects_zero_interval() {
    let error = SchedulerRendezvous::every(SimDuration { nanos: 0 })
        .expect_err("zero rendezvous interval cannot make progress");

    assert!(matches!(error, SchedulerError::BoundaryViolation { .. }));
    assert!(error.to_string().contains("must be nonzero"));
}

#[test]
fn single_scheduler_rendezvous_caps_without_decision_or_idle() {
    let scenario = SchedulerLivenessScenario::from_canonical_material(
        "rendezvous-cap-no-event",
        shift(0),
        8,
        SimInstant { nanos: 30 },
        vec![scenario_node(
            "node-a",
            0,
            finite_lookahead(30),
            ExactLocalEvent::NoArmedTimer,
        )],
        Vec::new(),
    )
    .with_rendezvous_interval(SimDuration { nanos: 5 })
    .expect("rendezvous interval should be valid");
    let mut scheduler = SingleScheduler::new(scenario).expect("scenario should be valid");

    let first = drive_one_quantum(&mut scheduler);

    assert_eq!(first.advanced_node, Some(scheduler_node("node-a")));
    assert_eq!(first.frontier, VirtualTime { ticks: 5 });
    assert!(first.resolved_events.is_empty());
    assert!(first.decisions.is_empty());
    assert!(first.configuration.schedule.is_empty());

    let second = drive_one_quantum(&mut scheduler);

    assert_eq!(second.advanced_node, Some(scheduler_node("node-a")));
    assert_eq!(second.frontier, VirtualTime { ticks: 10 });
    assert!(second.resolved_events.is_empty());
    assert!(second.decisions.is_empty());
    assert!(second.configuration.schedule.is_empty());
}

#[test]
fn empty_rendezvous_quantum_does_not_advance_decision_rng_cursor() {
    let scenario = SchedulerLivenessScenario::from_canonical_material(
        "rendezvous-cap-no-rng",
        shift(0),
        8,
        SimInstant { nanos: 30 },
        vec![scenario_node(
            "node-a",
            0,
            finite_lookahead(30),
            ExactLocalEvent::NoArmedTimer,
        )],
        Vec::new(),
    )
    .with_rendezvous_interval(SimDuration { nanos: 5 })
    .expect("rendezvous interval should be valid");
    let (handle, mut actor) = SchedulerActor::new(scenario).expect("scenario should be valid");
    let before = actor_snapshot(&handle, &mut actor);

    let reply = handle
        .drive_quantum(QuantumRequest {
            configuration: before.configuration,
            control: Vec::new(),
        })
        .expect("drive message should enqueue");
    actor.run_once().expect("actor should drive quantum");
    let outcome = reply
        .recv()
        .expect("actor should reply")
        .expect("scheduler should drive empty rendezvous quantum");
    let after = actor_snapshot(&handle, &mut actor);

    assert!(outcome.decisions.is_empty());
    assert!(after.decision_rng_cursor.positions.is_empty());
}

#[test]
fn rendezvous_frequency_does_not_change_delivery_order_or_configuration() {
    let consumer = scheduler_node("consumer");
    let producer = scheduler_node("producer");
    let base = SchedulerLivenessScenario::from_canonical_material(
        "rendezvous-frequency-independent-event",
        shift(0),
        8,
        SimInstant { nanos: 20 },
        vec![scenario_node(
            "consumer",
            0,
            finite_lookahead(20),
            ExactLocalEvent::NoArmedTimer,
        )],
        vec![backend_event(12, &consumer, &producer, 77, b"frame")],
    );
    let slow = base
        .clone()
        .with_rendezvous_interval(SimDuration { nanos: 100 })
        .expect("slow rendezvous interval should be valid");
    let fast = base
        .with_rendezvous_interval(SimDuration { nanos: 5 })
        .expect("fast rendezvous interval should be valid");

    let slow_report = check_scheduler_liveness(slow).expect("slow run should terminate");
    let fast_report = check_scheduler_liveness(fast).expect("fast run should terminate");

    assert!(
        fast_report.quanta > slow_report.quanta,
        "fast rendezvous should split advancement into more scheduler quanta"
    );
    assert_eq!(fast_report.frontier, slow_report.frontier);
    assert_eq!(fast_report.resolved_events, slow_report.resolved_events);
    assert_eq!(
        fast_report.final_configuration,
        slow_report.final_configuration
    );
    assert_eq!(
        delivery_order_decisions(&fast_report),
        delivery_order_decisions(&slow_report)
    );
    assert_eq!(delivery_order_decisions(&fast_report), vec![(12, vec![77])]);
}

fn actor_snapshot(
    handle: &SchedulerActorHandle,
    actor: &mut SchedulerActor,
) -> SchedulerActorStateSnapshot {
    let reply = handle.snapshot().expect("snapshot message should enqueue");
    actor.run_once().expect("actor should process snapshot");
    reply.recv().expect("actor should reply with snapshot")
}

fn delivery_order_decisions(report: &SchedulerLivenessReport) -> Vec<(u64, Vec<u64>)> {
    report
        .final_configuration
        .schedule
        .decisions()
        .iter()
        .filter_map(|decision| match decision {
            Decision::DeliveryOrder(order) => Some((
                order.at.ticks,
                order
                    .order
                    .iter()
                    .map(|event_key| event_key.sequence)
                    .collect(),
            )),
            _ => None,
        })
        .collect()
}

fn drive_one_quantum(scheduler: &mut SingleScheduler) -> crucible::QuantumOutcome {
    let request = QuantumRequest {
        configuration: scheduler.configuration().clone(),
        control: Vec::new(),
    };
    scheduler
        .drive_quantum(request)
        .expect("scheduler should drive one quantum")
}

fn scenario_node(
    name: &str,
    counter: u64,
    network_lookahead: NetworkLookahead,
    exact_local_event: ExactLocalEvent,
) -> SchedulerScenarioNode {
    SchedulerScenarioNode {
        id: scheduler_node(name),
        counter: NodeCounter { ticks: counter },
        activity: SchedulerNodeActivity::Runnable,
        network_lookahead,
        exact_local_event,
    }
}

fn scheduler_node(name: &str) -> SchedulerNodeId {
    SchedulerNodeId {
        node: NodeId {
            name: name.to_owned(),
        },
        kind: SchedulingNodeKind::Vm,
    }
}

fn backend_event(
    virtual_time: u64,
    consumer: &SchedulerNodeId,
    producer: &SchedulerNodeId,
    sequence: u64,
    payload: &[u8],
) -> ScheduledEvent {
    ScheduledEvent {
        key: ScheduledEventKey::from_parts(
            VirtualTime {
                ticks: virtual_time,
            },
            consumer.clone(),
            producer.clone(),
            sequence,
        ),
        payload: ScheduledEventPayload::BackendInput(BackendInput {
            node: consumer.node.clone(),
            payload: payload.to_vec(),
        }),
    }
}

fn finite_lookahead(nanos: u64) -> NetworkLookahead {
    NetworkLookahead::Finite(SimDuration { nanos })
}

fn shift(bits: u8) -> Shift {
    Shift::new(bits).expect("test shift should be valid")
}
