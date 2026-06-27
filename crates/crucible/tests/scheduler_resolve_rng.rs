//! Checks T-SCHED-17 seeded probabilistic RESOLVE decisions.

#![forbid(unsafe_code)]

use crucible::{
    Decision, DecisionRecorder, EventKey, ExactLocalEvent, FaultId, NetworkLookahead, NodeCounter,
    NodeId, QuantumLoop, QuantumRequest, RngStreamId, ScheduledEvent, ScheduledEventKey,
    ScheduledEventPayload, SchedulerLivenessScenario, SchedulerNodeActivity, SchedulerNodeId,
    SchedulerResolveFaultChoice, SchedulerScenarioNode, SchedulingNodeKind, Shift, SimDuration,
    SimInstant, SingleScheduler, VirtualTime, resolve_probabilistic_decisions,
};

#[test]
fn probabilistic_resolve_records_rng_draw_and_fault_outcome_in_total_order() {
    let consumer = scheduler_node("consumer", SchedulingNodeKind::Vm);
    let producer_a = scheduler_node("alpha-link", SchedulingNodeKind::Network);
    let producer_b = scheduler_node("beta-link", SchedulingNodeKind::Network);
    let stream_a = RngStreamId::for_link("alpha-link/loss");
    let stream_b = RngStreamId::for_link("beta-link/loss");
    let fault_a = FaultId {
        name: String::from("alpha-loss"),
    };
    let fault_b = FaultId {
        name: String::from("beta-loss"),
    };
    let first = probabilistic_fault_event(4, &consumer, &producer_a, 7, &fault_a, &stream_a, 0);
    let second = probabilistic_fault_event(4, &consumer, &producer_b, 3, &fault_b, &stream_b, 0);
    let mut scheduler = SingleScheduler::new(SchedulerLivenessScenario::from_canonical_material(
        "probabilistic-resolve-order",
        shift(0),
        8,
        SimInstant { nanos: 30 },
        vec![scenario_node("consumer", 0, finite_lookahead(12))],
        vec![second.clone(), first.clone()],
    ))
    .expect("scenario should build");

    let outcome = scheduler
        .drive_quantum(QuantumRequest {
            configuration: scheduler.configuration().clone(),
            control: Vec::new(),
        })
        .expect("scheduler should resolve probabilistic events");

    assert_eq!(outcome.frontier, VirtualTime { ticks: 4 });
    assert_eq!(outcome.resolved_events, vec![first.clone(), second.clone()]);
    assert_eq!(
        delivery_order_keys(&outcome.decisions),
        vec![event_key(&first), event_key(&second)]
    );
    assert_rng_draw(&outcome.decisions[1], &stream_a);
    assert_fault_decision(&outcome.decisions[2], &fault_a, false);
    assert_rng_draw(&outcome.decisions[3], &stream_b);
    assert_fault_decision(&outcome.decisions[4], &fault_b, false);
    assert_eq!(
        outcome.configuration.schedule.decisions(),
        outcome.decisions.as_slice()
    );
}

#[test]
fn probabilistic_resolve_hydrates_streams_from_prior_schedule_decisions() {
    let consumer = scheduler_node("consumer", SchedulingNodeKind::Vm);
    let producer = scheduler_node("link", SchedulingNodeKind::Network);
    let stream = RngStreamId::for_link("link/loss");
    let first_fault = FaultId {
        name: String::from("first-loss"),
    };
    let second_fault = FaultId {
        name: String::from("second-loss"),
    };
    let first = probabilistic_fault_event(3, &consumer, &producer, 0, &first_fault, &stream, 0);
    let second = probabilistic_fault_event(6, &consumer, &producer, 1, &second_fault, &stream, 0);
    let mut scheduler = SingleScheduler::new(SchedulerLivenessScenario::from_canonical_material(
        "probabilistic-resolve-resume",
        shift(0),
        8,
        SimInstant { nanos: 30 },
        vec![scenario_node("consumer", 0, finite_lookahead(12))],
        vec![first, second],
    ))
    .expect("scenario should build");
    let initial_configuration = scheduler.configuration().clone();
    let mut expected = DecisionRecorder::new(initial_configuration);
    let expected_first = expected.draw_u64(stream.clone());
    let expected_second = expected.draw_u64(stream.clone());

    let first_outcome = scheduler
        .drive_quantum(QuantumRequest {
            configuration: scheduler.configuration().clone(),
            control: Vec::new(),
        })
        .expect("first probabilistic quantum should drive");
    let second_outcome = scheduler
        .drive_quantum(QuantumRequest {
            configuration: scheduler.configuration().clone(),
            control: Vec::new(),
        })
        .expect("second probabilistic quantum should drive");

    assert_eq!(first_outcome.frontier, VirtualTime { ticks: 3 });
    assert_eq!(second_outcome.frontier, VirtualTime { ticks: 6 });
    assert_eq!(
        rng_draw_values(scheduler.configuration().schedule.decisions(), &stream),
        vec![expected_first, expected_second]
    );
}

#[test]
fn resolve_probabilistic_decisions_ignores_deterministic_events() {
    let consumer = scheduler_node("consumer", SchedulingNodeKind::Vm);
    let producer = scheduler_node("producer", SchedulingNodeKind::Vm);
    let event = ScheduledEvent {
        key: ScheduledEventKey::from_parts(VirtualTime { ticks: 9 }, consumer.clone(), producer, 0),
        payload: ScheduledEventPayload::FaultActivation(FaultId {
            name: String::from("deterministic-fault"),
        }),
    };
    let configuration = SchedulerLivenessScenario::from_canonical_material(
        "probabilistic-resolve-ignore-deterministic",
        shift(0),
        1,
        SimInstant { nanos: 10 },
        vec![scenario_node("consumer", 0, finite_lookahead(10))],
        vec![event.clone()],
    )
    .canonical_configuration();

    let record = resolve_probabilistic_decisions(configuration.clone(), &[event]);

    assert!(record.decisions.is_empty());
    assert_eq!(record.configuration, configuration);
    assert_eq!(consumer.node.name, "consumer");
}

fn delivery_order_keys(decisions: &[Decision]) -> Vec<EventKey> {
    decisions
        .iter()
        .flat_map(|decision| match decision {
            Decision::DeliveryOrder(order) => order.order.clone(),
            Decision::FaultFires(_)
            | Decision::RngDraw(_)
            | Decision::Override(_)
            | Decision::Preemption(_)
            | Decision::AppRandom(_) => Vec::new(),
        })
        .collect()
}

fn rng_draw_values(decisions: &[Decision], stream: &RngStreamId) -> Vec<u64> {
    decisions
        .iter()
        .filter_map(|decision| match decision {
            Decision::RngDraw(draw) if &draw.stream == stream => Some(draw.value),
            _ => None,
        })
        .collect()
}

fn assert_rng_draw(decision: &Decision, stream: &RngStreamId) {
    assert!(matches!(
        decision,
        Decision::RngDraw(draw) if &draw.stream == stream
    ));
}

fn assert_fault_decision(decision: &Decision, fault: &FaultId, fired: bool) {
    assert!(matches!(
        decision,
        Decision::FaultFires(recorded) if &recorded.fault == fault
            && recorded.at == VirtualTime { ticks: 4 }
            && recorded.fired == fired
    ));
}

fn event_key(event: &ScheduledEvent) -> EventKey {
    EventKey::new(
        event.key.virtual_time(),
        event.key.consumer().clone(),
        event.key.producer().clone(),
        event.key.sequence(),
    )
}

fn probabilistic_fault_event(
    virtual_time: u64,
    consumer: &SchedulerNodeId,
    producer: &SchedulerNodeId,
    sequence: u64,
    fault: &FaultId,
    stream: &RngStreamId,
    fire_below: u64,
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
        payload: ScheduledEventPayload::ProbabilisticFault(SchedulerResolveFaultChoice {
            fault: fault.clone(),
            stream: stream.clone(),
            fire_below,
        }),
    }
}

fn scenario_node(
    name: &str,
    counter: u64,
    network_lookahead: NetworkLookahead,
) -> SchedulerScenarioNode {
    SchedulerScenarioNode {
        id: scheduler_node(name, SchedulingNodeKind::Vm),
        counter: NodeCounter { ticks: counter },
        activity: SchedulerNodeActivity::Runnable,
        network_lookahead,
        exact_local_event: ExactLocalEvent::NoArmedTimer,
    }
}

fn finite_lookahead(nanos: u64) -> NetworkLookahead {
    NetworkLookahead::Finite(SimDuration { nanos })
}

fn scheduler_node(name: &str, kind: SchedulingNodeKind) -> SchedulerNodeId {
    SchedulerNodeId {
        node: node(name),
        kind,
    }
}

fn node(name: &str) -> NodeId {
    NodeId {
        name: name.to_owned(),
    }
}

fn shift(bits: u8) -> Shift {
    Shift::new(bits).expect("test shift should be valid")
}
