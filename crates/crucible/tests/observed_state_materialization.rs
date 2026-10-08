//! Checks T-ASRT-4 observed-state materialization from event-log prefixes.

#![forbid(unsafe_code)]
// crucible-lint: allow panic-shortcut -- test assertions use panic shortcuts for fixture setup and failure localization.
#![allow(clippy::expect_used, clippy::unwrap_used)]

use crucible::{
    BackendInput, ConditionEvaluationError, ConditionEvaluationPass, ConditionLeaf,
    ConditionLeafOracle, ContentHash, Decision, DeliveryOrderDecision, EventKey, IrqVector, NodeId,
    ObservableEvent, ObservedOrderingFact, OverrideDecision, PreemptionDecision, PreemptionKind,
    RngDecision, RngStreamId, ScheduledEvent, ScheduledEventKey, ScheduledEventPayload,
    SchedulerEvaluationBoundaryKind, SchedulerEventLogPayload, SchedulerNodeId, SchedulingNodeKind,
    VcpuId, VirtualTime,
};

#[test]
fn observed_state_materializes_only_checked_event_log_prefix() {
    let console = ObservableEvent::console_output(time(5), node("db-0"), b"ready\n".to_vec());
    let scheduled_key = scheduled_event_key(6, "db-0", "client", 3);
    let delivery_key = delivery_event_key(6, "db-0", "client", 3);
    let delivery = ScheduledEvent {
        key: scheduled_key.clone(),
        payload: ScheduledEventPayload::BackendInput(BackendInput {
            node: node("db-0"),
            payload: b"frame".to_vec(),
        }),
    };
    let prefix = crucible::test_support::condition_prefix_from_scheduler_entries_for_test(vec![
        observation_entry(0, &console),
        payload_entry(
            1,
            time(6),
            SchedulerEventLogPayload::ResolvedHappening(delivery),
        ),
        payload_entry(
            2,
            time(6),
            SchedulerEventLogPayload::Decision(Decision::DeliveryOrder(DeliveryOrderDecision {
                at: time(6),
                order: vec![delivery_key.clone()],
            })),
        ),
        payload_entry(
            3,
            time(6),
            SchedulerEventLogPayload::Decision(Decision::RngDraw(RngDecision {
                stream: RngStreamId::from_name("ignored-rng"),
                value: 0xfeed_beef,
            })),
        ),
        payload_entry(
            4,
            time(6),
            SchedulerEventLogPayload::Decision(Decision::Override(OverrideDecision {
                point: crucible::SchedulingPoint {
                    key: String::from("ignored-override"),
                },
                choice: crucible::ChoiceTag {
                    name: String::from("ignored-choice"),
                },
            })),
        ),
        payload_entry(
            5,
            time(6),
            SchedulerEventLogPayload::Decision(Decision::Preemption(PreemptionDecision {
                node: node("db-0"),
                at: crucible::SimInstant { ticks: 6 },
                kind: PreemptionKind::InterruptAt {
                    target_vcpu: VcpuId { index: 0 },
                    irq: IrqVector { vector: 33 },
                },
            })),
        ),
        payload_entry(
            6,
            time(6),
            SchedulerEventLogPayload::Decision(Decision::RngDraw(RngDecision {
                stream: RngStreamId::from_name("ignored-app-random"),
                value: 0x1234_5678,
            })),
        ),
        boundary_entry(7, time(6)),
    ])
    .expect("checked prefix should materialize observed state");
    let state = prefix.observed_state();

    assert_eq!(state.at(), time(6));
    assert_eq!(state.observable_events(), &[console]);
    assert_eq!(
        state.ordering_facts(),
        &[
            ObservedOrderingFact::ResolvedHappening {
                sequence: 1,
                at: time(6),
                key: scheduled_key,
                class: crucible::ScheduledEventResolveClass::FrameDelivery,
            },
            ObservedOrderingFact::DeliveryOrder {
                sequence: 2,
                at: time(6),
                order: vec![delivery_key],
            },
        ]
    );
    assert_eq!(prefix.ordering_facts(), state.ordering_facts());
    let expected_observable_events = state.observable_events().to_vec();
    let expected_ordering_facts = state.ordering_facts().to_vec();

    let borrowed = ConditionEvaluationPass::from_log_prefix_ref(&prefix, NoLeaves);
    let pass = ConditionEvaluationPass::from_log_prefix(prefix, NoLeaves);
    assert_eq!(borrowed.point(), pass.point());
    assert_eq!(borrowed.observed_state(), pass.observed_state());
    assert_eq!(
        pass.observed_state().observable_events(),
        expected_observable_events.as_slice()
    );
    assert_eq!(
        pass.observed_state().ordering_facts(),
        expected_ordering_facts.as_slice()
    );
}

#[test]
fn borrowed_projection_preserves_event_timer_and_once_histories() {
    use crucible::{
        Action, Condition, Event, EventGraph, EventGraphState, EventId, SimDuration, TimerId,
        TriggerActionApplication,
    };

    let anchor = EventId::from_name("anchor");
    let timer = TimerId {
        name: String::from("finish"),
    };
    let initial = EventGraph::new(vec![Event::once(
        anchor.clone(),
        Some(Condition::at(time(3))),
        Action::arm_timer(timer.clone(), SimDuration { ticks: 10 }),
    )])
    .expect("initial graph should validate");
    let initial_prefix = crucible::ConditionEventLogPrefix::from_evaluation_boundary(
        0,
        time(3),
        SchedulerEvaluationBoundaryKind::Quantum,
    )
    .expect("initial boundary should validate");
    let mut initial_pass = ConditionEvaluationPass::from_log_prefix(initial_prefix, NoLeaves);
    let initial_firings = initial_pass.evaluate_event_graph(&initial, &mut EventGraphState::new());
    let firing = initial_firings.as_slice()[0].clone();
    let prefix = crucible::test_support::condition_prefix_from_scheduler_entries_for_test(vec![
        payload_entry(0, time(3), SchedulerEventLogPayload::TriggerFired(firing)),
        payload_entry(
            1,
            time(3),
            SchedulerEventLogPayload::TriggerActionApplied(TriggerActionApplication {
                sequence: 0,
                event: anchor.clone(),
                at: time(3),
                path: Vec::new(),
                action: Action::arm_timer(timer.clone(), SimDuration { ticks: 10 }),
            }),
        ),
        boundary_entry(2, time(13)),
    ])
    .expect("runtime facts should form a checked prefix");
    let once = Condition::Once {
        predicate: Box::new(Condition::at(time(13))),
    };
    let conditions = [
        (
            Condition::after(SimDuration { ticks: 10 }, anchor.clone()),
            true,
        ),
        (Condition::after(SimDuration { ticks: 11 }, anchor), false),
        (Condition::timer(timer), true),
        (
            Condition::timer(TimerId {
                name: String::from("absent"),
            }),
            false,
        ),
        (once.clone(), true),
    ];
    let mut owned = ConditionEvaluationPass::from_log_prefix(prefix.clone(), NoLeaves);
    let mut borrowed = ConditionEvaluationPass::from_log_prefix_ref(&prefix, NoLeaves);

    assert_eq!(borrowed.point(), owned.point());
    assert_eq!(borrowed.observed_state(), owned.observed_state());
    for (condition, expected) in conditions {
        assert_eq!(owned.evaluate_assertion_condition(&condition), expected);
        assert_eq!(borrowed.evaluate_assertion_condition(&condition), expected);
    }
    assert_eq!(borrowed.once_latches(), &[Condition::at(time(13))]);
    assert_eq!(borrowed.once_latches(), owned.once_latches());

    let graph = EventGraph::new(vec![Event::once(
        EventId::from_name("finish"),
        Some(once.clone()),
        Action::Pass,
    )])
    .expect("completion graph should validate");
    let mut owned_state = EventGraphState::new();
    let mut borrowed_state = EventGraphState::new();
    let borrowed_firings = borrowed.evaluate_event_graph(&graph, &mut borrowed_state);
    let owned_firings = owned.evaluate_event_graph(&graph, &mut owned_state);
    assert_eq!(borrowed_firings.len(), 1);
    assert_eq!(borrowed_firings.as_slice()[0].action(), &Action::Pass);
    assert_eq!(borrowed_firings, owned_firings);
    assert_eq!(
        borrowed_state.to_compact_binary(),
        owned_state.to_compact_binary()
    );

    let later = crucible::ConditionEventLogPrefix::from_evaluation_boundary(
        0,
        time(14),
        SchedulerEvaluationBoundaryKind::Quantum,
    )
    .expect("later boundary should validate");
    let mut restored = ConditionEvaluationPass::from_log_prefix_ref(&later, NoLeaves)
        .with_once_latches(borrowed.once_latches().to_vec());
    assert!(restored.evaluate_assertion_condition(&once));
}

#[test]
fn fault_evidence_does_not_expose_internal_state_to_assertion_predicates() {
    use crucible::model::{FaultCoordinate, FaultObservation, FaultObservationKind};

    let observation = FaultObservation {
        semantic_version: 1,
        kind: FaultObservationKind::EffectApplied,
        coordinate: FaultCoordinate {
            virtual_ticks: 5,
            retired_instructions: Some(5),
        },
        binding: None,
        target: None,
        opportunity: None,
        evidence: ContentHash::from_bytes(b"internal fault evidence"),
    };
    let entry = payload_entry(
        0,
        time(5),
        SchedulerEventLogPayload::FaultObservation(observation),
    );
    let prefix =
        crucible::test_support::condition_prefix_from_scheduler_entries_for_test(vec![entry])
            .expect("typed fault evidence should form a checked prefix");

    let state = prefix.observed_state();
    assert!(state.observable_events().is_empty());
    assert!(state.ordering_facts().is_empty());
}

#[test]
fn observed_state_rejects_future_invalid_or_non_dense_prefixes() {
    let future = ObservableEvent::console_output(time(9), node("db-0"), b"future\n".to_vec());
    let invalid_hash = crucible::test_support::condition_entry_with_content_hash_for_test(
        boundary_entry(0, time(8)),
        ContentHash::default(),
    );

    assert_eq!(
        crucible::test_support::condition_prefix_from_scheduler_entries_for_test(vec![
            observation_entry(0, &future),
            boundary_entry(1, time(8)),
        ]),
        Err(ConditionEvaluationError::FutureEventLogEntry {
            point: time(8),
            sequence: 0,
            event_at: time(9),
        })
    );
    assert_eq!(
        crucible::test_support::condition_prefix_from_scheduler_entries_for_test(vec![
            invalid_hash
        ]),
        Err(ConditionEvaluationError::InvalidEventLogEntryHash { sequence: 0 })
    );
    assert_eq!(
        crucible::test_support::condition_prefix_from_scheduler_entries_for_test(vec![
            boundary_entry(1, time(8)),
        ]),
        Err(ConditionEvaluationError::NonPrefixEventLogSequence {
            expected: 0,
            actual: 1,
        })
    );
}

#[test]
fn observed_state_implementation_avoids_host_time_and_unordered_maps() {
    let trigger_source = include_str!("../src/trigger/conditions.rs");
    let observed_state_block = trigger_source
        .split("pub struct ObservedState")
        .nth(1)
        .expect("observed-state implementation block should be present");
    let host_oracle_source = include_str!("../src/trigger/conditions/host_oracle.rs");
    let (host_oracle_block, _) = host_oracle_source
        .split_once("pub fn lint_host_assertion_harness_source")
        .expect("host-oracle lint boundary should be present");

    for forbidden in [
        "HashMap",
        "HashSet",
        "SystemTime",
        "Instant",
        "std::time",
        "thread::",
    ] {
        for block in [observed_state_block, host_oracle_block] {
            assert!(
                !block.contains(forbidden),
                "observed-state materialization and host oracles must not use `{forbidden}`"
            );
        }
    }
}

#[derive(Clone, Debug)]
struct NoLeaves;

impl ConditionLeafOracle for NoLeaves {
    fn leaf_is_true(&mut self, leaf: ConditionLeaf<'_>) -> bool {
        match leaf {
            ConditionLeaf::Named { .. } | ConditionLeaf::GuestMarker { .. } => {
                panic!("observed-state tests do not evaluate named leaves")
            }
        }
    }
}

fn observation_entry(sequence: u64, event: &ObservableEvent) -> crucible::SchedulerEventLogEntry {
    crucible::test_support::condition_observation_entry_for_test(sequence, event)
}

fn boundary_entry(sequence: u64, at: VirtualTime) -> crucible::SchedulerEventLogEntry {
    crucible::test_support::condition_boundary_entry_for_test(
        sequence,
        at,
        SchedulerEvaluationBoundaryKind::Quantum,
    )
}

fn payload_entry(
    sequence: u64,
    at: VirtualTime,
    payload: SchedulerEventLogPayload,
) -> crucible::SchedulerEventLogEntry {
    crucible::test_support::condition_payload_entry_for_test(sequence, at, payload)
}

fn scheduled_event_key(
    virtual_time: u64,
    consumer: &str,
    producer: &str,
    sequence: u64,
) -> ScheduledEventKey {
    ScheduledEventKey::new(
        crucible::SharedTimelineKey {
            virtual_time: crucible::SimInstant {
                ticks: (time(virtual_time)).ticks,
            },
            node: scheduler_node(consumer),
            sequence,
        },
        scheduler_node(producer),
    )
}

fn delivery_event_key(
    virtual_time: u64,
    consumer: &str,
    producer: &str,
    sequence: u64,
) -> EventKey {
    EventKey::new(
        time(virtual_time),
        scheduler_node(consumer),
        scheduler_node(producer),
        sequence,
    )
}

fn scheduler_node(name: &str) -> SchedulerNodeId {
    SchedulerNodeId {
        node: node(name),
        kind: SchedulingNodeKind::Vm,
    }
}

fn node(name: &str) -> NodeId {
    NodeId {
        name: name.to_owned(),
    }
}

fn time(ticks: u64) -> VirtualTime {
    VirtualTime { ticks }
}
