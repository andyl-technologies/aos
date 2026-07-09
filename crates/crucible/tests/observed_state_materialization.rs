//! Checks T-ASRT-4 observed-state materialization from event-log prefixes.

#![forbid(unsafe_code)]
// crucible-lint: allow panic-shortcut -- test assertions use panic shortcuts for fixture setup and failure localization.
#![allow(clippy::expect_used, clippy::unwrap_used)]

use crucible::{
    Action, AppRandomDecision, BackendInput, ConditionEvaluationError, ConditionEvaluationPass,
    ConditionLeaf, ConditionLeafOracle, ContentHash, ControlFaultAction, ControlFaultDecision,
    Decision, DeliveryOrderDecision, EventKey, Fault, FaultDecision, FaultId, FaultRateBasisPoints,
    FaultTag, Icount, IrqVector, MembershipFault, NodeFault, NodeId, ObservableEvent,
    ObservedFaultFact, ObservedOrderingFact, OverrideDecision, PreemptionDecision, PreemptionKind,
    RestartPolicy, RngDecision, RngStreamId, ScheduledEvent, ScheduledEventKey,
    ScheduledEventPayload, SchedulerEvaluationBoundaryKind, SchedulerEventLogPayload,
    SchedulerNodeId, SchedulerResolveFaultChoice, SchedulingNodeKind, VcpuId, VirtualTime,
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
    let fault = fault_id("drop-request");

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
                at: Icount { retired: 6 },
                kind: PreemptionKind::InterruptAt {
                    target_vcpu: VcpuId { index: 0 },
                    irq: IrqVector { vector: 33 },
                },
            })),
        ),
        payload_entry(
            6,
            time(6),
            SchedulerEventLogPayload::Decision(Decision::AppRandom(AppRandomDecision {
                node: node("db-0"),
                stream: RngStreamId::from_name("ignored-app-random"),
                request_id: 99,
                width: 32,
                value: 0x1234_5678,
            })),
        ),
        payload_entry(
            7,
            time(6),
            SchedulerEventLogPayload::Decision(Decision::FaultFires(FaultDecision {
                at: time(6),
                fault: fault.clone(),
                fired: true,
            })),
        ),
        boundary_entry(8, time(6)),
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
    assert_eq!(
        state.fault_facts(),
        &[ObservedFaultFact::ProbabilisticOutcome {
            sequence: 7,
            at: time(6),
            fault,
            fired: true,
        }]
    );
    assert_eq!(prefix.ordering_facts(), state.ordering_facts());
    assert_eq!(prefix.fault_facts(), state.fault_facts());
    let expected_observable_events = state.observable_events().to_vec();
    let expected_ordering_facts = state.ordering_facts().to_vec();
    let expected_fault_facts = state.fault_facts().to_vec();

    let pass = ConditionEvaluationPass::from_log_prefix(prefix, NoLeaves);
    assert_eq!(
        pass.observed_state().observable_events(),
        expected_observable_events.as_slice()
    );
    assert_eq!(
        pass.observed_state().ordering_facts(),
        expected_ordering_facts.as_slice()
    );
    assert_eq!(
        pass.observed_state().fault_facts(),
        expected_fault_facts.as_slice()
    );
}

#[test]
fn observed_state_materializes_fault_activation_and_heal_facts() {
    let scheduled_fault = fault_id("scheduled-partition");
    let probabilistic_fault = fault_id("maybe-drop");
    let control_tag = tag("control-crash");
    let trigger_tag = tag("trigger-crash");
    let controlled_fault = Fault::Node(NodeFault::Crash {
        node: node("db-0"),
        restart: RestartPolicy::StayDown,
    });
    let trigger_fault = MembershipFault::Crash {
        node: node("db-0"),
        restart: RestartPolicy::FromReadyPoint,
    };

    let prefix = crucible::test_support::condition_prefix_from_scheduler_entries_for_test(vec![
        payload_entry(
            0,
            time(8),
            SchedulerEventLogPayload::ResolvedHappening(ScheduledEvent {
                key: scheduled_event_key(8, "db-0", "control", 0),
                payload: ScheduledEventPayload::FaultActivation(scheduled_fault.clone()),
            }),
        ),
        payload_entry(
            1,
            time(8),
            SchedulerEventLogPayload::ResolvedHappening(ScheduledEvent {
                key: scheduled_event_key(8, "db-0", "control", 1),
                payload: ScheduledEventPayload::ProbabilisticFault(SchedulerResolveFaultChoice {
                    fault: probabilistic_fault.clone(),
                    stream: RngStreamId::from_name("fault-stream"),
                    rate: FaultRateBasisPoints::from_basis_points(250)
                        .expect("test rate should be in range"),
                }),
            }),
        ),
        payload_entry(
            2,
            time(8),
            SchedulerEventLogPayload::Decision(Decision::ControlFault(ControlFaultDecision {
                at: time(8),
                sequence: 11,
                action: ControlFaultAction::Inject {
                    tag: control_tag.clone(),
                    fault: controlled_fault.clone(),
                },
            })),
        ),
        payload_entry(
            3,
            time(8),
            SchedulerEventLogPayload::Decision(Decision::ControlFault(ControlFaultDecision {
                at: time(8),
                sequence: 12,
                action: ControlFaultAction::Heal {
                    tag: control_tag.clone(),
                },
            })),
        ),
        payload_entry(
            4,
            time(8),
            SchedulerEventLogPayload::TriggerActionApplied(crucible::TriggerActionApplication {
                sequence: 21,
                event: crucible::EventId::from_name("trigger-inject"),
                at: time(8),
                path: vec![0],
                action: Action::InjectFault {
                    tag: trigger_tag.clone(),
                    fault: trigger_fault.clone(),
                },
            }),
        ),
        payload_entry(
            5,
            time(8),
            SchedulerEventLogPayload::TriggerActionApplied(crucible::TriggerActionApplication {
                sequence: 22,
                event: crucible::EventId::from_name("trigger-heal"),
                at: time(8),
                path: vec![1],
                action: Action::HealFault {
                    tag: trigger_tag.clone(),
                },
            }),
        ),
    ])
    .expect("checked prefix should materialize fault facts");

    assert_eq!(
        prefix.observed_state().fault_facts(),
        &[
            ObservedFaultFact::ScheduledActivation {
                sequence: 0,
                at: time(8),
                fault: scheduled_fault,
            },
            ObservedFaultFact::ScheduledProbabilisticChoice {
                sequence: 1,
                at: time(8),
                fault: probabilistic_fault,
            },
            ObservedFaultFact::ControlInjected {
                sequence: 2,
                at: time(8),
                control_sequence: 11,
                tag: control_tag.clone(),
                fault: controlled_fault,
            },
            ObservedFaultFact::ControlHealed {
                sequence: 3,
                at: time(8),
                control_sequence: 12,
                tag: control_tag,
            },
            ObservedFaultFact::TriggerInjected {
                sequence: 4,
                at: time(8),
                trigger_sequence: 21,
                event: crucible::EventId::from_name("trigger-inject"),
                tag: trigger_tag.clone(),
                fault: trigger_fault,
            },
            ObservedFaultFact::TriggerHealed {
                sequence: 5,
                at: time(8),
                trigger_sequence: 22,
                event: crucible::EventId::from_name("trigger-heal"),
                tag: trigger_tag,
            },
        ]
    );
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
    let trigger_source = include_str!("../src/trigger.rs");
    let observed_state_block = trigger_source
        .split("pub struct ObservedState")
        .nth(1)
        .and_then(|tail| {
            tail.split("pub fn lint_host_assertion_harness_source")
                .next()
        })
        .expect("observed-state implementation block should be present");

    for forbidden in [
        "HashMap",
        "HashSet",
        "SystemTime",
        "Instant",
        "std::time",
        "thread::",
    ] {
        assert!(
            !observed_state_block.contains(forbidden),
            "observed-state materialization must not use `{forbidden}`"
        );
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
    ScheduledEventKey::from_parts(
        time(virtual_time),
        scheduler_node(consumer),
        scheduler_node(producer),
        sequence,
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

fn fault_id(name: &str) -> FaultId {
    FaultId {
        name: name.to_owned(),
    }
}

fn tag(name: &str) -> FaultTag {
    FaultTag::from_name(name)
}

fn time(ticks: u64) -> VirtualTime {
    VirtualTime { ticks }
}
