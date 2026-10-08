//! Checks the T-OBS-1 unified event-log append owner.

#![forbid(unsafe_code)]
// crucible-lint: allow panic-shortcut -- test assertions use panic shortcuts for fixture setup and failure localization.
#![allow(clippy::expect_used, clippy::unwrap_used)]

use crucible::{
    Action, Condition, ConditionEvaluationPass, ConditionEventLogPrefix, ContentHash, Event,
    EventEvaluationKind, EventGraph, EventGraphState, EventId, EventLog, EventLogOffset, Icount,
    NodeId, ObservableEvent, SchedulerError, SchedulerEvaluationBoundaryKind,
    SchedulerEventLogClass, SchedulerEventLogEntry, SchedulerEventLogPayload, SimDuration, TimerId,
    TriggerActionApplication, VirtualTime,
};

#[test]
fn event_log_append_path_feeds_offsets_and_condition_projection() {
    let mut log = EventLog::new();
    assert_eq!(log.offset().events, 0);

    let first = crucible::test_support::condition_boundary_entry_for_test(
        0,
        VirtualTime { ticks: 4 },
        SchedulerEvaluationBoundaryKind::Quantum,
    );
    let first_append = log
        .append_entries(vec![first.clone()])
        .expect("first entry should append");

    assert_eq!(first_append.entries, vec![first]);
    assert_eq!(first_append.offset.events, 1);
    assert!(first_append.offset.appended_segment.is_some());
    assert_eq!(log.offset().events, 1);
    assert_eq!(
        log.condition_prefix().point().kind(),
        EventEvaluationKind::QuantumBoundary
    );
    assert_eq!(
        log.condition_prefix().point().at(),
        VirtualTime { ticks: 4 }
    );

    let second = crucible::test_support::condition_boundary_entry_for_test(
        1,
        VirtualTime { ticks: 9 },
        SchedulerEvaluationBoundaryKind::Rendezvous,
    );
    let second_append = log
        .append_entries(vec![second.clone()])
        .expect("second entry should append");

    assert_eq!(second_append.entries, vec![second]);
    assert_eq!(second_append.offset.events, 2);
    assert!(second_append.offset.bytes > first_append.offset.bytes);
    assert_ne!(second_append.offset.prefix, first_append.offset.prefix);
    assert_eq!(log.offset().events, 2);
    assert_eq!(
        log.condition_prefix().point().kind(),
        EventEvaluationKind::RendezvousBoundary
    );
    assert_eq!(
        log.condition_prefix().point().at(),
        VirtualTime { ticks: 9 }
    );
}

#[test]
fn event_log_rejects_non_dense_append_sequence() {
    let mut log = EventLog::new();
    let entry = crucible::test_support::condition_boundary_entry_for_test(
        7,
        VirtualTime { ticks: 4 },
        SchedulerEvaluationBoundaryKind::Quantum,
    );

    let error = log
        .append_entries(vec![entry])
        .expect_err("non-dense sequence should be rejected");

    assert!(matches!(
        error,
        SchedulerError::BoundaryViolation { message }
            if message.contains("does not match expected dense sequence 0")
    ));
    assert_eq!(log.offset().events, 0);
}

fn boundary(sequence: u64, ticks: u64) -> SchedulerEventLogEntry {
    crucible::test_support::condition_boundary_entry_for_test(
        sequence,
        VirtualTime { ticks },
        SchedulerEvaluationBoundaryKind::Quantum,
    )
}

fn console(sequence: u64, ticks: u64) -> SchedulerEventLogEntry {
    crucible::test_support::condition_observation_entry_for_test(
        sequence,
        &ObservableEvent::console_output(
            VirtualTime { ticks },
            NodeId {
                name: String::from("guest"),
            },
            b"ready\n".to_vec(),
        ),
    )
}

#[test]
fn incremental_append_preserves_observations_and_cross_batch_timer_cancellation() {
    let timer = TimerId {
        name: String::from("finish"),
    };
    let event = EventId::from_name("setup");
    let graph = EventGraph::new(vec![Event::once(
        event.clone(),
        Some(Condition::at(VirtualTime { ticks: 3 })),
        Action::Pass,
    )])
    .expect("setup graph should validate");
    let initial = ConditionEventLogPrefix::from_evaluation_boundary(
        0,
        VirtualTime { ticks: 3 },
        SchedulerEvaluationBoundaryKind::Quantum,
    )
    .expect("initial boundary should validate");
    let mut initial_pass =
        ConditionEvaluationPass::from_log_prefix(initial, |_leaf: crucible::ConditionLeaf<'_>| {
            false
        });
    let firings = initial_pass.evaluate_event_graph(&graph, &mut EventGraphState::new());
    assert_eq!(firings.len(), 1);
    let firing = crucible::test_support::condition_payload_entry_for_test(
        1,
        VirtualTime { ticks: 3 },
        SchedulerEventLogPayload::TriggerFired(firings.as_slice()[0].clone()),
    );
    let application = |sequence, ticks, action| {
        crucible::test_support::condition_payload_entry_for_test(
            sequence,
            VirtualTime { ticks },
            SchedulerEventLogPayload::TriggerActionApplied(TriggerActionApplication {
                sequence,
                event: event.clone(),
                at: VirtualTime { ticks },
                path: Vec::new(),
                action,
            }),
        )
    };
    let batches = [
        vec![
            console(0, 3),
            firing,
            application(
                2,
                3,
                Action::arm_timer(timer.clone(), SimDuration { ticks: 10 }),
            ),
            boundary(3, 3),
        ],
        vec![boundary(4, 13)],
        vec![
            application(
                5,
                13,
                Action::CancelTimer {
                    name: timer.clone(),
                },
            ),
            boundary(6, 13),
        ],
        vec![
            application(
                7,
                13,
                Action::arm_timer(timer.clone(), SimDuration { ticks: 2 }),
            ),
            console(8, 15),
            boundary(9, 15),
        ],
    ];
    let mut log = EventLog::new();
    let mut retained = Vec::new();
    for (index, batch) in batches.into_iter().enumerate() {
        retained.extend(batch.iter().cloned());
        let append = log
            .append_entries(batch.clone())
            .expect("valid batch should append");
        assert_eq!(append.entries, batch);
        assert_eq!(log.retained_entries(), retained);

        let rebuilt = ConditionEventLogPrefix::from_scheduler_event_log_entries(retained.clone())
            .expect("complete history should authenticate");
        assert_eq!(log.condition_prefix().point(), rebuilt.point());
        assert_eq!(
            log.condition_prefix().observable_events(),
            rebuilt.observable_events()
        );
        assert_eq!(
            log.condition_prefix().ordering_facts(),
            rebuilt.ordering_facts()
        );
        assert_eq!(
            log.condition_prefix().black_box_observation_kinds(),
            rebuilt.black_box_observation_kinds()
        );
        let oracle = |_leaf: crucible::ConditionLeaf<'_>| false;
        let mut cached =
            ConditionEvaluationPass::from_log_prefix_ref(log.condition_prefix(), oracle);
        let mut fresh = ConditionEvaluationPass::from_log_prefix(rebuilt, oracle);
        let condition = Condition::timer(timer.clone());
        let expected = matches!(index, 1 | 3);
        assert_eq!(cached.evaluate_assertion_condition(&condition), expected);
        assert_eq!(fresh.evaluate_assertion_condition(&condition), expected);
        let elapsed = log.condition_prefix().point().at().ticks - 3;
        let after = Condition::after(SimDuration { ticks: elapsed }, event.clone());
        assert!(cached.evaluate_assertion_condition(&after));
        assert!(fresh.evaluate_assertion_condition(&after));
    }
    assert_eq!(log.offset().events, 10);
    assert_eq!(log.condition_prefix().event_log_offset(), log.offset());
}

#[test]
fn invalid_suffixes_leave_prefix_offsets_and_retained_history_unchanged() {
    let mut original = EventLog::new();
    original
        .append_entries(vec![console(0, 10), boundary(1, 10)])
        .expect("initial history should authenticate");
    let bad_stamp = crucible::test_support::condition_entry_with_retirement_witness_for_test(
        console(2, 11),
        Some(NodeId {
            name: String::from("guest"),
        }),
        Icount { retired: 12 },
    );
    let valid_observation = console(2, 11);
    let bad_class = crucible::test_support::condition_open_payload_entry_for_test(
        2,
        VirtualTime { ticks: 11 },
        SchedulerEventLogClass::Causal,
        valid_observation.event_payload().clone(),
        valid_observation.payload().clone(),
    );
    let cases = [
        (vec![boundary(3, 11)], "dense sequence"),
        (
            vec![
                crucible::test_support::condition_entry_with_content_hash_for_test(
                    boundary(2, 11),
                    ContentHash::default(),
                ),
            ],
            "hash",
        ),
        (vec![boundary(2, 9)], "FutureEventLogEntry"),
        (
            vec![console(2, 9), boundary(3, 11)],
            "OutOfOrderEventLogEntry",
        ),
        (
            vec![bad_stamp, boundary(3, 11)],
            "InvalidBlackBoxObservationStamp",
        ),
        (vec![bad_class, boundary(3, 11)], "catalog class"),
        (vec![console(2, 12), boundary(3, 11)], "FutureEventLogEntry"),
    ];
    for (entries, expected) in cases {
        let mut log = original.clone();
        let error = log
            .append_entries(entries)
            .expect_err("invalid suffix must refuse atomically");
        assert!(
            format!("{error:?}")
                .to_lowercase()
                .contains(&expected.to_lowercase()),
            "{error:?}"
        );
        assert_eq!(log.offset(), original.offset());
        assert_eq!(log.condition_prefix(), original.condition_prefix());
        assert_eq!(log.retained_entries(), original.retained_entries());
        let accepted = log
            .append_entries(vec![console(2, 11), boundary(3, 11)])
            .expect("refusal must not contaminate the next append");
        let mut control = original.clone();
        let expected_append = control
            .append_entries(vec![console(2, 11), boundary(3, 11)])
            .expect("control append should authenticate");
        assert_eq!(accepted, expected_append);
        assert_eq!(log.condition_prefix(), control.condition_prefix());
    }
}

#[test]
fn offset_only_continuation_validates_its_suffix_without_requiring_genesis_entries() {
    let offset = EventLogOffset::new(ContentHash::from_bytes(b"retained-prefix"), 100, 20);
    let mut log = EventLog::from_offset(offset);
    log.append_entries(vec![console(20, 10), boundary(21, 10)])
        .expect("suffix should continue after its authenticated base");
    assert_eq!(log.retained_base_events(), 20);
    assert_eq!(log.retained_entries().len(), 2);
    assert_eq!(log.offset().events, 22);
    let before = log.condition_prefix().clone();
    assert!(log.append_entries(vec![boundary(22, 9)]).is_err());
    assert_eq!(log.condition_prefix(), &before);
    log.append_entries(vec![boundary(22, 11)])
        .expect("later boundary should append");
    assert_eq!(log.offset().events, 23);
}

#[test]
fn atomic_batch_keeps_earlier_diagnostic_times_visible_at_its_final_boundary() {
    let mut log = EventLog::new();
    log.append_entries(vec![boundary(0, 10)])
        .expect("initial boundary should append");
    let diagnostic = crucible::test_support::condition_payload_entry_for_test(
        1,
        VirtualTime { ticks: 5 },
        SchedulerEventLogPayload::Diagnostic(crucible::EventDiagnosticPayload::new(
            "retained.observation",
            crucible::EventLevel::Info,
            std::collections::BTreeMap::new(),
        )),
    );
    assert!(log.append_entries(vec![diagnostic.clone()]).is_err());
    log.append_entries(vec![diagnostic, boundary(2, 12)])
        .expect("atomic final boundary makes both earlier entries visible");
    assert_eq!(log.retained_entries()[1].at(), VirtualTime { ticks: 5 });
    assert_eq!(
        log.condition_prefix().point().at(),
        VirtualTime { ticks: 12 }
    );
}
