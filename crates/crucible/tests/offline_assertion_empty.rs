//! Checks authenticated empty assertion runs and their intermediate-prefix refusals.

#![forbid(unsafe_code)]

use crucible::{
    AssertionDef, AssertionId, BackendInput, BlackBoxHostOracle, ConditionEvaluationError,
    ContentHash, Decision, EventDiagnosticPayload, EventLevel, FramePredicate, GuestAssertionKind,
    GuestAssertionMarker, HostAssertionEvaluator, HostAssertionOutcomeKind, Icount, NodeId,
    NodeTemplate, ObservableEvent, OfflineAssertionCheckError, OfflineAssertionChecker, Predicate,
    Properties, Property, ReadyPoint, RecordedAssertionLog, RngDecision, RngStreamId,
    ScheduledEvent, ScheduledEventKey, ScheduledEventPayload, SchedulerEvaluationBoundaryKind,
    SchedulerEventLogEntry, SchedulerEventLogPayload, SchedulerNodeId, SchedulingNodeKind,
    SharedTimelineKey, SimInstant, VirtualTime, VmArchitecture, WhiteBoxPolicy, World, WorldNode,
};

type TestResult = Result<(), Box<dyn std::error::Error>>;

fn time(ticks: u64) -> VirtualTime {
    VirtualTime { ticks }
}

fn boundary(sequence: u64, ticks: u64) -> SchedulerEventLogEntry {
    crucible::test_support::condition_boundary_entry_for_test(
        sequence,
        time(ticks),
        SchedulerEvaluationBoundaryKind::Quantum,
    )
}

fn world(policy: WhiteBoxPolicy) -> Result<World, crucible::EngineError> {
    World::from_nodes(vec![WorldNode {
        id: NodeId {
            name: "guest".into(),
        },
        arch: VmArchitecture::X86_64,
        memory_mib: NodeTemplate::DEFAULT_MEMORY_MIB,
        cmdline: String::new(),
        ready_point: ReadyPoint::FixedIcount {
            icount: Icount { retired: 1 },
        },
        white_box: policy,
        smp_vcpus: NodeTemplate::DEFAULT_SMP_VCPUS,
        kernel: None,
        root_image: None,
        initrd: None,
    }])
}

#[test]
fn empty_checker_authenticates_2004_entries_and_matches_terminal_report() -> TestResult {
    let entries: Vec<_> = (0..2004)
        .map(|sequence| boundary(sequence, sequence + 1))
        .collect();
    let canonical_bytes: usize = entries
        .iter()
        .map(SchedulerEventLogEntry::canonical_material_len)
        .sum();
    let world = world(WhiteBoxPolicy::Disabled)?;
    let properties = Properties::empty();

    let report = OfflineAssertionChecker::new()
        .with_world_white_box_policies(&world)
        .check_run(&properties, &entries)?;

    let terminal =
        crucible::test_support::condition_prefix_from_scheduler_entries_for_test(entries)?;
    let expected = HostAssertionEvaluator::new(&properties)
        .with_world_white_box_policies(&world)
        .finalize_prefix(&terminal, &mut BlackBoxHostOracle);
    assert_eq!(report, expected);
    assert!(report.outcomes().is_empty());
    println!("empty_checker_measurement entries=2004 canonical_material_bytes={canonical_bytes}");
    Ok(())
}

#[test]
fn enabled_empty_checker_authenticates_marker_free_runs() -> TestResult {
    let enabled_world = world(WhiteBoxPolicy::Enabled)?;
    let disabled_world = world(WhiteBoxPolicy::Disabled)?;
    let properties = Properties::empty();

    for count in [512_u64, 1024, 2048, 10958] {
        let entries: Vec<_> = (0..count)
            .map(|sequence| boundary(sequence, sequence + 1))
            .collect();
        let canonical_bytes: usize = entries
            .iter()
            .map(SchedulerEventLogEntry::canonical_material_len)
            .sum();

        let enabled = OfflineAssertionChecker::new()
            .with_world_white_box_policies(&enabled_world)
            .check_run(&properties, &entries)?;
        let disabled = OfflineAssertionChecker::new()
            .with_world_white_box_policies(&disabled_world)
            .check_run(&properties, &entries)?;

        assert_eq!(enabled, disabled);
        assert!(enabled.outcomes().is_empty());
        println!(
            "empty_whitebox_checker_measurement entries={count} canonical_material_bytes={canonical_bytes}",
        );
    }
    Ok(())
}

#[test]
fn enabled_empty_checker_matches_published_atomic_batches() -> TestResult {
    let world = world(WhiteBoxPolicy::Enabled)?;
    let checker = OfflineAssertionChecker::new().with_world_white_box_policies(&world);
    let properties = Properties::empty();
    let observation = ObservableEvent::network_delivered(time(5), None, b"atomic".to_vec());

    for count in [512_u64, 1024, 2048, 10958] {
        let mut entries = vec![boundary(0, 10)];
        entries.extend((1..count - 1).map(|sequence| {
            crucible::test_support::condition_observation_entry_for_test(sequence, &observation)
        }));
        entries.push(boundary(count - 1, 10));
        let canonical_bytes: usize = entries
            .iter()
            .map(SchedulerEventLogEntry::canonical_material_len)
            .sum();
        let published = RecordedAssertionLog::from_segments([entries.clone()])?;

        let flat_report = checker.check_run(&properties, &entries)?;
        let published_report =
            checker.check_run_with_oracle(&properties, &published, &mut BlackBoxHostOracle)?;

        assert_eq!(flat_report, published_report);
        assert!(flat_report.outcomes().is_empty());
        println!(
            "atomic_empty_checker_measurement entries={count} canonical_material_bytes={canonical_bytes}",
        );
    }
    Ok(())
}

#[test]
fn enabled_empty_checker_matches_a_late_published_atomic_batch() -> TestResult {
    let world = world(WhiteBoxPolicy::Enabled)?;
    let checker = OfflineAssertionChecker::new().with_world_white_box_policies(&world);
    let properties = Properties::empty();
    let observation = ObservableEvent::network_delivered(time(5), None, b"late atomic".to_vec());

    for count in [512_u64, 1024, 2048, 10958] {
        let mut entries: Vec<_> = (0..count - 3)
            .map(|sequence| boundary(sequence, sequence + 1))
            .collect();
        entries.extend((count - 3..count - 1).map(|sequence| {
            crucible::test_support::condition_observation_entry_for_test(sequence, &observation)
        }));
        entries.push(boundary(count - 1, count));
        let canonical_bytes: usize = entries
            .iter()
            .map(SchedulerEventLogEntry::canonical_material_len)
            .sum();
        let published = RecordedAssertionLog::from_segments([entries.clone()])?;

        let flat_report = checker.check_run(&properties, &entries)?;
        let published_report =
            checker.check_run_with_oracle(&properties, &published, &mut BlackBoxHostOracle)?;

        assert_eq!(flat_report, published_report);
        assert!(flat_report.outcomes().is_empty());
        println!(
            "late_atomic_empty_checker_measurement entries={count} canonical_material_bytes={canonical_bytes}",
        );
    }
    Ok(())
}

fn causal_payloads() -> [SchedulerEventLogPayload; 2] {
    let node = NodeId {
        name: "guest".into(),
    };
    let owner = SchedulerNodeId {
        node: node.clone(),
        kind: SchedulingNodeKind::Vm,
    };
    [
        SchedulerEventLogPayload::Decision(Decision::RngDraw(RngDecision {
            stream: RngStreamId::from_name("atomic-empty"),
            value: 7,
        })),
        SchedulerEventLogPayload::ResolvedHappening(ScheduledEvent {
            key: ScheduledEventKey::new(
                SharedTimelineKey {
                    virtual_time: SimInstant { ticks: 5 },
                    node: owner.clone(),
                    sequence: 0,
                },
                owner,
            ),
            payload: ScheduledEventPayload::BackendInput(BackendInput {
                node,
                payload: b"delivered".to_vec(),
            }),
        }),
    ]
}

fn payload_entry(
    sequence: u64,
    ticks: u64,
    payload: SchedulerEventLogPayload,
) -> SchedulerEventLogEntry {
    let resolved = matches!(payload, SchedulerEventLogPayload::ResolvedHappening(_));
    let entry =
        crucible::test_support::condition_payload_entry_for_test(sequence, time(ticks), payload);
    if resolved {
        crucible::test_support::condition_entry_with_retirement_witness_for_test(
            entry,
            Some(NodeId {
                name: "guest".into(),
            }),
            Icount { retired: 0 },
        )
    } else {
        entry
    }
}

fn assert_future_at_five(entries: &[SchedulerEventLogEntry]) {
    assert!(matches!(
        OfflineAssertionChecker::new().check_run(&Properties::empty(), entries),
        Err(OfflineAssertionCheckError::ConditionEvaluation(
            ConditionEvaluationError::FutureEventLogEntry { point, sequence: 0, event_at }
        )) if point == time(5) && event_at == time(10)
    ));
}

#[test]
fn empty_checker_requires_the_original_first_atomic_boundary() {
    let observation = ObservableEvent::network_delivered(time(5), None, b"atomic".to_vec());
    for causal in causal_payloads() {
        // A later visible causal entry cannot repair the hidden observable prefix.
        assert_future_at_five(&[
            boundary(0, 10),
            crucible::test_support::condition_observation_entry_for_test(1, &observation),
            payload_entry(2, 10, causal.clone()),
            boundary(3, 10),
        ]);
        let diagnostic = SchedulerEventLogPayload::Diagnostic(EventDiagnosticPayload::new(
            "interrupt",
            EventLevel::Info,
            Default::default(),
        ));
        assert_future_at_five(&[
            boundary(0, 10),
            payload_entry(1, 5, causal.clone()),
            payload_entry(2, 10, diagnostic),
            boundary(3, 10),
        ]);
        assert_future_at_five(&[
            boundary(0, 10),
            payload_entry(1, 5, causal.clone()),
            payload_entry(
                2,
                10,
                SchedulerEventLogPayload::Observable(observation.payload().clone()),
            ),
        ]);
        // Terminal visibility is valid, but an earlier causal obligation is unclosed.
        assert_future_at_five(&[
            boundary(0, 10),
            payload_entry(1, 5, causal.clone()),
            payload_entry(2, 10, causal),
        ]);
    }
    let visible = ObservableEvent::network_delivered(time(10), None, b"visible".to_vec());
    assert_future_at_five(&[
        boundary(0, 10),
        crucible::test_support::condition_observation_entry_for_test(1, &observation),
        crucible::test_support::condition_observation_entry_for_test(2, &visible),
    ]);
    // A temporally hidden evaluation boundary remains an original refusal.
    assert_future_at_five(&[
        boundary(0, 10),
        crucible::test_support::condition_observation_entry_for_test(1, &observation),
        boundary(2, 5),
        boundary(3, 10),
    ]);
}

#[test]
fn empty_checker_preserves_causal_batches_offsets_and_authentication() -> TestResult {
    for causal in causal_payloads() {
        let observation = ObservableEvent::network_delivered(time(10), None, b"visible".to_vec());
        let entries = vec![
            boundary(0, 10),
            payload_entry(1, 5, causal),
            crucible::test_support::condition_observation_entry_for_test(2, &observation),
            boundary(3, 10),
        ];
        let checker = OfflineAssertionChecker::new();
        let flat = checker.check_run(&Properties::empty(), &entries)?;
        let atomic = RecordedAssertionLog::from_segments([entries.clone()])?;
        assert_eq!(
            flat,
            checker.check_run_with_oracle(
                &Properties::empty(),
                &atomic,
                &mut BlackBoxHostOracle
            )?
        );

        let published =
            RecordedAssertionLog::from_segments(entries.iter().cloned().map(|entry| vec![entry]))?;
        assert!(matches!(
            checker.check_run_with_oracle(
                &Properties::empty(),
                &published,
                &mut BlackBoxHostOracle
            ),
            Err(OfflineAssertionCheckError::ConditionEvaluation(
                ConditionEvaluationError::FutureEventLogEntry { sequence: 0, .. }
            ))
        ));

        let mut corrupt = entries;
        corrupt[3] = crucible::test_support::condition_entry_with_content_hash_for_test(
            corrupt[3].clone(),
            ContentHash::from_bytes(b"tampered"),
        );
        assert!(matches!(
            checker.check_run(&Properties::empty(), &corrupt),
            Err(OfflineAssertionCheckError::ConditionEvaluation(
                ConditionEvaluationError::InvalidEventLogEntryHash { sequence: 3 }
            ))
        ));
    }
    Ok(())
}

#[test]
fn empty_checker_preserves_terminal_integrity_and_error_precedence() {
    let checker = OfflineAssertionChecker::new();
    let properties = Properties::empty();
    let corrupt = crucible::test_support::condition_entry_with_content_hash_for_test(
        boundary(1, 8),
        ContentHash::from_bytes(b"tampered"),
    );
    // Terminal authentication must precede the intermediate backwards-time refusal.
    assert!(matches!(
        checker.check_run(&properties, &[boundary(0, 10), corrupt, boundary(2, 10)]),
        Err(OfflineAssertionCheckError::ConditionEvaluation(
            ConditionEvaluationError::InvalidEventLogEntryHash { sequence: 1 }
        ))
    ));
    assert!(matches!(
        checker.check_run(&properties, &[boundary(0, 1), boundary(2, 2)]),
        Err(OfflineAssertionCheckError::ConditionEvaluation(
            ConditionEvaluationError::NonPrefixEventLogSequence {
                expected: 1,
                actual: 2
            }
        ))
    ));
    assert!(matches!(
        checker.check_run(&properties, &[boundary(0, 10), boundary(1, 8)]),
        Err(OfflineAssertionCheckError::ConditionEvaluation(
            ConditionEvaluationError::FutureEventLogEntry { sequence: 0, .. }
        ))
    ));
}

#[test]
fn empty_checker_preserves_intermediate_future_entry_refusal() {
    let result = OfflineAssertionChecker::new().check_run(
        &Properties::empty(),
        &[boundary(0, 10), boundary(1, 8), boundary(2, 10)],
    );
    assert!(
        matches!(result, Err(OfflineAssertionCheckError::ConditionEvaluation(
        ConditionEvaluationError::FutureEventLogEntry { point, sequence: 0, event_at }
    )) if point == time(8) && event_at == time(10))
    );
}

#[test]
fn empty_checker_defers_only_unpublished_atomic_observations() -> TestResult {
    let observation = ObservableEvent::network_delivered(time(5), None, b"retained".to_vec());
    let entries = vec![
        boundary(0, 10),
        crucible::test_support::condition_observation_entry_for_test(1, &observation),
        boundary(2, 10),
    ];
    let checker = OfflineAssertionChecker::new();
    assert!(
        checker
            .check_run(&Properties::empty(), &entries)?
            .outcomes()
            .is_empty()
    );

    let recorded =
        RecordedAssertionLog::from_segments(entries.into_iter().map(|entry| vec![entry]))?;
    assert!(matches!(
        checker.check_run_with_oracle(&Properties::empty(), &recorded, &mut BlackBoxHostOracle),
        Err(OfflineAssertionCheckError::ConditionEvaluation(
            ConditionEvaluationError::FutureEventLogEntry { sequence: 0, .. }
        ))
    ));
    assert!(matches!(
        checker.check_run_with_oracle(
            &Properties::empty(),
            &RecordedAssertionLog::from_entries(vec![]),
            &mut BlackBoxHostOracle
        ),
        Err(OfflineAssertionCheckError::MissingEventLogOffset { prefix_len: 0 })
    ));
    Ok(())
}

#[test]
fn host_assertion_retains_earlier_failure_before_terminal_success() -> TestResult {
    let world = world(WhiteBoxPolicy::Disabled)?;
    let properties = Properties::from_assertions_for_world(
        &world,
        vec![AssertionDef {
            id: AssertionId::from_name("ack-always"),
            message: "ack remains visible".into(),
            property: Property::Always {
                predicate: Predicate::network_match(
                    None,
                    FramePredicate::contains(b"ack".to_vec()),
                ),
            },
        }],
    )?;
    let ack = ObservableEvent::network_delivered(time(2), None, b"ack".to_vec());
    let entries = vec![
        boundary(0, 1),
        crucible::test_support::condition_observation_entry_for_test(1, &ack),
        boundary(2, 2),
    ];
    let report = OfflineAssertionChecker::new()
        .with_world_white_box_policies(&world)
        .check_run(&properties, &entries)?;
    assert_eq!(
        report.outcomes()[0].kind,
        HostAssertionOutcomeKind::Violated
    );
    assert_eq!(report.outcomes()[0].at, time(1));
    Ok(())
}

#[test]
fn guest_catalog_declared_properties_and_whitebox_markers_keep_outcomes() -> TestResult {
    let marker = GuestAssertionMarker::new(
        AssertionId::from_name("required"),
        "required marker",
        GuestAssertionKind::Reachable,
        false,
        true,
        vec![],
        "fixture.rs:1",
    );
    let catalog_report = OfflineAssertionChecker::new()
        .with_guest_assertion_catalog([marker.clone()])
        .check_run(&Properties::empty(), &[boundary(0, 1)])?;
    assert_eq!(
        catalog_report.outcomes()[0].kind,
        HostAssertionOutcomeKind::NeverReachedFail
    );

    let world = world(WhiteBoxPolicy::Enabled)?;
    let properties = Properties::from_assertions_for_world(
        &world,
        vec![AssertionDef {
            id: AssertionId::from_name("required"),
            message: "declared marker".into(),
            property: Property::Sometimes {
                predicate: Predicate::guest_marker(crucible::MarkerId::from_name("required")),
            },
        }],
    )?;
    let declared = OfflineAssertionChecker::new()
        .with_world_white_box_policies(&world)
        .check_run(&properties, &[boundary(0, 1)])?;
    assert_eq!(declared.outcomes().len(), 1);

    let observation = ObservableEvent::guest_assertion_marker(
        Icount { retired: 1 },
        NodeId {
            name: "guest".into(),
        },
        marker,
    );
    let entries = vec![
        crucible::test_support::condition_observation_entry_for_test(0, &observation),
        boundary(1, 1),
    ];
    let dynamic = OfflineAssertionChecker::new()
        .with_world_white_box_policies(&world)
        .check_run(&Properties::empty(), &entries)?;
    assert_eq!(
        dynamic.outcomes()[0].kind,
        HostAssertionOutcomeKind::NeverReachedFail
    );
    Ok(())
}

#[test]
fn enabled_markers_retain_earlier_violation_before_later_success() -> TestResult {
    let world = world(WhiteBoxPolicy::Enabled)?;
    let marker = |ticks, condition| {
        ObservableEvent::guest_assertion_marker(
            Icount { retired: ticks },
            NodeId {
                name: "guest".into(),
            },
            GuestAssertionMarker::new(
                AssertionId::from_name("invariant"),
                "guest invariant",
                GuestAssertionKind::Always,
                condition,
                false,
                vec![],
                "fixture.rs:2",
            ),
        )
    };
    let failing = marker(2, false);
    let passing = marker(3, true);
    let entries = vec![
        boundary(0, 1),
        crucible::test_support::condition_observation_entry_for_test(1, &failing),
        boundary(2, 2),
        crucible::test_support::condition_observation_entry_for_test(3, &passing),
        boundary(4, 3),
    ];

    let report = OfflineAssertionChecker::new()
        .with_world_white_box_policies(&world)
        .check_run(&Properties::empty(), &entries)?;

    assert_eq!(report.outcomes().len(), 1);
    assert_eq!(
        report.outcomes()[0].kind,
        HostAssertionOutcomeKind::Violated
    );
    assert_eq!(report.outcomes()[0].at, time(2));
    let terminal =
        crucible::test_support::condition_prefix_from_scheduler_entries_for_test(entries)?;
    assert!(terminal.observable_events().contains(&failing));
    assert!(terminal.observable_events().contains(&passing));
    Ok(())
}

#[test]
fn disabled_and_unknown_node_markers_remain_unobserved() -> TestResult {
    for (policy, marker_node) in [
        (WhiteBoxPolicy::Disabled, "guest"),
        (WhiteBoxPolicy::Enabled, "unknown"),
    ] {
        let world = world(policy)?;
        let observation = ObservableEvent::guest_assertion_marker(
            Icount { retired: 1 },
            NodeId {
                name: marker_node.into(),
            },
            GuestAssertionMarker::new(
                AssertionId::from_name("ignored"),
                "unobserved marker",
                GuestAssertionKind::Always,
                false,
                false,
                vec![],
                "fixture.rs:3",
            ),
        );
        let entries = vec![
            crucible::test_support::condition_observation_entry_for_test(0, &observation),
            boundary(1, 1),
        ];

        let report = OfflineAssertionChecker::new()
            .with_world_white_box_policies(&world)
            .check_run(&Properties::empty(), &entries)?;

        assert!(report.outcomes().is_empty());
    }
    Ok(())
}

#[test]
fn enabled_checker_preserves_marker_authentication_and_prefix_refusals() -> TestResult {
    let world = world(WhiteBoxPolicy::Enabled)?;
    let checker = OfflineAssertionChecker::new().with_world_white_box_policies(&world);
    let observation = ObservableEvent::guest_assertion_marker(
        Icount { retired: 9 },
        NodeId {
            name: "guest".into(),
        },
        GuestAssertionMarker::new(
            AssertionId::from_name("authenticated"),
            "authenticated marker",
            GuestAssertionKind::Always,
            false,
            false,
            vec![],
            "fixture.rs:4",
        ),
    );
    let marker_entry =
        crucible::test_support::condition_observation_entry_for_test(2, &observation);
    let corrupt = crucible::test_support::condition_entry_with_content_hash_for_test(
        marker_entry.clone(),
        ContentHash::from_bytes(b"tampered marker"),
    );

    assert!(matches!(
        checker.check_run(
            &Properties::empty(),
            &[boundary(0, 10), boundary(1, 8), corrupt, boundary(3, 10)],
        ),
        Err(OfflineAssertionCheckError::ConditionEvaluation(
            ConditionEvaluationError::InvalidEventLogEntryHash { sequence: 2 }
        ))
    ));
    for suffix in [marker_entry, boundary(2, 9)] {
        assert!(matches!(
            checker.check_run(
                &Properties::empty(),
                &[boundary(0, 10), boundary(1, 8), suffix, boundary(3, 10)],
            ),
            Err(OfflineAssertionCheckError::ConditionEvaluation(
                ConditionEvaluationError::FutureEventLogEntry { sequence: 0, .. }
            ))
        ));
    }

    assert!(matches!(
        checker.check_run_with_oracle(
            &Properties::empty(),
            &RecordedAssertionLog::from_entries(vec![boundary(0, 1)]),
            &mut BlackBoxHostOracle,
        ),
        Err(OfflineAssertionCheckError::MissingEventLogOffset { prefix_len: 1 })
    ));
    Ok(())
}
