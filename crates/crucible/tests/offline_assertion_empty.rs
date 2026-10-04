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

fn sparse_marker(
    ticks: u64,
    kind: GuestAssertionKind,
    condition: bool,
    must_hit: bool,
) -> ObservableEvent {
    ObservableEvent::guest_assertion_marker(
        Icount { retired: ticks },
        NodeId {
            name: "guest".into(),
        },
        GuestAssertionMarker::new(
            AssertionId::from_name("sparse"),
            format!("marker at {ticks}"),
            kind,
            condition,
            must_hit,
            vec![],
            format!("fixture.rs:{ticks}"),
        ),
    )
}

fn marker_entry(sequence: u64, marker: &ObservableEvent) -> SchedulerEventLogEntry {
    crucible::test_support::condition_observation_entry_for_test(sequence, marker)
}

fn published_report(
    checker: &OfflineAssertionChecker,
    properties: &Properties,
    entries: &[SchedulerEventLogEntry],
) -> Result<crucible::HostAssertionReport, OfflineAssertionCheckError> {
    // Explicit offsets retain the original every-prefix checker path.
    let recorded =
        RecordedAssertionLog::from_segments(entries.iter().cloned().map(|entry| vec![entry]))?;
    checker.check_run_with_oracle(properties, &recorded, &mut BlackBoxHostOracle)
}

#[test]
fn sparse_markers_match_original_prefix_reports_for_every_kind_and_update() -> TestResult {
    let world = world(WhiteBoxPolicy::Enabled)?;
    let checker = OfflineAssertionChecker::new().with_world_white_box_policies(&world);
    let properties = Properties::empty();

    for kind in [
        GuestAssertionKind::Always,
        GuestAssertionKind::Sometimes,
        GuestAssertionKind::Reachable,
        GuestAssertionKind::Unreachable,
    ] {
        for first in [false, true] {
            for later_kind in [kind, GuestAssertionKind::Always] {
                let first_marker = sparse_marker(2, kind, first, false);
                let update = sparse_marker(5, later_kind, !first, true);
                let entries = vec![
                    boundary(0, 1),
                    marker_entry(1, &first_marker),
                    boundary(2, 3),
                    boundary(3, 4),
                    marker_entry(4, &update),
                    boundary(5, 6),
                ];

                let sparse = checker.check_run(&properties, &entries)?;
                let original = published_report(&checker, &properties, &entries)?;

                assert_eq!(
                    sparse, original,
                    "kind={kind:?} first={first} update={later_kind:?}"
                );
            }
        }
    }
    Ok(())
}

#[test]
fn sparse_marker_observes_first_visible_atomic_prefix_before_closing_boundary() -> TestResult {
    let world = world(WhiteBoxPolicy::Enabled)?;
    let checker = OfflineAssertionChecker::new().with_world_white_box_policies(&world);
    let marker = sparse_marker(5, GuestAssertionKind::Always, false, false);
    let hidden = ObservableEvent::network_delivered(time(9), None, b"hidden".to_vec());
    let visible = ObservableEvent::network_delivered(time(10), None, b"visible".to_vec());
    let entries = vec![
        boundary(0, 10),
        marker_entry(1, &marker),
        marker_entry(2, &hidden),
        marker_entry(3, &visible),
        boundary(4, 11),
    ];
    let published = RecordedAssertionLog::from_segments([
        entries[..1].to_vec(),
        entries[1..4].to_vec(),
        entries[4..].to_vec(),
    ])?;

    let sparse = checker.check_run(&Properties::empty(), &entries)?;
    let original =
        checker.check_run_with_oracle(&Properties::empty(), &published, &mut BlackBoxHostOracle)?;

    assert_eq!(sparse, original);
    assert_eq!(
        sparse.outcomes()[0].kind,
        HostAssertionOutcomeKind::Violated
    );
    assert_eq!(sparse.outcomes()[0].at, time(10));
    Ok(())
}

#[test]
fn sparse_marker_reports_match_at_flight_scale_without_implicit_observations() -> TestResult {
    let world = world(WhiteBoxPolicy::Enabled)?;
    let properties = Properties::empty();
    let checker = OfflineAssertionChecker::new().with_world_white_box_policies(&world);

    for count in [512_u64, 1024, 2048, 10952] {
        let mut entries: Vec<_> = (0..count)
            .map(|sequence| boundary(sequence, sequence + 1))
            .collect();
        entries[32] = marker_entry(
            32,
            &sparse_marker(33, GuestAssertionKind::Reachable, true, true),
        );
        let marker_prefix =
            crucible::test_support::condition_prefix_from_scheduler_entries_for_test(
                entries[..33].to_vec(),
            )?;
        let terminal = crucible::test_support::condition_prefix_from_scheduler_entries_for_test(
            entries.clone(),
        )?;
        let mut original_evaluator =
            HostAssertionEvaluator::new(&properties).with_world_white_box_policies(&world);
        original_evaluator.observe_prefix(&marker_prefix, &mut BlackBoxHostOracle);
        let expected = original_evaluator.finalize_prefix(&terminal, &mut BlackBoxHostOracle);

        let report = checker.check_run(&properties, &entries)?;

        assert_eq!(report, expected);
        assert_eq!(report.outcomes()[0].at, time(33));
    }
    Ok(())
}

#[test]
fn sparse_marker_payload_reapplication_and_late_retirement_keep_terminal_evidence() -> TestResult {
    let world = world(WhiteBoxPolicy::Enabled)?;
    let checker = OfflineAssertionChecker::new().with_world_white_box_policies(&world);
    let retired = ObservableEvent::node_state(
        time(4),
        NodeId {
            name: "guest".into(),
        },
        crucible::NodeLifecycle::Exited,
    );

    for kind in [
        GuestAssertionKind::Always,
        GuestAssertionKind::Reachable,
        GuestAssertionKind::Unreachable,
    ] {
        let marker = sparse_marker(2, kind, kind == GuestAssertionKind::Always, false);
        let update = sparse_marker(5, kind, kind == GuestAssertionKind::Always, true);
        let entries = vec![
            boundary(0, 1),
            marker_entry(1, &marker),
            boundary(2, 3),
            marker_entry(3, &retired),
            marker_entry(4, &update),
            boundary(5, 6),
        ];

        assert_eq!(
            checker.check_run(&Properties::empty(), &entries)?,
            published_report(&checker, &Properties::empty(), &entries)?
        );
    }
    Ok(())
}

#[test]
fn sparse_marker_preserves_original_invalid_history_and_terminal_error_order() -> TestResult {
    let world = world(WhiteBoxPolicy::Enabled)?;
    let checker = OfflineAssertionChecker::new().with_world_white_box_policies(&world);
    let marker = marker_entry(
        1,
        &sparse_marker(5, GuestAssertionKind::Always, false, false),
    );
    let mut invalid = vec![
        boundary(0, 10),
        marker.clone(),
        boundary(2, 5),
        boundary(3, 10),
    ];

    assert_eq!(
        checker.check_run(&Properties::empty(), &invalid),
        published_report(&checker, &Properties::empty(), &invalid)
    );
    assert!(matches!(
        checker.check_run(&Properties::empty(), &invalid),
        Err(OfflineAssertionCheckError::ConditionEvaluation(
            ConditionEvaluationError::FutureEventLogEntry { .. }
        ))
    ));
    invalid[3] = crucible::test_support::condition_entry_with_content_hash_for_test(
        invalid[3].clone(),
        ContentHash::from_bytes(b"terminal corrupt"),
    );
    assert!(matches!(
        checker.check_run(&Properties::empty(), &invalid),
        Err(OfflineAssertionCheckError::ConditionEvaluation(
            ConditionEvaluationError::InvalidEventLogEntryHash { sequence: 3 }
        ))
    ));
    assert!(matches!(
        checker.check_run(
            &Properties::empty(),
            &[
                boundary(0, 1),
                marker_entry(
                    2,
                    &sparse_marker(2, GuestAssertionKind::Always, false, false)
                )
            ]
        ),
        Err(OfflineAssertionCheckError::ConditionEvaluation(
            ConditionEvaluationError::NonPrefixEventLogSequence {
                expected: 1,
                actual: 2
            }
        ))
    ));

    let atomic = vec![boundary(0, 10), marker, boundary(2, 10)];
    assert!(checker.check_run(&Properties::empty(), &atomic).is_ok());
    assert!(matches!(
        published_report(&checker, &Properties::empty(), &atomic),
        Err(OfflineAssertionCheckError::ConditionEvaluation(
            ConditionEvaluationError::FutureEventLogEntry { .. }
        ))
    ));
    Ok(())
}

#[test]
fn sparse_marker_catalog_and_host_assertions_keep_original_every_prefix_path() -> TestResult {
    let world = world(WhiteBoxPolicy::Enabled)?;
    let marker = sparse_marker(2, GuestAssertionKind::Always, true, false);
    let entries = vec![boundary(0, 1), marker_entry(1, &marker), boundary(2, 3)];
    let properties = Properties::from_assertions_for_world(
        &world,
        vec![AssertionDef {
            id: AssertionId::from_name("host-failure"),
            message: "missing ack".into(),
            property: Property::Always {
                predicate: Predicate::network_match(
                    None,
                    FramePredicate::contains(b"ack".to_vec()),
                ),
            },
        }],
    )?;
    let checker = OfflineAssertionChecker::new().with_world_white_box_policies(&world);

    assert_eq!(
        checker.check_run(&properties, &entries)?,
        published_report(&checker, &properties, &entries)?
    );
    assert!(
        checker
            .check_run(&properties, &entries)?
            .outcomes()
            .iter()
            .any(|outcome| outcome.at == time(1)
                && outcome.kind == HostAssertionOutcomeKind::Violated)
    );
    let catalog = GuestAssertionMarker::new(
        AssertionId::from_name("catalog"),
        "required",
        GuestAssertionKind::Reachable,
        false,
        true,
        vec![],
        "fixture.rs:1",
    );
    let catalog_checker = checker.with_guest_assertion_catalog([catalog]);
    assert_eq!(
        catalog_checker.check_run(&Properties::empty(), &entries)?,
        published_report(&catalog_checker, &Properties::empty(), &entries)?
    );
    Ok(())
}
