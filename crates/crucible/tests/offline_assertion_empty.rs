//! Checks authenticated empty assertion runs and their intermediate-prefix refusals.

#![forbid(unsafe_code)]

use crucible::{
    AssertionDef, AssertionId, BlackBoxHostOracle, ConditionEvaluationError, ContentHash,
    FramePredicate, GuestAssertionKind, GuestAssertionMarker, HostAssertionEvaluator,
    HostAssertionOutcomeKind, Icount, NodeId, NodeTemplate, ObservableEvent,
    OfflineAssertionCheckError, OfflineAssertionChecker, Predicate, Properties, Property,
    ReadyPoint, RecordedAssertionLog, SchedulerEvaluationBoundaryKind, SchedulerEventLogEntry,
    VirtualTime, VmArchitecture, WhiteBoxPolicy, World, WorldNode,
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
