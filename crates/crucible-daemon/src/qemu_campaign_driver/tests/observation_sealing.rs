//! Observation sealing, final-drain, and retained-material tests.

use super::*;

#[test]
fn matching_observation_does_not_mutate_configuration_with_a_default_guest_reply() {
    let (input, node) = input_with_guest_selectable(StopCondition::Observation(
        ObservationCondition::SchedulerQuiescent,
    ));
    let configuration = starting_configuration(&input);
    let mut quantum = outcome(
        configuration.clone(),
        Vec::new(),
        EventLogOffset::default(),
        1,
    );
    quantum.scheduler_quiescence = Some(SchedulerQuiescence::default());
    let mut owner = PendingSelectableLifecycle {
        frontier: configuration.clone(),
        outcomes: VecDeque::from([quantum]),
        completed_coordinates: VecDeque::from([1]),
        pending: VecDeque::from([vec![pending_guest_request(node, None)]]),
        active_pending: Vec::new(),
        reply_entries: VecDeque::new(),
        replies: Vec::new(),
        completed_quanta: 0,
        drives: 0,
    };

    let pending = {
        let mut lifecycle = QemuFreshAttemptLifecycle::new(&mut owner);
        expect_observation(
            QemuFreshModeledDriver::new()
                .drive(
                    &mut lifecycle,
                    &input,
                    &context(),
                    QemuFreshStartMaterialization::genesis(),
                )
                .expect("observation before default reply"),
        )
    };

    assert!(matches!(
        pending.stop,
        ModeledStop::ObservationReached { .. }
    ));
    assert_eq!(pending.configuration, configuration);
    assert!(owner.replies.is_empty());
}

#[test]
fn matching_observation_rejects_a_nonadvancing_quantum_coordinate() {
    let input = input(StopCondition::Observation(
        ObservationCondition::SchedulerQuiescent,
    ));
    let configuration = starting_configuration(&input);
    let mut quantum = outcome(
        configuration.clone(),
        Vec::new(),
        EventLogOffset::default(),
        1,
    );
    quantum.scheduler_quiescence = Some(SchedulerQuiescence::default());
    let mut owner = PendingSelectableLifecycle {
        frontier: configuration,
        outcomes: VecDeque::from([quantum]),
        completed_coordinates: VecDeque::from([0]),
        pending: VecDeque::from([Vec::new()]),
        active_pending: Vec::new(),
        reply_entries: VecDeque::new(),
        replies: Vec::new(),
        completed_quanta: 0,
        drives: 0,
    };
    let mut lifecycle = QemuFreshAttemptLifecycle::new(&mut owner);

    let error = QemuFreshModeledDriver::new()
        .drive(
            &mut lifecycle,
            &input,
            &context(),
            QemuFreshStartMaterialization::genesis(),
        )
        .expect_err("observation proof requires an advancing quantum coordinate");

    assert!(matches!(
        error,
        AttemptWorkerFailure::Terminal(QemuFreshModeledDriverError::QuantumCounterDidNotAdvance {
            before: 0,
            after: 0,
        })
    ));
}

fn pending_assertion_observation() -> QemuFreshPendingObservation {
    let assertion = AssertionId::from_name("safety");
    let input = input_with_assertions(
        StopCondition::Observation(ObservationCondition::AssertionViolationTransition(
            assertion.name.clone(),
        )),
        ["safety"],
    );
    let configuration = starting_configuration(&input);
    let mut log = EventLog::new();
    let matching = log
        .append_entries(vec![SchedulerEventLogEntry::assertion_state_observation(
            0,
            VirtualTime { ticks: 1 },
            assertion,
            AssertionPhase::Violated,
        )])
        .expect("matching assertion segment");
    let mut owner = FakeLifecycle {
        outcomes: VecDeque::from([Ok(outcome(
            configuration,
            matching.entries,
            matching.offset,
            1,
        ))]),
        terminal: None,
        initial_quanta: 0,
        drives: 0,
    };
    let mut lifecycle = QemuFreshAttemptLifecycle::new(&mut owner);
    let mut driver = QemuFreshModeledDriver::new();
    expect_observation(
        driver
            .drive(
                &mut lifecycle,
                &input,
                &context(),
                QemuFreshStartMaterialization::genesis(),
            )
            .expect("assertion observation"),
    )
}

fn replace_observation_event_log(
    pending: &mut QemuFreshPendingObservation,
    event_log: ObservationEventLogProof,
) {
    let ModeledStop::ObservationReached { proof, .. } = &mut pending.stop else {
        panic!("fixture must stop on an observation")
    };
    **proof = ObservationStopProof::new(
        proof.condition().clone(),
        proof.satisfaction(),
        proof.child(),
        proof.boundary(),
        event_log,
        proof.assertion_witness().cloned(),
    )
    .expect("structurally valid mutated proof");
}

fn assert_observation_boundary_rejected(pending: QemuFreshPendingObservation) {
    let error = QemuFreshModeledDriver::new()
        .seal(pending, Vec::new())
        .expect_err("raw evidence must authenticate the observation boundary");

    let AttemptWorkerFailure::Terminal(QemuFreshModeledDriverError::PreparedResult(error)) = error
    else {
        panic!("unexpected observation-boundary error: {error:?}");
    };
    assert!(matches!(
        error.as_ref(),
        PreparedSemanticResultCodecError::Inconsistent {
            component: "observation stop execution boundary"
        }
    ));
}

#[test]
fn observation_seal_rejects_a_bytes_only_offset_mutation() {
    let mut pending = pending_assertion_observation();
    let ModeledStop::ObservationReached { proof, .. } = &pending.stop else {
        panic!("fixture must stop on an observation")
    };
    let event_log = proof.event_log();
    replace_observation_event_log(
        &mut pending,
        ObservationEventLogProof::new(
            event_log.prefix(),
            event_log.appended_segment(),
            event_log.bytes() + 1,
            event_log.events(),
            event_log.digest(),
        ),
    );

    assert_observation_boundary_rejected(pending);
}

#[test]
fn observation_seal_rejects_an_empty_segment_with_a_nonempty_prefix() {
    let mut pending = pending_assertion_observation();
    let ModeledStop::ObservationReached { proof, .. } = &pending.stop else {
        panic!("fixture must stop on an observation")
    };
    let event_log = proof.event_log();
    replace_observation_event_log(
        &mut pending,
        ObservationEventLogProof::new(
            CampaignHash::derive("test", b"nonempty forged prefix"),
            None,
            event_log.bytes(),
            event_log.events(),
            event_log.digest(),
        ),
    );

    assert_observation_boundary_rejected(pending);
}

#[test]
fn observation_seal_rejects_a_forged_prefix_with_a_coherent_segment() {
    let mut pending = pending_assertion_observation();
    let ModeledStop::ObservationReached { proof, .. } = &pending.stop else {
        panic!("fixture must stop on an observation")
    };
    let digest = proof.event_log().digest();
    let entry = SchedulerEventLogEntry::assertion_state_observation(
        0,
        VirtualTime { ticks: 1 },
        AssertionId::from_name("safety"),
        AssertionPhase::Violated,
    );
    let forged_prefix = ContentHash::from_bytes(b"forged observation prefix");
    let mut forged_log = EventLog::from_offset(EventLogOffset::new(forged_prefix, 0, 0));
    let forged = forged_log
        .append_entries(vec![entry])
        .expect("coherent forged-prefix segment");
    replace_observation_event_log(
        &mut pending,
        ObservationEventLogProof::new(
            CampaignHash::from_bytes(forged.offset.prefix.bytes),
            forged
                .offset
                .appended_segment
                .map(|hash| CampaignHash::from_bytes(hash.bytes)),
            forged.offset.bytes,
            forged.offset.events,
            digest,
        ),
    );

    assert_observation_boundary_rejected(pending);
}

#[test]
fn observation_seal_rejects_shifted_quantum_coordinates() {
    let mut pending = pending_assertion_observation();
    let ModeledStop::ObservationReached { proof, .. } = &mut pending.stop else {
        panic!("fixture must stop on an observation")
    };
    let boundary = proof.boundary();
    **proof = ObservationStopProof::new(
        proof.condition().clone(),
        proof.satisfaction(),
        proof.child(),
        ObservationQuantumBoundary::new(
            boundary.frontier_nanoseconds() + 1,
            boundary.start_completed_quanta() + 1,
            boundary.completed_quanta() + 1,
            boundary.start_events(),
        )
        .expect("structurally valid shifted boundary"),
        proof.event_log(),
        proof.assertion_witness().cloned(),
    )
    .expect("structurally valid shifted proof");

    assert_observation_boundary_rejected(pending);
}

#[test]
fn terminal_run_projects_offline_property_verdicts() {
    let fixture = crucible::happy_path_scenario().expect("happy-path fixture");
    let input = input_for_scenario(fixture.scenario.clone(), StopCondition::Terminal);
    let configuration = starting_configuration(&input);
    let mut log = EventLog::new();
    let append = log
        .append_observable_events(fixture.observations().iter().cloned())
        .expect("happy-path event log");
    let mut quantum = outcome(configuration, append.entries, append.offset, 38);
    quantum.scheduler_quiescence = Some(SchedulerQuiescence::default());
    let mut owner = FakeLifecycle {
        outcomes: VecDeque::from([Ok(quantum)]),
        terminal: Some(QuantumTerminalVerdict::Passed),
        initial_quanta: 0,
        drives: 0,
    };
    let mut lifecycle = QemuFreshAttemptLifecycle::new(&mut owner);
    let mut driver = QemuFreshModeledDriver::new();

    let pending = expect_observation(
        driver
            .drive(
                &mut lifecycle,
                &input,
                &context(),
                QemuFreshStartMaterialization::genesis(),
            )
            .expect("terminal modeled stop"),
    );
    let product = driver
        .seal(pending, Vec::new())
        .expect("property projection");
    let candidate = prepared_semantic_observation(product);

    assert_eq!(
        candidate.observation().stop(),
        &StopOutcome::TerminalSuccess
    );
    assert_eq!(
        candidate
            .properties()
            .properties()
            .get("no-crashes")
            .expect("no-crashes verdict")
            .verdict(),
        PropertyVerdict::Passed
    );
    assert_eq!(
        candidate
            .properties()
            .properties()
            .get("all-requests-succeed")
            .expect("request verdict")
            .verdict(),
        PropertyVerdict::Passed
    );
}

#[test]
fn terminal_failure_preserves_grouped_reasons_in_scheduler_order() {
    let fixture = crucible::happy_path_scenario().expect("happy-path fixture");
    let input = input_for_scenario(fixture.scenario.clone(), StopCondition::Terminal);
    let configuration = starting_configuration(&input);
    let mut log = EventLog::new();
    let append = log
        .append_observable_events(fixture.observations().iter().cloned())
        .expect("happy-path event log");
    let mut quantum = outcome(configuration, append.entries, append.offset, 38);
    quantum.scheduler_quiescence = Some(SchedulerQuiescence::default());
    let reasons = vec![
        "later lexical reason".to_owned(),
        "earlier lexical reason".to_owned(),
        "later lexical reason".to_owned(),
    ];
    let mut owner = FakeLifecycle {
        outcomes: VecDeque::from([Ok(quantum)]),
        terminal: Some(QuantumTerminalVerdict::Failed(reasons.clone())),
        initial_quanta: 0,
        drives: 0,
    };
    let mut lifecycle = QemuFreshAttemptLifecycle::new(&mut owner);
    let mut driver = QemuFreshModeledDriver::new();

    let pending = expect_observation(
        driver
            .drive(
                &mut lifecycle,
                &input,
                &context(),
                QemuFreshStartMaterialization::genesis(),
            )
            .expect("terminal modeled failure"),
    );
    let product = driver
        .seal(pending, Vec::new())
        .expect("scenario failure projection");
    let candidate = prepared_semantic_observation(product);

    assert_eq!(
        candidate.observation().stop(),
        &StopOutcome::ScenarioFailure(reasons)
    );
}

#[test]
fn empty_terminal_failure_is_rejected() {
    assert!(matches!(
        modeled_terminal_stop(QuantumTerminalVerdict::Failed(Vec::new())),
        Err(QemuFreshModeledDriverError::EmptyScenarioFailure)
    ));
}

#[test]
fn non_dense_final_drain_is_rejected_before_candidate_construction() {
    let input = input(StopCondition::EventCount(1));
    let configuration = starting_configuration(&input);
    let mut log = EventLog::new();
    let first = log
        .append_observable_events([ObservableEvent::guest_marker(
            Icount { retired: 1 },
            node("node-a"),
            MarkerId::from_name("first"),
        )])
        .expect("first event-log segment");
    let mut owner = FakeLifecycle {
        outcomes: VecDeque::from([Ok(outcome(configuration, first.entries, first.offset, 1))]),
        terminal: None,
        initial_quanta: 0,
        drives: 0,
    };
    let mut lifecycle = QemuFreshAttemptLifecycle::new(&mut owner);
    let mut driver = QemuFreshModeledDriver::new();
    let pending = expect_observation(
        driver
            .drive(
                &mut lifecycle,
                &input,
                &context(),
                QemuFreshStartMaterialization::genesis(),
            )
            .expect("event-count stop"),
    );
    let invalid = SchedulerEventLogEntry::guest_marker_observation(
        7,
        Icount { retired: 2 },
        node("node-a"),
        MarkerId::from_name("late"),
    );

    let error = driver
        .seal(pending, vec![invalid])
        .expect_err("non-dense final suffix must fail closed");

    assert!(matches!(
        error,
        AttemptWorkerFailure::Terminal(QemuFreshModeledDriverError::Assertions(_))
    ));
}

#[test]
fn retained_event_material_is_byte_bounded_before_append() {
    let entry = SchedulerEventLogEntry::guest_marker_observation(
        0,
        Icount { retired: 1 },
        node("node-a"),
        MarkerId::from_name("bounded"),
    );
    let mut event_log = Vec::new();
    let mut retained_bytes = MAX_QEMU_CAMPAIGN_EVENT_LOG_BYTES
        .checked_sub(entry.canonical_material_len())
        .expect("entry fits configured bound")
        + 1;

    let error = append_event_entries(&mut event_log, &mut retained_bytes, vec![entry])
        .expect_err("aggregate event material must be rejected before retention");

    assert!(matches!(
        error,
        QemuFreshModeledDriverError::LimitExceeded {
            limit: "fresh-campaign-event-log-bytes"
        }
    ));
    assert!(event_log.is_empty());
}

#[test]
fn retained_choices_share_contracts_and_charge_unique_records_once() {
    let scenario = ScenarioDefId::from_hash(CampaignHash::derive("fresh-driver-test", b"scenario"));
    let first = choice_discovery_named(scenario, "first");
    let second = choice_discovery_named(scenario, "second");
    let unshared_bytes = first.declaration().canonical_bytes().len()
        + first.domain().canonical_bytes().len()
        + first.opportunity().canonical_bytes().len()
        + second.declaration().canonical_bytes().len()
        + second.domain().canonical_bytes().len()
        + second.opportunity().canonical_bytes().len();
    let mut retained = RetainedChoiceDiscoveries::default();

    retained.insert(first).expect("first discovery");
    retained.insert(second).expect("second discovery");

    assert_eq!(retained.charged_records.len(), 4);
    assert!(retained.charged_bytes < unshared_bytes);
    assert_eq!(retained.representatives.len(), 1);
    assert_eq!(retained.discoveries.len(), 2);
}
