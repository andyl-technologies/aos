//! Authenticated guest and model measurement projection through the QEMU driver.

use super::*;

#[test]
fn modeled_scheduler_metrics_are_derived_from_the_canonical_log() {
    let _decode_scope = crate::exact_checkpoint_store::test_support::fixture_decode_scope();

    let fixture = crucible::happy_path_scenario().expect("happy-path fixture");
    let scenario = measured_scenario(&fixture.scenario);
    let input = input_for_scenario(scenario, StopCondition::Terminal);
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
        .expect("model-owned measurement projection");
    let candidate = prepared_semantic_observation(product);
    let retained = candidate.measurements().evaluation();
    let payload = std::str::from_utf8(retained.payload()).expect("canonical measurement JSON");
    assert!(payload.contains("\"scheduler-events\""));
    assert!(payload.contains(&format!(
        "\"aggregate\":{{\"kind\":\"unsigned\",\"value\":{}}}",
        fixture.observations().len()
    )));
}

#[test]
fn guest_measurement_messages_normalize_against_the_exact_scenario_contract() {
    let _decode_scope = crate::exact_checkpoint_store::test_support::fixture_decode_scope();

    let fixture = crucible::happy_path_scenario().expect("happy-path fixture");
    let definitions = guest_measurement_definitions(&fixture.scenario);
    let node = fixture
        .scenario
        .world()
        .vm_nodes()
        .first()
        .expect("happy-path VM")
        .id
        .clone();
    let entries = vec![
        SchedulerEventLogEntry::guest_measurement_observation(
            0,
            Icount { retired: 1 },
            node.clone(),
            GuestMeasurementEvent::Begin {
                measurement: String::from("driver-window"),
                instance: String::from("epoch-7"),
            },
        )
        .unwrap_or_else(|source| panic!("fixture event admission: {source}")),
        SchedulerEventLogEntry::guest_measurement_observation(
            1,
            Icount { retired: 2 },
            node.clone(),
            GuestMeasurementEvent::Sample {
                measurement: String::from("driver-window"),
                instance: String::from("epoch-7"),
                metric: String::from("healthy-peers"),
                value: GuestMeasurementValue::Unsigned(3),
            },
        )
        .unwrap_or_else(|source| panic!("fixture event admission: {source}")),
        SchedulerEventLogEntry::guest_semantic_marker_observation(
            2,
            Icount { retired: 3 },
            node.clone(),
            String::from("routing-converged"),
            String::from("epoch-7"),
            Vec::new(),
        )
        .unwrap_or_else(|source| panic!("fixture event admission: {source}")),
        SchedulerEventLogEntry::guest_measurement_observation(
            3,
            Icount { retired: 4 },
            node,
            GuestMeasurementEvent::End {
                measurement: String::from("driver-window"),
                instance: String::from("epoch-7"),
            },
        )
        .unwrap_or_else(|source| panic!("fixture event admission: {source}")),
    ];

    let publication = evaluate_test_measurements(&definitions, entries)
        .expect("declared guest measurement publication");
    let evaluation = publication.measurement_set().evaluation();
    let payload = std::str::from_utf8(evaluation.payload()).expect("canonical evaluation JSON");

    assert!(payload.contains("\"driver-window\""));
    assert!(payload.contains("\"healthy-peers\""));
    assert!(payload.contains("\"sequence\":1"));
    assert!(payload.contains("\"value\":3"));
}

#[test]
fn fresh_driver_retains_verified_guest_measurement_evaluation() {
    let _decode_scope = crate::exact_checkpoint_store::test_support::fixture_decode_scope();

    let fixture = crucible::happy_path_scenario().expect("happy-path fixture");
    let scenario = guest_measured_scenario(&fixture.scenario);
    let input = input_for_scenario(scenario, StopCondition::Terminal);
    let configuration = starting_configuration(&input);
    let node = input
        .scenario()
        .world()
        .vm_nodes()
        .first()
        .expect("happy-path VM")
        .id
        .clone();
    let mut observations = fixture.observations().to_vec();
    observations.extend([
        ObservableEvent::guest_measurement(
            Icount { retired: 40 },
            node.clone(),
            GuestMeasurementEvent::Begin {
                measurement: String::from("driver-window"),
                instance: String::from("epoch-7"),
            },
        ),
        ObservableEvent::guest_measurement(
            Icount { retired: 41 },
            node.clone(),
            GuestMeasurementEvent::Sample {
                measurement: String::from("driver-window"),
                instance: String::from("epoch-7"),
                metric: String::from("healthy-peers"),
                value: GuestMeasurementValue::Unsigned(3),
            },
        ),
        ObservableEvent::guest_semantic_marker(
            Icount { retired: 42 },
            node.clone(),
            String::from("routing-converged"),
            String::from("epoch-7"),
            Vec::new(),
        ),
        ObservableEvent::guest_measurement(
            Icount { retired: 43 },
            node,
            GuestMeasurementEvent::End {
                measurement: String::from("driver-window"),
                instance: String::from("epoch-7"),
            },
        ),
    ]);
    let mut log = EventLog::new();
    let append = log
        .append_observable_events(observations)
        .expect("guest measurement event log");
    let mut quantum = outcome(configuration, append.entries, append.offset, 43);
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
            .expect("terminal guest-measured stop"),
    );
    let product = driver
        .seal(pending, Vec::new())
        .expect("verified guest measurement projection");
    let candidate = prepared_semantic_observation(product);
    let evaluation = candidate.measurements().evaluation();
    let payload = std::str::from_utf8(evaluation.payload()).expect("canonical evaluation JSON");

    assert!(payload.contains("\"driver-window\""));
    assert!(payload.contains("\"healthy-peers\""));
    assert!(payload.contains("\"scheduler-events\""));
    assert!(payload.contains("\"value\":3"));
}

#[test]
fn guest_measurement_messages_fail_closed_on_type_and_lifecycle_mismatch() {
    let _decode_scope = crate::exact_checkpoint_store::test_support::fixture_decode_scope();

    let fixture = crucible::happy_path_scenario().expect("happy-path fixture");
    let definitions = guest_measurement_definitions(&fixture.scenario);
    let node = fixture
        .scenario
        .world()
        .vm_nodes()
        .first()
        .expect("happy-path VM")
        .id
        .clone();
    let begin = SchedulerEventLogEntry::guest_measurement_observation(
        0,
        Icount { retired: 1 },
        node.clone(),
        GuestMeasurementEvent::Begin {
            measurement: String::from("driver-window"),
            instance: String::from("epoch-7"),
        },
    )
    .unwrap_or_else(|source| panic!("fixture event admission: {source}"));
    let wrong_instance = SchedulerEventLogEntry::guest_measurement_observation(
        0,
        Icount { retired: 1 },
        node.clone(),
        GuestMeasurementEvent::Begin {
            measurement: String::from("driver-window"),
            instance: String::from("other-epoch"),
        },
    )
    .unwrap_or_else(|source| panic!("fixture event admission: {source}"));
    let wrong_type = SchedulerEventLogEntry::guest_measurement_observation(
        1,
        Icount { retired: 2 },
        node,
        GuestMeasurementEvent::Sample {
            measurement: String::from("driver-window"),
            instance: String::from("epoch-7"),
            metric: String::from("healthy-peers"),
            value: GuestMeasurementValue::Boolean(true),
        },
    )
    .unwrap_or_else(|source| panic!("fixture event admission: {source}"));
    let wrong_cohort_marker = SchedulerEventLogEntry::guest_semantic_marker_observation(
        0,
        Icount { retired: 1 },
        fixture
            .scenario
            .world()
            .vm_nodes()
            .get(1)
            .expect("measurement fixture second VM")
            .id
            .clone(),
        String::from("routing-converged"),
        String::from("epoch-7"),
        Vec::new(),
    )
    .unwrap_or_else(|source| panic!("fixture event admission: {source}"));

    let error = evaluate_test_measurements(&definitions, vec![begin.clone(), wrong_type])
        .expect_err("declared unsigned metric must reject a boolean");
    assert!(matches!(
        error,
        CrucibleMeasurementError::GuestMeasurementProtocol { sequence: 1, .. }
    ));

    let error = evaluate_test_measurements(&definitions, vec![wrong_instance])
        .expect_err("a guest message must bind the declared exact instance");
    assert!(matches!(
        error,
        CrucibleMeasurementError::GuestMeasurementProtocol { sequence: 0, .. }
    ));

    let error = evaluate_test_measurements(&definitions, vec![wrong_cohort_marker])
        .expect_err("a semantic marker must come from the declared cohort");
    assert!(matches!(
        error,
        CrucibleMeasurementError::GuestMeasurementProtocol { sequence: 0, .. }
    ));

    let error = evaluate_test_measurements(&definitions, vec![begin])
        .expect_err("an open measurement instance must be closed");
    assert!(matches!(
        error,
        CrucibleMeasurementError::GuestMeasurementProtocol { sequence: 1, .. }
    ));
}
