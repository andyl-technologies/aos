//! Terminal finding-retention tests for fresh QEMU campaign lifecycles.

use super::*;

#[test]
fn failed_observation_retains_terminal_boundary_without_replacing_semantic_result() {
    let directory = tempfile::tempdir().expect("terminal checkpoint fixture directory");
    let fixture =
        crucible_api::build_exact_ram_production_checkpoint_codec_fixture(directory.path())
            .expect("terminal checkpoint fixture");
    let input = modeled_fresh_runner_input_for_scenario(
        fixture.source().clone(),
        StopCondition::ExecutionQuanta(1),
    );
    let captures = Arc::new(Mutex::new(Vec::new()));
    let source = Arc::new(RecordingTerminalRetentionSource {
        captures: Arc::clone(&captures),
        reject_capture: false,
    });
    let context = AttemptExecutionContext::new(
        resources(4),
        ExecutionRetentionIntent::RetainOnFailure,
        ExecutionCancellation::default(),
        ExecutionCheckpointRequest::default(),
        crucible_campaign::AttemptRetentionPolicyDisposition::Disabled,
    );
    let mut runner = QemuFreshExecutionRunner::new(
        BoundaryCaptureLifecycleFactory {
            captured: Arc::new(Mutex::new(Vec::new())),
            final_events: Vec::new(),
            replay_decisions: VecDeque::new(),
            terminal_failure: true,
            terminal_marker: None,
        },
        QemuFreshModeledDriver::new(),
    )
    .with_terminal_exact_retention_source(source);

    let outcome = runner
        .execute(&input, &context)
        .expect("failed observation");
    assert!(matches!(
        outcome.product(),
        AttemptExecutionProduct::PreparedSemantic(_)
    ));
    let retained = captures.lock().expect("terminal captures");
    assert_eq!(retained.len(), 1);
    assert_eq!(retained[0].scenario, input.lineage().scenario());
    assert_eq!(
        retained[0].scenario_artifact,
        input.lineage().scenario_content()
    );
    assert_eq!(retained[0].event_count, 1);
    drop(retained);

    let failing_source = Arc::new(RecordingTerminalRetentionSource {
        captures: Arc::clone(&captures),
        reject_capture: true,
    });
    let mut runner = QemuFreshExecutionRunner::new(
        BoundaryCaptureLifecycleFactory {
            captured: Arc::new(Mutex::new(Vec::new())),
            final_events: Vec::new(),
            replay_decisions: VecDeque::new(),
            terminal_failure: true,
            terminal_marker: None,
        },
        QemuFreshModeledDriver::new(),
    )
    .with_terminal_exact_retention_source(failing_source);

    let outcome = runner
        .execute(&input, &context)
        .expect("optional capture failure");
    assert!(matches!(
        outcome.product(),
        AttemptExecutionProduct::PreparedSemantic(_)
    ));
    assert_eq!(captures.lock().expect("terminal captures").len(), 1);
}

#[test]
fn passed_trigger_retains_checker_failed_observation_boundary() {
    let directory = tempfile::tempdir().expect("terminal checkpoint fixture directory");
    let fixture =
        crucible_api::build_exact_ram_production_checkpoint_codec_fixture(directory.path())
            .expect("terminal checkpoint fixture");
    let node = fixture
        .source()
        .world()
        .vm_nodes()
        .iter()
        .next()
        .expect("checkpoint fixture VM")
        .id
        .clone();
    let input = modeled_fresh_runner_input_for_scenario(
        fixture.source().clone(),
        StopCondition::ExecutionQuanta(1),
    );
    let captured = Arc::new(Mutex::new(Vec::new()));
    let retained = Arc::new(Mutex::new(Vec::new()));
    let source = Arc::new(RecordingTerminalRetentionSource {
        captures: Arc::clone(&retained),
        reject_capture: false,
    });
    let context = AttemptExecutionContext::new(
        resources(4),
        ExecutionRetentionIntent::RetainOnFailure,
        ExecutionCancellation::default(),
        ExecutionCheckpointRequest::default(),
        crucible_campaign::AttemptRetentionPolicyDisposition::Disabled,
    );
    let mut runner = QemuFreshExecutionRunner::new(
        BoundaryCaptureLifecycleFactory {
            captured: Arc::clone(&captured),
            final_events: Vec::new(),
            replay_decisions: VecDeque::new(),
            terminal_failure: false,
            terminal_marker: Some(node),
        },
        QemuFreshModeledDriver::new(),
    )
    .with_terminal_exact_retention_source(source);

    let outcome = runner
        .execute(&input, &context)
        .expect("checker-failed observation after a passed trigger");
    let AttemptExecutionProduct::PreparedSemantic(result) = outcome.product() else {
        panic!("checker failure must remain a semantic observation")
    };
    assert_eq!(
        result.observation().observation().stop(),
        &StopOutcome::AssertionFailure(String::from("no-split-brain"))
    );
    let captured = captured.lock().expect("captured terminal boundary");
    let retained = retained.lock().expect("retained terminal identity");
    assert_eq!(captured.len(), 1);
    assert_eq!(retained.len(), 1);
    assert_eq!(captured[0].quanta, 1);
    assert_eq!(
        retained[0].configuration,
        ConfigurationId::from_hash(CampaignHash::from_bytes(captured[0].configuration.bytes))
    );
    assert_eq!(retained[0].event_count, captured[0].events.len() as u64);
}
