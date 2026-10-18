//! Continuation source admission and replay-prefix rejection tests.

use super::*;

#[test]
fn fresh_runner_rejects_resume_origin_before_factory_invocation() {
    let order = Arc::new(Mutex::new(Vec::new()));
    let mut runner = QemuFreshExecutionRunner::new(
        FakeFreshLifecycleFactory {
            order: Arc::clone(&order),
            cleanup_error: false,
            terminal_after_replay: false,
            checkpoint_ready: true,
        },
        FakeFreshDriver {
            order: Arc::clone(&order),
            failure: None,
        },
    );
    let checkpoint = ExactCheckpointId::try_from(ContentId::for_bytes(
        ObjectKind::ExactManifest,
        5,
        b"fresh-runner-resume-origin",
    ))
    .expect("exact checkpoint fixture");
    let resumed = fresh_runner_context().with_resume_checkpoint(Some(checkpoint));

    let error = runner
        .execute(&fresh_runner_input(), &resumed)
        .expect_err("fresh runner must reject a resume origin");

    assert!(matches!(
        error,
        AttemptWorkerFailure::Terminal(
            QemuFreshExecutionRunnerError::ResumeCheckpointUnsupported(actual)
        ) if actual == checkpoint
    ));
    assert!(order.lock().expect("fresh lifecycle order").is_empty());
}

#[test]
fn fresh_runner_rejects_unconsumed_continuation_input_before_factory_invocation() {
    let order = Arc::new(Mutex::new(Vec::new()));
    let mut runner = QemuFreshExecutionRunner::new(
        FakeFreshLifecycleFactory {
            order: Arc::clone(&order),
            cleanup_error: false,
            terminal_after_replay: false,
            checkpoint_ready: true,
        },
        FakeFreshDriver {
            order: Arc::clone(&order),
            failure: None,
        },
    );
    let continuation_input = AttemptContinuationInput::scheduler_reseed(
        test_continuation_source_observation(),
        1,
        [0x5a; 32],
    );
    let (input, _, _) = selected_after_genesis_input_with_continuation(Some(continuation_input));

    let error = runner
        .execute(&input, &fresh_runner_context())
        .expect_err("default factory must reject modeled continuation input");

    assert!(matches!(
        error,
        AttemptWorkerFailure::Terminal(QemuFreshExecutionRunnerError::ContinuationInputUnsupported)
    ));
    assert!(order.lock().expect("fresh lifecycle order").is_empty());
}

#[test]
fn fresh_runner_rejects_continuation_without_exact_virtual_time_source() {
    assert_invalid_continuation_source(StopCondition::ExecutionQuanta(1));
}

#[test]
fn fresh_runner_rejects_continuation_at_a_different_virtual_time() {
    assert_invalid_continuation_source(StopCondition::VirtualTimePicoseconds(2));
}

#[test]
fn continuation_accepts_an_authenticated_observation_source_frontier() {
    let condition = ObservationCondition::SchedulerQuiescent;
    let proof = ObservationStopProof::new(
        condition.clone(),
        ObservationStopSatisfaction::SchedulerQuiescent,
        ConfigurationId::from_hash(CampaignHash::derive(
            "continuation-observation-source",
            b"child",
        )),
        ObservationQuantumBoundary::new(1, 0, 1, 0).expect("observation source boundary"),
        ObservationEventLogProof::new(
            CampaignHash::derive("continuation-observation-source", b"prefix"),
            None,
            0,
            0,
            CampaignHash::derive("continuation-observation-source", b"digest"),
        ),
        None,
    )
    .expect("quiescent source proof");
    let continuation = AttemptContinuationInput::scheduler_reseed(
        test_continuation_source_observation(),
        1,
        [0x5a; 32],
    );
    let (input, _, _) = selected_after_genesis_input_with_continuation_source_evidence(
        continuation,
        StopCondition::Observation(condition),
        StopOutcome::ObservationReached(Box::new(proof)),
    );

    let controls = validated_attempt_continuations(&input)
        .unwrap_or_else(|()| panic!("authenticated observation source should validate"));

    assert_eq!(controls.len(), 1);
    assert_eq!(controls[0].input().source_frontier_ticks(), 1);
}

#[test]
fn continuation_rejects_a_terminally_preempted_source_stop() {
    let continuation = AttemptContinuationInput::scheduler_reseed(
        test_continuation_source_observation(),
        1,
        [0x5a; 32],
    );
    let (input, _, _) = selected_after_genesis_input_with_continuation_source_evidence(
        continuation,
        StopCondition::VirtualTimePicoseconds(1),
        StopOutcome::TerminalSuccess,
    );

    assert!(validated_attempt_continuations(&input).is_err());
}

fn assert_invalid_continuation_source(source_stop: StopCondition) {
    let order = Arc::new(Mutex::new(Vec::new()));
    let mut runner = QemuFreshExecutionRunner::new(
        ContinuationAcceptingFreshLifecycleFactory {
            inner: FakeFreshLifecycleFactory {
                order: Arc::clone(&order),
                cleanup_error: false,
                terminal_after_replay: false,
                checkpoint_ready: true,
            },
            continuations: Arc::new(Mutex::new(Vec::new())),
        },
        FakeFreshDriver {
            order: Arc::clone(&order),
            failure: None,
        },
    );
    let continuation = AttemptContinuationInput::scheduler_reseed(
        test_continuation_source_observation(),
        1,
        [0x5a; 32],
    );
    let (input, _, _) =
        selected_after_genesis_input_with_continuation_source_stop(continuation, source_stop);

    let error = runner
        .execute(&input, &fresh_runner_context())
        .expect_err("invalid source must not admit continuation control");

    assert!(matches!(
        error,
        AttemptWorkerFailure::Terminal(QemuFreshExecutionRunnerError::InvalidContinuationInput)
    ));
    assert!(order.lock().expect("fresh lifecycle order").is_empty());
}

#[test]
fn fresh_runner_replays_supported_non_genesis_start_before_driver() {
    let order = Arc::new(Mutex::new(Vec::new()));
    let mut runner = QemuFreshExecutionRunner::new(
        FakeFreshLifecycleFactory {
            order: Arc::clone(&order),
            cleanup_error: false,
            terminal_after_replay: false,
            checkpoint_ready: true,
        },
        FakeFreshDriver {
            order: Arc::clone(&order),
            failure: None,
        },
    );
    let input = non_genesis_fresh_runner_input();
    let outcome = runner
        .execute(&input, &fresh_runner_context())
        .expect("fresh runner must replay a supported non-genesis start");

    assert!(matches!(
        outcome.product(),
        AttemptExecutionProduct::ExactCheckpoint(_)
    ));
    assert_eq!(
        order.lock().expect("fresh lifecycle order").as_slice(),
        ["begin", "replay", "drive", "shutdown", "seal"]
    );
}

#[test]
fn terminal_evidence_runner_rejects_previous_attempt_samples_after_a_factory_reset() {
    let input = modeled_fresh_runner_input_for_stop(StopCondition::ExecutionQuanta(1));
    let captured = Arc::new(Mutex::new(Vec::new()));
    let factory = BoundaryCaptureLifecycleFactory {
        captured: Arc::clone(&captured),
        final_events: Vec::new(),
        replay_decisions: VecDeque::new(),
        terminal_failure: false,
        terminal_marker: None,
    };
    let (factory, evidence) = QemuObservedFreshAttemptLifecycleFactory::with_evidence(factory);
    let runner = QemuFreshExecutionRunner::new(factory, QemuFreshModeledDriver::new());
    let mut first = QemuTerminalEvidenceExecutionRunner::new(runner, evidence.clone());
    let first_outcome = first
        .execute(&input, &fresh_runner_context())
        .expect("first attempt publishes terminal evidence");
    let AttemptExecutionProduct::PreparedSemantic(first_result) = first_outcome.product() else {
        panic!("first attempt must produce a prepared semantic result")
    };
    assert!(first_result.terminal_fingerprints().is_some());

    let next_result = PreparedSemanticAttemptResult::new(
        first_result.observation().clone(),
        first_result.measurement_replay_evidence().to_vec(),
        first_result.finding().cloned(),
    )
    .expect("next prepared result without terminal evidence");
    let resetting_factory = QemuObservedFreshAttemptLifecycleFactory::with_shared_evidence(
        BoundaryCaptureLifecycleFactory {
            captured,
            final_events: Vec::new(),
            replay_decisions: VecDeque::new(),
            terminal_failure: false,
            terminal_marker: None,
        },
        evidence.clone(),
    );
    resetting_factory
        .prepare_observation(input.scenario())
        .expect("new fast-tier attempt resets per-worker evidence");
    assert_eq!(
        evidence
            .snapshot()
            .expect("reset evidence snapshot")
            .terminal_fingerprints(),
        None
    );

    let inner = PreparedSemanticResultRunner {
        result: Some(next_result),
    };
    let mut next = QemuTerminalEvidenceExecutionRunner::new(inner, evidence);
    let error = next
        .execute(&input, &fresh_runner_context())
        .expect_err("the next attempt cannot reuse the previous terminal set");

    assert!(matches!(
        error,
        AttemptWorkerFailure::Terminal(
            QemuTerminalEvidenceExecutionRunnerError::MissingTerminalFingerprints
        )
    ));
}
