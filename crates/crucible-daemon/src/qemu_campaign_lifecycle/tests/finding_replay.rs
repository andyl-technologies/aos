//! Finding boundary replay evidence, incompatibility and cleanup regressions.

use super::*;

#[test]
fn finding_candidate_replay_evaluates_the_declared_stop_after_materialization() {
    let _metadata = crate::exact_checkpoint_store::test_support::fixture_decode_scope();

    let input = modeled_fresh_runner_input_for_stop(StopCondition::ExecutionQuanta(4));
    let candidate = finding_candidate_artifact(&input);
    let context = fresh_runner_context();
    let mut runner = QemuFreshExecutionRunner::new(
        BoundaryCaptureLifecycleFactory {
            captured: Arc::new(Mutex::new(Vec::new())),
            final_events: Vec::new(),
            replay_decisions: VecDeque::new(),
            terminal_failure: false,
            terminal_marker: None,
        },
        QemuFreshModeledDriver::new(),
    );

    let outcome = runner
        .replay_finding_candidate_boundary(&input, &candidate, None, &context)
        .expect("candidate boundary replay");
    let QemuFindingCandidateReplayOutcome::Observed(evidence) = outcome else {
        panic!("genesis candidate must be observable")
    };

    let (replay, measurements, final_events, _) = (*evidence).into_parts();
    assert_eq!(replay.configuration(), &candidate);
    assert_eq!(measurements.len(), 1);
    assert!(final_events.is_empty());
    assert_eq!(context.consumed_execution_quanta(), 4);
}

#[test]
fn finding_candidate_replay_continues_after_reaching_a_nonempty_schedule() {
    let _metadata = crate::exact_checkpoint_store::test_support::fixture_decode_scope();

    let input = modeled_non_genesis_fresh_runner_input_for_stop(StopCondition::ExecutionQuanta(2));
    let candidate = finding_candidate_artifact(&input);
    let context = fresh_runner_context();
    let mut runner = QemuFreshExecutionRunner::new(
        BoundaryCaptureLifecycleFactory {
            captured: Arc::new(Mutex::new(Vec::new())),
            final_events: Vec::new(),
            replay_decisions: VecDeque::from([Decision::RngDraw(RngDecision {
                stream: RngStreamId::from_name("fresh-runner-non-genesis"),
                value: 7,
            })]),
            terminal_failure: false,
            terminal_marker: None,
        },
        QemuFreshModeledDriver::new(),
    );

    let outcome = runner
        .replay_finding_candidate_boundary(&input, &candidate, None, &context)
        .expect("nonempty candidate replay");
    let QemuFindingCandidateReplayOutcome::Observed(evidence) = outcome else {
        panic!("matching nonempty candidate must be observable")
    };

    let (replay, _, _, _) = (*evidence).into_parts();
    assert_eq!(replay.configuration(), &candidate);
    assert_eq!(
        context.consumed_execution_quanta(),
        2,
        "candidate evaluation must reach the declared stop after reconstructing the schedule"
    );
}

#[test]
fn finding_candidate_replay_retains_authenticated_execution_quanta_timeout() {
    let _metadata = crate::exact_checkpoint_store::test_support::fixture_decode_scope();

    let input = modeled_non_genesis_fresh_runner_input_for_stop(StopCondition::Observation(
        ObservationCondition::SchedulerQuiescentOrExecutionQuanta {
            execution_quanta: 1,
        },
    ));
    let candidate = finding_candidate_artifact(&input);
    let mut runner = QemuFreshExecutionRunner::new(
        BoundaryCaptureLifecycleFactory {
            captured: Arc::new(Mutex::new(Vec::new())),
            final_events: Vec::new(),
            replay_decisions: VecDeque::from([Decision::RngDraw(RngDecision {
                stream: RngStreamId::from_name("fresh-runner-non-genesis"),
                value: 7,
            })]),
            terminal_failure: false,
            terminal_marker: None,
        },
        QemuFreshModeledDriver::new(),
    );

    let outcome = runner
        .replay_finding_candidate_boundary(&input, &candidate, None, &fresh_runner_context())
        .expect("execution-bound candidate replay");
    let QemuFindingCandidateReplayOutcome::Observed(evidence) = outcome else {
        panic!("execution-bound candidate must be observable")
    };
    let (_, _, _, triage) = evidence.into_parts();
    let (failures, causal_entries, _, _, _) = triage.into_parts();
    let mut timeouts = failures.iter().filter_map(|failure| match failure {
        crucible::FailureClusterReportFailure::Timeout(timeout) => Some(timeout),
        crucible::FailureClusterReportFailure::Property(_)
        | crucible::FailureClusterReportFailure::Divergence(_) => None,
    });
    let timeout = timeouts
        .next()
        .expect("execution-bound replay must retain its timeout source");
    assert!(
        timeouts.next().is_none(),
        "execution-bound replay must retain one timeout source"
    );

    assert_eq!(
        timeout.budget_kind,
        crucible::FailureTimeoutBudgetKind::ExecutionQuanta
    );
    assert_eq!(timeout.configured_limit, Some(1));
    // One quantum reconstructs the candidate, then the declared one-quantum
    // attempt budget expires at the next absolute quantum.
    assert_eq!(timeout.observed_quanta, 2);
    assert!(causal_entries.iter().any(|entry| {
        entry.event_payload().kind() == "execution_budget_exhausted"
            && entry.event_payload().string("budget_kind") == Some("execution-quanta")
    }));
}

#[test]
fn property_failure_precedes_a_coincident_execution_quanta_timeout() {
    let _metadata = crate::exact_checkpoint_store::test_support::fixture_decode_scope();

    let assertion = AssertionId::from_name("coincident-timeout-safety");
    let base = modeled_assertion_candidate_input(assertion.clone(), 2);
    let decision = Decision::RngDraw(RngDecision {
        stream: RngStreamId::from_name("fresh-runner-non-genesis"),
        value: 7,
    });
    let configuration = accepted_step(base.start().configuration(), decision.clone());
    let input = finding_candidate_input_with_configuration_and_stop(
        &base,
        configuration,
        StopCondition::ExecutionQuanta(1),
    );
    let candidate = finding_candidate_artifact(&input);
    let final_event = SchedulerEventLogEntry::assertion_state_observation(
        1,
        VirtualTime { ticks: 1 },
        assertion,
        AssertionPhase::Violated,
    )
    .unwrap_or_else(|source| panic!("fixture event admission: {source}"));
    let mut runner = QemuFreshExecutionRunner::new(
        BoundaryCaptureLifecycleFactory {
            captured: Arc::new(Mutex::new(Vec::new())),
            final_events: vec![final_event],
            replay_decisions: VecDeque::from([decision]),
            terminal_failure: false,
            terminal_marker: None,
        },
        QemuFreshModeledDriver::new(),
    );

    let outcome = runner
        .replay_finding_candidate_boundary(&input, &candidate, None, &fresh_runner_context())
        .expect("coincident property and timeout candidate replay");
    let QemuFindingCandidateReplayOutcome::Observed(evidence) = outcome else {
        panic!("coincident property and timeout candidate must be observable")
    };
    let (_, _, _, triage) = evidence.into_parts();
    let (failures, _, _, _, _) = triage.into_parts();

    assert!(
        matches!(
            failures.as_slice(),
            [
                crucible::FailureClusterReportFailure::Property(_),
                crucible::FailureClusterReportFailure::Timeout(_)
            ]
        ),
        "unexpected coincident failure order: {failures:?}"
    );
}

#[test]
fn composed_candidate_replay_retains_app_random_choice_and_measurement_leaf() {
    let _metadata = crate::exact_checkpoint_store::test_support::fixture_decode_scope();

    let assertion = AssertionId::from_name("app-random-candidate-safety");
    let base = modeled_assertion_candidate_input(assertion.clone(), 2);
    let selectable = AppRandomSelectable::new(
        &base.scenario().scenario_def(),
        NodeId {
            name: String::from("node-a"),
        },
        RngStreamId::for_node("finding-replay-app-random"),
        11,
        16,
    )
    .expect("app-random selectable");
    let selection = selectable
        .sampled_selection(0x1234_5678_9abc_def0)
        .expect("app-random sampled selection");
    let discovery = selectable.into_discovery().expect("app-random discovery");
    let configuration = Configuration {
        def: base.scenario().scenario_def(),
        schedule: Schedule::empty()
            .appended(Decision::Selection(SelectionDecision::new(&selection))),
    };
    let input = finding_candidate_input_with_configuration(&base, configuration);

    assert_composed_candidate_replay_retains_choice_and_measurement(
        input, discovery, selection, &assertion,
    );
}

#[test]
fn composed_candidate_replay_retains_signal_fault_choice_and_measurement_leaf() {
    let _metadata = crate::exact_checkpoint_store::test_support::fixture_decode_scope();

    let assertion = AssertionId::from_name("signal-fault-candidate-safety");
    let base = modeled_assertion_candidate_input(assertion.clone(), 2);
    let parent = Configuration::genesis(base.scenario().scenario_def());
    let choice = BindingSearchChoice {
        id: SearchChoiceId::from_content_hash(crucible::ContentHash::from_bytes(
            b"finding-replay-signal-choice",
        )),
        candidates_digest: crucible::ContentHash::from_bytes(b"finding-replay-signal-candidates"),
        candidate_count: 2,
        candidate_semantics: crucible::model::BindingSearchCandidateSemantics::Outcome,
        selected_index: None,
        overridden: false,
    };
    let frontier =
        SignalFaultSelectable::runtime_frontier(&parent, VirtualTime { ticks: 17 }, &choice)
            .expect("typed signal-fault frontier");
    let selectable =
        SignalFaultSelectable::from_frontier(&frontier).expect("signal-fault selectable");
    let selection = selectable
        .branch_selection(&parent, 0)
        .expect("signal-fault selection");
    let discovery = selectable.discovery().expect("signal-fault discovery");
    let configuration = selectable
        .resolve_branch(&selection)
        .expect("signal-fault branch")
        .selected()
        .clone();
    let input = finding_candidate_input_with_configuration(&base, configuration);

    assert_composed_candidate_replay_retains_choice_and_measurement(
        input, discovery, selection, &assertion,
    );
}

#[test]
fn finding_candidate_replay_reports_preserving_and_nonpreserving_verdicts() {
    let _metadata = crate::exact_checkpoint_store::test_support::fixture_decode_scope();

    let assertion = AssertionId::from_name("candidate-safety");

    for (predicate_at, expected) in [(1, PropertyVerdict::Passed), (2, PropertyVerdict::Failed)] {
        let input = modeled_assertion_candidate_input(assertion.clone(), predicate_at);
        let candidate = finding_candidate_artifact(&input);
        let final_event = SchedulerEventLogEntry::assertion_state_observation(
            1,
            VirtualTime { ticks: 1 },
            assertion.clone(),
            AssertionPhase::Satisfied,
        )
        .unwrap_or_else(|source| panic!("fixture event admission: {source}"));
        let mut runner = QemuFreshExecutionRunner::new(
            BoundaryCaptureLifecycleFactory {
                captured: Arc::new(Mutex::new(Vec::new())),
                final_events: vec![final_event],
                replay_decisions: VecDeque::new(),
                terminal_failure: false,
                terminal_marker: None,
            },
            QemuFreshModeledDriver::new(),
        );

        let outcome = runner
            .replay_finding_candidate_boundary(&input, &candidate, None, &fresh_runner_context())
            .expect("candidate assertion replay");
        let QemuFindingCandidateReplayOutcome::Observed(evidence) = outcome else {
            panic!("materializable candidate must produce semantic evidence")
        };
        let (replay, _, final_events, _) = (*evidence).into_parts();
        let actual = replay
            .properties()
            .properties()
            .get(assertion.name.as_str())
            .expect("candidate assertion verdict")
            .verdict();

        assert_eq!(actual, expected);
        assert_eq!(final_events.len(), 1);
    }
}

#[test]
fn finding_candidate_replay_reports_prefix_divergence_after_cleanup() {
    let _metadata = crate::exact_checkpoint_store::test_support::fixture_decode_scope();

    let order = Arc::new(Mutex::new(Vec::new()));
    let input = non_genesis_fresh_runner_input_with_decision(Decision::RngDraw(RngDecision {
        stream: RngStreamId::from_name("fresh-runner-non-genesis"),
        value: 8,
    }));
    let candidate = finding_candidate_artifact(&input);
    let mut runner = QemuFreshExecutionRunner::new(
        FakeFreshLifecycleFactory {
            order: Arc::clone(&order),
            cleanup_error: false,
            terminal_after_replay: false,
            checkpoint_ready: true,
        },
        QemuFreshModeledDriver::new(),
    );

    let outcome = runner
        .replay_finding_candidate_boundary(&input, &candidate, None, &fresh_runner_context())
        .expect("incompatible replay is a modeled outcome");

    assert_eq!(
        outcome,
        QemuFindingCandidateReplayOutcome::DeterministicallyIncompatible(
            QemuFindingCandidateIncompatibility::PrefixDiverged,
        )
    );
    assert_eq!(
        order.lock().expect("fresh lifecycle order").as_slice(),
        ["begin", "replay", "shutdown"]
    );
}

#[test]
fn finding_candidate_replay_reports_terminal_prefix_after_cleanup() {
    let _metadata = crate::exact_checkpoint_store::test_support::fixture_decode_scope();

    let order = Arc::new(Mutex::new(Vec::new()));
    let decision = Decision::RngDraw(RngDecision {
        stream: RngStreamId::from_name("fresh-runner-non-genesis"),
        value: 7,
    });
    let input = non_genesis_fresh_runner_input_with_decisions(vec![decision.clone(), decision]);
    let candidate = finding_candidate_artifact(&input);
    let mut runner = QemuFreshExecutionRunner::new(
        FakeFreshLifecycleFactory {
            order: Arc::clone(&order),
            cleanup_error: false,
            terminal_after_replay: true,
            checkpoint_ready: true,
        },
        QemuFreshModeledDriver::new(),
    );

    let outcome = runner
        .replay_finding_candidate_boundary(&input, &candidate, None, &fresh_runner_context())
        .expect("terminal prefix is a modeled incompatibility");

    assert_eq!(
        outcome,
        QemuFindingCandidateReplayOutcome::DeterministicallyIncompatible(
            QemuFindingCandidateIncompatibility::PrefixTerminated,
        )
    );
    assert_eq!(
        order.lock().expect("fresh lifecycle order").as_slice(),
        ["begin", "replay", "shutdown"]
    );
}

#[test]
fn finding_candidate_replay_preserves_cleanup_failure_over_incompatibility() {
    let _metadata = crate::exact_checkpoint_store::test_support::fixture_decode_scope();

    let order = Arc::new(Mutex::new(Vec::new()));
    let input = non_genesis_fresh_runner_input_with_decision(Decision::RngDraw(RngDecision {
        stream: RngStreamId::from_name("fresh-runner-non-genesis"),
        value: 8,
    }));
    let candidate = finding_candidate_artifact(&input);
    let mut runner = QemuFreshExecutionRunner::new(
        FakeFreshLifecycleFactory {
            order: Arc::clone(&order),
            cleanup_error: true,
            terminal_after_replay: false,
            checkpoint_ready: true,
        },
        QemuFreshModeledDriver::new(),
    );

    let error = runner
        .replay_finding_candidate_boundary(&input, &candidate, None, &fresh_runner_context())
        .expect_err("cleanup failure overrides deterministic incompatibility");

    assert!(matches!(
        *error,
        AttemptWorkerFailure::Terminal(QemuFreshExecutionRunnerError::CleanupAfterRunner { .. })
    ));
    assert_eq!(
        order.lock().expect("fresh lifecycle order").as_slice(),
        ["begin", "replay", "shutdown"]
    );
}

#[test]
fn finding_candidate_replay_shares_cancellation_and_still_cleans_up() {
    let _metadata = crate::exact_checkpoint_store::test_support::fixture_decode_scope();

    let order = Arc::new(Mutex::new(Vec::new()));
    let input = non_genesis_fresh_runner_input();
    let candidate = finding_candidate_artifact(&input);
    let cancellation = ExecutionCancellation::default();
    cancellation.cancel_for_test();
    let mut runner = QemuFreshExecutionRunner::new(
        FakeFreshLifecycleFactory {
            order: Arc::clone(&order),
            cleanup_error: false,
            terminal_after_replay: false,
            checkpoint_ready: true,
        },
        QemuFreshModeledDriver::new(),
    );

    let error = runner
        .replay_finding_candidate_boundary(
            &input,
            &candidate,
            None,
            &context(resources(4), cancellation),
        )
        .expect_err("canceled candidate replay remains operational failure");

    assert!(matches!(
        *error,
        AttemptWorkerFailure::Canceled(QemuFreshExecutionRunnerError::StartReplay(
            QemuFreshStartReplayError::Canceled
        ))
    ));
    assert_eq!(
        order.lock().expect("fresh lifecycle order").as_slice(),
        ["begin", "shutdown"]
    );
}
