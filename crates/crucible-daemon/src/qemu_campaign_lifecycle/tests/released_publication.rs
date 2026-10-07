//! Refusals at the owner hook's canonical replay-publication boundary.

use super::*;

fn publication_fixture(
    outcome: crucible::QuantumOutcome,
    after_quanta: u64,
    terminal: bool,
) -> FakeFreshLifecycle {
    FakeFreshLifecycle {
        order: Arc::new(Mutex::new(Vec::new())),
        completed_quanta: 0,
        promotion_observations: None,
        cleanup_error: false,
        pending: Vec::new(),
        replies: Arc::new(Mutex::new(Vec::new())),
        signal_fault_branches: VecDeque::new(),
        terminal_after_replay: false,
        released_host_outcome: Some((after_quanta, outcome, terminal)),
        checkpoint_ready: true,
        fingerprint_error: false,
        fingerprint_node_override: Arc::new(Mutex::new(None)),
    }
}

fn retained_outcome(configuration: Configuration) -> crucible::QuantumOutcome {
    crucible::QuantumOutcome {
        configuration,
        frontier: VirtualTime { ticks: 19 },
        advanced_node: None,
        resolved_events: Vec::new(),
        decisions: Vec::new(),
        discovered_choices: Vec::new(),
        event_log_entries: Vec::new(),
        event_log_segment_bytes: Vec::new(),
        event_log_segment_text: String::new(),
        event_log_segment_hash: None,
        event_log_offset: crucible::EventLogOffset::default(),
        scheduler_quiescence: None,
    }
}

#[test]
fn retained_publication_refuses_gapped_suffix_and_regressed_decision_prefix() {
    let input = fresh_runner_input();
    let parent = input.start().configuration().clone();
    let selected = accepted_step(
        &parent,
        Decision::RngDraw(RngDecision {
            stream: RngStreamId::from_name("released-prefix"),
            value: 7,
        }),
    );
    for (current, sequences) in [
        (parent.clone(), vec![1]),
        (parent.clone(), vec![0, 2]),
        (selected.clone(), Vec::new()),
    ] {
        let mut outcome = retained_outcome(parent.clone());
        outcome.event_log_entries = sequences
            .into_iter()
            .map(|sequence| {
                SchedulerEventLogEntry::execution_budget_exhausted(
                    sequence,
                    VirtualTime { ticks: 19 },
                    "released-suffix",
                )
            })
            .collect();
        let mut lifecycle = publication_fixture(outcome, 0, false);
        let mut replay = QemuFreshStartMaterialization::genesis();
        let mut observed = current.clone();

        let error = super::super::guest_selectable::publish_replayed_host_outcomes::<(), ()>(
            &mut lifecycle,
            &selected,
            &mut observed,
            &mut replay,
        )
        .expect_err("invalid retained suffix must refuse replay");

        assert!(matches!(
            error,
            AttemptWorkerFailure::Terminal(QemuFreshExecutionRunnerError::StartReplay(
                QemuFreshStartReplayError::Diverged
            ))
        ));
        assert_eq!(observed, current);
        let parts = replay.into_parts();
        assert!(parts.0.is_empty());
        assert_eq!(parts.2, 0);
        assert_eq!(parts.3, VirtualTime::default());
        assert!(lifecycle.order.lock().expect("operation order").is_empty());
    }
}

#[test]
fn newly_terminal_retained_boundary_refuses_further_replay_without_another_run() {
    let input = fresh_runner_input();
    let parent = input.start().configuration().clone();
    let first = accepted_step(
        &parent,
        Decision::RngDraw(RngDecision {
            stream: RngStreamId::from_name("fresh-runner-non-genesis"),
            value: 7,
        }),
    );
    let target = accepted_step(
        &first,
        Decision::RngDraw(RngDecision {
            stream: RngStreamId::from_name("beyond-terminal"),
            value: 8,
        }),
    );
    for (after, released) in [(0, parent.clone()), (1, first.clone())] {
        let mut lifecycle = publication_fixture(retained_outcome(released), after, true);

        let error = materialize_start_from::<(), ()>(
            &mut lifecycle,
            &input,
            parent.clone(),
            &target,
            &fresh_runner_context(),
            QemuFreshStartMaterialization::genesis(),
        )
        .expect_err("terminal retained boundary cannot execute toward a later start");

        assert!(matches!(
            error,
            AttemptWorkerFailure::Terminal(QemuFreshExecutionRunnerError::StartReplay(
                QemuFreshStartReplayError::Terminated
            ))
        ));
        assert_eq!(lifecycle.completed_quanta, after + 1);
        assert_eq!(
            lifecycle.order.lock().expect("operation order").len(),
            after as usize
        );
    }

    let mut lifecycle = publication_fixture(retained_outcome(parent.clone()), 0, true);
    let replay = materialize_start_from::<(), ()>(
        &mut lifecycle,
        &input,
        parent.clone(),
        &parent,
        &fresh_runner_context(),
        QemuFreshStartMaterialization::genesis(),
    )
    .expect("exact terminal target remains a valid start");
    let parts = replay.into_parts();
    assert_eq!(parts.2, 1);
    assert_eq!(parts.3, VirtualTime { ticks: 19 });
    assert!(matches!(
        parts.5,
        Some(crucible::QuantumTerminalVerdict::Failed(_))
    ));
    assert!(lifecycle.order.lock().expect("operation order").is_empty());
}
