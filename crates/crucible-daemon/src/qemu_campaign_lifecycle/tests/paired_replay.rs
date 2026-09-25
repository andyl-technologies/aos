//! Paired finding replay evidence and first-causal-divergence tests.

use super::*;

#[test]
fn fresh_paired_replay_keeps_selected_evidence_and_both_distinct_coverages_coherent() {
    let fork_entry = |sequence, label: &'static [u8]| {
        let mut attributes = BTreeMap::new();
        attributes.insert(
            String::from("from_checkpoint_id"),
            EventAttributeValue::String(crucible::ContentHash::from_bytes(label).to_hex()),
        );
        attributes.insert(
            String::from("schedule_delta"),
            EventAttributeValue::String(
                crucible::ContentHash::from_bytes(&[label, b"-schedule"].concat()).to_hex(),
            ),
        );
        condition_open_payload_entry_for_test(
            sequence,
            VirtualTime { ticks: 1 },
            SchedulerEventLogClass::Causal,
            EventPayload::new("fork", attributes.clone()),
            SchedulerEventLogPayload::Diagnostic(EventDiagnosticPayload::new(
                "paired-fork",
                EventLevel::Info,
                attributes,
            )),
        )
    };
    let world = World::from_nodes_and_links(Vec::new(), Vec::new()).expect("empty World");
    let properties =
        Properties::from_assertions_for_world(&world, Vec::new()).expect("empty property set");
    let scenario = ScenarioDefForm::from_components(
        &world,
        &Plan::empty(),
        &properties,
        Seed::from_u64(0xa2b0_c0d0),
    )
    .expect("paired replay scenario");
    let input =
        modeled_fresh_runner_input_for_scenario(scenario, StopCondition::VirtualTimeNanoseconds(1));
    let candidate = finding_candidate_artifact(&input);
    let expected_event = condition_observation_entry_for_test(
        1,
        &ObservableEvent::coverage_marker(
            Icount { retired: 1 },
            NodeId {
                name: String::from("paired-node"),
            },
            MarkerId::from_name("expected-path"),
        ),
    );
    let reproduced_event = condition_observation_entry_for_test(
        1,
        &ObservableEvent::coverage_marker(
            Icount { retired: 1 },
            NodeId {
                name: String::from("paired-node"),
            },
            MarkerId::from_name("reproduced-path"),
        ),
    );
    let expected_boundary = fork_entry(2, b"expected-fork");
    let reproduced_boundary = fork_entry(2, b"reproduced-fork");
    let mut runner = QemuFreshExecutionRunner::new(
        SequencedBoundaryCaptureLifecycleFactory {
            captured: Arc::new(Mutex::new(Vec::new())),
            final_events: VecDeque::from([
                vec![expected_event, expected_boundary],
                vec![reproduced_event, reproduced_boundary],
            ]),
            replay_decisions: VecDeque::new(),
        },
        QemuFreshModeledDriver::new(),
    );
    let context = fresh_runner_context();

    let expected = runner
        .replay_finding_candidate_boundary(&input, &candidate, None, &context)
        .expect("expected candidate replay");
    let QemuFindingCandidateReplayOutcome::Observed(expected) = expected else {
        panic!("expected replay must reach the candidate boundary")
    };
    let (expected_replay, _, _, _) = (*expected).clone().into_parts();
    let expected_coverage = expected_replay.coverage().clone();
    let reproduced = runner
        .replay_finding_candidate_boundary(&input, &candidate, None, &context)
        .expect("reproduced candidate replay");
    let QemuFindingCandidateReplayOutcome::Observed(reproduced) = reproduced else {
        panic!("reproduced replay must reach the candidate boundary")
    };
    let (_, _, _, expected_triage) = (*expected).clone().into_parts();
    let (_, _, _, reproduced_triage) = (*reproduced).clone().into_parts();
    let (_, expected_causal, _, _, _) = expected_triage.into_parts();
    let (_, reproduced_causal, _, _, _) = reproduced_triage.into_parts();
    assert_ne!(expected_causal, reproduced_causal);
    let reproduced = Box::new((*reproduced).compare_against_expected_replay(&expected));
    let reproduced_coverage = reproduced
        .paired_reproduced_coverage()
        .expect("paired replay retains reproduced coverage")
        .clone();
    let (selected_replay, _, selected_events, triage) = (*reproduced).into_parts();
    let (failures, causal_entries, coverage_fingerprint, _, paired_logs) = triage.into_parts();

    assert_ne!(expected_coverage, reproduced_coverage);
    assert_eq!(selected_replay.coverage(), &expected_coverage);
    assert_eq!(selected_events.len(), 2);
    // Reaching the declared stop records a quantum boundary before the
    // selected coverage and fork entries drained at that boundary.
    assert_eq!(causal_entries.len(), 3);
    assert_eq!(&causal_entries[1..], selected_events.as_slice());
    assert_eq!(
        coverage_fingerprint,
        crucible::coverage_fingerprint_from_event_log(&selected_events)
    );
    assert!(matches!(
        failures.as_slice(),
        [crucible::FailureClusterReportFailure::Divergence(_)]
    ));
    assert!(paired_logs.is_some());
}

#[test]
fn replay_divergence_uses_the_actual_first_causal_log_mismatch() {
    let expected = vec![SchedulerEventLogEntry::execution_budget_exhausted(
        0,
        VirtualTime { ticks: 9 },
        "execution-quanta",
    )];
    let reproduced = vec![SchedulerEventLogEntry::execution_budget_exhausted(
        0,
        VirtualTime { ticks: 9 },
        "virtual-time",
    )];
    let comparison = crucible::compare_event_log_determinism(&expected, &reproduced);
    let mismatch = comparison.mismatch().expect("actual causal mismatch");
    let expected_point = mismatch.first_location().expect("mismatch coordinate");
    let expected_coverage = ContentHash::from_bytes(b"expected-replay-coverage");
    let reproduced_coverage = ContentHash::from_bytes(b"reproduced-replay-coverage");
    let expected_inputs =
        crate::qemu_campaign_driver::QemuFindingCandidateTriageInputs::replay_for_test(
            expected.clone(),
            expected_coverage,
            vec![b"expected-frame".to_vec()],
        );
    let reproduced_inputs =
        crate::qemu_campaign_driver::QemuFindingCandidateTriageInputs::replay_for_test(
            reproduced.clone(),
            reproduced_coverage,
            vec![b"reproduced-frame".to_vec()],
        );

    let (triage, selected_expected) = crate::qemu_campaign_driver::QemuFindingCandidateTriageInputs::from_replay_determinism_mismatch(
        &expected_inputs,
        &reproduced_inputs,
    )
    .expect("divergence triage inputs");
    let (failures, causal_entries, coverage_fingerprint, frames, paired_logs) = triage.into_parts();
    let [crucible::FailureClusterReportFailure::Divergence(divergence)] = failures.as_slice()
    else {
        panic!("mismatched causal logs must retain one divergence source")
    };

    assert!(selected_expected);
    assert_eq!(divergence.raw_index, expected_point.raw_index);
    assert_eq!(divergence.kind, expected_point.kind);
    assert!(
        divergence.expected_state_summary.contains(
            &mismatch
                .expected_entry
                .as_ref()
                .expect("expected mismatch entry")
                .content_hash()
                .to_hex()
        )
    );
    assert!(
        divergence.reproduced_state_summary.contains(
            &mismatch
                .reproduced_entry
                .as_ref()
                .expect("reproduced mismatch entry")
                .content_hash()
                .to_hex()
        )
    );
    assert_eq!(causal_entries, expected);
    assert_eq!(coverage_fingerprint, expected_coverage);
    assert_eq!(frames, [b"expected-frame".to_vec()]);
    assert_eq!(paired_logs, Some((expected, reproduced)));
}

#[test]
fn replay_divergence_uses_reproduced_evidence_when_expected_entry_is_absent() {
    let expected = Vec::new();
    let reproduced = vec![SchedulerEventLogEntry::execution_budget_exhausted(
        0,
        VirtualTime { ticks: 9 },
        "execution-quanta",
    )];
    let expected_coverage = ContentHash::from_bytes(b"empty-expected-replay-coverage");
    let reproduced_coverage = ContentHash::from_bytes(b"present-reproduced-replay-coverage");
    let expected_inputs =
        crate::qemu_campaign_driver::QemuFindingCandidateTriageInputs::replay_for_test(
            expected.clone(),
            expected_coverage,
            vec![b"empty-expected-frame".to_vec()],
        );
    let reproduced_inputs =
        crate::qemu_campaign_driver::QemuFindingCandidateTriageInputs::replay_for_test(
            reproduced.clone(),
            reproduced_coverage,
            vec![b"present-reproduced-frame".to_vec()],
        );

    let (triage, selected_expected) = crate::qemu_campaign_driver::QemuFindingCandidateTriageInputs::from_replay_determinism_mismatch(
        &expected_inputs,
        &reproduced_inputs,
    )
    .expect("divergence triage inputs");
    let (_, causal_entries, coverage_fingerprint, frames, paired_logs) = triage.into_parts();

    assert!(!selected_expected);
    assert_eq!(causal_entries, reproduced);
    assert_eq!(coverage_fingerprint, reproduced_coverage);
    assert_eq!(frames, [b"present-reproduced-frame".to_vec()]);
    assert_eq!(paired_logs, Some((expected, reproduced)));
}
