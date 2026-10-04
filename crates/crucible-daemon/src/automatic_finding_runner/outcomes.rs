//! End-to-end automatic finding outcome tests.

#![cfg(test)]

use super::super::finding_signature::property_violation_signature;
use super::*;

struct DescendantInputFixture {
    repository: Arc<CampaignRepository>,
    store: CampaignExecutorStore,
    input: CrucibleAttemptExecution,
    retention_basis: AttemptRetentionPolicyBasis,
    property: String,
    schedule: Schedule,
    controls: Vec<(u64, ObservationId)>,
}

fn descendant_input_fixture() -> DescendantInputFixture {
    const CAMPAIGN: &str = "automatic-finding-descendant";

    let scenario = crucible::happy_path_scenario()
        .expect("happy-path scenario")
        .scenario;
    let property = scenario
        .properties()
        .assertions()
        .first()
        .expect("declared assertion")
        .id
        .name
        .clone();
    let scenario_record = encode_crucible_scenario_artifact(&scenario).expect("scenario artifact");
    let genesis = Configuration::genesis(scenario.scenario_def());
    let genesis_record =
        encode_crucible_configuration_artifact(&scenario_record, &genesis.schedule)
            .expect("genesis artifact");
    let lineage = CampaignLineage::new(
        scenario_record.scenario(),
        scenario_record.id().expect("scenario ID"),
        genesis_record.configuration(),
        genesis_record.id().expect("genesis ID"),
        "automatic-finding-descendant-test",
        "qemu-test",
        BTreeMap::from([(String::from("control"), 1)]),
        scenario_record.payload_schema(),
        1,
    )
    .expect("campaign lineage");
    let repository = Arc::new(CampaignRepository::new(
        Arc::new(MemoryBlobBackend::new(
            "automatic-finding-descendant-test",
            u64::MAX,
        )),
        Arc::new(MemoryRefBackend::new()),
    ));
    repository
        .publish_scenario_artifact(
            scenario_record.scenario(),
            scenario_record.payload_schema(),
            scenario_record.payload().to_vec(),
        )
        .expect("publish scenario");
    repository
        .publish_configuration_artifact(
            genesis_record.scenario(),
            genesis_record.scenario_artifact(),
            genesis_record.configuration(),
            genesis_record.payload_schema(),
            genesis_record.payload().to_vec(),
        )
        .expect("publish genesis");
    let policy = finding_campaign_policy(&lineage);
    let created = repository
        .create(CAMPAIGN, &lineage, &policy, &BTreeMap::new())
        .expect("create finding fixture campaign");
    let funded = repository
        .apply_control(
            CAMPAIGN,
            &ControlRequest {
                command: campaign_command("fund"),
                expected_snapshot: created.snapshot_id(),
                action: CampaignControlAction::GrantBudget(
                    BudgetGrant::new(0, 3).expect("attempt budget"),
                ),
            },
        )
        .expect("fund finding fixture campaign");
    let running = repository
        .apply_control(
            CAMPAIGN,
            &ControlRequest {
                command: campaign_command("resume"),
                expected_snapshot: funded.new_snapshot,
                action: CampaignControlAction::Resume,
            },
        )
        .expect("run finding fixture campaign");
    let discovery = DiscoveryRequest::new(
        campaign_command("discover"),
        running.new_snapshot,
        lineage.genesis_content(),
        StopCondition::VirtualTimePicoseconds(1),
    )
    .expect("discovery request");
    let first_admission = repository
        .submit_discovery_request(CAMPAIGN, &discovery)
        .expect("admit first source attempt");
    let first = repository
        .load_attempt(first_admission.attempt)
        .expect("load first source attempt");
    let store = CampaignExecutorStore::new(Arc::clone(&repository));
    let path = store
        .load_branch_path(first.path())
        .expect("load source path");
    let first_input = CrucibleAttemptExecution::from_test_parts(
        lineage.clone(),
        scenario.clone(),
        first.clone(),
        path.clone(),
        CrucibleResolvedAttemptStart::Discover {
            configuration: genesis.clone(),
        },
    );
    let first_source_result = failed_result_with_stop(
        &first_input,
        &property,
        StopOutcome::Reached(StopCondition::VirtualTimePicoseconds(1)),
    );
    let first_source_observation = store
        .publish_observation_candidate(first_source_result.observation())
        .expect("publish first source observation");

    let second = select_controlled_continuation(ControlledContinuationRequest {
        repository: &repository,
        lineage: &lineage,
        campaign: CAMPAIGN,
        origin: &first,
        source_observation: first_source_observation,
        source_frontier_ticks: 1,
        stop: StopCondition::VirtualTimePicoseconds(2),
        marker: 0x29,
    });
    let first_origin = CrucibleAttemptOrigin::new_with_source_stop(
        first.clone(),
        genesis.clone(),
        crucible::SignalFaultCampaignReplayPlan::empty(genesis.clone()),
        StopOutcome::Reached(StopCondition::VirtualTimePicoseconds(1)),
    );
    let second_input = CrucibleAttemptExecution::from_test_parts(
        lineage.clone(),
        scenario.clone(),
        second.clone(),
        path.clone(),
        CrucibleResolvedAttemptStart::AfterAttempt {
            base: Box::new(CrucibleResolvedAttemptStart::Discover {
                configuration: genesis.clone(),
            }),
            base_signal_fault_replay: crucible::SignalFaultCampaignReplayPlan::empty(
                genesis.clone(),
            ),
            origins: Box::new(CrucibleAttemptOrigins::new(
                first_origin.clone(),
                Vec::new(),
            )),
        },
    );
    let second_source_result = failed_result_with_stop(
        &second_input,
        &property,
        StopOutcome::Reached(StopCondition::VirtualTimePicoseconds(2)),
    );
    let second_source_observation = store
        .publish_observation_candidate(second_source_result.observation())
        .expect("publish second source observation");

    let current = select_controlled_continuation(ControlledContinuationRequest {
        repository: &repository,
        lineage: &lineage,
        campaign: CAMPAIGN,
        origin: &second,
        source_observation: second_source_observation,
        source_frontier_ticks: 2,
        stop: StopCondition::Terminal,
        marker: 0x47,
    });
    let second_origin = CrucibleAttemptOrigin::new_with_source_stop(
        second,
        genesis.clone(),
        crucible::SignalFaultCampaignReplayPlan::empty(genesis.clone()),
        StopOutcome::Reached(StopCondition::VirtualTimePicoseconds(2)),
    );
    let input = CrucibleAttemptExecution::from_test_parts(
        lineage,
        scenario,
        current,
        path,
        CrucibleResolvedAttemptStart::AfterAttempt {
            base: Box::new(CrucibleResolvedAttemptStart::Discover {
                configuration: genesis.clone(),
            }),
            base_signal_fault_replay: crucible::SignalFaultCampaignReplayPlan::empty(genesis),
            origins: Box::new(CrucibleAttemptOrigins::new(
                first_origin,
                vec![second_origin],
            )),
        },
    );
    let schedule = Schedule::empty().appended(Decision::DeliveryOrder(DeliveryOrderDecision {
        at: VirtualTime { ticks: 3 },
        order: Vec::new(),
    }));
    let controls = vec![
        (1, first_source_observation),
        (2, second_source_observation),
    ];
    let retention_basis = repository
        .attempt_retention_policy_basis_at(
            repository
                .head(CAMPAIGN)
                .expect("campaign head")
                .snapshot_id(),
            input.attempt().id().expect("current attempt ID"),
        )
        .expect("current retention policy basis");

    DescendantInputFixture {
        repository,
        store,
        input,
        retention_basis,
        property,
        schedule,
        controls,
    }
}

#[test]
fn authenticated_assertion_observation_stop_produces_a_finding_signature() {
    let (input, property, _, _) = input_fixture();
    let scenario = encode_crucible_scenario_artifact(input.scenario()).expect("scenario");
    let child =
        encode_crucible_configuration_artifact(&scenario, &input.start().configuration().schedule)
            .expect("configuration");
    let boundary = ObservationQuantumBoundary::new(1, 0, 1, 0).expect("quantum boundary");
    let entry = CampaignHash::derive("test.observation-entry", property.as_bytes());
    let proof = ObservationStopProof::new(
        ObservationCondition::AssertionViolationTransition(property.clone()),
        ObservationStopSatisfaction::AssertionViolationTransition,
        child.configuration(),
        boundary,
        ObservationEventLogProof::new(
            CampaignHash::derive("test.event-prefix", b"empty"),
            Some(CampaignHash::derive("test.event-segment", b"assertion")),
            1,
            1,
            CampaignHash::derive("test.event-digest", b"assertion"),
        ),
        Some(
            AssertionViolationWitness::new(property.clone(), 0, entry).expect("assertion witness"),
        ),
    )
    .expect("observation stop proof");
    let result = failed_result_with_stop(
        &input,
        &property,
        StopOutcome::ObservationReached(Box::new(proof)),
    );

    let signature = property_violation_signature(&input, result.observation())
        .expect("valid observation signature")
        .expect("assertion finding signature");
    assert_eq!(signature.property(), Some(property.as_str()));
    assert_eq!(signature.failure_class(), ASSERTION_FAILURE_CLASS);
}

#[test]
fn automatic_finding_replays_both_passes_under_the_original_budget_and_path() {
    let (input, property, store, retention_basis) = input_fixture();
    let main_calls = Arc::new(AtomicUsize::new(0));
    let replay_calls = Arc::new(AtomicUsize::new(0));
    let quarantines = Arc::new(AtomicUsize::new(0));
    let observed = Arc::new(Mutex::new(Vec::new()));
    let main = MainRunner {
        result: failed_result(&input, &property),
        calls: Arc::clone(&main_calls),
        quarantines: Arc::clone(&quarantines),
    };
    let replay = ReplayRunner {
        calls: Arc::clone(&replay_calls),
        observed: Arc::clone(&observed),
        property,
        expected_controls: None,
        controlled_calls: None,
    };
    let mut runner = AutomaticFindingExecutionRunner::new(
        store,
        test_finding_exact_retention_source(),
        main,
        replay,
    );
    let context = AttemptExecutionContext::new(
        AttemptResourceLimits::new(1, 1, 0, 5).expect("attempt limits"),
        ExecutionRetentionIntent::Discard,
        ExecutionCancellation::default(),
        ExecutionCheckpointRequest::default(),
        crucible_campaign::AttemptRetentionPolicyDisposition::Required(retention_basis),
    );

    let outcome = runner
        .execute(&input, &context)
        .expect("automatic finding execution");
    let AttemptExecutionProduct::PreparedSemantic(result) = outcome.product() else {
        panic!("automatic finding returned a nonsemantic result")
    };
    let finding = result.finding().expect("automatic finding");
    let minimized =
        crucible::ReproductionArtifact::from_compact_binary(finding.minimized().payload())
            .expect("minimized reproduction");
    assert!(minimized.schedule().decisions().is_empty());
    assert_eq!(main_calls.load(Ordering::SeqCst), 1);
    assert_eq!(replay_calls.load(Ordering::SeqCst), 4);
    assert_eq!(quarantines.load(Ordering::SeqCst), 0);
    assert_eq!(context.consumed_execution_quanta(), 5);

    let observed = observed.lock().expect("replay observations");
    assert_eq!(
        observed
            .iter()
            .map(|(_, decisions)| *decisions)
            .collect::<Vec<_>>(),
        [1, 0, 1, 0]
    );
    assert!(observed.iter().all(|(path, _)| path == input.path()));
}

#[test]
fn default_runner_does_not_probe_an_ordinary_success() {
    let (input, property, store, retention_basis) = input_fixture();
    let replay_calls = Arc::new(AtomicUsize::new(0));
    let main = MainRunner {
        result: failed_result_with_stop(&input, &property, StopOutcome::TerminalSuccess),
        calls: Arc::new(AtomicUsize::new(0)),
        quarantines: Arc::new(AtomicUsize::new(0)),
    };
    let replay = ReplayRunner {
        calls: Arc::clone(&replay_calls),
        observed: Arc::new(Mutex::new(Vec::new())),
        property,
        expected_controls: None,
        controlled_calls: None,
    };
    let mut runner = AutomaticFindingExecutionRunner::new(
        store,
        test_finding_exact_retention_source(),
        main,
        replay,
    );
    let context = AttemptExecutionContext::new(
        AttemptResourceLimits::new(1, 1, 0, 2).expect("attempt limits"),
        ExecutionRetentionIntent::Discard,
        ExecutionCancellation::default(),
        ExecutionCheckpointRequest::default(),
        crucible_campaign::AttemptRetentionPolicyDisposition::Required(retention_basis),
    );

    let outcome = runner
        .execute(&input, &context)
        .expect("default automatic finding execution");
    let AttemptExecutionProduct::PreparedSemantic(result) = outcome.product() else {
        panic!("default automatic finding execution returned a nonsemantic result")
    };

    assert!(result.finding().is_none());
    assert_eq!(replay_calls.load(Ordering::SeqCst), 0);
    assert_eq!(
        runner.last_determinism_probe(),
        AutomaticFindingDeterminismProbeDisposition::NotRequested
    );
    assert_eq!(context.consumed_execution_quanta(), 1);
}

#[test]
fn paired_probe_derives_fingerprint_from_actual_divergence_kind_and_node() {
    let (input, property, store, retention_basis) = input_fixture();
    let main_calls = Arc::new(AtomicUsize::new(0));
    let replay_calls = Arc::new(AtomicUsize::new(0));
    let quarantines = Arc::new(AtomicUsize::new(0));
    let main = MainRunner {
        result: failed_result_with_stop(&input, &property, StopOutcome::TerminalSuccess),
        calls: Arc::clone(&main_calls),
        quarantines: Arc::clone(&quarantines),
    };
    let replay = DivergenceReplayRunner {
        calls: Arc::clone(&replay_calls),
        property,
        candidate_replays: 0,
        incompatible_replay_indices: BTreeSet::new(),
        mismatched_replay_indices: BTreeSet::new(),
    };
    let mut runner = AutomaticFindingExecutionRunner::new(
        store,
        test_finding_exact_retention_source(),
        main,
        replay,
    )
    .with_determinism_finding_verification();
    let context = AttemptExecutionContext::new(
        AttemptResourceLimits::new(1, 1, 0, 16).expect("attempt limits"),
        ExecutionRetentionIntent::Discard,
        ExecutionCancellation::default(),
        ExecutionCheckpointRequest::default(),
        crucible_campaign::AttemptRetentionPolicyDisposition::Required(retention_basis),
    );

    let outcome = runner
        .execute(&input, &context)
        .expect("paired divergence finding execution");
    let AttemptExecutionProduct::PreparedSemantic(result) = outcome.product() else {
        panic!("paired divergence finding returned a nonsemantic result")
    };
    let finding = result.finding().expect("paired divergence finding");
    let kind = CampaignHash::derive(
        "crucible.daemon.qemu-causal-divergence-kind.v1",
        b"execution_budget_exhausted",
    );
    let node = CampaignHash::derive(
        "crucible.daemon.qemu-causal-divergence-node.v1",
        b"paired-probe-node",
    );
    let mut material = Vec::with_capacity(96);
    material.extend_from_slice(&input.lineage().scenario().as_hash().as_bytes());
    material.extend_from_slice(&kind.as_bytes());
    material.extend_from_slice(&node.as_bytes());
    let expected_fingerprint = CampaignHash::derive(
        "crucible.daemon.qemu-causal-divergence-fingerprint.v1",
        &material,
    );

    assert_eq!(finding.bundle().signature().kind(), FindingKind::Divergence);
    assert_eq!(
        finding.bundle().signature().fingerprint(),
        expected_fingerprint
    );
    assert!(finding.bundle().triage_evidence().is_some());
    assert_eq!(
        runner.last_determinism_probe(),
        AutomaticFindingDeterminismProbeDisposition::Diverged
    );
    assert_eq!(main_calls.load(Ordering::SeqCst), 1);
    assert_eq!(replay_calls.load(Ordering::SeqCst), 10);
    assert_eq!(context.consumed_execution_quanta(), 11);
    assert_eq!(quarantines.load(Ordering::SeqCst), 0);
}

#[test]
fn paired_probe_binds_main_coverage_when_reproduced_coverage_differs() {
    let (input, property, store, retention_basis) = input_fixture();
    let main_result = failed_result_with_stop(&input, &property, StopOutcome::TerminalSuccess);
    let main_coverage = main_result
        .observation()
        .coverage()
        .id()
        .expect("main observation coverage ID")
        .content_id();
    let reproduced_coverage = divergence_probe_coverage()
        .id()
        .expect("reproduced coverage ID")
        .content_id();
    assert_ne!(main_coverage, reproduced_coverage);

    let main = MainRunner {
        result: main_result,
        calls: Arc::new(AtomicUsize::new(0)),
        quarantines: Arc::new(AtomicUsize::new(0)),
    };
    let replay = DivergenceReplayRunner {
        calls: Arc::new(AtomicUsize::new(0)),
        property,
        candidate_replays: 0,
        incompatible_replay_indices: BTreeSet::new(),
        mismatched_replay_indices: BTreeSet::new(),
    };
    let mut runner = AutomaticFindingExecutionRunner::new(
        store,
        test_finding_exact_retention_source(),
        main,
        replay,
    )
    .with_determinism_finding_verification();
    let context = AttemptExecutionContext::new(
        AttemptResourceLimits::new(1, 1, 0, 16).expect("attempt limits"),
        ExecutionRetentionIntent::Discard,
        ExecutionCancellation::default(),
        ExecutionCheckpointRequest::default(),
        crucible_campaign::AttemptRetentionPolicyDisposition::Required(retention_basis),
    );

    let outcome = runner
        .execute(&input, &context)
        .expect("paired divergence finding execution");
    let AttemptExecutionProduct::PreparedSemantic(result) = outcome.product() else {
        panic!("paired divergence finding returned a nonsemantic result")
    };
    let signature = result
        .finding()
        .expect("paired divergence finding")
        .bundle()
        .signature();

    assert_eq!(
        signature.causal_evidence(),
        &BTreeSet::from([main_coverage])
    );
    assert!(!signature.causal_evidence().contains(&reproduced_coverage));
}

#[test]
fn divergence_reduction_budget_exhaustion_preserves_the_original_result() {
    let (input, property, store, retention_basis) = input_fixture();
    let original_result = failed_result_with_stop(&input, &property, StopOutcome::TerminalSuccess);
    let replay_calls = Arc::new(AtomicUsize::new(0));
    let quarantines = Arc::new(AtomicUsize::new(0));
    let main = MainRunner {
        result: original_result.clone(),
        calls: Arc::new(AtomicUsize::new(0)),
        quarantines: Arc::clone(&quarantines),
    };
    let replay = DivergenceReplayRunner {
        calls: Arc::clone(&replay_calls),
        property,
        candidate_replays: 0,
        incompatible_replay_indices: BTreeSet::new(),
        mismatched_replay_indices: BTreeSet::new(),
    };
    let mut runner = AutomaticFindingExecutionRunner::new(
        store,
        test_finding_exact_retention_source(),
        main,
        replay,
    )
    .with_determinism_finding_verification();
    let context = AttemptExecutionContext::new(
        AttemptResourceLimits::new(1, 1, 0, 3).expect("attempt limits"),
        ExecutionRetentionIntent::Discard,
        ExecutionCancellation::default(),
        ExecutionCheckpointRequest::default(),
        crucible_campaign::AttemptRetentionPolicyDisposition::Required(retention_basis),
    );

    let outcome = runner
        .execute(&input, &context)
        .expect("incomplete divergence reduction preserves the attempt");
    let AttemptExecutionProduct::PreparedSemantic(result) = outcome.product() else {
        panic!("incomplete divergence reduction returned a nonsemantic result")
    };

    assert_eq!(result.as_ref(), &original_result);
    assert_eq!(
        runner.last_determinism_probe(),
        AutomaticFindingDeterminismProbeDisposition::Incomplete
    );
    assert_eq!(replay_calls.load(Ordering::SeqCst), 2);
    assert_eq!(context.consumed_execution_quanta(), 3);
    assert_eq!(quarantines.load(Ordering::SeqCst), 0);
}

#[test]
fn incompatible_reduction_trial_does_not_discard_a_later_reproduced_finding() {
    let (input, property, store, retention_basis) = input_fixture();
    let replay_calls = Arc::new(AtomicUsize::new(0));
    let quarantines = Arc::new(AtomicUsize::new(0));
    let main = MainRunner {
        result: failed_result_with_stop(&input, &property, StopOutcome::TerminalSuccess),
        calls: Arc::new(AtomicUsize::new(0)),
        quarantines: Arc::clone(&quarantines),
    };
    let replay = DivergenceReplayRunner {
        calls: Arc::clone(&replay_calls),
        property,
        candidate_replays: 0,
        incompatible_replay_indices: BTreeSet::from([1, 3]),
        mismatched_replay_indices: BTreeSet::new(),
    };
    let mut runner = AutomaticFindingExecutionRunner::new(
        store,
        test_finding_exact_retention_source(),
        main,
        replay,
    )
    .with_determinism_finding_verification();
    let context = AttemptExecutionContext::new(
        AttemptResourceLimits::new(1, 1, 0, 16).expect("attempt limits"),
        ExecutionRetentionIntent::Discard,
        ExecutionCancellation::default(),
        ExecutionCheckpointRequest::default(),
        crucible_campaign::AttemptRetentionPolicyDisposition::Required(retention_basis),
    );

    let outcome = runner
        .execute(&input, &context)
        .expect("later reproduced divergence remains a finding");
    let AttemptExecutionProduct::PreparedSemantic(result) = outcome.product() else {
        panic!("reproduced divergence returned a nonsemantic result")
    };

    assert!(result.finding().is_some());
    assert_eq!(
        runner.last_determinism_probe(),
        AutomaticFindingDeterminismProbeDisposition::Diverged
    );
    assert!(replay_calls.load(Ordering::SeqCst) > 2);
    assert_eq!(quarantines.load(Ordering::SeqCst), 0);
}

#[test]
fn probe_divergence_that_does_not_reproduce_preserves_the_successful_main_result() {
    let (input, property, store, retention_basis) = input_fixture();
    let original_result = failed_result_with_stop(&input, &property, StopOutcome::TerminalSuccess);
    let replay_calls = Arc::new(AtomicUsize::new(0));
    let quarantines = Arc::new(AtomicUsize::new(0));
    let main = MainRunner {
        result: original_result.clone(),
        calls: Arc::new(AtomicUsize::new(0)),
        quarantines: Arc::clone(&quarantines),
    };
    let replay = DivergenceReplayRunner {
        calls: Arc::clone(&replay_calls),
        property,
        candidate_replays: 0,
        incompatible_replay_indices: BTreeSet::from([0]),
        mismatched_replay_indices: BTreeSet::new(),
    };
    let mut runner = AutomaticFindingExecutionRunner::new(
        store,
        test_finding_exact_retention_source(),
        main,
        replay,
    )
    .with_determinism_finding_verification();
    let context = AttemptExecutionContext::new(
        AttemptResourceLimits::new(1, 1, 0, 16).expect("attempt limits"),
        ExecutionRetentionIntent::Discard,
        ExecutionCancellation::default(),
        ExecutionCheckpointRequest::default(),
        crucible_campaign::AttemptRetentionPolicyDisposition::Required(retention_basis),
    );

    let outcome = runner
        .execute(&input, &context)
        .expect("nonreproducing optional divergence preserves the attempt");
    let AttemptExecutionProduct::PreparedSemantic(result) = outcome.product() else {
        panic!("nonreproducing divergence returned a nonsemantic result")
    };

    assert_eq!(result.as_ref(), &original_result);
    assert!(result.finding().is_none());
    assert_eq!(
        runner.last_determinism_probe(),
        AutomaticFindingDeterminismProbeDisposition::Incomplete
    );
    assert!(replay_calls.load(Ordering::SeqCst) > 2);
    assert_eq!(quarantines.load(Ordering::SeqCst), 0);
}

#[test]
fn probe_divergence_with_a_different_original_signature_preserves_the_main_result() {
    let (input, property, store, retention_basis) = input_fixture();
    let original_result = failed_result_with_stop(&input, &property, StopOutcome::TerminalSuccess);
    let quarantines = Arc::new(AtomicUsize::new(0));
    let main = MainRunner {
        result: original_result.clone(),
        calls: Arc::new(AtomicUsize::new(0)),
        quarantines: Arc::clone(&quarantines),
    };
    let replay = DivergenceReplayRunner {
        calls: Arc::new(AtomicUsize::new(0)),
        property,
        candidate_replays: 0,
        incompatible_replay_indices: BTreeSet::new(),
        mismatched_replay_indices: BTreeSet::from([0]),
    };
    let mut runner = AutomaticFindingExecutionRunner::new(
        store,
        test_finding_exact_retention_source(),
        main,
        replay,
    )
    .with_determinism_finding_verification();
    let context = AttemptExecutionContext::new(
        AttemptResourceLimits::new(1, 1, 0, 16).expect("attempt limits"),
        ExecutionRetentionIntent::Discard,
        ExecutionCancellation::default(),
        ExecutionCheckpointRequest::default(),
        crucible_campaign::AttemptRetentionPolicyDisposition::Required(retention_basis),
    );

    let outcome = runner
        .execute(&input, &context)
        .expect("signature-mismatched optional divergence preserves the attempt");
    let AttemptExecutionProduct::PreparedSemantic(result) = outcome.product() else {
        panic!("signature-mismatched divergence returned a nonsemantic result")
    };

    assert_eq!(result.as_ref(), &original_result);
    assert!(result.finding().is_none());
    assert_eq!(
        runner.last_determinism_probe(),
        AutomaticFindingDeterminismProbeDisposition::Incomplete
    );
    assert_eq!(quarantines.load(Ordering::SeqCst), 0);
}

#[cfg(target_os = "linux")]
#[test]
fn descendant_finding_replay_preserves_controls_signature_and_retained_world() {
    let fixture = descendant_input_fixture();
    let DescendantInputFixture {
        repository,
        store,
        input,
        retention_basis,
        property,
        schedule: original_schedule,
        controls: expected_controls,
    } = fixture;
    let resources = finding_fixture_resources();
    let cancellation = ExecutionCancellation::default();
    let physical_active = Arc::new(AtomicUsize::new(1));
    let physical_finishes = Arc::new(AtomicUsize::new(0));
    let physical_quarantines = Arc::new(AtomicUsize::new(0));
    let underlying = TestProcessGuard::new(
        resources,
        cancellation.clone(),
        Arc::clone(&physical_active),
        Arc::clone(&physical_finishes),
        Arc::clone(&physical_quarantines),
    );
    let owner =
        QemuHotForkWorldResourceOwner::new(underlying, 1).expect("retained World resource owner");
    let broker = QemuHotForkWorldAuxiliaryResourceBroker::new();
    let fallback_begins = Arc::new(AtomicUsize::new(0));
    let retained_calls = Arc::new(AtomicUsize::new(0));
    let replay_calls = Arc::new(AtomicUsize::new(0));
    let controlled_calls = Arc::new(AtomicUsize::new(0));
    let observed = Arc::new(Mutex::new(Vec::new()));
    let main = RetainedWorldMainRunner {
        result: failed_result_for_schedule(&input, &property, &original_schedule),
        owner: Some(owner),
        binding: None,
        broker: broker.clone(),
    };
    let replay = RetainedReplayRunner {
        inner: ReplayRunner {
            calls: Arc::clone(&replay_calls),
            observed: Arc::clone(&observed),
            property,
            expected_controls: Some(expected_controls),
            controlled_calls: Some(Arc::clone(&controlled_calls)),
        },
        resources: QemuHotForkWorldAuxiliaryResourceFactory::new(
            broker,
            RejectingFreshFactory {
                begins: Arc::clone(&fallback_begins),
            },
        ),
        retained_calls: Arc::clone(&retained_calls),
    };
    let mut runner = AutomaticFindingExecutionRunner::new(
        store.clone(),
        test_finding_exact_retention_source(),
        main,
        replay,
    );
    let context = AttemptExecutionContext::new(
        resources,
        ExecutionRetentionIntent::RetainOnFailure,
        cancellation,
        ExecutionCheckpointRequest::default(),
        crucible_campaign::AttemptRetentionPolicyDisposition::Required(retention_basis),
    );

    let outcome = runner
        .execute(&input, &context)
        .expect("descendant automatic finding execution");
    assert_eq!(
        outcome.materialization(),
        CrucibleMaterializationTier::HotFork
    );
    let AttemptExecutionProduct::PreparedSemantic(result) = outcome.product() else {
        panic!("descendant automatic finding returned a nonsemantic result")
    };
    let observation_candidate = result.observation().clone();
    let finding = result
        .finding()
        .expect("descendant automatic finding")
        .clone();
    let minimized =
        crucible::ReproductionArtifact::from_compact_binary(finding.minimized().payload())
            .expect("minimized descendant reproduction");
    assert!(minimized.schedule().decisions().is_empty());
    assert_eq!(replay_calls.load(Ordering::SeqCst), 4);
    assert_eq!(controlled_calls.load(Ordering::SeqCst), 4);
    assert_eq!(retained_calls.load(Ordering::SeqCst), 4);
    assert_eq!(fallback_begins.load(Ordering::SeqCst), 0);
    assert_eq!(context.consumed_execution_quanta(), 5);
    assert_eq!(physical_active.load(Ordering::SeqCst), 1);

    let observation = store
        .publish_observation_candidate(&observation_candidate)
        .expect("publish descendant finding observation");
    assert_eq!(physical_active.load(Ordering::SeqCst), 1);
    let candidate = finding
        .publish_for_executor(&store, test_finding_exact_retention_source().as_ref())
        .expect("publish descendant finding closure");
    assert_eq!(physical_active.load(Ordering::SeqCst), 1);
    let durable = repository
        .load_finding_candidate_bundle(candidate)
        .expect("reload durable descendant finding closure");
    assert_eq!(physical_active.load(Ordering::SeqCst), 1);
    assert_eq!(durable.observation(), observation);

    let original_target = FindingTarget::Configuration(
        finding
            .original_configuration()
            .id()
            .expect("original configuration ID"),
    );
    let minimized_target = FindingTarget::Configuration(
        finding
            .minimized_configuration()
            .id()
            .expect("minimized configuration ID"),
    );
    assert_ne!(original_target, minimized_target);
    assert_eq!(durable.signature().target(), Some(original_target));
    let signatures = durable.signature_minimization();
    assert_eq!(
        signatures.minimization_pass(),
        signatures.verification_pass()
    );
    let minimized_signature = signatures
        .minimization_pass()
        .iter()
        .flatten()
        .find(|signature| signature.target() == Some(minimized_target))
        .expect("minimization pass observed minimized descendant signature");
    let verified_signature = signatures
        .verification_pass()
        .iter()
        .flatten()
        .find(|signature| signature.target() == Some(minimized_target))
        .expect("verification pass observed minimized descendant signature");
    assert_eq!(minimized_signature, verified_signature);
    assert_ne!(durable.signature(), minimized_signature);
    assert_eq!(
        FindingReplaySignature::from_observed(durable.signature()),
        FindingReplaySignature::from_observed(minimized_signature),
    );

    assert_eq!(
        runner
            .reconcile_execution(AttemptExecutionDisposition::Observation(observation))
            .expect("reconcile retained descendant World"),
        AttemptExecutionReconciliationStep::Complete,
    );
    assert_eq!(physical_active.load(Ordering::SeqCst), 0);
    assert_eq!(physical_finishes.load(Ordering::SeqCst), 1);
    assert_eq!(physical_quarantines.load(Ordering::SeqCst), 0);
}

#[test]
fn post_execution_validation_failure_quarantines_main_authority() {
    let (input, _, store, retention_basis) = input_fixture();
    let main_calls = Arc::new(AtomicUsize::new(0));
    let replay_calls = Arc::new(AtomicUsize::new(0));
    let quarantines = Arc::new(AtomicUsize::new(0));
    let observed = Arc::new(Mutex::new(Vec::new()));
    let main = MainRunner {
        result: failed_result(&input, "undeclared-property"),
        calls: Arc::clone(&main_calls),
        quarantines: Arc::clone(&quarantines),
    };
    let replay = ReplayRunner {
        calls: Arc::clone(&replay_calls),
        observed,
        property: String::from("undeclared-property"),
        expected_controls: None,
        controlled_calls: None,
    };
    let mut runner = AutomaticFindingExecutionRunner::new(
        store,
        test_finding_exact_retention_source(),
        main,
        replay,
    );
    let context = AttemptExecutionContext::new(
        AttemptResourceLimits::new(1, 1, 0, 5).expect("attempt limits"),
        ExecutionRetentionIntent::Discard,
        ExecutionCancellation::default(),
        ExecutionCheckpointRequest::default(),
        crucible_campaign::AttemptRetentionPolicyDisposition::Required(retention_basis),
    );

    assert!(matches!(
        runner.execute(&input, &context),
        Err(AttemptWorkerFailure::Terminal(
            AutomaticFindingExecutionRunnerError::Campaign(_)
        ))
    ));
    assert_eq!(main_calls.load(Ordering::SeqCst), 1);
    assert_eq!(replay_calls.load(Ordering::SeqCst), 0);
    assert_eq!(quarantines.load(Ordering::SeqCst), 1);
}
