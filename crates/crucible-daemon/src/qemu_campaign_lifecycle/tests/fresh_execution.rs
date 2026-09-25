//! Fresh replay execution, cleanup, and production continuation tests.

use super::*;

#[test]
fn fresh_runner_replays_authenticated_signal_fault_plan_before_driver() {
    let base = fresh_runner_input();
    let CrucibleResolvedAttemptStart::Discover {
        configuration: parent,
    } = base.start()
    else {
        panic!("fresh runner fixture should discover genesis");
    };
    let choice = BindingSearchChoice {
        id: SearchChoiceId::from_content_hash(crucible::ContentHash::from_bytes(
            b"fresh-runner-signal-choice",
        )),
        candidates_digest: crucible::ContentHash::from_bytes(b"fresh-runner-signal-candidates"),
        candidate_count: 2,
        candidate_semantics: crucible::model::BindingSearchCandidateSemantics::Outcome,
        selected_index: None,
        overridden: false,
    };
    let selectable =
        SignalFaultSelectable::from_binding_choice(parent, VirtualTime::default(), &choice)
            .expect("fresh runner signal selectable");
    let selection = selectable
        .branch_selection(parent, 1)
        .expect("fresh runner signal selection");
    let branch = selectable
        .resolve_branch(&selection)
        .expect("fresh runner signal branch");
    let replay = crucible::SignalFaultCampaignReplayPlan::new(
        branch.selected().clone(),
        vec![branch.clone()],
    )
    .expect("fresh runner signal replay plan");
    let input = non_genesis_fresh_runner_input_with_decisions(branch.decisions().to_vec())
        .with_test_signal_fault_replay(replay);
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

    let outcome = runner
        .execute(&input, &fresh_runner_context())
        .expect("typed signal-fault replay should reach the modeled driver");

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
fn fresh_replay_applies_campaign_selection_at_exact_guest_request() {
    let node = NodeId {
        name: String::from("router-a"),
    };
    let world = World::from_nodes(vec![WorldNode {
        id: node.clone(),
        arch: NodeTemplate::DEFAULT_ARCH,
        memory_mib: NodeTemplate::DEFAULT_MEMORY_MIB,
        cmdline: String::from("guest-selectable-replay-test"),
        ready_point: ReadyPoint::FixedIcount {
            icount: Icount { retired: 1 },
        },
        white_box: WhiteBoxPolicy::Enabled,
        smp_vcpus: NodeTemplate::DEFAULT_SMP_VCPUS,
        kernel: None,
        root_image: None,
        initrd: None,
    }])
    .expect("guest selectable replay World");
    let declaration = SelectableDeclaration::new(
        "product.recovery",
        ChoiceSource::Guest {
            node: node.name.clone(),
            protocol_version: u32::from(crucible_protocol::SELECTABLE_PROTOCOL_VERSION),
        },
        ChoiceDomain::Boolean(BooleanDomain::new(1).expect("Boolean domain")),
        ChoiceValue::Boolean(false),
        ChoiceClassContext::new(BTreeSet::new()).expect("choice class"),
        BTreeSet::from([String::from("recovery")]),
        true,
    )
    .expect("guest selectable declaration");
    let selectables = ScenarioSelectables::new(
        &world,
        ScenarioSelectableLimits::new(4, 8, 16, 32).expect("selectable limits"),
        vec![declaration.clone()],
    )
    .expect("scenario selectables");
    let source = ScenarioDefForm::from_components(
        &world,
        &Plan::empty(),
        &Properties::empty(),
        Seed::from_u64(17),
    )
    .expect("guest selectable replay scenario")
    .with_selectables(selectables)
    .expect("attach guest selectables");
    let scenario = ScenarioDefId::from_hash(CampaignHash::from_bytes(source.id().bytes));
    let parent = Configuration::genesis(source.scenario_def());
    let request = SelectionRequest::new(9, "product.recovery", "routing-epoch-7", None, 256)
        .expect("guest request");
    let pending = SelectablePlanPendingRequest::new(request, 41, 0, 0x1000);
    let discovery =
        crate::guest_selectable::resolve_guest_selectable(scenario, &source, &node, &pending)
            .expect("runtime opportunity");
    let default_selection = Selection::new(
        discovery.opportunity(),
        discovery.domain(),
        discovery.opportunity().default().clone(),
        crucible_campaign::SelectionOrigin::Default,
    )
    .expect("default guest selection");
    let default_target = accepted_step(
        &parent,
        Decision::Selection(SelectionDecision::new(&default_selection)),
    );
    assert_eq!(
        unsupported_fresh_replay_decision(
            &default_target,
            &crucible::SignalFaultCampaignReplayPlan::empty(default_target.clone()),
        ),
        None,
        "the runner prefilter must admit default guest replay"
    );
    let parent_id = ConfigurationId::from_hash(CampaignHash::from_bytes(parent.id().bytes));
    let selection = Selection::new_campaign_branch(
        discovery.opportunity(),
        discovery.domain(),
        ChoiceValue::Boolean(true),
        discovery.opportunity().branch_point_id(parent_id),
    )
    .expect("campaign selection");
    let target = accepted_step(
        &parent,
        Decision::Selection(SelectionDecision::new(&selection)),
    );
    let repository = CampaignRepository::new(
        Arc::new(MemoryBlobBackend::new(
            "guest-selectable-replay-diagnostic",
            1024 * 1024,
        )),
        Arc::new(MemoryRefBackend::new()),
    );
    repository
        .publish_choice_domain(discovery.domain())
        .expect("publish guest choice domain");
    repository
        .publish_selectable(&declaration)
        .expect("publish guest selectable declaration");
    repository
        .publish_choice_opportunity(discovery.opportunity())
        .expect("publish guest choice opportunity");
    repository
        .publish_selection(&selection)
        .expect("publish guest selection");
    let resolved_selection = repository
        .resolve_selection(selection.id().expect("guest selection ID"))
        .expect("resolve guest selection");
    let replay_start = CrucibleResolvedAttemptStart::Branch {
        parent: parent.clone(),
        selection: Box::new(resolved_selection),
        selected: target.clone(),
    };
    assert!(
        replay_start.replay_selection(1).is_none(),
        "expected context must not attach to an unrelated decision index"
    );
    let base_attempt = fresh_runner_input();
    let AttemptStart::Discover {
        configuration: parent_artifact,
    } = base_attempt.attempt().start()
    else {
        panic!("guest branch fixture must start from discovery")
    };
    let SelectionOrigin::CampaignBranch { branch_point, edge } = selection.origin() else {
        panic!("guest replay selection must be a campaign branch")
    };
    let replay_path = BranchPath::new(vec![BranchPathSegment::new(branch_point, edge)])
        .expect("guest replay branch path");
    let replay_attempt = Attempt::new(
        AttemptStart::Branch {
            edge,
            parent: parent_artifact,
            selection: selection.id().expect("guest replay selection ID"),
        },
        replay_path.id().expect("guest replay branch path ID"),
        StopCondition::Terminal,
    )
    .expect("guest replay branch attempt");
    let replies = Arc::new(Mutex::new(Vec::new()));
    let mut lifecycle = FakeFreshLifecycle {
        order: Arc::new(Mutex::new(Vec::new())),
        completed_quanta: 0,
        promotion_observations: None,
        cleanup_error: false,
        pending: vec![
            crucible_qemu::QemuNodeSelectablePendingRequest::from_test_parts(node, pending),
        ],
        replies: Arc::clone(&replies),
        signal_fault_branches: VecDeque::new(),
        terminal_after_replay: false,
        checkpoint_ready: true,
        fingerprint_error: false,
        fingerprint_node_override: Arc::new(Mutex::new(None)),
    };
    let mut current = parent.clone();
    let diagnostic_config = crate::GuestSelectableBoundaryDiagnosticConfig::new(4)
        .expect("guest-selectable diagnostic policy");
    let (diagnostics, diagnostic_lines) =
        crate::guest_selectable::GuestSelectableBoundaryDiagnosticRecorder::capture(
            diagnostic_config,
        );
    let execution_context =
        fresh_runner_context().with_guest_selectable_boundary_diagnostics(diagnostics);
    let mut materialization = QemuFreshStartMaterialization::genesis();
    apply_replayed_guest_selectables::<(), ()>(
        &mut lifecycle,
        &execution_context,
        GuestSelectableReplayContext {
            phase: GuestSelectableReplayPhase::FreshStart,
            attempt_role: GuestSelectableReplayAttemptRole::ExecutingAttempt,
            attempt: &replay_attempt,
            start: &replay_start,
            scenario,
            source: &source,
            target: &target,
        },
        &mut current,
        &mut materialization,
    )
    .expect("exact guest branch replay");

    assert_eq!(current, target);
    let replies = replies.lock().expect("fresh lifecycle replies");
    assert_eq!(replies.len(), 1);
    assert_eq!(
        replies[0].selected_value(),
        Some(ChoiceValue::Boolean(true).canonical_bytes().as_slice())
    );
    {
        let diagnostic_lines = diagnostic_lines.lock().expect("boundary diagnostics");
        assert_eq!(diagnostic_lines.len(), 1);
        assert!(diagnostic_lines[0].contains("stage=replay"));
        assert!(diagnostic_lines[0].contains("decision_index=0"));
        assert!(diagnostic_lines[0].contains("trap_icount=41 stopped_icount=42 vcpu=0"));
        assert!(diagnostic_lines[0].contains("fingerprint_node=\"router-a\""));
        assert!(diagnostic_lines[0].contains("fingerprint_at=0"));
        assert!(
            diagnostic_lines[0]
                .contains("expected_opportunity=crucible.campaign.choice-opportunity@")
        );
    }

    let drift_request = SelectionRequest::new(9, "product.recovery", "routing-epoch-7", None, 256)
        .expect("drifted guest request");
    let drift_pending = SelectablePlanPendingRequest::new(drift_request, 42, 0, 0x1000);
    let drift_replies = Arc::new(Mutex::new(Vec::new()));
    let mut drift_lifecycle = FakeFreshLifecycle {
        order: Arc::new(Mutex::new(Vec::new())),
        completed_quanta: 0,
        promotion_observations: None,
        cleanup_error: false,
        pending: vec![
            crucible_qemu::QemuNodeSelectablePendingRequest::from_test_parts(
                NodeId {
                    name: String::from("router-a"),
                },
                drift_pending,
            ),
        ],
        replies: Arc::clone(&drift_replies),
        signal_fault_branches: VecDeque::new(),
        terminal_after_replay: false,
        checkpoint_ready: true,
        fingerprint_error: false,
        fingerprint_node_override: Arc::new(Mutex::new(None)),
    };
    let mut drift_current = parent.clone();
    let mut drift_materialization = QemuFreshStartMaterialization::genesis();

    let failure = apply_replayed_guest_selectables::<std::io::Error, std::io::Error>(
        &mut drift_lifecycle,
        &execution_context,
        GuestSelectableReplayContext {
            phase: GuestSelectableReplayPhase::FreshStart,
            attempt_role: GuestSelectableReplayAttemptRole::ExecutingAttempt,
            attempt: &replay_attempt,
            start: &replay_start,
            scenario,
            source: &source,
            target: &target,
        },
        &mut drift_current,
        &mut drift_materialization,
    )
    .expect_err("drifted runtime opportunity must fail replay");

    let AttemptWorkerFailure::Terminal(QemuFreshExecutionRunnerError::StartReplay(
        QemuFreshStartReplayError::GuestSelectable(GuestSelectableError::ReplayMismatch(mismatch)),
    )) = &failure
    else {
        panic!("replay mismatch must retain its typed production error chain")
    };
    assert_eq!(
        finding_candidate_incompatibility(&failure),
        Some(QemuFindingCandidateIncompatibility::SelectionMismatch)
    );
    assert_eq!(
        mismatch.mismatch().kind(),
        SelectionReplayMismatchKind::OpportunityIdentity
    );
    assert_eq!(mismatch.phase(), GuestSelectableReplayPhase::FreshStart);
    assert_eq!(
        mismatch.attempt_role(),
        GuestSelectableReplayAttemptRole::ExecutingAttempt
    );
    assert_eq!(
        mismatch.attempt(),
        replay_attempt.id().expect("replay attempt identity")
    );
    assert_eq!(
        mismatch.replayed_configuration(),
        ConfigurationId::from_hash(CampaignHash::from_bytes(parent.id().bytes))
    );
    assert_eq!(mismatch.decision_index(), 0);
    assert_eq!(mismatch.node(), "router-a");
    assert_eq!(mismatch.selectable(), "product.recovery");
    assert_eq!(mismatch.request_instance(), "routing-epoch-7");
    assert_eq!(mismatch.request_sequence(), 9);
    assert_eq!(mismatch.request_icount(), 42);
    assert_eq!(mismatch.request_vcpu_index(), 0);
    let expected_opportunity = mismatch
        .expected_opportunity()
        .expect("branch start retains expected opportunity context");
    assert_eq!(
        expected_opportunity.declaration(),
        discovery.opportunity().declaration()
    );
    assert_eq!(
        expected_opportunity.coordinate(),
        discovery.opportunity().coordinate()
    );
    assert_eq!(expected_opportunity.instance(), "routing-epoch-7");
    assert_eq!(
        mismatch.replayed_opportunity().instance(),
        "routing-epoch-7"
    );
    assert_eq!(drift_current, parent);
    assert!(drift_replies.lock().expect("drift replies").is_empty());

    let execution = ExecutionId::from_bytes([0x39; 16]).expect("execution identity");
    let diagnostic =
        crate::packaged_qemu_executor::packaged_attempt_failure_diagnostic(execution, &failure);
    assert!(diagnostic.contains("phase=fresh-start"));
    assert!(diagnostic.contains("attempt-role=executing-attempt"));
    assert!(diagnostic.contains("failed-predicate=selection-opportunity-identity"));
    assert!(diagnostic.contains("decision-index=0"));
    assert!(diagnostic.contains("request-sequence=9"));
    assert!(diagnostic.contains("request-icount=42"));
    assert!(diagnostic.contains("request-vcpu=0"));
    assert!(diagnostic.contains("expected-declaration="));
    assert!(diagnostic.contains("expected-choice-scheduler-coordinate="));

    let oversized = crate::packaged_qemu_executor::packaged_attempt_failure_diagnostic(
        execution,
        &OversizedFailure { source: failure },
    );
    assert!(oversized.contains("phase=fresh-start"));
    assert!(oversized.contains("attempt-role=executing-attempt"));
    assert!(oversized.contains("failed-predicate=selection-opportunity-identity"));
    assert!(oversized.ends_with("\n  ... diagnostic truncated"));
    assert!(
        oversized.len()
            <= crate::packaged_qemu_executor::MAX_PACKAGED_ATTEMPT_FAILURE_DIAGNOSTIC_BYTES
    );
}

#[test]
fn fresh_runner_replay_divergence_cleans_up_without_calling_driver() {
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
    let input = non_genesis_fresh_runner_input_with_decision(Decision::RngDraw(RngDecision {
        stream: RngStreamId::from_name("fresh-runner-non-genesis"),
        value: 8,
    }));

    let error = runner
        .execute(&input, &fresh_runner_context())
        .expect_err("drifted replay prefix must fail closed");

    let AttemptWorkerFailure::Terminal(QemuFreshExecutionRunnerError::StartReplay(
        QemuFreshStartReplayError::DivergedAt {
            reason,
            index,
            expected,
            observed,
        },
    )) = error
    else {
        panic!("expected typed fresh replay divergence: {error:?}");
    };
    assert_eq!(reason, "decision prefix");
    assert_eq!(index, 0);
    assert!(expected.contains("value: 8"), "{expected}");
    assert!(observed.contains("value: 7"), "{observed}");
    assert_eq!(
        order.lock().expect("fresh lifecycle order").as_slice(),
        ["begin", "replay", "shutdown"]
    );
}

#[test]
fn fresh_runner_replay_honors_cancellation_before_first_quantum() {
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
    let cancellation = ExecutionCancellation::default();
    cancellation.cancel_for_test();

    let error = runner
        .execute(
            &non_genesis_fresh_runner_input(),
            &context(resources(4), cancellation),
        )
        .expect_err("canceled replay must fail before a scheduler quantum");

    assert!(matches!(
        error,
        AttemptWorkerFailure::Canceled(QemuFreshExecutionRunnerError::StartReplay(
            QemuFreshStartReplayError::Canceled
        ))
    ));
    assert_eq!(
        order.lock().expect("fresh lifecycle order").as_slice(),
        ["begin", "shutdown"]
    );
}

#[test]
fn fresh_runner_replay_is_bounded_by_admitted_quanta() {
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
    let decision = Decision::RngDraw(RngDecision {
        stream: RngStreamId::from_name("fresh-runner-non-genesis"),
        value: 7,
    });
    let input = non_genesis_fresh_runner_input_with_decisions(vec![decision.clone(), decision]);

    let error = runner
        .execute(
            &input,
            &context(resources(1), ExecutionCancellation::default()),
        )
        .expect_err("replay must not exceed the attempt quantum ceiling");

    assert!(matches!(
        error,
        AttemptWorkerFailure::Terminal(QemuFreshExecutionRunnerError::StartReplay(
            QemuFreshStartReplayError::ResourceRefusal(_)
        ))
    ));
    assert_eq!(
        order.lock().expect("fresh lifecycle order").as_slice(),
        ["begin", "replay", "shutdown"]
    );
}

#[test]
fn attempt_start_verifier_seals_the_prefix_before_final_drain() {
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
    let checkpoint = ExactCheckpointId::try_from(ContentId::for_bytes(
        ObjectKind::ExactManifest,
        5,
        b"ordinary-attempt-start-proof",
    ))
    .expect("resume checkpoint");
    let resume_context = fresh_runner_context().with_resume_checkpoint(Some(checkpoint));

    let proof = runner
        .verify_attempt_start(&input, &resume_context)
        .expect("cold-replayed attempt-start prefix");

    assert_eq!(
        proof.attempt_event_count(input.start().configuration(), &[]),
        Some(0)
    );
    assert_eq!(
        order.lock().expect("fresh lifecycle order").as_slice(),
        ["begin", "replay", "shutdown"]
    );
}

#[test]
fn attempt_start_verifier_rejects_unsupported_override_before_factory() {
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
    let input = non_genesis_fresh_runner_input_with_decisions_for_stop(
        vec![Decision::Override(OverrideDecision {
            point: SchedulingPoint {
                key: String::from("unsupported-fresh-replay"),
            },
            choice: ChoiceTag {
                name: String::from("unsupported-choice"),
            },
        })],
        StopCondition::Terminal,
    );
    let expected = input.start().configuration().id();
    let checkpoint = ExactCheckpointId::try_from(ContentId::for_bytes(
        ObjectKind::ExactManifest,
        5,
        b"unsupported-override-start",
    ))
    .expect("resume checkpoint");
    let resume_context = fresh_runner_context().with_resume_checkpoint(Some(checkpoint));

    let error = runner
        .verify_attempt_start(&input, &resume_context)
        .expect_err("unsupported override start must fail closed");

    assert!(matches!(
        error,
        AttemptWorkerFailure::Terminal(
            QemuFreshExecutionRunnerError::StartDecisionUnsupported {
                configuration,
                decision: 0,
            }
        ) if configuration == expected
    ));
    assert!(order.lock().expect("fresh lifecycle order").is_empty());
}

#[test]
fn fresh_runner_cleans_up_and_preserves_driver_failure_classification() {
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
            failure: Some(FakeFreshDriverFailure::Retryable),
        },
    );

    let error = runner
        .execute(&fresh_runner_input(), &fresh_runner_context())
        .expect_err("driver retry should remain classified");

    assert!(matches!(
        error,
        AttemptWorkerFailure::Retryable(QemuFreshExecutionRunnerError::Driver("driver retry"))
    ));
    assert_eq!(
        order.lock().expect("fresh lifecycle order").as_slice(),
        ["begin", "drive", "shutdown"]
    );
}

#[test]
fn fresh_runner_cleans_up_after_terminal_fingerprint_capture_failure() {
    let order = Arc::new(Mutex::new(Vec::new()));
    let failing = FingerprintFailingFreshLifecycleFactory {
        inner: FakeFreshLifecycleFactory {
            order: Arc::clone(&order),
            cleanup_error: false,
            terminal_after_replay: false,
            checkpoint_ready: true,
        },
    };
    let (factory, evidence) = QemuObservedFreshAttemptLifecycleFactory::with_evidence(failing);
    let mut runner = QemuFreshExecutionRunner::new(
        factory,
        FakeFreshDriver {
            order: Arc::clone(&order),
            failure: None,
        },
    );

    let error = runner
        .execute(&fresh_runner_input(), &fresh_runner_context())
        .expect_err("missing terminal fingerprint authority must fail closed");

    assert!(matches!(
        error,
        AttemptWorkerFailure::Terminal(QemuFreshExecutionRunnerError::TerminalFingerprintCapture(
            SchedulerError::BoundaryViolation { .. }
        ))
    ));
    assert_eq!(
        order.lock().expect("fresh lifecycle order").as_slice(),
        ["begin", "drive", "shutdown"]
    );
    assert_eq!(
        evidence
            .snapshot()
            .expect("evidence after capture failure")
            .terminal_fingerprints(),
        None
    );
}

#[test]
fn cleanup_failure_overrides_terminal_fingerprint_capture_failure() {
    let order = Arc::new(Mutex::new(Vec::new()));
    let failing = FingerprintFailingFreshLifecycleFactory {
        inner: FakeFreshLifecycleFactory {
            order: Arc::clone(&order),
            cleanup_error: true,
            terminal_after_replay: false,
            checkpoint_ready: true,
        },
    };
    let (factory, evidence) = QemuObservedFreshAttemptLifecycleFactory::with_evidence(failing);
    let mut runner = QemuFreshExecutionRunner::new(
        factory,
        FakeFreshDriver {
            order: Arc::clone(&order),
            failure: None,
        },
    );

    let error = runner
        .execute(&fresh_runner_input(), &fresh_runner_context())
        .expect_err("cleanup failure must retain precedence");

    let AttemptWorkerFailure::Terminal(runner_error) = &error else {
        panic!("cleanup failure must retain the prior capture failure");
    };
    let QemuFreshExecutionRunnerError::CleanupAfterRunner { failure, .. } = runner_error else {
        panic!("cleanup failure must retain the prior capture failure");
    };
    assert!(matches!(
        failure.as_ref(),
        QemuFreshExecutionRunnerError::TerminalFingerprintCapture(
            SchedulerError::BoundaryViolation { .. }
        )
    ));
    let message = runner_error.to_string();
    assert!(message.contains("injected fresh lifecycle cleanup failure"));
    assert!(message.contains("TerminalFingerprintCapture"));
    assert_eq!(
        order.lock().expect("fresh lifecycle order").as_slice(),
        ["begin", "drive", "shutdown"]
    );
    assert_eq!(
        evidence
            .snapshot()
            .expect("evidence after cleanup failure")
            .terminal_fingerprints(),
        None
    );
}

#[test]
fn fresh_cleanup_failure_overrides_driver_retry_and_retains_diagnostics() {
    let order = Arc::new(Mutex::new(Vec::new()));
    let mut runner = QemuFreshExecutionRunner::new(
        FakeFreshLifecycleFactory {
            order: Arc::clone(&order),
            cleanup_error: true,
            terminal_after_replay: false,
            checkpoint_ready: true,
        },
        FakeFreshDriver {
            order: Arc::clone(&order),
            failure: Some(FakeFreshDriverFailure::Retryable),
        },
    );

    let error = runner
        .execute(&fresh_runner_input(), &fresh_runner_context())
        .expect_err("cleanup failure must take precedence");

    assert!(matches!(
        error,
        AttemptWorkerFailure::Terminal(QemuFreshExecutionRunnerError::CleanupAfterDriver {
            driver: "driver retry",
            ..
        })
    ));
    assert_eq!(
        order.lock().expect("fresh lifecycle order").as_slice(),
        ["begin", "drive", "shutdown"]
    );
}

#[test]
fn production_lifecycle_resource_admission_keeps_retry_and_cancel_classes() {
    let unavailable = classify_production_lifecycle_failure(
        QemuAttemptProductionVmLifecycleError::ResourceInstallation(
            QemuVmRealizationError::ExecutorUnavailable {
                operation: "install test resources",
                message: String::from("temporarily unavailable"),
            },
        ),
    );
    assert!(matches!(unavailable, AttemptWorkerFailure::Retryable(_)));

    let canceled = classify_production_lifecycle_failure(
        QemuAttemptProductionVmLifecycleError::ResourceInstallation(
            QemuVmRealizationError::Canceled {
                operation: "install test resources",
            },
        ),
    );
    assert!(matches!(canceled, AttemptWorkerFailure::Canceled(_)));

    let terminal = classify_production_lifecycle_failure(
        QemuAttemptProductionVmLifecycleError::ScenarioIdentityMismatch,
    );
    assert!(matches!(terminal, AttemptWorkerFailure::Terminal(_)));
}

#[test]
fn production_continuation_plan_consumes_the_authenticated_reseed() {
    let input = fresh_runner_input();
    let source = accepted_step(
        input.start().configuration(),
        Decision::RngDraw(RngDecision {
            stream: RngStreamId::from_name("continuation-plan-source"),
            value: 7,
        }),
    );
    let frontier = VirtualTime { ticks: 37 };
    let seed = Seed::from_u64(0x51ec_7ed0);
    let continuation = OwnedQemuAttemptContinuation {
        input: AttemptContinuationInput::scheduler_reseed(
            test_continuation_source_observation(),
            frontier.ticks,
            seed.bytes(),
        ),
        source: source.clone(),
    };

    let plan =
        production_continuation_plan(Some(&continuation)).expect("production continuation plan");

    assert_eq!(
        plan,
        ProductionContinuationPlan::Reseed {
            base: source,
            frontier,
            seed,
        }
    );
}
