//! Branch replay through the production whole-world runner.

fn accepted_step(
    configuration: &crucible::Configuration,
    decision: crucible::Decision,
) -> crucible::Configuration {
    match crucible::try_step(configuration, decision) {
        Ok(configuration) => configuration,
        Err(error) => panic!("test configuration step should be accepted: {error}"),
    }
}

use super::reconciliation::repository_execution_fixture;
use super::*;

fn branch_execution_input(
    source: ChoiceSource,
    domain: ChoiceDomain,
    default: ChoiceValue,
    selected_value: ChoiceValue,
    name: &str,
) -> CrucibleAttemptExecution {
    let base = if matches!(source, ChoiceSource::Guest { .. }) {
        execution_input_for_scenario(guest_selectable_scenario())
    } else {
        execution_input()
    };
    let declaration = if matches!(source, ChoiceSource::Guest { .. }) {
        guest_selectable_declaration()
    } else {
        SelectableDeclaration::new(
            name,
            source,
            domain.clone(),
            default,
            ChoiceClassContext::new(BTreeSet::new()).expect("branch choice class"),
            BTreeSet::new(),
            true,
        )
        .expect("branch selectable declaration")
    };
    let repository = CampaignRepository::new(
        Arc::new(MemoryBlobBackend::new(
            "hot-world-branch-selection",
            8 * 1024 * 1024,
        )),
        Arc::new(MemoryRefBackend::new()),
    );
    repository
        .publish_choice_domain(&domain)
        .expect("publish branch choice domain");
    repository
        .publish_selectable(&declaration)
        .expect("publish branch selectable");
    let opportunity = if matches!(declaration.source(), ChoiceSource::Guest { .. }) {
        let pending = branch_replay_guest_pending(&declaration, "publication");
        crate::guest_selectable::resolve_guest_selectable(
            base.lineage().scenario(),
            base.scenario(),
            pending.node(),
            pending.pending(),
        )
        .expect("resolve guest branch opportunity")
        .opportunity()
        .clone()
    } else {
        crucible_campaign::ChoiceOpportunity::new(
            base.lineage().scenario(),
            &declaration,
            &domain,
            ChoiceCoordinate {
                scheduler: CampaignHash::derive("hot-world-branch-scheduler", name.as_bytes()),
                producer: CampaignHash::derive("hot-world-branch-producer", name.as_bytes()),
            },
            name,
            None,
        )
        .expect("branch choice opportunity")
    };
    repository
        .publish_choice_opportunity(&opportunity)
        .expect("publish branch choice opportunity");

    let crate::CrucibleResolvedAttemptStart::Discover {
        configuration: parent,
    } = base.start()
    else {
        panic!("branch fixture base must begin at discovery")
    };
    let parent = parent.clone();
    let parent_id = ConfigurationId::from_hash(CampaignHash::from_bytes(parent.id().bytes));
    let branch_point = opportunity.branch_point_id(parent_id);
    let selection =
        Selection::new_campaign_branch(&opportunity, &domain, selected_value, branch_point)
            .expect("campaign branch selection");
    repository
        .publish_selection(&selection)
        .expect("publish campaign branch selection");
    let resolved = repository
        .resolve_selection(selection.id().expect("branch selection id"))
        .expect("resolve campaign branch selection");
    let SelectionOrigin::CampaignBranch { edge, .. } = selection.origin() else {
        panic!("campaign branch selection has the wrong origin")
    };
    let selected = accepted_step(
        &parent,
        Decision::Selection(SelectionDecision::new(&selection)),
    );
    let path =
        BranchPath::new(vec![BranchPathSegment::new(branch_point, edge)]).expect("branch path");
    let attempt = Attempt::new(
        AttemptStart::Branch {
            edge,
            parent: base.lineage().genesis_content(),
            selection: selection.id().expect("branch selection id"),
        },
        path.id().expect("branch path id"),
        StopCondition::Terminal,
    )
    .expect("branch attempt");

    CrucibleAttemptExecution::from_test_parts(
        base.lineage().clone(),
        base.scenario().clone(),
        attempt,
        path,
        crate::CrucibleResolvedAttemptStart::Branch {
            parent,
            selection: Box::new(resolved),
            selected,
        },
    )
}

fn run_branch_through_hot_world_runner(input: CrucibleAttemptExecution, expect_guest_reply: bool) {
    let (_repository, _store, _lineage, _attempt, result, _scenario) =
        repository_execution_fixture();
    let observations = BranchReplayObservations::new();
    let factory = BranchReplayLifecycleFactory {
        observations: observations.clone(),
    };
    let (factory, evidence) = QemuObservedFreshAttemptLifecycleFactory::with_evidence(factory);
    let runner = QemuHotForkWorldExecutionRunner::new(
        factory,
        BranchReplayDriver {
            result,
            observations: observations.clone(),
        },
    );
    let fallback_calls = Arc::new(AtomicUsize::new(0));
    let runner = QemuHotFirstExecutionRouter::new(
        runner,
        NeverFallbackRunner {
            calls: Arc::clone(&fallback_calls),
        },
    );
    let runner = PackagedQemuInitialExecutionRunner::<_, NeverFallbackRunner>::HotFork(runner);
    let runner = QemuAttemptExecutionRouter::new(runner, NeverResumeRunner);
    let mut runner = QemuTerminalEvidenceExecutionRunner::new(runner, evidence.clone());
    let context = execution_context(&input, 0x83);
    let (parent, selected, selected_value) = match input.start() {
        crate::CrucibleResolvedAttemptStart::Branch {
            parent,
            selection,
            selected,
        } => (
            parent.clone(),
            selected.clone(),
            selection.selection().value().clone(),
        ),
        crate::CrucibleResolvedAttemptStart::Discover { .. } => {
            panic!("branch runner fixture must contain a branch start")
        }
        crate::CrucibleResolvedAttemptStart::AfterAttempt { .. } => {
            panic!("branch runner fixture must not contain a continuation start")
        }
    };

    let outcome = runner
        .execute(&input, &context)
        .expect("packaged hot-world route must execute the selected branch");
    assert_eq!(
        outcome.materialization(),
        CrucibleMaterializationTier::HotFork
    );
    assert!(matches!(
        outcome.product(),
        AttemptExecutionProduct::PreparedSemantic(_)
    ));
    assert_eq!(fallback_calls.load(Ordering::SeqCst), 0);
    let expected_replay_requests = if expect_guest_reply {
        Vec::new()
    } else {
        vec![parent]
    };
    assert_eq!(
        *observations
            .replay_requests
            .lock()
            .expect("branch replay requests"),
        expected_replay_requests
    );
    assert_eq!(
        *observations
            .driver_starts
            .lock()
            .expect("branch driver starts"),
        [selected]
    );
    let replies = observations
        .guest_replies
        .lock()
        .expect("branch replay guest replies");
    assert_eq!(replies.len(), usize::from(expect_guest_reply));
    if let Some(reply) = replies.first() {
        assert_eq!(reply.sequence(), 7);
        assert_eq!(
            reply.selected_value(),
            Some(selected_value.canonical_bytes().as_slice())
        );
    }
    drop(replies);
    assert_eq!(
        observations
            .terminal_fingerprint_prepares
            .load(Ordering::SeqCst),
        1
    );
    assert_eq!(observations.shutdowns.load(Ordering::SeqCst), 1);

    let expected_nodes = input
        .scenario()
        .world()
        .vm_nodes()
        .iter()
        .map(|node| node.id.clone())
        .collect::<BTreeSet<_>>();
    let terminal_fingerprints = evidence
        .snapshot()
        .expect("hot-fork evidence snapshot")
        .terminal_fingerprints()
        .expect("hot-fork terminal fingerprints")
        .to_vec();
    assert!(!terminal_fingerprints.is_empty());
    assert_eq!(
        terminal_fingerprints
            .iter()
            .map(|sample| sample.node.clone())
            .collect::<BTreeSet<_>>(),
        expected_nodes
    );
    assert!(terminal_fingerprints.iter().all(|sample| {
        sample.at == crucible::VirtualTime { ticks: 1 }
            && sample.fingerprint.hash == ContentHash::from_bytes(sample.node.name.as_bytes())
    }));

    assert_eq!(
        runner
            .reconcile_execution(AttemptExecutionDisposition::Canceled)
            .expect("reconcile scripted hot-world branch"),
        AttemptExecutionReconciliationStep::Complete
    );
    assert_eq!(observations.recoveries.load(Ordering::SeqCst), 1);
    assert_eq!(observations.quarantines.load(Ordering::SeqCst), 0);
    runner
        .reconcile_execution(AttemptExecutionDisposition::Canceled)
        .expect_err("a packaged route reconciles one successful execution exactly once");
    assert_eq!(observations.recoveries.load(Ordering::SeqCst), 1);
    assert_eq!(observations.quarantines.load(Ordering::SeqCst), 0);
}

#[test]
fn hot_world_runner_honors_an_inherited_quantum_boundary_without_driving() {
    let completed_quanta = 3;
    let stop = StopCondition::ExecutionQuanta(completed_quanta);
    let scenario = crucible::happy_path_scenario()
        .expect("hot-fork terminal evidence scenario")
        .scenario;
    let input = execution_input_for_scenario_with_stop(scenario, stop.clone());
    let crate::CrucibleResolvedAttemptStart::Discover { configuration } = input.start() else {
        panic!("inherited-boundary fixture must begin at discovery")
    };
    assert_eq!(configuration.def, input.scenario().scenario_def());
    let mut source_log = EventLog::new();
    let prefix = source_log
        .append_observable_events([ObservableEvent::coverage_marker(
            Icount { retired: 9 },
            NodeId {
                name: String::from("node-a"),
            },
            MarkerId::from_name("world-runner-inherited-prefix"),
        )])
        .expect("inherited source prefix");
    let expected_coverage = crucible::event_log_coverage_projection(&prefix.entries)
        .entries()
        .iter()
        .map(|entry| CampaignHash::from_bytes(entry.observation.content_hash().bytes))
        .collect::<BTreeSet<_>>();
    let observations = InheritedBoundaryObservations::new();
    let (factory, evidence) = QemuObservedFreshAttemptLifecycleFactory::with_evidence(
        InheritedBoundaryLifecycleFactory {
            start_events: prefix.entries,
            completed_quanta,
            frontier: crucible::VirtualTime { ticks: 9 },
            observations: observations.clone(),
        },
    );
    let runner = QemuHotForkWorldExecutionRunner::new(factory, QemuFreshModeledDriver::new());
    let fallback_calls = Arc::new(AtomicUsize::new(0));
    let runner = QemuHotFirstExecutionRouter::new(
        runner,
        NeverFallbackRunner {
            calls: Arc::clone(&fallback_calls),
        },
    );
    let mut runner = QemuTerminalEvidenceExecutionRunner::new(runner, evidence);
    let context = execution_context(&input, 0x84);

    let outcome = runner
        .execute(&input, &context)
        .expect("hot-world runner should stop at the inherited boundary");
    let AttemptExecutionProduct::PreparedSemantic(result) = outcome.product() else {
        panic!("inherited absolute stop must produce a prepared semantic result")
    };
    let candidate = result.observation();
    let expected_nodes = input
        .scenario()
        .world()
        .vm_nodes()
        .iter()
        .map(|node| node.id.clone())
        .collect::<BTreeSet<_>>();
    let terminal_nodes = result
        .terminal_fingerprints()
        .expect("prepared hot-fork terminal fingerprints")
        .iter()
        .map(|sample| sample.node.clone())
        .collect::<BTreeSet<_>>();

    assert_eq!(
        outcome.materialization(),
        CrucibleMaterializationTier::HotFork
    );
    assert!(!expected_nodes.is_empty());
    assert_eq!(terminal_nodes, expected_nodes);
    assert_eq!(fallback_calls.load(Ordering::SeqCst), 0);
    assert_eq!(candidate.observation().stop(), &StopOutcome::Reached(stop));
    assert_eq!(candidate.coverage().identities(), &expected_coverage);
    assert_eq!(observations.drives.load(Ordering::SeqCst), 0);
    assert_eq!(
        observations
            .terminal_fingerprint_prepares
            .load(Ordering::SeqCst),
        1
    );
    assert_eq!(observations.shutdowns.load(Ordering::SeqCst), 1);

    assert_eq!(
        runner
            .reconcile_execution(AttemptExecutionDisposition::Canceled)
            .expect("reconcile inherited-boundary execution"),
        AttemptExecutionReconciliationStep::Complete
    );
    assert_eq!(observations.recoveries.load(Ordering::SeqCst), 1);
}

#[test]
fn hot_world_runner_materializes_a_discrete_typed_branch_from_its_parent() {
    let keep = AlternativeId::from_hash(CampaignHash::derive("hot-world-discrete", b"keep"));
    let replace = AlternativeId::from_hash(CampaignHash::derive("hot-world-discrete", b"replace"));
    let domain = ChoiceDomain::Discrete(
        DiscreteDomain::new(
            1,
            BTreeMap::from([
                (
                    keep,
                    DiscreteAlternative::new(keep, "Keep route", None).expect("keep alternative"),
                ),
                (
                    replace,
                    DiscreteAlternative::new(replace, "Replace route", None)
                        .expect("replace alternative"),
                ),
            ]),
        )
        .expect("discrete branch domain"),
    );
    let input = branch_execution_input(
        ChoiceSource::Workload {
            producer: String::from("route-controller"),
        },
        domain,
        ChoiceValue::Discrete(keep),
        ChoiceValue::Discrete(replace),
        "product.route-strategy",
    );

    run_branch_through_hot_world_runner(input, false);
}

#[test]
fn observed_hot_fork_factory_preserves_recovery_ownership_for_quarantine() {
    let input = branch_execution_input(
        ChoiceSource::Scheduler {
            producer: String::from("observed-recovery"),
        },
        ChoiceDomain::Boolean(BooleanDomain::new(1).expect("recovery branch domain")),
        ChoiceValue::Boolean(false),
        ChoiceValue::Boolean(true),
        "scheduler.observed-recovery",
    );
    let (_repository, _store, _lineage, _attempt, result, _scenario) =
        repository_execution_fixture();
    let observations = BranchReplayObservations::new();
    observations
        .recovery_failures_remaining
        .store(1, Ordering::SeqCst);
    let factory = BranchReplayLifecycleFactory {
        observations: observations.clone(),
    };
    let (factory, evidence) = QemuObservedFreshAttemptLifecycleFactory::with_evidence(factory);
    let mut runner = QemuHotForkWorldExecutionRunner::new(
        factory,
        BranchReplayDriver {
            result,
            observations: observations.clone(),
        },
    );

    let executed = runner
        .try_execute(&input, &execution_context(&input, 0x85))
        .expect("observed hot-fork execution");
    assert!(matches!(
        executed,
        QemuHotForkWorldExecutionAttempt::Executed(_)
    ));

    runner
        .reconcile_execution(AttemptExecutionDisposition::Canceled)
        .expect_err("failed source recovery must quarantine retained ownership");

    assert_eq!(observations.recoveries.load(Ordering::SeqCst), 1);
    assert_eq!(observations.quarantines.load(Ordering::SeqCst), 1);
    assert!(
        evidence
            .snapshot()
            .expect("recovery evidence snapshot")
            .terminal_fingerprints()
            .is_some()
    );
}

#[test]
fn packaged_route_quarantines_a_hot_world_when_terminal_result_preparation_fails() {
    let input = branch_execution_input(
        ChoiceSource::Scheduler {
            producer: String::from("terminal-preparation"),
        },
        ChoiceDomain::Boolean(BooleanDomain::new(1).expect("terminal preparation branch domain")),
        ChoiceValue::Boolean(false),
        ChoiceValue::Boolean(true),
        "scheduler.terminal-preparation",
    );
    let (_repository, _store, _lineage, _attempt, result, _scenario) =
        repository_execution_fixture();
    let observations = BranchReplayObservations::new();
    let factory = BranchReplayLifecycleFactory {
        observations: observations.clone(),
    };
    let (factory, completed_evidence) =
        QemuObservedFreshAttemptLifecycleFactory::with_evidence(factory);
    let hot = QemuHotForkWorldExecutionRunner::new(
        factory,
        BranchReplayDriver {
            result,
            observations: observations.clone(),
        },
    );
    let fallback_calls = Arc::new(AtomicUsize::new(0));
    let hot_first = QemuHotFirstExecutionRouter::new(
        hot,
        NeverFallbackRunner {
            calls: Arc::clone(&fallback_calls),
        },
    );
    let initial = PackagedQemuInitialExecutionRunner::<_, NeverFallbackRunner>::HotFork(hot_first);
    let router = QemuAttemptExecutionRouter::new(initial, NeverResumeRunner);
    let mut runner =
        QemuTerminalEvidenceExecutionRunner::new(router, QemuAttemptExecutionEvidence::default());
    let context = execution_context(&input, 0x86);

    let failure = runner
        .execute(&input, &context)
        .expect_err("unrelated evidence must reject terminal result preparation");
    assert!(matches!(
        failure,
        AttemptWorkerFailure::Terminal(
            QemuTerminalEvidenceExecutionRunnerError::MissingTerminalFingerprints
        )
    ));
    assert_eq!(observations.quarantines.load(Ordering::SeqCst), 1);
    assert_eq!(observations.recoveries.load(Ordering::SeqCst), 0);
    runner.quarantine_pending_execution();
    assert_eq!(observations.quarantines.load(Ordering::SeqCst), 1);

    let (router, _unrelated_evidence) = runner.into_parts();
    let mut runner = QemuTerminalEvidenceExecutionRunner::new(router, completed_evidence);
    let outcome = runner
        .execute(&input, &context)
        .expect("a clean execution may follow quarantined result preparation");
    let AttemptExecutionProduct::PreparedSemantic(result) = outcome.product() else {
        panic!("clean packaged hot execution must produce a prepared result")
    };
    let observation = result
        .observation()
        .observation()
        .id()
        .expect("observation id");
    assert_eq!(fallback_calls.load(Ordering::SeqCst), 0);
    assert_eq!(observations.quarantines.load(Ordering::SeqCst), 1);

    assert_eq!(
        runner
            .reconcile_execution(AttemptExecutionDisposition::Observation(observation))
            .expect("reconcile the clean packaged hot execution"),
        AttemptExecutionReconciliationStep::Complete
    );
    assert_eq!(observations.recoveries.load(Ordering::SeqCst), 1);
    assert_eq!(observations.quarantines.load(Ordering::SeqCst), 1);
}

#[test]
fn hot_world_runner_materializes_an_unsigned_64_bit_branch_from_its_parent() {
    let domain = ChoiceDomain::Integer(
        IntegerDomain::new(
            1,
            IntegerRepresentation::Unsigned64,
            IntegerValue::Unsigned(0),
            IntegerValue::Unsigned(u64::MAX),
            1,
            Some(String::from("nanoseconds")),
            ExactRational::new(1, 1).expect("unsigned branch scale"),
            vec![IntegerValue::Unsigned(0), IntegerValue::Unsigned(u64::MAX)],
        )
        .expect("unsigned branch domain"),
    );
    let input = branch_execution_input(
        ChoiceSource::Workload {
            producer: String::from("timeout-controller"),
        },
        domain,
        ChoiceValue::Integer(IntegerValue::Unsigned(0)),
        ChoiceValue::Integer(IntegerValue::Unsigned(u64::MAX)),
        "product.timeout-nanoseconds",
    );

    run_branch_through_hot_world_runner(input, false);
}

#[test]
fn hot_world_runner_materializes_a_scheduler_source_branch_from_its_parent() {
    let input = branch_execution_input(
        ChoiceSource::Scheduler {
            producer: String::from("delivery-order"),
        },
        ChoiceDomain::Boolean(BooleanDomain::new(1).expect("scheduler branch domain")),
        ChoiceValue::Boolean(false),
        ChoiceValue::Boolean(true),
        "scheduler.delivery-order",
    );

    run_branch_through_hot_world_runner(input, false);
}

#[test]
fn hot_world_runner_materializes_a_guest_branch_and_enqueues_its_exact_reply() {
    let declaration = guest_selectable_declaration();
    let input = branch_execution_input(
        declaration.source().clone(),
        declaration.domain().clone(),
        declaration.default().clone(),
        ChoiceValue::Boolean(true),
        declaration.name(),
    );

    run_branch_through_hot_world_runner(input, true);
}
