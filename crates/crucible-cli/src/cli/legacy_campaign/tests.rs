//! Guarded local-QEMU campaign workflow tests.

use super::*;

use std::collections::BTreeSet;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicUsize, Ordering};
use std::time::Duration;

use clap::Parser;
use crucible_api::ProductionVmLifecycleConfig;
use crucible_campaign::{
    AssertionViolationWitness, BooleanDomain, CampaignHash, ChoiceClassContext, ChoiceCoordinate,
    ChoiceDomain, ChoiceOpportunity, ChoiceSource, ChoiceValue, ObservationEventLogProof,
    ObservationQuantumBoundary, ObservationStopProof, SelectableDeclaration, Selection,
    SelectionOrigin,
};
use crucible_core::AppRandomDecision;
use crucible_daemon::LinuxQemuAttemptHostConfig;
use crucible_daemon::qemu_campaign_lifecycle::{
    GuardedDefaultCampaignTestTrace, run_guarded_default_campaign_test_fixture,
    run_guarded_default_campaign_test_fixture_with_trace,
};
use tempfile::TempDir;

fn default_run_plan() -> RunInvocationPlan {
    let cli = Cli::parse_from(["crucible", "run", "builtin:happy-path"]);
    let Commands::Run(args) = &cli.command else {
        panic!("expected run command");
    };
    plan_run_invocation(args, Path::new("."))
        .expect("built-in default run should produce an invocation plan")
}

fn campaign_fingerprint(node: &str, tick: u64) -> crucible::FingerprintSample {
    crucible::FingerprintSample {
        node: crucible::NodeId {
            name: node.to_string(),
        },
        at: VirtualTime { ticks: tick },
        fingerprint: crucible::ExecutionFingerprint {
            hash: crucible::ContentHash::from_bytes(&tick.to_le_bytes()),
        },
    }
}

#[test]
fn campaign_report_fingerprints_append_the_distinct_terminal_epoch() {
    let diagnostics = vec![
        campaign_fingerprint("node-a", 0),
        campaign_fingerprint("node-b", 0),
        campaign_fingerprint("node-a", 1),
        campaign_fingerprint("node-b", 1),
    ];
    let terminal = vec![
        campaign_fingerprint("node-a", 3),
        campaign_fingerprint("node-b", 3),
    ];

    let combined = campaign_execution_fingerprints(&diagnostics, Some(&terminal))
        .expect("complete terminal epoch");

    assert_eq!(&combined[..diagnostics.len()], diagnostics);
    assert_eq!(&combined[diagnostics.len()..], terminal);
    assert_ne!(combined[2].fingerprint, combined[4].fingerprint);
}

#[test]
fn campaign_report_fingerprints_require_a_terminal_epoch() {
    let error = campaign_execution_fingerprints(&[], None)
        .expect_err("accepted campaign reports require terminal fingerprints");

    assert!(error.to_string().contains("without terminal fingerprint"));
}

fn resume_evidence(schedule: Schedule, frontier: VirtualTime) -> ResumeHandleEvidence {
    let scenario_form = default_run_plan().scenario.scenario_form().clone();
    resume_evidence_for_scenario(scenario_form, schedule, frontier)
}

fn resume_evidence_with_assertion(frontier: VirtualTime) -> ResumeHandleEvidence {
    let scenario_form = default_run_plan().scenario.scenario_form().clone();
    assert!(!scenario_form.properties().assertions().is_empty());
    resume_evidence_for_scenario(scenario_form, Schedule::empty(), frontier)
}

fn resume_evidence_for_scenario(
    scenario_form: crucible::ScenarioDefForm,
    schedule: Schedule,
    frontier: VirtualTime,
) -> ResumeHandleEvidence {
    let scenario = scenario_form.scenario_def();
    let configuration = crucible::Configuration {
        def: scenario.clone(),
        schedule: schedule.clone(),
    };
    let checkpoint =
        checkpoint_for_resume_configuration(&configuration, frontier).expect("resume checkpoint");
    let replay_closure = GuardedCampaignReplayClosure::empty_for_selection_free_schedule(&schedule)
        .unwrap_or_else(|_| {
            GuardedCampaignReplayClosure::empty_for_selection_free_schedule(&Schedule::empty())
                .expect("empty replay closure")
        });
    ResumeHandleEvidence {
        scenario_form,
        scenario,
        schedule,
        configuration,
        checkpoint,
        replay_closure,
        source_observation_proof: None,
        source_observation_evidence: None,
    }
}

fn default_resume_plan(evidence: &ResumeHandleEvidence, store: &Path) -> ResumeInvocationPlan {
    ResumeInvocationPlan {
        savepoint: ResumeSavepointRef::CheckpointHash(evidence.checkpoint.id),
        store_root: store.to_path_buf(),
        terminal_condition: RunTerminalCondition::Stopped,
        max_virtual_time: None,
        max_virtual_time_ticks: None,
        execution_mode: RunExecutionMode::ToCompletion,
        watch_streams_live_status: false,
        startup_commands: vec![SessionCommandKind::Start, SessionCommandKind::Continue],
        initial_control_commands: vec![SessionCommandKind::Query],
        accepted_interactive_commands: Vec::new(),
    }
}

fn default_fork_plan(evidence: &ResumeHandleEvidence, store: &Path) -> ForkInvocationPlan {
    ForkInvocationPlan {
        source: ResumeSavepointRef::CheckpointHash(evidence.checkpoint.id),
        label: String::from("campaign-unchanged-fork"),
        artifact_dir: store.join("artifacts"),
        store_root: store.to_path_buf(),
        decision_overrides: Vec::new(),
        fork_seed: None,
        terminal_condition: RunTerminalCondition::Stopped,
        max_virtual_time: None,
        max_virtual_time_ticks: None,
        execution_mode: RunExecutionMode::ToCompletion,
        watch_streams_live_status: false,
        startup_commands: vec![SessionCommandKind::Fork, SessionCommandKind::Continue],
        initial_control_commands: vec![SessionCommandKind::Query],
        accepted_interactive_commands: Vec::new(),
    }
}

fn typed_selection_schedule(scenario: &crucible::ScenarioDef) -> Schedule {
    let domain = ChoiceDomain::Boolean(BooleanDomain::new(1).expect("Boolean domain"));
    let declaration = SelectableDeclaration::new(
        "product.test.legacy-resume-route",
        ChoiceSource::Scheduler {
            producer: String::from("legacy-resume-route-test"),
        },
        domain.clone(),
        ChoiceValue::Boolean(false),
        ChoiceClassContext::new(BTreeSet::new()).expect("class context"),
        BTreeSet::new(),
        true,
    )
    .expect("selectable declaration");
    let opportunity = ChoiceOpportunity::new(
        crucible_campaign::ScenarioDefId::from_hash(CampaignHash::from_bytes(scenario.id().bytes)),
        &declaration,
        &domain,
        ChoiceCoordinate {
            scheduler: CampaignHash::derive("test", b"legacy-resume-scheduler"),
            producer: CampaignHash::derive("test", b"legacy-resume-producer"),
        },
        "legacy-resume-route",
        None,
    )
    .expect("choice opportunity");
    let selection = Selection::new(
        &opportunity,
        &domain,
        ChoiceValue::Boolean(false),
        SelectionOrigin::Default,
    )
    .expect("default selection");
    Schedule::from_decisions([crucible::Decision::Selection(
        crucible::SelectionDecision::new(&selection),
    )])
}

struct ResumeCampaignFixture {
    campaign: GuardedDefaultCampaignRun,
    trace: GuardedDefaultCampaignTestTrace,
    checkpoints: Arc<ExactCheckpointStore>,
    checkpoint_directory: TempDir,
    checkpoint_root: PathBuf,
}

fn resume_campaign_fixture(
    temporary: &TempDir,
    evidence: &ResumeHandleEvidence,
    final_stop: StopCondition,
    watch_frames: bool,
) -> ResumeCampaignFixture {
    try_resume_campaign_fixture(temporary, evidence, final_stop, watch_frames)
        .expect("campaign fixture should resume through exact capture")
}

fn try_resume_campaign_fixture(
    temporary: &TempDir,
    evidence: &ResumeHandleEvidence,
    final_stop: StopCondition,
    watch_frames: bool,
) -> Result<ResumeCampaignFixture, Box<dyn Error + Send + Sync>> {
    let resources = AttemptResourceLimits::new(1, 256 * 1024 * 1024, 1024 * 1024, 16)
        .expect("campaign fixture resources");
    let checkpoint_directory = tempfile::Builder::new()
        .prefix("transient-resume-exact-")
        .tempdir_in(temporary.path())
        .expect("transient exact directory");
    let checkpoint_root = checkpoint_directory.path().to_path_buf();
    let exact_backend: Arc<dyn ImmutableBlobBackend> = Arc::new(DirectoryBlobBackend::new(
        "legacy-campaign-resume-projection-test",
        checkpoint_root.clone(),
    ));
    let checkpoints = Arc::new(
        ExactCheckpointStore::new(exact_backend, resources.maximum_disk_bytes())
            .expect("exact checkpoint store"),
    );
    let host = LinuxQemuAttemptHostConfig::new(
        "/sys/fs/cgroup/crucible-campaign-resume-projection-test",
        "/tmp/crucible-campaign-resume-projection-test",
        "campaign-resume-projection-test",
        1,
        1,
        65_529,
        65_529,
        16,
        1_024,
        Duration::from_secs(1),
    )
    .expect("fixture host configuration");
    let request = GuardedDefaultCampaignRunRequest::new(
        evidence.scenario_form.clone(),
        evidence.scenario.seed(),
        "campaign-resume-projection-test-engine",
        "campaign-resume-projection-test-qemu",
        ProductionVmLifecycleConfig::new("qemu", "plugin", "kernel", "root", "run-state"),
        host,
        resources,
    );
    let request = attach_guarded_resume_source(
        request,
        evidence,
        final_stop,
        Arc::clone(&checkpoints),
        None,
    );
    let request = if watch_frames {
        request.with_watch_frames()
    } else {
        request
    };
    let (campaign, trace) = run_guarded_default_campaign_test_fixture_with_trace(request)?;

    Ok(ResumeCampaignFixture {
        campaign,
        trace,
        checkpoints,
        checkpoint_directory,
        checkpoint_root,
    })
}

fn capture_only_remote_observation_factory(
    plan: ResumeInvocationPlan,
    evidence: ResumeHandleEvidence,
    calls: Arc<AtomicUsize>,
    selection_applications: Arc<AtomicUsize>,
    continuation_applications: Arc<AtomicUsize>,
) -> impl Fn(
    &crucible_api::ResumeSessionRequest,
    &crucible::Configuration,
    &crucible_api::ResumeObservationPreparationContext,
) -> Result<ResumeRecordingLifecycleLoop, crucible_api::LifecycleApiError>
+ Send
+ Sync
+ 'static {
    move |request, configuration, context| {
        calls.fetch_add(1, Ordering::SeqCst);
        let source = request.observation_source.as_ref().ok_or_else(|| {
            crucible_api::LifecycleApiError::ResumeObservationSource {
                message: String::from("test remote resume lost its observation source"),
            }
        })?;
        let proof =
            ObservationStopProof::from_canonical_bytes(source.proof()).map_err(|error| {
                crucible_api::LifecycleApiError::ResumeObservationSource {
                    message: format!("decode test remote observation proof: {error}"),
                }
            })?;
        let replay_evidence =
            crucible_daemon::CrucibleMeasurementReplayEvidence::from_canonical_bytes(
                source.evidence(),
            )
            .map_err(|error| {
                crucible_api::LifecycleApiError::ResumeObservationSource {
                    message: format!("decode test remote observation evidence: {error}"),
                }
            })?;
        replay_evidence
            .verify_observation_stop_proof(&proof)
            .map_err(
                |error| crucible_api::LifecycleApiError::ResumeObservationSource {
                    message: format!("validate test remote observation source: {error}"),
                },
            )?;
        let closure = request
            .replay_closure
            .as_ref()
            .ok_or_else(
                || crucible_api::LifecycleApiError::ResumeObservationSource {
                    message: String::from("test remote resume lost its replay closure"),
                },
            )
            .and_then(|closure| {
                GuardedCampaignReplayClosure::from_canonical_bytes(closure.payload()).map_err(
                    |error| crucible_api::LifecycleApiError::ResumeObservationSource {
                        message: format!("decode test remote replay closure: {error}"),
                    },
                )
            })?;
        if configuration.id() != request.checkpoint.configuration {
            return Err(crucible_api::LifecycleApiError::ResumeObservationSource {
                message: String::from(
                    "test remote configuration differs from its logical checkpoint",
                ),
            });
        }
        if context.cancellation().is_canceled() {
            return Err(crucible_api::LifecycleApiError::ResumeObservationSource {
                message: String::from("test remote observation preparation was canceled"),
            });
        }

        let resources = AttemptResourceLimits::new(1, 256 * 1024 * 1024, 1024 * 1024, 16)
            .expect("remote observation fixture resources");
        let checkpoint_directory = TempDir::new().map_err(|error| {
            crucible_api::LifecycleApiError::ResumeObservationSource {
                message: format!("create test remote checkpoint directory: {error}"),
            }
        })?;
        let exact_backend: Arc<dyn ImmutableBlobBackend> = Arc::new(DirectoryBlobBackend::new(
            "remote-observation-capture-only-test",
            checkpoint_directory.path().to_path_buf(),
        ));
        let checkpoints = Arc::new(
            ExactCheckpointStore::new(exact_backend, resources.maximum_disk_bytes()).map_err(
                |error| crucible_api::LifecycleApiError::ResumeObservationSource {
                    message: format!("open test remote checkpoint store: {error}"),
                },
            )?,
        );
        let host = LinuxQemuAttemptHostConfig::new(
            "/sys/fs/cgroup/crucible-remote-observation-test",
            "/tmp/crucible-remote-observation-test",
            "remote-observation-test",
            1,
            1,
            65_528,
            65_528,
            16,
            1_024,
            Duration::from_secs(1),
        )
        .map_err(
            |error| crucible_api::LifecycleApiError::ResumeObservationSource {
                message: format!("configure test remote host: {error}"),
            },
        )?;
        let campaign_request = GuardedDefaultCampaignRunRequest::new(
            request.scenario.clone(),
            request.seed,
            "remote-observation-test-engine",
            "remote-observation-test-qemu",
            ProductionVmLifecycleConfig::new(
                "qemu",
                "plugin",
                "kernel",
                "root",
                checkpoint_directory.path().join("run-state"),
            ),
            host,
            resources,
        )
        .with_observation_resume_source_capture_only(
            request.schedule.clone(),
            closure,
            request.checkpoint.clone(),
            GuardedDefaultCampaignObservationSource::new(proof, replay_evidence),
            checkpoints,
        );
        let (campaign, trace) =
            run_guarded_default_campaign_test_fixture_with_trace(campaign_request).map_err(
                |error| crucible_api::LifecycleApiError::ResumeObservationSource {
                    message: format!("authenticate test remote source campaign: {error}"),
                },
            )?;
        let resume = campaign.resume().ok_or_else(|| {
            crucible_api::LifecycleApiError::ResumeObservationSource {
                message: String::from("test remote source campaign lost its resume proof"),
            }
        })?;
        if resume.source_savepoint().is_none()
            || resume.ready().is_some()
            || resume.selection().is_some()
            || resume.continuation().is_some()
        {
            return Err(crucible_api::LifecycleApiError::ResumeObservationSource {
                message: String::from(
                    "test remote source campaign crossed its capture-only boundary",
                ),
            });
        }
        let applications = trace.selection_applications().map_err(|error| {
            crucible_api::LifecycleApiError::ResumeObservationSource {
                message: format!("read test remote reply trace: {error}"),
            }
        })?;
        selection_applications.store(applications.len(), Ordering::SeqCst);
        continuation_applications.store(
            applications
                .iter()
                .filter(|(generation, _)| *generation >= 2)
                .count(),
            Ordering::SeqCst,
        );

        resume_recording_loop_for_plan(&plan, &evidence).map_err(|error| {
            crucible_api::LifecycleApiError::ResumeObservationSource {
                message: format!("construct test restored lifecycle: {error}"),
            }
        })
    }
}

#[test]
fn campaign_resume_route_accepts_only_standard_selection_free_workflows() {
    let temporary = TempDir::new().expect("resume route workspace");
    let supported = Schedule::from_decisions([
        crucible::Decision::DeliveryOrder(crucible::DeliveryOrderDecision {
            at: VirtualTime { ticks: 5 },
            order: Vec::new(),
        }),
        crucible::Decision::RngDraw(crucible::RngDecision {
            stream: crucible::RngStreamId::from_name("legacy-resume-route"),
            value: 7,
        }),
    ]);
    let evidence = resume_evidence(supported, VirtualTime { ticks: 5 });
    let default = default_resume_plan(&evidence, temporary.path());
    assert!(guarded_campaign_resume_eligible(&default, &evidence));

    let mut virtual_time = default.clone();
    virtual_time.terminal_condition = RunTerminalCondition::VirtualTime;
    virtual_time.max_virtual_time = Some(String::from("10ticks"));
    virtual_time.max_virtual_time_ticks = Some(10);
    assert!(guarded_campaign_resume_eligible(&virtual_time, &evidence));

    let mut unsupported_evidence = evidence.clone();
    unsupported_evidence.schedule =
        Schedule::from_decisions([crucible::Decision::Override(crucible::OverrideDecision {
            point: crucible::SchedulingPoint {
                key: String::from("legacy-resume/override"),
            },
            choice: crucible::ChoiceTag {
                name: String::from("alternate"),
            },
        })]);
    assert!(!guarded_campaign_resume_eligible(
        &default,
        &unsupported_evidence
    ));
    unsupported_evidence.schedule =
        Schedule::from_decisions([crucible::Decision::AppRandom(AppRandomDecision {
            node: crucible::NodeId {
                name: String::from("legacy-resume-node"),
            },
            stream: crucible::RngStreamId::from_name("legacy-resume-app-random"),
            request_id: 1,
            width: 8,
            value: 3,
        })]);
    assert!(!guarded_campaign_resume_eligible(
        &default,
        &unsupported_evidence
    ));
    unsupported_evidence.schedule = typed_selection_schedule(&evidence.scenario);
    assert!(!guarded_campaign_resume_eligible(
        &default,
        &unsupported_evidence
    ));

    let mut property = default.clone();
    property.terminal_condition = RunTerminalCondition::Property;
    assert_eq!(
        guarded_campaign_resume_eligible(&property, &evidence),
        !evidence.scenario_form.properties().assertions().is_empty()
    );
    let property_evidence = resume_evidence_with_assertion(VirtualTime { ticks: 5 });
    let mut property = default_resume_plan(&property_evidence, temporary.path());
    property.terminal_condition = RunTerminalCondition::Property;
    assert!(guarded_campaign_resume_eligible(
        &property,
        &property_evidence
    ));
    assert_eq!(
        guarded_resume_stop(&property, &property_evidence).expect("property stop"),
        StopCondition::Observation(ObservationCondition::AnyAssertionViolationTransition)
    );
    let mut interactive = default.clone();
    interactive.execution_mode = RunExecutionMode::Interactive;
    interactive.startup_commands = vec![SessionCommandKind::Start];
    interactive.accepted_interactive_commands = run_interactive_session_command_set();
    assert!(!guarded_campaign_resume_eligible(&interactive, &evidence));
    let mut changed_controls = default;
    changed_controls.initial_control_commands.clear();
    assert!(!guarded_campaign_resume_eligible(
        &changed_controls,
        &evidence
    ));
}

#[test]
fn campaign_fork_route_accepts_standard_controlled_workflows() {
    let temporary = TempDir::new().expect("fork route workspace");
    let evidence = resume_evidence(Schedule::empty(), VirtualTime { ticks: 5 });
    let default = default_fork_plan(&evidence, temporary.path());
    assert!(guarded_campaign_fork_eligible(&default, &evidence));

    let mut virtual_time = default.clone();
    virtual_time.terminal_condition = RunTerminalCondition::VirtualTime;
    virtual_time.max_virtual_time = Some(String::from("10ticks"));
    virtual_time.max_virtual_time_ticks = Some(10);
    assert!(guarded_campaign_fork_eligible(&virtual_time, &evidence));

    let mut reseeded = default.clone();
    reseeded.fork_seed = Some(7);
    assert!(guarded_campaign_fork_eligible(&reseeded, &evidence));
    assert!(
        guarded_campaign_fork_control(&reseeded, &evidence)
            .expect("model reseed control")
            .is_some()
    );

    let mut overridden = default.clone();
    overridden.decision_overrides = vec![ForkDecisionOverride {
        decision: String::from("network:delivery"),
        value: String::from("alternate"),
    }];
    assert!(guarded_campaign_fork_eligible(&overridden, &evidence));
    assert!(
        guarded_campaign_fork_control(&overridden, &evidence)
            .expect("model override control")
            .is_some()
    );

    let mut property = default.clone();
    property.terminal_condition = RunTerminalCondition::Property;
    assert_eq!(
        guarded_campaign_fork_eligible(&property, &evidence),
        !evidence.scenario_form.properties().assertions().is_empty()
    );
    let property_evidence = resume_evidence_with_assertion(VirtualTime { ticks: 5 });
    let mut property = default_fork_plan(&property_evidence, temporary.path());
    property.terminal_condition = RunTerminalCondition::Property;
    assert!(guarded_campaign_fork_eligible(
        &property,
        &property_evidence
    ));

    let mut quiescence = default.clone();
    quiescence.terminal_condition = RunTerminalCondition::Quiescence;
    assert!(guarded_campaign_fork_eligible(&quiescence, &evidence));

    let mut interactive = default.clone();
    interactive.execution_mode = RunExecutionMode::Interactive;
    interactive.startup_commands = vec![SessionCommandKind::Fork];
    interactive.accepted_interactive_commands = run_interactive_session_command_set();
    assert!(!guarded_campaign_fork_eligible(&interactive, &evidence));

    let mut changed_controls = default;
    changed_controls.initial_control_commands.clear();
    assert!(!guarded_campaign_fork_eligible(
        &changed_controls,
        &evidence
    ));
}

#[test]
fn campaign_unchanged_fork_projects_resume_with_campaign_ownership() {
    let temporary = TempDir::new().expect("fork projection workspace");
    let source_frontier = VirtualTime { ticks: 5 };
    let evidence = resume_evidence(Schedule::empty(), source_frontier);
    let mut fork_plan = default_fork_plan(&evidence, temporary.path());
    fork_plan.terminal_condition = RunTerminalCondition::VirtualTime;
    fork_plan.max_virtual_time = Some(String::from("10ticks"));
    fork_plan.max_virtual_time_ticks = Some(10);
    fork_plan.watch_streams_live_status = true;
    let mut resume_plan = default_resume_plan(&evidence, temporary.path());
    resume_plan.terminal_condition = fork_plan.terminal_condition;
    resume_plan.max_virtual_time = fork_plan.max_virtual_time.clone();
    resume_plan.max_virtual_time_ticks = fork_plan.max_virtual_time_ticks;
    resume_plan.watch_streams_live_status = true;
    let ResumeCampaignFixture {
        campaign,
        trace: _,
        checkpoints,
        checkpoint_directory,
        checkpoint_root,
    } = resume_campaign_fixture(
        &temporary,
        &evidence,
        StopCondition::VirtualTimeNanoseconds(10),
        true,
    );

    let resumed = campaign_resume_workflow_report(&resume_plan, &evidence, &campaign)
        .expect("project campaign resume");
    let report = campaign_fork_workflow_report(&fork_plan, &evidence, resumed);
    let live_artifact = live_qemu_artifact_evidence_from_run(
        LiveQemuArtifactRecipe {
            producer: "fork",
            terminal_condition: fork_plan.terminal_condition,
            max_virtual_time_ticks: fork_plan.max_virtual_time_ticks,
            max_quanta: None,
            coverage: false,
            execution_mode: fork_plan.execution_mode,
            startup_commands: &fork_plan.startup_commands,
            initial_control_commands: &fork_plan.initial_control_commands,
            branch: LiveQemuReplayBranch::Resume {
                base_decisions: evidence.schedule.len() as u64,
                frontier_ticks: source_frontier.ticks,
            },
        },
        &evidence.scenario_form,
        &report.run,
    )
    .expect("campaign-owned fork has replay-complete artifact evidence");
    drop(campaign);
    complete_transient_checkpoint_workflow(
        checkpoints,
        checkpoint_directory,
        &checkpoint_root,
        Ok(()),
    )
    .expect("clean transient fork checkpoints");

    assert_eq!(report.run.execution_owner, RunExecutionOwner::Campaign);
    assert!(report.run.campaign_replay_closure.is_some());
    assert_eq!(
        live_artifact.campaign_replay_closure,
        report.run.campaign_replay_closure
    );
    assert_eq!(live_artifact.contract.producer, "fork");
    assert_eq!(report.source_checkpoint, evidence.checkpoint.id);
    assert_eq!(report.branch_checkpoint, evidence.checkpoint.id);
    assert_eq!(report.branch_configuration, evidence.configuration.id());
    assert_eq!(
        report.terminal_oracle.configuration,
        report.terminal_configuration.id()
    );
    assert_eq!(report.scenario_form, evidence.scenario_form);
    assert_eq!(report.scenario_label, fork_plan.source.label());
    assert_eq!(report.label, fork_plan.label);
    assert!(
        report
            .run
            .watch_statuses
            .iter()
            .all(|status| { status.contains("owner=campaign") })
    );
    assert!(!checkpoint_root.exists());
}

#[test]
fn campaign_resume_projection_preserves_source_oracle_watch_and_cleanup() {
    let temporary = TempDir::new().expect("resume projection workspace");
    let source_frontier = VirtualTime { ticks: 5 };
    let schedule = Schedule::from_decisions([crucible::Decision::DeliveryOrder(
        crucible::DeliveryOrderDecision {
            at: VirtualTime { ticks: 10 },
            order: Vec::new(),
        },
    )]);
    let evidence = resume_evidence(schedule.clone(), source_frontier);
    let mut resume_plan = default_resume_plan(&evidence, temporary.path());
    resume_plan.terminal_condition = RunTerminalCondition::VirtualTime;
    resume_plan.max_virtual_time = Some(String::from("10ticks"));
    resume_plan.max_virtual_time_ticks = Some(10);
    resume_plan.watch_streams_live_status = true;
    let ResumeCampaignFixture {
        campaign,
        trace: _,
        checkpoints,
        checkpoint_directory,
        checkpoint_root,
    } = resume_campaign_fixture(
        &temporary,
        &evidence,
        StopCondition::VirtualTimeNanoseconds(10),
        true,
    );
    let result = campaign_resume_workflow_report(&resume_plan, &evidence, &campaign);
    let proof = campaign.resume().cloned().expect("campaign resume proof");
    let terminal_observation = campaign.terminal().id();
    drop(campaign);
    let report = complete_transient_checkpoint_workflow(
        checkpoints,
        checkpoint_directory,
        &checkpoint_root,
        result,
    )
    .expect("project campaign resume into legacy contract");

    assert_eq!(report.run.execution_owner, RunExecutionOwner::Campaign);
    assert_eq!(report.source_checkpoint, evidence.checkpoint.id);
    assert_eq!(report.resumed_configuration, evidence.configuration.id());
    assert_eq!(report.run.final_frontier_ticks, 10);
    assert_eq!(report.run.final_state, "virtual-time");
    assert_eq!(
        report.run.terminal_savepoint,
        Some(report.terminal_oracle.fat_checkpoint)
    );
    assert_eq!(
        report
            .terminal_oracle
            .schedule
            .prefix(evidence.schedule.len()),
        Ok(evidence.schedule.clone())
    );
    assert!(report.run.campaign_replay_closure.is_some());
    assert!(!report.run.watch_statuses.is_empty());
    assert!(
        report
            .run
            .watch_statuses
            .iter()
            .all(|status| status.contains("owner=campaign"))
    );
    assert!(
        report.run.watch_statuses.iter().any(|status| {
            status.contains(&format!("observation={}", proof.source_observation()))
        })
    );
    assert!(
        report
            .run
            .watch_statuses
            .iter()
            .any(|status| { status.contains(&format!("observation={terminal_observation}")) })
    );
    assert_eq!(proof.source_frontier(), source_frontier);
    assert!(proof.source_savepoint().is_some());
    assert!(proof.ready().is_some());
    assert!(proof.selection().is_some());
    assert!(proof.continuation().is_some());

    assert!(!checkpoint_root.exists());
}

#[test]
fn campaign_resume_projects_quiescence_observation() {
    let temporary = TempDir::new().expect("resume observation workspace");
    let evidence = resume_evidence(Schedule::empty(), VirtualTime { ticks: 5 });
    let mut plan = default_resume_plan(&evidence, temporary.path());
    plan.terminal_condition = RunTerminalCondition::Quiescence;
    let fixture = resume_campaign_fixture(
        &temporary,
        &evidence,
        StopCondition::Observation(ObservationCondition::SchedulerQuiescent),
        false,
    );

    let report = campaign_resume_workflow_report(&plan, &evidence, &fixture.campaign)
        .expect("project quiescence observation resume");
    let stop = fixture.campaign.terminal().observation().stop();
    let StopOutcome::ObservationReached(proof) = stop else {
        panic!("quiescence resume requires an observation proof");
    };

    assert_eq!(proof.condition(), &ObservationCondition::SchedulerQuiescent);
    assert_eq!(
        proof.satisfaction(),
        ObservationStopSatisfaction::SchedulerQuiescent
    );
    assert_eq!(report.run.status, BackendCommandStatus::Passed);
    assert_eq!(report.run.outcome, Some(OutcomeKind::Passed));
    assert_eq!(report.run.final_state, "quiescent");
}

#[test]
fn campaign_resume_projects_property_violation_observation() {
    let temporary = TempDir::new().expect("resume property workspace");
    let cli = Cli::parse_from(["crucible", "run", "builtin:fault-campaign"]);
    let Commands::Run(args) = &cli.command else {
        panic!("expected run command");
    };
    let scenario = plan_run_invocation(args, Path::new("."))
        .expect("fault campaign plan")
        .scenario
        .scenario_form()
        .clone();
    let evidence =
        resume_evidence_for_scenario(scenario, Schedule::empty(), VirtualTime { ticks: 5 });
    let mut plan = default_resume_plan(&evidence, temporary.path());
    plan.terminal_condition = RunTerminalCondition::Property;
    let fixture = resume_campaign_fixture(
        &temporary,
        &evidence,
        StopCondition::Observation(ObservationCondition::AnyAssertionViolationTransition),
        false,
    );

    let report = campaign_resume_workflow_report(&plan, &evidence, &fixture.campaign)
        .expect("project property observation resume");
    let stop = fixture.campaign.terminal().observation().stop();
    let StopOutcome::ObservationReached(proof) = stop else {
        panic!("property resume requires an observation proof");
    };

    assert_eq!(
        proof.condition(),
        &ObservationCondition::AnyAssertionViolationTransition
    );
    assert_eq!(
        proof.satisfaction(),
        ObservationStopSatisfaction::AssertionViolationTransition
    );
    assert_eq!(
        proof
            .assertion_witness()
            .expect("property observation witness")
            .assertion(),
        "no-split-brain"
    );
    assert_eq!(report.run.status, BackendCommandStatus::Failed);
    assert_eq!(report.run.outcome, Some(OutcomeKind::Failed));
    assert_eq!(report.run.final_state, "property-failed");
}

#[test]
fn campaign_resume_projection_does_not_rewind_for_an_earlier_deadline() {
    let temporary = TempDir::new().expect("resume no-rewind workspace");
    let source_frontier = VirtualTime { ticks: 5 };
    let evidence = resume_evidence(Schedule::empty(), source_frontier);
    let mut resume_plan = default_resume_plan(&evidence, temporary.path());
    resume_plan.terminal_condition = RunTerminalCondition::VirtualTime;
    resume_plan.max_virtual_time = Some(String::from("3ticks"));
    resume_plan.max_virtual_time_ticks = Some(3);
    let ResumeCampaignFixture {
        campaign,
        trace: _,
        checkpoints,
        checkpoint_directory,
        checkpoint_root,
    } = resume_campaign_fixture(
        &temporary,
        &evidence,
        StopCondition::VirtualTimeNanoseconds(3),
        false,
    );

    assert_eq!(
        campaign.terminal().observation().stop(),
        &StopOutcome::Reached(StopCondition::VirtualTimeNanoseconds(3))
    );
    assert_eq!(campaign.evidence().frontier(), source_frontier);

    let result = campaign_resume_workflow_report(&resume_plan, &evidence, &campaign);
    drop(campaign);
    let report = complete_transient_checkpoint_workflow(
        checkpoints,
        checkpoint_directory,
        &checkpoint_root,
        result,
    )
    .expect("project no-rewind campaign resume into legacy contract");

    assert_eq!(report.run.status, BackendCommandStatus::Passed);
    assert_eq!(report.run.outcome, Some(OutcomeKind::Passed));
    assert_eq!(report.run.final_frontier_ticks, source_frontier.ticks);
    assert_eq!(report.terminal_oracle.frontier, source_frontier);
    assert!(!checkpoint_root.exists());
}

#[test]
fn campaign_resume_frontier_validation_binds_reached_deadlines_only() {
    let temporary = TempDir::new().expect("resume frontier workspace");
    let source_frontier = VirtualTime { ticks: 5 };
    let evidence = resume_evidence(Schedule::empty(), source_frontier);
    let mut plan = default_resume_plan(&evidence, temporary.path());
    plan.terminal_condition = RunTerminalCondition::VirtualTime;
    plan.max_virtual_time = Some(String::from("3ticks"));
    plan.max_virtual_time_ticks = Some(3);
    let earlier_stop = StopOutcome::Reached(StopCondition::VirtualTimeNanoseconds(3));

    validate_campaign_resume_frontier(&plan, source_frontier, &earlier_stop, source_frontier)
        .expect("an earlier deadline must preserve the source frontier");
    assert!(
        validate_campaign_resume_frontier(
            &plan,
            source_frontier,
            &earlier_stop,
            VirtualTime { ticks: 3 }
        )
        .is_err()
    );
    assert!(
        validate_campaign_resume_frontier(
            &plan,
            source_frontier,
            &earlier_stop,
            VirtualTime { ticks: 6 }
        )
        .is_err()
    );

    plan.max_virtual_time = Some(String::from("10ticks"));
    plan.max_virtual_time_ticks = Some(10);
    let future_stop = StopOutcome::Reached(StopCondition::VirtualTimeNanoseconds(10));
    validate_campaign_resume_frontier(
        &plan,
        source_frontier,
        &future_stop,
        VirtualTime { ticks: 10 },
    )
    .expect("a future deadline must advance to that exact frontier");
}

#[test]
fn campaign_resume_terminal_outcomes_bypass_the_requested_future_deadline() {
    let temporary = TempDir::new().expect("resume terminal outcome workspace");
    let source_frontier = VirtualTime { ticks: 5 };
    let evidence = resume_evidence(Schedule::empty(), source_frontier);
    let mut plan = default_resume_plan(&evidence, temporary.path());
    plan.terminal_condition = RunTerminalCondition::VirtualTime;
    plan.max_virtual_time = Some(String::from("10ticks"));
    plan.max_virtual_time_ticks = Some(10);
    let terminal_cases = [
        (
            StopOutcome::ModeledTimeout(String::from("deadline")),
            BackendCommandStatus::Timeout,
            OutcomeKind::Timeout,
        ),
        (
            StopOutcome::GuestCrash(String::from("guest-crash")),
            BackendCommandStatus::Crashed,
            OutcomeKind::Crashed,
        ),
        (
            StopOutcome::AssertionFailure(String::from("invariant")),
            BackendCommandStatus::Failed,
            OutcomeKind::Failed,
        ),
        (
            StopOutcome::ScenarioFailure(vec![String::from("scenario failed")]),
            BackendCommandStatus::Failed,
            OutcomeKind::Failed,
        ),
    ];

    for (stop, expected_status, expected_outcome) in terminal_cases {
        assert_eq!(
            campaign_resume_status(&plan, &stop).expect("terminal outcome status"),
            (expected_status, expected_outcome)
        );
        validate_campaign_resume_frontier(&plan, source_frontier, &stop, source_frontier)
            .expect("terminal outcomes may precede the requested future deadline");
    }
}

#[test]
fn transient_checkpoint_cleanup_preserves_the_execution_error() {
    let temporary = TempDir::new().expect("cleanup workspace");
    let checkpoint_directory = tempfile::Builder::new()
        .prefix("transient-resume-error-")
        .tempdir_in(temporary.path())
        .expect("transient exact directory");
    let checkpoint_root = checkpoint_directory.path().to_path_buf();
    let backend: Arc<dyn ImmutableBlobBackend> = Arc::new(DirectoryBlobBackend::new(
        "legacy-campaign-resume-cleanup-test",
        &checkpoint_root,
    ));
    let checkpoints =
        Arc::new(ExactCheckpointStore::new(backend, 1024 * 1024).expect("exact checkpoint store"));
    let expected = "injected campaign resume failure";
    let result: Result<(), CliError> = Err(backend_error(expected));

    let error = complete_transient_checkpoint_workflow(
        checkpoints,
        checkpoint_directory,
        &checkpoint_root,
        result,
    )
    .expect_err("execution failure must survive successful cleanup");

    assert!(error.to_string().contains(expected));
    assert!(!checkpoint_root.exists());
}

#[test]
fn campaign_route_accepts_exact_semantic_stops_and_rejects_session_only_modes() {
    let mut default = default_run_plan();
    assert!(guarded_campaign_run_eligible(&default));
    default.campaign_deployment = Some(PathBuf::from("guarded.toml"));
    assert!(guarded_campaign_run_eligible(&default));

    let mut plan = default.clone();
    plan.terminal_condition = RunTerminalCondition::VirtualTime;
    plan.max_virtual_time = Some(String::from("1tick"));
    plan.max_virtual_time_ticks = Some(1);
    assert!(guarded_campaign_run_eligible(&plan));
    assert_eq!(
        guarded_discovery_stop(&plan).expect("virtual-time stop"),
        StopCondition::VirtualTimeNanoseconds(1)
    );

    let cli = Cli::parse_from([
        "crucible",
        "run",
        "builtin:happy-path",
        "--until",
        "virtual-time",
        "--max-virtual-time",
        "2ms",
    ]);
    let Commands::Run(args) = &cli.command else {
        panic!("expected run command");
    };
    let plan = plan_run_invocation(args, Path::new("."))
        .expect("virtual-time run should produce an invocation plan");
    assert_eq!(
        guarded_discovery_stop(&plan).expect("converted virtual-time stop"),
        StopCondition::VirtualTimeNanoseconds(2_000_000)
    );
    assert_eq!(
        campaign_stop_status(
            &plan,
            &StopOutcome::Reached(StopCondition::VirtualTimeNanoseconds(2_000_000)),
        )
        .expect("reached deadline status"),
        (BackendCommandStatus::Timeout, OutcomeKind::Timeout)
    );

    let mut plan = default.clone();
    plan.max_virtual_time = Some(String::from("1tick"));
    assert!(!guarded_campaign_run_eligible(&plan));

    let mut plan = default.clone();
    plan.max_virtual_time_ticks = Some(1);
    assert!(!guarded_campaign_run_eligible(&plan));

    let mut plan = default.clone();
    plan.terminal_condition = RunTerminalCondition::Stopped;
    assert!(guarded_campaign_run_eligible(&plan));
    assert_eq!(
        guarded_discovery_stop(&plan).expect("terminal stop"),
        StopCondition::Terminal
    );

    let mut plan = default.clone();
    plan.terminal_condition = RunTerminalCondition::Property;
    assert!(!guarded_campaign_run_eligible(&plan));

    let mut plan = default.clone();
    plan.max_quanta = Some(1);
    assert!(guarded_campaign_run_eligible(&plan));
    assert_eq!(
        guarded_discovery_stop(&plan).expect("execution-quanta stop"),
        StopCondition::ExecutionQuanta(1)
    );
    assert_eq!(
        campaign_stop_status(
            &plan,
            &StopOutcome::Reached(StopCondition::ExecutionQuanta(1)),
        )
        .expect("reached execution-quanta status"),
        (BackendCommandStatus::Timeout, OutcomeKind::Timeout)
    );

    plan.max_virtual_time = Some(String::from("2ms"));
    plan.max_virtual_time_ticks = Some(2_000_000);
    assert_eq!(
        guarded_discovery_stop(&plan).expect("combined stop"),
        StopCondition::VirtualTimeOrExecutionQuanta {
            virtual_time_nanoseconds: 2_000_000,
            execution_quanta: 1,
        }
    );
    assert_eq!(
        campaign_stop_status(
            &plan,
            &StopOutcome::Reached(StopCondition::VirtualTimeOrExecutionQuanta {
                virtual_time_nanoseconds: 2_000_000,
                execution_quanta: 1,
            }),
        )
        .expect("reached combined status"),
        (BackendCommandStatus::Timeout, OutcomeKind::Timeout)
    );

    let mut plan = default.clone();
    plan.execution_mode = RunExecutionMode::Interactive;
    assert!(!guarded_campaign_run_eligible(&plan));

    let mut plan = default.clone();
    plan.save_policy = RunSavePolicy::OnFail;
    assert!(!guarded_campaign_run_eligible(&plan));

    let mut plan = default.clone();
    plan.watch_streams_live_status = true;
    assert!(guarded_campaign_run_eligible(&plan));

    let mut plan = default.clone();
    plan.startup_commands.pop();
    assert!(!guarded_campaign_run_eligible(&plan));

    let mut plan = default.clone();
    plan.initial_control_commands.clear();
    assert!(!guarded_campaign_run_eligible(&plan));

    let mut plan = default.clone();
    plan.accepted_interactive_commands
        .push(SessionCommandKind::Continue);
    assert!(!guarded_campaign_run_eligible(&plan));

    let mut plan = default.clone();
    plan.observer_profile = VERIFY_OBSERVER_PROFILES[0];
    assert!(!guarded_campaign_run_eligible(&plan));

    let mut plan = default;
    plan.collect_execution_fingerprints = true;
    assert!(!guarded_campaign_run_eligible(&plan));
}

#[test]
fn campaign_save_route_accepts_standard_virtual_time_and_marker_saves() {
    let cli = Cli::parse_from([
        "crucible",
        "save",
        "builtin:happy-path",
        "--at",
        "virtual-time",
        "--max-virtual-time",
        "2ms",
    ]);
    let Commands::Save(args) = &cli.command else {
        panic!("expected save command");
    };
    let mut plan = plan_save_invocation(args, Path::new("."), Path::new("./artifacts"))
        .expect("virtual-time save plan");

    assert!(plan.run_plan.campaign_deployment.is_none());
    assert!(guarded_campaign_save_eligible(&plan));

    plan.run_plan.campaign_deployment = Some(PathBuf::from("guarded.toml"));
    assert!(guarded_campaign_save_eligible(&plan));

    let marker_cli = Cli::parse_from([
        "crucible",
        "save",
        "builtin:happy-path",
        "--at",
        "marker",
        "--marker",
        "checkpoint",
    ]);
    let Commands::Save(args) = &marker_cli.command else {
        panic!("expected marker save command");
    };
    let marker = plan_save_invocation(args, Path::new("."), Path::new("./artifacts"))
        .expect("marker save plan");
    assert!(guarded_campaign_save_eligible(&marker));
    assert_eq!(
        guarded_campaign_save_stop(&marker).expect("marker campaign stop"),
        StopCondition::NamedBoundary(String::from("checkpoint"))
    );

    let mut quiescence = plan.clone();
    quiescence.at = SaveAtArg::Quiescence;
    quiescence.run_plan.terminal_condition = RunTerminalCondition::Quiescence;
    quiescence.run_plan.max_virtual_time = None;
    quiescence.run_plan.max_virtual_time_ticks = None;
    assert!(guarded_campaign_save_eligible(&quiescence));
    assert_eq!(
        guarded_campaign_save_stop(&quiescence).expect("quiescence campaign stop"),
        StopCondition::Observation(ObservationCondition::SchedulerQuiescent)
    );

    let mut unsupported = plan.clone();
    unsupported.selector = Some(SaveAtSelector::Marker {
        name: String::from("checkpoint"),
    });
    assert!(!guarded_campaign_save_eligible(&unsupported));

    let mut unsupported = plan;
    unsupported.run_plan.execution_mode = RunExecutionMode::Interactive;
    assert!(!guarded_campaign_save_eligible(&unsupported));
}

#[test]
fn campaign_save_schedule_taxonomy_admits_typed_selections() {
    let scenario = default_run_plan().scenario.scenario_def().clone();
    let schedule = typed_selection_schedule(&scenario);

    validate_portable_campaign_save_schedule(&schedule)
        .expect("typed saves carry their portable replay closure during export");
    validate_portable_campaign_save_schedule(&Schedule::empty())
        .expect("selection-free saves remain portable");
}

#[test]
fn campaign_virtual_time_save_exports_closure_for_unchanged_resume_and_fork_readers() {
    assert_campaign_save_exports_closure(
        &["--at", "virtual-time", "--max-virtual-time", "2ms"],
        StopCondition::VirtualTimeNanoseconds(2_000_000),
        false,
    );
}

#[test]
fn campaign_marker_save_exports_v4_event_proof_for_resume_and_fork_readers() {
    let marker = "guarded-campaign-save-fixture-marker";
    assert_campaign_save_exports_closure(
        &["--at", "marker", "--marker", marker],
        StopCondition::NamedBoundary(String::from(marker)),
        false,
    );
}

#[test]
fn campaign_marker_save_after_a_typed_choice_exports_a_portable_resume() {
    let marker = "guarded-campaign-save-fixture-marker";
    assert_campaign_save_exports_closure(
        &["--at", "marker", "--marker", marker],
        StopCondition::NamedBoundary(String::from(marker)),
        true,
    );
}

#[test]
fn campaign_virtual_time_save_after_a_typed_choice_exports_a_portable_resume() {
    assert_campaign_save_exports_closure(
        &["--at", "virtual-time", "--max-virtual-time", "2ticks"],
        StopCondition::VirtualTimeNanoseconds(2),
        true,
    );
}

#[test]
fn campaign_quiescence_save_after_a_typed_choice_replays_its_observation_proof() {
    assert_campaign_save_exports_closure(
        &["--at", "quiescence"],
        StopCondition::Observation(ObservationCondition::SchedulerQuiescent),
        true,
    );
}

#[test]
fn campaign_property_save_after_a_typed_choice_replays_its_observation_proof() {
    assert_campaign_save_exports_closure(
        &["--at", "property", "--property", "no-split-brain"],
        StopCondition::Observation(ObservationCondition::AssertionViolationTransition(
            String::from("no-split-brain"),
        )),
        true,
    );
}

#[test]
fn campaign_typed_save_without_a_replay_closure_fails_before_export() {
    let marker = "guarded-campaign-save-fixture-marker";
    let stop = StopCondition::NamedBoundary(String::from(marker));
    let capture =
        capture_campaign_save(&["--at", "marker", "--marker", marker], stop.clone(), true);
    let report = campaign_save_workflow_report(&capture.save_plan, &capture.campaign, &stop)
        .expect("typed campaign save report");
    let thin_plan = plan_cli_invocation(&capture.cli);
    let backend_plan = plan_backend_selection(&capture.cli)
        .expect("backend plan")
        .expect("save requires a backend");
    let mut outcome =
        finish_save_workflow_outcome(&thin_plan, &backend_plan, None, &capture.save_plan, report)
            .expect("finish typed save report");
    outcome.savepoint_replay_closure = None;

    let error = export_savepoint_handle(&capture.save_plan, &mut outcome)
        .expect_err("typed save missing its closure must fail before persistence");

    assert!(error.to_string().contains("missing the replay closure"));
    assert!(!capture.output.exists());
    assert!(!capture.temporary.path().join("_indexes").exists());
}

struct CampaignSaveCapture {
    temporary: TempDir,
    artifact_directory: PathBuf,
    output: PathBuf,
    cli: Cli,
    save_plan: SaveInvocationPlan,
    campaign: GuardedDefaultCampaignRun,
}

fn capture_campaign_save(
    boundary_arguments: &[&str],
    stop: StopCondition,
    marker_with_selection: bool,
) -> CampaignSaveCapture {
    let temporary = TempDir::new().expect("temporary save workspace");
    let artifact_directory = temporary.path().join("artifacts");
    let output = temporary.path().join("campaign.crucible-savepoint");
    let scenario = match &stop {
        StopCondition::Observation(ObservationCondition::AssertionViolationTransition(
            assertion,
        )) => campaign_portable_save_scenario(&temporary, marker_with_selection, Some(assertion)),
        _ if marker_with_selection
            || matches!(
                &stop,
                StopCondition::NamedBoundary(_)
                    | StopCondition::Observation(ObservationCondition::SchedulerQuiescent)
            ) =>
        {
            campaign_portable_save_scenario(&temporary, marker_with_selection, None)
        }
        _ => String::from("builtin:happy-path"),
    };
    let mut arguments = vec![
        String::from("crucible"),
        String::from("--backend"),
        String::from("double"),
        String::from("--store"),
        temporary.path().display().to_string(),
        String::from("--artifact-dir"),
        artifact_directory.display().to_string(),
        String::from("save"),
        scenario,
    ];
    arguments.extend(
        boundary_arguments
            .iter()
            .map(|argument| String::from(*argument)),
    );
    arguments.extend([String::from("--out"), output.display().to_string()]);
    let cli = Cli::parse_from(arguments);
    let Commands::Save(args) = &cli.command else {
        panic!("expected save command");
    };
    let save_plan = plan_save_invocation(args, temporary.path(), &artifact_directory)
        .expect("campaign save plan");
    let resources = AttemptResourceLimits::new(1, 256 * 1024 * 1024, 1024 * 1024, 16)
        .expect("campaign fixture resources");
    let exact_root = temporary.path().join("transient-exact");
    let exact_backend: Arc<dyn ImmutableBlobBackend> = Arc::new(DirectoryBlobBackend::new(
        "legacy-campaign-save-reader-test",
        exact_root.clone(),
    ));
    let checkpoints = Arc::new(
        ExactCheckpointStore::new(exact_backend, resources.maximum_disk_bytes())
            .expect("exact checkpoint store"),
    );
    let scenario = save_plan.run_plan.scenario.scenario_form().clone();
    let seed = save_plan
        .run_plan
        .request_seed
        .unwrap_or_else(|| scenario.scenario_def().seed());
    let host = LinuxQemuAttemptHostConfig::new(
        "/sys/fs/cgroup/crucible-campaign-save-reader-test",
        "/tmp/crucible-campaign-save-reader-test",
        "campaign-save-reader-test",
        1,
        1,
        65_529,
        65_529,
        16,
        1_024,
        Duration::from_secs(1),
    )
    .expect("fixture host configuration");
    let request = GuardedDefaultCampaignRunRequest::new(
        scenario,
        seed,
        "campaign-save-reader-test-engine",
        "campaign-save-reader-test-qemu",
        ProductionVmLifecycleConfig::new("qemu", "plugin", "kernel", "root", "run-state"),
        host,
        resources,
    )
    .with_discovery_stop(stop)
    .with_reached_stop_savepoint_capture(checkpoints);
    let campaign = run_guarded_default_campaign_test_fixture(request)
        .expect("campaign fixture should capture an authenticated savepoint");
    std::fs::remove_dir_all(&exact_root)
        .expect("remove transient physical checkpoint before durable readers run");

    CampaignSaveCapture {
        temporary,
        artifact_directory,
        output,
        cli,
        save_plan,
        campaign,
    }
}

fn handle_with_observation_proof(handle: &str, proof: &ObservationStopProof) -> String {
    let proof_bytes = proof.canonical_bytes();
    handle
        .lines()
        .map(|line| {
            if line.starts_with("boundary-proof\tcampaign-observation\t") {
                let fields = line.split('\t').collect::<Vec<_>>();
                assert_eq!(fields.len(), 6, "v6 observation proof fields");
                format!(
                    "boundary-proof\tcampaign-observation\t{}\t{}\t{}\t{}",
                    content_address_bytes(&proof_bytes),
                    hex_bytes(&proof_bytes),
                    fields[4],
                    fields[5],
                )
            } else {
                line.to_owned()
            }
        })
        .collect::<Vec<_>>()
        .join("\n")
        + "\n"
}

fn handle_with_observation_claim(
    handle: &str,
    proof: &ObservationStopProof,
    evidence: &crucible_daemon::CrucibleMeasurementReplayEvidence,
) -> String {
    let proof_bytes = proof.canonical_bytes();
    let evidence_bytes = evidence
        .canonical_bytes()
        .expect("canonical forged observation evidence");
    handle
        .lines()
        .map(|line| {
            if line.starts_with("boundary-proof\tcampaign-observation\t") {
                format!(
                    "boundary-proof\tcampaign-observation\t{}\t{}\t{}\t{}",
                    content_address_bytes(&proof_bytes),
                    hex_bytes(&proof_bytes),
                    content_address_bytes(&evidence_bytes),
                    hex_bytes(&evidence_bytes),
                )
            } else {
                line.to_owned()
            }
        })
        .collect::<Vec<_>>()
        .join("\n")
        + "\n"
}

fn rebuilt_observation_proof(
    source: &ObservationStopProof,
    boundary: ObservationQuantumBoundary,
    event_log: ObservationEventLogProof,
    witness: Option<AssertionViolationWitness>,
) -> ObservationStopProof {
    ObservationStopProof::new(
        source.condition().clone(),
        source.satisfaction(),
        source.child(),
        boundary,
        event_log,
        witness,
    )
    .expect("structurally valid forged observation proof")
}

fn recomputed_observation_proof_forgeries(
    source: &ObservationStopProof,
    retained_entries: &[crucible::SchedulerEventLogEntry],
) -> Vec<(&'static str, ObservationStopProof)> {
    let event_log = source.event_log();
    let wrong_event_log = ObservationEventLogProof::new(
        event_log.prefix(),
        event_log.appended_segment(),
        event_log.bytes(),
        event_log.events(),
        CampaignHash::derive("test.observation-forgery", b"event-log"),
    );
    let mut forgeries = vec![(
        "event-log",
        rebuilt_observation_proof(
            source,
            source.boundary(),
            wrong_event_log,
            source.assertion_witness().cloned(),
        ),
    )];

    let boundary = source.boundary();
    let shifted_boundary = ObservationQuantumBoundary::new(
        boundary.frontier_nanoseconds(),
        boundary.start_completed_quanta() + 1,
        boundary.completed_quanta() + 1,
        boundary.start_events(),
    )
    .expect("shifted quantum boundary remains structurally valid");
    forgeries.push((
        "quanta",
        rebuilt_observation_proof(
            source,
            shifted_boundary,
            event_log,
            source.assertion_witness().cloned(),
        ),
    ));

    if let Some(witness) = source.assertion_witness() {
        let wrong_state = crucible::SchedulerEventLogEntry::assertion_state_observation(
            witness.sequence(),
            VirtualTime {
                ticks: boundary.frontier_nanoseconds(),
            },
            crucible::AssertionId::from_name(witness.assertion()),
            crucible::AssertionPhase::Satisfied,
        );
        let wrong_state_witness = AssertionViolationWitness::new(
            witness.assertion(),
            witness.sequence(),
            CampaignHash::from_bytes(wrong_state.content_hash().bytes),
        )
        .expect("wrong-state witness remains structurally valid");
        forgeries.push((
            "assertion-state",
            rebuilt_observation_proof(source, boundary, event_log, Some(wrong_state_witness)),
        ));

        let other_entry = retained_entries
            .iter()
            .find(|entry| {
                entry.sequence() >= boundary.start_events()
                    && entry.sequence() < event_log.events()
                    && entry.sequence() != witness.sequence()
            })
            .expect("property fixture emits a second event in the matching quantum");
        let wrong_witness = AssertionViolationWitness::new(
            witness.assertion(),
            other_entry.sequence(),
            CampaignHash::from_bytes(other_entry.content_hash().bytes),
        )
        .expect("wrong event witness remains structurally valid");
        forgeries.push((
            "assertion-witness",
            rebuilt_observation_proof(source, boundary, event_log, Some(wrong_witness)),
        ));
    }

    forgeries
}

fn assert_campaign_save_exports_closure(
    boundary_arguments: &[&str],
    stop: StopCondition,
    with_selection: bool,
) {
    let CampaignSaveCapture {
        temporary,
        artifact_directory,
        output,
        cli,
        save_plan,
        campaign,
    } = capture_campaign_save(boundary_arguments, stop.clone(), with_selection);
    let report = campaign_save_workflow_report(&save_plan, &campaign, &stop)
        .expect("project campaign capture into legacy save contract");
    let thin_plan = plan_cli_invocation(&cli);
    let backend_plan = plan_backend_selection(&cli)
        .expect("backend plan")
        .expect("save requires a backend");
    let mut outcome =
        finish_save_workflow_outcome(&thin_plan, &backend_plan, None, &save_plan, report)
            .expect("finish projected save workflow");
    export_savepoint_handle(&save_plan, &mut outcome)
        .expect("export versioned handle and DAG closure");

    match &stop {
        StopCondition::NamedBoundary(name) => {
            assert_eq!(
                campaign.terminal_configuration().schedule.len(),
                usize::from(with_selection)
            );
            let boundary = outcome
                .save_boundary_evidence
                .as_ref()
                .expect("marker save boundary evidence");
            assert_eq!(
                boundary.selector,
                Some(SaveAtSelector::Marker { name: name.clone() })
            );
            let SaveBoundaryProof::CampaignMarkerEvent {
                sequence,
                content_hash,
                node: proved_node,
                retired_icount,
                marker: proved_marker,
            } = &boundary.proof
            else {
                panic!("expected authenticated campaign marker event proof");
            };
            let marker_entry = campaign
                .evidence()
                .event_log_entries()
                .iter()
                .find(|entry| entry.sequence() == *sequence)
                .expect("retained marker proof entry");
            assert_eq!(*content_hash, marker_entry.content_hash());
            assert_eq!(proved_marker, &crucible::MarkerId::from_name(name));
            assert_eq!(marker_entry.event_payload().kind(), "guest_marker");
            assert_eq!(marker_entry.event_payload().node("node"), Some(proved_node));
            assert_eq!(
                marker_entry.event_payload().icount("retired_icount"),
                Some(crucible::Icount {
                    retired: *retired_icount,
                })
            );
            assert_eq!(
                marker_entry.event_payload().string("marker"),
                Some(proved_marker.name.as_str())
            );
            let handle = std::fs::read_to_string(&output).expect("marker v5 handle");
            assert!(handle.contains("schema\tcrucible.savepoint-handle.v5\n"));
            assert!(handle.contains("campaign-replay-closure\tcrucible-hash:"));
            assert!(handle.contains("boundary-proof\tcampaign-marker-event\t"));
            assert!(handle.contains("boundary-predicate\t"));
            let decoded = decode_savepoint_handle(handle.as_bytes())
                .expect("decode authenticated campaign marker handle");
            assert!(matches!(
                decoded.boundary_proof,
                Some(SavepointBoundaryProof::CampaignMarkerEvent {
                    event_sequence,
                    event_content_hash,
                    node,
                    retired_icount: decoded_retired_icount,
                    frontier_ticks,
                    quanta,
                }) if event_sequence == *sequence
                    && event_content_hash == *content_hash
                    && node == *proved_node
                    && decoded_retired_icount == *retired_icount
                    && frontier_ticks == campaign.evidence().frontier().ticks
                    && quanta == campaign.evidence().quanta()
            ));
            assert_eq!(
                decoded.boundary_predicate,
                Some(crucible::Predicate::guest_marker(proved_marker.clone()))
            );
            if !with_selection {
                let legacy_v4 = handle
                    .lines()
                    .filter(|line| !line.starts_with("campaign-replay-closure\t"))
                    .map(|line| {
                        if line == "schema\tcrucible.savepoint-handle.v5" {
                            String::from("schema\tcrucible.savepoint-handle.v4")
                        } else {
                            line.to_owned()
                        }
                    })
                    .collect::<Vec<_>>()
                    .join("\n")
                    + "\n";
                let legacy_v4 = decode_savepoint_handle(legacy_v4.as_bytes())
                    .expect("historical selection-free v4 marker handle remains readable");
                savepoint_handle_evidence("resume", &legacy_v4)
                    .expect("historical v4 marker evidence synthesizes an empty closure");
            }

            let mislabeled_v3 = handle.replace(
                "schema\tcrucible.savepoint-handle.v5",
                "schema\tcrucible.savepoint-handle.v4",
            );
            assert!(decode_savepoint_handle(mislabeled_v3.as_bytes()).is_err());

            let wrong_hash = handle.replace(
                &format_content_hash_ref(*content_hash),
                &format_content_hash_ref(crucible::ContentHash::default()),
            );
            let error = decode_savepoint_handle(wrong_hash.as_bytes())
                .expect_err("v5 campaign marker hash must bind its canonical event");
            assert!(error.to_string().contains("canonical event"));

            let wrong_predicate = handle
                .lines()
                .map(|line| {
                    if line.starts_with("boundary-predicate\t") {
                        String::from("boundary-predicate\tnone")
                    } else {
                        line.to_owned()
                    }
                })
                .collect::<Vec<_>>()
                .join("\n")
                + "\n";
            assert!(decode_savepoint_handle(wrong_predicate.as_bytes()).is_err());

            let coordinate_proof = handle
                .lines()
                .map(|line| {
                    if line.starts_with("boundary-proof\t") {
                        format!(
                            "boundary-proof\tcoordinate\t{}\t{}",
                            campaign.evidence().frontier().ticks,
                            campaign.evidence().quanta()
                        )
                    } else {
                        line.to_owned()
                    }
                })
                .collect::<Vec<_>>()
                .join("\n")
                + "\n";
            assert!(decode_savepoint_handle(coordinate_proof.as_bytes()).is_err());

            let missing_node = crucible::NodeId {
                name: String::from("missing-campaign-marker-node"),
            };
            let missing_node_event = crucible::SchedulerEventLogEntry::guest_marker_observation(
                *sequence,
                crucible::Icount {
                    retired: *retired_icount,
                },
                missing_node.clone(),
                proved_marker.clone(),
            );
            let missing_source = handle
                .lines()
                .map(|line| {
                    if line.starts_with("boundary-proof\t") {
                        format!(
                            "boundary-proof\tcampaign-marker-event\t{}\t{}\t{}\t{}\t{}\t{}",
                            sequence,
                            format_content_hash_ref(missing_node_event.content_hash()),
                            missing_node.name,
                            retired_icount,
                            campaign.evidence().frontier().ticks,
                            campaign.evidence().quanta()
                        )
                    } else {
                        line.to_owned()
                    }
                })
                .collect::<Vec<_>>()
                .join("\n")
                + "\n";
            let missing_source = decode_savepoint_handle(missing_source.as_bytes())
                .expect("structurally valid v5 event record");
            let error = savepoint_handle_evidence("resume", &missing_source)
                .expect_err("v5 source node must belong to the embedded scenario");
            assert!(error.to_string().contains("not declared"));
        }
        StopCondition::VirtualTimeNanoseconds(_) => {
            assert_eq!(
                outcome
                    .save_boundary_evidence
                    .as_ref()
                    .expect("virtual-time boundary evidence")
                    .proof,
                SaveBoundaryProof::Coordinate
            );
            let handle = std::fs::read_to_string(&output).expect("virtual-time v5 handle");
            assert!(handle.contains("schema\tcrucible.savepoint-handle.v5\n"));
            assert!(handle.contains("campaign-replay-closure\tcrucible-hash:"));
            decode_savepoint_handle(handle.as_bytes())
                .expect("v5 decoder accepts campaign coordinate proof");
            if !with_selection {
                let legacy_v3 = handle
                    .lines()
                    .filter(|line| !line.starts_with("campaign-replay-closure\t"))
                    .map(|line| {
                        if line == "schema\tcrucible.savepoint-handle.v5" {
                            String::from("schema\tcrucible.savepoint-handle.v3")
                        } else {
                            line.to_owned()
                        }
                    })
                    .collect::<Vec<_>>()
                    .join("\n")
                    + "\n";
                let legacy_v3 = decode_savepoint_handle(legacy_v3.as_bytes())
                    .expect("historical selection-free v3 coordinate handle remains readable");
                savepoint_handle_evidence("resume", &legacy_v3)
                    .expect("historical v3 coordinate evidence synthesizes an empty closure");
            }
        }
        StopCondition::Observation(condition) => {
            let boundary = outcome
                .save_boundary_evidence
                .as_ref()
                .expect("observation save boundary evidence");
            let SaveBoundaryProof::CampaignObservation { proof, evidence } = &boundary.proof else {
                panic!("expected authenticated campaign observation proof");
            };
            let retained_evidence =
                crucible_daemon::CrucibleMeasurementReplayEvidence::from_canonical_bytes(evidence)
                    .expect("decode retained campaign observation evidence");
            assert_eq!(proof.condition(), condition);
            assert_eq!(proof.child(), campaign.terminal().observation().child());
            assert_eq!(
                proof.boundary().frontier_nanoseconds(),
                campaign.evidence().frontier().ticks
            );
            assert_eq!(
                campaign.terminal().observation().stop(),
                &StopOutcome::ObservationReached(proof.clone())
            );

            let handle = std::fs::read_to_string(&output).expect("observation v6 handle");
            assert!(handle.contains("schema\tcrucible.savepoint-handle.v6\n"));
            assert!(handle.contains("campaign-replay-closure\tcrucible-hash:"));
            assert!(handle.contains("boundary-proof\tcampaign-observation\t"));
            let decoded = decode_savepoint_handle(handle.as_bytes())
                .expect("decode authenticated campaign observation handle");
            assert_eq!(
                decoded.boundary_proof,
                Some(SavepointBoundaryProof::CampaignObservation {
                    proof: proof.clone(),
                    evidence: Box::new(retained_evidence.clone()),
                })
            );
            let pending = savepoint_handle_evidence("resume", &decoded)
                .expect("campaign observation handle reconstructs its checkpoint");
            assert_eq!(
                pending.source_observation_proof.as_deref(),
                Some(proof.as_ref())
            );
            assert_eq!(
                pending.source_observation_evidence.as_deref(),
                Some(&retained_evidence)
            );

            let mislabeled = handle.replace(
                "schema\tcrucible.savepoint-handle.v6",
                "schema\tcrucible.savepoint-handle.v5",
            );
            assert!(decode_savepoint_handle(mislabeled.as_bytes()).is_err());

            let wrong_checkpoint = handle
                .lines()
                .map(|line| {
                    if line.starts_with("checkpoint\t") {
                        format!(
                            "checkpoint\t{}",
                            format_content_hash_ref(crucible::ContentHash::default())
                        )
                    } else {
                        line.to_owned()
                    }
                })
                .collect::<Vec<_>>()
                .join("\n")
                + "\n";
            let error = decode_savepoint_handle(wrong_checkpoint.as_bytes())
                .expect_err("observation proof child must bind the checkpoint");
            assert!(error.to_string().contains("proof child"));

            let missing_predicate = handle
                .lines()
                .map(|line| {
                    if line.starts_with("boundary-predicate\t") {
                        String::from("boundary-predicate\tnone")
                    } else {
                        line.to_owned()
                    }
                })
                .collect::<Vec<_>>()
                .join("\n")
                + "\n";
            assert!(decode_savepoint_handle(missing_predicate.as_bytes()).is_err());
        }
        other => panic!("unsupported campaign save test boundary: {other:?}"),
    }

    let checkpoint = outcome
        .terminal_savepoint
        .expect("projected save exposes its logical checkpoint");
    let (handle_resume_plan, handle_evidence) =
        resume_plan_and_evidence_from_cli(&output, temporary.path());
    let (mut handle_fork_plan, handle_fork_evidence) = fork_plan_and_evidence_from_cli(
        &output.display().to_string(),
        temporary.path(),
        &artifact_directory,
    );
    let checkpoint_reference = format_content_hash_ref(checkpoint);
    let (store_resume_plan, store_evidence) =
        resume_plan_and_evidence_from_cli(Path::new(&checkpoint_reference), temporary.path());
    let (mut store_fork_plan, store_fork_evidence) = fork_plan_and_evidence_from_cli(
        &checkpoint_reference,
        temporary.path(),
        &artifact_directory,
    );

    assert_eq!(handle_evidence, handle_fork_evidence);
    assert_eq!(store_evidence, store_fork_evidence);
    let mut handle_without_source_claim = handle_evidence.clone();
    handle_without_source_claim.source_observation_proof = None;
    handle_without_source_claim.source_observation_evidence = None;
    assert_eq!(handle_without_source_claim, store_evidence);
    assert_eq!(handle_evidence.checkpoint.id, checkpoint);
    assert!(guarded_campaign_resume_eligible(
        &handle_resume_plan,
        &handle_evidence
    ));
    assert!(guarded_campaign_resume_eligible(
        &store_resume_plan,
        &store_evidence
    ));
    assert!(guarded_campaign_fork_eligible(
        &handle_fork_plan,
        &handle_fork_evidence
    ));
    assert!(guarded_campaign_fork_eligible(
        &store_fork_plan,
        &store_fork_evidence
    ));

    if let Some(source_proof) = handle_evidence.source_observation_proof.as_deref() {
        assert!(
            handle_evidence
                .schedule
                .decisions()
                .iter()
                .any(|decision| { matches!(decision, crucible::Decision::Selection(_)) })
        );
        let source_frontier = handle_evidence.checkpoint.virtual_time.ticks;
        let terminal_frontier = source_frontier.saturating_add(1);
        let mut replay_plan = handle_resume_plan.clone();
        replay_plan.terminal_condition = RunTerminalCondition::VirtualTime;
        replay_plan.max_virtual_time = Some(format!("{terminal_frontier}ticks"));
        replay_plan.max_virtual_time_ticks = Some(terminal_frontier);
        let replay = resume_campaign_fixture(
            &temporary,
            &handle_evidence,
            StopCondition::VirtualTimeNanoseconds(terminal_frontier),
            true,
        );
        let source = replay
            .campaign
            .resume()
            .expect("v6 replay retains its source authentication");
        let accepted_source = replay
            .campaign
            .observations()
            .iter()
            .find(|observation| observation.id() == source.source_observation())
            .expect("v6 replay retains its accepted source observation");
        assert!(matches!(
            accepted_source.observation().stop(),
            StopOutcome::ObservationReached(actual) if actual.as_ref() == source_proof
        ));
        assert!(source.source_savepoint().is_some());
        campaign_resume_workflow_report(&replay_plan, &handle_evidence, &replay.campaign)
            .expect("v6 source observation is reproduced before continuation");

        let mut remote_plan = handle_resume_plan.clone();
        remote_plan.max_virtual_time = None;
        remote_plan.max_virtual_time_ticks = None;
        remote_plan.terminal_condition = match source_proof.condition() {
            ObservationCondition::SchedulerQuiescent => RunTerminalCondition::Quiescence,
            ObservationCondition::AssertionViolationTransition(_)
            | ObservationCondition::AnyAssertionViolationTransition => {
                RunTerminalCondition::Property
            }
            ObservationCondition::SchedulerQuiescentOrExecutionQuanta { .. } => {
                RunTerminalCondition::Quiescence
            }
        };
        let ordinary_starts = Arc::new(AtomicUsize::new(0));
        let counted_ordinary = Arc::clone(&ordinary_starts);
        let observation_calls = Arc::new(AtomicUsize::new(0));
        let selection_applications = Arc::new(AtomicUsize::new(0));
        let continuation_applications = Arc::new(AtomicUsize::new(0));
        let control_plane = LifecycleControlPlane::new(
            "typed-observation-remote-resume",
            Vec::new(),
            move |_scenario: &crucible::ScenarioDef, _seed| {
                counted_ordinary.fetch_add(1, Ordering::SeqCst);
                ResumeRecordingLifecycleLoop::new(VirtualTime {
                    ticks: source_frontier,
                })
            },
        )
        .with_resume_replay_closure_validator(|scenario, configuration, checkpoint, envelope| {
            crucible_daemon::qemu_campaign_lifecycle::validate_remote_resume_replay_closure(
                scenario,
                configuration,
                checkpoint,
                envelope,
            )
            .map_err(|error| {
                crucible_api::ResumeReplayClosureValidationError::new(error.to_string())
            })
        })
        .with_resume_observation_loop_factory(capture_only_remote_observation_factory(
            remote_plan.clone(),
            handle_evidence.clone(),
            Arc::clone(&observation_calls),
            Arc::clone(&selection_applications),
            Arc::clone(&continuation_applications),
        ));
        let client = InProcessLifecycleClient::new(control_plane);
        let runtime = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .expect("observation remote resume test runtime");
        let remote_report = runtime
            .block_on(
                run_remote_control_client_resume_from_evidence_with_driver_async(
                    &client,
                    &remote_plan,
                    handle_evidence.clone(),
                    ResumeInteractiveCommandDriver::Preparsed(&[]),
                    false,
                ),
            )
            .expect("cold remote session path should authenticate and restore v6 evidence");
        assert_eq!(remote_report.source_checkpoint, checkpoint);
        assert_eq!(runtime.block_on(client.session_count()), 0);
        assert_eq!(ordinary_starts.load(Ordering::SeqCst), 0);
        assert_eq!(observation_calls.load(Ordering::SeqCst), 1);
        assert_eq!(selection_applications.load(Ordering::SeqCst), 2);
        assert_eq!(continuation_applications.load(Ordering::SeqCst), 0);
        match source_proof.condition() {
            ObservationCondition::SchedulerQuiescent
            | ObservationCondition::SchedulerQuiescentOrExecutionQuanta { .. } => {
                assert_eq!(remote_report.run.status, BackendCommandStatus::Passed);
                assert_eq!(remote_report.run.outcome, Some(OutcomeKind::Passed));
                assert_eq!(remote_report.run.final_state, "quiescent");
            }
            ObservationCondition::AssertionViolationTransition(_)
            | ObservationCondition::AnyAssertionViolationTransition => {
                assert_eq!(remote_report.run.status, BackendCommandStatus::Failed);
                assert_eq!(remote_report.run.outcome, Some(OutcomeKind::Failed));
                assert_eq!(remote_report.run.final_state, "property-failed");
            }
        }

        let handle = std::fs::read_to_string(&output).expect("read v6 handle for tampering");
        for (mutation, forged) in recomputed_observation_proof_forgeries(
            source_proof,
            campaign.evidence().event_log_entries(),
        ) {
            let forged_handle = handle_with_observation_proof(&handle, &forged);
            let error = decode_savepoint_handle(forged_handle.as_bytes())
                .expect_err("proof-only forgery must disagree with retained raw evidence");
            assert!(
                error
                    .to_string()
                    .contains("campaign observation proof and evidence disagree"),
                "{mutation}: {error}"
            );
        }

        let source_evidence = handle_evidence
            .source_observation_evidence
            .as_deref()
            .expect("v6 handle retains raw source evidence");
        let source_boundary = source_evidence
            .observation_boundary()
            .expect("v6 raw evidence retains an observation boundary");
        let shifted_boundary = crucible_daemon::CrucibleObservationBoundaryEvidence::new(
            source_boundary.frontier(),
            source_boundary.quantum_start_completed_quanta() + 1,
            source_boundary.completed_quanta() + 1,
            source_boundary.quantum_start_events(),
            source_boundary.event_log_offset(),
            source_boundary.scheduler_quiescent(),
        )
        .expect("shifted raw boundary remains structurally valid");
        let shifted_proof = recomputed_observation_proof_forgeries(
            source_proof,
            campaign.evidence().event_log_entries(),
        )
        .into_iter()
        .find_map(|(mutation, proof)| (mutation == "quanta").then_some(proof))
        .expect("quantum-coordinate proof forgery");
        let (shifted_evidence, _, _) =
            crucible_daemon::evaluate_crucible_observation_measurement_publication(
                source_evidence.scenario(),
                source_evidence.configuration(),
                handle_evidence.scenario_form.measurements(),
                source_evidence.entries().to_vec(),
                source_evidence.terminal().clone(),
                shifted_boundary,
                crucible_daemon::MAX_CRUCIBLE_MEASUREMENT_REPLAY_EVIDENCE_BYTES,
            )
            .expect("build coherent shifted raw evidence")
            .into_parts();
        shifted_evidence
            .verify_observation_stop_proof(&shifted_proof)
            .expect("shifted proof and raw evidence agree with each other");
        let forged_handle =
            handle_with_observation_claim(&handle, &shifted_proof, &shifted_evidence);
        let decoded = decode_savepoint_handle(forged_handle.as_bytes())
            .expect("coherent proof and raw evidence pass portable structural checks");
        let forged_evidence = savepoint_handle_evidence("resume", &decoded)
            .expect("coherent forged claim remains pending until actual replay");
        let error = match try_resume_campaign_fixture(
            &temporary,
            &forged_evidence,
            StopCondition::VirtualTimeNanoseconds(terminal_frontier),
            true,
        ) {
            Err(error) => error,
            Ok(_) => panic!("actual source replay accepted coherent portable forgery"),
        };
        assert!(
            error
                .to_string()
                .contains("legacy resume source observation differs"),
            "{error}"
        );
        let remote_error = runtime
            .block_on(
                run_remote_control_client_resume_from_evidence_with_driver_async(
                    &client,
                    &remote_plan,
                    forged_evidence,
                    ResumeInteractiveCommandDriver::Preparsed(&[]),
                    false,
                ),
            )
            .expect_err("cold remote source replay must reject a coherent forged pair");
        assert!(
            remote_error
                .to_string()
                .contains("legacy resume source observation differs"),
            "{remote_error}"
        );
        assert_eq!(runtime.block_on(client.session_count()), 0);
        assert_eq!(ordinary_starts.load(Ordering::SeqCst), 0);
        assert_eq!(observation_calls.load(Ordering::SeqCst), 2);
    }

    let fork_frontier = handle_evidence
        .checkpoint
        .virtual_time
        .ticks
        .saturating_mul(2);
    for plan in [&mut handle_fork_plan, &mut store_fork_plan] {
        plan.terminal_condition = RunTerminalCondition::VirtualTime;
        plan.max_virtual_time = Some(format!("{fork_frontier}ticks"));
        plan.max_virtual_time_ticks = Some(fork_frontier);
    }
    assert!(guarded_campaign_fork_eligible(
        &handle_fork_plan,
        &handle_fork_evidence
    ));
    assert!(guarded_campaign_fork_eligible(
        &store_fork_plan,
        &store_fork_evidence
    ));

    if with_selection {
        handle_evidence
            .replay_closure
            .validate_for_schedule(&handle_evidence.scenario_form, &handle_evidence.schedule)
            .expect("v5 handle closure authenticates its typed schedule");
        assert!(
            ensure_session_replay_evidence_supported(
                "typed fork regression",
                &handle_fork_evidence
            )
            .is_err()
        );
        if handle_evidence.source_observation_proof.is_none() {
            let lifecycle_starts = Arc::new(AtomicUsize::new(0));
            let counted_starts = Arc::clone(&lifecycle_starts);
            let source_frontier = handle_evidence.checkpoint.virtual_time;
            let control_plane = LifecycleControlPlane::new(
                "typed-selection-remote-resume",
                Vec::new(),
                move |_scenario: &crucible::ScenarioDef, _seed| {
                    counted_starts.fetch_add(1, Ordering::Relaxed);
                    ResumeRecordingLifecycleLoop::new(source_frontier)
                },
            )
            .with_resume_replay_closure_validator(
                |scenario, configuration, checkpoint, envelope| {
                    crucible_daemon::qemu_campaign_lifecycle::validate_remote_resume_replay_closure(
                        scenario,
                        configuration,
                        checkpoint,
                        envelope,
                    )
                    .map_err(|error| {
                        crucible_api::ResumeReplayClosureValidationError::new(error.to_string())
                    })
                },
            );
            let client = InProcessLifecycleClient::new(control_plane);
            let runtime = tokio::runtime::Builder::new_current_thread()
                .enable_all()
                .build()
                .expect("typed remote resume test runtime");
            let mut remote_plan = handle_resume_plan.clone();
            let remote_target = source_frontier.ticks.saturating_add(1);
            remote_plan.terminal_condition = RunTerminalCondition::VirtualTime;
            remote_plan.max_virtual_time = Some(format!("{remote_target}ticks"));
            remote_plan.max_virtual_time_ticks = Some(remote_target);
            let report = runtime
                .block_on(
                    run_remote_control_client_resume_from_evidence_with_driver_async(
                        &client,
                        &remote_plan,
                        handle_evidence.clone(),
                        ResumeInteractiveCommandDriver::Preparsed(&[]),
                        false,
                    ),
                )
                .expect("remote session path should consume authenticated typed evidence");
            assert_eq!(report.source_checkpoint, checkpoint);
            assert_eq!(report.run.final_frontier_ticks, remote_target);
            assert_eq!(runtime.block_on(client.session_count()), 0);
            assert_eq!(lifecycle_starts.load(Ordering::Relaxed), 1);
        }

        for (reader, mut plan, mut fork_plan, evidence) in [
            (
                "v5 handle",
                handle_resume_plan.clone(),
                handle_fork_plan.clone(),
                handle_evidence.clone(),
            ),
            (
                "v3 DAG index",
                store_resume_plan.clone(),
                store_fork_plan.clone(),
                store_evidence.clone(),
            ),
        ] {
            let source_frontier = evidence.checkpoint.virtual_time.ticks;
            let terminal_frontier = source_frontier.saturating_mul(2);
            plan.terminal_condition = RunTerminalCondition::VirtualTime;
            plan.max_virtual_time = Some(format!("{terminal_frontier}ticks"));
            plan.max_virtual_time_ticks = Some(terminal_frontier);
            assert!(guarded_campaign_resume_eligible(&plan, &evidence));
            fork_plan.terminal_condition = RunTerminalCondition::VirtualTime;
            fork_plan.max_virtual_time = Some(format!("{terminal_frontier}ticks"));
            fork_plan.max_virtual_time_ticks = Some(terminal_frontier);
            assert!(guarded_campaign_fork_eligible(&fork_plan, &evidence));

            // This modeled lifecycle proves campaign ownership and exact
            // reply application. Packaged-QEMU acceptance remains a VM gate.
            let fixture = resume_campaign_fixture(
                &temporary,
                &evidence,
                StopCondition::VirtualTimeNanoseconds(terminal_frontier),
                true,
            );
            let resume = fixture
                .campaign
                .resume()
                .unwrap_or_else(|| panic!("{reader} resume must retain its source proof"));
            let source_savepoint = resume
                .source_savepoint()
                .unwrap_or_else(|| panic!("{reader} resume must capture its exact source"));

            assert_eq!(resume.source_checkpoint(), checkpoint);
            assert_eq!(resume.source_frontier().ticks, source_frontier);
            assert!(resume.ready().is_some());
            assert!(resume.selection().is_some());
            assert!(resume.continuation().is_some());
            let selection_applications = fixture
                .trace
                .selection_applications()
                .expect("read explicit fixture reply trace");
            assert_eq!(selection_applications.len(), 3);
            assert!(selection_applications.iter().enumerate().all(
                |(generation, (actual_generation, frontier))| {
                    *actual_generation == generation as u64 && frontier.ticks == 0
                }
            ));
            assert!(
                selection_applications
                    .iter()
                    .any(|(generation, _)| { *generation >= 2 })
            );
            assert_eq!(
                source_savepoint.evidence().frontier().ticks,
                source_frontier
            );
            assert_eq!(
                fixture.campaign.evidence().frontier().ticks,
                terminal_frontier
            );
            assert!(terminal_frontier > source_frontier);
            assert!(
                fixture
                    .campaign
                    .evidence()
                    .event_log_entries()
                    .iter()
                    .any(|entry| {
                        entry
                            .event_payload()
                            .icount("retired_icount")
                            .is_some_and(|icount| icount.retired > source_frontier)
                    })
            );
            assert_eq!(
                fixture
                    .campaign
                    .terminal_configuration()
                    .schedule
                    .decisions()
                    .get(..evidence.schedule.len()),
                Some(evidence.schedule.decisions())
            );

            let report = campaign_resume_workflow_report(&plan, &evidence, &fixture.campaign)
                .unwrap_or_else(|error| panic!("{reader} projection should pass: {error}"));
            assert_eq!(report.run.execution_owner, RunExecutionOwner::Campaign);
            assert_eq!(report.run.final_frontier_ticks, terminal_frontier);
            let fork_report = campaign_fork_workflow_report(&fork_plan, &evidence, report);
            let live_artifact = live_qemu_artifact_evidence_from_run(
                LiveQemuArtifactRecipe {
                    producer: "fork",
                    terminal_condition: fork_plan.terminal_condition,
                    max_virtual_time_ticks: fork_plan.max_virtual_time_ticks,
                    max_quanta: None,
                    coverage: false,
                    execution_mode: fork_plan.execution_mode,
                    startup_commands: &fork_plan.startup_commands,
                    initial_control_commands: &fork_plan.initial_control_commands,
                    branch: LiveQemuReplayBranch::Resume {
                        base_decisions: evidence.schedule.len() as u64,
                        frontier_ticks: source_frontier,
                    },
                },
                &evidence.scenario_form,
                &fork_report.run,
            )
            .unwrap_or_else(|error| {
                panic!("{reader} typed fork artifact capture should pass: {error}")
            });
            let closure_bytes = live_artifact
                .campaign_replay_closure
                .as_deref()
                .unwrap_or_else(|| panic!("{reader} fork artifact must retain its closure"));
            let replay_closure = GuardedCampaignReplayClosure::from_canonical_bytes(closure_bytes)
                .unwrap_or_else(|error| panic!("{reader} fork closure should decode: {error}"));
            replay_closure
                .validate_for_schedule(
                    &evidence.scenario_form,
                    &fork_report.terminal_configuration.schedule,
                )
                .unwrap_or_else(|error| {
                    panic!("{reader} fork closure should cover terminal schedule: {error}")
                });
            assert_eq!(
                expected_live_qemu_execution_owner(
                    &live_artifact.contract,
                    &fork_report.terminal_configuration.schedule,
                    true,
                ),
                RunExecutionOwner::Campaign,
            );
            let replay_closure = campaign_owner_replay_closure(
                "fork",
                &fork_report.terminal_configuration.schedule,
                Some(replay_closure),
            )
            .unwrap_or_else(|error| {
                panic!("{reader} fork replay should admit its closure: {error}")
            });
            replay_closure
                .validate_for_schedule(
                    &evidence.scenario_form,
                    &fork_report.terminal_configuration.schedule,
                )
                .unwrap_or_else(|error| {
                    panic!("{reader} admitted fork closure should remain exact: {error}")
                });
            assert_eq!(fork_report.source_checkpoint, checkpoint);
            assert_eq!(fork_report.branch_checkpoint, checkpoint);
            assert_eq!(
                fork_report.branch_configuration,
                evidence.configuration.id()
            );
        }

        let handle_text = std::fs::read_to_string(&output).expect("read v5 handle");
        let missing_closure = handle_text
            .lines()
            .filter(|line| !line.starts_with("campaign-replay-closure\t"))
            .collect::<Vec<_>>()
            .join("\n")
            + "\n";
        assert!(decode_savepoint_handle(missing_closure.as_bytes()).is_err());
        if handle_evidence.source_observation_proof.is_some() {
            return;
        }
        let historical_schema = match stop {
            StopCondition::NamedBoundary(_) => "crucible.savepoint-handle.v4",
            StopCondition::VirtualTimeNanoseconds(_) => "crucible.savepoint-handle.v3",
            _ => panic!("typed portable-save regression uses marker or virtual time"),
        };
        let typed_legacy_handle = handle_text
            .lines()
            .filter(|line| !line.starts_with("campaign-replay-closure\t"))
            .map(|line| {
                if line == "schema\tcrucible.savepoint-handle.v5" {
                    format!("schema\t{historical_schema}")
                } else {
                    line.to_owned()
                }
            })
            .collect::<Vec<_>>()
            .join("\n")
            + "\n";
        let typed_legacy_handle = decode_savepoint_handle(typed_legacy_handle.as_bytes())
            .expect("historical schema remains structurally readable");
        let error = savepoint_handle_evidence("resume", &typed_legacy_handle)
            .expect_err("historical typed handle without closure must fail closed");
        assert!(error.to_string().contains("missing the replay closure"));
        let empty_closure =
            GuardedCampaignReplayClosure::empty_for_selection_free_schedule(&Schedule::empty())
                .expect("empty closure")
                .to_canonical_bytes()
                .expect("encode empty closure");
        let mismatched_closure = handle_text
            .lines()
            .map(|line| {
                if line.starts_with("campaign-replay-closure\t") {
                    format!(
                        "campaign-replay-closure\t{}\t{}",
                        content_address_bytes(&empty_closure),
                        hex_bytes(&empty_closure)
                    )
                } else {
                    line.to_owned()
                }
            })
            .collect::<Vec<_>>()
            .join("\n")
            + "\n";
        let mismatched_closure = decode_savepoint_handle(mismatched_closure.as_bytes())
            .expect("mismatched closure remains structurally canonical");
        let error = savepoint_handle_evidence("resume", &mismatched_closure)
            .expect_err("closure must cover its exact typed schedule");
        assert!(error.to_string().contains("missing a schedule selection"));

        let store = crucible::LocalDagStore::new(temporary.path().to_path_buf());
        let index = store
            .read_checkpoint_closure_index(checkpoint)
            .expect("read v3 checkpoint closure index");
        let replay_object = index
            .opaque_replay_artifact
            .expect("v3 index retains replay closure object");
        assert_eq!(
            index.referenced_objects(),
            BTreeSet::from([index.reproduction_artifact, replay_object])
        );
        assert!(
            store
                .delete(&replay_object)
                .expect("delete closure fixture")
        );
        let error = savepoint_store_evidence("resume", checkpoint, temporary.path())
            .expect_err("missing retained closure object must fail closed");
        assert!(error.to_string().contains("missing retained object"));
        store
            .write_checkpoint_closure_index(
                checkpoint,
                index.reproduction_artifact,
                handle_evidence.checkpoint.virtual_time,
            )
            .expect("write historical v2 typed index fixture");
        let error = savepoint_store_evidence("resume", checkpoint, temporary.path())
            .expect_err("historical typed index without closure must fail closed");
        assert!(error.to_string().contains("missing the replay closure"));
    }
}

fn campaign_portable_save_scenario(
    temporary: &TempDir,
    with_selection: bool,
    assertion: Option<&str>,
) -> String {
    let node = crucible::NodeId {
        name: String::from("campaign-marker-save-node"),
    };
    let world = crucible::World::from_nodes(vec![crucible::WorldNode {
        id: node.clone(),
        arch: crucible::NodeTemplate::DEFAULT_ARCH,
        memory_mib: crucible::NodeTemplate::DEFAULT_MEMORY_MIB,
        cmdline: String::from("crucible-campaign-marker-save-fixture"),
        ready_point: crucible::ReadyPoint::FixedIcount {
            icount: crucible::Icount { retired: 1 },
        },
        white_box: crucible::WhiteBoxPolicy::Enabled,
        smp_vcpus: crucible::NodeTemplate::DEFAULT_SMP_VCPUS,
        icount_shift: crucible::NodeTemplate::DEFAULT_ICOUNT_SHIFT,
        kernel: None,
        root_image: None,
        initrd: None,
    }])
    .expect("campaign marker save world");
    let declaration = SelectableDeclaration::new(
        "campaign.save.fixture-choice",
        ChoiceSource::Guest {
            node: node.name.clone(),
            protocol_version: u32::from(crucible_protocol::SELECTABLE_PROTOCOL_VERSION),
        },
        ChoiceDomain::Boolean(BooleanDomain::new(1).expect("boolean domain")),
        ChoiceValue::Boolean(false),
        ChoiceClassContext::new(BTreeSet::new()).expect("choice class"),
        BTreeSet::from([String::from("campaign-save")]),
        true,
    )
    .expect("campaign marker save selectable declaration");
    let selectables = crucible::ScenarioSelectables::new(
        &world,
        crucible::ScenarioSelectableLimits::new(4, 8, 16, 32)
            .expect("campaign marker selectable limits"),
        vec![declaration],
    )
    .expect("campaign marker save selectables");
    let properties = assertion
        .map_or_else(
            || Ok(crucible::Properties::empty()),
            |assertion| {
                crucible::Properties::from_assertions_for_world(
                    &world,
                    vec![crucible::AssertionDef::guest_unreachable(
                        crucible::AssertionId::from_name(assertion),
                        "the campaign save fixture must retain its violation",
                    )],
                )
            },
        )
        .expect("campaign portable save properties");
    let mut form = crucible::ScenarioDefForm::from_components(
        &world,
        &crucible::Plan::empty(),
        &properties,
        crucible::Seed::from_u64(8_004),
    )
    .expect("campaign portable save scenario");
    if with_selection {
        form = form
            .with_selectables(selectables)
            .expect("attach campaign portable save selectables");
    }
    let path = temporary.path().join("campaign-portable-save.toml");
    std::fs::write(
        &path,
        form.to_canonical_toml()
            .expect("canonical campaign portable save scenario"),
    )
    .expect("write campaign portable save scenario");
    path.display().to_string()
}

fn resume_plan_and_evidence_from_cli(
    savepoint: &Path,
    store: &Path,
) -> (ResumeInvocationPlan, ResumeHandleEvidence) {
    let cli = Cli::parse_from([
        String::from("crucible"),
        String::from("--store"),
        store.display().to_string(),
        String::from("resume"),
        savepoint.display().to_string(),
    ]);
    let Commands::Resume(args) = &cli.command else {
        panic!("expected resume command");
    };
    let plan = plan_resume_invocation(args, store).expect("resume plan");
    let evidence =
        resume_handle_evidence(&plan).expect("unchanged resume reader accepts campaign save");
    (plan, evidence)
}

fn fork_plan_and_evidence_from_cli(
    savepoint: &str,
    store: &Path,
    artifact_directory: &Path,
) -> (ForkInvocationPlan, ResumeHandleEvidence) {
    let cli = Cli::parse_from([
        String::from("crucible"),
        String::from("--store"),
        store.display().to_string(),
        String::from("fork"),
        String::from(savepoint),
    ]);
    let Commands::Fork(args) = &cli.command else {
        panic!("expected fork command");
    };
    let plan = plan_fork_invocation(args, None, artifact_directory, store).expect("fork plan");
    let evidence =
        fork_handle_evidence(&plan).expect("unchanged fork reader accepts campaign save");
    (plan, evidence)
}

#[test]
fn guarded_campaign_route_uses_the_deployment_quanta_ceiling() {
    let insufficient = AttemptResourceLimits::new(1, 1, 1, PRODUCTION_CLI_QUANTUM_BUDGET - 1)
        .expect("nonzero limits");
    assert!(guarded_run_resources(insufficient, None).is_err());

    let sufficient = AttemptResourceLimits::new(
        2,
        1024 * 1024 * 1024,
        2 * 1024 * 1024 * 1024,
        PRODUCTION_CLI_QUANTUM_BUDGET,
    )
    .expect("guarded capacity");
    let resources = guarded_run_resources(sufficient, None).expect("default run resources");
    assert_eq!(
        resources.maximum_execution_quanta(),
        PRODUCTION_CLI_QUANTUM_BUDGET
    );

    let larger = AttemptResourceLimits::new(
        2,
        1024 * 1024 * 1024,
        2 * 1024 * 1024 * 1024,
        PRODUCTION_CLI_QUANTUM_BUDGET + 10,
    )
    .expect("larger guarded capacity");
    let resources = guarded_run_resources(larger, Some(PRODUCTION_CLI_QUANTUM_BUDGET + 10))
        .expect("requested run resources");
    assert_eq!(
        resources.maximum_execution_quanta(),
        PRODUCTION_CLI_QUANTUM_BUDGET + 10
    );
    assert!(guarded_run_resources(larger, Some(PRODUCTION_CLI_QUANTUM_BUDGET + 11)).is_err());
}
