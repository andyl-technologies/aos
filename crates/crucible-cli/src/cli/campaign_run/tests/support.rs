//! Provides shared guarded campaign fixtures and evidence.

use super::*;

pub(super) fn default_run_plan() -> RunInvocationPlan {
    let cli = Cli::parse_from(["crucible", "run", "builtin:happy-path"]);
    let Commands::Run(args) = &cli.command else {
        panic!("expected run command");
    };
    plan_run_invocation(args, Path::new("."))
        .or_panic("built-in default run should produce an invocation plan")
}

fn determinism_policy_request() -> GuardedDefaultCampaignRunRequest {
    let scenario = default_run_plan().scenario.scenario_form().clone();
    let resources = AttemptResourceLimits::new(1, 256 * 1024 * 1024, 1024 * 1024, 16)
        .or_panic("campaign policy fixture resources");
    let host = LinuxQemuAttemptHostConfig::new(
        "/sys/fs/cgroup/crucible-campaign-policy-test",
        "/tmp/crucible-campaign-policy-test",
        "campaign-policy-test",
        1,
        1,
        65_529,
        65_529,
        16,
        1_024,
        Duration::from_secs(1),
    )
    .or_panic("campaign policy fixture host configuration");

    GuardedDefaultCampaignRunRequest::new(
        scenario.clone(),
        scenario.scenario_def().seed(),
        "campaign-policy-test-engine",
        "campaign-policy-test-qemu",
        ProductionVmLifecycleConfig::new("qemu", "plugin", "kernel", "root", "run-state"),
        host,
        resources,
    )
}

#[test]
fn deployment_determinism_policy_controls_paired_replay_verification() {
    let request = apply_guarded_campaign_determinism_policy(determinism_policy_request(), false);
    assert!(!request.verifies_determinism_findings());

    let request = apply_guarded_campaign_determinism_policy(determinism_policy_request(), true);
    assert!(request.verifies_determinism_findings());
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
        .or_panic("complete terminal epoch");

    assert_eq!(&combined[..diagnostics.len()], diagnostics);
    assert_eq!(&combined[diagnostics.len()..], terminal);
    assert_ne!(combined[2].fingerprint, combined[4].fingerprint);
}

#[test]
fn campaign_report_fingerprints_require_a_terminal_epoch() {
    let error = campaign_execution_fingerprints(&[], None)
        .error_or_panic("accepted campaign reports require terminal fingerprints");

    assert!(error.to_string().contains("without terminal fingerprint"));
}

pub(super) fn resume_evidence(schedule: Schedule, frontier: VirtualTime) -> ResumeHandleEvidence {
    let scenario_form = fixed_checkpoint_scenario_form();
    resume_evidence_for_scenario(scenario_form, schedule, frontier)
}

pub(super) fn resume_evidence_with_assertion(frontier: VirtualTime) -> ResumeHandleEvidence {
    let scenario_form = fixed_checkpoint_scenario_form();
    assert!(!scenario_form.properties().assertions().is_empty());
    resume_evidence_for_scenario(scenario_form, Schedule::empty(), frontier)
}

pub(super) fn fixed_checkpoint_scenario_form() -> crucible::ScenarioDefForm {
    let directory = TempDir::new().or_panic("fixed checkpoint scenario workspace");
    crucible_api::build_exact_ram_production_checkpoint_codec_fixture(directory.path())
        .or_panic("fixed authenticated checkpoint scenario")
        .source()
        .clone()
}

pub(super) fn resume_evidence_for_scenario(
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
        checkpoint_for_resume_configuration(&configuration, frontier).or_panic("resume checkpoint");
    let replay_closure =
        GuardedCampaignReplayClosure::from_canonical_bytes(b"CCRC\0\0\0\x01\0\0\0\0")
            .or_panic("canonical empty replay closure");
    replay_closure
        .validate_for_schedule(&scenario_form, &schedule)
        .or_panic("replay closure matches fixture schedule");
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

pub(super) fn default_resume_plan(
    evidence: &ResumeHandleEvidence,
    store: &Path,
) -> ResumeInvocationPlan {
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

pub(super) fn typed_selection_schedule(scenario: &crucible::ScenarioDef) -> Schedule {
    let domain = ChoiceDomain::Boolean(BooleanDomain::new(1).or_panic("Boolean domain"));
    let declaration = SelectableDeclaration::new(
        "product.recovery",
        ChoiceSource::Guest {
            node: String::from("vm-a"),
            protocol_version: u32::from(crucible_protocol::SELECTABLE_PROTOCOL_VERSION),
        },
        domain.clone(),
        ChoiceValue::Boolean(false),
        ChoiceClassContext::new(BTreeSet::new()).or_panic("class context"),
        BTreeSet::new(),
        true,
    )
    .or_panic("selectable declaration");
    let opportunity = ChoiceOpportunity::new(
        crucible_campaign::ScenarioDefId::from_hash(CampaignHash::from_bytes(scenario.id().bytes)),
        &declaration,
        &domain,
        ChoiceCoordinate {
            scheduler: CampaignHash::derive("test", b"guarded-campaign-resume-scheduler"),
            producer: CampaignHash::derive("test", b"guarded-campaign-resume-producer"),
        },
        "guarded-campaign-resume-route",
        None,
    )
    .or_panic("choice opportunity");
    let selection = Selection::new(
        &opportunity,
        &domain,
        ChoiceValue::Boolean(false),
        SelectionOrigin::Default,
    )
    .or_panic("default selection");
    Schedule::from_decisions([crucible::Decision::Selection(
        crucible::SelectionDecision::new(&selection),
    )])
}

pub(super) struct ResumeCampaignFixture {
    pub(super) campaign: GuardedDefaultCampaignRun,
    pub(super) checkpoints: Arc<ExactCheckpointStore>,
    pub(super) checkpoint_directory: TempDir,
    pub(super) checkpoint_root: PathBuf,
}

pub(super) fn resume_campaign_fixture(
    temporary: &TempDir,
    evidence: &ResumeHandleEvidence,
    final_stop: StopCondition,
    watch_frames: bool,
) -> ResumeCampaignFixture {
    try_resume_campaign_fixture(temporary, evidence, final_stop, watch_frames)
        .or_panic("campaign fixture should resume through exact capture")
}

pub(super) fn try_resume_campaign_fixture(
    temporary: &TempDir,
    evidence: &ResumeHandleEvidence,
    final_stop: StopCondition,
    watch_frames: bool,
) -> Result<ResumeCampaignFixture, Box<dyn Error + Send + Sync>> {
    let resources = AttemptResourceLimits::new(1, 256 * 1024 * 1024, 1024 * 1024, 16)
        .or_panic("campaign fixture resources");
    let checkpoint_directory = tempfile::Builder::new()
        .prefix("transient-resume-exact-")
        .tempdir_in(temporary.path())
        .or_panic("transient exact directory");
    let checkpoint_root = checkpoint_directory.path().to_path_buf();
    let exact_backend: Arc<dyn ImmutableBlobBackend> = Arc::new(DirectoryBlobBackend::new(
        "guarded-campaign-resume-projection-test",
        checkpoint_root.clone(),
    ));
    let checkpoints = Arc::new(
        ExactCheckpointStore::new(exact_backend, resources.maximum_disk_bytes())
            .or_panic("exact checkpoint store"),
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
    .or_panic("fixture host configuration");
    let request = GuardedDefaultCampaignRunRequest::new(
        evidence.scenario_form.clone(),
        evidence.scenario.seed(),
        "campaign-resume-projection-test-engine",
        "campaign-resume-projection-test-qemu",
        ProductionVmLifecycleConfig::new(
            "qemu",
            "plugin",
            "kernel",
            "root",
            temporary.path().join("run-state"),
        ),
        host,
        resources,
    );
    let request =
        attach_guarded_resume_source(request, evidence, final_stop, Arc::clone(&checkpoints));
    let request = if watch_frames {
        request.with_watch_frames()
    } else {
        request
    };
    let (campaign, _trace) =
        run_guarded_default_campaign_test_fixture_with_trace_and_choice_offer(request, false)?;

    Ok(ResumeCampaignFixture {
        campaign,
        checkpoints,
        checkpoint_directory,
        checkpoint_root,
    })
}

pub(super) fn capture_only_remote_observation_factory(
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
        let source = &request.observation_source;
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
            .or_panic("remote observation fixture resources");
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
            run_guarded_default_campaign_test_fixture_with_trace_and_choice_offer(
                campaign_request,
                false,
            )
            .map_err(|error| {
                crucible_api::LifecycleApiError::ResumeObservationSource {
                    message: format!("authenticate test remote source campaign: {error}"),
                }
            })?;
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
