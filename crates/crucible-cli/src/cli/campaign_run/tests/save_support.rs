//! Builds authenticated campaign save and resume fixtures.

use super::*;

pub(super) struct CampaignSaveCapture {
    pub(super) temporary: TempDir,
    pub(super) output: PathBuf,
    pub(super) cli: Cli,
    pub(super) save_plan: SaveInvocationPlan,
    pub(super) campaign: GuardedDefaultCampaignRun,
}

pub(super) fn capture_campaign_save(
    boundary_arguments: &[&str],
    stop: StopCondition,
) -> CampaignSaveCapture {
    let temporary = TempDir::new().or_panic("temporary save workspace");
    let artifact_directory = temporary.path().join("artifacts");
    let output = temporary.path().join("campaign.crucible-savepoint");
    let scenario = match &stop {
        StopCondition::Observation(ObservationCondition::AssertionViolationTransition(
            assertion,
        )) => campaign_portable_save_scenario(&temporary, false, Some(assertion)),
        _ if matches!(
            &stop,
            StopCondition::NamedBoundary(_)
                | StopCondition::Observation(ObservationCondition::SchedulerQuiescent)
        ) =>
        {
            campaign_portable_save_scenario(&temporary, false, None)
        }
        _ => String::from("builtin:happy-path.scn"),
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
    let mut save_plan = plan_save_invocation(args, temporary.path(), &artifact_directory)
        .or_panic("campaign save plan");
    let checkpoint_fixture = crucible_api::build_exact_ram_production_checkpoint_codec_fixture(
        &temporary.path().join("request-checkpoint-fixture"),
    )
    .or_panic("authenticated campaign request fixture");
    save_plan.run_plan.scenario = save_plan
        .run_plan
        .scenario
        .with_form(checkpoint_fixture.source().clone());
    let resources = AttemptResourceLimits::new(1, 256 * 1024 * 1024, 1024 * 1024, 16)
        .or_panic("campaign fixture resources");
    let exact_root = temporary.path().join("transient-exact");
    let exact_backend: Arc<dyn ImmutableBlobBackend> = Arc::new(DirectoryBlobBackend::new(
        "guarded-campaign-save-reader-test",
        exact_root.clone(),
    ));
    let checkpoints = Arc::new(
        ExactCheckpointStore::new(exact_backend, resources.maximum_disk_bytes())
            .or_panic("exact checkpoint store"),
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
    .or_panic("fixture host configuration");
    let request = GuardedDefaultCampaignRunRequest::new(
        scenario,
        seed,
        "campaign-save-reader-test-engine",
        "campaign-save-reader-test-qemu",
        ProductionVmLifecycleConfig::new(
            "qemu",
            "plugin",
            "kernel",
            "root",
            temporary.path().join("run-state"),
        ),
        host,
        resources,
    )
    .with_discovery_stop(stop)
    .with_reached_stop_savepoint_capture(checkpoints);
    let campaign = run_guarded_default_campaign_test_fixture_with_choice_offer(request, false)
        .or_panic("campaign fixture should capture an authenticated savepoint");
    std::fs::remove_dir_all(&exact_root)
        .or_panic("remove transient physical checkpoint before durable readers run");

    CampaignSaveCapture {
        temporary,
        output,
        cli,
        save_plan,
        campaign,
    }
}

pub(super) fn handle_with_observation_proof(handle: &str, proof: &ObservationStopProof) -> String {
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

pub(super) fn assert_fixed_typed_choice_replay_closure(stop: &StopCondition) {
    let temporary = TempDir::new().or_panic("typed replay closure workspace");
    let scenario = fixed_checkpoint_scenario_form();
    let resources = AttemptResourceLimits::new(1, 256 * 1024 * 1024, 1024 * 1024, 16)
        .or_panic("typed replay closure resources");
    let host = LinuxQemuAttemptHostConfig::new(
        "/sys/fs/cgroup/crucible-campaign-typed-replay-test",
        "/tmp/crucible-campaign-typed-replay-test",
        "campaign-typed-replay-test",
        1,
        1,
        65_527,
        65_527,
        16,
        1_024,
        Duration::from_secs(1),
    )
    .or_panic("typed replay closure host configuration");
    let request = GuardedDefaultCampaignRunRequest::new(
        scenario.clone(),
        scenario.seed(),
        "campaign-typed-replay-test-engine",
        "campaign-typed-replay-test-qemu",
        ProductionVmLifecycleConfig::new(
            "qemu",
            "plugin",
            "kernel",
            "root",
            temporary.path().join("run-state"),
        ),
        host,
        resources,
    )
    .with_discovery_stop(stop.clone());
    let campaign = run_guarded_default_campaign_test_fixture_with_choice_offer(request, true)
        .or_panic("typed choice campaign fixture");
    let schedule = &campaign.terminal_configuration().schedule;

    assert_eq!(schedule.len(), 1);
    assert!(matches!(
        schedule.decisions(),
        [crucible::Decision::Selection(_)]
    ));
    campaign
        .replay_closure()
        .validate_for_schedule(&scenario, schedule)
        .or_panic("typed campaign replay closure authenticates its exact selection");
}

pub(super) fn handle_with_observation_claim(
    handle: &str,
    proof: &ObservationStopProof,
    evidence: &crucible_daemon::CrucibleMeasurementReplayEvidence,
) -> String {
    let proof_bytes = proof.canonical_bytes();
    let evidence_bytes = evidence
        .canonical_bytes()
        .or_panic("canonical forged observation evidence");
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
    .or_panic("structurally valid forged observation proof")
}

pub(super) fn recomputed_observation_proof_forgeries(
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
    .or_panic("shifted quantum boundary remains structurally valid");
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
        .or_panic("wrong-state witness remains structurally valid");
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
            .or_panic("property fixture emits a second event in the matching quantum");
        let wrong_witness = AssertionViolationWitness::new(
            witness.assertion(),
            other_entry.sequence(),
            CampaignHash::from_bytes(other_entry.content_hash().bytes),
        )
        .or_panic("wrong event witness remains structurally valid");
        forgeries.push((
            "assertion-witness",
            rebuilt_observation_proof(source, boundary, event_log, Some(wrong_witness)),
        ));
    }

    forgeries
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
    .or_panic("campaign marker save world");
    let declaration = SelectableDeclaration::new(
        "campaign.save.fixture-choice",
        ChoiceSource::Guest {
            node: node.name.clone(),
            protocol_version: u32::from(crucible_protocol::SELECTABLE_PROTOCOL_VERSION),
        },
        ChoiceDomain::Boolean(BooleanDomain::new(1).or_panic("boolean domain")),
        ChoiceValue::Boolean(false),
        ChoiceClassContext::new(BTreeSet::new()).or_panic("choice class"),
        BTreeSet::from([String::from("campaign-save")]),
        true,
    )
    .or_panic("campaign marker save selectable declaration");
    let selectables = crucible::ScenarioSelectables::new(
        &world,
        crucible::ScenarioSelectableLimits::new(4, 8, 16, 32)
            .or_panic("campaign marker selectable limits"),
        vec![declaration],
    )
    .or_panic("campaign marker save selectables");
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
        .or_panic("campaign portable save properties");
    let mut form = crucible::ScenarioDefForm::from_components(
        &world,
        &crucible::Plan::empty(),
        &properties,
        crucible::Seed::from_u64(8_004),
    )
    .or_panic("campaign portable save scenario");
    if with_selection {
        form = form
            .with_selectables(selectables)
            .or_panic("attach campaign portable save selectables");
    }
    let path = temporary.path().join("campaign-portable-save.toml");
    std::fs::write(
        &path,
        form.to_canonical_toml()
            .or_panic("canonical campaign portable save scenario"),
    )
    .or_panic("write campaign portable save scenario");
    path.display().to_string()
}

pub(super) fn resume_plan_and_evidence_from_cli(
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
    let plan = plan_resume_invocation(args, store).or_panic("resume plan");
    let evidence =
        resume_handle_evidence(&plan).or_panic("unchanged resume reader accepts campaign save");
    (plan, evidence)
}
