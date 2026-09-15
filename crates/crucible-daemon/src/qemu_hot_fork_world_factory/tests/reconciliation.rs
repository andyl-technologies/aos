//! Whole-world factory and durable reconciliation regressions.

use super::*;

pub(super) fn factory(
    source_world: ProductionVmHotForkSourceWorld,
    lineage: &CampaignLineage,
    run_state_root: PathBuf,
    observations: ScriptedWorldObservations,
) -> QemuProductionHotForkWorldLifecycleFactory<
    QemuSingleHotForkSourceWorldProvider,
    ScriptedWorldGuardFactory,
> {
    let key = QemuHotForkSourceWorldKey::new(
        lineage.id().expect("lineage id"),
        source_world.continuation().configuration().def.id(),
        source_world.continuation().configuration().id(),
        ExecutorCompatibilityProfile::from_lineage(lineage),
    );
    let mut shutdown_policy = QemuShutdownPolicy::fast_test();
    shutdown_policy.sigterm_wait = Duration::from_secs(2);
    shutdown_policy.sigkill_wait = Duration::from_secs(1);
    shutdown_policy.reap_wait = Duration::from_secs(1);

    QemuProductionHotForkWorldLifecycleFactory::new(
        QemuSingleHotForkSourceWorldProvider::new(key, source_world),
        ScriptedWorldGuardFactory { observations },
        run_state_root,
        shutdown_policy,
        QemuAsyncDriverPolicy::fast_test(),
    )
}

pub(super) fn repository_execution_fixture() -> (
    Arc<CampaignRepository>,
    CampaignExecutorStore,
    CampaignLineage,
    crucible_campaign::AttemptId,
    crate::PreparedSemanticAttemptResult,
    ScenarioDefForm,
) {
    let repository = Arc::new(CampaignRepository::new(
        Arc::new(MemoryBlobBackend::new(
            "hot-world-publication",
            64 * 1024 * 1024,
        )),
        Arc::new(MemoryRefBackend::new()),
    ));
    let scenario = guest_selectable_scenario();
    let scenario_artifact =
        encode_crucible_scenario_artifact(&scenario).expect("encode scenario artifact");
    let scenario_content = repository
        .publish_scenario_artifact(
            scenario_artifact.scenario(),
            scenario_artifact.payload_schema(),
            scenario_artifact.payload().to_vec(),
        )
        .expect("publish scenario artifact");
    assert_eq!(
        scenario_content,
        scenario_artifact.id().expect("scenario artifact id")
    );

    let configuration = Configuration::genesis(scenario.scenario_def());
    let configuration_artifact =
        encode_crucible_configuration_artifact(&scenario_artifact, &configuration.schedule)
            .expect("encode configuration artifact");
    let configuration_content = repository
        .publish_configuration_artifact(
            configuration_artifact.scenario(),
            configuration_artifact.scenario_artifact(),
            configuration_artifact.configuration(),
            configuration_artifact.payload_schema(),
            configuration_artifact.payload().to_vec(),
        )
        .expect("publish configuration artifact");
    assert_eq!(
        configuration_content,
        configuration_artifact
            .id()
            .expect("configuration artifact id")
    );

    let lineage = CampaignLineage::new(
        scenario_artifact.scenario(),
        scenario_content,
        configuration_artifact.configuration(),
        configuration_content,
        "crucible-test",
        "qemu-test",
        BTreeMap::from([(String::from("control"), 1)]),
        scenario_artifact.payload_schema(),
        1,
    )
    .expect("campaign lineage");
    let widening = ProgressiveWideningPolicy::new(
        ExactRational::new(1, 1).expect("widening numerator"),
        ExactRational::new(1, 2).expect("widening exponent"),
        1,
        100,
        1,
    )
    .expect("widening policy");
    let policy = CampaignPolicy::new(
        CampaignPolicy::identity(
            scenario_artifact.scenario(),
            CampaignSeed::from_bytes([0x71; 32]),
            CampaignMode::Strict,
            ExplorerPolicy::TreeSearch {
                widening: Some(widening),
                puct: PuctPolicy::new(1_000_000, 1, 0),
            },
        ),
        CampaignPolicy::rules(
            BTreeMap::new(),
            BTreeMap::new(),
            BTreeMap::new(),
            BTreeSet::new(),
            FairnessPolicy::new(0, 0).expect("fairness policy"),
            RetentionPolicy::new(true, 1, true, true),
            true,
        ),
    )
    .expect("campaign policy");
    let created = repository
        .create("hot-world-publication", &lineage, &policy, &BTreeMap::new())
        .expect("create campaign");
    repository
        .apply_control(
            "hot-world-publication",
            &ControlRequest {
                command: CampaignCommandId::from_hash(CampaignHash::derive(
                    "crucible.test.hot-world-publication.budget.v1",
                    b"budget",
                )),
                expected_snapshot: created.snapshot_id(),
                action: CampaignControlAction::GrantBudget(
                    BudgetGrant::new(0, 1).expect("attempt budget"),
                ),
            },
        )
        .expect("fund campaign");
    let funded = repository
        .head("hot-world-publication")
        .expect("funded head");
    repository
        .apply_control(
            "hot-world-publication",
            &ControlRequest {
                command: CampaignCommandId::from_hash(CampaignHash::derive(
                    "crucible.test.hot-world-publication.resume.v1",
                    b"resume",
                )),
                expected_snapshot: funded.snapshot_id(),
                action: CampaignControlAction::Resume,
            },
        )
        .expect("resume campaign");
    let attempt_id = repository
        .admit_initial_discovery_if_ready("hot-world-publication")
        .expect("admit discovery")
        .expect("initial discovery attempt");
    let attempt = repository.load_attempt(attempt_id).expect("load attempt");

    let publication = crate::evaluate_crucible_measurement_publication(
        scenario_artifact.scenario(),
        configuration_artifact.configuration(),
        scenario.measurements(),
        Vec::new(),
        MeasurementTerminalState {
            scenario_ready_at: None,
            at: crucible::VirtualTime { ticks: 0 },
            node_icounts: BTreeMap::new(),
            scheduler_quiescent: true,
        },
        crate::MAX_CRUCIBLE_MEASUREMENT_REPLAY_EVIDENCE_BYTES,
    )
    .expect("evaluate fixture measurement evidence");
    let (measurement_evidence, _, measurements) = publication.into_parts();
    let properties = PropertyVerdictSet::new(BTreeMap::new()).expect("properties");
    let coverage =
        CoverageProjection::new(BTreeSet::new(), BTreeSet::new()).expect("coverage projection");
    let observation = Observation::new(
        attempt_id,
        Observation::outcome(
            configuration_artifact.configuration(),
            configuration_content,
            attempt.path(),
            StopOutcome::TerminalSuccess,
            measurements.id().expect("measurement set id"),
            properties.id().expect("property verdict set id"),
            coverage.id().expect("coverage projection id"),
        ),
        BTreeSet::new(),
    )
    .expect("observation");
    let candidate = ObservationCandidate::new(
        configuration_artifact,
        measurements,
        properties,
        coverage,
        Vec::new(),
        observation,
    )
    .expect("observation candidate");
    let store = CampaignExecutorStore::new(Arc::clone(&repository));

    let result =
        crate::PreparedSemanticAttemptResult::new(candidate, vec![measurement_evidence], None)
            .expect("prepare fixture semantic result");

    (repository, store, lineage, attempt_id, result, scenario)
}

pub(super) fn reconcile_canceled_world(
    lifecycle: &mut QemuProductionHotForkWorldLifecycle<ScriptedWorldGuard>,
) {
    let mut reconciled = false;
    for _ in 0..64 {
        if lifecycle
            .reconcile_execution_disposition(AttemptExecutionDisposition::Canceled)
            .expect("reconcile world")
            == AttemptExecutionReconciliationStep::Complete
        {
            reconciled = true;
            break;
        }
    }
    assert!(reconciled);
}

#[path = "reconciliation/lifecycle.rs"]
mod lifecycle;
#[path = "reconciliation/publication.rs"]
mod publication;
