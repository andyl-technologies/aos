//! Crucible campaign artifact encoding, verification, and publication tests.

use std::collections::BTreeMap;

use std::collections::BTreeSet;
use std::sync::Arc;

use crucible::model::{MeasurementDefinitions, MeasurementTerminalState};
use crucible::{
    ContentHash, Decision, DeliveryOrderDecision, ExecutionFingerprint, FindingDiscoveryPath,
    FingerprintSample, SelectionDecision, VirtualTime,
};
use crucible_campaign::{
    AlternativeId, AssignmentId, AttemptResourceLimits, BooleanDomain, BudgetGrant,
    CampaignCommandId, CampaignControlAction, CampaignExecutorStore, CampaignLineage, CampaignMode,
    CampaignName, CampaignPolicy, CampaignRepository, CampaignSeed, ChoiceClassContext,
    ChoiceCoordinate, ChoiceDiscovery, ChoiceDomain, ChoiceOpportunity, ChoiceSource, ChoiceValue,
    ControlRequest, CoverageProjection, DaemonEpoch, DiscreteAlternative, DiscreteDomain,
    ExactCheckpointId, ExecutionRetentionIntent, ExecutorService, ExplorerPolicy, FairnessPolicy,
    FindingCandidateBundle, FindingCandidateBundleId, FindingExactPins, FindingExactRetention,
    FindingExactRetentionCandidate, FindingExactRetentionDisposition,
    FindingExactRetentionEvidence, FindingKind, FindingReplayCaptureIncomplete, FindingTarget,
    MeasurementSet, Observation, ObservationCandidate, ProgressiveWideningPolicy,
    PropertyVerdictSet, PuctPolicy, RetentionPolicy, SelectableDeclaration, Selection,
    SelectionOrigin, StopCondition, StopOutcome, SubmitAttemptDisposition, SubmitAttemptRequest,
};
use crucible_cas::content_store::{
    ContentId, DirectoryBlobBackend, MemoryBlobBackend, MemoryRefBackend, ObjectKind,
};

use super::*;
use crate::{
    AllowAllAttemptAdmission, AssignmentLedger, AttemptExecutionKey, AttemptExecutionProduct,
    AttemptResultStageOutcome, AttemptRuntimeState, AttemptWorkResult,
    AttemptWorkerReconcileOutcome, CompletedFindingCandidate, CompletionOutcome,
    CrucibleMeasurementPublication, CrucibleMeasurementReplayEvidence, ExactCheckpointStore,
    ExecutorCapacity, LocalExecutorError, LocalExecutorSupervisor,
    MAX_CRUCIBLE_MEASUREMENT_REPLAY_EVIDENCE_BYTES, MemoryAssignmentLedger,
    PreparedAttemptWorkResult, evaluate_crucible_measurement_publication,
    incorporate_and_acknowledge_finding_candidate, prepare_attempt_result,
    publish_prepared_attempt_result, reconcile_published_attempt_result,
    stage_prepared_attempt_result,
};

fn empty_measurement_publication(
    scenario: ScenarioDefId,
    configuration: ConfigurationId,
) -> CrucibleMeasurementPublication {
    evaluate_crucible_measurement_publication(
        scenario,
        configuration,
        &MeasurementDefinitions::empty(),
        Vec::new(),
        MeasurementTerminalState {
            scenario_ready_at: None,
            at: VirtualTime { ticks: 0 },
            node_icounts: BTreeMap::new(),
            scheduler_quiescent: true,
        },
        MAX_CRUCIBLE_MEASUREMENT_REPLAY_EVIDENCE_BYTES,
    )
    .expect("empty measurement publication")
}

fn observation_with_measurements(
    candidate: &ObservationCandidate,
    measurements: MeasurementSet,
) -> ObservationCandidate {
    let retained = candidate.observation();
    assert!(retained.produced_selections().is_empty());
    let observation = Observation::new(
        retained.attempt(),
        retained.child(),
        retained.child_content(),
        retained.path(),
        retained.stop().clone(),
        measurements.id().expect("replacement measurement ID"),
        retained.properties(),
        retained.coverage(),
        retained.discovered_choices().clone(),
    )
    .expect("observation with replacement measurements");
    ObservationCandidate::new(
        candidate.child().clone(),
        measurements,
        candidate.properties().clone(),
        candidate.coverage().clone(),
        candidate.discovered_choices().to_vec(),
        observation,
    )
    .expect("candidate with replacement measurements")
}

fn measurement_with_evidence(
    template: &MeasurementSet,
    evidence: &CrucibleMeasurementReplayEvidence,
    definitions: CampaignHash,
) -> MeasurementSet {
    let retained = template.evaluation().expect("measurement evaluation");
    MeasurementSet::from_evaluation(
        definitions,
        retained.payload_schema(),
        retained.evaluation(),
        retained.payload().to_vec(),
        BTreeSet::from([evidence.id().expect("measurement evidence ID")]),
    )
    .expect("measurement with replacement evidence")
}

fn selection_decision(scenario: ScenarioDefId) -> Decision {
    let domain = ChoiceDomain::Boolean(BooleanDomain::new(1).expect("Boolean domain"));
    let declaration = SelectableDeclaration::new(
        "product.test.daemon-selection",
        ChoiceSource::Scheduler {
            producer: String::from("daemon-test"),
        },
        domain.clone(),
        ChoiceValue::Boolean(false),
        ChoiceClassContext::new(BTreeSet::new()).expect("class context"),
        BTreeSet::new(),
        true,
    )
    .expect("selectable declaration");
    let opportunity = ChoiceOpportunity::new(
        scenario,
        &declaration,
        &domain,
        ChoiceCoordinate {
            scheduler: CampaignHash::derive("test", b"daemon-scheduler"),
            producer: CampaignHash::derive("test", b"daemon-producer"),
        },
        "daemon-selection",
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
    Decision::Selection(SelectionDecision::new(&selection))
}

fn signal_fault_selectable(
    parent: &Configuration,
    label: &[u8],
    frontier: u64,
) -> SignalFaultSelectable {
    let choice = crucible::model::BindingSearchChoice {
        id: crucible::model::SearchChoiceId::from_content_hash(ContentHash::from_bytes(label)),
        candidates_digest: ContentHash::from_canonical_material(
            "crucible.test.artifact-signal-candidates",
            &label
                .iter()
                .map(|byte| format!("{byte:02x}"))
                .collect::<String>(),
        ),
        candidate_count: 2,
        selected_index: None,
        overridden: false,
    };
    SignalFaultSelectable::from_frontier(&crucible::SearchRuntimeFrontier {
        configuration: parent.clone(),
        at: VirtualTime { ticks: frontier },
        choices: crucible::SearchFrontierChoices::from_decisions(
            choice
                .override_decisions(parent.id())
                .into_iter()
                .map(Decision::Override),
        ),
    })
    .expect("signal-fault selectable fixture")
}

fn publish_signal_selection(
    repository: &CampaignRepository,
    selectable: &SignalFaultSelectable,
    selection: &Selection,
) {
    repository
        .publish_choice_domain(selectable.domain())
        .expect("publish signal-fault domain");
    repository
        .publish_selectable(selectable.declaration())
        .expect("publish signal-fault declaration");
    repository
        .publish_choice_opportunity(selectable.opportunity())
        .expect("publish signal-fault opportunity");
    repository
        .publish_selection(selection)
        .expect("publish signal-fault selection");
}

fn replay_evidence(
    candidate: &FindingReproductionArtifact,
    signature: FindingSignature,
) -> CrucibleFindingReplayEvidence {
    let scenario = encode_crucible_scenario_artifact(candidate.artifact.scenario_form())
        .expect("encode replay scenario");
    let configuration =
        encode_crucible_configuration_artifact(&scenario, candidate.artifact.schedule())
            .expect("encode replay configuration");
    CrucibleFindingReplayEvidence::new(
        Some(signature),
        configuration,
        MeasurementSet::new(BTreeMap::new()).expect("empty replay measurements"),
        PropertyVerdictSet::new(BTreeMap::new()).expect("empty replay properties"),
        CoverageProjection::new(BTreeSet::new(), BTreeSet::new()).expect("empty replay coverage"),
        Vec::new(),
        Vec::new(),
    )
    .expect("typed replay evidence")
}

pub(crate) struct PreparedFindingRecoveryFixture {
    pub(crate) lineage: CampaignLineage,
    pub(crate) attempt: crucible_campaign::AttemptId,
    pub(crate) observation: ObservationCandidate,
    pub(crate) result: PreparedSemanticAttemptResult,
    pub(crate) replay_capture_child: ContentId,
}

pub(crate) fn prepared_finding_recovery_fixture(
    repository: &Arc<CampaignRepository>,
    campaign: &str,
    checkpoint: ExactCheckpointId,
) -> PreparedFindingRecoveryFixture {
    let scenario = crucible::happy_path_scenario()
        .expect("recovery scenario")
        .scenario;
    let configuration = crucible::Configuration {
        def: scenario.scenario_def(),
        schedule: crucible::Schedule::empty(),
    };
    let scenario_record = encode_crucible_scenario_artifact(&scenario).expect("scenario record");
    let configuration_record =
        encode_crucible_configuration_artifact(&scenario_record, &configuration.schedule)
            .expect("configuration record");
    repository
        .publish_scenario_artifact(
            scenario_record.scenario(),
            scenario_record.payload_schema(),
            scenario_record.payload().to_vec(),
        )
        .expect("publish recovery scenario");
    repository
        .publish_configuration_artifact(
            configuration_record.scenario(),
            configuration_record.scenario_artifact(),
            configuration_record.configuration(),
            configuration_record.payload_schema(),
            configuration_record.payload().to_vec(),
        )
        .expect("publish recovery configuration");
    let lineage = CampaignLineage::new(
        scenario_record.scenario(),
        scenario_record.id().expect("scenario ID"),
        configuration_record.configuration(),
        configuration_record.id().expect("configuration ID"),
        "crucible-test",
        "qemu-test",
        BTreeMap::from([(String::from("control"), 1)]),
        scenario_record.payload_schema(),
        1,
    )
    .expect("recovery lineage");
    let widening = ProgressiveWideningPolicy::new(
        crucible_campaign::ExactRational::new(1, 1).expect("widening coefficient"),
        crucible_campaign::ExactRational::new(1, 2).expect("widening exponent"),
        1,
        100,
        1,
    )
    .expect("widening policy");
    let policy = CampaignPolicy::new(
        lineage.scenario(),
        CampaignSeed::from_bytes([7; 32]),
        CampaignMode::Strict,
        ExplorerPolicy::TreeSearch {
            widening: Some(widening),
            puct: PuctPolicy::new(1_000_000, 1, 0),
        },
        BTreeMap::new(),
        BTreeMap::new(),
        BTreeMap::new(),
        BTreeSet::new(),
        FairnessPolicy::new(0, 0).expect("fairness policy"),
        RetentionPolicy::new(true, 1, true, true),
        true,
    )
    .expect("recovery policy");
    let created = repository
        .create(campaign, &lineage, &policy, &BTreeMap::new())
        .expect("create recovery campaign");
    let funded = repository
        .apply_control(
            campaign,
            &ControlRequest {
                command: CampaignCommandId::from_hash(CampaignHash::derive(
                    "crucible.test.prepared-recovery.command.v1",
                    b"fund",
                )),
                expected_snapshot: created.snapshot_id(),
                action: CampaignControlAction::GrantBudget(
                    BudgetGrant::new(0, 1).expect("attempt grant"),
                ),
            },
        )
        .expect("fund recovery campaign");
    repository
        .apply_control(
            campaign,
            &ControlRequest {
                command: CampaignCommandId::from_hash(CampaignHash::derive(
                    "crucible.test.prepared-recovery.command.v1",
                    b"resume",
                )),
                expected_snapshot: funded.new_snapshot,
                action: CampaignControlAction::Resume,
            },
        )
        .expect("resume recovery campaign");
    let attempt = repository
        .admit_initial_discovery_if_ready(campaign)
        .expect("admit recovery attempt")
        .expect("recovery attempt");
    let attempt_record = repository
        .load_attempt(attempt)
        .expect("load recovery attempt");
    let measurements = MeasurementSet::new(BTreeMap::new()).expect("measurements");
    let properties = PropertyVerdictSet::new(BTreeMap::new()).expect("properties");
    let coverage = CoverageProjection::new(BTreeSet::new(), BTreeSet::new()).expect("coverage");
    let observation = Observation::new(
        attempt,
        configuration_record.configuration(),
        configuration_record
            .id()
            .expect("observation configuration"),
        attempt_record.path(),
        StopOutcome::TerminalSuccess,
        measurements.id().expect("measurement ID"),
        properties.id().expect("property ID"),
        coverage.id().expect("coverage ID"),
        BTreeSet::new(),
    )
    .expect("recovery observation");
    let observation_candidate = ObservationCandidate::new(
        configuration_record.clone(),
        measurements,
        properties,
        coverage,
        Vec::new(),
        observation,
    )
    .expect("recovery observation candidate");
    let observation_id = observation_candidate
        .observation()
        .id()
        .expect("recovery observation ID");

    let fingerprint = ContentHash::from_bytes(b"complete-recovery-finding");
    let finding = FindingReproductionArtifact::capture(
        FindingDiscoveryPath::StateSpaceSearch,
        fingerprint,
        &scenario,
        &configuration,
    )
    .expect("capture recovery finding");
    let signature = FindingSignature::new(
        FindingKind::Divergence,
        CampaignHash::from_bytes(fingerprint.bytes),
        None,
        String::from("qemu.complete-recovery-divergence"),
        Some(FindingTarget::Configuration(
            configuration_record.id().expect("finding target"),
        )),
        BTreeSet::new(),
    )
    .expect("recovery signature");
    let seed = crucible::Seed::from_u64(0xcafe);
    let mut transcript = CrucibleFindingReplayTranscript::new();
    for pass in [
        FindingReplayPass::Minimization,
        FindingReplayPass::Verification,
    ] {
        minimize_signature_preserving_finding(
            &finding,
            &signature,
            seed,
            pass,
            &mut transcript,
            |candidate| Ok(replay_evidence(candidate, signature.clone())),
        )
        .expect("recovery finding replay pass");
    }
    let mut finding = prepare_signature_preserving_minimized_finding_candidate(
        signature,
        observation_id,
        &finding,
        FindingExactPins::default(),
        seed,
        transcript,
    )
    .expect("prepare recovery finding");

    let replay_capture_bytes = b"complete V5 recovery replay capture".to_vec();
    let replay_capture_child = ContentId::for_bytes(ObjectKind::Trace, 1, &replay_capture_bytes);
    let incomplete = || {
        crate::FindingReplayCaptureInput::Incomplete(
            FindingReplayCaptureIncomplete::MissingTerminalFingerprints,
        )
    };
    let replay_captures = crate::FindingReplayCaptureStore::prepare_set([
        crate::FindingReplayCaptureInput::Complete {
            content_hash: ContentHash::from_bytes(&replay_capture_bytes),
            bytes: replay_capture_bytes,
        },
        incomplete(),
        incomplete(),
        incomplete(),
    ])
    .expect("prepare recovery replay captures");
    let executor_store = CampaignExecutorStore::new(Arc::clone(repository));
    let publication_guard = executor_store
        .acquire_finding_replay_publication_guard()
        .expect("acquire recovery capture publication guard");
    crate::FindingReplayCaptureStore::publish_set(&publication_guard, &replay_captures)
        .expect("publish recovery replay captures");
    drop(publication_guard);

    let bundle = finding.bundle();
    finding.bundle = FindingCandidateBundle::new_with_replay_captures(
        bundle.observation(),
        bundle.signature().clone(),
        bundle.reproduction(),
        bundle.minimized(),
        bundle.signature_minimization().clone(),
        bundle.exact_pins().clone(),
        bundle.triage_evidence(),
        replay_captures.references(),
    )
    .expect("bind recovery replay captures");
    let mut result =
        PreparedSemanticAttemptResult::new(observation_candidate.clone(), Some(finding))
            .expect("prepare recovery semantic result");
    let exact_pins = FindingExactPins::new(
        BTreeSet::new(),
        BTreeSet::new(),
        BTreeSet::from([checkpoint]),
        BTreeSet::new(),
    )
    .expect("recovery exact pins");
    let source_snapshot = repository
        .head(campaign)
        .expect("recovery head")
        .snapshot_id();
    let basis = repository
        .attempt_retention_policy_basis_at(source_snapshot, attempt)
        .expect("recovery retention basis");
    let exact_retention = FindingExactRetention::new(
        basis.snapshot(),
        basis.policy(),
        basis.admission(),
        1,
        FindingExactRetentionDisposition::Complete,
    )
    .expect("complete recovery retention");
    let evidence = FindingExactRetentionEvidence::new(
        vec![FindingExactRetentionCandidate::new(checkpoint, 0)],
        checkpoint,
        0,
        None,
        exact_pins.clone(),
    )
    .expect("complete recovery evidence");
    let finding = result
        .prepare_bound_finding_exact_retention(exact_pins, exact_retention, Some(evidence))
        .expect("bind complete recovery retention");
    result.commit_bound_production_replay_finding(finding);

    PreparedFindingRecoveryFixture {
        lineage,
        attempt,
        observation: observation_candidate,
        result,
        replay_capture_child,
    }
}

mod configuration;
mod finding;
mod publication;
