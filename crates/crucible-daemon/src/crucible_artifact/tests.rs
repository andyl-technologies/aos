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
    CampaignCommandId, CampaignControlAction, CampaignLineage, CampaignMode, CampaignName,
    CampaignPolicy, CampaignRepository, CampaignSeed, ChoiceClassContext, ChoiceCoordinate,
    ChoiceDiscovery, ChoiceDomain, ChoiceOpportunity, ChoiceSource, ChoiceValue, ControlRequest,
    CoverageProjection, DaemonEpoch, DiscreteAlternative, DiscreteDomain, ExecutionRetentionIntent,
    ExecutorService, ExplorerPolicy, FairnessPolicy, FindingCandidateBundleId, FindingKind,
    FindingTarget, MeasurementSet, Observation, ObservationCandidate, ProgressiveWideningPolicy,
    PropertyVerdictSet, PuctPolicy, RetentionPolicy, SelectableDeclaration, Selection,
    SelectionOrigin, StopCondition, StopOutcome, SubmitAttemptDisposition, SubmitAttemptRequest,
};
use crucible_cas::content_store::{
    ContentId, DirectoryBlobBackend, MemoryBlobBackend, MemoryRefBackend, ObjectKind,
};

use super::*;
use crate::{
    AssignmentLedger, AttemptExecutionKey, AttemptExecutionProduct, AttemptResultStageOutcome,
    AttemptRuntimeState, AttemptWorkResult, AttemptWorkerReconcileOutcome,
    CompletedFindingCandidate, CompletionOutcome, CrucibleMeasurementPublication,
    CrucibleMeasurementReplayEvidence, ExactCheckpointStore, ExecutorCapacity, LocalExecutorError,
    LocalExecutorSupervisor, MAX_CRUCIBLE_MEASUREMENT_REPLAY_EVIDENCE_BYTES,
    MemoryAssignmentLedger, PreparedAttemptWorkResult, evaluate_crucible_measurement_publication,
    incorporate_and_acknowledge_finding_candidate, prepare_attempt_result,
    publish_prepared_attempt_result, reconcile_published_attempt_result,
    stage_prepared_attempt_result,
};

fn minimize_signature_preserving_finding<F>(
    finding: &FindingReproductionArtifact,
    signature: &FindingSignature,
    seed: crucible::Seed,
    pass: FindingReplayPass,
    transcript: &mut CrucibleFindingReplayTranscript,
    mut signature_oracle: F,
) -> Result<MinimizationRun, CrucibleArtifactError>
where
    F: FnMut(&FindingReproductionArtifact) -> Result<CrucibleFindingReplayEvidence, EngineError>,
{
    minimize_signature_preserving_finding_with_outcomes(
        finding,
        signature,
        seed,
        pass,
        transcript,
        |candidate| {
            signature_oracle(candidate)
                .map(|evidence| AutomaticFindingReplayOutcome::observed(evidence, Vec::new()))
        },
    )
}

fn prepare_signature_preserving_minimized_finding_candidate(
    signature: FindingSignature,
    observation: ObservationId,
    finding: &FindingReproductionArtifact,
    exact_pins: FindingExactPins,
    seed: crucible::Seed,
    transcript: CrucibleFindingReplayTranscript,
) -> Result<PreparedCrucibleFindingCandidate, CrucibleArtifactError> {
    prepare_signature_preserving_minimized_finding_candidate_with_retention(
        signature,
        observation,
        finding,
        exact_pins,
        test_disabled_finding_exact_retention()?,
        seed,
        transcript,
    )
}

impl CrucibleCampaignArtifactStore {
    fn publish_signature_preserving_minimized_finding_candidate<F>(
        &self,
        signature: FindingSignature,
        observation: ObservationId,
        finding: &FindingReproductionArtifact,
        exact_pins: FindingExactPins,
        seed: crucible::Seed,
        mut signature_oracle: F,
    ) -> Result<FindingCandidateBundleId, CrucibleArtifactError>
    where
        F: FnMut(
            &FindingReproductionArtifact,
        ) -> Result<CrucibleFindingReplayEvidence, EngineError>,
    {
        let mut transcript = CrucibleFindingReplayTranscript::new();
        minimize_signature_preserving_finding(
            finding,
            &signature,
            seed,
            FindingReplayPass::Minimization,
            &mut transcript,
            &mut signature_oracle,
        )?;
        minimize_signature_preserving_finding(
            finding,
            &signature,
            seed,
            FindingReplayPass::Verification,
            &mut transcript,
            &mut signature_oracle,
        )?;
        let prepared = prepare_signature_preserving_minimized_finding_candidate(
            signature,
            observation,
            finding,
            exact_pins,
            seed,
            transcript,
        )?;
        prepared.publish(self)
    }
}

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
        Observation::outcome(
            retained.child(),
            retained.child_content(),
            retained.path(),
            retained.stop().clone(),
            measurements.id().expect("replacement measurement ID"),
            retained.properties(),
            retained.coverage(),
        ),
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
    let retained = template.evaluation();
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
        candidate_semantics: crucible::model::BindingSearchCandidateSemantics::Outcome,
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
        MeasurementSet::from_evaluation(
            crucible_campaign::CampaignHash::derive(
                "crucible.test.measurement-definitions.v1",
                b"finding replay",
            ),
            1,
            crucible_campaign::CampaignHash::derive(
                "crucible.test.measurement-evaluation.v1",
                b"finding replay",
            ),
            b"finding replay".to_vec(),
            BTreeSet::new(),
        )
        .expect("empty replay measurements"),
        PropertyVerdictSet::new(BTreeMap::new()).expect("empty replay properties"),
        CoverageProjection::new(BTreeSet::new(), BTreeSet::new()).expect("empty replay coverage"),
        Vec::new(),
        Vec::new(),
    )
    .expect("typed replay evidence")
}

mod configuration;
mod finding;
mod publication;
