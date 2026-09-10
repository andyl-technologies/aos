//! Authenticated campaign Finding fixture for executable triage acceptance.
//!
//! The fixture directory is self-contained:
//!
//! ```text
//! findings-v4.crucible-findings
//! findings-v4-proof-mutation.crucible-findings
//! findings-v4-payload-mutation.crucible-findings
//! store/
//! ```
//!
//! The command reports the paths and expected artifact identities in a
//! versioned object:
//!
//! ```json
//! {
//!   "schema": "crucible.cli.campaign-finding-triage-fixture.v1",
//!   "directory": "/tmp/fixture",
//!   "findings": "/tmp/fixture/findings-v4.crucible-findings",
//!   "store": "/tmp/fixture/store",
//!   "proof_mutation": "/tmp/fixture/findings-v4-proof-mutation.crucible-findings",
//!   "payload_mutation": "/tmp/fixture/findings-v4-payload-mutation.crucible-findings",
//!   "original_artifact": "<hex digest>",
//!   "minimized_artifact": "<hex digest>"
//! }
//! ```

use super::*;

use std::fmt;
use std::sync::Arc;

use crucible_campaign::{
    BudgetGrant, CampaignAuthorizationError, CampaignClient, CampaignCommandId,
    CampaignControlAction, CampaignHash, CampaignLineage, CampaignMode, CampaignName,
    CampaignPolicy, CampaignPrincipal, CampaignPrincipalAuthorizer, CampaignRepository,
    CampaignSeed, CampaignServiceOperation, ConfigurationId, ControlRequest, CoverageProjection,
    ExplorerPolicy, FairnessPolicy, FindingCandidateBundle, FindingExactPins, FindingKind,
    FindingMinimizationAttempt, FindingMinimizationEvidence, FindingSignature,
    FindingSignatureMinimizationEvidence, FindingTarget, FindingTriageEvidenceSet,
    FindingTriageReplayEvidence, MeasurementSet, Observation, PropertyEvidence, PropertyVerdict,
    PropertyVerdictSet, RepositoryCampaignService, RetentionPolicy, ScenarioDefId, StopOutcome,
};
use crucible_cas::content_store::{MemoryBlobBackend, MemoryRefBackend};

const FINDING_TRIAGE_FIXTURE_REPORT_SCHEMA: &str =
    "crucible.cli.campaign-finding-triage-fixture.v1";
const CAMPAIGN: &str = "finding-triage-fixture";
const PROPERTY: &str = "finding-triage-fixture-property";

#[derive(Serialize)]
pub(in crate::cli_campaign) struct FindingTriageFixtureReport {
    schema: &'static str,
    directory: PathBuf,
    findings: PathBuf,
    store: PathBuf,
    proof_mutation: PathBuf,
    payload_mutation: PathBuf,
    original_artifact: String,
    minimized_artifact: String,
}

struct PermitFindingExport;

impl CampaignPrincipalAuthorizer for PermitFindingExport {
    fn authorize(
        &self,
        _principal: &CampaignPrincipal,
        _operation: CampaignServiceOperation,
        _campaign: &CampaignName,
        _request_digest: CampaignHash,
    ) -> Result<(), CampaignAuthorizationError> {
        Ok(())
    }
}

pub(in crate::cli_campaign) fn generate_finding_triage_fixture(
    output: &Path,
) -> Result<FindingTriageFixtureReport, CliError> {
    let output = absolute_output_path(output)?;
    create_fixture_directory(&output)?;

    let native = build_native_finding_fixture()?;
    let campaign = start_fixture_campaign(&native.form)?;
    let published = publish_campaign_finding_fixture(&native, campaign)?;
    let captures = capture_campaign_finding_fixture(&published, native.report.clone())?;

    write_finding_triage_fixture(&output, &native, &captures)
}

struct NativeFindingFixture {
    form: crucible::ScenarioDefForm,
    configuration: crucible::Configuration,
    minimized_configuration: crucible::Configuration,
    model_finding: crucible::FindingReproductionArtifact,
    minimized_model_finding: crucible::FindingReproductionArtifact,
    report: TriageFindingEvidence,
    native_replay: crucible::FailureTriageReplayEvidence,
    minimized_native_replay: crucible::FailureTriageReplayEvidence,
    verification_selected_native_replay: crucible::FailureTriageReplayEvidence,
}

struct CampaignFixtureContext {
    repository: CampaignRepository,
    scenario: ScenarioDefId,
    scenario_artifact: crucible_campaign::ScenarioArtifactId,
    attempt: crucible_campaign::AttemptId,
    attempt_path: crucible_campaign::BranchPathId,
}

struct PublishedFindingFixture {
    repository: CampaignRepository,
    campaign: CampaignName,
    snapshot: crucible_campaign::CampaignSnapshotId,
    finding: crucible_campaign::FindingId,
}

struct FindingFixtureCaptures {
    evidence: CampaignTriageFindingEvidence,
    other_evidence: CampaignTriageFindingEvidence,
}

fn build_native_finding_fixture() -> Result<NativeFindingFixture, CliError> {
    let form = fixture_step("build scenario", crucible::happy_path_scenario())?.scenario;
    let configuration = crucible::Configuration {
        def: form.scenario_def(),
        schedule: crucible::Schedule::from_decisions(vec![crucible::Decision::RngDraw(
            crucible::RngDecision {
                stream: crucible::RngStreamId::from_name("finding-triage-fixture"),
                value: 1,
            },
        )]),
    };
    let minimized_configuration = crucible::Configuration::genesis(form.scenario_def());
    let fingerprint = crucible::ContentHash::from_bytes(b"finding-triage-fixture-fingerprint");
    let model_finding = fixture_step(
        "capture original finding",
        crucible::FindingReproductionArtifact::capture(
            crucible::FindingDiscoveryPath::StateSpaceSearch,
            fingerprint,
            &form,
            &configuration,
        ),
    )?;
    let minimized_model_finding = fixture_step(
        "capture minimized finding",
        crucible::FindingReproductionArtifact::capture(
            crucible::FindingDiscoveryPath::StateSpaceSearch,
            fingerprint,
            &form,
            &minimized_configuration,
        ),
    )?;
    let report = fixture_step(
        "build native property evidence",
        crate::cli_triage_debug::triage_property_evidence_for_violation(
            model_finding.clone(),
            crucible_model::HostAssertionViolation {
                assertion: crucible::AssertionId::from_name(PROPERTY),
                message: String::from("campaign fixture property violated"),
                quantifier: crucible::AssertionQuantifierKind::Always,
                event_kind: String::from("assertion_state_changed"),
                at_icount: Some(crucible::Icount { retired: 7 }),
                at_virtual_time: crucible::VirtualTime { ticks: 7 },
                node: None,
                detail: String::from("retained executable campaign fixture"),
                reproduction_artifact: model_finding.artifact.id(),
            },
        ),
    )?;

    let native_replay = native_replay_evidence(&report)?;
    let minimized_report = fixture_step(
        "build minimized native evidence",
        crate::cli_triage_debug::triage_evidence_for_finding(
            minimized_model_finding.clone(),
            &report,
        ),
    )?;
    let minimized_native_replay = native_replay_evidence(&minimized_report)?;
    let mut verification_failure = minimized_report.failure.clone();
    let crucible_model::FailureClusterReportFailure::Property(verification_property) =
        &mut verification_failure
    else {
        return Err(fixture_error(
            "fixture native evidence is not a property failure",
        ));
    };
    verification_property
        .violation
        .message
        .push_str(" during independent verification");
    let verification_selected_native_replay = fixture_step(
        "build verification replay evidence",
        crucible::FailureTriageReplayEvidence::new(
            minimized_report.finding.clone(),
            verification_failure,
            minimized_report.causal_entries.clone(),
            minimized_report.recorded_event_log.coverage_fingerprint(),
            minimized_report.recorded_event_frames.clone(),
        ),
    )?;
    if minimized_native_replay.signature() != verification_selected_native_replay.signature() {
        return Err(fixture_error(
            "fixture independent verification changed the native signature",
        ));
    }

    Ok(NativeFindingFixture {
        form,
        configuration,
        minimized_configuration,
        model_finding,
        minimized_model_finding,
        report,
        native_replay,
        minimized_native_replay,
        verification_selected_native_replay,
    })
}

fn start_fixture_campaign(
    form: &crucible::ScenarioDefForm,
) -> Result<CampaignFixtureContext, CliError> {
    let repository = CampaignRepository::new(
        Arc::new(MemoryBlobBackend::new(CAMPAIGN, u64::MAX)),
        Arc::new(MemoryRefBackend::new()),
    );
    let scenario =
        ScenarioDefId::from_hash(CampaignHash::from_bytes(form.scenario_def().id().bytes));
    let scenario_artifact = fixture_step(
        "publish scenario",
        repository.publish_scenario_artifact(scenario, 1, form.to_compact_binary()),
    )?;
    let genesis = ConfigurationId::from_hash(CampaignHash::derive(
        "finding-triage-fixture-configuration",
        b"genesis",
    ));
    let genesis_artifact = fixture_step(
        "publish genesis configuration",
        repository.publish_configuration_artifact(
            scenario,
            scenario_artifact,
            genesis,
            1,
            b"finding triage fixture genesis".to_vec(),
        ),
    )?;
    let lineage = fixture_step(
        "build lineage",
        CampaignLineage::new(
            scenario,
            scenario_artifact,
            genesis,
            genesis_artifact,
            "finding-triage-fixture-engine",
            "finding-triage-fixture-qemu",
            BTreeMap::from([(String::from("control"), 1)]),
            1,
            1,
        ),
    )?;
    let policy = fixture_step(
        "build policy",
        CampaignPolicy::new(
            scenario,
            CampaignSeed::from_bytes([0x47; 32]),
            CampaignMode::Strict,
            ExplorerPolicy::Exhaustive {
                maximum_cardinality: 1,
            },
            BTreeMap::new(),
            BTreeMap::new(),
            BTreeMap::new(),
            BTreeSet::new(),
            fixture_step("build fairness policy", FairnessPolicy::new(0, 0))?,
            RetentionPolicy::new(true, 1, true, true),
            true,
        ),
    )?;
    let created = fixture_step(
        "create campaign",
        repository.create(CAMPAIGN, &lineage, &policy, &BTreeMap::new()),
    )?;
    let resumed = fixture_step(
        "resume campaign",
        repository.apply_control(
            CAMPAIGN,
            &ControlRequest {
                command: CampaignCommandId::from_hash(CampaignHash::derive(
                    "finding-triage-fixture-command",
                    b"resume",
                )),
                expected_snapshot: created.snapshot_id(),
                action: CampaignControlAction::Resume,
            },
        ),
    )?;
    fixture_step(
        "fund campaign",
        repository.apply_control(
            CAMPAIGN,
            &ControlRequest {
                command: CampaignCommandId::from_hash(CampaignHash::derive(
                    "finding-triage-fixture-command",
                    b"fund",
                )),
                expected_snapshot: resumed.new_snapshot,
                action: CampaignControlAction::GrantBudget(fixture_step(
                    "build budget grant",
                    BudgetGrant::new(0, 1),
                )?),
            },
        ),
    )?;
    let attempt = fixture_step(
        "admit initial discovery",
        repository.admit_initial_discovery_if_ready(CAMPAIGN),
    )?
    .ok_or_else(|| fixture_error("fixture campaign did not admit its initial discovery"))?;
    let attempt_record = fixture_step("load attempt", repository.load_attempt(attempt))?;

    Ok(CampaignFixtureContext {
        repository,
        scenario,
        scenario_artifact,
        attempt,
        attempt_path: attempt_record.path(),
    })
}

fn publish_campaign_finding_fixture(
    native: &NativeFindingFixture,
    campaign: CampaignFixtureContext,
) -> Result<PublishedFindingFixture, CliError> {
    let repository = &campaign.repository;
    let scenario = campaign.scenario;
    let scenario_artifact = campaign.scenario_artifact;
    let attempt = campaign.attempt;
    let attempt_path = campaign.attempt_path;
    let configuration = &native.configuration;
    let minimized_configuration = &native.minimized_configuration;
    let model_finding = &native.model_finding;
    let minimized_model_finding = &native.minimized_model_finding;
    let native_replay = &native.native_replay;
    let minimized_native_replay = &native.minimized_native_replay;
    let verification_selected_native_replay = &native.verification_selected_native_replay;

    let child = ConfigurationId::from_hash(CampaignHash::from_bytes(configuration.id().bytes));
    let child_artifact = fixture_step(
        "publish child configuration",
        repository.publish_configuration_artifact(
            scenario,
            scenario_artifact,
            child,
            1,
            b"finding triage fixture child".to_vec(),
        ),
    )?;
    let minimized_child =
        ConfigurationId::from_hash(CampaignHash::from_bytes(minimized_configuration.id().bytes));
    let minimized_child_artifact = fixture_step(
        "publish minimized configuration",
        repository.publish_configuration_artifact(
            scenario,
            scenario_artifact,
            minimized_child,
            1,
            b"finding triage fixture minimized child".to_vec(),
        ),
    )?;
    let measurement_set = fixture_step("build measurements", MeasurementSet::new(BTreeMap::new()))?;
    let measurements = fixture_step(
        "publish measurements",
        repository.publish_measurement_set(&measurement_set),
    )?;
    let property_evidence = fixture_step(
        "build property evidence",
        PropertyEvidence::new(PropertyVerdict::Failed, BTreeSet::new()),
    )?;
    let property_verdicts = fixture_step(
        "build property verdicts",
        PropertyVerdictSet::new(BTreeMap::from([(
            String::from(PROPERTY),
            property_evidence,
        )])),
    )?;
    let properties = fixture_step(
        "publish property verdicts",
        repository.publish_property_verdict_set(&property_verdicts),
    )?;
    let coverage_projection = fixture_step(
        "build coverage",
        CoverageProjection::new(BTreeSet::new(), BTreeSet::new()),
    )?;
    let coverage = fixture_step(
        "publish coverage",
        repository.publish_coverage_projection(&coverage_projection),
    )?;
    let observation = fixture_step(
        "build observation",
        Observation::new(
            attempt,
            child,
            child_artifact,
            attempt_path,
            StopOutcome::AssertionFailure(String::from(PROPERTY)),
            measurements,
            properties,
            coverage,
            BTreeSet::new(),
        ),
    )?;
    let observation_snapshot =
        fixture_step("read campaign head", repository.head(CAMPAIGN))?.snapshot_id();
    let observed = fixture_step(
        "publish observation",
        repository.publish_observation(CAMPAIGN, observation_snapshot, &observation),
    )?;

    let campaign_fingerprint = CampaignHash::from_bytes(model_finding.finding_fingerprint.bytes);
    let original = fixture_step(
        "publish original reproduction",
        repository.publish_reproduction_artifact(
            scenario,
            scenario_artifact,
            child,
            child_artifact,
            campaign_fingerprint,
            1,
            model_finding.artifact.to_compact_binary(),
        ),
    )?;
    let replayed_state = CampaignHash::from_bytes(minimized_model_finding.replay.state.bytes);
    let minimization = fixture_step(
        "build minimization evidence",
        FindingMinimizationEvidence::new(
            original,
            1,
            b"finding triage fixture deterministic minimizer".to_vec(),
            vec![FindingMinimizationAttempt::new(
                0,
                CampaignHash::from_bytes(minimized_model_finding.artifact.id().bytes),
                CampaignHash::from_bytes(
                    minimized_model_finding
                        .artifact
                        .schedule()
                        .content_hash()
                        .bytes,
                ),
                replayed_state,
                Some(campaign_fingerprint),
                true,
            )],
            replayed_state,
        ),
    )?;
    let minimized = fixture_step(
        "publish minimized reproduction",
        repository.publish_minimized_reproduction_artifact(
            scenario,
            scenario_artifact,
            minimized_child,
            minimized_child_artifact,
            campaign_fingerprint,
            1,
            minimized_model_finding.artifact.to_compact_binary(),
            minimization.clone(),
        ),
    )?;
    let signature = fixture_step(
        "build original campaign signature",
        FindingSignature::new(
            FindingKind::PropertyViolation,
            campaign_fingerprint,
            Some(String::from(PROPERTY)),
            String::from("fixture.property-violation"),
            Some(FindingTarget::Configuration(child_artifact)),
            BTreeSet::from([properties.content_id()]),
        ),
    )?;
    let minimized_signature = fixture_step(
        "build minimized campaign signature",
        FindingSignature::new(
            FindingKind::PropertyViolation,
            campaign_fingerprint,
            Some(String::from(PROPERTY)),
            String::from("fixture.property-violation"),
            Some(FindingTarget::Configuration(minimized_child_artifact)),
            BTreeSet::from([properties.content_id()]),
        ),
    )?;
    let replay_pass = vec![Some(signature.clone()), Some(minimized_signature.clone())];
    let signature_minimization = fixture_step(
        "build signature minimization evidence",
        FindingSignatureMinimizationEvidence::new(
            &signature,
            &minimization,
            replay_pass.clone(),
            replay_pass,
        ),
    )?;

    let publish_triage_replay =
        |reproduction, observed_signature: &FindingSignature, payload: Vec<u8>| {
            let evidence = fixture_step(
                "build campaign triage replay evidence",
                FindingTriageReplayEvidence::new(
                    reproduction,
                    observed_signature.clone(),
                    crucible::FAILURE_TRIAGE_REPLAY_EVIDENCE_SCHEMA_VERSION,
                    payload,
                ),
            )?;
            fixture_step(
                "publish campaign triage replay evidence",
                repository.publish_finding_triage_replay_evidence(&evidence),
            )
        };
    let triage_evidence = FindingTriageEvidenceSet::new(
        publish_triage_replay(
            original,
            &signature,
            fixture_step("encode original replay", native_replay.to_compact_binary())?,
        )?,
        publish_triage_replay(
            minimized,
            &minimized_signature,
            fixture_step(
                "encode minimized replay",
                minimized_native_replay.to_compact_binary(),
            )?,
        )?,
        publish_triage_replay(
            original,
            &signature,
            fixture_step(
                "encode verification original",
                native_replay.to_compact_binary(),
            )?,
        )?,
        publish_triage_replay(
            minimized,
            &minimized_signature,
            fixture_step(
                "encode verification selected",
                verification_selected_native_replay.to_compact_binary(),
            )?,
        )?,
    );
    let bundle = fixture_step(
        "build finding candidate bundle",
        FindingCandidateBundle::new_with_triage_evidence(
            observed.observation,
            signature,
            original,
            minimized,
            signature_minimization,
            FindingExactPins::default(),
            triage_evidence,
        ),
    )?;
    let bundle = fixture_step(
        "publish finding candidate bundle",
        repository.publish_finding_candidate_bundle(&bundle),
    )?;
    let published = fixture_step(
        "incorporate finding candidate bundle",
        repository.incorporate_finding_candidate_bundle(CAMPAIGN, observed.new_snapshot, bundle),
    )?;
    Ok(PublishedFindingFixture {
        repository: campaign.repository,
        campaign: fixture_step("build fixture campaign name", CampaignName::new(CAMPAIGN))?,
        snapshot: published.new_snapshot,
        finding: published.finding,
    })
}

fn capture_campaign_finding_fixture(
    published: &PublishedFindingFixture,
    report: TriageFindingEvidence,
) -> Result<FindingFixtureCaptures, CliError> {
    let repository = &published.repository;
    let client = CampaignClient::new(RepositoryCampaignService::new(
        repository,
        PermitFindingExport,
    ));
    let principal = fixture_step(
        "build fixture principal",
        CampaignPrincipal::new("operator:finding-triage-fixture"),
    )?;
    let campaign = published.campaign.clone();
    let evidence = crate::cli_triage_debug::campaign_evidence::capture_campaign_triage_finding(
        &client,
        principal,
        campaign.clone(),
        published.snapshot,
        published.finding,
        report,
    )?;
    let other_evidence =
        crate::cli_triage_debug::campaign_evidence::capture_campaign_triage_finding(
            &client,
            fixture_step(
                "build mutation principal",
                CampaignPrincipal::new("operator:finding-triage-proof-mutation"),
            )?,
            campaign,
            published.snapshot,
            published.finding,
            evidence.report.clone(),
        )?;

    Ok(FindingFixtureCaptures {
        evidence,
        other_evidence,
    })
}

fn write_finding_triage_fixture(
    output: &Path,
    native: &NativeFindingFixture,
    captures: &FindingFixtureCaptures,
) -> Result<FindingTriageFixtureReport, CliError> {
    let evidence = &captures.evidence;
    let other_evidence = &captures.other_evidence;
    let model_finding = &native.model_finding;
    let minimized_model_finding = &native.minimized_model_finding;

    let findings = output.join("findings-v4.crucible-findings");
    let (_, _, bytes) =
        crate::cli_triage_debug::campaign_evidence::write_failure_findings_ledger_v4(
            output,
            Some(&findings),
            std::slice::from_ref(evidence),
        )?;
    let proof_mutation = output.join("findings-v4-proof-mutation.crucible-findings");
    write_proof_mutation(&proof_mutation, &bytes, evidence, other_evidence)?;
    let payload_mutation = output.join("findings-v4-payload-mutation.crucible-findings");
    write_payload_mutation(&payload_mutation, &bytes)?;

    let store = output.join("store");
    let dag_store = crucible::LocalDagStore::new(store.clone());
    let stored_original = fixture_step(
        "store original artifact",
        model_finding.store_artifact(&dag_store),
    )?;
    let stored_minimized = fixture_step(
        "store minimized artifact",
        minimized_model_finding.store_artifact(&dag_store),
    )?;
    if stored_original != model_finding.artifact.id()
        || stored_minimized != minimized_model_finding.artifact.id()
    {
        return Err(fixture_error(
            "fixture DagStore changed a reproduction artifact identity",
        ));
    }

    Ok(FindingTriageFixtureReport {
        schema: FINDING_TRIAGE_FIXTURE_REPORT_SCHEMA,
        directory: output.to_path_buf(),
        findings,
        store,
        proof_mutation,
        payload_mutation,
        original_artifact: model_finding.artifact.id().to_hex(),
        minimized_artifact: minimized_model_finding.artifact.id().to_hex(),
    })
}

pub(in crate::cli_campaign) fn render_finding_triage_fixture(
    report: &FindingTriageFixtureReport,
    format: OutputFormat,
) -> Result<String, CliError> {
    match format {
        OutputFormat::Jsonl => serde_json::to_string(report)
            .map_err(|error| fixture_error(format!("encode fixture JSON: {error}"))),
        OutputFormat::Json => serde_json::to_string_pretty(report)
            .map_err(|error| fixture_error(format!("encode fixture JSON: {error}"))),
        OutputFormat::Table => Ok([
            format!("{:<20} {}", "directory", report.directory.display()),
            format!("{:<20} {}", "findings", report.findings.display()),
            format!("{:<20} {}", "store", report.store.display()),
            format!(
                "{:<20} {}",
                "proof mutation",
                report.proof_mutation.display()
            ),
            format!(
                "{:<20} {}",
                "payload mutation",
                report.payload_mutation.display()
            ),
            format!("{:<20} {}", "original artifact", report.original_artifact),
            format!("{:<20} {}", "minimized artifact", report.minimized_artifact),
        ]
        .join("\n")),
        OutputFormat::Markdown => Ok([
            String::from("| Fixture field | Value |"),
            String::from("| --- | --- |"),
            format!("| directory | `{}` |", report.directory.display()),
            format!("| findings | `{}` |", report.findings.display()),
            format!("| store | `{}` |", report.store.display()),
            format!("| proof mutation | `{}` |", report.proof_mutation.display()),
            format!(
                "| payload mutation | `{}` |",
                report.payload_mutation.display()
            ),
            format!("| original artifact | `{}` |", report.original_artifact),
            format!("| minimized artifact | `{}` |", report.minimized_artifact),
        ]
        .join("\n")),
    }
}

fn native_replay_evidence(
    report: &TriageFindingEvidence,
) -> Result<crucible::FailureTriageReplayEvidence, CliError> {
    fixture_step(
        "build native replay evidence",
        crucible::FailureTriageReplayEvidence::new(
            report.finding.clone(),
            report.failure.clone(),
            report.causal_entries.clone(),
            report.recorded_event_log.coverage_fingerprint(),
            report.recorded_event_frames.clone(),
        ),
    )
}

fn write_proof_mutation(
    path: &Path,
    bytes: &[u8],
    evidence: &CampaignTriageFindingEvidence,
    other_evidence: &CampaignTriageFindingEvidence,
) -> Result<(), CliError> {
    let response = triage_verification_selected_response(evidence)?;
    let other_response = triage_verification_selected_response(other_evidence)?;
    let text = std::str::from_utf8(bytes)
        .map_err(|error| fixture_error(format!("decode fixture ledger: {error}")))?;
    let mutated = text.replacen(
        &ledger_hex(&response.canonical_bytes()),
        &ledger_hex(&other_response.canonical_bytes()),
        1,
    );
    if mutated == text {
        return Err(fixture_error(
            "fixture proof mutation did not replace its authenticated response",
        ));
    }
    write_fixture_file(path, mutated.as_bytes())
}

fn write_payload_mutation(path: &Path, bytes: &[u8]) -> Result<(), CliError> {
    let text = std::str::from_utf8(bytes)
        .map_err(|error| fixture_error(format!("decode fixture ledger: {error}")))?;
    let original = format!(
        "finding.0.assertion_hex={}",
        ledger_hex(PROPERTY.as_bytes())
    );
    let replacement = format!(
        "finding.0.assertion_hex={}",
        ledger_hex(b"finding-triage-foreign-property")
    );
    let mutated = text.replacen(&original, &replacement, 1);
    if mutated == text {
        return Err(fixture_error(
            "fixture payload mutation did not replace its projected assertion",
        ));
    }
    write_fixture_file(path, mutated.as_bytes())
}

fn triage_verification_selected_response(
    evidence: &CampaignTriageFindingEvidence,
) -> Result<&crucible_campaign::GetCampaignFindingOccurrenceObjectResponse, CliError> {
    evidence
        .occurrence_proofs
        .first()
        .and_then(|proof| proof.triage_evidence.as_ref())
        .map(|triage| &triage.verification_selected.response)
        .ok_or_else(|| fixture_error("fixture is missing verification replay proof"))
}

fn fixture_step<T, E>(action: &'static str, result: Result<T, E>) -> Result<T, CliError>
where
    E: fmt::Display,
{
    result.map_err(|error| fixture_error(format!("{action}: {error}")))
}
