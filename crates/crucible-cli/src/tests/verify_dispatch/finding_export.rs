//! Campaign finding export round-trip and tamper tests.

use super::*;

struct AllowCampaignFindingExport;

impl crucible_campaign::CampaignPrincipalAuthorizer for AllowCampaignFindingExport {
    fn authorize(
        &self,
        _principal: &crucible_campaign::CampaignPrincipal,
        _operation: crucible_campaign::CampaignServiceOperation,
        _campaign: &crucible_campaign::CampaignName,
        _request_digest: crucible_campaign::CampaignHash,
    ) -> Result<(), crucible_campaign::CampaignAuthorizationError> {
        Ok(())
    }
}

#[test]
pub(super) fn campaign_findings_round_trip_authenticates_occurrence_objects_and_tampering()
-> Result<(), Box<dyn Error>> {
    use std::collections::{BTreeMap, BTreeSet};
    use std::sync::Arc;

    if let Some(input) = std::env::var_os("CRUCIBLE_FINDING_BUNDLE_VALID_ARCHIVE_CHILD") {
        let cli = <crate::Cli as clap::Parser>::try_parse_from([
            std::ffi::OsString::from("crucible"),
            std::ffi::OsString::from("--format"),
            std::ffi::OsString::from("json"),
            std::ffi::OsString::from("campaign"),
            std::ffi::OsString::from("finding-bundle"),
            std::ffi::OsString::from("verify"),
            input,
        ])?;
        let crate::Commands::Campaign(campaign) = &cli.command else {
            return Err(std::io::Error::other("missing parsed campaign command").into());
        };
        crate::cli_campaign::run_campaign_invocation(&cli, campaign)?;
        return Ok(());
    }

    if let Some(input) = std::env::var_os("CRUCIBLE_FINDING_BUNDLE_INVALID_ARCHIVE_CHILD") {
        let cli = <crate::Cli as clap::Parser>::try_parse_from([
            std::ffi::OsString::from("crucible"),
            std::ffi::OsString::from("--format"),
            std::ffi::OsString::from("json"),
            std::ffi::OsString::from("campaign"),
            std::ffi::OsString::from("finding-bundle"),
            std::ffi::OsString::from("verify"),
            input,
        ])?;
        let crate::Commands::Campaign(campaign) = &cli.command else {
            return Err(std::io::Error::other("missing parsed campaign command").into());
        };
        let error = crate::cli_campaign::run_campaign_invocation(&cli, campaign)
            .err()
            .ok_or_else(|| std::io::Error::other("missing archive unexpectedly verified"))?;
        assert!(error.to_string().contains("archive"));
        return Ok(());
    }

    use crucible_campaign::{
        BudgetGrant, CampaignArchivePolicy, CampaignClient, CampaignCommandId,
        CampaignControlAction, CampaignHash, CampaignLineage, CampaignMode, CampaignName,
        CampaignPolicy, CampaignPrincipal, CampaignRepository, CampaignSeed, ConfigurationId,
        ControlRequest, CoverageProjection, ExplorerPolicy, FairnessPolicy, FindingCandidateBundle,
        FindingCandidateCore, FindingExactPins, FindingExactRetention,
        FindingExactRetentionDisposition, FindingKind, FindingMinimizationAttempt,
        FindingMinimizationEvidence, FindingSignature, FindingSignatureMinimizationEvidence,
        FindingTarget, FindingTriageEvidenceSet, FindingTriageReplayEvidence, MeasurementSet,
        Observation, PropertyEvidence, PropertyVerdict, PropertyVerdictSet,
        RepositoryCampaignService, RetentionPolicy, ScenarioDefId, StopOutcome,
    };
    use crucible_cas::content_store::{MemoryBlobBackend, MemoryRefBackend};
    use crucible_daemon::campaign_store_composition::{
        DirectoryBlobBackend, DirectoryRefBackend, DurabilityRequirement,
    };

    const CAMPAIGN: &str = "cli-campaign-findings-finding-export";
    const PROPERTY: &str = "cli-campaign-findings-property";

    let form = search_frontier_scenario_form()?;
    let configuration = crucible::Configuration {
        def: form.scenario_def(),
        schedule: crucible::Schedule::from_decisions(search_frontier_decisions()),
    };
    let minimized_configuration = crucible::Configuration::genesis(form.scenario_def());
    let fingerprint =
        crucible::ContentHash::from_bytes(b"cli-campaign-findings-finding-fingerprint");
    let model_finding = crucible::FindingReproductionArtifact::capture(
        crucible::FindingDiscoveryPath::StateSpaceSearch,
        fingerprint,
        &form,
        &configuration,
    )?;
    let minimized_model_finding = crucible::FindingReproductionArtifact::capture(
        crucible::FindingDiscoveryPath::StateSpaceSearch,
        fingerprint,
        &form,
        &minimized_configuration,
    )?;
    let report = triage_property_evidence_for_violation(
        model_finding.clone(),
        crucible_model::HostAssertionViolation {
            assertion: crucible::AssertionId::from_name(PROPERTY),
            message: String::from("CLI campaign findings property violated"),
            quantifier: crucible::AssertionQuantifierKind::Always,
            event_kind: String::from("assertion_state_changed"),
            at_icount: Some(crucible::Icount { retired: 7 }),
            at_virtual_time: crucible::VirtualTime { ticks: 7 },
            node: None,
            detail: String::from("retained campaign finding"),
            reproduction_artifact: model_finding.artifact.id(),
        },
    )?;

    let repository = CampaignRepository::new(
        Arc::new(MemoryBlobBackend::new(
            "cli-campaign-findings-finding-export",
            u64::MAX,
        )),
        Arc::new(MemoryRefBackend::new()),
    );
    let scenario = ScenarioDefId::from_hash(CampaignHash::from_bytes(form.id().bytes));
    let scenario_artifact =
        repository.publish_scenario_artifact(scenario, 1, form.to_compact_binary())?;
    let genesis = ConfigurationId::from_hash(CampaignHash::derive(
        "cli-campaign-findings-test-configuration",
        b"genesis",
    ));
    let genesis_artifact = repository.publish_configuration_artifact(
        scenario,
        scenario_artifact,
        genesis,
        1,
        b"cli v4 genesis".to_vec(),
    )?;
    let lineage = CampaignLineage::new(
        scenario,
        scenario_artifact,
        genesis,
        genesis_artifact,
        "cli-campaign-findings-engine",
        "cli-campaign-findings-qemu",
        BTreeMap::from([(String::from("control"), 1)]),
        1,
        1,
    )?;
    let policy = CampaignPolicy::new(
        CampaignPolicy::identity(
            scenario,
            CampaignSeed::from_bytes([0x47; 32]),
            CampaignMode::Strict,
            ExplorerPolicy::Exhaustive {
                maximum_cardinality: 1,
            },
        ),
        CampaignPolicy::rules(
            BTreeMap::new(),
            BTreeMap::new(),
            BTreeMap::new(),
            BTreeSet::new(),
            FairnessPolicy::new(0, 0)?,
            RetentionPolicy::new(true, 1, false, true),
            true,
        ),
    )?;
    let created = repository.create(CAMPAIGN, &lineage, &policy, &BTreeMap::new())?;
    let resumed = repository.apply_control(
        CAMPAIGN,
        &ControlRequest {
            command: CampaignCommandId::from_hash(CampaignHash::derive(
                "cli-campaign-findings-test-command",
                b"resume",
            )),
            expected_snapshot: created.snapshot_id(),
            action: CampaignControlAction::Resume,
        },
    )?;
    let _funded = repository.apply_control(
        CAMPAIGN,
        &ControlRequest {
            command: CampaignCommandId::from_hash(CampaignHash::derive(
                "cli-campaign-findings-test-command",
                b"fund",
            )),
            expected_snapshot: resumed.new_snapshot,
            action: CampaignControlAction::GrantBudget(BudgetGrant::new(0, 1)?),
        },
    )?;
    let attempt = repository
        .admit_initial_discovery_if_ready(CAMPAIGN)?
        .ok_or_else(|| std::io::Error::other("missing admitted discovery"))?;
    let attempt_record = repository.load_attempt(attempt)?;
    let child = ConfigurationId::from_hash(CampaignHash::from_bytes(configuration.id().bytes));
    let child_artifact = repository.publish_configuration_artifact(
        scenario,
        scenario_artifact,
        child,
        1,
        b"cli v4 child".to_vec(),
    )?;
    let minimized_child =
        ConfigurationId::from_hash(CampaignHash::from_bytes(minimized_configuration.id().bytes));
    let minimized_child_artifact = repository.publish_configuration_artifact(
        scenario,
        scenario_artifact,
        minimized_child,
        1,
        b"cli v4 minimized child".to_vec(),
    )?;
    let measurements = repository.publish_measurement_set(&MeasurementSet::from_evaluation(
        CampaignHash::derive(
            "crucible.cli.verify-dispatch.measurements.v1",
            b"definitions",
        ),
        1,
        CampaignHash::derive("crucible.cli.verify-dispatch.evaluation.v1", b"evaluation"),
        b"empty evaluation".to_vec(),
        BTreeSet::new(),
    )?)?;
    let properties =
        repository.publish_property_verdict_set(&PropertyVerdictSet::new(BTreeMap::from([(
            String::from(PROPERTY),
            PropertyEvidence::new(PropertyVerdict::Failed, BTreeSet::new())?,
        )]))?)?;
    let coverage = repository
        .publish_coverage_projection(&CoverageProjection::new(BTreeSet::new(), BTreeSet::new())?)?;
    let observation = Observation::new(
        attempt,
        Observation::outcome(
            child,
            child_artifact,
            attempt_record.path(),
            StopOutcome::AssertionFailure(String::from(PROPERTY)),
            measurements,
            properties,
            coverage,
        ),
        BTreeSet::new(),
    )?;
    let observation_snapshot = repository.head(CAMPAIGN)?.snapshot_id();
    let retention_basis =
        repository.attempt_retention_policy_basis_at(observation_snapshot, attempt)?;
    let exact_retention = FindingExactRetention::new(
        retention_basis.snapshot(),
        retention_basis.policy(),
        retention_basis.admission(),
        0,
        FindingExactRetentionDisposition::Disabled,
    )?;
    let observed = repository.publish_observation(CAMPAIGN, observation_snapshot, &observation)?;
    let campaign_fingerprint = CampaignHash::from_bytes(fingerprint.bytes);
    let reproduction_payload = model_finding.artifact.to_compact_binary();
    assert_eq!(
        model_finding.artifact.scenario_form().id().to_hex(),
        scenario.to_hex()
    );
    assert_eq!(configuration.id().to_hex(), child.to_hex());
    assert_eq!(
        model_finding.artifact.id().to_hex(),
        crucible::ContentHash::from_bytes(&reproduction_payload).to_hex()
    );
    let original = repository.publish_reproduction_artifact(
        scenario,
        scenario_artifact,
        child,
        child_artifact,
        campaign_fingerprint,
        crucible_daemon::CRUCIBLE_REPRODUCTION_PAYLOAD_SCHEMA_V3,
        reproduction_payload.clone(),
    )?;
    let replayed_state = CampaignHash::from_bytes(minimized_model_finding.replay.state.bytes);
    let minimization = FindingMinimizationEvidence::new(
        original,
        3,
        b"cli v4 deterministic minimizer".to_vec(),
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
    )?;
    let minimized = repository.publish_minimized_reproduction_artifact(
        scenario,
        scenario_artifact,
        minimized_child,
        minimized_child_artifact,
        campaign_fingerprint,
        crucible_daemon::CRUCIBLE_REPRODUCTION_PAYLOAD_SCHEMA_V3,
        minimized_model_finding.artifact.to_compact_binary(),
        minimization.clone(),
    )?;
    let signature = FindingSignature::new(
        FindingKind::PropertyViolation,
        campaign_fingerprint,
        Some(String::from(PROPERTY)),
        String::from("cli.campaign-findings-property-violation"),
        Some(FindingTarget::Configuration(child_artifact)),
        BTreeSet::from([properties.content_id()]),
    )?;
    let minimized_signature = FindingSignature::new(
        FindingKind::PropertyViolation,
        campaign_fingerprint,
        Some(String::from(PROPERTY)),
        String::from("cli.campaign-findings-property-violation"),
        Some(FindingTarget::Configuration(minimized_child_artifact)),
        BTreeSet::from([properties.content_id()]),
    )?;
    let replay_pass = vec![Some(signature.clone()), Some(minimized_signature.clone())];
    let signature_minimization = FindingSignatureMinimizationEvidence::new(
        &signature,
        &minimization,
        replay_pass.clone(),
        replay_pass,
    )?;
    let native_replay = crucible::FailureTriageReplayEvidence::new(
        report.finding.clone(),
        report.failure.clone(),
        report.causal_entries.clone(),
        report.recorded_event_log.coverage_fingerprint(),
        report.recorded_event_frames.clone(),
    )?;
    let minimized_report = triage_evidence_for_finding(minimized_model_finding.clone(), &report)?;
    let minimized_native_replay = crucible::FailureTriageReplayEvidence::new(
        minimized_report.finding.clone(),
        minimized_report.failure.clone(),
        minimized_report.causal_entries.clone(),
        minimized_report.recorded_event_log.coverage_fingerprint(),
        minimized_report.recorded_event_frames.clone(),
    )?;
    let mut verification_failure = minimized_report.failure.clone();
    let crucible::FailureClusterReportFailure::Property(verification_property) =
        &mut verification_failure
    else {
        return Err(std::io::Error::other("expected property replay evidence").into());
    };
    verification_property
        .violation
        .message
        .push_str(" during independent verification");
    let verification_selected_native_replay = crucible::FailureTriageReplayEvidence::new(
        minimized_report.finding.clone(),
        verification_failure,
        minimized_report.causal_entries.clone(),
        minimized_report.recorded_event_log.coverage_fingerprint(),
        minimized_report.recorded_event_frames.clone(),
    )?;
    assert_eq!(
        minimized_native_replay.signature(),
        verification_selected_native_replay.signature()
    );
    assert_ne!(
        minimized_native_replay.to_compact_binary()?,
        verification_selected_native_replay.to_compact_binary()?
    );

    let publish_triage_replay = |reproduction,
                                 observed_signature: &FindingSignature,
                                 payload: Vec<u8>|
     -> Result<_, Box<dyn Error>> {
        let evidence = FindingTriageReplayEvidence::new(
            reproduction,
            observed_signature.clone(),
            crucible::FAILURE_TRIAGE_REPLAY_EVIDENCE_SCHEMA_VERSION,
            payload,
        )?;
        Ok(repository.publish_finding_triage_replay_evidence(&evidence)?)
    };
    let triage_evidence = FindingTriageEvidenceSet::new(
        publish_triage_replay(original, &signature, native_replay.to_compact_binary()?)?,
        publish_triage_replay(
            minimized,
            &minimized_signature,
            minimized_native_replay.to_compact_binary()?,
        )?,
        publish_triage_replay(original, &signature, native_replay.to_compact_binary()?)?,
        publish_triage_replay(
            minimized,
            &minimized_signature,
            verification_selected_native_replay.to_compact_binary()?,
        )?,
    );
    let bundle = FindingCandidateBundle::new_with_exact_retention(
        FindingCandidateCore::new(
            observed.observation,
            signature.clone(),
            original,
            minimized,
            signature_minimization.clone(),
            FindingExactPins::default(),
        ),
        Some(triage_evidence),
        exact_retention,
    )?;
    let bundle = repository.publish_finding_candidate_bundle(&bundle)?;
    let published =
        repository.incorporate_finding_candidate_bundle(CAMPAIGN, observed.new_snapshot, bundle)?;
    let client = CampaignClient::new(RepositoryCampaignService::new(
        &repository,
        AllowCampaignFindingExport,
    ));
    let evidence = crate::cli_triage_debug::campaign_evidence::capture_campaign_triage_finding(
        &client,
        CampaignPrincipal::new("operator:cli-campaign-findings")?,
        CampaignName::new(CAMPAIGN)?,
        published.new_snapshot,
        published.finding,
        report,
    )?;
    let service_evidence =
        crate::cli_triage_debug::campaign_evidence::capture_campaign_triage_finding_from_service(
            &client,
            CampaignPrincipal::new("operator:cli-campaign-findings")?,
            CampaignName::new(CAMPAIGN)?,
            published.new_snapshot,
            published.finding,
        )?;
    assert_eq!(service_evidence.report, evidence.report);

    let artifact_dir = tempfile::tempdir()?;
    let bytes = crate::cli_triage_debug::campaign_evidence::campaign_findings_ledger_bytes(
        std::slice::from_ref(&evidence),
    )?;
    let executable = repository.plan_campaign_archive(
        published.new_snapshot,
        CampaignArchivePolicy::Executable,
        [],
        None,
    )?;
    repository.stage_campaign_archive_metadata(&executable)?;
    let portable_root = tempfile::tempdir()?;
    let portable_bundle = portable_root.path().join("finding");
    let archive_root = portable_bundle.join("archive");
    let private_archive = CampaignRepository::new(
        Arc::new(DirectoryBlobBackend::new(
            "cli-finding-bundle-test",
            archive_root.join("objects"),
        )),
        Arc::new(DirectoryRefBackend::new(archive_root.join("refs"))),
    );
    repository.transfer_campaign_archive_objects(
        &private_archive,
        &executable,
        DurabilityRequirement::new(1, false)?,
    )?;
    assert_eq!(
        private_archive.inspect_archived_finding(executable.manifest_id(), published.finding)?,
        evidence.finding
    );
    std::fs::write(
        portable_bundle.join("manifest"),
        format!(
            "crucible.campaign.finding-bundle.v2\narchive_manifest={}\n",
            executable.manifest_id()
        ),
    )?;
    std::fs::write(portable_bundle.join("ledger"), &bytes)?;
    let child = std::process::Command::new(std::env::current_exe()?)
        .arg("campaign_findings_round_trip_authenticates_occurrence_objects_and_tampering")
        .arg("--test-threads=1")
        .env(
            "CRUCIBLE_FINDING_BUNDLE_VALID_ARCHIVE_CHILD",
            &portable_bundle,
        )
        .output()?;
    assert!(
        child.status.success() && String::from_utf8_lossy(&child.stdout).contains("1 passed"),
        "fresh-process archive verification failed: {}{}",
        String::from_utf8_lossy(&child.stdout),
        String::from_utf8_lossy(&child.stderr)
    );

    let external_objects = portable_root.path().join("external-objects");
    std::fs::rename(archive_root.join("objects"), &external_objects)?;
    std::os::unix::fs::symlink(&external_objects, archive_root.join("objects"))?;
    let cli = <crate::Cli as clap::Parser>::try_parse_from([
        std::ffi::OsString::from("crucible"),
        std::ffi::OsString::from("campaign"),
        std::ffi::OsString::from("finding-bundle"),
        std::ffi::OsString::from("verify"),
        portable_bundle.as_os_str().to_owned(),
    ])?;
    let crate::Commands::Campaign(campaign) = &cli.command else {
        return Err(std::io::Error::other("missing parsed campaign command").into());
    };
    let error = crate::cli_campaign::run_campaign_invocation(&cli, campaign)
        .err()
        .ok_or_else(|| std::io::Error::other("external archive unexpectedly verified"))?;
    assert!(error.to_string().contains("symlink"));

    let plan = repository.plan_campaign_archive(
        published.new_snapshot,
        CampaignArchivePolicy::Findings,
        [],
        None,
    )?;
    let invalid_bundle = portable_root.path().join("invalid-finding");
    std::fs::create_dir_all(invalid_bundle.join("archive"))?;
    std::fs::write(
        invalid_bundle.join("manifest"),
        format!(
            "crucible.campaign.finding-bundle.v2\narchive_manifest={}\n",
            plan.manifest_id()
        ),
    )?;
    std::fs::write(invalid_bundle.join("ledger"), &bytes)?;
    let child = std::process::Command::new(std::env::current_exe()?)
        .arg("campaign_findings_round_trip_authenticates_occurrence_objects_and_tampering")
        .arg("--test-threads=1")
        .env(
            "CRUCIBLE_FINDING_BUNDLE_INVALID_ARCHIVE_CHILD",
            &invalid_bundle,
        )
        .output()?;
    assert!(
        child.status.success() && String::from_utf8_lossy(&child.stdout).contains("1 passed"),
        "fresh-process archive rejection failed: {}{}",
        String::from_utf8_lossy(&child.stdout),
        String::from_utf8_lossy(&child.stderr)
    );
    let store_temp = tempfile::tempdir()?;
    let store = crucible::LocalDagStore::new(store_temp.path().join("store"));
    let loaded = crate::cli_triage_debug::campaign_evidence::parse_campaign_findings_ledger_bytes(
        &store,
        &bytes,
        std::str::from_utf8(&bytes)?,
    )?;
    assert_eq!(loaded.campaign_evidence, vec![evidence.clone()]);
    assert_eq!(loaded.ledger.signed_findings().len(), 1);
    assert_eq!(
        loaded.ledger.signed_findings()[0].signature,
        native_replay.signature().clone()
    );
    assert!(
        loaded.campaign_evidence[0].occurrence_proofs[0]
            .triage_evidence
            .is_some()
    );
    let policy = crucible::SignaturePolicy::exact();
    let clustering = crucible::FailureClusteringResult::from_findings(
        policy,
        loaded.ledger.signed_findings().iter().cloned(),
    )?;
    let triage_plan = TriageInvocationPlan {
        policy,
        minimize: TriageMinimizeArg::All,
        report_dir: artifact_dir.path().join("reports"),
        format: crucible::FailureClusterReportFormat::JsonLines,
        recompute_signatures: true,
        store_root: store_temp.path().join("triage-store"),
    };
    let minimization = build_triage_minimization(&triage_plan, &clustering, &loaded)?;
    assert_eq!(minimization.runs.len(), 1);
    assert!(minimization.runs[0].preserves_signature());
    assert_eq!(
        minimization.runs[0].representative_artifact,
        model_finding.artifact.id()
    );
    assert_eq!(
        minimization.runs[0].minimized_artifact(),
        minimized_model_finding.artifact.id()
    );
    let report_set = build_triage_report_set(policy, &clustering, &minimization, &loaded)?;
    assert_eq!(report_set.reports.len(), 1);
    assert_eq!(
        report_set.reports[0].minimal_representative,
        minimized_model_finding.artifact.id()
    );
    assert_eq!(
        report_set.reports[0].signature,
        minimized_native_replay.signature().clone()
    );

    let other_evidence =
        crate::cli_triage_debug::campaign_evidence::capture_campaign_triage_finding(
            &client,
            CampaignPrincipal::new("operator:other-cli-campaign-findings")?,
            CampaignName::new(CAMPAIGN)?,
            published.new_snapshot,
            published.finding,
            evidence.report.clone(),
        )?;
    let text = String::from_utf8(bytes)?;
    let response = ledger_hex(
        &evidence.occurrence_proofs[0]
            .triage_evidence
            .as_ref()
            .ok_or_else(|| std::io::Error::other("missing native triage evidence"))?
            .verification_selected
            .segments
            .first()
            .ok_or_else(|| std::io::Error::other("missing selected replay segment"))?
            .response
            .canonical_bytes(),
    );
    let wrong_response = ledger_hex(
        &other_evidence.occurrence_proofs[0]
            .triage_evidence
            .as_ref()
            .ok_or_else(|| std::io::Error::other("missing native triage evidence"))?
            .verification_selected
            .segments
            .first()
            .ok_or_else(|| std::io::Error::other("missing alternate selected replay segment"))?
            .response
            .canonical_bytes(),
    );
    assert_ne!(response, wrong_response);
    let tampered = text.replacen(&response, &wrong_response, 1);
    assert!(
        crate::cli_triage_debug::campaign_evidence::parse_campaign_findings_ledger_bytes(
            &store,
            tampered.as_bytes(),
            &tampered,
        )
        .is_err()
    );

    let mut alternate_selected_failure = minimized_report.failure.clone();
    let crucible::FailureClusterReportFailure::Property(alternate_property) =
        &mut alternate_selected_failure
    else {
        return Err(std::io::Error::other("expected property replay evidence").into());
    };
    alternate_property
        .violation
        .message
        .push_str(" from a second valid occurrence");
    let alternate_selected_replay = crucible::FailureTriageReplayEvidence::new(
        minimized_report.finding.clone(),
        alternate_selected_failure,
        minimized_report.causal_entries.clone(),
        minimized_report.recorded_event_log.coverage_fingerprint(),
        minimized_report.recorded_event_frames.clone(),
    )?;
    assert_eq!(
        alternate_selected_replay.signature(),
        minimized_native_replay.signature()
    );
    let alternate_selected = publish_triage_replay(
        minimized,
        &minimized_signature,
        alternate_selected_replay.to_compact_binary()?,
    )?;
    let duplicate_bundle = FindingCandidateBundle::new_with_exact_retention(
        FindingCandidateCore::new(
            observed.observation,
            signature.clone(),
            original,
            minimized,
            signature_minimization.clone(),
            FindingExactPins::default(),
        ),
        Some(FindingTriageEvidenceSet::new(
            triage_evidence.minimization_original(),
            triage_evidence.minimization_selected(),
            triage_evidence.verification_original(),
            alternate_selected,
        )),
        exact_retention,
    )?;
    let duplicate_bundle = repository.publish_finding_candidate_bundle(&duplicate_bundle)?;
    let duplicate_published = repository.incorporate_finding_candidate_bundle(
        CAMPAIGN,
        published.new_snapshot,
        duplicate_bundle,
    )?;
    let duplicate_evidence =
        crate::cli_triage_debug::campaign_evidence::capture_campaign_triage_finding(
            &client,
            CampaignPrincipal::new("operator:cli-campaign-findings")?,
            CampaignName::new(CAMPAIGN)?,
            duplicate_published.new_snapshot,
            duplicate_published.finding,
            evidence.report.clone(),
        )?;
    assert_eq!(duplicate_evidence.occurrence_proofs.len(), 2);
    let duplicate_bytes =
        crate::cli_triage_debug::campaign_evidence::campaign_findings_ledger_bytes(
            std::slice::from_ref(&duplicate_evidence),
        )?;
    let duplicate_loaded =
        crate::cli_triage_debug::campaign_evidence::parse_campaign_findings_ledger_bytes(
            &store,
            &duplicate_bytes,
            std::str::from_utf8(&duplicate_bytes)?,
        )?;
    assert_eq!(duplicate_loaded.ledger.signed_findings().len(), 1);
    assert_eq!(
        duplicate_loaded.campaign_evidence[0]
            .occurrence_proofs
            .len(),
        2
    );

    let frame_distinct_replay = crucible::FailureTriageReplayEvidence::new(
        evidence.report.finding.clone(),
        evidence.report.failure.clone(),
        evidence.report.causal_entries.clone(),
        evidence.report.recorded_event_log.coverage_fingerprint(),
        vec![b"distinct authenticated event frame".to_vec()],
    )?;
    assert_ne!(frame_distinct_replay.signature(), native_replay.signature());
    let frame_distinct_original = publish_triage_replay(
        original,
        &signature,
        frame_distinct_replay.to_compact_binary()?,
    )?;
    let conflicting_bundle = FindingCandidateBundle::new_with_exact_retention(
        FindingCandidateCore::new(
            observed.observation,
            signature.clone(),
            original,
            minimized,
            signature_minimization.clone(),
            FindingExactPins::default(),
        ),
        Some(FindingTriageEvidenceSet::new(
            frame_distinct_original,
            triage_evidence.minimization_selected(),
            triage_evidence.verification_original(),
            triage_evidence.verification_selected(),
        )),
        exact_retention,
    )?;
    let conflicting_bundle = repository.publish_finding_candidate_bundle(&conflicting_bundle)?;
    let conflicting_published = repository.incorporate_finding_candidate_bundle(
        CAMPAIGN,
        duplicate_published.new_snapshot,
        conflicting_bundle,
    )?;
    let conflicting_evidence =
        crate::cli_triage_debug::campaign_evidence::capture_campaign_triage_finding(
            &client,
            CampaignPrincipal::new("operator:cli-campaign-findings")?,
            CampaignName::new(CAMPAIGN)?,
            conflicting_published.new_snapshot,
            conflicting_published.finding,
            evidence.report.clone(),
        )?;
    let conflicting_bytes =
        crate::cli_triage_debug::campaign_evidence::campaign_findings_ledger_bytes(
            std::slice::from_ref(&conflicting_evidence),
        )?;
    assert!(matches!(
        crate::cli_triage_debug::campaign_evidence::parse_campaign_findings_ledger_bytes(
            &store,
            &conflicting_bytes,
            std::str::from_utf8(&conflicting_bytes)?,
        ),
        Err(CliError::Artifact(message))
            if message.contains("conflicting authenticated native signatures")
    ));

    let foreign_report = triage_property_evidence_for_violation(
        model_finding.clone(),
        crucible_model::HostAssertionViolation {
            assertion: crucible::AssertionId::from_name("cli-campaign-findings-foreign-property"),
            message: String::from("foreign but internally valid native failure"),
            quantifier: crucible::AssertionQuantifierKind::Always,
            event_kind: String::from("assertion_state_changed"),
            at_icount: Some(crucible::Icount { retired: 7 }),
            at_virtual_time: crucible::VirtualTime { ticks: 7 },
            node: None,
            detail: String::from("must not supersede the campaign signature"),
            reproduction_artifact: model_finding.artifact.id(),
        },
    )?;
    let foreign_native_replay = crucible::FailureTriageReplayEvidence::new(
        foreign_report.finding,
        foreign_report.failure,
        foreign_report.causal_entries,
        foreign_report.recorded_event_log.coverage_fingerprint(),
        foreign_report.recorded_event_frames,
    )?;
    assert_ne!(
        foreign_native_replay.signature().property,
        native_replay.signature().property
    );
    let foreign_original = publish_triage_replay(
        original,
        &signature,
        foreign_native_replay.to_compact_binary()?,
    )?;
    let foreign_bundle = FindingCandidateBundle::new_with_exact_retention(
        FindingCandidateCore::new(
            observed.observation,
            signature,
            original,
            minimized,
            signature_minimization,
            FindingExactPins::default(),
        ),
        Some(FindingTriageEvidenceSet::new(
            foreign_original,
            triage_evidence.minimization_selected(),
            triage_evidence.verification_original(),
            triage_evidence.verification_selected(),
        )),
        exact_retention,
    )?;
    let foreign_bundle = repository.publish_finding_candidate_bundle(&foreign_bundle)?;
    let foreign_published = repository.incorporate_finding_candidate_bundle(
        CAMPAIGN,
        conflicting_published.new_snapshot,
        foreign_bundle,
    )?;
    let foreign_capture =
        crate::cli_triage_debug::campaign_evidence::capture_campaign_triage_finding(
            &client,
            CampaignPrincipal::new("operator:cli-campaign-findings")?,
            CampaignName::new(CAMPAIGN)?,
            foreign_published.new_snapshot,
            foreign_published.finding,
            evidence.report,
        );
    assert!(matches!(
        foreign_capture,
        Err(CliError::Artifact(message))
            if message.contains("disagrees with its observed campaign signature")
    ));
    Ok(())
}
