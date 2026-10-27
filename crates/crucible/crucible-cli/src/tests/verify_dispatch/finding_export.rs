//! Campaign finding export round-trip and tamper tests.

use super::*;

#[path = "finding_export/evidence.rs"]
mod evidence;

use evidence::*;

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
        let crate::CampaignCommand::FindingBundle(bundle) = &campaign.command else {
            return Err(std::io::Error::other("missing finding bundle command").into());
        };
        let crate::CampaignFindingBundleCommand::Verify(verify) = &bundle.command else {
            return Err(std::io::Error::other("missing finding bundle verification").into());
        };
        let report = crate::cli_campaign::finding_bundle::verify_exported_finding(
            &cli,
            verify,
            cli.output_format(),
        )?;
        let report: serde_json::Value = serde_json::from_str(&report)?;
        let minimization = &report["minimization"];
        assert_eq!(minimization["disposition"], "candidate-accepted");
        assert_eq!(minimization["retained"]["policy_schema"], 4);
        assert_eq!(minimization["retained"]["attempts"][0]["accepted"], true);
        assert!(
            minimization["retained"]["original_schedule_decisions"]
                .as_u64()
                .ok_or_else(|| std::io::Error::other("missing original schedule count"))?
                > minimization["retained"]["minimized_schedule_decisions"]
                    .as_u64()
                    .ok_or_else(|| std::io::Error::other("missing minimized schedule count"))?
        );
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
        CampaignControlAction, CampaignHash, CampaignLineage, CampaignMode, CampaignPolicy,
        CampaignRepository, CampaignSeed, ConfigurationId, ControlRequest, CoverageProjection,
        ExplorerPolicy, FairnessPolicy, FindingCandidateBundle, FindingCandidateCore,
        FindingExactPins, FindingExactRetention, FindingExactRetentionDisposition, FindingKind,
        FindingMinimizationAttempt, FindingMinimizationEvidence, FindingSignature,
        FindingSignatureMinimizationEvidence, FindingTarget, FindingTriageEvidenceSet,
        MeasurementSet, Observation, PropertyEvidence, PropertyVerdict, PropertyVerdictSet,
        RepositoryCampaignService, RetentionPolicy, ScenarioDefId, StopOutcome,
    };
    use crucible_daemon::campaign_store_composition::{
        DirectoryBlobBackend, DirectoryRefBackend, DurabilityRequirement,
    };
    use crucible_store::content_store::{MemoryBlobBackend, MemoryRefBackend};

    const CAMPAIGN: &str = "cli-campaign-findings-finding-export";
    const PROPERTY: &str = "cli-campaign-findings-property";
    const FOREIGN_PROPERTY: &str = "cli-campaign-findings-foreign-property";

    let world = search_frontier_world()?;
    let assertions = [PROPERTY, FOREIGN_PROPERTY]
        .into_iter()
        .map(|name| crucible_engine::AssertionDef {
            id: crucible_engine::AssertionId::from_name(name),
            message: format!("{name} must not fail at the recorded boundary"),
            property: crucible_engine::Property::Always {
                predicate: crucible_engine::Predicate::not(crucible_engine::Predicate::At {
                    at: crucible_engine::VirtualTime { ticks: 7 },
                }),
            },
        })
        .collect();
    let properties = crucible_engine::Properties::from_assertions_for_world(&world, assertions)?;
    let form = crucible_engine::ScenarioDefForm::from_components(
        &world,
        &crucible_engine::Plan::empty(),
        &properties,
        crucible_engine::Seed::default(),
    )?;
    let configuration = crucible_engine::Configuration {
        def: form.scenario_def(),
        schedule: crucible_engine::Schedule::from_decisions(search_frontier_decisions()),
    };
    let minimized_configuration = crucible_engine::Configuration::genesis(form.scenario_def());
    let fingerprint =
        crucible_engine::ContentHash::from_bytes(b"cli-campaign-findings-finding-fingerprint");
    let model_finding = crucible_engine::FindingReproductionArtifact::capture(
        crucible_engine::FindingDiscoveryPath::StateSpaceSearch,
        fingerprint,
        &form,
        &configuration,
    )?;
    let minimized_model_finding = crucible_engine::FindingReproductionArtifact::capture(
        crucible_engine::FindingDiscoveryPath::StateSpaceSearch,
        fingerprint,
        &form,
        &minimized_configuration,
    )?;
    let report = triage_property_evidence_for_violation(
        model_finding.clone(),
        finding_export_violation(&model_finding, PROPERTY)?,
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
    let reproduction_payload =
        crucible_daemon::crucible_reproduction_payload(&model_finding.artifact)?;
    assert_eq!(
        model_finding.artifact.scenario_form().id().to_hex(),
        scenario.to_hex()
    );
    assert_eq!(configuration.id().to_hex(), child.to_hex());
    assert_eq!(
        model_finding.artifact.id().to_hex(),
        crucible_engine::ContentHash::from_bytes(&model_finding.artifact.to_compact_binary())
            .to_hex()
    );
    publish_reproduction_segments(&repository, &model_finding.artifact)?;
    publish_reproduction_segments(&repository, &minimized_model_finding.artifact)?;
    let original = repository.publish_reproduction_artifact(
        scenario,
        scenario_artifact,
        child,
        child_artifact,
        campaign_fingerprint,
        reproduction_payload.clone(),
    )?;
    let replayed_state = CampaignHash::from_bytes(minimized_model_finding.replay.state.bytes);
    let minimization = FindingMinimizationEvidence::new(
        original,
        4,
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
        crucible_daemon::crucible_reproduction_payload(&minimized_model_finding.artifact)?,
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
    let native_replay = ::crucible_engine::test_support::replay_evidence_for_test(
        report.finding.clone(),
        report.failure.clone(),
        &report.causal_entries,
        report.recorded_event_log.coverage_fingerprint(),
    )?;
    let minimized_report = triage_evidence_for_finding(minimized_model_finding.clone(), &report)?;
    let minimized_native_replay = ::crucible_engine::test_support::replay_evidence_for_test(
        minimized_report.finding.clone(),
        minimized_report.failure.clone(),
        &minimized_report.causal_entries,
        minimized_report.recorded_event_log.coverage_fingerprint(),
    )?;
    let mut verification_entries = minimized_report.causal_entries.clone();
    // A later diagnostic distinguishes the independent replay's raw log while
    // preserving the exact causal failure and its host-checked violation.
    verification_entries.push(finding_export_observational_entry(
        "finding-export-verification-complete",
    ));
    let verification_selected_native_replay =
        ::crucible_engine::test_support::replay_evidence_for_test(
            minimized_report.finding.clone(),
            minimized_report.failure.clone(),
            &verification_entries,
            minimized_report.recorded_event_log.coverage_fingerprint(),
        )?;
    assert_eq!(
        minimized_native_replay.signature(),
        verification_selected_native_replay.signature()
    );
    assert_ne!(
        minimized_native_replay.to_compact_binary()?,
        verification_selected_native_replay.to_compact_binary()?
    );

    // Each record's log segments are published before the record that names
    // them, as the repository requires.
    let publish_triage_replay = |reproduction,
                                 observed_signature: &FindingSignature,
                                 native: &crucible_engine::FailureTriageReplayEvidence|
     -> Result<_, Box<dyn Error>> {
        let evidence = finding_export_triage_record(reproduction, observed_signature, native)?;
        for segment in evidence.log_segments() {
            let bytes = crucible_engine::SegmentSource::segment(
                native.log_segments().as_ref(),
                segment.content(),
            )?;
            repository.publish_finding_triage_replay_log_segment(*segment, &bytes)?;
        }
        Ok(repository.publish_finding_triage_replay_evidence(&evidence)?)
    };
    let triage_evidence = FindingTriageEvidenceSet::new(
        publish_triage_replay(original, &signature, &native_replay)?,
        publish_triage_replay(minimized, &minimized_signature, &minimized_native_replay)?,
        publish_triage_replay(original, &signature, &native_replay)?,
        publish_triage_replay(
            minimized,
            &minimized_signature,
            &verification_selected_native_replay,
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
    let portable_root = tempfile::tempdir()?;
    let portable_bundle = portable_root.path().join("finding");
    let evidence_store = crucible_engine::LocalDagStore::new(portable_bundle.join("evidence"));
    let record = capture_finding(
        &client,
        "operator:cli-campaign-findings",
        published.new_snapshot,
        published.finding,
        Some(report.clone()),
        &evidence_store,
    )?;
    // The service-derived report projection is the one supplied above, so both
    // captures write byte-identical evidence and share one record identity.
    let service_record = capture_finding(
        &client,
        "operator:cli-campaign-findings",
        published.new_snapshot,
        published.finding,
        None,
        &evidence_store,
    )?;
    assert_eq!(service_record, record);

    let artifact_dir = tempfile::tempdir()?;
    let bytes = crate::cli_triage_debug::campaign_evidence::campaign_findings_ledger_bytes(&[(
        published.finding,
        record,
    )])?;
    let executable = repository.plan_campaign_archive(
        published.new_snapshot,
        CampaignArchivePolicy::Executable,
        [],
        None,
    )?;
    repository.stage_campaign_archive_metadata(&executable)?;
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
    let archived_finding =
        private_archive.inspect_archived_finding(executable.manifest_id(), published.finding)?;
    let bundle_manifest = |archive: String| {
        format!(
            "crucible.campaign.finding-bundle.v3\narchive_manifest={archive}\nledger={}\n",
            crucible_engine::ContentHash::from_bytes(&bytes).to_hex()
        )
    };
    std::fs::write(
        portable_bundle.join("manifest"),
        bundle_manifest(executable.manifest_id().to_string()),
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
    let verify_cli = <crate::Cli as clap::Parser>::try_parse_from([
        std::ffi::OsString::from("crucible"),
        std::ffi::OsString::from("campaign"),
        std::ffi::OsString::from("finding-bundle"),
        std::ffi::OsString::from("verify"),
        portable_bundle.as_os_str().to_owned(),
    ])?;
    let crate::Commands::Campaign(campaign) = &verify_cli.command else {
        return Err(std::io::Error::other("missing parsed campaign command").into());
    };
    let error = crate::cli_campaign::run_campaign_invocation(&verify_cli, campaign)
        .err()
        .ok_or_else(|| std::io::Error::other("external archive unexpectedly verified"))?;
    assert!(error.to_string().contains("symlink"));
    std::fs::remove_file(archive_root.join("objects"))?;
    std::fs::rename(&external_objects, archive_root.join("objects"))?;

    // A bundle whose ledger file differs from the hash its manifest names, or
    // whose evidence prefix directory resolves elsewhere, fails closed.
    std::fs::write(
        portable_bundle.join("manifest"),
        bundle_manifest(executable.manifest_id().to_string()).replace(
            &crucible_engine::ContentHash::from_bytes(&bytes).to_hex(),
            &record.to_hex(),
        ),
    )?;
    let error = crate::cli_campaign::run_campaign_invocation(&verify_cli, campaign)
        .err()
        .ok_or_else(|| std::io::Error::other("mismatched ledger unexpectedly verified"))?;
    assert!(error.to_string().contains("differs from its manifest"));
    std::fs::write(
        portable_bundle.join("manifest"),
        bundle_manifest(executable.manifest_id().to_string()),
    )?;
    let record_prefix = evidence_store
        .object_path(&record)
        .parent()
        .map(std::path::Path::to_path_buf)
        .ok_or_else(|| std::io::Error::other("record object has no prefix directory"))?;
    let external_prefix = portable_root.path().join("external-prefix");
    std::fs::rename(&record_prefix, &external_prefix)?;
    std::os::unix::fs::symlink(&external_prefix, &record_prefix)?;
    let error = crate::cli_campaign::run_campaign_invocation(&verify_cli, campaign)
        .err()
        .ok_or_else(|| std::io::Error::other("external evidence unexpectedly verified"))?;
    assert!(error.to_string().contains("not a directory"));
    std::fs::remove_file(&record_prefix)?;
    std::fs::rename(&external_prefix, &record_prefix)?;

    let plan = repository.plan_campaign_archive(
        published.new_snapshot,
        CampaignArchivePolicy::Findings,
        [],
        None,
    )?;
    let invalid_bundle = portable_root.path().join("invalid-finding");
    std::fs::create_dir_all(invalid_bundle.join("archive"))?;
    capture_finding(
        &client,
        "operator:cli-campaign-findings",
        published.new_snapshot,
        published.finding,
        None,
        &crucible_engine::LocalDagStore::new(invalid_bundle.join("evidence")),
    )?;
    std::fs::write(
        invalid_bundle.join("manifest"),
        bundle_manifest(plan.manifest_id().to_string()),
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
    let artifact_store = crucible_engine::LocalDagStore::new(store_temp.path().join("store"));
    let load = |ledger: &[u8]| {
        crate::cli_triage_debug::campaign_evidence::load_campaign_findings_ledger_bytes(
            &evidence_store,
            &artifact_store,
            ledger,
        )
    };
    let loaded = load(&bytes)?;
    let loaded_finding = loaded.evidence.finding(0)?;
    assert_eq!(loaded.evidence.finding_count(), 1);
    assert_eq!(loaded_finding.finding, archived_finding);
    assert_eq!(loaded_finding.report, report);
    assert_eq!(loaded_finding.occurrence_count, 1);
    assert_eq!(loaded.ledger.signed_findings().len(), 1);
    let ledger_text = std::str::from_utf8(&bytes)?;
    for rejected in [
        ledger_text.replacen(
            "crucible.failure-triage.findings-ledger.v5",
            "crucible.failure-triage.findings-ledger.v4",
            1,
        ),
        ledger_text.replacen("ledger_kind=campaign", "ledger_kind=reproduction", 1),
    ] {
        assert!(load(rejected.as_bytes()).is_err());
    }
    assert_eq!(
        loaded.ledger.signed_findings()[0].signature,
        native_replay.signature().clone()
    );
    assert!(
        loaded
            .evidence
            .member(model_finding.artifact.id())?
            .ok_or_else(|| std::io::Error::other("missing clustered member"))?
            .retains_occurrence_replays()
    );
    let policy = crucible_engine::SignaturePolicy::exact();
    let clustering = crucible_engine::FailureClusteringResult::from_findings(
        policy,
        loaded.ledger.signed_findings().iter().cloned(),
    )?;
    let triage_plan = TriageInvocationPlan {
        policy,
        minimize: TriageMinimizeArg::All,
        report_dir: artifact_dir.path().join("reports"),
        format: crucible_engine::FailureClusterReportFormat::JsonLines,
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

    // Substituting another principal's authenticated segment response, even
    // under a fully re-hashed chunk, record, and ledger, fails authentication.
    let other_record = capture_finding(
        &client,
        "operator:other-cli-campaign-findings",
        published.new_snapshot,
        published.finding,
        Some(report.clone()),
        &evidence_store,
    )?;
    let segment_field = "occurrence.0.verification_selected.segment.0";
    let response = stored_field(&evidence_store, record, segment_field)?;
    let wrong_response = stored_field(&evidence_store, other_record, segment_field)?;
    assert_ne!(response, wrong_response);
    let (_, response_hash) = response
        .split_once(' ')
        .ok_or_else(|| std::io::Error::other("malformed segment exchange"))?;
    let (_, wrong_response_hash) = wrong_response
        .split_once(' ')
        .ok_or_else(|| std::io::Error::other("malformed segment exchange"))?;
    let tampered = rewrite_first_chunk(&evidence_store, record, |chunk| {
        chunk.replacen(response_hash, wrong_response_hash, 1)
    })?;
    assert!(load(&ledger_with_record(&bytes, record, tampered)?).is_err());

    // A chunk that lists one more segment exchange than the replay's storage
    // description requires is rejected even though every hash resolves.
    let role = "occurrence.0.verification_selected";
    let segment_count = stored_field(&evidence_store, record, &format!("{role}.segment_count"))?
        .parse::<usize>()?;
    let last_field = format!("{role}.segment.{}", segment_count - 1);
    let last_segment = stored_field(&evidence_store, record, &last_field)?;
    let extra_segment = rewrite_first_chunk(&evidence_store, record, |chunk| {
        chunk
            .replacen(
                &format!("{role}.segment_count={segment_count}\n"),
                &format!("{role}.segment_count={}\n", segment_count + 1),
                1,
            )
            .replacen(
                &format!("{last_field}={last_segment}\n"),
                &format!(
                    "{last_field}={last_segment}\n{role}.segment.{segment_count}={last_segment}\n"
                ),
                1,
            )
    })?;
    assert!(matches!(
        load(&ledger_with_record(&bytes, record, extra_segment)?),
        Err(CliError::Artifact(message)) if message.contains("transfer bounds are invalid")
    ));

    // Corrupted and missing evidence blobs fail closed.
    let damaged_store = crucible_engine::LocalDagStore::new(store_temp.path().join("damaged"));
    let damaged_record = capture_finding(
        &client,
        "operator:cli-campaign-findings",
        published.new_snapshot,
        published.finding,
        None,
        &damaged_store,
    )?;
    assert_eq!(damaged_record, record);
    let page_field = stored_field(&damaged_store, record, "occurrence.0.page")?;
    let (_, page_response) = page_field
        .split_once(' ')
        .ok_or_else(|| std::io::Error::other("malformed page exchange"))?;
    let page_response = parse_hash(page_response)?;
    std::fs::write(damaged_store.object_path(&page_response), b"corrupt")?;
    let load_damaged = || {
        crate::cli_triage_debug::campaign_evidence::load_campaign_findings_ledger_bytes(
            &damaged_store,
            &artifact_store,
            &bytes,
        )
    };
    assert!(load_damaged().is_err());
    std::fs::remove_file(damaged_store.object_path(&page_response))?;
    assert!(load_damaged().is_err());
    std::fs::remove_file(damaged_store.object_path(&record))?;
    assert!(matches!(
        load_damaged(),
        Err(CliError::Artifact(message)) if message.contains("is missing finding evidence record")
    ));

    let mut alternate_selected_entries = minimized_report.causal_entries.clone();
    alternate_selected_entries.push(finding_export_observational_entry(
        "finding-export-second-valid-occurrence",
    ));
    let alternate_selected_replay = ::crucible_engine::test_support::replay_evidence_for_test(
        minimized_report.finding.clone(),
        minimized_report.failure.clone(),
        &alternate_selected_entries,
        minimized_report.recorded_event_log.coverage_fingerprint(),
    )?;
    assert_eq!(
        alternate_selected_replay.signature(),
        minimized_native_replay.signature()
    );
    let alternate_selected =
        publish_triage_replay(minimized, &minimized_signature, &alternate_selected_replay)?;
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
    let duplicate_record = capture_finding(
        &client,
        "operator:cli-campaign-findings",
        duplicate_published.new_snapshot,
        duplicate_published.finding,
        Some(report.clone()),
        &evidence_store,
    )?;
    let duplicate_loaded = load(
        &crate::cli_triage_debug::campaign_evidence::campaign_findings_ledger_bytes(&[(
            duplicate_published.finding,
            duplicate_record,
        )])?,
    )?;
    assert_eq!(duplicate_loaded.ledger.signed_findings().len(), 1);
    assert_eq!(duplicate_loaded.evidence.finding(0)?.occurrence_count, 2);

    // Distinct coverage changes only the native signature's coverage class and
    // evidence binding, which the campaign signature does not carry.
    let coverage_distinct_replay = ::crucible_engine::test_support::replay_evidence_for_test(
        report.finding.clone(),
        report.failure.clone(),
        &report.causal_entries,
        crucible_engine::ContentHash::from_bytes(b"distinct authenticated replay coverage"),
    )?;
    assert_ne!(
        coverage_distinct_replay.signature(),
        native_replay.signature()
    );
    let coverage_distinct_original =
        publish_triage_replay(original, &signature, &coverage_distinct_replay)?;
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
            coverage_distinct_original,
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
    let conflicting_record = capture_finding(
        &client,
        "operator:cli-campaign-findings",
        conflicting_published.new_snapshot,
        conflicting_published.finding,
        Some(report.clone()),
        &evidence_store,
    )?;
    assert!(matches!(
        load(
            &crate::cli_triage_debug::campaign_evidence::campaign_findings_ledger_bytes(&[(
                conflicting_published.finding,
                conflicting_record,
            )])?
        ),
        Err(CliError::Artifact(message))
            if message.contains("conflicting authenticated native signatures")
    ));

    let foreign_report = triage_property_evidence_for_violation(
        model_finding.clone(),
        finding_export_violation(&model_finding, FOREIGN_PROPERTY)?,
    )?;
    let foreign_native_replay = ::crucible_engine::test_support::replay_evidence_for_test(
        foreign_report.finding,
        foreign_report.failure,
        &foreign_report.causal_entries,
        foreign_report.recorded_event_log.coverage_fingerprint(),
    )?;
    assert_ne!(
        foreign_native_replay.signature().property,
        native_replay.signature().property
    );

    // In isolation, a record whose native payload names another property is
    // refused by the signature binding alone.
    let foreign_evidence =
        finding_export_triage_record(original, &signature, &foreign_native_replay)?;
    assert!(matches!(
        crate::cli_triage_debug::campaign_evidence::decode_campaign_triage_replay_record(
            &foreign_evidence,
            &repository.load_reproduction_artifact(original)?,
            model_finding.clone(),
            foreign_native_replay.log_segments().clone(),
        ),
        Err(CliError::Artifact(message))
            if message.contains("disagrees with its observed campaign signature")
    ));

    let foreign_original = publish_triage_replay(original, &signature, &foreign_native_replay)?;
    assert_eq!(foreign_original, foreign_evidence.id()?);
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
    // Capture only records exchanges; the ledger load authenticates them.
    let foreign_record = capture_finding(
        &client,
        "operator:cli-campaign-findings",
        foreign_published.new_snapshot,
        foreign_published.finding,
        Some(report),
        &evidence_store,
    )?;
    // The finding still holds the coverage-distinct occurrence above, and
    // occurrence pages follow candidate-bundle identity. Whichever of the two
    // tampered occurrences is authenticated first refuses the ledger.
    assert!(matches!(
        load(
            &crate::cli_triage_debug::campaign_evidence::campaign_findings_ledger_bytes(&[(
                foreign_published.finding,
                foreign_record,
            )])?
        ),
        Err(CliError::Artifact(message))
            if message.contains("disagrees with its observed campaign signature")
                || message.contains("conflicting authenticated native signatures")
    ));
    Ok(())
}

fn finding_export_violation(
    finding: &crucible_engine::FindingReproductionArtifact,
    property: &str,
) -> Result<crucible_model::HostAssertionViolation, Box<dyn Error>> {
    let scenario = finding.artifact.scenario_form();
    let entry = crucible_engine::SchedulerEventLogEntry::assertion_state_observation(
        0,
        crucible_engine::VirtualTime { ticks: 7 },
        crucible_engine::AssertionId::from_name(property),
        crucible_engine::AssertionPhase::Violated,
    );
    let report = ::crucible_engine::OfflineAssertionChecker::new()
        .with_world_white_box_policies(scenario.world())
        .check_run(scenario.properties(), &[entry])?;
    let mut violation = report
        .violations()
        .iter()
        .find(|violation| violation.assertion.name == property)
        .cloned()
        .ok_or_else(|| std::io::Error::other("fixture assertion did not fail at its boundary"))?;
    violation.reproduction_artifact = finding.artifact.id();
    Ok(violation)
}

/// Builds the campaign record of `native`, naming each of its log segments.
fn finding_export_triage_record(
    reproduction: crucible_campaign::ReproductionArtifactId,
    observed_signature: &crucible_campaign::FindingSignature,
    native: &crucible_engine::FailureTriageReplayEvidence,
) -> Result<crucible_campaign::FindingTriageReplayEvidence, Box<dyn Error>> {
    let log_segments = native
        .referenced_segments()
        .iter()
        .map(|segment| {
            crucible_campaign::FindingTriageReplayLogSegment::new(segment.id, segment.encoded_bytes)
        })
        .collect::<Result<Vec<_>, _>>()?;
    Ok(
        crucible_campaign::FindingTriageReplayEvidence::new_with_log_segments(
            reproduction,
            observed_signature.clone(),
            crucible_engine::FAILURE_TRIAGE_REPLAY_EVIDENCE_SCHEMA_VERSION,
            native.to_compact_binary()?,
            log_segments,
        )?,
    )
}

fn finding_export_observational_entry(name: &str) -> crucible_engine::SchedulerEventLogEntry {
    crucible_engine::SchedulerEventLogEntry::diagnostic(
        1,
        crucible_engine::VirtualTime { ticks: 8 },
        crucible_engine::EventDiagnosticPayload::new(
            name,
            crucible_engine::EventLevel::Info,
            Default::default(),
        ),
    )
}
