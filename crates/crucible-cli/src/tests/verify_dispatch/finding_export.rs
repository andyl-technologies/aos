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

pub(super) fn campaign_findings_v4_round_trip_authenticates_occurrence_objects_and_tampering()
-> Result<(), Box<dyn Error>> {
    use std::collections::{BTreeMap, BTreeSet};
    use std::sync::Arc;

    use crucible_campaign::{
        BudgetGrant, CampaignClient, CampaignCommandId, CampaignControlAction, CampaignHash,
        CampaignLineage, CampaignMode, CampaignName, CampaignPolicy, CampaignPrincipal,
        CampaignRepository, CampaignSeed, ConfigurationId, ControlRequest, CoverageProjection,
        ExplorerPolicy, FairnessPolicy, FindingCandidateBundle, FindingExactPins,
        FindingExactRetention, FindingExactRetentionDisposition, FindingExactRetentionIncomplete,
        FindingKind, FindingMinimizationAttempt, FindingMinimizationEvidence, FindingSignature,
        FindingSignatureMinimizationEvidence, FindingTarget, FindingTriageEvidenceSet,
        FindingTriageReplayEvidence, MeasurementSet, Observation, PropertyEvidence,
        PropertyVerdict, PropertyVerdictSet, RepositoryCampaignService, RetentionPolicy,
        ScenarioDefId, StopOutcome,
    };
    use crucible_cas::content_store::{MemoryBlobBackend, MemoryRefBackend};

    const CAMPAIGN: &str = "cli-v4-finding-export";
    const PROPERTY: &str = "cli-v4-property";

    let form = search_frontier_scenario_form()?;
    let configuration = crucible::Configuration {
        def: form.scenario_def(),
        schedule: crucible::Schedule::from_decisions(search_frontier_decisions()),
    };
    let minimized_configuration = crucible::Configuration::genesis(form.scenario_def());
    let fingerprint = crucible::ContentHash::from_bytes(b"cli-v4-finding-fingerprint");
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
            message: String::from("CLI V4 property violated"),
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
        Arc::new(MemoryBlobBackend::new("cli-v4-finding-export", u64::MAX)),
        Arc::new(MemoryRefBackend::new()),
    );
    let scenario =
        ScenarioDefId::from_hash(CampaignHash::from_bytes(form.scenario_def().id().bytes));
    let scenario_artifact =
        repository.publish_scenario_artifact(scenario, 1, form.to_compact_binary())?;
    let genesis = ConfigurationId::from_hash(CampaignHash::derive(
        "cli-v4-test-configuration",
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
        "cli-v4-engine",
        "cli-v4-qemu",
        BTreeMap::from([(String::from("control"), 1)]),
        1,
        1,
    )?;
    let policy = CampaignPolicy::new(
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
        FairnessPolicy::new(0, 0)?,
        RetentionPolicy::new(true, 1, true, true),
        true,
    )?;
    let created = repository.create(CAMPAIGN, &lineage, &policy, &BTreeMap::new())?;
    let resumed = repository.apply_control(
        CAMPAIGN,
        &ControlRequest {
            command: CampaignCommandId::from_hash(CampaignHash::derive(
                "cli-v4-test-command",
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
                "cli-v4-test-command",
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
    let measurements =
        repository.publish_measurement_set(&MeasurementSet::new(BTreeMap::new())?)?;
    let properties =
        repository.publish_property_verdict_set(&PropertyVerdictSet::new(BTreeMap::from([(
            String::from(PROPERTY),
            PropertyEvidence::new(PropertyVerdict::Failed, BTreeSet::new())?,
        )]))?)?;
    let coverage = repository
        .publish_coverage_projection(&CoverageProjection::new(BTreeSet::new(), BTreeSet::new())?)?;
    let observation = Observation::new(
        attempt,
        child,
        child_artifact,
        attempt_record.path(),
        StopOutcome::AssertionFailure(String::from(PROPERTY)),
        measurements,
        properties,
        coverage,
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
        FindingExactRetentionDisposition::Incomplete(
            FindingExactRetentionIncomplete::MissingSafeBoundaryCapture,
        ),
    )?;
    let observed = repository.publish_observation(CAMPAIGN, observation_snapshot, &observation)?;
    let campaign_fingerprint = CampaignHash::from_bytes(fingerprint.bytes);
    let reproduction_payload = model_finding.artifact.to_compact_binary();
    let original = repository.publish_reproduction_artifact(
        scenario,
        scenario_artifact,
        child,
        child_artifact,
        campaign_fingerprint,
        1,
        reproduction_payload.clone(),
    )?;
    let replayed_state = CampaignHash::from_bytes(minimized_model_finding.replay.state.bytes);
    let minimization = FindingMinimizationEvidence::new(
        original,
        1,
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
        1,
        minimized_model_finding.artifact.to_compact_binary(),
        minimization.clone(),
    )?;
    let signature = FindingSignature::new(
        FindingKind::PropertyViolation,
        campaign_fingerprint,
        Some(String::from(PROPERTY)),
        String::from("cli.v4-property-violation"),
        Some(FindingTarget::Configuration(child_artifact)),
        BTreeSet::from([properties.content_id()]),
    )?;
    let minimized_signature = FindingSignature::new(
        FindingKind::PropertyViolation,
        campaign_fingerprint,
        Some(String::from(PROPERTY)),
        String::from("cli.v4-property-violation"),
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
        observed.observation,
        signature.clone(),
        original,
        minimized,
        signature_minimization.clone(),
        FindingExactPins::default(),
        Some(triage_evidence),
        None,
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
        CampaignPrincipal::new("operator:cli-v4")?,
        CampaignName::new(CAMPAIGN)?,
        published.new_snapshot,
        published.finding,
        report,
    )?;

    let alternate_fingerprint =
        crucible::ContentHash::from_bytes(b"cli-v4-shared-artifact-alternate-fingerprint");
    let alternate_finding = crucible::FindingReproductionArtifact::capture(
        crucible::FindingDiscoveryPath::StateSpaceSearch,
        alternate_fingerprint,
        &form,
        &configuration,
    )?;
    assert_eq!(
        alternate_finding.artifact.id(),
        evidence.report.finding.artifact.id(),
        "a model reproduction identity does not include the finding signature"
    );
    let alternate_report = triage_property_evidence_for_violation(
        alternate_finding.clone(),
        crucible_model::HostAssertionViolation {
            assertion: crucible::AssertionId::from_name("cli-v4-alternate-property"),
            message: String::from("another failure shares the model reproduction"),
            quantifier: crucible::AssertionQuantifierKind::Always,
            event_kind: String::from("assertion_state_changed"),
            at_icount: Some(crucible::Icount { retired: 7 }),
            at_virtual_time: crucible::VirtualTime { ticks: 7 },
            node: None,
            detail: String::from("report selection must include finding identity"),
            reproduction_artifact: alternate_finding.artifact.id(),
        },
    )?;
    assert_eq!(
        crate::cli_triage_debug::campaign_evidence::guarded_finding_report(
            0,
            &evidence.finding,
            &evidence.reproduction,
            &[alternate_report, evidence.report.clone()],
        )?,
        evidence.report,
    );

    let finding_id = evidence.finding.id()?;
    let guarded_request = crucible_campaign::QueryCampaignFindingsRequest::new(
        CampaignPrincipal::new("operator:cli-v4")?,
        CampaignName::new(CAMPAIGN)?,
        published.new_snapshot,
        None,
        1,
    )?;
    let guarded_membership = CampaignFindingsMembershipProof {
        response: client.query_campaign_findings(&guarded_request)?,
        request: guarded_request,
    };
    let query_pages = vec![guarded_membership.clone()];
    let finding_pages = vec![(finding_id, guarded_membership)];
    assert_eq!(
        crate::cli_triage_debug::campaign_evidence::validate_guarded_finding_query_chain_parts(
            &evidence.campaign,
            evidence.snapshot,
            &query_pages,
            &finding_pages,
        )?,
        query_pages,
    );
    let missing_page =
        crate::cli_triage_debug::campaign_evidence::validate_guarded_finding_query_chain_parts(
            &evidence.campaign,
            evidence.snapshot,
            &[],
            &finding_pages,
        )
        .expect_err("an incomplete guarded query chain must be rejected before V4 rendering");
    assert!(
        missing_page
            .to_string()
            .contains("no authenticated query page")
    );

    let artifact_dir = tempfile::tempdir()?;
    let (_, _, bytes) =
        crate::cli_triage_debug::campaign_evidence::write_failure_findings_ledger_v4(
            artifact_dir.path(),
            None,
            std::slice::from_ref(&evidence),
        )?;
    let exact_boundary =
        crate::cli_triage_debug::campaign_evidence::failure_findings_ledger_v4_bytes_with_test_limit(
            std::slice::from_ref(&evidence),
            bytes.len(),
        )?;
    assert_eq!(exact_boundary, bytes);
    let one_byte_too_large =
        crate::cli_triage_debug::campaign_evidence::failure_findings_ledger_v4_bytes_with_test_limit(
            std::slice::from_ref(&evidence),
            bytes.len() - 1,
        )
        .expect_err("the complete V4 artifact must be rejected one byte beyond its bound");
    assert!(
        one_byte_too_large
            .to_string()
            .contains(&format!("exceeds {} bytes", bytes.len() - 1))
    );
    let store_temp = tempfile::tempdir()?;
    let store = crucible::LocalDagStore::new(store_temp.path().join("store"));
    let loaded = parse_failure_findings_ledger_bytes(&store, &bytes)?;
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
        findings: TriageFindingsSource::Path(artifact_dir.path().join("unused")),
        policy,
        minimize: TriageMinimizeArg::All,
        report_dir: artifact_dir.path().join("reports"),
        format: crucible::FailureClusterReportFormat::JsonLines,
        recompute_signatures: true,
        compare: None,
        store_root: store_temp.path().join("triage-store"),
        pipeline: vec![
            TriagePipelineStep::LoadFindingsLedger,
            TriagePipelineStep::RecomputeSignatureSelfCheck,
            TriagePipelineStep::Cluster,
            TriagePipelineStep::MinimizeAll,
            TriagePipelineStep::EmitReports,
            TriagePipelineStep::StoreTriageResult,
        ],
        failure_exit_code: 1,
        thin_driver: true,
        owns_run_state: false,
        offline: true,
        scheduler_started: false,
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
            CampaignPrincipal::new("operator:other-cli-v4")?,
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
            .segments[0]
            .response
            .canonical_bytes(),
    );
    let wrong_response = ledger_hex(
        &other_evidence.occurrence_proofs[0]
            .triage_evidence
            .as_ref()
            .ok_or_else(|| std::io::Error::other("missing native triage evidence"))?
            .verification_selected
            .segments[0]
            .response
            .canonical_bytes(),
    );
    assert_ne!(response, wrong_response);
    let tampered = text.replacen(&response, &wrong_response, 1);
    assert!(parse_failure_findings_ledger_bytes(&store, tampered.as_bytes()).is_err());

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
        observed.observation,
        signature.clone(),
        original,
        minimized,
        signature_minimization.clone(),
        FindingExactPins::default(),
        Some(FindingTriageEvidenceSet::new(
            triage_evidence.minimization_original(),
            triage_evidence.minimization_selected(),
            triage_evidence.verification_original(),
            alternate_selected,
        )),
        None,
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
            CampaignPrincipal::new("operator:cli-v4")?,
            CampaignName::new(CAMPAIGN)?,
            duplicate_published.new_snapshot,
            duplicate_published.finding,
            evidence.report.clone(),
        )?;
    assert_eq!(duplicate_evidence.occurrence_proofs.len(), 2);
    let (_, _, duplicate_bytes) =
        crate::cli_triage_debug::campaign_evidence::write_failure_findings_ledger_v4(
            artifact_dir.path(),
            None,
            std::slice::from_ref(&duplicate_evidence),
        )?;
    let duplicate_loaded = parse_failure_findings_ledger_bytes(&store, &duplicate_bytes)?;
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
        observed.observation,
        signature.clone(),
        original,
        minimized,
        signature_minimization.clone(),
        FindingExactPins::default(),
        Some(FindingTriageEvidenceSet::new(
            frame_distinct_original,
            triage_evidence.minimization_selected(),
            triage_evidence.verification_original(),
            triage_evidence.verification_selected(),
        )),
        None,
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
            CampaignPrincipal::new("operator:cli-v4")?,
            CampaignName::new(CAMPAIGN)?,
            conflicting_published.new_snapshot,
            conflicting_published.finding,
            evidence.report.clone(),
        )?;
    let (_, _, conflicting_bytes) =
        crate::cli_triage_debug::campaign_evidence::write_failure_findings_ledger_v4(
            artifact_dir.path(),
            None,
            std::slice::from_ref(&conflicting_evidence),
        )?;
    assert!(matches!(
        parse_failure_findings_ledger_bytes(&store, &conflicting_bytes),
        Err(CliError::Artifact(message))
            if message.contains("conflicting authenticated native signatures")
    ));

    let foreign_report = triage_property_evidence_for_violation(
        model_finding.clone(),
        crucible_model::HostAssertionViolation {
            assertion: crucible::AssertionId::from_name("cli-v4-foreign-property"),
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
        observed.observation,
        signature,
        original,
        minimized,
        signature_minimization,
        FindingExactPins::default(),
        Some(FindingTriageEvidenceSet::new(
            foreign_original,
            triage_evidence.minimization_selected(),
            triage_evidence.verification_original(),
            triage_evidence.verification_selected(),
        )),
        None,
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
            CampaignPrincipal::new("operator:cli-v4")?,
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
