//! Schema-registry completeness and compatibility assertions.

use super::*;

pub(super) fn schema_registry_is_unique_complete_and_names_real_gates() {
    let registry =
        include_str!("../../../../docs/rfcs/0020-crucible-campaigns/schema-registry.tsv");
    let implementation_plan =
        include_str!("../../../../docs/rfcs/0020-crucible-campaigns/11-implementation-plan.md");
    let mut rows = BTreeMap::<&str, Vec<&str>>::new();
    for (line_number, line) in registry.lines().enumerate() {
        if line.is_empty() || line.starts_with('#') {
            continue;
        }
        let fields = line.split('\t').collect::<Vec<_>>();
        assert_eq!(
            fields.len(),
            5,
            "registry line {} must contain five tab-separated fields",
            line_number + 1
        );
        assert!(
            fields[1].parse::<u32>().is_ok_and(|version| version > 0),
            "{} has an invalid version",
            fields[0]
        );
        assert!(!fields[2].is_empty(), "{} has no schema owner", fields[0]);
        for gate in fields[4].split(',') {
            assert!(
                gate.starts_with("gate:") && implementation_plan.contains(gate),
                "{} names unknown compatibility gate {gate}",
                fields[0]
            );
        }
        assert!(
            rows.insert(fields[0], fields).is_none(),
            "duplicate schema registry entry {line}"
        );
    }

    for kind in CampaignRecordKind::ALL {
        let row = rows
            .get(kind.schema_name())
            .unwrap_or_else(|| panic!("missing campaign schema {}", kind.schema_name()));
        assert_eq!(
            row[1].parse::<u32>().expect("validated schema version"),
            kind.schema_version()
        );
        let expected_owner = match kind {
            CampaignRecordKind::MerkleNode => "crucible-campaign::merkle",
            CampaignRecordKind::ScenarioArtifact | CampaignRecordKind::ConfigurationArtifact => {
                "crucible-campaign::artifact"
            }
            CampaignRecordKind::BranchRequest
            | CampaignRecordKind::Proposal
            | CampaignRecordKind::BranchPath
            | CampaignRecordKind::Attempt
            | CampaignRecordKind::AttemptAdmission
            | CampaignRecordKind::PlannerStep
            | CampaignRecordKind::ExpansionState
            | CampaignRecordKind::ContinuationProjection
            | CampaignRecordKind::ExpansionCredit => "crucible-campaign::exploration",
            CampaignRecordKind::MeasurementSet
            | CampaignRecordKind::PropertyVerdictSet
            | CampaignRecordKind::CoverageProjection
            | CampaignRecordKind::Observation => "crucible-campaign::observation",
            CampaignRecordKind::ObjectiveEvaluation
            | CampaignRecordKind::RankingExplanation
            | CampaignRecordKind::SurvivorSelection => "crucible-campaign::objective",
            CampaignRecordKind::ReproductionArtifact | CampaignRecordKind::Finding => {
                "crucible-campaign::finding"
            }
            CampaignRecordKind::FindingCandidateBundle => "crucible-campaign::finding_candidate",
            CampaignRecordKind::FindingTriageReplayEvidence
            | CampaignRecordKind::FindingTriageReplayEvidenceChunk => {
                "crucible-campaign::finding_triage_evidence"
            }
            CampaignRecordKind::ArchiveManifest | CampaignRecordKind::ArchiveInventoryPage => {
                "crucible-campaign::archive"
            }
            _ => "crucible-campaign::object",
        };
        assert_eq!(row[2], expected_owner);
        assert_eq!(row[3], kind.object_kind().as_str());
    }
    assert_eq!(
        rows.get("crucible.campaign.fact")
            .expect("missing campaign fact schema")[1],
        "14"
    );
    let mut owned_campaign_schemas = CampaignRecordKind::ALL
        .into_iter()
        .map(CampaignRecordKind::schema_name)
        .collect::<BTreeSet<_>>();
    let planner_result = rows
        .get("crucible.campaign.planner-step-proposal")
        .expect("missing planner result component schema");
    assert_eq!(planner_result[1], "1");
    assert_eq!(planner_result[2], "crucible-campaign::exploration");
    assert_eq!(planner_result[3], "component-message");
    owned_campaign_schemas.insert("crucible.campaign.planner-step-proposal");
    for schema in [
        "crucible.campaign.planner-request",
        "crucible.campaign.planner-response",
    ] {
        let message = rows
            .get(schema)
            .unwrap_or_else(|| panic!("missing planner service schema {schema}"));
        assert_eq!(message[1], "1");
        assert_eq!(message[2], "crucible-campaign::planner_service");
        assert_eq!(message[3], "component-message");
        owned_campaign_schemas.insert(schema);
    }
    for schema in [
        "crucible.campaign.planner-submission",
        "crucible.campaign.debugger-submission",
    ] {
        let submission = rows
            .get(schema)
            .unwrap_or_else(|| panic!("missing component schema {schema}"));
        assert_eq!(submission[1], "1");
        assert_eq!(submission[2], "crucible-campaign::authority");
        assert_eq!(submission[3], "component-message");
        owned_campaign_schemas.insert(schema);
    }
    for schema in [
        "crucible.campaign.attempt-execution-scope",
        "crucible.campaign.submit-attempt-request",
        "crucible.campaign.submit-attempt-response",
        "crucible.campaign.get-attempt-execution-request",
        "crucible.campaign.get-attempt-execution-response",
        "crucible.campaign.resume-attempt-execution-request",
        "crucible.campaign.resume-attempt-execution-response",
        "crucible.campaign.cancel-attempt-execution-request",
        "crucible.campaign.cancel-attempt-execution-response",
        "crucible.campaign.checkpoint-attempt-execution-request",
        "crucible.campaign.checkpoint-attempt-execution-response",
    ] {
        let message = rows
            .get(schema)
            .unwrap_or_else(|| panic!("missing executor component schema {schema}"));
        let expected_version = match schema {
            "crucible.campaign.attempt-execution-scope" => "1",
            "crucible.campaign.submit-attempt-request" => "6",
            "crucible.campaign.resume-attempt-execution-request" => "6",
            "crucible.campaign.get-attempt-execution-request"
            | "crucible.campaign.cancel-attempt-execution-request"
            | "crucible.campaign.checkpoint-attempt-execution-request" => "3",
            _ => "4",
        };
        assert_eq!(message[1], expected_version);
        assert_eq!(message[2], "crucible-campaign::execution");
        assert_eq!(message[3], "component-message");
        owned_campaign_schemas.insert(schema);
    }
    for schema in [
        "crucible.campaign.describe-executor-request",
        "crucible.campaign.executor-description",
        "crucible.campaign.watch-executor-capacity-request",
        "crucible.campaign.executor-capacity-report",
    ] {
        let message = rows
            .get(schema)
            .unwrap_or_else(|| panic!("missing executor capability schema {schema}"));
        assert_eq!(message[1], "1");
        assert_eq!(message[2], "crucible-campaign::executor_capability");
        assert_eq!(message[3], "component-message");
        owned_campaign_schemas.insert(schema);
    }
    for schema in [
        "crucible.campaign.create-campaign-request",
        "crucible.campaign.create-campaign-response",
        "crucible.campaign.derive-campaign-request",
        "crucible.campaign.derive-campaign-response",
        "crucible.campaign.get-campaign-request",
        "crucible.campaign.get-campaign-response",
        "crucible.campaign.get-campaign-status-request",
        "crucible.campaign.get-campaign-status-response",
        "crucible.campaign.list-campaigns-request",
        "crucible.campaign.list-campaigns-response",
        "crucible.campaign.get-campaign-snapshot-request",
        "crucible.campaign.get-campaign-snapshot-response",
        "crucible.campaign.watch-campaign-request",
        "crucible.campaign.watch-campaign-response",
        "crucible.campaign.query-campaign-graph-request",
        "crucible.campaign.query-campaign-graph-response",
        "crucible.campaign.query-campaign-findings-request",
        "crucible.campaign.query-campaign-findings-response",
        "crucible.campaign.query-campaign-finding-occurrences-request",
        "crucible.campaign.query-campaign-finding-occurrences-response",
        "crucible.campaign.get-campaign-finding-occurrence-object-request",
        "crucible.campaign.get-campaign-finding-occurrence-object-response",
        "crucible.campaign.get-campaign-finding-triage-replay-segment-request",
        "crucible.campaign.get-campaign-finding-triage-replay-segment-response",
        "crucible.campaign.get-campaign-finding-object-request",
        "crucible.campaign.get-campaign-finding-object-response",
        "crucible.campaign.explain-campaign-attempt-request",
        "crucible.campaign.explain-campaign-attempt-response",
        "crucible.campaign.get-campaign-planner-rankings-request",
        "crucible.campaign.get-campaign-planner-rankings-response",
        "crucible.campaign.get-campaign-graph-object-request",
        "crucible.campaign.get-campaign-graph-object-response",
        "crucible.campaign.query-campaign-choices-request",
        "crucible.campaign.query-campaign-choices-response",
        "crucible.campaign.query-campaign-frontier-request",
        "crucible.campaign.query-campaign-frontier-response",
        "crucible.campaign.get-campaign-frontier-object-request",
        "crucible.campaign.get-campaign-frontier-object-response",
        "crucible.campaign.get-campaign-choice-object-request",
        "crucible.campaign.get-campaign-choice-object-response",
        "crucible.campaign.apply-campaign-command-request",
        "crucible.campaign.apply-campaign-command-response",
        "crucible.campaign.pin-campaign-request",
        "crucible.campaign.pin-campaign-response",
        "crucible.campaign.submit-campaign-discovery-request",
        "crucible.campaign.submit-campaign-discovery-response",
        "crucible.campaign.submit-campaign-branch-request",
        "crucible.campaign.submit-campaign-branch-response",
        "crucible.campaign.service-error-response",
    ] {
        let message = rows
            .get(schema)
            .unwrap_or_else(|| panic!("missing campaign service schema {schema}"));
        let expected_version = match schema {
            "crucible.campaign.explain-campaign-attempt-response"
            | "crucible.campaign.submit-campaign-discovery-request" => "2",
            _ => "1",
        };
        assert_eq!(message[1], expected_version);
        assert_eq!(message[2], "crucible-campaign::campaign_service");
        assert_eq!(message[3], "component-message");
        owned_campaign_schemas.insert(schema);
    }
    for (schema, version, kind) in [
        (
            "crucible.executor.assignment-record",
            "1",
            "operational-record",
        ),
        (
            "crucible.executor.attempt-state-record",
            "15",
            "operational-record",
        ),
        (
            "crucible.executor.assignment-retention-state",
            "1",
            "administrative-record",
        ),
        (
            "crucible.executor.exact-pin-materialization-selection",
            "1",
            "administrative-record",
        ),
    ] {
        let record = rows
            .get(schema)
            .unwrap_or_else(|| panic!("missing executor ledger schema {schema}"));
        assert_eq!(record[1], version);
        let expected_owner = if schema == "crucible.executor.exact-pin-materialization-selection" {
            "crucible-daemon::exact_pin_retention"
        } else {
            "crucible-daemon::assignment_ledger"
        };
        assert_eq!(record[2], expected_owner);
        assert_eq!(record[3], kind);
    }
    let hot_fallback = rows
        .get("crucible.executor.hot-checkpoint-fallback")
        .unwrap_or_else(|| panic!("missing hot-checkpoint fallback schema"));
    assert_eq!(hot_fallback[1], "1");
    assert_eq!(hot_fallback[2], "crucible-daemon::hot_checkpoint_retention");
    assert_eq!(hot_fallback[3], "operational-record");
    for (schema, version, owner) in [
        (
            "crucible.executor.prepared-semantic-attempt-result",
            "6",
            "crucible-daemon::crucible_artifact::prepared_result",
        ),
        (
            "crucible.executor.prepared-result-journal-state",
            "2",
            "crucible-daemon::prepared_result_journal",
        ),
    ] {
        let record = rows
            .get(schema)
            .unwrap_or_else(|| panic!("missing prepared-result schema {schema}"));
        assert_eq!(record[1], version);
        assert_eq!(record[2], owner);
        assert_eq!(record[3], "operational-record");
    }
    for (schema, version, owner, kind) in [
        (
            "crucible.qemu.vm-snapshot",
            "2",
            "crucible-qemu::realization",
            "device-state",
        ),
        (
            "crucible.qemu.vmstate",
            "1",
            "crucible-daemon::exact_checkpoint_store",
            "device-state",
        ),
        (
            "crucible.executor.scheduler-continuation",
            "3",
            "crucible-daemon::exact_checkpoint_store",
            "device-state",
        ),
        (
            "crucible.production-exact-closure",
            "8",
            "crucible-api::vm_lifecycle",
            "device-state",
        ),
        (
            "crucible.executor.production-checkpoint-object",
            "5",
            "crucible-daemon::exact_checkpoint_store",
            "device-state",
        ),
        (
            "crucible.executor.production-checkpoint-index",
            "1",
            "crucible-daemon::exact_checkpoint_store",
            "exact-manifest",
        ),
        (
            "crucible.executor.exact-checkpoint-root",
            "4",
            "crucible-daemon::exact_checkpoint_store",
            "exact-manifest",
        ),
    ] {
        let record = rows
            .get(schema)
            .unwrap_or_else(|| panic!("missing exact-checkpoint schema {schema}"));
        assert_eq!(record[1], version);
        assert_eq!(record[2], owner);
        assert_eq!(record[3], kind);
    }
    let replay_capture = rows
        .get("crucible.executor.finding-replay-capture-manifest")
        .unwrap_or_else(|| panic!("missing finding replay capture manifest schema"));
    assert_eq!(replay_capture[1], "1");
    assert_eq!(
        replay_capture[2],
        "crucible-daemon::finding_replay_capture_store"
    );
    assert_eq!(replay_capture[3], "exact-manifest");
    let loopback = rows
        .get("crucible.executor.loopback-frame")
        .unwrap_or_else(|| panic!("missing executor loopback frame schema"));
    assert_eq!(loopback[1], "5");
    assert_eq!(loopback[2], "crucible-daemon::executor_loopback");
    assert_eq!(loopback[3], "component-message");
    let planner_loopback = rows
        .get("crucible.planner.loopback-frame")
        .unwrap_or_else(|| panic!("missing planner loopback frame schema"));
    assert_eq!(planner_loopback[1], "1");
    assert_eq!(planner_loopback[2], "crucible-daemon::planner_loopback");
    assert_eq!(planner_loopback[3], "component-message");
    let planner_process = rows
        .get("crucible.planner.process-frame")
        .unwrap_or_else(|| panic!("missing planner process frame schema"));
    assert_eq!(planner_process[1], "1");
    assert_eq!(planner_process[2], "crucible-daemon::planner_process");
    assert_eq!(planner_process[3], "component-message");
    let campaign_loopback = rows
        .get("crucible.campaign.loopback-frame")
        .unwrap_or_else(|| panic!("missing campaign loopback frame schema"));
    assert_eq!(campaign_loopback[1], "20");
    assert_eq!(campaign_loopback[2], "crucible-daemon::campaign_loopback");
    assert_eq!(campaign_loopback[3], "component-message");
    owned_campaign_schemas.insert("crucible.campaign.loopback-frame");
    for schema in [
        "crucible.campaign.attach-runtime-request",
        "crucible.campaign.attach-runtime-response",
    ] {
        let message = rows
            .get(schema)
            .unwrap_or_else(|| panic!("missing campaign runtime control schema {schema}"));
        assert_eq!(message[1], "1");
        assert_eq!(message[2], "crucible-daemon::campaign_runtime_control");
        assert_eq!(message[3], "component-message");
        owned_campaign_schemas.insert(schema);
    }
    let campaign_policy = rows
        .get("crucible.campaign-local-policy")
        .unwrap_or_else(|| panic!("missing local campaign policy schema"));
    assert_eq!(campaign_policy[1], "1");
    assert_eq!(campaign_policy[2], "crucible-daemon::campaign_policy");
    assert_eq!(campaign_policy[3], "deployment-config");
    let component_authorities = rows
        .get("crucible.campaign-component-authorities")
        .unwrap_or_else(|| panic!("missing campaign component-authority schema"));
    assert_eq!(component_authorities[1], "1");
    assert_eq!(
        component_authorities[2],
        "crucible-daemon::campaign_bootstrap"
    );
    assert_eq!(component_authorities[3], "deployment-secret");
    let campaign_import = rows
        .get("crucible.campaign-import")
        .unwrap_or_else(|| panic!("missing local campaign import schema"));
    assert_eq!(campaign_import[1], "1");
    assert_eq!(campaign_import[2], "crucible-cli::campaign_import");
    assert_eq!(campaign_import[3], "deployment-config");
    let campaign_store = rows
        .get("crucible.campaign-repository-store")
        .unwrap_or_else(|| panic!("missing campaign repository-store deployment schema"));
    assert_eq!(campaign_store[1], "2");
    assert_eq!(campaign_store[2], "crucible-cli::campaign_store");
    assert_eq!(campaign_store[3], "deployment-config");
    let campaign_s3_credentials = rows
        .get("crucible.campaign-s3-credentials")
        .unwrap_or_else(|| panic!("missing campaign S3 credential schema"));
    assert_eq!(campaign_s3_credentials[1], "1");
    assert_eq!(campaign_s3_credentials[2], "crucible-cli::campaign_store");
    assert_eq!(campaign_s3_credentials[3], "deployment-secret");
    for (schema, version, owner) in [
        (
            "crucible.executor.crucible-scenario-payload",
            "3",
            "crucible-daemon::crucible_artifact",
        ),
        (
            "crucible.executor.crucible-reproduction-payload",
            "3",
            "crucible-daemon::crucible_artifact",
        ),
        ("crucible.execution.scenario-form", "7", "crucible::model"),
        (
            "crucible.execution.measurement-definitions",
            "1",
            "crucible::model",
        ),
        (
            "crucible.execution.measurement-evaluation",
            "1",
            "crucible::model",
        ),
        (
            "crucible.execution.reproduction-artifact",
            "7",
            "crucible::model",
        ),
    ] {
        let record = rows
            .get(schema)
            .unwrap_or_else(|| panic!("missing execution-model schema {schema}"));
        assert_eq!(record[1], version);
        assert_eq!(record[2], owner);
        assert_eq!(record[3], "execution-model-payload");
    }
    for (schema, version) in [
        ("crucible.campaign.gc-plan", "2"),
        ("crucible.campaign.gc-root-manifest", "1"),
        ("crucible.campaign.gc-candidate-manifest", "2"),
        ("crucible.campaign.gc-journal-state", "1"),
    ] {
        let record = rows
            .get(schema)
            .unwrap_or_else(|| panic!("missing campaign GC administrative schema {schema}"));
        assert_eq!(record[1], version);
        assert_eq!(record[2], "crucible-daemon::campaign_gc");
        assert_eq!(record[3], "administrative-record");
        owned_campaign_schemas.insert(schema);
    }
    let scan_index_schema = "crucible.campaign.planner-scan-index";
    let scan_index = rows
        .get(scan_index_schema)
        .unwrap_or_else(|| panic!("missing ordered planner scan index schema"));
    assert_eq!(scan_index[1], "1");
    assert_eq!(
        scan_index[2],
        "crucible-campaign::repository::planner_scan_index"
    );
    assert_eq!(scan_index[3], "merkle-node");
    owned_campaign_schemas.insert(scan_index_schema);
    for schema in rows.keys() {
        if schema.starts_with("crucible.campaign.") {
            assert!(
                owned_campaign_schemas.contains(schema),
                "registry contains an unowned campaign schema {schema}"
            );
        }
    }
    for (schema, owner, kind) in [
        (
            "crucible.content-envelope",
            "crucible-cas::content_envelope",
            "envelope",
        ),
        (
            "crucible.content-id-text",
            "crucible-cas::content_store",
            "identity",
        ),
        (
            "crucible.content-store.graph-configuration",
            "crucible-cas::content_store",
            "administrative-record",
        ),
        (
            "crucible.directory-ref",
            "crucible-cas::content_store",
            "mutable-ref",
        ),
        (
            "crucible.content-store.directory-inventory-state",
            "crucible-cas::content_store",
            "administrative-record",
        ),
        (
            "crucible.content-store.directory-ref-inventory-state",
            "crucible-cas::content_store",
            "administrative-record",
        ),
        (
            "crucible.content-store.s3-ref",
            "crucible-cas::content_store",
            "physical-record",
        ),
        (
            "crucible.content-store.s3-ref-inventory-state",
            "crucible-cas::content_store",
            "administrative-record",
        ),
        (
            "crucible.content-store.s3-object-inventory-state",
            "crucible-cas::content_store",
            "administrative-record",
        ),
        (
            "crucible.content-store.write-back-transfer-journal",
            "crucible-cas::content_store",
            "administrative-record",
        ),
        (
            "crucible.content-store.compressed-object",
            "crucible-cas::content_store",
            "physical-record",
        ),
        (
            "crucible.content-store.encrypted-object",
            "crucible-cas::content_store",
            "physical-record",
        ),
        (
            "crucible.content-store.compressed-encrypted-object",
            "crucible-cas::content_store",
            "physical-record",
        ),
        (
            "crucible.content-store.encryption-key-state",
            "crucible-cas::content_store",
            "administrative-record",
        ),
        (
            "crucible.content-store.logical-quota-state",
            "crucible-cas::content_store",
            "administrative-record",
        ),
        (
            "crucible.content-store.pack",
            "crucible-cas::content_store",
            "physical-record",
        ),
        (
            "crucible.content-store.pack-index",
            "crucible-cas::content_store",
            "administrative-record",
        ),
        (
            "crucible.content-store.pack-repack-plan",
            "crucible-cas::content_store",
            "administrative-record",
        ),
    ] {
        let row = rows
            .get(schema)
            .unwrap_or_else(|| panic!("missing lower schema {schema}"));
        let expected_version = if schema == "crucible.content-store.graph-configuration" {
            "10"
        } else {
            "1"
        };
        assert_eq!(row[1], expected_version);
        assert_eq!(row[2], owner);
        assert_eq!(row[3], kind);
    }
}
