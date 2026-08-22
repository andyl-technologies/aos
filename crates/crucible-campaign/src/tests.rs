//! Unit tests for campaign canonical primitives.

#![allow(clippy::expect_used)]

use super::codec::{Canonical, Decoder, Encoder, decode, encode};
use super::*;
use crucible_cas::content_store::{ContentId, ObjectKind};
use std::collections::{BTreeMap, BTreeSet};

macro_rules! stored_id {
    ($type:ty, $kind:expr, $schema:expr, $label:expr) => {
        <$type>::from_content_id(ContentId::for_bytes($kind, $schema, $label.as_bytes()))
            .expect("typed content id")
    };
    ($type:ty, $kind:expr, $label:expr) => {
        <$type>::from_content_id(content_kind($label, $kind)).expect("typed content id")
    };
}

#[derive(Clone, Debug, PartialEq, Eq)]
struct CodecFixture {
    enabled: bool,
    count: u64,
    name: String,
}

impl Canonical for CodecFixture {
    fn encode(&self, encoder: &mut Encoder) {
        encoder.bool(self.enabled);
        encoder.u64(self.count);
        encoder.string(&self.name);
    }

    fn decode(decoder: &mut Decoder<'_>) -> Result<Self, CampaignCodecError> {
        Ok(Self {
            enabled: decoder.bool()?,
            count: decoder.u64()?,
            name: decoder.string()?,
        })
    }
}

#[test]
fn canonical_codec_rejects_trailing_truncated_and_noncanonical_input() {
    let fixture = CodecFixture {
        enabled: true,
        count: 42,
        name: "network-recovery".to_owned(),
    };
    let bytes = encode(&fixture);
    assert_eq!(
        decode::<CodecFixture>(&bytes).expect("canonical decode"),
        fixture
    );

    let mut trailing = bytes.clone();
    trailing.push(0);
    assert_eq!(
        decode::<CodecFixture>(&trailing),
        Err(CampaignCodecError::TrailingBytes)
    );
    assert_eq!(
        decode::<CodecFixture>(&bytes[..bytes.len() - 1]),
        Err(CampaignCodecError::Truncated)
    );

    let mut invalid_boolean = bytes;
    invalid_boolean[0] = 2;
    assert_eq!(
        decode::<CodecFixture>(&invalid_boolean),
        Err(CampaignCodecError::InvalidBoolean)
    );

    let decomposed = CodecFixture {
        enabled: true,
        count: 1,
        name: "e\u{301}".to_owned(),
    };
    assert_eq!(
        decode::<CodecFixture>(&encode(&decomposed)),
        Err(CampaignCodecError::NonCanonical)
    );
}

#[test]
fn canonical_text_and_exact_rational_ordering_are_mathematical() {
    let alternative = AlternativeId::from_hash(hash("accented"));
    assert_eq!(
        DiscreteAlternative::new(alternative, "e\u{301}", None),
        Err(CampaignCodecError::NonCanonical)
    );

    let third = ExactRational::new(1, 3).expect("third");
    let half = ExactRational::new(1, 2).expect("half");
    assert!(third < half);
    assert!(
        ExactRational::new(u64::MAX - 1, u64::MAX).expect("near one")
            < ExactRational::new(u64::MAX, u64::MAX).expect("one")
    );
    let ordered = [
        ExactRational::new(0, u64::MAX).expect("zero"),
        ExactRational::new(1, u64::MAX).expect("tiny"),
        ExactRational::new(u64::MAX - 1, u64::MAX).expect("near one"),
        ExactRational::new(1, 1).expect("one"),
        ExactRational::new(u64::MAX, 1).expect("maximum"),
    ];
    assert!(ordered.windows(2).all(|pair| pair[0] < pair[1]));
}

#[test]
fn campaign_hashes_are_domain_separated_and_text_is_canonical() {
    let bytes = b"same canonical object";
    let policy = CampaignHash::derive("crucible.campaign-policy.v1", bytes);
    let snapshot = CampaignHash::derive("crucible.campaign-snapshot.v1", bytes);
    assert_ne!(policy, snapshot);
    assert_eq!(
        CampaignHash::parse(&policy.to_hex()).expect("parse hash"),
        policy
    );
    assert_eq!(
        CampaignHash::parse(&policy.to_hex().to_ascii_uppercase()),
        Err(CampaignCodecError::InvalidHex)
    );

    let policy_id = stored_id!(CampaignPolicyId, ObjectKind::Policy, "policy");
    let encoded = serde_json::to_string(&policy_id).expect("serialize typed ID");
    assert_eq!(encoded, format!("\"{policy_id}\""));
    assert_eq!(
        serde_json::from_str::<CampaignPolicyId>(&encoded).expect("deserialize typed ID"),
        policy_id
    );
    let planner_state = stored_id!(PlannerStateId, ObjectKind::Policy, "planner-state");
    assert!(CampaignPolicyId::parse(&planner_state.to_text()).is_err());
}

#[test]
fn schema_registry_is_unique_complete_and_names_real_gates() {
    let registry = include_str!("../../../docs/rfcs/0016-crucible-campaigns/schema-registry.tsv");
    let implementation_plan =
        include_str!("../../../docs/rfcs/0016-crucible-campaigns/11-implementation-plan.md");
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
            CampaignRecordKind::ReproductionArtifact | CampaignRecordKind::Finding => {
                "crucible-campaign::finding"
            }
            _ => "crucible-campaign::object",
        };
        assert_eq!(row[2], expected_owner);
        assert_eq!(row[3], kind.object_kind().as_str());
    }
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
        "crucible.campaign.submit-attempt-request",
        "crucible.campaign.submit-attempt-response",
        "crucible.campaign.get-attempt-execution-request",
        "crucible.campaign.get-attempt-execution-response",
        "crucible.campaign.cancel-attempt-execution-request",
        "crucible.campaign.cancel-attempt-execution-response",
        "crucible.campaign.checkpoint-attempt-execution-request",
        "crucible.campaign.checkpoint-attempt-execution-response",
    ] {
        let message = rows
            .get(schema)
            .unwrap_or_else(|| panic!("missing executor component schema {schema}"));
        assert_eq!(message[1], "2");
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
        "crucible.campaign.get-campaign-snapshot-request",
        "crucible.campaign.get-campaign-snapshot-response",
        "crucible.campaign.watch-campaign-request",
        "crucible.campaign.watch-campaign-response",
        "crucible.campaign.query-campaign-graph-request",
        "crucible.campaign.query-campaign-graph-response",
        "crucible.campaign.query-campaign-findings-request",
        "crucible.campaign.query-campaign-findings-response",
        "crucible.campaign.get-campaign-finding-object-request",
        "crucible.campaign.get-campaign-finding-object-response",
        "crucible.campaign.explain-campaign-attempt-request",
        "crucible.campaign.explain-campaign-attempt-response",
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
        "crucible.campaign.submit-campaign-branch-request",
        "crucible.campaign.submit-campaign-branch-response",
        "crucible.campaign.service-error-response",
    ] {
        let message = rows
            .get(schema)
            .unwrap_or_else(|| panic!("missing campaign service schema {schema}"));
        assert_eq!(message[1], "1");
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
            "3",
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
            "crucible.executor.exact-checkpoint-root",
            "2",
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
    let loopback = rows
        .get("crucible.executor.loopback-frame")
        .unwrap_or_else(|| panic!("missing executor loopback frame schema"));
    assert_eq!(loopback[1], "4");
    assert_eq!(loopback[2], "crucible-daemon::executor_loopback");
    assert_eq!(loopback[3], "component-message");
    let planner_loopback = rows
        .get("crucible.planner.loopback-frame")
        .unwrap_or_else(|| panic!("missing planner loopback frame schema"));
    assert_eq!(planner_loopback[1], "1");
    assert_eq!(planner_loopback[2], "crucible-daemon::planner_loopback");
    assert_eq!(planner_loopback[3], "component-message");
    let campaign_loopback = rows
        .get("crucible.campaign.loopback-frame")
        .unwrap_or_else(|| panic!("missing campaign loopback frame schema"));
    assert_eq!(campaign_loopback[1], "16");
    assert_eq!(campaign_loopback[2], "crucible-daemon::campaign_loopback");
    assert_eq!(campaign_loopback[3], "component-message");
    owned_campaign_schemas.insert("crucible.campaign.loopback-frame");
    let campaign_policy = rows
        .get("crucible.campaign-local-policy")
        .unwrap_or_else(|| panic!("missing local campaign policy schema"));
    assert_eq!(campaign_policy[1], "1");
    assert_eq!(campaign_policy[2], "crucible-daemon::campaign_policy");
    assert_eq!(campaign_policy[3], "deployment-config");
    for schema in [
        "crucible.campaign.gc-plan",
        "crucible.campaign.gc-root-manifest",
        "crucible.campaign.gc-candidate-manifest",
        "crucible.campaign.gc-journal-state",
    ] {
        let record = rows
            .get(schema)
            .unwrap_or_else(|| panic!("missing campaign GC administrative schema {schema}"));
        assert_eq!(record[1], "1");
        assert_eq!(record[2], "crucible-daemon::campaign_gc");
        assert_eq!(record[3], "administrative-record");
        owned_campaign_schemas.insert(schema);
    }
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
            "crucible.content-store.write-back-transfer-journal",
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
        assert_eq!(row[1], "1");
        assert_eq!(row[2], owner);
        assert_eq!(row[3], kind);
    }
}

#[test]
fn campaign_policy_identity_is_order_independent_and_strictly_decoded() {
    let generator = stored_id!(CandidateGeneratorSpecId, ObjectKind::Policy, "generator");
    let choice = ChoicePolicy::new("product.recovery", generator, true).expect("choice policy");
    let objective = Objective::new("recovery.latency-ns", ObjectiveGoal::Minimize, 1_000_000)
        .expect("objective");
    let guidance = GuidanceWeight::new("coverage", 250_000).expect("guidance");
    let policy = CampaignPolicy::new(
        ScenarioDefId::from_hash(hash("scenario")),
        CampaignSeed::from_bytes([0x5d; 32]),
        CampaignMode::Strict,
        ExplorerPolicy::TreeSearch {
            puct: PuctPolicy::new(1_250_000, 250_000, 100_000),
            widening: Some(
                ProgressiveWideningPolicy::new(
                    ExactRational::new(2, 1).expect("k"),
                    ExactRational::new(1, 2).expect("alpha"),
                    3,
                    64,
                    1,
                )
                .expect("widening"),
            ),
        },
        BTreeMap::from([("product.recovery".to_owned(), choice)]),
        BTreeMap::from([("recovery.latency-ns".to_owned(), objective)]),
        BTreeMap::from([("coverage".to_owned(), guidance)]),
        BTreeSet::from(["measurement.recovery".to_owned()]),
        FairnessPolicy::new(10, 8).expect("fairness"),
        RetentionPolicy::new(true, 64, true, true),
        false,
    )
    .expect("campaign policy");

    let bytes = policy.canonical_bytes();
    assert_eq!(
        CampaignPolicy::from_canonical_bytes(&bytes).expect("canonical policy"),
        policy
    );
    let mut trailing = bytes;
    trailing.push(0);
    assert_eq!(
        CampaignPolicy::from_canonical_bytes(&trailing),
        Err(CampaignCodecError::TrailingBytes)
    );
    let policy_id = policy.id().expect("policy id");
    assert_eq!(policy_id.content_id().kind(), ObjectKind::Policy);
    assert_eq!(
        CampaignPolicyId::parse(&policy_id.to_text()).expect("parse policy id"),
        policy_id
    );
    let envelope = ObjectEnvelope::for_policy(&policy).expect("policy envelope");
    assert_eq!(envelope.children().len(), 1);
    assert_eq!(
        envelope.children().first().expect("generator child").id(),
        generator.content_id()
    );
}

#[test]
fn snapshot_planning_view_excludes_pins_and_coordination_but_snapshot_identity_does_not() {
    let roots = CampaignRoots {
        graph: content("graph"),
        exploration: content("exploration"),
        observations: content("observations"),
        corpus: content("corpus"),
        coverage: content("coverage"),
        findings: content("findings"),
        pins: content("pins-a"),
        accounting: content("accounting"),
        coordination: content("coordination"),
    };
    let snapshot = CampaignSnapshot::genesis(
        stored_id!(CampaignLineageId, ObjectKind::CampaignFact, "lineage"),
        stored_id!(CampaignPolicyId, ObjectKind::Policy, "policy"),
        roots,
    )
    .expect("genesis snapshot");
    let mut changed_roots = roots;
    changed_roots.pins = content("pins-b");
    let changed =
        CampaignSnapshot::genesis(snapshot.lineage(), snapshot.active_policy(), changed_roots)
            .expect("changed genesis snapshot");

    assert_ne!(
        snapshot.id().expect("snapshot id"),
        changed.id().expect("changed id")
    );
    assert_eq!(
        snapshot.planning_view().id().expect("view id"),
        changed.planning_view().id().expect("changed view id")
    );
    let mut coordinated_roots = roots;
    coordinated_roots.coordination = content("coordination-b");
    let coordinated = CampaignSnapshot::genesis(
        snapshot.lineage(),
        snapshot.active_policy(),
        coordinated_roots,
    )
    .expect("coordinated genesis snapshot");
    assert_ne!(
        snapshot.id().expect("snapshot id"),
        coordinated.id().expect("coordinated snapshot id")
    );
    assert_eq!(
        snapshot.planning_view().id().expect("view id"),
        coordinated
            .planning_view()
            .id()
            .expect("coordinated view id")
    );
    assert_eq!(
        CampaignSnapshot::from_canonical_bytes(&snapshot.canonical_bytes())
            .expect("canonical snapshot"),
        snapshot
    );
}

#[test]
fn lineage_and_invocation_identities_name_every_compatibility_input() {
    let protocols = BTreeMap::from([
        ("guest-choice".to_owned(), 1),
        ("qemu-control".to_owned(), 7),
    ]);
    let scenario = ScenarioDefId::from_hash(hash("scenario"));
    let scenario_artifact = ScenarioArtifact::new(scenario, 1, b"scenario-record".to_vec())
        .expect("scenario artifact")
        .id()
        .expect("scenario artifact id");
    let genesis = ConfigurationId::from_hash(hash("genesis"));
    let genesis_artifact = ConfigurationArtifact::new(
        scenario,
        scenario_artifact,
        genesis,
        1,
        b"genesis-record".to_vec(),
    )
    .expect("genesis artifact")
    .id()
    .expect("genesis artifact id");
    let lineage = CampaignLineage::new(
        scenario,
        scenario_artifact,
        genesis,
        genesis_artifact,
        "1.2.3",
        "qemu-10.0-series-a",
        protocols.clone(),
        1,
        2,
    )
    .expect("lineage");
    let changed = CampaignLineage::new(
        lineage.scenario(),
        lineage.scenario_content(),
        lineage.genesis(),
        lineage.genesis_content(),
        "1.2.3",
        "qemu-10.0-series-b",
        protocols,
        1,
        2,
    )
    .expect("changed lineage");
    assert_ne!(lineage.id(), changed.id());

    let budget = PlanningBudget::new(1, 4, 100, 1_000_000, 50_000).expect("budget");
    let invocation = PlannerInvocation::new(
        stored_id!(PlannerEngineId, ObjectKind::Policy, "engine"),
        stored_id!(PolicyArtifactId, ObjectKind::Policy, "artifact"),
        stored_id!(CampaignPolicyId, ObjectKind::Policy, "policy"),
        stored_id!(PlannerStateId, ObjectKind::Policy, "state"),
        stored_id!(CampaignViewId, ObjectKind::CampaignFact, "view"),
        PlanningScanPage::new(None, 1, Vec::new(), true, 0).expect("scan page"),
        budget,
    )
    .expect("invocation");
    let more_fuel = PlannerInvocation::new(
        invocation.engine(),
        invocation.policy_artifact(),
        invocation.policy(),
        invocation.planner_state(),
        invocation.input_view(),
        invocation.scan_page().clone(),
        PlanningBudget::new(
            budget.branch_requests(),
            budget.proposals(),
            budget.input_objects(),
            budget.input_bytes(),
            budget.fuel() + 1,
        )
        .expect("changed budget"),
    )
    .expect("changed invocation");
    assert_ne!(invocation.id(), more_fuel.id());
    assert!(PlanningBudget::new(0, 1, 1, 1, 1).is_err());
    assert!(
        CampaignPlanningView::new(
            content_kind("not-a-root", ObjectKind::Trace),
            content("exploration"),
            content("observations"),
            content("corpus"),
            content("coverage"),
            content("findings"),
            content("accounting"),
        )
        .is_err()
    );
}

#[test]
fn command_and_fact_identities_bind_payload_and_admission_order() {
    let command = CampaignCommandId::from_hash(hash("command"));
    let expected_snapshot = stored_id!(
        CampaignSnapshotId,
        ObjectKind::CampaignSnapshot,
        2,
        "snapshot"
    );
    let request = ControlRequest {
        command,
        expected_snapshot,
        action: CampaignControlAction::Pause(ActiveAttemptPolicy::Drain),
    };
    let different = ControlRequest {
        command,
        expected_snapshot,
        action: CampaignControlAction::Pause(ActiveAttemptPolicy::CancelAndRetry),
    };
    assert_ne!(request.request_digest(), different.request_digest());

    let attempt = stored_id!(AttemptId, ObjectKind::CampaignFact, "attempt");
    let first = CampaignFact::AttemptAdmitted(
        AttemptAdmission::new(
            attempt,
            AttemptAdmissionRole::ExecutionBasis {
                proposal: None,
                cause: BranchRequestCause::Operator(command),
                admission_ordinal: AdmissionOrdinal::new(7),
            },
        )
        .id()
        .expect("first admission id"),
    );
    let second = CampaignFact::AttemptAdmitted(
        AttemptAdmission::new(
            attempt,
            AttemptAdmissionRole::ExecutionBasis {
                proposal: None,
                cause: BranchRequestCause::Operator(command),
                admission_ordinal: AdmissionOrdinal::new(8),
            },
        )
        .id()
        .expect("second admission id"),
    );
    assert_ne!(first.id(), second.id());
    assert_eq!(
        CampaignFact::from_canonical_bytes(&first.canonical_bytes()).expect("canonical fact"),
        first
    );
    assert_eq!(AdmissionOrdinal::new(u64::MAX).checked_next(), None);

    let cancelled = CampaignFact::AttemptClosed {
        attempt,
        ordinal: AdmissionOrdinal::new(7),
        disposition: NonModeledAttemptDisposition::OperatorCancelled,
    };
    let incompatible = CampaignFact::AttemptClosed {
        attempt,
        ordinal: AdmissionOrdinal::new(7),
        disposition: NonModeledAttemptDisposition::PermanentlyIncompatible,
    };
    assert_ne!(cancelled.id(), incompatible.id());
    let envelope = ObjectEnvelope::for_fact(&cancelled).expect("closure fact envelope");
    assert_eq!(envelope.children().len(), 1);
    assert_eq!(
        CampaignFact::from_canonical_bytes(envelope.body()).expect("closure fact"),
        cancelled
    );

    let credited = CampaignFact::ObservationCredited(stored_id!(
        ObservationId,
        ObjectKind::Observation,
        "credited-observation"
    ));
    assert_eq!(
        &credited.canonical_bytes()[..std::mem::size_of::<u32>()],
        &4_u32.to_be_bytes()
    );
    let credited_envelope = ObjectEnvelope::for_fact(&credited).expect("credited fact envelope");
    assert_eq!(credited_envelope.content_id().schema_version(), 4);
    assert_eq!(
        CampaignFact::from_canonical_bytes(credited_envelope.body())
            .expect("canonical credited fact"),
        credited
    );
    let legacy_envelope_with_credited_body = crucible_cas::content_envelope::ContentEnvelope::new(
        CampaignRecordKind::Fact.schema_name(),
        2,
        credited_envelope.children().clone(),
        credited.canonical_bytes(),
    )
    .expect("mismatched legacy credited envelope");
    assert!(
        ObjectEnvelope::from_canonical_bytes(&legacy_envelope_with_credited_body.canonical_bytes())
            .is_err()
    );

    let pin = CampaignFact::PinCommandAccepted(PinRequest {
        command,
        expected_snapshot,
        change: PinChange::new(
            ConfigurationId::from_hash(hash("pin-configuration")),
            Some(PinRetention::Exact),
            "retain reproducer",
        )
        .expect("pin change"),
    });
    assert_eq!(
        &pin.canonical_bytes()[..std::mem::size_of::<u32>()],
        &5_u32.to_be_bytes()
    );
    let pin_envelope = ObjectEnvelope::for_fact(&pin).expect("pin fact envelope");
    assert_eq!(pin_envelope.content_id().schema_version(), 5);
    assert_eq!(pin_envelope.children().len(), 1);
    assert_eq!(
        CampaignFact::from_canonical_bytes(pin_envelope.body()).expect("canonical pin fact"),
        pin
    );
    let prior_envelope_with_pin_body = crucible_cas::content_envelope::ContentEnvelope::new(
        CampaignRecordKind::Fact.schema_name(),
        4,
        pin_envelope.children().clone(),
        pin.canonical_bytes(),
    )
    .expect("mismatched prior pin envelope");
    assert!(
        ObjectEnvelope::from_canonical_bytes(&prior_envelope_with_pin_body.canonical_bytes())
            .is_err()
    );
}

#[test]
fn integer_domains_use_checked_cardinality_and_validate_steps() {
    let unsigned = ChoiceDomain::Integer(
        IntegerDomain::new(
            1,
            IntegerRepresentation::Unsigned64,
            IntegerValue::Unsigned(0),
            IntegerValue::Unsigned(u64::MAX),
            1,
            Some("count".to_owned()),
            ExactRational::new(1, 1).expect("scale"),
            vec![IntegerValue::Unsigned(0), IntegerValue::Unsigned(u64::MAX)],
        )
        .expect("full unsigned domain"),
    );
    assert_eq!(unsigned.cardinality(), u128::from(u64::MAX) + 1);
    assert!(unsigned.contains(&ChoiceValue::Integer(IntegerValue::Unsigned(u64::MAX))));

    let stepped = IntegerDomain::new(
        1,
        IntegerRepresentation::Signed64,
        IntegerValue::Signed(-10),
        IntegerValue::Signed(10),
        4,
        None,
        ExactRational::new(1, 1).expect("scale"),
        vec![IntegerValue::Signed(-10), IntegerValue::Signed(10)],
    )
    .expect("stepped signed domain");
    assert_eq!(stepped.cardinality(), 6);
    assert!(stepped.contains_integer(IntegerValue::Signed(-2)));
    assert!(!stepped.contains_integer(IntegerValue::Signed(0)));
    assert!(matches!(
        IntegerDomain::new(
            1,
            IntegerRepresentation::Signed64,
            IntegerValue::Signed(-10),
            IntegerValue::Signed(10),
            4,
            None,
            ExactRational::new(1, 1).expect("scale"),
            vec![IntegerValue::Signed(0)],
        ),
        Err(CampaignCodecError::InvalidValue { .. })
    ));

    let parent = ChoiceDomain::Integer(
        IntegerDomain::new(
            1,
            IntegerRepresentation::Unsigned64,
            IntegerValue::Unsigned(0),
            IntegerValue::Unsigned(1_000),
            1,
            Some("ms".to_owned()),
            ExactRational::new(1, 1).expect("scale"),
            Vec::new(),
        )
        .expect("parent domain"),
    );
    let changed_unit = ChoiceDomain::Integer(
        IntegerDomain::new(
            1,
            IntegerRepresentation::Unsigned64,
            IntegerValue::Unsigned(0),
            IntegerValue::Unsigned(100),
            1,
            Some("s".to_owned()),
            ExactRational::new(1, 1).expect("scale"),
            Vec::new(),
        )
        .expect("changed-unit domain"),
    );
    let changed_scale = ChoiceDomain::Integer(
        IntegerDomain::new(
            1,
            IntegerRepresentation::Unsigned64,
            IntegerValue::Unsigned(0),
            IntegerValue::Unsigned(100),
            1,
            Some("ms".to_owned()),
            ExactRational::new(1_000, 1).expect("scale"),
            Vec::new(),
        )
        .expect("changed-scale domain"),
    );
    assert!(!changed_unit.is_subset_of(&parent));
    assert!(!changed_scale.is_subset_of(&parent));

    for unaligned in [
        IntegerDomain::new(
            1,
            IntegerRepresentation::Signed64,
            IntegerValue::Signed(-10),
            IntegerValue::Signed(10),
            3,
            None,
            ExactRational::new(1, 1).expect("scale"),
            Vec::new(),
        ),
        IntegerDomain::new(
            1,
            IntegerRepresentation::Unsigned64,
            IntegerValue::Unsigned(0),
            IntegerValue::Unsigned(u64::MAX),
            2,
            None,
            ExactRational::new(1, 1).expect("scale"),
            Vec::new(),
        ),
    ] {
        assert!(matches!(
            unaligned,
            Err(CampaignCodecError::InvalidValue {
                reason: "integer domain maximum is unreachable by its step"
            })
        ));
    }

    let extreme_signed = IntegerDomain::new(
        1,
        IntegerRepresentation::Signed64,
        IntegerValue::Signed(i64::MIN),
        IntegerValue::Signed(i64::MAX),
        u64::MAX,
        None,
        ExactRational::new(1, 1).expect("scale"),
        vec![
            IntegerValue::Signed(i64::MIN),
            IntegerValue::Signed(i64::MAX),
        ],
    )
    .expect("aligned extreme signed range");
    assert_eq!(extreme_signed.cardinality(), 2);
}

#[test]
fn discrete_domain_identity_excludes_declared_presentation_text() {
    let first_id = AlternativeId::from_hash(hash("first"));
    let second_id = AlternativeId::from_hash(hash("second"));
    let domain = ChoiceDomain::Discrete(
        DiscreteDomain::new(
            1,
            BTreeMap::from([
                (
                    first_id,
                    DiscreteAlternative::new(first_id, "Prefer old route", None)
                        .expect("first alternative"),
                ),
                (
                    second_id,
                    DiscreteAlternative::new(second_id, "Recompute routes", None)
                        .expect("second alternative"),
                ),
            ]),
        )
        .expect("discrete domain"),
    );
    let relabeled = ChoiceDomain::Discrete(
        DiscreteDomain::new(
            1,
            BTreeMap::from([
                (
                    first_id,
                    DiscreteAlternative::new(first_id, "Old", Some("display only".to_owned()))
                        .expect("relabeled first"),
                ),
                (
                    second_id,
                    DiscreteAlternative::new(second_id, "New", None).expect("relabeled second"),
                ),
            ]),
        )
        .expect("relabeled domain"),
    );
    assert_eq!(domain.semantic_id(), relabeled.semantic_id());
    assert_ne!(
        domain.id().expect("domain id"),
        relabeled.id().expect("relabeled id")
    );
    assert_ne!(domain.canonical_bytes(), relabeled.canonical_bytes());
    assert_eq!(
        ChoiceDomain::from_canonical_bytes(&domain.canonical_bytes())
            .expect("canonical choice domain"),
        domain
    );
}

#[test]
fn presentation_and_landmark_changes_preserve_semantic_branch_identity() {
    let alternative = AlternativeId::from_hash(hash("keep-route"));
    let discrete = ChoiceDomain::Discrete(
        DiscreteDomain::new(
            1,
            BTreeMap::from([(
                alternative,
                DiscreteAlternative::new(alternative, "Keep route", None).expect("alternative"),
            )]),
        )
        .expect("domain"),
    );
    let relabeled = ChoiceDomain::Discrete(
        DiscreteDomain::new(
            1,
            BTreeMap::from([(
                alternative,
                DiscreteAlternative::new(
                    alternative,
                    "Preserve current route",
                    Some("presentation only".to_owned()),
                )
                .expect("relabeled alternative"),
            )]),
        )
        .expect("relabeled domain"),
    );
    let declaration = selectable_fixture(
        "route-response",
        discrete.clone(),
        ChoiceValue::Discrete(alternative),
    );
    let relabeled_declaration = selectable_fixture(
        "route-response",
        relabeled.clone(),
        ChoiceValue::Discrete(alternative),
    );
    assert_eq!(
        declaration.semantic_id(),
        relabeled_declaration.semantic_id()
    );
    assert_ne!(declaration.id(), relabeled_declaration.id());

    let coordinate = ChoiceCoordinate {
        scheduler: hash("scheduler-coordinate"),
        producer: hash("producer-coordinate"),
    };
    let scenario = ScenarioDefId::from_hash(hash("scenario"));
    let opportunity = ChoiceOpportunity::new(
        scenario,
        &declaration,
        &discrete,
        coordinate,
        "route-1",
        None,
    )
    .expect("opportunity");
    let relabeled_opportunity = ChoiceOpportunity::new(
        scenario,
        &relabeled_declaration,
        &relabeled,
        coordinate,
        "route-1",
        None,
    )
    .expect("relabeled opportunity");
    assert_ne!(opportunity.id(), relabeled_opportunity.id());
    assert_eq!(
        opportunity.semantic_id(),
        relabeled_opportunity.semantic_id()
    );

    let parent = ConfigurationId::from_hash(hash("parent"));
    let branch_point = opportunity.branch_point_id(parent);
    let relabeled_branch_point = relabeled_opportunity.branch_point_id(parent);
    assert_eq!(branch_point, relabeled_branch_point);
    let selection = Selection::new_campaign_branch(
        &opportunity,
        &discrete,
        ChoiceValue::Discrete(alternative),
        branch_point,
    )
    .expect("selection");
    let relabeled_selection = Selection::new_campaign_branch(
        &relabeled_opportunity,
        &relabeled,
        ChoiceValue::Discrete(alternative),
        relabeled_branch_point,
    )
    .expect("relabeled selection");
    assert_eq!(selection.origin(), relabeled_selection.origin());

    let integer = ChoiceDomain::Integer(
        IntegerDomain::new(
            1,
            IntegerRepresentation::Unsigned64,
            IntegerValue::Unsigned(0),
            IntegerValue::Unsigned(100),
            1,
            Some("ms".to_owned()),
            ExactRational::new(1, 1).expect("scale"),
            vec![IntegerValue::Unsigned(10)],
        )
        .expect("integer domain"),
    );
    let different_landmarks = ChoiceDomain::Integer(
        IntegerDomain::new(
            1,
            IntegerRepresentation::Unsigned64,
            IntegerValue::Unsigned(0),
            IntegerValue::Unsigned(100),
            1,
            Some("ms".to_owned()),
            ExactRational::new(1, 1).expect("scale"),
            vec![IntegerValue::Unsigned(90)],
        )
        .expect("integer domain"),
    );
    assert_eq!(integer.semantic_id(), different_landmarks.semantic_id());
    assert_ne!(integer.id(), different_landmarks.id());
}

#[test]
fn type_specific_collection_limits_reject_counts_before_elements() {
    let mut domain = Encoder::new();
    domain.u32(1);
    domain.u8(1);
    domain.u32(1);
    domain.u64(4097);
    assert_eq!(
        ChoiceDomain::from_canonical_bytes(&domain.finish()),
        Err(CampaignCodecError::LimitExceeded {
            limit: "discrete-domain-alternative-count"
        })
    );

    let mut generator = Encoder::new();
    generator.u32(1);
    generator.u32(1);
    generator.u8(1);
    generator.u64(4097);
    assert_eq!(
        CandidateGeneratorSpec::from_canonical_bytes(&generator.finish()),
        Err(CampaignCodecError::LimitExceeded {
            limit: "candidate-generator-weight-count"
        })
    );

    let mut selectable = Encoder::new();
    selectable.u32(1);
    selectable.u64(513);
    assert_eq!(
        SelectableDeclaration::from_canonical_bytes(&selectable.finish()),
        Err(CampaignCodecError::LimitExceeded {
            limit: "selectable-name-bytes"
        })
    );
}

#[test]
fn opportunities_and_selections_fail_closed_on_domain_drift() {
    let declaration_domain = ChoiceDomain::Integer(
        IntegerDomain::new(
            1,
            IntegerRepresentation::Unsigned64,
            IntegerValue::Unsigned(0),
            IntegerValue::Unsigned(30_000),
            1,
            Some("ms".to_owned()),
            ExactRational::new(1, 1).expect("scale"),
            vec![IntegerValue::Unsigned(0), IntegerValue::Unsigned(1_000)],
        )
        .expect("declaration domain"),
    );
    let declaration = SelectableDeclaration::new(
        "product.network.retry-delay-ms",
        ChoiceSource::Guest {
            node: "router-a".to_owned(),
            protocol_version: 1,
        },
        declaration_domain.clone(),
        ChoiceValue::Integer(IntegerValue::Unsigned(1_000)),
        ChoiceClassContext::new(BTreeSet::from(["network-recovery".to_owned()]))
            .expect("class context"),
        BTreeSet::from(["integral".to_owned(), "latency".to_owned()]),
        true,
    )
    .expect("selectable declaration");
    let narrowed = ChoiceDomain::Integer(
        IntegerDomain::new(
            1,
            IntegerRepresentation::Unsigned64,
            IntegerValue::Unsigned(0),
            IntegerValue::Unsigned(5_000),
            10,
            Some("ms".to_owned()),
            ExactRational::new(1, 1).expect("scale"),
            vec![IntegerValue::Unsigned(0), IntegerValue::Unsigned(1_000)],
        )
        .expect("narrowed domain"),
    );
    let opportunity = ChoiceOpportunity::new(
        ScenarioDefId::from_hash(hash("scenario")),
        &declaration,
        &narrowed,
        ChoiceCoordinate {
            scheduler: hash("scheduler-coordinate"),
            producer: hash("routing-epoch"),
        },
        "epoch-42",
        None,
    )
    .expect("choice opportunity");
    let opportunity_envelope =
        ObjectEnvelope::for_choice_opportunity(&opportunity).expect("choice opportunity envelope");
    assert_eq!(
        ChoiceOpportunity::from_canonical_bytes(opportunity_envelope.body())
            .expect("canonical choice opportunity"),
        opportunity
    );
    let selection = Selection::new(
        &opportunity,
        &narrowed,
        ChoiceValue::Integer(IntegerValue::Unsigned(2_500)),
        SelectionOrigin::LockedReplay,
    )
    .expect("selection");
    selection
        .validate_replay(&opportunity, &narrowed)
        .expect("matching replay");
    assert!(matches!(
        selection.validate_replay(&opportunity, &declaration_domain),
        Err(CampaignCodecError::InvalidValue { .. })
    ));
}

#[test]
fn branch_requests_proposals_and_attempts_share_one_typed_lazy_model() {
    let scenario = ScenarioDefId::from_hash(hash("scenario"));
    let scenario_artifact = ScenarioArtifact::new(scenario, 1, b"scenario".to_vec())
        .expect("scenario artifact")
        .id()
        .expect("scenario artifact id");
    let parent_configuration = ConfigurationId::from_hash(hash("parent configuration"));
    let parent = ConfigurationArtifact::new(
        scenario,
        scenario_artifact,
        parent_configuration,
        1,
        b"parent".to_vec(),
    )
    .expect("parent artifact");
    let domain = ChoiceDomain::Integer(
        IntegerDomain::new(
            1,
            IntegerRepresentation::Unsigned64,
            IntegerValue::Unsigned(0),
            IntegerValue::Unsigned(10),
            1,
            Some("ms".to_owned()),
            ExactRational::new(1, 1).expect("scale"),
            vec![IntegerValue::Unsigned(0), IntegerValue::Unsigned(10)],
        )
        .expect("domain"),
    );
    let declaration = selectable_fixture(
        "retry-delay",
        domain.clone(),
        ChoiceValue::Integer(IntegerValue::Unsigned(0)),
    );
    let opportunity = ChoiceOpportunity::new(
        scenario,
        &declaration,
        &domain,
        ChoiceCoordinate {
            scheduler: hash("scheduler"),
            producer: hash("producer"),
        },
        "retry-1",
        None,
    )
    .expect("opportunity");
    let branch_point = opportunity.branch_point_id(parent_configuration);
    let cause = BranchRequestCause::Operator(CampaignCommandId::from_hash(hash("command")));
    let request = BranchRequest::new(
        branch_point,
        parent.id().expect("parent id"),
        opportunity.id().expect("opportunity id"),
        domain.id().expect("domain id"),
        CandidateSource::finite(BTreeSet::from([
            ChoiceValue::Integer(IntegerValue::Unsigned(0)),
            ChoiceValue::Integer(IntegerValue::Unsigned(10)),
        ]))
        .expect("finite source"),
        cause,
        BranchBudget::new(2, 2).expect("budget"),
        StopCondition::NextChoice,
    )
    .expect("request");
    request
        .validate_resolved(&parent, &opportunity, &domain)
        .expect("resolved request");
    let request_envelope = ObjectEnvelope::for_record(
        CampaignRecordKind::BranchRequest,
        super::object::content_children(request.content_children()).expect("request children"),
        request.canonical_bytes(),
    )
    .expect("request envelope");
    assert_eq!(
        ObjectEnvelope::from_canonical_bytes(&request_envelope.canonical_bytes())
            .expect("request decode"),
        request_envelope
    );

    let proposal = Proposal::new(
        branch_point,
        request.id().expect("request id"),
        domain.id().expect("domain id"),
        ChoiceValue::Integer(IntegerValue::Unsigned(10)),
        stored_id!(CampaignPolicyId, ObjectKind::Policy, "policy"),
        None,
        1,
        stored_id!(CampaignViewId, ObjectKind::CampaignFact, "view"),
    )
    .expect("proposal");
    proposal
        .validate_resolved(&request, &domain)
        .expect("resolved proposal");
    let outside_source = Proposal::new(
        branch_point,
        request.id().expect("request id"),
        domain.id().expect("domain id"),
        ChoiceValue::Integer(IntegerValue::Unsigned(5)),
        stored_id!(CampaignPolicyId, ObjectKind::Policy, "policy"),
        None,
        1,
        stored_id!(CampaignViewId, ObjectKind::CampaignFact, "view"),
    )
    .expect("legal-domain proposal");
    assert!(outside_source.validate_resolved(&request, &domain).is_err());
    let over_budget = Proposal::new(
        branch_point,
        request.id().expect("request id"),
        domain.id().expect("domain id"),
        ChoiceValue::Integer(IntegerValue::Unsigned(10)),
        stored_id!(CampaignPolicyId, ObjectKind::Policy, "policy"),
        None,
        3,
        stored_id!(CampaignViewId, ObjectKind::CampaignFact, "view"),
    )
    .expect("over-budget proposal");
    assert!(over_budget.validate_resolved(&request, &domain).is_err());

    let selection = Selection::new_campaign_branch(
        &opportunity,
        &domain,
        proposal.value().clone(),
        branch_point,
    )
    .expect("selection");
    let edge = match selection.origin() {
        SelectionOrigin::CampaignBranch { edge, .. } => edge,
        _ => panic!("campaign branch selection"),
    };
    let path = BranchPath::new(vec![BranchPathSegment::new(branch_point, edge)]).expect("path");
    assert_eq!(
        path.segments(),
        Some([BranchPathSegment::new(branch_point, edge)].as_slice())
    );
    assert_eq!(
        BranchPath::from_canonical_bytes(&path.canonical_bytes()).expect("canonical path"),
        path
    );
    let path_envelope = super::object::ObjectEnvelope::for_branch_path(&path)
        .expect("current branch path envelope");
    assert_eq!(path_envelope.content_id().schema_version(), 2);

    let mut legacy_path_encoder = Encoder::new();
    1_u32.encode(&mut legacy_path_encoder);
    vec![edge].encode(&mut legacy_path_encoder);
    let legacy_path_bytes = legacy_path_encoder.finish();
    let legacy_path = BranchPath::from_canonical_bytes(&legacy_path_bytes)
        .expect("legacy branch path remains readable");
    assert_eq!(legacy_path.edges(), [edge]);
    assert_eq!(legacy_path.segments(), None);
    assert_eq!(legacy_path.canonical_bytes(), legacy_path_bytes);
    let legacy_path_envelope = crucible_cas::content_envelope::ContentEnvelope::new(
        CampaignRecordKind::BranchPath.schema_name(),
        1,
        BTreeSet::new(),
        legacy_path_bytes,
    )
    .expect("legacy branch path envelope");
    ObjectEnvelope::from_canonical_bytes(&legacy_path_envelope.canonical_bytes())
        .expect("legacy branch path envelope remains readable");
    assert_eq!(
        legacy_path.id().expect("legacy branch path identity"),
        BranchPathId::from_content_id(legacy_path_envelope.content_id(ObjectKind::CampaignFact))
            .expect("legacy branch path id")
    );
    let mut trailing_path = path.canonical_bytes();
    trailing_path.push(0);
    assert_eq!(
        BranchPath::from_canonical_bytes(&trailing_path),
        Err(CampaignCodecError::TrailingBytes)
    );

    let attempt = Attempt::new(
        AttemptStart::Branch {
            edge,
            parent: parent.id().expect("parent id"),
            selection: selection.id().expect("selection id"),
        },
        path.id().expect("path id"),
        StopCondition::NextChoice,
    )
    .expect("attempt");
    assert_eq!(
        Attempt::from_canonical_bytes(&attempt.canonical_bytes()).expect("canonical attempt"),
        attempt
    );

    let basis = AttemptAdmission::new(
        attempt.id().expect("attempt id"),
        AttemptAdmissionRole::ExecutionBasis {
            proposal: Some(proposal.id().expect("proposal id")),
            cause,
            admission_ordinal: AdmissionOrdinal::new(1),
        },
    );
    let additional = AttemptAdmission::new(
        attempt.id().expect("attempt id"),
        AttemptAdmissionRole::AdditionalCause {
            proposal: proposal.id().expect("proposal id"),
        },
    );
    assert_ne!(basis.id(), additional.id());
    assert_eq!(
        AttemptAdmission::from_canonical_bytes(&basis.canonical_bytes())
            .expect("canonical attempt admission"),
        basis
    );

    let planner_view = stored_id!(CampaignViewId, ObjectKind::CampaignFact, "planner-view");
    let planner_step = PlannerStep::new(
        None,
        stored_id!(
            PlannerInvocationId,
            ObjectKind::Policy,
            2,
            "planner-invocation"
        ),
        stored_id!(
            RetainedPlannerRequestId,
            ObjectKind::Policy,
            "retained-planner-request"
        ),
        CampaignHash::derive("crucible.test.planner-request-digest.v1", b"planner-step"),
        stored_id!(CampaignPolicyId, ObjectKind::Policy, "planner-step-policy"),
        stored_id!(PlannerEngineId, ObjectKind::Policy, "planner-engine"),
        stored_id!(PolicyArtifactId, ObjectKind::Policy, "policy-artifact"),
        planner_view,
        PlannerDisposition::Issue {
            selected: PlanningScanPosition::new(branch_point, request.id().expect("request id")),
            issued_branch_requests: Vec::new(),
            issued_proposals: vec![proposal.id().expect("proposal id")],
        },
        stored_id!(PlannerStateId, ObjectKind::Policy, "next-planner-state"),
        PlanningUsage {
            branch_requests: 0,
            proposals: 1,
            input_objects: 8,
            input_bytes: 4096,
            fuel: 1,
        },
        PlanningAccounting {
            branch_requests: 0,
            proposals: 1,
            attempts: 1,
            deduplicated: 0,
            input_objects: 8,
            input_bytes: 4096,
            fuel: 1,
        },
        GuidanceEvidence::new(BTreeMap::new()).expect("guidance evidence"),
    )
    .expect("planner step");
    assert_eq!(
        PlannerStep::from_canonical_bytes(&planner_step.canonical_bytes())
            .expect("canonical planner step"),
        planner_step
    );
    assert_eq!(
        &planner_step.canonical_bytes()[..std::mem::size_of::<u32>()],
        &4_u32.to_be_bytes()
    );
    let planner_step_children =
        super::object::content_children(planner_step.content_children()).expect("step children");
    let planner_step_envelope = ObjectEnvelope::for_record(
        CampaignRecordKind::PlannerStep,
        planner_step_children.clone(),
        planner_step.canonical_bytes(),
    )
    .expect("planner step envelope");
    let stored_planner_step =
        crucible_cas::content_envelope::ContentEnvelope::from_canonical_bytes(
            &planner_step_envelope.canonical_bytes(),
        )
        .expect("stored planner step envelope");
    assert_eq!(stored_planner_step.schema_version(), 4);
    let prior_envelope = crucible_cas::content_envelope::ContentEnvelope::new(
        CampaignRecordKind::PlannerStep.schema_name(),
        3,
        planner_step_children,
        planner_step.canonical_bytes(),
    )
    .expect("prior planner step envelope");
    assert!(ObjectEnvelope::from_canonical_bytes(&prior_envelope.canonical_bytes()).is_err());
    let legacy_step_id = PlannerStepId::from_content_id(ContentId::for_bytes(
        ObjectKind::CampaignFact,
        3,
        b"legacy planner step",
    ))
    .expect("legacy planner step id");
    let legacy_fact = CampaignFact::PlannerAdvanced(legacy_step_id);
    let mut legacy_fact_encoder = Encoder::new();
    2_u32.encode(&mut legacy_fact_encoder);
    legacy_fact.encode(&mut legacy_fact_encoder);
    let legacy_fact_bytes = legacy_fact_encoder.finish();
    assert_eq!(
        CampaignFact::from_canonical_bytes(&legacy_fact_bytes)
            .expect("legacy planner fact remains readable"),
        legacy_fact
    );
    let legacy_fact_children = BTreeSet::from([crucible_cas::content_envelope::ContentChild::new(
        "planner-step",
        legacy_step_id.content_id(),
    )
    .expect("legacy fact child")]);
    let legacy_fact_envelope = crucible_cas::content_envelope::ContentEnvelope::new(
        CampaignRecordKind::Fact.schema_name(),
        2,
        legacy_fact_children.clone(),
        legacy_fact_bytes.clone(),
    )
    .expect("legacy fact envelope");
    ObjectEnvelope::from_canonical_bytes(&legacy_fact_envelope.canonical_bytes())
        .expect("legacy fact envelope remains readable");
    let legacy_fact_id =
        CampaignFactId::from_content_id(legacy_fact_envelope.content_id(ObjectKind::CampaignFact));
    assert_eq!(legacy_fact.canonical_bytes(), legacy_fact_bytes);
    assert_eq!(
        legacy_fact.id().expect("legacy fact identity"),
        legacy_fact_id.expect("legacy fact id remains readable")
    );
    let current_envelope_with_prior_body = crucible_cas::content_envelope::ContentEnvelope::new(
        CampaignRecordKind::Fact.schema_name(),
        CampaignRecordKind::Fact.schema_version(),
        legacy_fact_children,
        legacy_fact_bytes,
    )
    .expect("mismatched current fact envelope");
    assert!(
        ObjectEnvelope::from_canonical_bytes(&current_envelope_with_prior_body.canonical_bytes())
            .is_err()
    );

    let derivation = CampaignFact::CampaignDerived(CampaignDerivation::new(
        stored_id!(
            CampaignSnapshotId,
            ObjectKind::CampaignSnapshot,
            2,
            "derivation-source"
        ),
        stored_id!(CampaignPolicyId, ObjectKind::Policy, "derivation-policy"),
    ));
    assert_eq!(
        &derivation.canonical_bytes()[..std::mem::size_of::<u32>()],
        &3_u32.to_be_bytes()
    );
    let derivation_envelope = ObjectEnvelope::for_fact(&derivation).expect("derivation envelope");
    ObjectEnvelope::from_canonical_bytes(&derivation_envelope.canonical_bytes())
        .expect("version 3 derivation envelope remains readable");
    let prior_envelope_with_derivation_body = crucible_cas::content_envelope::ContentEnvelope::new(
        CampaignRecordKind::Fact.schema_name(),
        2,
        derivation_envelope.children().clone(),
        derivation.canonical_bytes(),
    )
    .expect("mismatched derivation envelope");
    assert!(
        ObjectEnvelope::from_canonical_bytes(
            &prior_envelope_with_derivation_body.canonical_bytes()
        )
        .is_err()
    );

    let continue_scan = PlannerStep::new(
        Some(planner_step.id().expect("parent planner step")),
        planner_step.invocation(),
        planner_step.request(),
        planner_step.request_digest(),
        planner_step.policy(),
        planner_step.engine(),
        planner_step.policy_artifact(),
        planner_view,
        PlannerDisposition::ContinueScan {
            cursor: PlanningScanCursor::new(
                planner_view,
                Some(PlanningScanPosition::new(
                    branch_point,
                    request.id().expect("request id"),
                )),
            ),
        },
        planner_step.next_state(),
        PlanningUsage {
            branch_requests: 0,
            proposals: 0,
            input_objects: 8,
            input_bytes: 4096,
            fuel: 4,
        },
        PlanningAccounting {
            branch_requests: 0,
            proposals: 0,
            attempts: 0,
            deduplicated: 0,
            input_objects: 8,
            input_bytes: 4096,
            fuel: 4,
        },
        GuidanceEvidence::new(BTreeMap::new()).expect("scan evidence"),
    )
    .expect("continue scan");
    assert!(continue_scan.selected_source().is_none());
    assert!(continue_scan.issued_proposals().is_empty());
    assert_eq!(
        PlannerStep::from_canonical_bytes(&continue_scan.canonical_bytes())
            .expect("canonical continue scan"),
        continue_scan
    );
    let no_work = PlannerStep::new(
        Some(continue_scan.id().expect("continue-scan step id")),
        planner_step.invocation(),
        planner_step.request(),
        planner_step.request_digest(),
        planner_step.policy(),
        planner_step.engine(),
        planner_step.policy_artifact(),
        planner_view,
        PlannerDisposition::NoWork,
        planner_step.next_state(),
        PlanningUsage {
            branch_requests: 0,
            proposals: 0,
            input_objects: 1,
            input_bytes: 64,
            fuel: 1,
        },
        PlanningAccounting {
            branch_requests: 0,
            proposals: 0,
            attempts: 0,
            deduplicated: 0,
            input_objects: 1,
            input_bytes: 64,
            fuel: 1,
        },
        GuidanceEvidence::new(BTreeMap::new()).expect("no-work evidence"),
    )
    .expect("no-work step");
    assert!(no_work.selected_branch_point().is_none());
    assert_eq!(
        PlannerStep::from_canonical_bytes(&no_work.canonical_bytes())
            .expect("canonical no-work step"),
        no_work
    );

    assert!(
        continue_scan
            .content_children()
            .iter()
            .any(|(role, id)| role == "scan-after-source"
                && *id == request.id().expect("request id").content_id())
    );

    assert!(
        PlannerStep::new(
            None,
            planner_step.invocation(),
            planner_step.request(),
            planner_step.request_digest(),
            planner_step.policy(),
            planner_step.engine(),
            planner_step.policy_artifact(),
            planner_view,
            PlannerDisposition::ContinueScan {
                cursor: PlanningScanCursor::new(
                    stored_id!(CampaignViewId, ObjectKind::CampaignFact, "another-view"),
                    None,
                ),
            },
            planner_step.next_state(),
            PlanningUsage {
                branch_requests: 0,
                proposals: 0,
                input_objects: 1,
                input_bytes: 64,
                fuel: 1,
            },
            PlanningAccounting {
                branch_requests: 0,
                proposals: 0,
                attempts: 0,
                deduplicated: 0,
                input_objects: 1,
                input_bytes: 64,
                fuel: 1,
            },
            GuidanceEvidence::new(BTreeMap::new()).expect("invalid scan evidence"),
        )
        .is_err()
    );

    let planner_request = BranchRequest::new(
        branch_point,
        parent.id().expect("parent id"),
        opportunity.id().expect("opportunity id"),
        domain.id().expect("domain id"),
        CandidateSource::finite(BTreeSet::from([ChoiceValue::Integer(
            IntegerValue::Unsigned(10),
        )]))
        .expect("planner finite source"),
        BranchRequestCause::Planner(planner_step.invocation()),
        BranchBudget::new(1, 1).expect("planner branch budget"),
        StopCondition::NextChoice,
    )
    .expect("planner request");
    let planner_proposal = Proposal::new(
        branch_point,
        planner_request.id().expect("planner request id"),
        domain.id().expect("domain id"),
        ChoiceValue::Integer(IntegerValue::Unsigned(10)),
        planner_step.policy(),
        Some(planner_step.invocation()),
        1,
        planner_view,
    )
    .expect("planner proposal");
    let proposed_step = PlannerStepProposal::new(
        planner_step.invocation(),
        PlannerState::new(planner_step.engine(), "scan-state", 1, vec![1, 2, 3])
            .expect("next planner state"),
        PlanningUsage {
            branch_requests: 1,
            proposals: 1,
            input_objects: 8,
            input_bytes: 4096,
            fuel: 4,
        },
        GuidanceEvidence::new(BTreeMap::from([("score".to_owned(), 1_000)]))
            .expect("proposal evidence"),
        PlannerProposalDisposition::Issue {
            selected: PlanningScanPosition::new(
                branch_point,
                planner_request.id().expect("planner request id"),
            ),
            branch_requests: vec![planner_request.clone()],
            proposals: vec![planner_proposal.clone()],
        },
    )
    .expect("pure planner result");
    assert_eq!(
        PlannerStepProposal::from_canonical_bytes(&proposed_step.canonical_bytes())
            .expect("canonical pure planner result"),
        proposed_step
    );
    assert!(matches!(
        PlannerStepProposal::new_with_encoded_limit(
            planner_step.invocation(),
            PlannerState::new(planner_step.engine(), "scan-state", 1, Vec::new())
                .expect("bounded result state"),
            PlanningUsage {
                branch_requests: 0,
                proposals: 0,
                input_objects: 1,
                input_bytes: 1,
                fuel: 1,
            },
            GuidanceEvidence::new(BTreeMap::new()).expect("bounded result evidence"),
            PlannerProposalDisposition::NoWork,
            1,
        ),
        Err(CampaignCodecError::LimitExceeded {
            limit: "planner-step-proposal-encoded-bytes"
        })
    ));

    let proposed_no_work = PlannerStepProposal::new(
        planner_step.invocation(),
        PlannerState::new(planner_step.engine(), "scan-state", 1, Vec::new())
            .expect("no-work result state"),
        PlanningUsage {
            branch_requests: 0,
            proposals: 0,
            input_objects: 8,
            input_bytes: 4096,
            fuel: 1,
        },
        GuidanceEvidence::new(BTreeMap::new()).expect("no-work result evidence"),
        PlannerProposalDisposition::NoWork,
    )
    .expect("pure no-work result");
    assert_eq!(
        PlannerStepProposal::from_canonical_bytes(&proposed_no_work.canonical_bytes())
            .expect("canonical pure no-work result"),
        proposed_no_work
    );

    assert!(
        PlannerStepProposal::new(
            planner_step.invocation(),
            PlannerState::new(planner_step.engine(), "scan-state", 1, Vec::new())
                .expect("duplicate result state"),
            PlanningUsage {
                branch_requests: 1,
                proposals: 2,
                input_objects: 8,
                input_bytes: 4096,
                fuel: 4,
            },
            GuidanceEvidence::new(BTreeMap::new()).expect("duplicate result evidence"),
            PlannerProposalDisposition::Issue {
                selected: PlanningScanPosition::new(
                    branch_point,
                    planner_request.id().expect("planner request id"),
                ),
                branch_requests: vec![planner_request],
                proposals: vec![planner_proposal.clone(), planner_proposal],
            },
        )
        .is_err()
    );

    let illegal = BranchRequest::new(
        branch_point,
        parent.id().expect("parent id"),
        opportunity.id().expect("opportunity id"),
        domain.id().expect("domain id"),
        CandidateSource::finite(BTreeSet::from([ChoiceValue::Integer(
            IntegerValue::Unsigned(11),
        )]))
        .expect("bounded source"),
        cause,
        BranchBudget::new(1, 1).expect("budget"),
        StopCondition::NextChoice,
    )
    .expect("structural request");
    assert!(
        illegal
            .validate_resolved(&parent, &opportunity, &domain)
            .is_err()
    );

    let credit_observation = stored_id!(
        ObservationId,
        ObjectKind::Observation,
        "expansion-credit-observation"
    );
    let credit = ExpansionCredit::new(credit_observation, branch_point);
    assert_eq!(
        ExpansionCredit::from_canonical_bytes(&credit.canonical_bytes())
            .expect("canonical expansion credit"),
        credit
    );
    let credit_envelope = ObjectEnvelope::for_record(
        CampaignRecordKind::ExpansionCredit,
        super::object::content_children(credit.content_children()).expect("credit children"),
        credit.canonical_bytes(),
    )
    .expect("credit envelope");
    assert_eq!(
        credit_envelope.content_id(),
        credit.content_id().expect("credit content id")
    );
    assert_eq!(
        credit_envelope
            .children()
            .iter()
            .map(crate::ChildReference::id)
            .collect::<Vec<_>>(),
        vec![credit_observation.content_id()]
    );

    let wait = FeedbackWait::new(2, 3).expect("pending feedback");
    assert_eq!(wait.completed_visits(), 2);
    assert_eq!(wait.required_visits(), 3);
    assert!(FeedbackWait::new(3, 3).is_err());
    assert!(FeedbackWait::new(4, 3).is_err());

    let request_id = request.id().expect("request id");
    let source_snapshot = stored_id!(
        CampaignSnapshotId,
        ObjectKind::CampaignSnapshot,
        2,
        "expansion-source-snapshot"
    );
    let input_view = stored_id!(CampaignViewId, ObjectKind::CampaignFact, "expansion-view");
    let expansion = ExpansionState::new(
        source_snapshot,
        input_view,
        branch_point,
        content("request-root"),
        content("proposal-root"),
        content("admission-root"),
        content("observation-root"),
        ExpansionStatistics::default(),
        None,
        1,
        None,
        BTreeMap::from([(request_id, ContinuationState::WaitingForFeedback(wait))]),
    )
    .expect("expansion state");
    assert_eq!(
        ExpansionState::from_canonical_bytes(&expansion.canonical_bytes())
            .expect("canonical expansion state"),
        expansion
    );
    let mut invalid_wait = expansion.canonical_bytes();
    let required_offset = invalid_wait.len() - std::mem::size_of::<u64>();
    invalid_wait[required_offset..].copy_from_slice(&2_u64.to_be_bytes());
    assert!(matches!(
        ExpansionState::from_canonical_bytes(&invalid_wait),
        Err(CampaignCodecError::InvalidValue { .. })
    ));
    let expansion_envelope = ObjectEnvelope::for_record(
        CampaignRecordKind::ExpansionState,
        super::object::content_children(expansion.content_children()).expect("expansion children"),
        expansion.canonical_bytes(),
    )
    .expect("expansion envelope");
    assert_eq!(
        &expansion.canonical_bytes()[..std::mem::size_of::<u32>()],
        &2_u32.to_be_bytes()
    );
    let mut legacy_body = expansion.canonical_bytes();
    legacy_body[..std::mem::size_of::<u32>()].copy_from_slice(&1_u32.to_be_bytes());
    assert!(ExpansionState::from_canonical_bytes(&legacy_body).is_err());
    assert_eq!(expansion_envelope.content_id().schema_version(), 2);
    let legacy_expansion = crucible_cas::content_envelope::ContentEnvelope::new(
        CampaignRecordKind::ExpansionState.schema_name(),
        1,
        expansion_envelope.children().clone(),
        expansion.canonical_bytes(),
    )
    .expect("legacy expansion envelope");
    assert!(ObjectEnvelope::from_canonical_bytes(&legacy_expansion.canonical_bytes()).is_err());
    assert!(
        expansion_envelope
            .children()
            .iter()
            .any(|child| child.role() == "continuation.00000000"
                && child.id() == request_id.content_id())
    );
}

struct ParityModel {
    model: ProbabilityModelId,
}

impl ModelSampleVerifier for ParityModel {
    fn verifies(&self, evidence: ModelSampleEvidence, value: &ChoiceValue) -> bool {
        evidence.model() == self.model
            && *value == ChoiceValue::Integer(IntegerValue::Unsigned(evidence.draw() % 2))
    }
}

#[test]
fn selection_origins_require_and_replay_exact_provenance() {
    let domain = ChoiceDomain::Integer(
        IntegerDomain::new(
            1,
            IntegerRepresentation::Unsigned64,
            IntegerValue::Unsigned(0),
            IntegerValue::Unsigned(1),
            1,
            Some("bit".to_owned()),
            ExactRational::new(1, 1).expect("scale"),
            Vec::new(),
        )
        .expect("binary domain"),
    );
    let declaration = SelectableDeclaration::new(
        "product.network.binary-choice",
        ChoiceSource::Guest {
            node: "router-a".to_owned(),
            protocol_version: 1,
        },
        domain.clone(),
        ChoiceValue::Integer(IntegerValue::Unsigned(0)),
        ChoiceClassContext::new(BTreeSet::new()).expect("context"),
        BTreeSet::new(),
        true,
    )
    .expect("declaration");
    let model = ProbabilityModelId::from_hash(hash("parity-model"));
    let opportunity = ChoiceOpportunity::new(
        ScenarioDefId::from_hash(hash("scenario")),
        &declaration,
        &domain,
        ChoiceCoordinate {
            scheduler: hash("scheduler"),
            producer: hash("producer"),
        },
        "binary-1",
        Some(model),
    )
    .expect("opportunity");
    let one = ChoiceValue::Integer(IntegerValue::Unsigned(1));

    assert!(matches!(
        Selection::new(&opportunity, &domain, one.clone(), SelectionOrigin::Default),
        Err(CampaignCodecError::InvalidValue { .. })
    ));
    let evidence = ModelSampleEvidence::new(model, ChoiceRngStreamId::from_hash(hash("stream")), 3);
    let verifier = ParityModel { model };
    let sampled =
        Selection::new_model_sample(&opportunity, &domain, one.clone(), evidence, &verifier)
            .expect("model selection");
    assert!(sampled.validate_replay(&opportunity, &domain).is_err());
    sampled
        .validate_model_replay(&opportunity, &domain, &verifier)
        .expect("model replay");
    assert!(
        sampled
            .validate_model_replay(
                &opportunity,
                &domain,
                &ParityModel {
                    model: ProbabilityModelId::from_hash(hash("wrong-model")),
                },
            )
            .is_err()
    );

    let branch_point = BranchPointId::from_hash(hash("branch-point"));
    let branched = Selection::new_campaign_branch(&opportunity, &domain, one, branch_point)
        .expect("branch selection");
    branched
        .validate_branch_replay(&opportunity, &domain, branch_point)
        .expect("branch replay");
    assert!(
        branched
            .validate_branch_replay(
                &opportunity,
                &domain,
                BranchPointId::from_hash(hash("wrong-point")),
            )
            .is_err()
    );
}

#[test]
fn choice_group_validates_complete_constraints_before_atomic_value() {
    let delay_domain = ChoiceDomain::Integer(
        IntegerDomain::new(
            1,
            IntegerRepresentation::Unsigned64,
            IntegerValue::Unsigned(0),
            IntegerValue::Unsigned(100),
            1,
            None,
            ExactRational::new(1, 1).expect("scale"),
            Vec::new(),
        )
        .expect("delay domain"),
    );
    let delay_declaration = selectable_fixture(
        "delay",
        delay_domain.clone(),
        ChoiceValue::Integer(IntegerValue::Unsigned(0)),
    );
    let timeout_declaration = selectable_fixture(
        "timeout",
        delay_domain.clone(),
        ChoiceValue::Integer(IntegerValue::Unsigned(0)),
    );
    let delay = delay_declaration.id().expect("delay id");
    let timeout = timeout_declaration.id().expect("timeout id");
    let declarations = BTreeMap::from([(delay, delay_declaration), (timeout, timeout_declaration)]);
    let group = ChoiceGroup::new(
        &declarations,
        ChoiceGroupDomain::Cartesian {
            members: BTreeMap::from([(delay, delay_domain.clone()), (timeout, delay_domain)]),
            constraints: BTreeSet::from([ChoiceRelationalConstraint::LessThan(delay, timeout)]),
        },
        ChoiceGroupApplication::new("network.profile", 1).expect("group application"),
    )
    .expect("choice group");
    let valid = ChoiceTuple::new(BTreeMap::from([
        (delay, ChoiceValue::Integer(IntegerValue::Unsigned(20))),
        (timeout, ChoiceValue::Integer(IntegerValue::Unsigned(80))),
    ]));
    assert_eq!(
        group.select(valid).expect("valid tuple").group(),
        group.id().expect("group id")
    );

    let invalid = ChoiceTuple::new(BTreeMap::from([
        (delay, ChoiceValue::Integer(IntegerValue::Unsigned(90))),
        (timeout, ChoiceValue::Integer(IntegerValue::Unsigned(80))),
    ]));
    assert!(matches!(
        group.select(invalid),
        Err(CampaignCodecError::InvalidValue { .. })
    ));
}

#[test]
fn choice_groups_reject_untyped_tuples_and_relations() {
    let boolean = ChoiceDomain::Boolean(BooleanDomain::new(1).expect("Boolean domain"));
    let first_declaration =
        selectable_fixture("first", boolean.clone(), ChoiceValue::Boolean(false));
    let second_declaration =
        selectable_fixture("second", boolean.clone(), ChoiceValue::Boolean(false));
    let first = first_declaration.id().expect("first id");
    let second = second_declaration.id().expect("second id");
    let declarations = BTreeMap::from([(first, first_declaration), (second, second_declaration)]);

    let invalid_tuple = ChoiceTuple::new(BTreeMap::from([
        (first, ChoiceValue::Boolean(false)),
        (second, ChoiceValue::Integer(IntegerValue::Unsigned(1))),
    ]));
    assert!(matches!(
        ChoiceGroup::new(
            &declarations,
            ChoiceGroupDomain::Finite {
                members: BTreeMap::from([(first, boolean.clone()), (second, boolean.clone())]),
                tuples: BTreeSet::from([invalid_tuple]),
            },
            ChoiceGroupApplication::new("product.atomic", 1).expect("application"),
        ),
        Err(CampaignCodecError::InvalidValue { .. })
    ));

    assert!(matches!(
        ChoiceGroup::new(
            &declarations,
            ChoiceGroupDomain::Cartesian {
                members: BTreeMap::from([(first, boolean.clone()), (second, boolean.clone())]),
                constraints: BTreeSet::from([ChoiceRelationalConstraint::LessThan(first, second)]),
            },
            ChoiceGroupApplication::new("product.atomic", 1).expect("application"),
        ),
        Err(CampaignCodecError::InvalidValue { .. })
    ));

    assert!(matches!(
        ChoiceGroup::new(
            &declarations,
            ChoiceGroupDomain::Cartesian {
                members: BTreeMap::from([(first, boolean.clone()), (second, boolean)]),
                constraints: BTreeSet::from([ChoiceRelationalConstraint::Implies {
                    if_member: first,
                    if_alternative: AlternativeId::from_hash(hash("not-a-boolean-alternative")),
                    then_member: second,
                    allowed: BTreeSet::from([ChoiceValue::Boolean(true)]),
                }]),
            },
            ChoiceGroupApplication::new("product.atomic", 1).expect("application"),
        ),
        Err(CampaignCodecError::InvalidValue { .. })
    ));
}

#[test]
fn choice_group_domains_are_bound_to_exact_declarations() {
    let declared = ChoiceDomain::Integer(
        IntegerDomain::new(
            1,
            IntegerRepresentation::Unsigned64,
            IntegerValue::Unsigned(0),
            IntegerValue::Unsigned(10),
            1,
            None,
            ExactRational::new(1, 1).expect("scale"),
            Vec::new(),
        )
        .expect("declared domain"),
    );
    let declaration = selectable_fixture(
        "bounded",
        declared,
        ChoiceValue::Integer(IntegerValue::Unsigned(0)),
    );
    let id = declaration.id().expect("declaration id");
    let widened = ChoiceDomain::Integer(
        IntegerDomain::new(
            1,
            IntegerRepresentation::Unsigned64,
            IntegerValue::Unsigned(0),
            IntegerValue::Unsigned(20),
            1,
            None,
            ExactRational::new(1, 1).expect("scale"),
            Vec::new(),
        )
        .expect("widened domain"),
    );
    assert!(matches!(
        ChoiceGroup::new(
            &BTreeMap::from([(id, declaration)]),
            ChoiceGroupDomain::Cartesian {
                members: BTreeMap::from([(id, widened)]),
                constraints: BTreeSet::new(),
            },
            ChoiceGroupApplication::new("product.atomic", 1).expect("application"),
        ),
        Err(CampaignCodecError::InvalidValue { .. })
    ));
}

#[test]
fn snapshot_envelope_exposes_every_child_and_authenticates_logical_identity() {
    let roots = CampaignRoots {
        graph: content("graph"),
        exploration: content("exploration"),
        observations: content("observations"),
        corpus: content("corpus"),
        coverage: content("coverage"),
        findings: content("findings"),
        pins: content("pins"),
        accounting: content("accounting"),
        coordination: content("coordination"),
    };
    let parent = stored_id!(
        CampaignSnapshotId,
        ObjectKind::CampaignSnapshot,
        2,
        "parent-snapshot"
    );
    let transition = stored_id!(CampaignFactId, ObjectKind::CampaignFact, 2, "transition");
    let snapshot = CampaignSnapshot::successor(
        parent,
        stored_id!(CampaignLineageId, ObjectKind::CampaignFact, "lineage"),
        stored_id!(CampaignPolicyId, ObjectKind::Policy, "policy"),
        roots,
        transition,
    )
    .expect("successor snapshot");
    let envelope = ObjectEnvelope::for_snapshot(&snapshot).expect("snapshot envelope");

    assert_eq!(envelope.record_kind(), CampaignRecordKind::Snapshot);
    assert_eq!(envelope.children().len(), 13);
    assert!(
        envelope
            .children()
            .iter()
            .any(|child| child.role() == "root.graph")
    );
    assert_eq!(
        snapshot.id().expect("snapshot id").content_id(),
        envelope.content_id()
    );
    assert_eq!(envelope.content_id().kind(), ObjectKind::CampaignSnapshot);
    assert_eq!(
        ObjectEnvelope::from_canonical_bytes(&envelope.canonical_bytes())
            .expect("canonical envelope"),
        envelope
    );
    let mut extra_children = envelope.children().clone();
    extra_children.insert(
        ChildReference::new("unrelated", content_kind("unrelated", ObjectKind::Trace))
            .expect("extra child"),
    );
    let extra = crucible_cas::content_envelope::ContentEnvelope::new(
        "crucible.campaign.snapshot",
        2,
        extra_children,
        snapshot.canonical_bytes(),
    )
    .expect("generic extra-child envelope");
    assert!(matches!(
        ObjectEnvelope::from_canonical_bytes(&extra.canonical_bytes()),
        Err(CampaignCodecError::InvalidValue { .. })
    ));
    let legacy = crucible_cas::content_envelope::ContentEnvelope::new(
        "crucible.campaign.snapshot",
        1,
        envelope.children().clone(),
        snapshot.canonical_bytes(),
    )
    .expect("legacy snapshot envelope");
    assert!(ObjectEnvelope::from_canonical_bytes(&legacy.canonical_bytes()).is_err());
}

#[test]
fn generic_public_object_decode_rejects_owner_validated_merkle_records() {
    let envelope = ObjectEnvelope::for_record(
        CampaignRecordKind::MerkleNode,
        BTreeSet::new(),
        vec![0, 1, 2],
    )
    .expect("structural Merkle envelope");
    assert!(matches!(
        ObjectEnvelope::from_canonical_bytes(&envelope.canonical_bytes()),
        Err(CampaignCodecError::InvalidValue { .. })
    ));
}

#[test]
fn observation_records_are_canonical_bounded_and_child_bearing() {
    let evidence = content_kind("measurement evidence", ObjectKind::Trace);
    let measurements = MeasurementSet::new(BTreeMap::from([(
        "latency".to_owned(),
        MeasurementSeries::new(
            vec![MetricValue::Unsigned(5), MetricValue::Unsigned(8)],
            MetricValue::Unsigned(13),
            BTreeSet::from([evidence]),
        )
        .expect("measurement series"),
    )]))
    .expect("measurement set");
    assert_eq!(
        MeasurementSet::from_canonical_bytes(&measurements.canonical_bytes())
            .expect("canonical measurements"),
        measurements
    );
    assert!(
        MeasurementSeries::new(
            vec![MetricValue::Unsigned(1)],
            MetricValue::Signed(1),
            BTreeSet::new(),
        )
        .is_err()
    );

    let properties = PropertyVerdictSet::new(BTreeMap::from([(
        "network-recovers".to_owned(),
        PropertyEvidence::new(PropertyVerdict::Passed, BTreeSet::from([evidence]))
            .expect("property evidence"),
    )]))
    .expect("property verdict set");
    assert_eq!(
        PropertyVerdictSet::from_canonical_bytes(&properties.canonical_bytes())
            .expect("canonical properties"),
        properties
    );
    let coverage = CoverageProjection::new(BTreeSet::from([hash("coverage")]), BTreeSet::new())
        .expect("coverage projection");
    assert_eq!(
        CoverageProjection::from_canonical_bytes(&coverage.canonical_bytes())
            .expect("canonical coverage"),
        coverage
    );

    let observation = Observation::new(
        stored_id!(AttemptId, ObjectKind::CampaignFact, "observation attempt"),
        ConfigurationId::from_hash(hash("observation child")),
        stored_id!(
            ConfigurationArtifactId,
            ObjectKind::Configuration,
            "observation child artifact"
        ),
        stored_id!(BranchPathId, ObjectKind::CampaignFact, "observation path"),
        StopOutcome::Reached(StopCondition::NextChoice),
        measurements.id().expect("measurement id"),
        properties.id().expect("property id"),
        coverage.id().expect("coverage id"),
        BTreeSet::from([stored_id!(
            ChoiceOpportunityId,
            ObjectKind::CampaignFact,
            "discovered choice"
        )]),
    )
    .expect("observation");
    assert_eq!(
        Observation::from_canonical_bytes(&observation.canonical_bytes())
            .expect("canonical observation"),
        observation
    );
    let envelope = ObjectEnvelope::for_record(
        CampaignRecordKind::Observation,
        super::object::content_children(observation.content_children())
            .expect("observation children"),
        observation.canonical_bytes(),
    )
    .expect("observation envelope");
    assert_eq!(
        observation.id().expect("observation id").content_id(),
        envelope.content_id()
    );
    assert_eq!(
        ObjectEnvelope::from_canonical_bytes(&envelope.canonical_bytes())
            .expect("canonical observation envelope"),
        envelope
    );

    let mut trailing = observation.canonical_bytes();
    trailing.push(0);
    assert_eq!(
        Observation::from_canonical_bytes(&trailing),
        Err(CampaignCodecError::TrailingBytes)
    );

    let maximum_series_evidence = (0_u32..4096)
        .map(|ordinal| ContentId::for_bytes(ObjectKind::Trace, 1, &ordinal.to_be_bytes()))
        .collect::<BTreeSet<_>>();
    let evidence_heavy_series = MeasurementSeries::new(
        vec![MetricValue::Unsigned(1)],
        MetricValue::Unsigned(1),
        maximum_series_evidence.clone(),
    )
    .expect("maximum series evidence");
    let excessive_measurements = (0..17)
        .map(|ordinal| (format!("metric-{ordinal}"), evidence_heavy_series.clone()))
        .collect::<BTreeMap<_, _>>();
    assert!(matches!(
        MeasurementSet::new(excessive_measurements),
        Err(CampaignCodecError::LimitExceeded {
            limit: "measurement-evidence-child-count"
        })
    ));
    let evidence_heavy_property =
        PropertyEvidence::new(PropertyVerdict::Passed, maximum_series_evidence)
            .expect("maximum property evidence");
    let excessive_properties = (0..17)
        .map(|ordinal| {
            (
                format!("property-{ordinal}"),
                evidence_heavy_property.clone(),
            )
        })
        .collect::<BTreeMap<_, _>>();
    assert!(matches!(
        PropertyVerdictSet::new(excessive_properties),
        Err(CampaignCodecError::LimitExceeded {
            limit: "property-evidence-child-count"
        })
    ));

    let excessive_choices = (0..=crate::observation::MAX_DISCOVERED_CHOICES)
        .map(|ordinal| {
            ChoiceOpportunityId::from_content_id(ContentId::for_bytes(
                ObjectKind::CampaignFact,
                1,
                &ordinal.to_be_bytes(),
            ))
            .expect("choice id")
        })
        .collect::<BTreeSet<_>>();
    assert!(matches!(
        Observation::new(
            observation.attempt(),
            observation.child(),
            observation.child_content(),
            observation.path(),
            observation.stop().clone(),
            observation.measurements(),
            observation.properties(),
            observation.coverage(),
            excessive_choices,
        ),
        Err(CampaignCodecError::LimitExceeded {
            limit: "observation-discovered-choice-count"
        })
    ));
}

fn selectable_fixture(
    name: &str,
    domain: ChoiceDomain,
    default: ChoiceValue,
) -> SelectableDeclaration {
    SelectableDeclaration::new(
        name,
        ChoiceSource::Workload {
            producer: "campaign-test".to_owned(),
        },
        domain,
        default,
        ChoiceClassContext::new(BTreeSet::new()).expect("class context"),
        BTreeSet::new(),
        true,
    )
    .expect("selectable declaration")
}

#[test]
fn finding_and_reproduction_records_round_trip_with_exact_children() {
    let scenario = ScenarioDefId::from_hash(hash("finding-scenario"));
    let scenario_artifact =
        ScenarioArtifact::new(scenario, 1, b"scenario".to_vec()).expect("scenario artifact");
    let scenario_artifact_id = scenario_artifact.id().expect("scenario artifact id");
    let configuration = ConfigurationId::from_hash(hash("finding-configuration"));
    let configuration_artifact = ConfigurationArtifact::new(
        scenario,
        scenario_artifact_id,
        configuration,
        1,
        b"configuration".to_vec(),
    )
    .expect("configuration artifact");
    let configuration_artifact_id = configuration_artifact
        .id()
        .expect("configuration artifact id");
    let fingerprint = hash("finding-fingerprint");
    let reproduction = ReproductionArtifact::new(
        scenario,
        scenario_artifact_id,
        configuration,
        configuration_artifact_id,
        fingerprint,
        1,
        b"self-contained reproduction".to_vec(),
    )
    .expect("reproduction");
    let reproduction_id = reproduction.id().expect("reproduction id");
    assert_eq!(
        ReproductionArtifact::from_canonical_bytes(&reproduction.canonical_bytes())
            .expect("decode reproduction"),
        reproduction
    );

    let evidence = ContentId::for_bytes(ObjectKind::Trace, 1, b"causal-evidence");
    let signature = FindingSignature::new(
        FindingKind::PropertyViolation,
        fingerprint,
        Some("network.delivery".to_owned()),
        "guest.assertion".to_owned(),
        Some(FindingTarget::Configuration(configuration_artifact_id)),
        BTreeSet::from([evidence]),
    )
    .expect("signature");
    let observation = ObservationId::from_content_id(ContentId::for_bytes(
        ObjectKind::Observation,
        1,
        b"finding-observation",
    ))
    .expect("observation id");
    let first_seen = CampaignSnapshotId::from_content_id(ContentId::for_bytes(
        ObjectKind::CampaignSnapshot,
        2,
        b"finding-parent-snapshot",
    ))
    .expect("snapshot id");
    let finding = Finding::new(
        signature.clone(),
        observation,
        reproduction_id,
        first_seen,
        FindingOccurrenceSet::new(
            ContentId::for_bytes(ObjectKind::MerkleNode, 1, b"finding occurrences"),
            1,
            observation,
        )
        .expect("occurrences"),
        None,
        BTreeSet::new(),
    )
    .expect("finding");
    assert_eq!(
        Finding::from_canonical_bytes(&finding.canonical_bytes()).expect("decode finding"),
        finding
    );
    assert_eq!(signature.cluster_key(), finding.signature().cluster_key());

    let envelope = ObjectEnvelope::for_record(
        CampaignRecordKind::Finding,
        crate::object::content_children(finding.content_children()).expect("finding children"),
        finding.canonical_bytes(),
    )
    .expect("finding envelope");
    assert_eq!(
        envelope,
        ObjectEnvelope::from_canonical_bytes(&envelope.canonical_bytes()).expect("decode envelope")
    );
    assert!(
        envelope
            .children()
            .iter()
            .any(|child| child.id() == evidence)
    );
    assert!(
        envelope
            .children()
            .iter()
            .any(|child| child.id() == reproduction_id.content_id())
    );
}

#[test]
fn finding_signature_and_membership_invariants_fail_closed() {
    assert!(matches!(
        FindingSignature::new(
            FindingKind::PropertyViolation,
            hash("missing-property"),
            None,
            "guest.assertion".to_owned(),
            None,
            BTreeSet::new(),
        ),
        Err(CampaignCodecError::InvalidValue {
            reason: "finding property identity disagrees with failure kind"
        })
    ));

    let observation = ObservationId::from_content_id(ContentId::for_bytes(
        ObjectKind::Observation,
        1,
        b"omitted-observation",
    ))
    .expect("observation id");
    assert!(matches!(
        FindingOccurrenceSet::new(
            ContentId::for_bytes(ObjectKind::MerkleNode, 1, b"empty occurrences"),
            0,
            observation,
        ),
        Err(CampaignCodecError::LimitExceeded {
            limit: "finding-occurrence-count"
        })
    ));
    assert!(matches!(
        FindingOccurrenceSet::new(
            ContentId::for_bytes(ObjectKind::Trace, 1, b"not a merkle root"),
            1,
            observation,
        ),
        Err(CampaignCodecError::InvalidValue {
            reason: "finding occurrence root is not a Merkle node"
        })
    ));
}

fn hash(label: &str) -> CampaignHash {
    CampaignHash::derive("crucible.campaign.test-fixture.v1", label.as_bytes())
}

fn content(label: &str) -> ContentId {
    content_kind(label, ObjectKind::MerkleNode)
}

fn content_kind(label: &str, kind: ObjectKind) -> ContentId {
    ContentId::for_bytes(kind, 1, label.as_bytes())
}
