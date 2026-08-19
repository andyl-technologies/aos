//! Unit tests for campaign canonical primitives.

#![allow(clippy::expect_used)]

use super::codec::{Canonical, Decoder, Encoder, decode, encode};
use super::*;
use crucible_cas::content_store::{ContentId, ObjectKind};
use std::collections::{BTreeMap, BTreeSet};

macro_rules! stored_id {
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
    let registry = include_str!("../../../docs/rfcs/0015-crucible-campaigns/schema-registry.tsv");
    let implementation_plan =
        include_str!("../../../docs/rfcs/0015-crucible-campaigns/11-implementation-plan.md");
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
            _ => "crucible-campaign::object",
        };
        assert_eq!(row[2], expected_owner);
        assert_eq!(row[3], kind.object_kind().as_str());
    }
    let owned_campaign_schemas = CampaignRecordKind::ALL
        .into_iter()
        .map(CampaignRecordKind::schema_name)
        .collect::<BTreeSet<_>>();
    for (schema, row) in &rows {
        if schema.starts_with("crucible.campaign.") {
            assert!(
                owned_campaign_schemas.contains(schema),
                "registry contains an unowned campaign schema {schema}"
            );
            assert_eq!(row[1], "1", "campaign schema version drift for {schema}");
        }
    }
    for (schema, owner) in [
        (
            "crucible.content-envelope",
            "crucible-cas::content_envelope",
        ),
        ("crucible.content-id-text", "crucible-cas::content_store"),
        ("crucible.directory-ref", "crucible-cas::content_store"),
    ] {
        let row = rows
            .get(schema)
            .unwrap_or_else(|| panic!("missing lower schema {schema}"));
        assert_eq!(row[1], "1");
        assert_eq!(row[2], owner);
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
fn snapshot_planning_view_excludes_pins_but_snapshot_identity_does_not() {
    let roots = CampaignRoots {
        graph: content("graph"),
        exploration: content("exploration"),
        observations: content("observations"),
        corpus: content("corpus"),
        coverage: content("coverage"),
        findings: content("findings"),
        pins: content("pins-a"),
        accounting: content("accounting"),
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
        budget,
    )
    .expect("invocation");
    let more_fuel = PlannerInvocation::new(
        invocation.engine(),
        invocation.policy_artifact(),
        invocation.policy(),
        invocation.planner_state(),
        invocation.input_view(),
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
    let expected_snapshot =
        stored_id!(CampaignSnapshotId, ObjectKind::CampaignSnapshot, "snapshot");
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
    let first = CampaignFact::AttemptAdmitted {
        attempt,
        ordinal: AdmissionOrdinal::new(7),
    };
    let second = CampaignFact::AttemptAdmitted {
        attempt,
        ordinal: AdmissionOrdinal::new(8),
    };
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
    };
    let parent = stored_id!(
        CampaignSnapshotId,
        ObjectKind::CampaignSnapshot,
        "parent-snapshot"
    );
    let transition = stored_id!(CampaignFactId, ObjectKind::CampaignFact, "transition");
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
    assert_eq!(envelope.children().len(), 12);
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
        1,
        extra_children,
        snapshot.canonical_bytes(),
    )
    .expect("generic extra-child envelope");
    assert!(matches!(
        ObjectEnvelope::from_canonical_bytes(&extra.canonical_bytes()),
        Err(CampaignCodecError::InvalidValue { .. })
    ));
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

fn hash(label: &str) -> CampaignHash {
    CampaignHash::derive("crucible.campaign.test-fixture.v1", label.as_bytes())
}

fn content(label: &str) -> ContentId {
    content_kind(label, ObjectKind::MerkleNode)
}

fn content_kind(label: &str, kind: ObjectKind) -> ContentId {
    ContentId::for_bytes(kind, 1, label.as_bytes())
}
