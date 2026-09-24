//! Unit tests for campaign canonical primitives.

// crucible-lint: allow panic-shortcut -- test fixtures use panic shortcuts for exact failure localization.
#![allow(clippy::expect_used)]

use super::codec::{Canonical, Decoder, Encoder, decode, encode};
use super::*;
use crucible_cas::content_store::{
    BlobHandle, ContentId, ObjectKind, Reconstructibility, RetentionRole, SensitivityClass,
    StoreError, StoreObjectProfiler,
};
use std::collections::{BTreeMap, BTreeSet};

mod schema_registry;

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

    let policy_id = stored_id!(CampaignPolicyId, ObjectKind::Policy, 5, "policy");
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
fn exact_checkpoint_identity_admits_only_the_current_schema() {
    let current = ContentId::for_bytes(ObjectKind::ExactManifest, 5, b"current exact root");
    assert!(ExactCheckpointId::try_from(current).is_ok());

    let pre_choice_root = ContentId::for_bytes(ObjectKind::ExactManifest, 4, b"pre-choice root");
    assert!(ExactCheckpointId::try_from(pre_choice_root).is_err());

    let wrong_version =
        ContentId::for_bytes(ObjectKind::ExactManifest, u32::MAX, b"wrong exact root");
    assert!(ExactCheckpointId::try_from(wrong_version).is_err());
}

#[test]
fn content_identities_admit_only_current_registry_versions() {
    macro_rules! assert_current_version {
        ($type:ty, $kind:expr, $version:expr) => {{
            let current = ContentId::for_bytes($kind, $version, b"current identity");
            assert!(<$type>::from_content_id(current).is_ok());

            let wrong_version = ContentId::for_bytes($kind, u32::MAX, b"wrong identity");
            assert!(<$type>::from_content_id(wrong_version).is_err());
        }};
    }

    assert_current_version!(CampaignPolicyId, ObjectKind::Policy, 5);
    assert_current_version!(CampaignFactId, ObjectKind::CampaignFact, 15);
    assert_current_version!(BranchRequestId, ObjectKind::CampaignFact, 10);
    assert_current_version!(ProposalId, ObjectKind::CampaignFact, 3);
    assert_current_version!(AttemptId, ObjectKind::CampaignFact, 9);
    assert_current_version!(ObservationId, ObjectKind::Observation, 14);
    assert_current_version!(ObjectiveEvaluationId, ObjectKind::Observation, 2);
    assert_current_version!(RankingExplanationId, ObjectKind::Projection, 2);
    assert_current_version!(FindingId, ObjectKind::Finding, 4);
    assert_current_version!(FindingCandidateBundleId, ObjectKind::Finding, 7);
    assert_current_version!(FindingTriageReplayEvidenceId, ObjectKind::Finding, 2);
    assert_current_version!(ReproductionArtifactId, ObjectKind::Finding, 2);
    assert_current_version!(PlannerBeamCandidateId, ObjectKind::Projection, 2);
}

#[test]
fn schema_registry_is_unique_complete_and_names_real_gates() {
    schema_registry::schema_registry_is_unique_complete_and_names_real_gates();
}

#[test]
fn campaign_policy_identity_is_order_independent_and_strictly_decoded() {
    let generator = stored_id!(CandidateGeneratorSpecId, ObjectKind::Policy, "generator");
    let choice = ChoicePolicy::new("product.recovery", generator, true).expect("choice policy");
    let objective = Objective::new("recovery.latency-ns", ObjectiveGoal::Minimize, 1_000_000)
        .expect("objective");
    let guidance = GuidanceWeight::new("coverage", 250_000).expect("guidance");
    let policy = CampaignPolicy::new(
        CampaignPolicy::identity(
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
        ),
        CampaignPolicy::rules(
            BTreeMap::from([("product.recovery".to_owned(), choice)]),
            BTreeMap::from([("recovery.latency-ns".to_owned(), objective)]),
            BTreeMap::from([("coverage".to_owned(), guidance)]),
            BTreeSet::from(["measurement.recovery".to_owned()]),
            FairnessPolicy::new(10, 8).expect("fairness"),
            RetentionPolicy::new(true, 64, true, true),
            false,
        ),
    )
    .expect("campaign policy");
    assert_eq!(
        policy.intervention_learning_policy(),
        InterventionLearningPolicy::Exclude
    );

    let bytes = policy.canonical_bytes();
    assert_eq!(
        CampaignPolicy::from_canonical_bytes(&bytes).expect("canonical policy"),
        policy
    );
    let mut wrong_version = bytes.clone();
    wrong_version[..4].copy_from_slice(&u32::MAX.to_be_bytes());
    assert!(CampaignPolicy::from_canonical_bytes(&wrong_version).is_err());

    let mut trailing = bytes;
    trailing.push(0);
    assert_eq!(
        CampaignPolicy::from_canonical_bytes(&trailing),
        Err(CampaignCodecError::TrailingBytes)
    );
    let policy_id = policy.id().expect("policy id");
    assert_eq!(policy_id.content_id().kind(), ObjectKind::Policy);
    assert_eq!(policy_id.content_id().schema_version(), 5);
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
    let envelope_bytes = envelope.canonical_bytes();
    let profile = CampaignObjectProfiler
        .derive_profile(
            envelope.content_id(),
            &BlobHandle::from_bytes(envelope_bytes),
        )
        .expect("campaign object profile");
    assert_eq!(profile.kind(), ObjectKind::Policy);
    assert_eq!(profile.sensitivity(), SensitivityClass::Metadata);
    assert_eq!(profile.reconstructibility(), Reconstructibility::Canonical);
    assert_eq!(profile.retention_role(), RetentionRole::CampaignMetadata);

    let opted_in = policy
        .clone()
        .with_intervention_learning_policy(InterventionLearningPolicy::IncludeInGuidance)
        .expect("opt-in campaign policy");
    assert_eq!(
        CampaignPolicy::from_canonical_bytes(&opted_in.canonical_bytes())
            .expect("current campaign policy"),
        opted_in
    );
    assert_eq!(
        opted_in.intervention_learning_policy(),
        InterventionLearningPolicy::IncludeInGuidance
    );
    assert_eq!(
        opted_in
            .id()
            .expect("current policy ID")
            .content_id()
            .schema_version(),
        5
    );

    let mut malformed = envelope.canonical_bytes();
    malformed.push(0);
    let malformed_id = ContentId::for_bytes(ObjectKind::Policy, 5, &malformed);
    assert!(matches!(
        CampaignObjectProfiler.derive_profile(
            malformed_id,
            &BlobHandle::from_bytes(malformed),
        ),
        Err(StoreError::Corrupt { id }) if id == malformed_id
    ));
}

#[test]
fn campaign_object_profile_classifies_opaque_state_without_reading_a_caller_hint() {
    let bytes = b"opaque exact guest state";
    let id = ContentId::for_bytes(ObjectKind::RamExtent, 1, bytes);
    let profile = CampaignObjectProfiler
        .derive_profile(id, &BlobHandle::from_bytes(bytes))
        .expect("opaque object profile");

    assert_eq!(profile.kind(), ObjectKind::RamExtent);
    assert_eq!(profile.logical_length(), bytes.len() as u64);
    assert_eq!(profile.sensitivity(), SensitivityClass::GuestState);
    assert_eq!(profile.reconstructibility(), Reconstructibility::Canonical);
    assert_eq!(profile.retention_role(), RetentionRole::ExactState);
}

#[test]
fn campaign_object_profile_rejects_raw_observation_without_exact_root_role() {
    let bytes = b"raw checkpoint choice bytes";
    let id = ContentId::for_bytes(ObjectKind::Observation, 1, bytes);

    assert!(matches!(
        CampaignObjectProfiler.derive_profile(id, &BlobHandle::from_bytes(bytes)),
        Err(StoreError::Corrupt { id: corrupt }) if corrupt == id
    ));
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
        stored_id!(CampaignPolicyId, ObjectKind::Policy, 5, "policy"),
        roots,
        crate::test_budget_ledger_id(),
    )
    .expect("genesis snapshot");
    let mut changed_roots = roots;
    changed_roots.pins = content("pins-b");
    let changed = CampaignSnapshot::genesis(
        snapshot.lineage(),
        snapshot.active_policy(),
        changed_roots,
        crate::test_budget_ledger_id(),
    )
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
        crate::test_budget_ledger_id(),
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
fn planner_candidate_guidance_retains_objective_reward() {
    let input_view = stored_id!(CampaignViewId, ObjectKind::CampaignFact, "guidance-view");
    let policy_value = CampaignPolicy::new(
        CampaignPolicy::identity(
            ScenarioDefId::from_hash(hash("guidance-scenario")),
            CampaignSeed::from_bytes([0x37; 32]),
            CampaignMode::Strict,
            ExplorerPolicy::TreeSearch {
                puct: PuctPolicy::new(0, 0, 0),
                widening: None,
            },
        ),
        CampaignPolicy::rules(
            BTreeMap::new(),
            BTreeMap::from([(
                "guidance-objective".to_owned(),
                Objective::new("guidance-objective", ObjectiveGoal::Maximize, 1_000_000)
                    .expect("guidance objective"),
            )]),
            BTreeMap::new(),
            BTreeSet::new(),
            FairnessPolicy::new(1, 1).expect("guidance fairness"),
            RetentionPolicy::new(false, 1, false, false),
            false,
        ),
    )
    .expect("guidance policy");
    let policy = policy_value.id().expect("guidance policy ID");
    let request = stored_id!(
        BranchRequestId,
        ObjectKind::CampaignFact,
        10,
        "guidance-request"
    );
    let branch_point = BranchPointId::from_hash(hash("guidance-branch-point"));
    let position = PlanningScanPosition::new(branch_point, request);
    let domain = stored_id!(
        ChoiceDomainId,
        ObjectKind::CampaignFact,
        2,
        "guidance-domain"
    );
    let domain_semantics = ChoiceDomainSemanticId::from_hash(hash("guidance-domain-semantics"));
    let value = ChoiceValue::Boolean(true);
    let edge = Selection::campaign_edge_id(branch_point, domain_semantics, &value);
    let statistics = PuctEdgeStatistics::new(1, 1, -500_000, 1_000_000, false, true)
        .expect("objective statistics");
    let current = PlannerCandidateGuidance::new(
        input_view,
        policy,
        position,
        domain,
        domain_semantics,
        value.clone(),
        1,
        edge,
        statistics,
        0,
        -500_000,
        BTreeMap::new(),
    )
    .expect("v2 candidate guidance");
    assert_eq!(current.objective_reward_micros(), -500_000);
    assert_eq!(
        current
            .score_for_policy(&policy_value, input_view)
            .expect("objective guidance score")
            .mean_reward_micros(),
        -500_000
    );
    assert_eq!(
        PlannerCandidateGuidance::from_canonical_bytes(&current.canonical_bytes())
            .expect("v2 guidance round trip"),
        current
    );
    assert_eq!(
        current
            .id()
            .expect("v2 guidance ID")
            .content_id()
            .schema_version(),
        2
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
        "qemu-11.1.1-profile-a",
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
        "qemu-11.1.1-profile-b",
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
        stored_id!(CampaignPolicyId, ObjectKind::Policy, 5, "policy"),
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
    let policy = stored_id!(CampaignPolicyId, ObjectKind::Policy, 5, "policy");
    let expected_snapshot = stored_id!(
        CampaignSnapshotId,
        ObjectKind::CampaignSnapshot,
        3,
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

    let attempt = stored_id!(AttemptId, ObjectKind::CampaignFact, 9, "attempt");
    let first = CampaignFact::AttemptAdmitted(
        AttemptAdmission::new(
            attempt,
            AttemptAdmissionRole::ExecutionBasis {
                proposal: None,
                cause: BranchRequestCause::Operator(command),
                admission_ordinal: AdmissionOrdinal::new(7),
            },
            policy,
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
            policy,
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

    let terminal = CampaignFact::AttemptClosed {
        attempt,
        ordinal: AdmissionOrdinal::new(7),
        disposition: NonModeledAttemptDisposition::TerminalWorkerFailure,
    };
    let terminal_bytes = terminal.canonical_bytes();
    assert_eq!(&terminal_bytes[..4], &15_u32.to_be_bytes());
    assert_eq!(terminal_bytes[4], 9);
    assert_eq!(
        CampaignFact::from_canonical_bytes(&terminal_bytes).expect("terminal closure fact"),
        terminal
    );
    let terminal_envelope = ObjectEnvelope::for_fact(&terminal).expect("terminal fact envelope");
    assert_eq!(terminal_envelope.content_id().schema_version(), 15);

    let credited = CampaignFact::ObservationCredited(stored_id!(
        ObservationId,
        ObjectKind::Observation,
        14,
        "credited-observation"
    ));
    assert_eq!(
        &credited.canonical_bytes()[..std::mem::size_of::<u32>()],
        &15_u32.to_be_bytes()
    );
    assert_eq!(credited.canonical_bytes()[4], 11);
    let credited_envelope = ObjectEnvelope::for_fact(&credited).expect("credited fact envelope");
    assert_eq!(credited_envelope.content_id().schema_version(), 15);
    assert_eq!(
        CampaignFact::from_canonical_bytes(credited_envelope.body())
            .expect("canonical credited fact"),
        credited
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
        &15_u32.to_be_bytes()
    );
    assert_eq!(pin.canonical_bytes()[4], 12);
    let pin_envelope = ObjectEnvelope::for_fact(&pin).expect("pin fact envelope");
    assert_eq!(pin_envelope.content_id().schema_version(), 15);
    assert_eq!(pin_envelope.children().len(), 1);
    assert_eq!(
        CampaignFact::from_canonical_bytes(pin_envelope.body()).expect("canonical pin fact"),
        pin
    );

    let branch = CampaignFact::BranchRequestAccepted {
        request: stored_id!(
            BranchRequestId,
            ObjectKind::CampaignFact,
            10,
            "accepted-branch-request"
        ),
        summary: BranchAcceptanceSummary::new(
            BranchAcceptanceCount::Exact(2),
            BranchAcceptanceCount::Exact(0),
            BranchAcceptanceCount::Exact(2),
            2,
            1,
        )
        .expect("branch acceptance summary"),
    };
    assert_eq!(
        &branch.canonical_bytes()[..std::mem::size_of::<u32>()],
        &15_u32.to_be_bytes()
    );
    assert_eq!(branch.canonical_bytes()[4], 14);
    let branch_envelope = ObjectEnvelope::for_fact(&branch).expect("branch acceptance envelope");
    assert_eq!(branch_envelope.content_id().schema_version(), 15);
    assert_eq!(branch_envelope.children().len(), 1);
    assert_eq!(
        CampaignFact::from_canonical_bytes(branch_envelope.body())
            .expect("canonical branch acceptance fact"),
        branch
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
    domain.u32(2);
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
        BranchRequest::identity(
            branch_point,
            parent.id().expect("parent id"),
            opportunity.id().expect("opportunity id"),
            domain.id().expect("domain id"),
        ),
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
    let request_envelope = ObjectEnvelope::for_record_versioned(
        CampaignRecordKind::BranchRequest,
        request.schema_version(),
        super::object::content_children(request.content_children()).expect("request children"),
        request.canonical_bytes(),
    )
    .expect("request envelope");
    assert_eq!(
        ObjectEnvelope::from_canonical_bytes(&request_envelope.canonical_bytes())
            .expect("request decode"),
        request_envelope
    );
    let encode_request_body = |schema_version: u32, source: &CandidateSource| {
        let mut encoder = Encoder::new();
        schema_version.encode(&mut encoder);
        request.branch_point().encode(&mut encoder);
        request.parent().encode(&mut encoder);
        request.opportunity().encode(&mut encoder);
        request.domain().encode(&mut encoder);
        source.encode(&mut encoder);
        request.cause().encode(&mut encoder);
        request.budget().encode(&mut encoder);
        request.stop().encode(&mut encoder);
        encoder.finish()
    };
    assert!(matches!(
        BranchRequest::from_canonical_bytes(&encode_request_body(7, request.source())),
        Err(CampaignCodecError::InvalidValue {
            reason: "unsupported branch-request schema or source"
        })
    ));

    let weighted_source = CandidateSource::weighted_finite(BTreeMap::from([
        (ChoiceValue::Integer(IntegerValue::Unsigned(0)), 1),
        (ChoiceValue::Integer(IntegerValue::Unsigned(10)), u64::MAX),
    ]))
    .expect("weighted source");
    assert_eq!(
        decode::<CandidateSource>(&encode(&weighted_source)).expect("weighted source round trip"),
        weighted_source
    );
    assert!(matches!(
        CandidateSource::weighted_finite(BTreeMap::from([(ChoiceValue::Boolean(true), 0)])),
        Err(CampaignCodecError::InvalidValue {
            reason: "weighted finite candidate source is empty, oversized, or has zero weight"
        })
    ));
    assert!(matches!(
        BranchRequest::from_canonical_bytes(&encode_request_body(1, &weighted_source)),
        Err(CampaignCodecError::InvalidValue {
            reason: "unsupported branch-request schema or source"
        })
    ));
    assert!(matches!(
        BranchRequest::from_canonical_bytes(&encode_request_body(2, &weighted_source)),
        Err(CampaignCodecError::InvalidValue {
            reason: "unsupported branch-request schema or source"
        })
    ));

    let model = ProbabilityModelId::from_hash(hash("retry-delay-model"));
    let modeled_source = CandidateSource::modeled_finite(
        model,
        BTreeMap::from([
            (ChoiceValue::Integer(IntegerValue::Unsigned(0)), 1),
            (ChoiceValue::Integer(IntegerValue::Unsigned(10)), 9),
        ]),
    )
    .expect("model-resolved finite source");
    assert_eq!(modeled_source.model_prior(), Some(model));
    assert_eq!(
        modeled_source.prior_weight(&ChoiceValue::Integer(IntegerValue::Unsigned(10))),
        Some(9)
    );
    assert!(matches!(
        CandidateSource::modeled_finite(model, BTreeMap::from([(ChoiceValue::Boolean(true), 0)])),
        Err(CampaignCodecError::InvalidValue {
            reason: "modeled finite candidate source is empty, oversized, or has zero weight"
        })
    ));
    assert!(matches!(
        BranchRequest::from_canonical_bytes(&encode_request_body(2, &modeled_source)),
        Err(CampaignCodecError::InvalidValue {
            reason: "unsupported branch-request schema or source"
        })
    ));
    let modeled_opportunity = ChoiceOpportunity::new(
        scenario,
        &declaration,
        &domain,
        ChoiceCoordinate {
            scheduler: hash("scheduler"),
            producer: hash("producer"),
        },
        "retry-1",
        Some(model),
    )
    .expect("modeled opportunity");
    let explicit_override = BranchRequest::new(
        BranchRequest::identity(
            modeled_opportunity.branch_point_id(parent_configuration),
            parent.id().expect("parent id"),
            modeled_opportunity.id().expect("modeled opportunity id"),
            domain.id().expect("domain id"),
        ),
        weighted_source,
        cause,
        BranchBudget::new(2, 2).expect("explicit override budget"),
        StopCondition::NextChoice,
    )
    .expect("explicitly weighted modeled-opportunity request");
    explicit_override
        .validate_resolved(&parent, &modeled_opportunity, &domain)
        .expect("explicit source takes precedence over an available model");
    let modeled_request = BranchRequest::new(
        BranchRequest::identity(
            modeled_opportunity.branch_point_id(parent_configuration),
            parent.id().expect("parent id"),
            modeled_opportunity.id().expect("modeled opportunity id"),
            domain.id().expect("domain id"),
        ),
        modeled_source,
        cause,
        BranchBudget::new(2, 2).expect("modeled budget"),
        StopCondition::NextChoice,
    )
    .expect("modeled request");
    assert_eq!(modeled_request.schema_version(), 10);
    assert_eq!(
        BranchRequest::from_canonical_bytes(&modeled_request.canonical_bytes())
            .expect("current modeled branch-request round trip"),
        modeled_request
    );
    modeled_request
        .validate_resolved(&parent, &modeled_opportunity, &domain)
        .expect("model-resolved request");

    let modeled_generator = stored_id!(
        CandidateGeneratorSpecId,
        ObjectKind::Policy,
        "modeled-generator"
    );
    let modeled_generated_source = CandidateSource::modeled_generated(model, modeled_generator);
    assert_eq!(modeled_generated_source.model_prior(), Some(model));
    assert_eq!(
        modeled_generated_source.generator(),
        Some(modeled_generator)
    );
    assert_eq!(
        decode::<CandidateSource>(&encode(&modeled_generated_source))
            .expect("modeled generated source round trip"),
        modeled_generated_source
    );
    assert!(matches!(
        BranchRequest::from_canonical_bytes(&encode_request_body(3, &modeled_generated_source)),
        Err(CampaignCodecError::InvalidValue {
            reason: "unsupported branch-request schema or source"
        })
    ));
    let modeled_generated_request = BranchRequest::new(
        BranchRequest::identity(
            modeled_opportunity.branch_point_id(parent_configuration),
            parent.id().expect("parent id"),
            modeled_opportunity.id().expect("modeled opportunity id"),
            domain.id().expect("domain id"),
        ),
        modeled_generated_source,
        cause,
        BranchBudget::new(2, 2).expect("modeled generated budget"),
        StopCondition::NextChoice,
    )
    .expect("modeled generated request");
    assert_eq!(modeled_generated_request.schema_version(), 10);
    assert_eq!(
        BranchRequest::from_canonical_bytes(&modeled_generated_request.canonical_bytes())
            .expect("current modeled generated branch-request round trip"),
        modeled_generated_request
    );
    assert!(
        modeled_generated_request
            .content_children()
            .contains(&("generator", modeled_generator.content_id()))
    );
    modeled_generated_request
        .validate_resolved(&parent, &modeled_opportunity, &domain)
        .expect("modeled generated request basis");

    let wrong_model = ProbabilityModelId::from_hash(hash("wrong-retry-delay-model"));
    let mismatched_request = BranchRequest::new(
        BranchRequest::identity(
            modeled_opportunity.branch_point_id(parent_configuration),
            parent.id().expect("parent id"),
            modeled_opportunity.id().expect("modeled opportunity id"),
            domain.id().expect("domain id"),
        ),
        CandidateSource::modeled_finite(
            wrong_model,
            BTreeMap::from([
                (ChoiceValue::Integer(IntegerValue::Unsigned(0)), 1),
                (ChoiceValue::Integer(IntegerValue::Unsigned(10)), 9),
            ]),
        )
        .expect("mismatched modeled source"),
        cause,
        BranchBudget::new(2, 2).expect("mismatched budget"),
        StopCondition::NextChoice,
    )
    .expect("structurally valid mismatched modeled request");
    assert!(matches!(
        mismatched_request.validate_resolved(&parent, &modeled_opportunity, &domain),
        Err(CampaignCodecError::InvalidValue {
            reason: "branch request modeled prior disagrees with its opportunity"
        })
    ));

    let proposal = Proposal::new(
        branch_point,
        request.id().expect("request id"),
        domain.id().expect("domain id"),
        ChoiceValue::Integer(IntegerValue::Unsigned(10)),
        stored_id!(CampaignPolicyId, ObjectKind::Policy, 5, "policy"),
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
        stored_id!(CampaignPolicyId, ObjectKind::Policy, 5, "policy"),
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
        stored_id!(CampaignPolicyId, ObjectKind::Policy, 5, "policy"),
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
        [BranchPathSegment::new(branch_point, edge)].as_slice()
    );
    assert_eq!(
        BranchPath::from_canonical_bytes(&path.canonical_bytes()).expect("canonical path"),
        path
    );
    let path_envelope = super::object::ObjectEnvelope::for_branch_path(&path)
        .expect("current branch path envelope");
    assert_eq!(path_envelope.content_id().schema_version(), 2);
}

#[test]
fn continuation_inputs_are_canonical_bounded_and_attempt_identifying() {
    let origin = stored_id!(
        AttemptId,
        ObjectKind::CampaignFact,
        9,
        "continuation-input-origin"
    );
    let reached = stored_id!(
        ConfigurationArtifactId,
        ObjectKind::Configuration,
        "continuation-input-reached"
    );
    let path = stored_id!(
        BranchPathId,
        ObjectKind::CampaignFact,
        2,
        "continuation-input-path"
    );
    let source_observation = stored_id!(
        ObservationId,
        ObjectKind::Observation,
        14,
        "continuation-input-source-observation"
    );
    let another_source_observation = stored_id!(
        ObservationId,
        ObjectKind::Observation,
        14,
        "continuation-input-another-source-observation"
    );
    let start = AttemptStart::AfterAttempt { origin, reached };

    let base_seed = AttemptContinuationInput::scheduler_reseed(source_observation, 17, [0; 32]);
    let mut changed_seed_bytes = [0; 32];
    changed_seed_bytes[31] = 1;
    let changed_seed =
        AttemptContinuationInput::scheduler_reseed(source_observation, 17, changed_seed_bytes);
    let changed_source =
        AttemptContinuationInput::scheduler_reseed(another_source_observation, 17, [0; 32]);
    let seed_attempt = Attempt::new_with_continuation_input(
        start,
        path,
        StopCondition::Terminal,
        base_seed.clone(),
    )
    .expect("seed continuation attempt");
    let changed_seed_attempt =
        Attempt::new_with_continuation_input(start, path, StopCondition::Terminal, changed_seed)
            .expect("changed-seed continuation attempt");
    let changed_source_attempt =
        Attempt::new_with_continuation_input(start, path, StopCondition::Terminal, changed_source)
            .expect("changed-source continuation attempt");

    assert_eq!(seed_attempt.schema_version(), 9);
    assert_eq!(seed_attempt.continuation_input(), Some(&base_seed));
    assert_ne!(
        seed_attempt.id().expect("seed attempt id"),
        changed_seed_attempt.id().expect("changed seed attempt id")
    );
    assert_ne!(
        seed_attempt.id().expect("seed attempt id"),
        changed_source_attempt
            .id()
            .expect("changed source attempt id")
    );
    assert!(
        seed_attempt
            .content_children()
            .contains(&("source-observation", source_observation.content_id()))
    );
    assert_eq!(
        Attempt::from_canonical_bytes(&seed_attempt.canonical_bytes())
            .expect("canonical seed continuation attempt"),
        seed_attempt
    );

    let observed_attempt = Attempt::new_with_continuation_input(
        start,
        path,
        StopCondition::Observation(ObservationCondition::SchedulerQuiescent),
        base_seed.clone(),
    )
    .expect("observed continuation attempt");
    assert_eq!(observed_attempt.schema_version(), 9);
    assert_eq!(
        Attempt::from_canonical_bytes(&observed_attempt.canonical_bytes())
            .expect("canonical observed continuation attempt"),
        observed_attempt
    );

    let first = vec![0x10, 0x20];
    let second = vec![0x30, 0x40];
    let changed = vec![0x30, 0x41];
    let ordered = AttemptContinuationInput::scheduler_selections(
        source_observation,
        17,
        vec![first.clone(), second.clone()],
    )
    .expect("ordered override input");
    let reordered = AttemptContinuationInput::scheduler_selections(
        source_observation,
        17,
        vec![second.clone(), first.clone()],
    )
    .expect("reordered override input");
    let changed_value = AttemptContinuationInput::scheduler_selections(
        source_observation,
        17,
        vec![first.clone(), changed],
    )
    .expect("changed override input");

    let ordered_attempt =
        Attempt::new_with_continuation_input(start, path, StopCondition::Terminal, ordered.clone())
            .expect("ordered override attempt");
    let reordered_attempt =
        Attempt::new_with_continuation_input(start, path, StopCondition::Terminal, reordered)
            .expect("reordered override attempt");
    let changed_value_attempt =
        Attempt::new_with_continuation_input(start, path, StopCondition::Terminal, changed_value)
            .expect("changed override attempt");
    assert_ne!(
        ordered_attempt.id().expect("ordered override attempt id"),
        reordered_attempt
            .id()
            .expect("reordered override attempt id")
    );
    assert_ne!(
        ordered_attempt.id().expect("ordered override attempt id"),
        changed_value_attempt
            .id()
            .expect("changed override attempt id")
    );
    assert_eq!(
        decode::<AttemptContinuationInput>(&encode(&ordered)).expect("canonical override input"),
        ordered
    );

    assert!(matches!(
        AttemptContinuationInput::scheduler_selections(source_observation, 17, Vec::new()),
        Err(CampaignCodecError::InvalidValue {
            reason: "attempt continuation selection set is empty"
        })
    ));
    assert!(matches!(
        AttemptContinuationInput::scheduler_selections(
            source_observation,
            17,
            vec![first.clone(), first],
        ),
        Err(CampaignCodecError::InvalidValue {
            reason: "attempt continuation selection set contains a duplicate selection"
        })
    ));
    assert!(matches!(
        AttemptContinuationInput::scheduler_selections(
            source_observation,
            17,
            vec![vec![0; 1024 * 1024 + 1]],
        ),
        Err(CampaignCodecError::LimitExceeded {
            limit: "attempt-continuation-selection-item-bytes"
        })
    ));
    assert!(matches!(
        AttemptContinuationInput::scheduler_selections(
            source_observation,
            17,
            vec![vec![0]; 4_097],
        ),
        Err(CampaignCodecError::LimitExceeded {
            limit: "attempt-continuation-selection-count"
        })
    ));
    assert_eq!(
        decode::<AttemptContinuationInput>(&[2]),
        Err(CampaignCodecError::UnknownTag {
            kind: "attempt-continuation-input",
            tag: 2
        })
    );
    assert_eq!(
        decode::<AttemptContinuationInput>(&[0]),
        Err(CampaignCodecError::Truncated)
    );

    assert!(matches!(
        Attempt::new_with_continuation_input(
            AttemptStart::Discover {
                configuration: reached
            },
            path,
            StopCondition::Terminal,
            base_seed,
        ),
        Err(CampaignCodecError::InvalidValue {
            reason: "attempt continuation input requires an after-attempt start"
        })
    ));
    assert!(matches!(
        Attempt::new_with_continuation_input(
            start,
            path,
            StopCondition::Terminal,
            AttemptContinuationInput::SchedulerSelections {
                source_observation,
                source_frontier_ticks: 17,
                selections: Vec::new(),
            },
        ),
        Err(CampaignCodecError::InvalidValue {
            reason: "attempt continuation selection set is empty"
        })
    ));
}

#[test]
fn branch_request_variants_use_one_current_schema() {
    let branch_point = BranchPointId::from_hash(hash("scenario-default-branch-point"));
    let parent = stored_id!(
        ConfigurationArtifactId,
        ObjectKind::Configuration,
        "scenario-default-parent"
    );
    let opportunity = stored_id!(
        ChoiceOpportunityId,
        ObjectKind::CampaignFact,
        "scenario-default-opportunity"
    );
    let domain = stored_id!(
        ChoiceDomainId,
        ObjectKind::CampaignFact,
        2,
        "scenario-default-domain"
    );
    let policy = stored_id!(
        CampaignPolicyId,
        ObjectKind::Policy,
        5,
        "scenario-default-policy"
    );
    let operator = BranchRequestCause::Operator(CampaignCommandId::from_hash(hash(
        "scenario-default-vector-command",
    )));
    let finite = CandidateSource::finite(BTreeSet::from([ChoiceValue::Boolean(false)]))
        .expect("finite vector source");
    let encode_request =
        |schema_version: u32, source: &CandidateSource, cause: BranchRequestCause| {
            let mut encoder = Encoder::new();
            schema_version.encode(&mut encoder);
            branch_point.encode(&mut encoder);
            parent.encode(&mut encoder);
            opportunity.encode(&mut encoder);
            domain.encode(&mut encoder);
            source.encode(&mut encoder);
            cause.encode(&mut encoder);
            BranchBudget::new(1, 1)
                .expect("vector budget")
                .encode(&mut encoder);
            StopCondition::NextChoice.encode(&mut encoder);
            encoder.finish()
        };
    let model = ProbabilityModelId::from_hash(hash("scenario-default-vector-model"));
    let modeled_finite =
        CandidateSource::modeled_finite(model, BTreeMap::from([(ChoiceValue::Boolean(false), 1)]))
            .expect("modeled finite vector source");
    let modeled_generated = CandidateSource::modeled_generated(
        model,
        stored_id!(
            CandidateGeneratorSpecId,
            ObjectKind::Policy,
            "scenario-default-vector-generator"
        ),
    );
    for source in [&finite, &modeled_finite, &modeled_generated] {
        assert!(
            BranchRequest::from_canonical_bytes(&encode_request(u32::MAX, source, operator,))
                .is_err()
        );
    }

    let request = BranchRequest::new(
        BranchRequest::identity(branch_point, parent, opportunity, domain),
        finite,
        BranchRequestCause::ScenarioDefault(policy),
        BranchBudget::new(1, 1).expect("scenario-default vector budget"),
        StopCondition::NextChoice,
    )
    .expect("scenario-default vector request");
    assert_eq!(request.schema_version(), 10);
    assert_eq!(
        BranchRequest::from_canonical_bytes(&request.canonical_bytes())
            .expect("current scenario-default request"),
        request
    );

    let mut wrong_request_version = request.canonical_bytes();
    wrong_request_version[..4].copy_from_slice(&u32::MAX.to_be_bytes());
    assert!(BranchRequest::from_canonical_bytes(&wrong_request_version).is_err());
    let attempt = stored_id!(
        AttemptId,
        ObjectKind::CampaignFact,
        9,
        "scenario-default-attempt"
    );
    let proposal = stored_id!(
        ProposalId,
        ObjectKind::CampaignFact,
        3,
        "policy-bound-admission-proposal"
    );
    let causes = [
        BranchRequestCause::Planner(stored_id!(
            PlannerInvocationId,
            ObjectKind::Policy,
            2,
            "policy-bound-admission-planner"
        )),
        BranchRequestCause::Operator(CampaignCommandId::from_hash(hash(
            "policy-bound-admission-operator",
        ))),
        BranchRequestCause::Debugger(DebugSessionId::from_hash(hash(
            "policy-bound-admission-debugger",
        ))),
        BranchRequestCause::ExhaustivePolicy(policy),
        BranchRequestCause::ScenarioDefault(policy),
    ];
    for cause in causes {
        let bound = AttemptAdmission::new(
            attempt,
            AttemptAdmissionRole::ExecutionBasis {
                proposal: Some(proposal),
                cause,
                admission_ordinal: AdmissionOrdinal::new(7),
            },
            policy,
        );
        assert_eq!(bound.schema_version(), 3);
        assert_eq!(bound.retention_policy(), policy);
        assert_eq!(
            AttemptAdmission::from_canonical_bytes(&bound.canonical_bytes())
                .expect("policy-bound admission"),
            bound
        );
        let child_names = bound
            .content_children()
            .into_iter()
            .map(|(name, _)| name)
            .collect::<BTreeSet<_>>();
        assert!(child_names.contains("retention-policy"));
        assert!(!child_names.contains("source-snapshot"));
    }
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
    let encoded = crate::codec::encode(&group);
    let restored: ChoiceGroup = crate::codec::decode(&encoded).expect("v3 group round trip");
    assert_eq!(restored, group);
    assert_eq!(
        restored.id().expect("restored identity"),
        group.id().expect("group identity")
    );
    let omitted_bytes = crate::codec::encode(group.members()).len()
        + crate::codec::encode(group.declaration_semantics()).len();
    assert!(
        omitted_bytes > 127,
        "deriving identities saves the guest envelope overflow"
    );
    let mut obsolete_version = encoded;
    obsolete_version[..4].copy_from_slice(&crate::codec::encode(&2_u32));
    assert!(crate::codec::decode::<ChoiceGroup>(&obsolete_version).is_err());

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
fn atomic_group_flows_through_one_branch_request_proposal_and_selection() {
    let member_domain = ChoiceDomain::Boolean(BooleanDomain::new(1).expect("boolean domain"));
    let first_declaration = selectable_fixture(
        "network.first",
        member_domain.clone(),
        ChoiceValue::Boolean(false),
    );
    let second_declaration = selectable_fixture(
        "network.second",
        member_domain.clone(),
        ChoiceValue::Boolean(true),
    );
    let first = first_declaration.id().expect("first member");
    let second = second_declaration.id().expect("second member");
    let tuple = ChoiceTuple::new(BTreeMap::from([
        (first, ChoiceValue::Boolean(false)),
        (second, ChoiceValue::Boolean(true)),
    ]));
    let group = ChoiceGroup::new(
        &BTreeMap::from([(first, first_declaration), (second, second_declaration)]),
        ChoiceGroupDomain::Finite {
            members: BTreeMap::from([(first, member_domain.clone()), (second, member_domain)]),
            tuples: BTreeSet::from([tuple.clone()]),
        },
        ChoiceGroupApplication::new("network.fault", 1).expect("application"),
    )
    .expect("group");
    let group_value = ChoiceValue::Group(group.select(tuple).expect("admitted tuple"));
    let group_domain = ChoiceDomain::Group(Box::new(group));
    let declaration =
        selectable_fixture("fault.network", group_domain.clone(), group_value.clone());

    let scenario = ScenarioDefId::from_hash(hash("atomic scenario"));
    let scenario_artifact = ScenarioArtifact::new(scenario, 1, b"atomic".to_vec())
        .expect("scenario artifact")
        .id()
        .expect("scenario artifact id");
    let parent_configuration = ConfigurationId::from_hash(hash("atomic parent"));
    let parent = ConfigurationArtifact::new(
        scenario,
        scenario_artifact,
        parent_configuration,
        1,
        b"atomic parent".to_vec(),
    )
    .expect("parent artifact");
    let opportunity = ChoiceOpportunity::new(
        scenario,
        &declaration,
        &group_domain,
        ChoiceCoordinate {
            scheduler: hash("atomic scheduler"),
            producer: hash("atomic producer"),
        },
        "phase-1",
        None,
    )
    .expect("one group opportunity");
    let branch_point = opportunity.branch_point_id(parent_configuration);
    let request = BranchRequest::new(
        BranchRequest::identity(
            branch_point,
            parent.id().expect("parent id"),
            opportunity.id().expect("opportunity id"),
            group_domain.id().expect("group domain id"),
        ),
        CandidateSource::finite(BTreeSet::from([group_value.clone()])).expect("one tuple source"),
        BranchRequestCause::Operator(CampaignCommandId::from_hash(hash("atomic command"))),
        BranchBudget::new(1, 1).expect("branch budget"),
        StopCondition::NextChoice,
    )
    .expect("one branch request");
    request
        .validate_resolved(&parent, &opportunity, &group_domain)
        .expect("resolved group request");

    let proposal = Proposal::new(
        branch_point,
        request.id().expect("request id"),
        group_domain.id().expect("domain id"),
        group_value.clone(),
        stored_id!(CampaignPolicyId, ObjectKind::Policy, 5, "atomic policy"),
        None,
        1,
        stored_id!(CampaignViewId, ObjectKind::CampaignFact, "atomic view"),
    )
    .expect("one proposal");
    proposal
        .validate_resolved(&request, &group_domain)
        .expect("proposal recomputes group constraints");
    let evidence = proposal.constraint_evidence().expect("group evidence");
    assert_eq!(evidence.group_schema_version(), 3);
    assert_eq!(evidence.constraint_schema_version(), 1);
    assert_eq!(evidence.result(), ChoiceGroupConstraintResult::Admitted);
    assert_eq!(
        Proposal::from_canonical_bytes(&proposal.canonical_bytes()).expect("proposal round trip"),
        proposal
    );
    let mut invalid_evidence = proposal.canonical_bytes();
    *invalid_evidence.last_mut().expect("constraint result byte") = 2;
    assert!(Proposal::from_canonical_bytes(&invalid_evidence).is_err());

    let selection =
        Selection::new_campaign_branch(&opportunity, &group_domain, group_value, branch_point)
            .expect("one atomic selection");
    selection
        .validate_branch_replay(&opportunity, &group_domain, branch_point)
        .expect("exact tuple replay");
}

#[test]
fn progressive_group_candidates_include_anchors_and_reject_conflicting_constraints() {
    let integer_domain = ChoiceDomain::Integer(
        IntegerDomain::new(
            1,
            IntegerRepresentation::Unsigned64,
            IntegerValue::Unsigned(0),
            IntegerValue::Unsigned(1_000_000),
            1,
            None,
            ExactRational::new(1, 1).expect("scale"),
            vec![IntegerValue::Unsigned(500_000)],
        )
        .expect("integer domain"),
    );
    let duration_declaration = selectable_fixture(
        "duration",
        integer_domain.clone(),
        ChoiceValue::Integer(IntegerValue::Unsigned(100)),
    );
    let constrained_declaration = selectable_fixture(
        "constrained",
        integer_domain.clone(),
        ChoiceValue::Integer(IntegerValue::Unsigned(0)),
    );
    let duration = duration_declaration.id().expect("duration id");
    let constrained = constrained_declaration.id().expect("constrained id");
    let declarations = BTreeMap::from([
        (duration, duration_declaration),
        (constrained, constrained_declaration),
    ]);
    let members = BTreeMap::from([
        (duration, integer_domain.clone()),
        (constrained, integer_domain),
    ]);
    let application = ChoiceGroupApplication::new("network.progressive", 1).expect("application");
    let group = ChoiceGroup::new(
        &declarations,
        ChoiceGroupDomain::Cartesian {
            members: members.clone(),
            constraints: BTreeSet::from([ChoiceRelationalConstraint::Member(
                constrained,
                BTreeSet::from([ChoiceValue::Integer(IntegerValue::Unsigned(0))]),
            )]),
        },
        application.clone(),
    )
    .expect("progressive group");
    assert!(group.supports_progressive_generation(4));
    let values = (1..=4)
        .map(|ordinal| {
            group
                .progressive_candidate(ordinal, 4)
                .expect("admitted candidate")
                .tuple()
                .values()
                .get(&duration)
                .cloned()
                .expect("duration member")
        })
        .collect::<Vec<_>>();
    assert_eq!(
        values,
        vec![
            ChoiceValue::Integer(IntegerValue::Unsigned(100)),
            ChoiceValue::Integer(IntegerValue::Unsigned(0)),
            ChoiceValue::Integer(IntegerValue::Unsigned(1_000_000)),
            ChoiceValue::Integer(IntegerValue::Unsigned(500_000)),
        ]
    );

    let conflicting = ChoiceGroup::new(
        &declarations,
        ChoiceGroupDomain::Cartesian {
            members,
            constraints: BTreeSet::from([
                ChoiceRelationalConstraint::Member(
                    constrained,
                    BTreeSet::from([ChoiceValue::Integer(IntegerValue::Unsigned(0))]),
                ),
                ChoiceRelationalConstraint::Member(
                    constrained,
                    BTreeSet::from([ChoiceValue::Integer(IntegerValue::Unsigned(1))]),
                ),
            ]),
        },
        application,
    )
    .expect("structurally valid but unsatisfiable group");
    assert!(!conflicting.supports_progressive_generation(4));
    assert!(conflicting.progressive_candidate(1, 4).is_err());
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
        3,
        "parent-snapshot"
    );
    let transition = stored_id!(CampaignFactId, ObjectKind::CampaignFact, 15, "transition");
    let snapshot = CampaignSnapshot::successor(
        parent,
        stored_id!(CampaignLineageId, ObjectKind::CampaignFact, "lineage"),
        stored_id!(CampaignPolicyId, ObjectKind::Policy, 5, "policy"),
        roots,
        transition,
        crate::test_budget_ledger_id(),
    )
    .expect("successor snapshot");
    let envelope = ObjectEnvelope::for_snapshot(&snapshot).expect("snapshot envelope");

    assert_eq!(envelope.record_kind(), CampaignRecordKind::Snapshot);
    assert_eq!(envelope.children().len(), 14);
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
        3,
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

#[test]
fn observation_records_are_canonical_bounded_and_child_bearing() {
    let evidence = content_kind("measurement evidence", ObjectKind::Trace);
    let measurements = MeasurementSet::test_evaluation(b"latency-13", BTreeSet::from([evidence]))
        .expect("measurement set");
    assert_eq!(
        MeasurementSet::from_canonical_bytes(&measurements.canonical_bytes())
            .expect("canonical measurements"),
        measurements
    );
    assert_eq!(measurements.schema_version(), 2);
    assert_eq!(
        measurements
            .id()
            .expect("measurement id")
            .content_id()
            .schema_version(),
        2
    );
    let measurement_envelope =
        ObjectEnvelope::for_measurement_set(&measurements).expect("measurement envelope");
    assert_eq!(measurement_envelope.content_id().schema_version(), 2);
    assert_eq!(
        ObjectEnvelope::from_canonical_bytes(&measurement_envelope.canonical_bytes())
            .expect("canonical measurement envelope"),
        measurement_envelope
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
        stored_id!(
            AttemptId,
            ObjectKind::CampaignFact,
            9,
            "observation attempt"
        ),
        Observation::outcome(
            ConfigurationId::from_hash(hash("observation child")),
            stored_id!(
                ConfigurationArtifactId,
                ObjectKind::Configuration,
                "observation child artifact"
            ),
            stored_id!(
                BranchPathId,
                ObjectKind::CampaignFact,
                2,
                "observation path"
            ),
            StopOutcome::Reached(StopCondition::NextChoice),
            measurements.id().expect("measurement id"),
            properties.id().expect("property id"),
            coverage.id().expect("coverage id"),
        ),
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
    let envelope = ObjectEnvelope::for_record_versioned(
        CampaignRecordKind::Observation,
        13,
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

    let produced_selection = stored_id!(
        SelectionId,
        ObjectKind::CampaignFact,
        "observation produced selection"
    );
    let selection_observation = observation
        .clone()
        .with_produced_selections(BTreeSet::from([produced_selection]))
        .expect("selection observation");
    assert_eq!(selection_observation.schema_version(), 14);
    assert_eq!(
        Observation::from_canonical_bytes(&selection_observation.canonical_bytes())
            .expect("canonical selection observation"),
        selection_observation
    );
    assert_eq!(
        selection_observation
            .id()
            .expect("selection observation id")
            .content_id()
            .schema_version(),
        13
    );
    assert!(
        selection_observation
            .content_children()
            .iter()
            .any(|(role, child)| role == "produced-selection.0000"
                && *child == produced_selection.content_id())
    );

    let scenario_failure = Observation::new(
        observation.attempt(),
        Observation::outcome(
            observation.child(),
            observation.child_content(),
            observation.path(),
            StopOutcome::ScenarioFailure(vec![
                "first declared failure".to_owned(),
                "second declared failure".to_owned(),
            ]),
            observation.measurements(),
            observation.properties(),
            observation.coverage(),
        ),
        BTreeSet::new(),
    )
    .expect("scenario failure observation");
    assert_eq!(scenario_failure.schema_version(), 13);
    assert_eq!(
        Observation::from_canonical_bytes(&scenario_failure.canonical_bytes())
            .expect("canonical scenario failure observation"),
        scenario_failure
    );
    assert_eq!(
        scenario_failure
            .id()
            .expect("scenario failure observation id")
            .content_id()
            .schema_version(),
        13
    );
    let failure_selection_observation = scenario_failure
        .clone()
        .with_produced_selections(BTreeSet::from([produced_selection]))
        .expect("scenario failure selection observation");
    assert_eq!(failure_selection_observation.schema_version(), 14);
    assert_eq!(
        Observation::from_canonical_bytes(&failure_selection_observation.canonical_bytes())
            .expect("canonical scenario failure selection observation"),
        failure_selection_observation
    );
    let mut malformed_observation = observation.canonical_bytes();
    malformed_observation[..4].copy_from_slice(&0_u32.to_be_bytes());
    assert!(Observation::from_canonical_bytes(&malformed_observation).is_err());
    assert!(
        Observation::new(
            observation.attempt(),
            Observation::outcome(
                observation.child(),
                observation.child_content(),
                observation.path(),
                StopOutcome::ScenarioFailure(Vec::new()),
                observation.measurements(),
                observation.properties(),
                observation.coverage(),
            ),
            BTreeSet::new(),
        )
        .is_err()
    );
    let aggregate_oversize_failure =
        vec!["a".repeat(16 * 1024 * 1024), "b".repeat(16 * 1024 * 1024)];
    assert!(
        Observation::new(
            observation.attempt(),
            Observation::outcome(
                observation.child(),
                observation.child_content(),
                observation.path(),
                StopOutcome::ScenarioFailure(aggregate_oversize_failure),
                observation.measurements(),
                observation.properties(),
                observation.coverage(),
            ),
            BTreeSet::new(),
        )
        .is_err()
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
            Observation::outcome(
                observation.child(),
                observation.child_content(),
                observation.path(),
                observation.stop().clone(),
                observation.measurements(),
                observation.properties(),
                observation.coverage(),
            ),
            excessive_choices,
        ),
        Err(CampaignCodecError::LimitExceeded {
            limit: "observation-discovered-choice-count"
        })
    ));
}

#[test]
fn verified_measurement_payload_is_v2_and_retains_exact_children() {
    let evidence = content_kind("evaluation evidence", ObjectKind::Trace);
    let definitions = hash("measurement definitions");
    let evaluation = hash("measurement evaluation");
    let measurements = MeasurementSet::from_evaluation(
        definitions,
        1,
        evaluation,
        br#"{"measurement":{}}"#.to_vec(),
        BTreeSet::from([evidence]),
    )
    .expect("verified measurement payload");
    let decoded = MeasurementSet::from_canonical_bytes(&measurements.canonical_bytes())
        .expect("canonical verified measurements");

    assert_eq!(decoded, measurements);
    assert_eq!(measurements.schema_version(), 2);
    let retained = measurements.evaluation();
    assert_eq!(retained.definitions(), definitions);
    assert_eq!(retained.payload_schema(), 1);
    assert_eq!(retained.evaluation(), evaluation);
    assert_eq!(retained.payload(), br#"{"measurement":{}}"#);
    assert_eq!(retained.evidence(), &BTreeSet::from([evidence]));
    assert_eq!(
        measurements
            .id()
            .expect("measurement id")
            .content_id()
            .schema_version(),
        2
    );

    let envelope = super::object::ObjectEnvelope::for_measurement_set(&measurements)
        .expect("measurement envelope");
    assert_eq!(envelope.children().len(), 1);
    assert_eq!(
        envelope.children().iter().next().expect("evidence").id(),
        evidence
    );
    assert_eq!(
        ObjectEnvelope::from_canonical_bytes(&envelope.canonical_bytes())
            .expect("decoded measurement envelope"),
        envelope
    );
    let mismatched = crucible_cas::content_envelope::ContentEnvelope::new(
        "crucible.campaign.measurement-set",
        1,
        envelope.children().clone(),
        measurements.canonical_bytes(),
    )
    .expect("structural mismatched measurement envelope");
    assert!(matches!(
        ObjectEnvelope::from_canonical_bytes(&mismatched.canonical_bytes()),
        Err(CampaignCodecError::InvalidValue { .. })
    ));
    assert!(matches!(
        MeasurementSet::from_evaluation(definitions, 0, evaluation, vec![1], BTreeSet::new(),),
        Err(CampaignCodecError::InvalidValue { .. })
    ));
    assert!(matches!(
        MeasurementSet::from_evaluation(definitions, 1, evaluation, Vec::new(), BTreeSet::new(),),
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
        crate::ReproductionArtifactBasis::new(
            scenario,
            scenario_artifact_id,
            configuration,
            configuration_artifact_id,
            fingerprint,
        ),
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
        14,
        b"finding-observation",
    ))
    .expect("observation id");
    let first_seen = CampaignSnapshotId::from_content_id(ContentId::for_bytes(
        ObjectKind::CampaignSnapshot,
        3,
        b"finding-parent-snapshot",
    ))
    .expect("snapshot id");
    let finding = Finding::new_current_for_test(
        Finding::basis(
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
        ),
        None,
        FindingExactPins::default(),
    )
    .expect("finding");
    assert_eq!(
        Finding::from_canonical_bytes(&finding.canonical_bytes()).expect("decode finding"),
        finding
    );
    let first_bundle = finding.candidate_bundle();
    let candidate_occurrences = FindingCandidateOccurrenceSet::new(
        finding.candidate_occurrences(),
        finding.candidate_occurrence_count(),
        finding.latest_candidate_bundle(),
    )
    .expect("candidate occurrence set");
    let canonical = finding.canonical_bytes();
    let bundle_bytes = encode(&Some(first_bundle));
    let occurrence_bytes = encode(&Some(candidate_occurrences));
    let bundle_start = canonical.len() - bundle_bytes.len() - occurrence_bytes.len();

    let mut missing_bundle = canonical[..bundle_start].to_vec();
    missing_bundle.extend(encode(&None::<FindingCandidateBundleId>));
    missing_bundle.extend(&canonical[bundle_start + bundle_bytes.len()..]);
    assert_eq!(
        Finding::from_canonical_bytes(&missing_bundle),
        Err(CampaignCodecError::InvalidValue {
            reason: "finding record has no authenticated candidate bundle",
        })
    );

    let mut missing_occurrences = canonical[..canonical.len() - occurrence_bytes.len()].to_vec();
    missing_occurrences.extend(encode(&None::<FindingCandidateOccurrenceSet>));
    assert_eq!(
        Finding::from_canonical_bytes(&missing_occurrences),
        Err(CampaignCodecError::InvalidValue {
            reason: "finding record has no authenticated candidate occurrences",
        })
    );
    assert_eq!(signature.cluster_key(), finding.signature().cluster_key());

    let envelope = ObjectEnvelope::for_record_versioned(
        CampaignRecordKind::Finding,
        finding.schema_version(),
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
fn current_finding_retains_minimization_trace_and_role_tagged_exact_pins() {
    let scenario = ScenarioDefId::from_hash(hash("finding-current-scenario"));
    let scenario_artifact =
        ScenarioArtifact::new(scenario, 1, b"scenario-v2".to_vec()).expect("scenario artifact");
    let scenario_artifact_id = scenario_artifact.id().expect("scenario artifact id");
    let original_configuration = ConfigurationId::from_hash(hash("finding-current-original"));
    let original_configuration_artifact = ConfigurationArtifact::new(
        scenario,
        scenario_artifact_id,
        original_configuration,
        1,
        b"original configuration".to_vec(),
    )
    .expect("original configuration artifact");
    let original_configuration_artifact_id = original_configuration_artifact
        .id()
        .expect("original configuration artifact id");
    let fingerprint = hash("finding-current-fingerprint");
    let original = ReproductionArtifact::new(
        crate::ReproductionArtifactBasis::new(
            scenario,
            scenario_artifact_id,
            original_configuration,
            original_configuration_artifact_id,
            fingerprint,
        ),
        1,
        b"original reproduction".to_vec(),
    )
    .expect("original reproduction");
    let original_id = original.id().expect("original reproduction id");
    assert_eq!(original.schema_version(), 2);
    assert!(original.minimization().is_none());

    let minimized_configuration = ConfigurationId::from_hash(hash("finding-current-minimized"));
    let minimized_configuration_artifact = ConfigurationArtifact::new(
        scenario,
        scenario_artifact_id,
        minimized_configuration,
        1,
        b"minimized configuration".to_vec(),
    )
    .expect("minimized configuration artifact");
    let minimized_configuration_artifact_id = minimized_configuration_artifact
        .id()
        .expect("minimized configuration artifact id");
    let attempt = FindingMinimizationAttempt::new(
        0,
        hash("candidate artifact"),
        hash("candidate schedule"),
        hash("candidate state"),
        Some(fingerprint),
        true,
    );
    let current_policy = b"crucible.finding-minimization-policy.v3\0current-limits".to_vec();
    assert!(matches!(
        FindingMinimizationEvidence::new(
            original_id,
            2,
            current_policy.clone(),
            vec![attempt],
            hash("candidate state"),
        ),
        Err(CampaignCodecError::InvalidValue {
            reason: "finding minimization policy is empty or not current schema"
        })
    ));
    assert!(matches!(
        FindingMinimizationEvidence::new(
            original_id,
            3,
            current_policy.clone(),
            vec![attempt],
            hash("different final state"),
        ),
        Err(CampaignCodecError::InvalidValue {
            reason: "finding minimization accepted candidate is inconsistent"
        })
    ));
    let minimization = FindingMinimizationEvidence::new(
        original_id,
        3,
        current_policy.clone(),
        vec![attempt],
        hash("candidate state"),
    )
    .expect("minimization evidence");
    let minimized = ReproductionArtifact::new_minimized(
        crate::ReproductionArtifactBasis::new(
            scenario,
            scenario_artifact_id,
            minimized_configuration,
            minimized_configuration_artifact_id,
            fingerprint,
        ),
        1,
        b"minimized reproduction".to_vec(),
        minimization,
    )
    .expect("minimized reproduction");
    let minimized_id = minimized.id().expect("minimized reproduction id");
    assert_eq!(minimized.schema_version(), 2);
    assert_eq!(minimized_id.content_id().schema_version(), 2);
    let decoded = ReproductionArtifact::from_canonical_bytes(&minimized.canonical_bytes())
        .expect("decode minimized reproduction");
    assert_eq!(decoded, minimized);
    let decoded_minimization = decoded
        .minimization()
        .expect("decode current minimization evidence");
    assert_eq!(decoded_minimization.policy_schema(), 3);
    assert_eq!(decoded_minimization.policy(), current_policy);

    let checkpoint = |name: &[u8]| {
        ExactCheckpointId::from_content_id(ContentId::for_bytes(ObjectKind::ExactManifest, 5, name))
            .expect("exact checkpoint id")
    };
    let pre = checkpoint(b"pre-failure");
    let measurement = checkpoint(b"measurement-boundary");
    let post = checkpoint(b"post-failure");
    let pins = FindingExactPins::new(
        BTreeSet::from([pre]),
        BTreeSet::from([measurement]),
        BTreeSet::from([post]),
        BTreeSet::new(),
    )
    .expect("role-tagged pins");
    let observation = ObservationId::from_content_id(ContentId::for_bytes(
        ObjectKind::Observation,
        14,
        b"finding-current-observation",
    ))
    .expect("observation id");
    let signature = FindingSignature::new(
        FindingKind::Divergence,
        fingerprint,
        None,
        "qemu.replay-divergence".to_owned(),
        Some(FindingTarget::Configuration(
            original_configuration_artifact_id,
        )),
        BTreeSet::new(),
    )
    .expect("finding signature");
    let finding = Finding::new_current_for_test(
        Finding::basis(
            signature,
            observation,
            original_id,
            CampaignSnapshotId::from_content_id(ContentId::for_bytes(
                ObjectKind::CampaignSnapshot,
                3,
                b"finding-current-parent",
            ))
            .expect("snapshot id"),
            FindingOccurrenceSet::new(
                ContentId::for_bytes(ObjectKind::MerkleNode, 1, b"finding-current-occurrences"),
                1,
                observation,
            )
            .expect("occurrences"),
        ),
        Some(minimized_id),
        pins,
    )
    .expect("current finding");
    assert_eq!(finding.schema_version(), 4);
    assert_eq!(
        finding
            .id()
            .expect("finding id")
            .content_id()
            .schema_version(),
        4
    );
    assert_eq!(
        finding.exact_pin_retention().pre_failure(),
        &BTreeSet::from([pre])
    );
    assert_eq!(
        finding.exact_pin_retention().measurement_boundary(),
        &BTreeSet::from([measurement])
    );
    assert_eq!(
        finding.exact_pin_retention().post_failure(),
        &BTreeSet::from([post])
    );
    assert_eq!(
        Finding::from_canonical_bytes(&finding.canonical_bytes()).expect("decode current finding"),
        finding
    );
    let envelope = ObjectEnvelope::for_record_versioned(
        CampaignRecordKind::Finding,
        finding.schema_version(),
        crate::object::content_children(finding.content_children()).expect("finding children"),
        finding.canonical_bytes(),
    )
    .expect("current finding envelope");
    assert_eq!(
        ObjectEnvelope::from_canonical_bytes(&envelope.canonical_bytes())
            .expect("decode current finding envelope"),
        envelope
    );
}

mod finding_signature;

fn hash(label: &str) -> CampaignHash {
    CampaignHash::derive("crucible.campaign.test-fixture.v1", label.as_bytes())
}

fn content(label: &str) -> ContentId {
    content_kind(label, ObjectKind::MerkleNode)
}

fn content_kind(label: &str, kind: ObjectKind) -> ContentId {
    ContentId::for_bytes(kind, 1, label.as_bytes())
}
