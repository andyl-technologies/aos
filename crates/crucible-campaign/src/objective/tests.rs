#![allow(clippy::expect_used)]

use super::*;
use crate::{
    CampaignMode, CampaignSeed, CoverageProjection, ExplorerPolicy, FairnessPolicy, MeasurementSet,
    PuctPolicy, RetentionPolicy, StopOutcome,
};
use crucible_cas::content_store::{ContentId, ObjectKind};

trait TestContentId: Sized {
    fn from_test_content(value: ContentId) -> Result<Self, CampaignCodecError>;
}

macro_rules! test_content_id {
    ($($type:ty),+ $(,)?) => {
        $(
            impl TestContentId for $type {
                fn from_test_content(value: ContentId) -> Result<Self, CampaignCodecError> {
                    Self::from_content_id(value)
                }
            }
        )+
    };
}

test_content_id!(
    crate::AttemptId,
    crate::ConfigurationArtifactId,
    crate::BranchPathId,
    crate::ObservationId,
);

fn typed_content<T: TestContentId>(kind: ObjectKind, _schema: &str, label: &str) -> T {
    T::from_test_content(ContentId::for_bytes(kind, 1, label.as_bytes())).expect("typed content ID")
}

fn policy(objectives: &[(&str, ObjectiveGoal, u64)]) -> CampaignPolicy {
    let objectives = objectives
        .iter()
        .map(|(name, goal, weight)| {
            (
                (*name).to_owned(),
                Objective::new(*name, *goal, *weight).expect("objective"),
            )
        })
        .collect();
    CampaignPolicy::new(
        crate::ScenarioDefId::from_hash(crate::CampaignHash::derive("test", b"scenario")),
        CampaignSeed::from_bytes([0x5a; 32]),
        CampaignMode::Strict,
        ExplorerPolicy::TreeSearch {
            puct: PuctPolicy::new(1_000_000, 0, 0),
            widening: None,
        },
        BTreeMap::new(),
        objectives,
        BTreeMap::new(),
        BTreeSet::new(),
        FairnessPolicy::new(0, 0).expect("fairness"),
        RetentionPolicy::new(true, 64, true, true),
        false,
    )
    .expect("policy")
}

fn observation_basis(label: &str) -> (Observation, PropertyVerdictSet) {
    let measurements = MeasurementSet::new(BTreeMap::new()).expect("measurements");
    let properties = PropertyVerdictSet::new(BTreeMap::new()).expect("properties");
    let coverage = CoverageProjection::new(BTreeSet::new(), BTreeSet::new()).expect("coverage");
    let observation = Observation::new(
        typed_content(
            ObjectKind::CampaignFact,
            "crucible.campaign.attempt",
            &format!("attempt-{label}"),
        ),
        ConfigurationId::from_hash(crate::CampaignHash::derive(
            "configuration",
            label.as_bytes(),
        )),
        typed_content(
            ObjectKind::Configuration,
            "crucible.campaign.configuration-artifact",
            &format!("configuration-{label}"),
        ),
        typed_content(
            ObjectKind::CampaignFact,
            "crucible.campaign.branch-path",
            &format!("path-{label}"),
        ),
        StopOutcome::TerminalSuccess,
        measurements.id().expect("measurement ID"),
        properties.id().expect("property ID"),
        coverage.id().expect("coverage ID"),
        BTreeSet::new(),
    )
    .expect("observation");
    (observation, properties)
}

fn evaluation(
    policy: &CampaignPolicy,
    label: &str,
    values: &[(&str, ObjectiveValue)],
) -> ObjectiveEvaluation {
    let (observation, properties) = observation_basis(label);
    evaluate_objectives(
        policy,
        &observation,
        &properties,
        values
            .iter()
            .map(|(name, value)| ((*name).to_owned(), value.clone()))
            .collect(),
    )
    .expect("objective evaluation")
}

#[test]
fn exact_objective_evaluation_round_trips_and_recomputes_basis() {
    let policy = policy(&[
        ("recovery.latency", ObjectiveGoal::Minimize, 1_000_000),
        ("recovery.throughput", ObjectiveGoal::Maximize, 500_000),
    ]);
    let (observation, properties) = observation_basis("exact");
    let evaluation = evaluate_objectives(
        &policy,
        &observation,
        &properties,
        BTreeMap::from([
            ("recovery.latency".to_owned(), ObjectiveValue::Signed(10)),
            (
                "recovery.throughput".to_owned(),
                ObjectiveValue::rational(false, 8, 2).expect("rational"),
            ),
        ]),
    )
    .expect("evaluation");

    assert!(evaluation.is_admissible());
    let reward = evaluation.scalar_reward().expect("scalar reward");
    assert!(reward.is_negative());
    assert_eq!(reward.numerator(), &[8]);
    assert_eq!(reward.denominator(), &[1]);
    evaluation
        .validate_basis(&policy, &observation, &properties)
        .expect("exact basis");
    assert_eq!(
        ObjectiveEvaluation::from_canonical_bytes(&evaluation.canonical_bytes())
            .expect("round trip"),
        evaluation
    );
    assert_eq!(
        evaluation.id().expect("ID").content_id().kind(),
        ObjectKind::Observation
    );
}

#[test]
fn fixed_rewards_convert_to_puct_micros_with_exact_truncation_and_saturation() {
    assert_eq!(
        FixedReward::from_parts(false, vec![3], vec![2])
            .expect("positive reward")
            .to_micros_saturating(),
        1_500_000
    );
    assert_eq!(
        FixedReward::from_parts(true, vec![1], vec![3])
            .expect("negative reward")
            .to_micros_saturating(),
        -333_333
    );
    assert_eq!(
        FixedReward::from_parts(false, vec![0xff; 16], vec![1])
            .expect("large positive reward")
            .to_micros_saturating(),
        i64::MAX
    );
    assert_eq!(
        FixedReward::from_parts(true, vec![0xff; 16], vec![1])
            .expect("large negative reward")
            .to_micros_saturating(),
        i64::MIN
    );
}

#[test]
fn compact_policy_contract_rejects_copied_component_forgery() {
    let policy = policy(&[("recovery.latency", ObjectiveGoal::Minimize, 1_000_000)]);
    let (observation, properties) = observation_basis("forged-policy-contract");
    let evaluation = evaluate_objectives(
        &policy,
        &observation,
        &properties,
        BTreeMap::from([("recovery.latency".to_owned(), ObjectiveValue::Unsigned(10))]),
    )
    .expect("evaluation");

    let mut forged = evaluation;
    forged
        .components
        .get_mut("recovery.latency")
        .expect("component")
        .weight_micros = 2_000_000;
    forged.scalar_reward = Some(
        compute_scalar_reward(forged.components.values()).expect("forged internally exact reward"),
    );
    let decoded = ObjectiveEvaluation::from_canonical_bytes(&forged.canonical_bytes())
        .expect("structurally valid forged evaluation");

    assert_eq!(
        decoded.validate_compact_basis(
            policy.id().expect("policy ID"),
            policy.objective_contract_hash(),
            &observation,
            &properties,
        ),
        Err(CampaignCodecError::InvalidValue {
            reason: "objective evaluation compact policy contract mismatch"
        })
    );
}

#[test]
fn missing_measurements_and_property_failures_are_explicit_filters() {
    let policy = policy(&[
        ("recovery.latency", ObjectiveGoal::Minimize, 1_000_000),
        ("recovery.loss", ObjectiveGoal::Minimize, 1_000_000),
    ]);
    let measurements = MeasurementSet::new(BTreeMap::new()).expect("measurements");
    let properties = PropertyVerdictSet::new(BTreeMap::from([(
        "safety".to_owned(),
        crate::PropertyEvidence::new(PropertyVerdict::Failed, BTreeSet::new()).expect("property"),
    )]))
    .expect("properties");
    let coverage = CoverageProjection::new(BTreeSet::new(), BTreeSet::new()).expect("coverage");
    let observation = Observation::new(
        typed_content(
            ObjectKind::CampaignFact,
            "crucible.campaign.attempt",
            "filtered",
        ),
        ConfigurationId::from_hash(crate::CampaignHash::derive("configuration", b"filtered")),
        typed_content(
            ObjectKind::Configuration,
            "crucible.campaign.configuration-artifact",
            "filtered",
        ),
        typed_content(
            ObjectKind::CampaignFact,
            "crucible.campaign.branch-path",
            "filtered",
        ),
        StopOutcome::TerminalSuccess,
        measurements.id().expect("measurement ID"),
        properties.id().expect("property ID"),
        coverage.id().expect("coverage ID"),
        BTreeSet::new(),
    )
    .expect("observation");
    let evaluation = evaluate_objectives(
        &policy,
        &observation,
        &properties,
        BTreeMap::from([("recovery.latency".to_owned(), ObjectiveValue::Unsigned(9))]),
    )
    .expect("evaluation");

    assert!(!evaluation.is_admissible());
    assert_eq!(evaluation.scalar_reward(), None);
    assert!(
        evaluation
            .rejections()
            .contains(&ObjectiveRejection::PropertyFailed("safety".to_owned()))
    );
    assert!(
        evaluation
            .rejections()
            .contains(&ObjectiveRejection::MissingMeasurement(
                "recovery.loss".to_owned()
            ))
    );
}

#[test]
fn pareto_ranking_records_dominance_and_fairness_reserves() {
    let policy = policy(&[
        ("recovery.latency", ObjectiveGoal::Minimize, 1_000_000),
        ("recovery.loss", ObjectiveGoal::Minimize, 1_000_000),
    ]);
    let candidates = vec![
        RankingCandidate::new(
            evaluation(
                &policy,
                "a",
                &[
                    ("recovery.latency", ObjectiveValue::Unsigned(10)),
                    ("recovery.loss", ObjectiveValue::Unsigned(5)),
                ],
            ),
            1,
            2,
        ),
        RankingCandidate::new(
            evaluation(
                &policy,
                "b",
                &[
                    ("recovery.latency", ObjectiveValue::Unsigned(12)),
                    ("recovery.loss", ObjectiveValue::Unsigned(2)),
                ],
            ),
            10,
            1,
        ),
        RankingCandidate::new(
            evaluation(
                &policy,
                "c",
                &[
                    ("recovery.latency", ObjectiveValue::Unsigned(20)),
                    ("recovery.loss", ObjectiveValue::Unsigned(20)),
                ],
            ),
            0,
            0,
        ),
    ];
    let no_reserve = rank_survivors(
        &policy,
        SurvivorRule::new(RankingMethod::ParetoTopK, 2, 0, 0).expect("rule"),
        candidates.clone(),
    )
    .expect("Pareto ranking");
    let c = candidates[2].evaluation().configuration();
    assert!(!no_reserve.selection().selected().contains(&c));
    assert!(matches!(
        no_reserve.explanations()[&c].disposition(),
        RankingDisposition::ParetoDominated(_)
    ));

    let reserved = rank_survivors(
        &policy,
        SurvivorRule::new(RankingMethod::ParetoTopK, 3, 1, 1).expect("rule"),
        candidates,
    )
    .expect("reserved ranking");
    assert_eq!(reserved.selection().selected().len(), 3);
    assert_eq!(
        reserved.explanations()[&c].disposition(),
        &RankingDisposition::SelectedBreadthFirst
    );
    assert_eq!(
        SurvivorSelection::from_canonical_bytes(&reserved.selection().canonical_bytes())
            .expect("selection round trip"),
        *reserved.selection()
    );
}

#[test]
fn lexicographic_and_weighted_top_k_are_distinct_and_order_independent() {
    let policy = policy(&[
        ("a", ObjectiveGoal::Minimize, 1),
        ("b", ObjectiveGoal::Maximize, 1_000_000),
    ]);
    let left = RankingCandidate::new(
        evaluation(
            &policy,
            "left",
            &[
                ("a", ObjectiveValue::Unsigned(1)),
                ("b", ObjectiveValue::Unsigned(0)),
            ],
        ),
        0,
        0,
    );
    let right = RankingCandidate::new(
        evaluation(
            &policy,
            "right",
            &[
                ("a", ObjectiveValue::Unsigned(2)),
                ("b", ObjectiveValue::Unsigned(10)),
            ],
        ),
        0,
        1,
    );
    let lexicographic = rank_survivors(
        &policy,
        SurvivorRule::new(RankingMethod::Lexicographic, 1, 0, 0).expect("rule"),
        vec![right.clone(), left.clone()],
    )
    .expect("lexicographic");
    assert!(
        lexicographic
            .selection()
            .selected()
            .contains(&left.evaluation().configuration())
    );

    let weighted = rank_survivors(
        &policy,
        SurvivorRule::new(RankingMethod::WeightedTopK, 1, 0, 0).expect("rule"),
        vec![left.clone(), right.clone()],
    )
    .expect("weighted");
    assert!(
        weighted
            .selection()
            .selected()
            .contains(&right.evaluation().configuration())
    );
    let reordered = rank_survivors(
        &policy,
        SurvivorRule::new(RankingMethod::WeightedTopK, 1, 0, 0).expect("rule"),
        vec![right, left],
    )
    .expect("reordered");
    assert_eq!(weighted, reordered);
}

#[test]
fn pareto_work_is_rejected_before_quadratic_comparison() {
    let policy = policy(&[("value", ObjectiveGoal::Minimize, 1_000_000)]);
    let base = evaluation(&policy, "base", &[("value", ObjectiveValue::Unsigned(1))]);
    let candidates = (0_u64..=2_000)
        .map(|index| {
            let mut evaluation = base.clone();
            evaluation.configuration = ConfigurationId::from_hash(crate::CampaignHash::derive(
                "configuration",
                &index.to_be_bytes(),
            ));
            evaluation.observation = typed_content(
                ObjectKind::Observation,
                "crucible.campaign.observation",
                &format!("observation-{index}"),
            );
            RankingCandidate::new(evaluation, 0, index)
        })
        .collect();
    assert_eq!(
        rank_survivors(
            &policy,
            SurvivorRule::new(RankingMethod::ParetoTopK, 1, 0, 0).expect("rule"),
            candidates,
        ),
        Err(CampaignCodecError::LimitExceeded {
            limit: "pareto-component-visits"
        })
    );
}

#[test]
fn lexicographic_work_is_rejected_before_quadratic_component_visits() {
    let policy = policy(&[("value", ObjectiveGoal::Minimize, 1_000_000)]);
    let base = evaluation(&policy, "base", &[("value", ObjectiveValue::Unsigned(1))]);
    let candidates = (0_u64..=2_000)
        .map(|index| {
            let mut evaluation = base.clone();
            evaluation.configuration = ConfigurationId::from_hash(crate::CampaignHash::derive(
                "configuration",
                &index.to_be_bytes(),
            ));
            evaluation.observation = typed_content(
                ObjectKind::Observation,
                "crucible.campaign.observation",
                &format!("lexicographic-observation-{index}"),
            );
            RankingCandidate::new(evaluation, 0, index)
        })
        .collect();
    assert_eq!(
        rank_survivors(
            &policy,
            SurvivorRule::new(RankingMethod::Lexicographic, 1, 0, 0).expect("rule"),
            candidates,
        ),
        Err(CampaignCodecError::LimitExceeded {
            limit: "lexicographic-component-visits"
        })
    );
}

#[test]
fn weighted_work_is_rejected_before_large_reward_comparisons() {
    let policy = policy(&[("value", ObjectiveGoal::Maximize, 1_000_000)]);
    let mut base = evaluation(&policy, "base", &[("value", ObjectiveValue::Unsigned(1))]);
    base.scalar_reward = Some(
        FixedReward::from_parts(false, vec![1; MAX_FIXED_REWARD_MAGNITUDE_BYTES], vec![1])
            .expect("maximum reward magnitude"),
    );
    let candidates = (0_u64..256)
        .map(|index| {
            let mut evaluation = base.clone();
            evaluation.configuration = ConfigurationId::from_hash(crate::CampaignHash::derive(
                "configuration",
                &index.to_be_bytes(),
            ));
            evaluation.observation = typed_content(
                ObjectKind::Observation,
                "crucible.campaign.observation",
                &format!("weighted-observation-{index}"),
            );
            RankingCandidate::new(evaluation, 0, index)
        })
        .collect();
    assert_eq!(
        rank_survivors(
            &policy,
            SurvivorRule::new(RankingMethod::WeightedTopK, 1, 0, 0).expect("rule"),
            candidates,
        ),
        Err(CampaignCodecError::LimitExceeded {
            limit: "weighted-ranking-byte-visits"
        })
    );
}

#[test]
fn survivor_evidence_aggregate_byte_bound_is_checked_arithmetically() {
    let mut charged = MAX_SURVIVOR_EVIDENCE_BYTES - 1;
    charge_survivor_evidence_bytes(&mut charged, 1).expect("exact evidence byte ceiling");
    assert_eq!(charged, MAX_SURVIVOR_EVIDENCE_BYTES);
    assert_eq!(
        charge_survivor_evidence_bytes(&mut charged, 1),
        Err(CampaignCodecError::LimitExceeded {
            limit: "survivor-evidence-aggregate-bytes"
        })
    );
}
