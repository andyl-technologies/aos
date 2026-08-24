//! Cross-layer measurement payload verification regressions.

// crucible-lint: allow panic-shortcut -- test fixtures use panic shortcuts.
#![allow(clippy::expect_used)]

use super::*;
use std::collections::{BTreeMap, BTreeSet};

use crucible::model::{
    Aggregation, BoundarySelector, CohortPolicy, MeasurementDefinition, MeasurementId,
    MeasurementSampleValue, MetricDefinition, MetricId, MetricSource, MetricValueType, UnitId,
};
use crucible::{Icount, MarkerId, NodeId, NodeTemplate, ReadyPoint, VirtualTime, WhiteBoxPolicy};
use crucible_campaign::{
    CampaignMode, CampaignPolicy, CampaignSeed, ConfigurationId, CoverageProjection,
    ExplorerPolicy, FairnessPolicy, MeasurementSeries, MetricValue, Objective, ObjectiveGoal,
    Observation, PuctPolicy, RetentionPolicy, StopOutcome,
};
use crucible_cas::content_store::{ContentId, ObjectKind};

fn terminal() -> MeasurementTerminalState {
    MeasurementTerminalState {
        scenario_ready_at: None,
        at: VirtualTime { ticks: 0 },
        node_icounts: Default::default(),
        scheduler_quiescent: true,
    }
}

fn node(name: &str) -> NodeId {
    NodeId {
        name: name.to_owned(),
    }
}

fn typed_text(tag: &str, kind: ObjectKind, schema_version: u32, label: &str) -> String {
    format!(
        "{tag}@{}",
        ContentId::for_bytes(kind, schema_version, label.as_bytes())
    )
}

fn objective_policy() -> CampaignPolicy {
    let name = "recovery.latency";
    CampaignPolicy::new(
        crucible_campaign::ScenarioDefId::from_hash(CampaignHash::derive("test", b"scenario")),
        CampaignSeed::from_bytes([0x8c; 32]),
        CampaignMode::Strict,
        ExplorerPolicy::TreeSearch {
            puct: PuctPolicy::new(1_000_000, 0, 0),
            widening: None,
        },
        BTreeMap::new(),
        BTreeMap::from([(
            name.to_owned(),
            Objective::new(name, ObjectiveGoal::Minimize, 1_000_000).expect("objective"),
        )]),
        BTreeMap::new(),
        BTreeSet::new(),
        FairnessPolicy::new(0, 0).expect("fairness"),
        RetentionPolicy::new(true, 8, true, true),
        false,
    )
    .expect("policy")
}

#[test]
fn verified_evaluation_round_trips_through_campaign_v2() {
    let scenario = crucible::happy_path_scenario()
        .expect("happy-path scenario")
        .scenario;
    let definitions = scenario.measurements();
    let set = evaluate_crucible_measurement_set(
        definitions,
        &[],
        Vec::new(),
        &terminal(),
        BTreeSet::new(),
    )
    .expect("measurement set");

    assert_eq!(set.schema_version(), 2);
    let verified = verify_crucible_measurement_set(&set, definitions, &[], Vec::new(), &terminal())
        .expect("verified evaluation");
    assert_eq!(
        set.evaluation().expect("v2 evaluation").evaluation(),
        campaign_hash(verified.content_hash())
    );
}

#[test]
fn forged_and_legacy_measurement_sets_fail_closed() {
    let scenario = crucible::happy_path_scenario()
        .expect("happy-path scenario")
        .scenario;
    let definitions = scenario.measurements();
    let evaluation =
        evaluate_measurements(definitions, &[], Vec::new(), &terminal()).expect("empty evaluation");
    let mut forged_payload = evaluation.canonical_bytes().to_vec();
    forged_payload.push(b' ');
    let forged = MeasurementSet::from_evaluation(
        campaign_hash(evaluation.definitions()),
        CRUCIBLE_MEASUREMENT_EVALUATION_PAYLOAD_SCHEMA_V1,
        campaign_hash(evaluation.content_hash()),
        forged_payload,
        BTreeSet::new(),
    )
    .expect("structural forged measurement set");
    assert!(matches!(
        verify_crucible_measurement_set(&forged, definitions, &[], Vec::new(), &terminal()),
        Err(CrucibleMeasurementError::Evaluation(
            MeasurementEvaluationError::ReplayMismatch
        ))
    ));

    let legacy = MeasurementSet::new(BTreeMap::from([(
        "legacy".to_owned(),
        MeasurementSeries::new(
            vec![MetricValue::Unsigned(1)],
            MetricValue::Unsigned(1),
            BTreeSet::new(),
        )
        .expect("legacy series"),
    )]))
    .expect("legacy set");
    assert!(matches!(
        verify_crucible_measurement_set(&legacy, definitions, &[], Vec::new(), &terminal()),
        Err(CrucibleMeasurementError::LegacyMeasurementSet)
    ));
}

#[test]
fn verified_crucible_aggregate_drives_exact_campaign_objective() {
    let world = crucible::World::from_nodes(vec![crucible::WorldNode {
        id: node("router"),
        arch: NodeTemplate::DEFAULT_ARCH,
        memory_mib: NodeTemplate::DEFAULT_MEMORY_MIB,
        cmdline: "objective-test".to_owned(),
        ready_point: ReadyPoint::FixedIcount {
            icount: Icount { retired: 1 },
        },
        white_box: WhiteBoxPolicy::Enabled,
        smp_vcpus: NodeTemplate::DEFAULT_SMP_VCPUS,
        icount_shift: NodeTemplate::DEFAULT_ICOUNT_SHIFT,
        kernel: None,
        root_image: None,
        initrd: None,
    }])
    .expect("world");
    let definitions = MeasurementDefinitions::new(
        &world,
        &crucible::Plan::empty(),
        &crucible::Properties::empty(),
        vec![MeasurementDefinition {
            id: MeasurementId::parse("recovery").expect("measurement ID"),
            begin: BoundarySelector::ScenarioGenesis,
            end: BoundarySelector::GuestMarker {
                marker: MarkerId::from_name("done"),
                instance: None,
            },
            timeout: None,
            cohort: CohortPolicy::All(vec![node("router")]),
            metrics: vec![MetricDefinition {
                id: MetricId::parse("latency").expect("metric ID"),
                value_type: MetricValueType::UnsignedInteger,
                unit: UnitId::parse("virtual_nanoseconds").expect("unit"),
                source: MetricSource::Guest,
                aggregation: Aggregation::Sum,
            }],
        }],
    )
    .expect("definitions");
    let entries = vec![crucible::SchedulerEventLogEntry::guest_marker_observation(
        0,
        Icount { retired: 2 },
        node("router"),
        MarkerId::from_name("done"),
    )];
    let samples = vec![MeasurementRuntimeSample::new(
        0,
        MeasurementId::parse("recovery").expect("measurement ID"),
        MetricId::parse("latency").expect("metric ID"),
        MeasurementSampleValue::Unsigned(7),
    )];
    let terminal = MeasurementTerminalState {
        scenario_ready_at: None,
        at: VirtualTime { ticks: 2 },
        node_icounts: BTreeMap::from([(node("router"), Icount { retired: 2 })]),
        scheduler_quiescent: false,
    };
    let evaluation = evaluate_measurements(&definitions, &entries, samples, &terminal)
        .expect("measurement evaluation");
    let measurement_set =
        encode_crucible_measurement_set(&evaluation, BTreeSet::new()).expect("measurement set");
    let properties =
        crucible_campaign::PropertyVerdictSet::new(BTreeMap::new()).expect("properties");
    let coverage = CoverageProjection::new(BTreeSet::new(), BTreeSet::new()).expect("coverage");
    let observation = Observation::new(
        crucible_campaign::AttemptId::parse(&typed_text(
            "crucible.campaign.attempt",
            ObjectKind::CampaignFact,
            1,
            "attempt",
        ))
        .expect("attempt ID"),
        ConfigurationId::from_hash(CampaignHash::derive("configuration", b"child")),
        crucible_campaign::ConfigurationArtifactId::parse(&typed_text(
            "crucible.campaign.configuration-artifact",
            ObjectKind::Configuration,
            1,
            "child",
        ))
        .expect("configuration artifact ID"),
        crucible_campaign::BranchPathId::parse(&typed_text(
            "crucible.campaign.branch-path",
            ObjectKind::CampaignFact,
            2,
            "path",
        ))
        .expect("path ID"),
        StopOutcome::TerminalSuccess,
        measurement_set.id().expect("measurement ID"),
        properties.id().expect("properties ID"),
        coverage.id().expect("coverage ID"),
        BTreeSet::new(),
    )
    .expect("observation");
    let policy = objective_policy();

    let objective = evaluate_crucible_objectives(
        &measurement_set,
        &evaluation,
        &policy,
        &observation,
        &properties,
    )
    .expect("objective evaluation");
    assert!(objective.is_admissible());
    assert_eq!(
        objective.components()["recovery.latency"].value(),
        Some(&crucible_campaign::ObjectiveValue::Unsigned(7))
    );
    assert!(objective.scalar_reward().expect("reward").is_negative());
}
