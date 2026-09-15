//! Cross-layer measurement payload verification regressions.

// crucible-lint: allow panic-shortcut -- test fixtures use panic shortcuts.
#![allow(clippy::expect_used)]

use super::*;
use std::collections::{BTreeMap, BTreeSet};

use crucible::model::{
    Aggregation, BoundarySelector, CohortPolicy, MeasurementDefinition, MeasurementId,
    MetricDefinition, MetricId, MetricSource, MetricValueType, UnitId,
};
use crucible::{Icount, MarkerId, NodeId, NodeTemplate, ReadyPoint, VirtualTime, WhiteBoxPolicy};
use crucible_campaign::{
    CampaignMode, CampaignPolicy, CampaignSeed, ConfigurationId, CoverageProjection,
    ExplorerPolicy, FairnessPolicy, Objective, ObjectiveGoal, Observation, PuctPolicy,
    RetentionPolicy, ScenarioDefId, StopOutcome,
};
use crucible_cas::content_store::{ContentId, ObjectKind};

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
        CampaignPolicy::identity(
            crucible_campaign::ScenarioDefId::from_hash(CampaignHash::derive("test", b"scenario")),
            CampaignSeed::from_bytes([0x8c; 32]),
            CampaignMode::Strict,
            ExplorerPolicy::TreeSearch {
                puct: PuctPolicy::new(1_000_000, 0, 0),
                widening: None,
            },
        ),
        CampaignPolicy::rules(
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
        ),
    )
    .expect("policy")
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
                unit: UnitId::parse("events").expect("unit"),
                source: MetricSource::SchedulerEventCount,
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
    let terminal = MeasurementTerminalState {
        scenario_ready_at: None,
        at: VirtualTime { ticks: 2 },
        node_icounts: BTreeMap::from([(node("router"), Icount { retired: 2 })]),
        scheduler_quiescent: false,
    };
    let scenario = ScenarioDefId::from_hash(CampaignHash::derive("test", b"scenario"));
    let configuration = ConfigurationId::from_hash(CampaignHash::derive("configuration", b"child"));
    let publication = evaluate_crucible_measurement_publication(
        scenario,
        configuration,
        &definitions,
        entries,
        terminal,
        MAX_CRUCIBLE_MEASUREMENT_REPLAY_EVIDENCE_BYTES,
    )
    .expect("measurement publication");
    let evaluation = verify_crucible_measurement_publication(
        publication.measurement_set(),
        publication.evidence(),
        scenario,
        configuration,
        &definitions,
    )
    .expect("verified measurement publication");
    let (_, _, measurement_set) = publication.into_parts();
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
        Observation::outcome(
            configuration,
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
        ),
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
        Some(&crucible_campaign::ObjectiveValue::Unsigned(1))
    );
    assert!(objective.scalar_reward().expect("reward").is_negative());
}
