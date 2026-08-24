//! Cross-layer measurement payload verification regressions.

// crucible-lint: allow panic-shortcut -- test fixtures use panic shortcuts.
#![allow(clippy::expect_used)]

use super::*;
use std::collections::{BTreeMap, BTreeSet};

use crucible::VirtualTime;
use crucible_campaign::{MeasurementSeries, MetricValue};

fn terminal() -> MeasurementTerminalState {
    MeasurementTerminalState {
        scenario_ready_at: None,
        at: VirtualTime { ticks: 0 },
        node_icounts: Default::default(),
        scheduler_quiescent: true,
    }
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
