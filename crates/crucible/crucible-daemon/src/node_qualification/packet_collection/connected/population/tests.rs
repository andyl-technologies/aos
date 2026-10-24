//! Checks supplemental criterion geometry without executing native witnesses.

// crucible-lint: allow panic-shortcut -- Assertions are the planning-data test oracle.
#![allow(clippy::unwrap_used)]

use super::*;
use crate::node_qualification::{
    AcceptanceDecision, CaseVerdict, PlannedFixtureAudit, QualificationLimits,
    RequirementDisposition,
};
use crucible_engine::node_contract::OperationRequest;
use crucible_node_format::{Id, Phase, Position, Tick, U64};

fn population() -> PacketConnectedWitnessPopulation {
    use PacketConnectedCaseKind::*;

    let nodes = ["producer", "relay", "sink"].map(|name| Id::new(name).unwrap());
    let operation = Id::new("original-operation").unwrap();
    let schedule = PacketConnectedSchedule {
        nodes: nodes.clone(),
        grants: vec![super::super::PacketConnectedGrant {
            node: nodes[0].clone(),
            operation: operation.clone(),
            request: OperationRequest::BoundarySettle {
                start: Position::new(Tick::new(0), U64::new(0), Phase::BoundaryControl),
                limit: Position::new(Tick::new(0), U64::new(1), Phase::Publication),
            },
        }],
        cases: [
            Stage,
            InputAcknowledgement,
            Commit,
            Delivery,
            Reaction,
            Publication,
            BeforeRetirement,
            AfterRetirement,
            SlowProducerRefusal,
            ZeroDelayClosure,
            PositiveDelayCoordinate,
            DurableRoot,
        ]
        .into_iter()
        .enumerate()
        .map(|(index, kind)| super::super::PacketConnectedCase {
            id: format!("packet-connected-{index:02}"),
            kind,
            node: nodes[0].clone(),
            operation: Some(operation.clone()),
        })
        .collect(),
    };
    let bytes = b"inert planning-data fixture".to_vec();
    let reference = canonical::content_ref(&bytes, "text/plain").unwrap();
    let unit = QualificationUnit {
        implementation: reference.clone(),
        realization: reference.clone(),
        descriptors: reference.clone(),
        contracts: reference.clone(),
        port_profiles: reference.clone(),
        environment: reference.clone(),
        harness: reference.clone(),
        fixtures: reference.clone(),
        specification: normative_specification().unwrap().0,
    };

    PacketConnectedWitnessPopulation::build(PacketConnectedPopulationRequest {
        unit,
        schedule: &schedule,
        content: &BTreeMap::from([(reference, bytes)]),
    })
    .unwrap()
}

#[test]
fn every_original_obligation_and_supplemental_conjunct_remains_unexecuted() {
    let population = population();
    let (_, catalog) = requirement_catalog().unwrap();
    let plan = population.plan();

    assert_eq!(plan.requirements.len(), 382);
    assert_eq!(plan.cases.len(), 394);
    let mut referenced = BTreeSet::new();
    for id in catalog {
        let WitnessCriterion::Applicable { cases, criterion } = &plan.requirements[id] else {
            panic!("original obligations cannot become exclusions");
        };
        assert!(cases.contains(&format!("unexecuted-original-{id}")));
        referenced.extend(cases.iter());

        // The retained criterion binds the full conjunct list, not just the ID.
        let body: serde_json::Value =
            serde_json::from_slice(&population.bodies()[criterion]).unwrap();
        assert_eq!(body[4], serde_json::to_value(cases).unwrap());
    }
    assert!(plan.cases.iter().all(|case| referenced.contains(&case.id)));

    let audit = PlannedFixtureAudit::prepare(
        plan,
        population.reference(),
        QualificationLimits::default(),
        8 * 1024 * 1024,
    )
    .unwrap();
    assert!(matches!(
        audit.record().decision,
        AcceptanceDecision::Refused { .. }
    ));
    assert!(audit.record().original.requirements.iter().all(|row| {
        row.disposition == RequirementDisposition::NotExecuted
            && row
                .cases
                .iter()
                .all(|case| case.verdict == CaseVerdict::NotExecuted)
    }));
}

#[test]
fn removing_a_supplemental_association_still_refuses_the_orphan() {
    let population = population();
    let mut plan = population.plan().clone();
    for criterion in plan.requirements.values_mut() {
        if let WitnessCriterion::Applicable { cases, .. } = criterion {
            cases.retain(|case| case != "packet-connected-00");
        }
    }
    let bytes = canonical::canonical_json(&serde_json::to_value(&plan).unwrap()).unwrap();
    let reference = canonical::content_ref(&bytes, "application/json").unwrap();

    assert!(
        PlannedFixtureAudit::prepare(
            &plan,
            &reference,
            QualificationLimits::default(),
            8 * 1024 * 1024,
        )
        .is_err()
    );
}

#[test]
fn distinct_input_and_causal_witnesses_bind_their_relevant_obligations() {
    let population = population();
    let expected = [
        ("CN-NODE-24", "packet-connected-02"),
        ("CN-TIME-13", "packet-connected-08"),
        ("CN-TEST-036", "packet-connected-09"),
        ("CN-TIME-14", "packet-connected-10"),
        ("CN-TEST-038", "packet-connected-11"),
    ];
    for (requirement, case) in expected {
        let WitnessCriterion::Applicable { cases, .. } =
            &population.plan().requirements[requirement]
        else {
            panic!("supplemental witnesses cannot supply applicability exclusions");
        };
        assert!(cases.contains(&case.to_owned()));
        assert!(cases.contains(&format!("unexecuted-original-{requirement}")));
    }
}
