//! Model-only tests of original controller state, retained packets and exact histories.
//!
//! These fixtures do not qualify installed profiles or mint production runtime
//! authority. The later real owning-worker and signed cold tests are separate.

// crucible-lint: allow panic-shortcut -- These model tests deliberately panic on invalid fixture setup or state drift.
#![allow(clippy::unwrap_used, clippy::expect_used)]

use std::rc::Rc;

use super::*;
use crate::node_contract::{
    ActivationRecord, NodeRoute, OperationToken, OwnerIdentity, WorldActivation,
};

fn probability(value: u64) -> FaultProbability {
    FaultProbability {
        numerator: value.into(),
        denominator: 1.into(),
    }
}

fn coefficients(loss: u64, duplicate: u64, corrupt: u64) -> FaultCoefficients {
    FaultCoefficients {
        loss: probability(loss),
        duplicate: probability(duplicate),
        corrupt: probability(corrupt),
    }
}

fn position(time: u64, phase: Phase) -> Position {
    Position::new(time.into(), 0.into(), phase)
}

fn program() -> ControlledFaultProgram {
    ControlledFaultProgram {
        version: 1,
        initial: FaultedLinkDefinition {
            version: 1,
            seed: 42.into(),
            stream: Id::new("controller/link").unwrap(),
            source_node: 7,
            latency_ps: 100.into(),
            floor_ps: 1.into(),
            loss: probability(0),
            duplicate: probability(0),
            duplicate_gap_ps: 1.into(),
            corrupt: probability(1),
            corruption_bits: 1,
        },
        transitions: vec![
            AuthoredFaultTransition {
                at: position(12, Phase::BoundaryControl),
                coefficients: coefficients(1, 0, 0),
            },
            AuthoredFaultTransition {
                at: position(20, Phase::BoundaryControl),
                coefficients: coefficients(0, 1, 0),
            },
        ],
    }
}

fn admission(link: &ControlledFaultLink, name: &str) -> OperationAdmission {
    let owner = OwnerIdentity {
        owner: Id::new("link-owner").unwrap(),
        incarnation: Id::new("original-owner").unwrap(),
        generation: 1.into(),
    };
    OperationAdmission {
        token: OperationToken {
            authority: Rc::new(()),
            operation: Id::new(name).unwrap(),
            route: NodeRoute {
                node: Id::new("link").unwrap(),
                owners: vec![owner.clone()],
            },
        },
        request: OperationRequest::FaultInjectionV1(Box::new(link.next_request().unwrap())),
        inputs: None,
        activation: WorldActivation {
            authority: Rc::new(()),
            nodes: Rc::from([]),
            preparation: None,
            record: ActivationRecord {
                generation: 1.into(),
                activation_id: Id::new("original-activation").unwrap(),
                world_binding_hash: canonical::hash(
                    "cnp.world-binding.v1",
                    b"explicit model fixture",
                )
                .unwrap(),
                owners: vec![owner],
                boundary: position(0, Phase::BoundaryControl),
            },
        },
    }
}

fn input(
    link: &mut ControlledFaultLink,
    time: u64,
    sequence: u64,
    payload: &[u8],
) -> ResolveOutcome {
    link.consume(
        FaultedInput {
            position: position(time, Phase::Delivery),
            sequence: sequence.into(),
            payload,
        },
        32,
    )
    .unwrap()
}

fn mutate(link: &mut ControlledFaultLink, time: u64, name: &str) -> FaultMutationRecord {
    link.native_mut().park_exact(time).unwrap();
    let original = admission(link, name);
    let prepared = link.prepare_mutation(&original).unwrap();
    let record = prepared.record.clone();
    link.commit_mutation(prepared).unwrap();
    record
}

#[test]
fn applied_coefficients_change_only_later_inputs_and_preserve_original_packets() {
    let mut link = ControlledFaultLink::new(program()).unwrap();
    let first = input(&mut link, 10, 0, b"original");
    assert_eq!(first.deliveries.len(), 1);
    let retained = link.native().snapshot().inflight.clone();
    let original_record = mutate(&mut link, 12, "original-change-0");

    assert_eq!(original_record.input_prefix.get(), 1);
    assert_eq!(link.native().snapshot().inflight, retained);
    assert!(input(&mut link, 13, 1, b"lost later").deliveries.is_empty());
    assert_eq!(link.native().rng_position(), 11);
    assert_eq!(link.native().snapshot().next_seq, 1);

    mutate(&mut link, 20, "original-change-1");
    let last = input(&mut link, 21, 2, b"duplicated later");
    assert_eq!(last.deliveries.len(), 2);
    assert_eq!(last.deliveries[0].payload, b"duplicated later");
    assert_eq!(last.deliveries[1].payload, b"duplicated later");
    assert_eq!(last.deliveries[0].key.seq, 1);
    assert_eq!(last.deliveries[1].key.seq, 2);
    assert_eq!(link.native().rng_position(), 16);
    assert!(!link.native().snapshot().lookahead_recompute_pending);
}

#[test]
fn unchanged_native_restoration_retains_original_controller_and_next_draw() {
    let definition = program();
    let mut original = ControlledFaultLink::new(definition.clone()).unwrap();
    input(&mut original, 10, 0, b"original");
    let record = mutate(&mut original, 12, "original-change-0");
    let snapshot = original.capture(4 << 20).unwrap();
    let mut restored = ControlledFaultLink::restore(&definition, &snapshot, 4 << 20).unwrap();

    assert_eq!(restored.capture(4 << 20).unwrap(), snapshot);
    assert_eq!(restored.original_mutation(&record.operation), Some(&record));
    assert_eq!(restored.next_request(), original.next_request());
    assert_eq!(
        input(&mut restored, 13, 1, b"later").deliveries,
        input(&mut original, 13, 1, b"later").deliveries
    );
    mutate(&mut original, 20, "original-change-1");
    mutate(&mut restored, 20, "original-change-1");
    assert_eq!(
        input(&mut restored, 21, 2, b"future").deliveries,
        input(&mut original, 21, 2, b"future").deliveries
    );
    assert_eq!(
        restored.capture(4 << 20).unwrap(),
        original.capture(4 << 20).unwrap()
    );
}

#[test]
fn wrong_coordinate_request_and_unapplied_decision_refuse_without_effects() {
    let mut link = ControlledFaultLink::new(program()).unwrap();
    let before = link.capture(4 << 20).unwrap();
    let original = admission(&link, "original-change-0");
    assert!(link.prepare_mutation(&original).is_err());
    assert!(
        link.consume(
            FaultedInput {
                position: position(12, Phase::Delivery),
                sequence: 0.into(),
                payload: b"after decision"
            },
            32
        )
        .is_err()
    );
    assert_eq!(link.capture(4 << 20).unwrap(), before);

    link.native_mut().park_exact(12).unwrap();
    let mut changed = admission(&link, "changed");
    let OperationRequest::FaultInjectionV1(request) = &mut changed.request else {
        unreachable!()
    };
    request.decision = 1.into();
    let parked = link.capture(4 << 20).unwrap();
    assert!(link.prepare_mutation(&changed).is_err());
    assert_eq!(link.capture(4 << 20).unwrap(), parked);
}

#[test]
fn changed_original_table_decision_and_clock_contract_cannot_decode() {
    let definition = program();
    let mut original = ControlledFaultLink::new(definition.clone()).unwrap();
    input(&mut original, 10, 0, b"original");
    mutate(&mut original, 12, "original-change-0");
    let snapshot = original.capture(4 << 20).unwrap();
    let saved: ControlledSnapshot = serde_json::from_slice(&snapshot).unwrap();
    let mut changed = saved;
    changed.mutations[0].input_prefix = 0.into();
    assert!(
        ControlledFaultLink::restore(&definition, &encode(&changed).unwrap(), 4 << 20).is_err()
    );
    changed.mutations[0].input_prefix = 1.into();
    changed.mutations[0].applied_table = changed.mutations[0].previous_table.clone();
    assert!(
        ControlledFaultLink::restore(&definition, &encode(&changed).unwrap(), 4 << 20).is_err()
    );
    let mut different = definition;
    different.initial.floor_ps = 2.into();
    assert!(ControlledFaultLink::restore(&different, &snapshot, 4 << 20).is_err());
}
