//! Checks adverse data population bounds; these tests qualify no native profile.
// crucible-lint: allow panic-shortcut -- Malformed data must fail the unit test
// crucible-lint: allow rust-allow -- Malformed data must fail the unit test
#![allow(clippy::unwrap_used, reason = "Malformed data must fail the unit test")]

use super::*;
use crucible_node_contract::{Extensions, HashRef, U64};
use crucible_node_provider::envelope::Nullable;

fn observe(id: &str) -> CnpPreparedAdverseRequest {
    CnpPreparedAdverseRequest {
        request: Id::new(id).unwrap(),
        operation: None,
        body: CnpPreparedAdverseBody::Observe(Box::new(ObserveRequest {
            binding_hash: HashRef {
                algorithm: "blake3-256".into(),
                domain: "cnp.owner-binding.v1".into(),
                digest: "0".repeat(64),
            },
            owner_generation: U64::new(1),
            after_observation_sequence: U64::new(0),
            maximum_items: U64::new(1),
            extensions: Extensions::new(),
        })),
    }
}

#[test]
fn observe_cannot_smuggle_an_operation() {
    let mut request = observe("observe");
    request.operation = Some(Id::new("foreign-operation").unwrap());
    assert!(
        matches!(prepare_bodies(&[request]), Err(error) if error.effects == EffectKnowledge::None)
    );
}

#[test]
fn later_invalid_body_refuses_complete_population_before_dispatch() {
    let first = observe("first");
    let mut second = observe("second");
    if let CnpPreparedAdverseBody::Observe(body) = &mut second.body {
        body.owner_generation = U64::new(0);
    }
    assert!(
        matches!(prepare_bodies(&[first, second]), Err(error) if error.effects == EffectKnowledge::None)
    );
}

#[test]
fn duplicate_originals_and_excess_population_refuse() {
    assert!(prepare_bodies(&[observe("same"), observe("same")]).is_err());
    let requests = (0..17)
        .map(|index| observe(&format!("row-{index}")))
        .collect::<Vec<_>>();
    assert!(prepare_bodies(&requests).is_err());
    assert!(prepare_bodies(&requests[..16]).is_ok());
}

#[test]
fn executable_kind_cannot_enter_preparation_probe() {
    let request = CnpPreparedAdverseRequest {
        request: Id::new("forbidden-run").unwrap(),
        operation: Some(Id::new("forbidden-operation").unwrap()),
        body: CnpPreparedAdverseBody::UnsupportedBegin(Box::new(BeginRequest {
            kind: BeginKind::QuantumBegin,
            binding_hash: HashRef {
                algorithm: "blake3-256".into(),
                domain: "cnp.owner-binding.v1".into(),
                digest: "0".repeat(64),
            },
            owner_generation: U64::new(1),
            activation_id: Nullable(None),
            world_generation: U64::new(0),
            arguments: serde_json::Map::new(),
            extensions: Extensions::new(),
        })),
    };
    assert!(
        matches!(prepare_bodies(&[request]), Err(error) if error.effects == EffectKnowledge::None)
    );
}
