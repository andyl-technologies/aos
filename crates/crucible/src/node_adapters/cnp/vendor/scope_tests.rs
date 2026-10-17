//! Original quantum and operation-role adversaries without native authority.

// crucible-lint: allow panic-shortcut -- Closed inert argument fixtures assert their own grammar.
#![allow(clippy::unwrap_used)]

use super::*;
use crucible_node_contract::{Id, OperatingMode, Phase, Position, Tick, U64, canonical};
use crucible_node_provider::bodies::QuantumBeginArguments;
use std::time::Duration;

fn arguments() -> QuantumBeginArguments {
    QuantumBeginArguments {
        grant_id: Id::new("window").unwrap(),
        participant_ids: vec![Id::new("node").unwrap()],
        realization_id: Id::new("realization").unwrap(),
        activation_id: Id::new("activation").unwrap(),
        world_generation: U64::new(1),
        owner_generation: U64::new(1),
        input_epoch: Id::new("epoch").unwrap(),
        mode: OperatingMode::Quantized,
        ordering_profile: "superdense-v1".into(),
        quantum_index: U64::new(0),
        from_ps: Tick::new(0),
        until_ps: Tick::new(1000),
        input_batch: canonical::content_ref(b"[]", "application/json").unwrap(),
        input_watermark: U64::new(0),
        policy_hash: canonical::hash("cnp.policy.v1", b"inert").unwrap(),
        wall_budget_ns: U64::new(123),
    }
}

fn request() -> OperationRequest {
    OperationRequest::QuantumBegin {
        window: Id::new("window").unwrap(),
        start: Position::new(U64::new(0), U64::new(0), Phase::BoundaryControl),
        end: Position::new(U64::new(1000), U64::new(0), Phase::Publication),
        input_batch: Id::new("input").unwrap(),
        host_budget: Duration::from_nanos(123),
    }
}

#[test]
fn unchanged_quantum_accepts_but_widened_tick_or_hardware_budget_refuses() {
    let original = request();
    let args = arguments();
    assert!(validate_bounds(&original, &BeginArguments::QuantumBegin(args.clone())).is_ok());

    let mut widened = args.clone();
    widened.until_ps = Tick::new(1001);
    assert!(validate_bounds(&original, &BeginArguments::QuantumBegin(widened)).is_err());

    let mut changed_budget = args;
    changed_budget.wall_budget_ns = U64::new(124);
    assert!(validate_bounds(&original, &BeginArguments::QuantumBegin(changed_budget)).is_err());
}

#[test]
fn same_transport_begin_cannot_turn_observation_into_quantum() {
    assert!(
        validate_bounds(
            &OperationRequest::Observe,
            &BeginArguments::QuantumBegin(arguments())
        )
        .is_err()
    );
}
