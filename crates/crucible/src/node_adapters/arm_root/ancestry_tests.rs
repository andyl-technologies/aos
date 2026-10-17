//! Checks bounded historical data without constructing native or public authority.

// crucible-lint: allow panic-shortcut -- Data-only fixtures use panics to report violated lineage invariants.
#![allow(clippy::unwrap_used)]

use std::{collections::BTreeMap, path::PathBuf};

use crucible_node_contract::{ContentRef, Id, Phase, Position, U64, canonical};
use crucible_node_provider::gem5::{ArmRootHistoricalSource, Gem5Boundary};

use crate::{node_contract::*, node_scheduling::InputPayload};

use super::{
    ancestry::{decode_ancestry, validate_observation_roster, validate_prefix_ancestry},
    capture::{OperationWire, PrefixWire, RootWire},
    encoding,
};

#[test]
fn historical_prefix_requires_unchanged_permission_and_original_scope() {
    let mut original = wire(1);
    let body = reference(b"native-original-prefix");
    original.native_outcomes.push(body.clone());
    let request = OperationRequest::ExactRun {
        start: position(0),
        limit: position(100),
        boundary_policy: ExactBoundaryPolicy::HorizonPark,
    };
    let operation = SavedRuntimeOperation {
        operation: id("original/run"),
        route: NodeRoute {
            node: id("root"),
            owners: original.owners.clone(),
        },
        request,
        input_batch: None,
        result: SavedRuntimeResult::Pending,
        close_submission: None,
        submission_effects: None,
        scheduling_commit: None,
    };
    original.operations.push(OperationWire {
        original: operation,
        prefixes: vec![PrefixWire {
            body,
            activation: original.source_activation.clone(),
            route: NodeRoute {
                node: id("root"),
                owners: original.owners.clone(),
            },
        }],
    });
    let mut fresh = wire(2);
    fresh.native_outcomes = original.native_outcomes.clone();
    fresh.operations = original.operations.clone();
    fresh.operations[0].original.route.owners = fresh.owners.clone();
    assert!(validate_prefix_ancestry(&fresh, std::slice::from_ref(&original)).is_ok());

    let mut widened = fresh.clone();
    widened.operations[0].original.request = OperationRequest::ExactRun {
        start: position(0),
        limit: position(101),
        boundary_policy: ExactBoundaryPolicy::HorizonPark,
    };
    assert!(validate_prefix_ancestry(&widened, std::slice::from_ref(&original)).is_err());

    fresh.operations[0].prefixes[0].activation.generation = 99.into();
    assert!(validate_prefix_ancestry(&fresh, &[original]).is_err());
}

#[test]
fn preparation_chain_has_exact_missing_body_and_depth_bounds() {
    let mut bodies = BTreeMap::new();
    let mut previous = None;
    for generation in 1..=7 {
        let mut prior = wire(generation);
        prior.previous = previous;
        let bytes = encoding::record(&prior, 16 * 1024 * 1024).unwrap();
        let reference = reference(&bytes);
        bodies.insert(
            reference.clone(),
            InputPayload {
                reference: reference.clone(),
                bytes,
            },
        );
        previous = Some(reference);
    }
    let mut current = wire(8);
    current.previous = previous;
    assert_eq!(decode_ancestry(&current, &bodies).unwrap().len(), 7);
    assert!(decode_ancestry(&current, &BTreeMap::new()).is_err());

    let bytes = encoding::record(&current, 16 * 1024 * 1024).unwrap();
    let reference = reference(&bytes);
    bodies.insert(
        reference.clone(),
        InputPayload {
            reference: reference.clone(),
            bytes,
        },
    );
    let mut excessive = wire(9);
    excessive.previous = Some(reference);
    assert!(decode_ancestry(&excessive, &bodies).is_err());
}

#[test]
fn stopped_observation_requires_exact_historical_scope_and_readable_closure() {
    let original = wire(1);
    let mut current = wire(2);
    let bytes = canonical::canonical_json(&serde_json::json!({
        "schema":"crucible.gem5.arm-root-observation.v1",
        "boundary":original.native_boundary,
        "closure":original.closure,
        "owners":original.owners,
        "activation":original.source_activation,
    }))
    .unwrap();
    let body = reference(&bytes);
    current.observations.push(body.clone());
    let mut evidence = BTreeMap::from([
        (
            body.clone(),
            InputPayload {
                reference: body,
                bytes,
            },
        ),
        (
            original.closure.clone(),
            InputPayload {
                reference: original.closure.clone(),
                bytes: b"data-only-reference".to_vec(),
            },
        ),
    ]);
    assert!(
        validate_observation_roster(&current, std::slice::from_ref(&original), &evidence).is_ok()
    );
    assert!(validate_observation_roster(&current, &[], &evidence).is_err());
    evidence.remove(&original.closure);
    assert!(validate_observation_roster(&current, &[original], &evidence).is_err());
}

fn wire(generation: u64) -> RootWire {
    let owner = OwnerIdentity {
        owner: id("owner/root"),
        incarnation: id(&format!("root/incarnation/{generation}")),
        generation: generation.into(),
    };
    let owners = vec![owner.clone()];
    let reference = reference(b"data-only-reference");
    RootWire {
        format: "crucible.gem5.arm-root-public-native-continuation".to_owned(),
        schema_version: 2,
        node: id("root"),
        source_activation: SavedRuntimeActivation {
            generation: generation.into(),
            activation_id: id(&format!("activation/{generation}")),
            world_binding_hash: reference.hash.clone(),
            owners: owners.clone(),
            boundary: position(0),
        },
        common_cut: position(50),
        owners,
        capture: id(&format!("capture/{generation}")),
        source: ArmRootHistoricalSource {
            schema: "crucible.gem5.arm-root-historical-source.v1".to_owned(),
            owner: owner.owner,
            incarnation: owner.incarnation,
            generation: owner.generation,
            profile: reference.clone(),
            model_id: super::ARM_ROOT_MODEL.to_owned(),
            native_dialect: super::ARM_ROOT_DIALECT.to_owned(),
            bindings: BTreeMap::new(),
            resource_root: PathBuf::from("/inert/resource"),
            image_root: PathBuf::from("/inert/image"),
            temporary_root: PathBuf::from("/inert/temporary"),
            timeout_nanoseconds: 1.into(),
        },
        supplementary_files_root: "/inert/image/peer_files".to_owned(),
        native_boundary: Gem5Boundary {
            tick: 50.into(),
            logical_position: position(50),
            ordinal: 1.into(),
            tick_ordinal: 1.into(),
            has_next_event: false,
            next_tick: 0.into(),
            next_priority: 0,
            inventory: serde_json::Value::Null,
        },
        maximum_microsteps: 1_000_000.into(),
        maximum_events_per_poll: 262_144.into(),
        output_sequence: 0.into(),
        operations: Vec::new(),
        native_outcomes: Vec::new(),
        control_schema: "data-only-control".to_owned(),
        packets: Vec::new(),
        sessions: Vec::new(),
        pending: None,
        last_acknowledged: None,
        closure: reference.clone(),
        world_preparation: reference.clone(),
        ready: reference.clone(),
        native_ready: reference.clone(),
        native_session: reference,
        previous: None,
        observations: Vec::new(),
        artifacts: Vec::new(),
    }
}

fn reference(bytes: &[u8]) -> ContentRef {
    canonical::content_ref(bytes, "application/json").unwrap()
}

fn id(value: &str) -> Id {
    Id::new(value).unwrap()
}

fn position(time: u64) -> Position {
    Position::new(U64::new(time), 0.into(), Phase::BoundaryControl)
}
