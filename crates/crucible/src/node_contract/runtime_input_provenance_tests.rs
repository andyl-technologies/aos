//! Data-only proof-integrity and legacy-format regressions; no native authority.

// crucible-lint: allow panic-shortcut -- These runtime input provenance tests deliberately panic on invalid fixtures or failed invariants.
#![allow(clippy::unwrap_used, clippy::expect_used)]

use super::*;
use crucible_node_contract::{Phase, Position, canonical};

fn id(value: &str) -> Id {
    Id::new(value).unwrap()
}

fn object(bytes: &[u8]) -> InputPayload {
    InputPayload {
        reference: canonical::content_ref(bytes, "application/octet-stream").unwrap(),
        bytes: bytes.to_vec(),
    }
}

fn legacy_input() -> SavedRuntimeInput {
    SavedRuntimeInput {
        node: id("consumer"),
        stage_operation: id("stage/1"),
        batch: id("batch/1"),
        owners: vec![],
        cutoff: Position::new(1.into(), 0.into(), Phase::BoundaryControl),
        inventory: canonical::content_ref(b"[]", "application/vnd.crucible.input-inventory+json")
            .unwrap(),
        deliveries: vec![],
        payloads: vec![],
        provenance: None,
        acknowledgement: None,
        failure: None,
        committed: false,
        coordinator_committed: false,
    }
}

#[test]
fn legacy_input_encoding_has_the_exact_original_field_roster() {
    let value = serde_json::to_value(legacy_input()).unwrap();
    let mut actual: Vec<_> = value
        .as_object()
        .unwrap()
        .keys()
        .map(String::as_str)
        .collect();
    actual.sort();
    assert_eq!(
        actual,
        [
            "acknowledgement",
            "batch",
            "committed",
            "coordinator_committed",
            "cutoff",
            "deliveries",
            "failure",
            "inventory",
            "node",
            "owners",
            "payloads",
            "stage_operation"
        ]
    );
    let restored: SavedRuntimeInput = serde_json::from_value(value).unwrap();
    assert_eq!(restored, legacy_input());
}

#[test]
fn legacy_input_canonical_bytes_keep_the_original_golden_envelope() {
    let input = legacy_input();
    let inventory =
        canonical::canonical_json(&serde_json::to_value(&input.inventory).unwrap()).unwrap();
    let inventory = std::str::from_utf8(&inventory).unwrap();
    let golden = r#"{"acknowledgement":null,"batch":"batch/1","committed":false,"coordinator_committed":false,"cutoff":{"microstep":"0","phase":0,"time_ps":"1"},"deliveries":[],"failure":null,"inventory":INVENTORY,"node":"consumer","owners":[],"payloads":[],"stage_operation":"stage/1"}"#;
    let expected = golden.replace("INVENTORY", inventory);
    let actual = canonical::canonical_json(&serde_json::to_value(input).unwrap()).unwrap();
    assert_eq!(actual, expected.as_bytes());
}

#[test]
fn root_and_dependency_bytes_are_reserved_before_retrieval() {
    let root = object(b"original root");
    let dependency = object(b"original dependency");
    let requested = [root.reference.clone(), dependency.reference.clone()];
    let credit = root.bytes.len() + dependency.bytes.len();
    let retained = BTreeMap::new();
    assert!(
        reserve_objects(
            &retained,
            &requested,
            InputProvenanceLimits {
                maximum_objects: 1,
                maximum_bytes: credit
            }
        )
        .is_err()
    );
    assert!(
        reserve_objects(
            &retained,
            &requested,
            InputProvenanceLimits {
                maximum_objects: 2,
                maximum_bytes: credit - 1
            }
        )
        .is_err()
    );
    assert!(
        reserve_objects(
            &retained,
            &requested,
            InputProvenanceLimits {
                maximum_objects: 2,
                maximum_bytes: credit
            }
        )
        .is_ok()
    );
    assert!(retained.is_empty());
}

#[test]
fn hash_only_missing_and_corrupt_original_objects_are_refused() {
    let root = object(b"original proof bytes");
    let mut retained = BTreeMap::new();
    assert!(retain_objects(&mut retained, std::slice::from_ref(&root.reference), vec![]).is_err());
    assert!(retained.is_empty());
    let mut changed = root.clone();
    changed.bytes[0] ^= 1;
    assert!(
        retain_objects(
            &mut retained,
            std::slice::from_ref(&root.reference),
            vec![changed]
        )
        .is_err()
    );
    assert!(retained.is_empty());
    retain_objects(
        &mut retained,
        std::slice::from_ref(&root.reference),
        vec![root.clone()],
    )
    .unwrap();
    assert_eq!(retained[&root.reference], root);
}

#[test]
fn explicit_sidecar_cannot_be_rebound_to_a_different_stage() {
    let mut input = legacy_input();
    input.provenance = Some(SavedInputProvenance {
        schema_version: 1,
        node: input.node.clone(),
        stage_operation: id("other-stage"),
        batch: input.batch.clone(),
        inventory: input.inventory.clone(),
        roots: vec![],
        objects: vec![],
    });
    assert_eq!(
        validate_saved_inputs(&[input]),
        Err(RuntimeError::InvalidReceipt)
    );
}

#[test]
fn explicit_sidecar_rejects_corrupt_dependency_storage_and_unknown_edition() {
    let mut input = legacy_input();
    let mut proof = object(b"model-only dependency");
    proof.bytes.push(0);
    input.provenance = Some(SavedInputProvenance {
        schema_version: 1,
        node: input.node.clone(),
        stage_operation: input.stage_operation.clone(),
        batch: input.batch.clone(),
        inventory: input.inventory.clone(),
        roots: vec![],
        objects: vec![proof],
    });
    assert_eq!(
        validate_saved_inputs(&[input.clone()]),
        Err(RuntimeError::InvalidReceipt)
    );
    input.provenance.as_mut().unwrap().schema_version = 2;
    assert_eq!(
        validate_saved_inputs(&[input]),
        Err(RuntimeError::InvalidReceipt)
    );
}
