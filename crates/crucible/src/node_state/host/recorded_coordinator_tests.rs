//! Inert legacy byte compatibility and selected portable provenance codec checks.

#![cfg(test)]
// crucible-lint: allow panic-shortcut -- Any changed legacy bytes or accepted malformed codec must fail this unit fixture.
// crucible-lint: allow rust-allow -- Assertions inspect exact serde encodings and deliberately panic on changed data-only expectations.
#![allow(clippy::unwrap_used, clippy::expect_used)]

use super::*;
use crucible_node_contract::{Phase, canonical};

#[derive(Serialize)]
struct OriginalDerive<'a> {
    schema_version: u32,
    scheduler: &'a SchedulingSnapshot,
    runtime: &'a RuntimeSnapshot,
    world_repeatability: Repeatability,
}

fn fixture() -> Coordinator {
    let reference = canonical::content_ref(&[0, 127, 255], "application/octet-stream").unwrap();
    let hash = reference.hash.clone();
    let boundary = Position::new(0.into(), 0.into(), Phase::BoundaryControl);
    let activation = SavedRuntimeActivation {
        generation: 1.into(),
        activation_id: Id::new("original/activation").unwrap(),
        world_binding_hash: hash.clone(),
        owners: vec![],
        boundary,
    };
    let scheduler: SchedulingSnapshot = serde_json::from_value(serde_json::json!({
        "schema_version":1,"ordering_profile":"superdense-v1","world_binding_hash":hash,
        "source_activation_id":"original/activation","source_generation":"1",
        "source_boundary":boundary,"capture_cut":boundary,"capture_ordinal":"0",
        "source_owners":[],"maximum_microsteps":"16","positions":[],"producers":[],
        "native_sequences":[],"external_closed_prefixes":[],"payload_objects":[],
        "pending_deliveries":[],"used_operations":[],"reservations":[],"input_batches":[],
        "used_input_batches":[]
    }))
    .unwrap();
    let input = SavedRuntimeInput {
        node: Id::new("disk").unwrap(),
        stage_operation: Id::new("original/stage").unwrap(),
        batch: Id::new("original/batch").unwrap(),
        owners: vec![],
        cutoff: boundary,
        inventory: reference.clone(),
        deliveries: vec![],
        payloads: vec![],
        provenance: Some(SavedInputProvenance {
            schema_version: 1,
            node: Id::new("disk").unwrap(),
            stage_operation: Id::new("original/stage").unwrap(),
            batch: Id::new("original/batch").unwrap(),
            inventory: reference.clone(),
            roots: vec![reference.clone()],
            objects: vec![InputPayload {
                reference,
                bytes: vec![0, 127, 255],
            }],
        }),
        acknowledgement: None,
        failure: None,
        committed: false,
        coordinator_committed: false,
    };
    Coordinator {
        schema_version: 1,
        scheduler,
        runtime: RuntimeSnapshot {
            schema_version: 2,
            source_activation: activation,
            capture_cut: boundary,
            capture_ordinal: 0.into(),
            owners: vec![],
            operations: vec![],
            inputs: vec![input],
            terminal: None,
            condition_stop: None,
        },
        world_repeatability: Repeatability::Qualified,
    }
}

#[test]
fn recorded_coordinator_preserves_old_numeric_body_bytes_and_nullable_fields() {
    let mut original = fixture();
    for version in [1, 2, 3] {
        original.schema_version = version;
        let old = serde_json::to_vec(&OriginalDerive {
            schema_version: version,
            scheduler: &original.scheduler,
            runtime: &original.runtime,
            world_repeatability: original.world_repeatability,
        })
        .unwrap();
        let encoded = serde_json::to_vec(&original).unwrap();
        assert_eq!(encoded, old);
        let value: serde_json::Value = serde_json::from_slice(&encoded).unwrap();
        assert_eq!(
            value["runtime"]["inputs"][0]["provenance"]["objects"][0]["bytes"],
            serde_json::json!([0, 127, 255])
        );
        assert_eq!(
            value["runtime"]["inputs"][0]["acknowledgement"],
            serde_json::Value::Null
        );
        assert_eq!(
            value["runtime"]["inputs"][0]["failure"],
            serde_json::Value::Null
        );
        let decoded: Coordinator = serde_json::from_slice(&old).unwrap();
        assert_eq!(serde_json::to_vec(&decoded).unwrap(), old);
    }
}

#[test]
fn recorded_coordinator_selected_portable_body_refuses_mixed_and_duplicate_editions() {
    let mut original = fixture();
    original.schema_version = 5;
    let bytes = serde_json::to_vec(&original).unwrap();
    let value: serde_json::Value = serde_json::from_slice(&bytes).unwrap();
    assert_eq!(
        value["runtime"]["inputs"][0]["provenance"]["objects"][0]["bytes"],
        "AH__"
    );
    let restored: Coordinator = serde_json::from_slice(&bytes).unwrap();
    assert_eq!(restored.runtime, original.runtime);
    assert_eq!(restored.scheduler, original.scheduler);
    for version in [1, 2, 3, 4, 6] {
        let mut changed = value.clone();
        changed["schema_version"] = serde_json::json!(version);
        assert!(serde_json::from_value::<Coordinator>(changed).is_err());
    }
    let text = std::str::from_utf8(&bytes).unwrap();
    let duplicate = text.replacen(
        "\"schema_version\":5",
        "\"schema_version\":5,\"schema_version\":5",
        1,
    );
    assert!(serde_json::from_str::<Coordinator>(&duplicate).is_err());
    for runtime_edition in [1, 3, 4, 5, 6] {
        let mut changed = value.clone();
        changed["runtime"]["schema_version"] = serde_json::json!(runtime_edition);
        assert!(serde_json::from_value::<Coordinator>(changed).is_err());
    }
    // Before this selected successor, five was unsupported. Retagging the
    // unchanged numeric legacy body cannot turn it into portable recorded data.
    let old = serde_json::to_vec(&OriginalDerive {
        schema_version: 5,
        scheduler: &original.scheduler,
        runtime: &original.runtime,
        world_repeatability: original.world_repeatability,
    })
    .unwrap();
    assert!(serde_json::from_slice::<Coordinator>(&old).is_err());
    let mut missing = value;
    missing["runtime"]["inputs"][0]
        .as_object_mut()
        .unwrap()
        .remove("failure");
    assert!(serde_json::from_value::<Coordinator>(missing).is_err());
}

#[test]
fn recorded_coordinator_direct_decoder_preserves_large_legacy_and_closed_grammar() {
    let mut original = fixture();
    let payload = &mut original.runtime.inputs[0]
        .provenance
        .as_mut()
        .unwrap()
        .objects[0];
    payload.bytes = vec![127; 70_000];
    payload.reference = canonical::content_ref(&payload.bytes, "application/octet-stream").unwrap();
    for edition in [1, 2, 3, 5] {
        original.schema_version = edition;
        let bytes = serde_json::to_vec(&original).unwrap();
        let decoded = decode(&bytes).unwrap();
        assert_eq!(serde_json::to_vec(&decoded).unwrap(), bytes);
        let mut trailing = bytes.clone();
        trailing.extend_from_slice(b" null");
        assert!(decode(&trailing).is_err());
        let text = std::str::from_utf8(&bytes).unwrap();
        let duplicate = text.replacen(
            "\"schema_version\":",
            "\"schema_version\":0,\"schema_version\":",
            1,
        );
        assert!(decode(duplicate.as_bytes()).is_err());
    }
    let mut value = serde_json::to_value(&original).unwrap();
    for edition in [4, 6] {
        value["schema_version"] = serde_json::json!(edition);
        assert!(decode(&serde_json::to_vec(&value).unwrap()).is_err());
    }
    value["schema_version"] = serde_json::json!(5);
    value["runtime"]["schema_version"] = serde_json::json!(6);
    let error = decode(&serde_json::to_vec(&value).unwrap())
        .err()
        .unwrap()
        .to_string();
    assert!(error.contains("condition runtime six"));
}
