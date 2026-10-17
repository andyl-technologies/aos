//! Checks complete borrowed ancestry byte preservation without native authority.

// crucible-lint: allow panic-shortcut -- Assertion failure is the data-control verdict.
#![allow(clippy::unwrap_used)]

use super::*;
use crate::node_adapters::cnp::semantic::semantic_snapshot::{
    CnpSemanticSnapshotReservation, authenticate_component, record_component, take_component,
};

fn claim() -> OriginalPublicationClaim {
    let payload = InputPayload {
        reference: canonical::content_ref(&[0, 255, 17, 128], "application/octet-stream").unwrap(),
        bytes: vec![0, 255, 17, 128],
    };
    let proof = canonical::content_ref(b"native-proof", "application/octet-stream").unwrap();
    let hash = canonical::json_hash("original-ancestry-test", &"same original").unwrap();
    let endpoint = Endpoint {
        node_id: Id::new("source").unwrap(),
        port_id: Id::new("packet").unwrap(),
        lane_id: Id::new("lane").unwrap(),
    };
    let position = Position::new(U64::new(6), U64::new(1), Phase::Publication);
    OriginalPublicationClaim {
        event: Event {
            schema_version: 1,
            id: Id::new("packet-original").unwrap(),
            source: endpoint.clone(),
            destination: endpoint,
            position,
            stage: EventStage::Publication,
            publication_position: position,
            delivery_position: None,
            source_sequence: U64::new(3),
            causal_parent_ids: vec![Id::new("prior-input").unwrap()],
            payload: payload.reference.clone(),
            provenance_ref: proof.clone(),
            extensions: Extensions::new(),
        },
        origin: OriginalPublicationOrigin {
            owner_binding_hash: hash.clone(),
            execution_owner_id: Id::new("original-owner").unwrap(),
            session_id: Id::new("original-session").unwrap(),
            world_binding_hash: hash,
            activation_id: Id::new("original-activation").unwrap(),
            world_generation: U64::new(9),
            incarnation_id: Id::new("original-incarnation").unwrap(),
            owner_generation: U64::new(7),
            operation_id: Id::new("original-operation").unwrap(),
            grant_id: Id::new("original-operation").unwrap(),
            observation_batch: proof.clone(),
            stop_receipt: proof.clone(),
            measurement: proof,
        },
        published: payload.reference.clone(),
        rows: vec![OriginalLineageRow {
            object: payload.reference.clone(),
            dependencies: vec![],
        }],
        objects: vec![payload],
    }
}

#[test]
fn ancestry_preserves_non_json_octets_and_distinct_ordered_source_occurrences() {
    let first = claim();
    let mut second = first.clone();
    second.origin.session_id = Id::new("different-original-session").unwrap();
    let claims = [first, second];
    let mut bank = Some(CnpSemanticSnapshotReservation::reserve(65_536, 65_536).unwrap());
    let capacity = bank.as_ref().unwrap().allocated_bytes();
    record_component(&mut bank, &Publications(&claims)).unwrap();
    let original = take_component(&mut bank, "application/json").unwrap();

    assert!(bank.is_none());
    assert_eq!(original.bytes.capacity(), capacity);
    original.reference.verify(&original.bytes).unwrap();
    let data: serde_json::Value = serde_json::from_slice(&original.bytes).unwrap();
    assert_eq!(
        data[0]["objects"][0]["bytes"],
        serde_json::json!([0, 255, 17, 128])
    );
    assert_eq!(data[0]["origin"]["session_id"], "original-session");
    assert_eq!(
        data[1]["origin"]["session_id"],
        "different-original-session"
    );
    authenticate_component(&original, &Publications(&claims)).unwrap();
}

#[test]
fn ancestry_recheck_refuses_changed_scope_or_rows_even_with_unchanged_payload_ref() {
    let mut claims = [claim()];
    let mut bank = Some(CnpSemanticSnapshotReservation::reserve(65_536, 65_536).unwrap());
    record_component(&mut bank, &Publications(&claims)).unwrap();
    let original = take_component(&mut bank, "application/json").unwrap();
    let payload = claims[0].event.payload.clone();

    claims[0].origin.owner_generation = U64::new(8);
    assert!(authenticate_component(&original, &Publications(&claims)).is_err());
    claims[0].origin.owner_generation = U64::new(7);
    claims[0].rows[0].dependencies.push(payload.clone());
    assert!(authenticate_component(&original, &Publications(&claims)).is_err());
    assert_eq!(claims[0].event.payload, payload);
    original.reference.verify(&original.bytes).unwrap();
}
