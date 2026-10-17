//! Portable condition-body codec checks; these create no live stop authority.

// crucible-lint: allow panic-shortcut -- These codec tests deliberately panic on invalid fixtures or changed original dependency bytes.
#![allow(clippy::unwrap_used, clippy::expect_used)]

use super::*;
use crucible_node_contract::{Phase, canonical};

#[test]
fn condition_inventory_index_cannot_recreate_large_original_body_or_authority() {
    let bytes = vec![73; 65_537];
    let reference = canonical::content_ref(&bytes, "application/octet-stream").unwrap();
    let inventory = NativeConditionStopInventory {
        node: Id::new("original-node").unwrap(),
        owners: vec![OwnerIdentity {
            owner: Id::new("original-owner").unwrap(),
            incarnation: Id::new("original-incarnation").unwrap(),
            generation: 1.into(),
        }],
        boundary: Position::new(513_010.into(), 3.into(), Phase::BoundaryControl),
        proof_objects: Vec::new(),
        receipt: InputPayload {
            reference: reference.clone(),
            bytes: bytes.clone(),
        },
    };

    let value = serde_json::to_value(&inventory).unwrap();
    assert!(value["receipt"].get("bytes").is_none());
    let encoded = canonical::canonical_json(&value).unwrap();
    let restored: NativeConditionStopInventory = serde_json::from_slice(&encoded).unwrap();

    assert!(encoded.len() < 2048);
    assert!(restored.receipt.bytes.is_empty());
    assert!(restored.proof_objects.is_empty());
    assert_eq!(restored.receipt.reference, reference);
    assert!(
        restored
            .receipt
            .reference
            .verify(&restored.receipt.bytes)
            .is_err()
    );
    inventory
        .receipt
        .reference
        .verify(&inventory.receipt.bytes)
        .unwrap();
}

#[test]
fn condition_body_refuses_extra_fields_without_issuing_a_permit() {
    let object = InputPayload {
        reference: canonical::content_ref(b"original", "application/octet-stream").unwrap(),
        bytes: b"original".to_vec(),
    };
    let inventory = NativeConditionEventFrontier {
        node: Id::new("original-node").unwrap(),
        owners: Vec::new(),
        boundary: Position::new(0.into(), 0.into(), Phase::BoundaryControl),
        next: None,
        receipt: object,
    };
    let mut value = serde_json::to_value(inventory).unwrap();
    value["receipt"]["ready"] = serde_json::Value::Bool(true);

    assert!(serde_json::from_value::<NativeConditionEventFrontier>(value).is_err());
}
