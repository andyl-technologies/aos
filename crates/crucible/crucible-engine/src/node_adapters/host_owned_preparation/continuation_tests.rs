//! Data-only controls for the selected finite-model preservation grammar.
//!
//! These checks exercise the production decoder and model association. They
//! neither construct an authenticated archive source nor qualify restoration.

#![cfg(test)]
// crucible-lint: allow panic-shortcut -- Closed grammar and identity mismatches must fail these data-only assertions.
#![allow(clippy::unwrap_used)]

use super::*;

fn envelope() -> Wire {
    let reference = canonical::content_ref(b"original", "application/json").unwrap();
    Wire {
        format: "crucible.host.public-owned-model-continuation".into(),
        schema_version: 9,
        node: Id::new("original/block").unwrap(),
        native_state: reference.clone(),
        world_preparation: reference.clone(),
        session: reference.clone(),
        ready: reference.clone(),
        native_ready: reference.clone(),
        original_model: reference,
        previous: None,
    }
}

#[test]
fn selected_envelope_requires_explicit_nullable_predecessor_and_closed_fields() {
    let original = envelope();
    let mut value = serde_json::to_value(&original).unwrap();
    let bytes = canonical::canonical_json(&value).unwrap();
    let decoded: Wire = decode(&bytes, bytes.len()).unwrap();
    validate_wire_scope(&decoded, &original.node).unwrap();
    assert!(decoded.previous.is_none());

    value.as_object_mut().unwrap().remove("previous");
    assert!(decode::<Wire>(&canonical::canonical_json(&value).unwrap(), 4096).is_err());
    value["previous"] = serde_json::Value::Null;
    value["foreign_body"] = serde_json::Value::Null;
    assert!(decode::<Wire>(&canonical::canonical_json(&value).unwrap(), 4096).is_err());
    assert!(decode::<Wire>(&[bytes.as_slice(), b"{}"].concat(), 4096).is_err());
    assert!(decode::<Wire>(&bytes, bytes.len() - 1).is_err());
}

#[test]
fn selected_envelope_refuses_other_host_editions_and_foreign_node() {
    let mut original = envelope();
    let node = original.node.clone();
    for edition in [0, 1, 2, 3, 4, 5, 6, 7, 8, 10] {
        original.schema_version = edition;
        assert!(validate_wire_scope(&original, &node).is_err());
    }
    original.schema_version = 9;
    assert!(validate_wire_scope(&original, &Id::new("foreign/block").unwrap()).is_err());
    original.format = "crucible.host.public-clock-continuation".into();
    assert!(validate_wire_scope(&original, &node).is_err());
}

#[test]
fn predecessor_model_association_reopens_exact_native_body_and_legacy_grammar() {
    let mut value = serde_json::json!({
        "schema_version":1, "profile":HOST_EXACT_PROFILE,
        "boundary":Position::new(0.into(),0.into(),Phase::BoundaryControl),
        "native":[17,34], "native_sequence":"0", "staged":null,
        "input_history":[], "pending_causes":[], "operations":[],
    });
    let bytes = serde_json::to_vec(&value).unwrap();
    let original = state::public_owned_native_model_reference(&bytes, bytes.len()).unwrap();
    original.verify(&[17, 34]).unwrap();

    value["native"] = serde_json::json!([17, 35]);
    let changed = serde_json::to_vec(&value).unwrap();
    assert_ne!(
        original,
        state::public_owned_native_model_reference(&changed, changed.len()).unwrap()
    );
    assert!(state::public_owned_native_model_reference(&bytes, bytes.len() - 1).is_err());
    value["schema_version"] = serde_json::json!(9);
    assert!(
        state::public_owned_native_model_reference(&serde_json::to_vec(&value).unwrap(), 4096)
            .is_err()
    );
    value["schema_version"] = serde_json::json!(1);
    value["foreign"] = serde_json::Value::Null;
    assert!(
        state::public_owned_native_model_reference(&serde_json::to_vec(&value).unwrap(), 4096)
            .is_err()
    );
}

#[test]
fn combined_retention_refuses_when_independent_native_and_ancestry_budgets_fit() {
    let maximum = 110;
    let native = 45;
    let ancestry = 45;
    let outer = 5;
    let target = 6;
    assert!(native + outer + target <= maximum);
    assert!(ancestry + outer + target <= maximum);

    assert!(precredit_retention(outer, target, [Ok(native), Ok(ancestry)], maximum).is_err());
    assert_eq!(
        precredit_retention(outer, target, [Ok(native), Ok(ancestry)], 146).unwrap(),
        146
    );
    assert!(precredit_retention(usize::MAX, target, [], usize::MAX).is_err());
}

#[test]
fn native_model_duplicate_association_consumes_credit_before_copying() {
    let outer = 5;
    let target = 6;
    let native_model = 45;
    let ancestry = 45;
    let distinct_closure = outer + target + native_model + ancestry;
    assert_eq!(distinct_closure, 101);

    assert!(
        precredit_retention(
            outer,
            target,
            [Ok(native_model), Ok(ancestry)],
            distinct_closure
        )
        .is_err()
    );
    assert_eq!(
        precredit_retention(outer, target, [Ok(native_model), Ok(ancestry)], 146).unwrap(),
        146
    );
}
