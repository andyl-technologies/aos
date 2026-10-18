//! Checks proof DATA grammar and identity correspondence without issuing grants.

use super::*;
use crucible_node_contract::{Phase, Tick, canonical};
use serde_json::json;

fn proof_data() -> Value {
    let reference =
        canonical::content_ref(b"actual immutable proof operand", "application/json").unwrap();
    let owner = OwnerIdentity {
        owner: Id::new("logical-owner").unwrap(),
        incarnation: Id::new("fresh-incarnation").unwrap(),
        generation: U64::new(2),
    };
    // Repeated owners are deliberately insufficient for full qualification.
    // This fixture exercises only the borrowed finite-width/closed grammar.
    let identities = [[0u8; 32], [1u8; 32], [2u8; 32]];
    json!({
        "schema":"source-owned.complete-restoration-scope/1",
        "source_artifact":reference,
        "source_runtime":reference,
        "target":["2","new-world",reference.hash,[owner,owner,owner,owner],
            Position::new(Tick::new(4),U64::new(0),Phase::Delivery)],
        "native_held_reference_identities":identities
    })
}

fn encode(value: &Value) -> Vec<u8> {
    canonical::canonical_json(value).unwrap()
}

#[test]
fn borrowed_proof_requires_exact_closed_tuple_and_fixed_rosters() {
    let value = proof_data();
    assert!(authenticate_borrowed_shape_data(&encode(&value)).is_ok());

    let mut changed = value.clone();
    changed["unchecked"] = json!(true);
    assert!(authenticate_borrowed_shape_data(&encode(&changed)).is_err());

    let mut changed = value.clone();
    changed["target"] = json!({"generation":"2"});
    assert!(authenticate_borrowed_shape_data(&encode(&changed)).is_err());

    let mut changed = value.clone();
    changed["target"][3].as_array_mut().unwrap().pop();
    assert!(authenticate_borrowed_shape_data(&encode(&changed)).is_err());

    let mut changed = value;
    changed["native_held_reference_identities"][0]
        .as_array_mut()
        .unwrap()
        .pop();
    assert!(authenticate_borrowed_shape_data(&encode(&changed)).is_err());
}

#[test]
fn identity_roster_preserves_literal_order_and_refuses_aliases_or_substitutions() {
    let references = [
        b"first Hold".as_slice(),
        b"second Hold".as_slice(),
        b"third Hold".as_slice(),
    ]
    .map(|bytes| canonical::content_ref(bytes, "application/json").unwrap());
    let actual = references
        .each_ref()
        .map(|reference| held_reference_identity_data(reference).unwrap());
    assert!(authenticate_identity_roster_data(&actual, &actual).is_ok());

    let permuted = [actual[2], actual[0], actual[1]];
    assert!(authenticate_identity_roster_data(&permuted, &actual).is_ok());
    assert!(
        authenticate_identity_roster_data(&[actual[0], actual[0], actual[2]], &actual).is_err()
    );

    for field in 0..5 {
        let mut changed = references[1].clone();
        match field {
            0 => changed.hash.algorithm.push('x'),
            1 => changed.hash.domain.push('x'),
            2 => {
                let replacement = if &changed.hash.digest[..1] == "0" {
                    "1"
                } else {
                    "0"
                };
                changed.hash.digest.replace_range(0..1, replacement);
            }
            3 => changed.media_type.push('x'),
            _ => changed.length = U64::new(changed.length.get() + 1),
        }
        let mut replaced = actual;
        replaced[1] = held_reference_identity_data(&changed).unwrap();
        assert!(authenticate_identity_roster_data(&replaced, &actual).is_err());
    }
}

#[test]
fn fixed_hash_validation_matches_full_reference_and_rejects_substitutions() {
    let body = br#"{"actual":"retained scope DATA"}"#;
    let reference =
        crucible_node_contract::canonical::content_ref(body, "application/json").unwrap();
    authenticate_body_data(&reference, body).unwrap();
    assert!(authenticate_body_data(&reference, b"different body").is_err());

    let mut changed = reference.clone();
    changed.length = U64::new(reference.length.get() + 1);
    assert!(authenticate_body_data(&changed, body).is_err());

    let mut changed = reference.clone();
    changed.hash.domain = "another.domain".into();
    assert!(authenticate_body_data(&changed, body).is_err());

    let mut changed = reference.clone();
    changed.media_type = "text/plain".into();
    assert!(authenticate_body_data(&changed, body).is_err());

    let mut changed = reference;
    changed.hash.digest.replace_range(..1, "G");
    assert!(authenticate_body_data(&changed, body).is_err());
}
