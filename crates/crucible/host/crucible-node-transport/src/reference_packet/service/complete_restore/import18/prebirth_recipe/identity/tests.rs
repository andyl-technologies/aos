//! Checks the commitment roster independently from the borrowed serializer.

use super::super::super::inert_bootstrap_fixtures;
use super::*;
use serde_json::{Value, json};

fn fixture() -> Value {
    let mut value = inert_bootstrap_fixtures::recipe();
    value["decoder_limits"][9] = json!("268435456");
    value["phases"] = json!(([["10485760", "167772160", "4194304"]; 5]));
    value["escrow"] = json!(["52428800", "167772160", "4194304"]);
    value
}

fn wire(value: &Value) -> PacketNativeImport18PrebirthRecipeWireData {
    serde_json::from_value(value.clone()).unwrap()
}

fn unsigned(mut value: Value) -> Vec<u8> {
    value.as_object_mut().unwrap().remove("identity").unwrap();
    canonical::canonical_json(&value).unwrap()
}

#[test]
fn identity_covers_exact_canonical_fields_and_excludes_only_its_own_digest() {
    let mut value = fixture();
    let encoded = unsigned(value.clone());
    let expected = blake3::derive_key(
        "source-owned.packet-native-import-prebirth-recipe-identity/18",
        &encoded,
    );
    let actual = wire(&value)
        .reconstructed_identity_data(encoded.len())
        .unwrap();

    assert_eq!(actual, expected);
    assert!(
        wire(&value)
            .reconstructed_identity_data(encoded.len() - 1)
            .is_err()
    );
    assert!(wire(&value).authenticate_identity_data(usize::MAX).is_err());

    value["identity"] = json!(actual);
    wire(&value).authenticate_identity_data(usize::MAX).unwrap();
    assert_eq!(
        wire(&value)
            .reconstructed_identity_data(usize::MAX)
            .unwrap(),
        actual
    );
    value["identity"] = json!(([255u8; 32]));
    assert_eq!(
        wire(&value)
            .reconstructed_identity_data(usize::MAX)
            .unwrap(),
        actual
    );
    assert!(wire(&value).authenticate_identity_data(usize::MAX).is_err());
}

fn change(value: &mut Value) {
    match value {
        Value::String(text) => *text = "2".to_owned(),
        Value::Number(number) => *number = 1.into(),
        Value::Array(items) => change(&mut items[0]),
        _ => panic!("unexpected closed recipe leaf"),
    }
}

#[test]
fn each_variable_operand_changes_the_commitment_without_minting_a_recipe() {
    let original = fixture();
    let expected = wire(&original)
        .reconstructed_identity_data(usize::MAX)
        .unwrap();
    let fields: Vec<_> = original.as_object().unwrap().keys().cloned().collect();
    assert_eq!(fields.len(), 24);

    for field in fields {
        // The closed schema enum has one possible value. The digest itself is
        // excluded; every remaining operand must independently change the hash.
        if matches!(field.as_str(), "schema" | "identity") {
            continue;
        }
        let mut changed = original.clone();
        match field.as_str() {
            "native_family" => changed[&field] = json!("snapshot18"),
            "source_family" => changed[&field] = json!("captured18"),
            "semantic_spend_family" => changed[&field] = json!("legacy17"),
            _ => change(&mut changed[&field]),
        }
        assert_ne!(
            wire(&changed)
                .reconstructed_identity_data(usize::MAX)
                .unwrap(),
            expected,
            "{field}"
        );
        changed["identity"] = json!(expected);
        assert!(
            wire(&changed)
                .authenticate_identity_data(usize::MAX)
                .is_err(),
            "{field}"
        );
    }
}

#[test]
fn construction_is_fixed_before_recipe_values_and_refuses_one_byte_short() {
    let (temporary, scratch) =
        native_import18_recipe_identity_construction_data(usize::MAX).unwrap();
    let peak = temporary.checked_add(scratch).unwrap();
    assert_eq!(
        native_import18_recipe_identity_construction_data(peak).unwrap(),
        (temporary, scratch)
    );
    assert!(native_import18_recipe_identity_construction_data(peak - 1).is_err());

    for value in [fixture(), inert_bootstrap_fixtures::maximum_recipe()] {
        let bytes = unsigned(value);
        assert!(bytes.len() < temporary);
    }
}
