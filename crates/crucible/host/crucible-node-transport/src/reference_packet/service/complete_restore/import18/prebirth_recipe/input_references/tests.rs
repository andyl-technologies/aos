//! Verifies full-reference framing and role correspondence without opaque recipes.

use super::super::super::inert_bootstrap_fixtures;
use super::*;
use serde_json::{Value, json};

fn references() -> [ContentRef; 6] {
    std::array::from_fn(|index| {
        canonical::content_ref(
            &[index as u8; 31],
            if index == 5 {
                PacketNativeImport18SemanticSpendFamily::Complete18.media_type_data()
            } else {
                "application/octet-stream"
            },
        )
        .unwrap()
    })
}

fn framed(reference: &ContentRef) -> [u8; 32] {
    let mut bytes = Vec::new();
    for value in [
        &reference.hash.algorithm,
        &reference.hash.domain,
        &reference.hash.digest,
        &reference.media_type,
    ] {
        bytes.extend_from_slice(&(value.len() as u64).to_be_bytes());
        bytes.extend_from_slice(value.as_bytes());
    }
    bytes.extend_from_slice(&reference.length.get().to_be_bytes());
    blake3::derive_key(
        "source-owned.packet-native-import-fullref-identity/18",
        &bytes,
    )
}

fn recipe(references: &[ContentRef; 6]) -> Value {
    let mut recipe = inert_bootstrap_fixtures::recipe();
    recipe["archived_reference_identities"] =
        json!(references[..5].iter().map(framed).collect::<Vec<_>>());
    recipe["archived_lengths"] = json!((["31"; 5]));
    recipe["semantic_reference_identity"] = json!(framed(&references[5]));
    recipe["semantic_length"] = json!("31");
    recipe["semantic_spend_maximum"] = json!("31");
    recipe["decoder_limits"] = json!([
        "31",
        "31",
        "31",
        "31",
        "31",
        "1",
        "1",
        "1",
        "1",
        "268435456"
    ]);
    recipe["phases"] = json!(([["10485760", "167772160", "4194304"]; 5]));
    recipe["escrow"] = json!(["52428800", "167772160", "4194304"]);
    recipe
}

fn authenticate(recipe: &Value, references: &[ContentRef; 6]) -> Result<(), ProviderError> {
    let wire: PacketNativeImport18PrebirthRecipeWireData =
        serde_json::from_value(recipe.clone()).unwrap();
    let [snapshot, after, control, anchor, journal, semantic] = references.each_ref();
    wire.authenticate_input_references_data([snapshot, after, control, anchor, journal], semantic)
}

#[test]
fn full_reference_identity_matches_independent_framing_and_distinguishes_media_and_length() {
    let original = references();
    for reference in &original {
        assert_eq!(
            native_import18_reference_identity_data(reference).unwrap(),
            framed(reference)
        );
        for field in 0..5 {
            let mut changed = reference.clone();
            match field {
                0 => changed.hash.algorithm = "sha256".to_owned(),
                1 => changed.hash.domain = "cnp.blob.v0".to_owned(),
                2 => changed.hash.digest = "a".repeat(64),
                3 => changed.media_type.push_str(";changed"),
                4 => changed.length = U64::new(32),
                _ => unreachable!(),
            }
            assert_ne!(
                native_import18_reference_identity_data(&changed).ok(),
                Some(framed(reference))
            );
        }
    }
}

#[test]
fn every_full_reference_and_equal_length_role_swap_is_independently_bound() {
    let original = references();
    let recipe = recipe(&original);
    authenticate(&recipe, &original).unwrap();

    for role in 0..6 {
        for field in 0..5 {
            let mut changed = original.clone();
            match field {
                0 => changed[role].hash.algorithm = "sha256".to_owned(),
                1 => changed[role].hash.domain = "cnp.blob.v0".to_owned(),
                2 => changed[role].hash.digest = "a".repeat(64),
                3 => changed[role].media_type.push_str(";changed"),
                4 => changed[role].length = U64::new(32),
                _ => unreachable!(),
            }
            assert!(
                authenticate(&recipe, &changed).is_err(),
                "role {role}, field {field}"
            );
        }
    }
    for left in 0..5 {
        for right in (left + 1)..5 {
            let mut changed = original.clone();
            changed.swap(left, right);
            assert!(
                authenticate(&recipe, &changed).is_err(),
                "roles {left}/{right}"
            );
        }
    }
    let mut changed = recipe.clone();
    changed["semantic_spend_family"] = json!("legacy17");
    assert!(authenticate(&changed, &original).is_err());
}
