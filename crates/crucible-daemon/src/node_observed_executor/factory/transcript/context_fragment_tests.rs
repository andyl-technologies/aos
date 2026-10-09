//! Original context byte and bounded fragment closure counterexamples.

#![allow(clippy::unwrap_used)] // A failed fixture invariant deliberately panics.

use super::*;

fn source() -> InputPayload {
    let bytes = (0..100_007)
        .map(|index| ((index * 13) % 251) as u8)
        .collect::<Vec<_>>();
    InputPayload {
        reference: canonical::content_ref(&bytes, "application/json").unwrap(),
        bytes,
    }
}

fn manifest(objects: &[InputPayload]) -> InputPayload {
    objects
        .iter()
        .find(|object| object.reference.media_type == FRAGMENT_MEDIA_TYPE)
        .unwrap()
        .clone()
}

fn changed_manifest(
    original: &InputPayload,
    change: impl FnOnce(&mut serde_json::Value),
) -> InputPayload {
    let mut value: serde_json::Value = serde_json::from_slice(&original.bytes).unwrap();
    change(&mut value);
    let bytes = canonical::canonical_json(&value).unwrap();
    InputPayload {
        reference: canonical::content_ref(&bytes, FRAGMENT_MEDIA_TYPE).unwrap(),
        bytes,
    }
}

#[test]
fn oversized_original_context_roundtrips_every_raw_byte_and_content_identity() {
    let original = source();
    let objects = fragment_source_object(original.clone()).unwrap();
    assert!(
        objects
            .iter()
            .all(|object| object.bytes.len() <= CHUNK_BYTES)
    );
    let rebuilt =
        reconstruct_source_object(&manifest(&objects), &objects, original.bytes.len()).unwrap();
    assert_eq!(rebuilt, original);
}

#[test]
fn missing_reordered_or_changed_original_fragment_refuses() {
    let objects = fragment_source_object(source()).unwrap();
    let source_manifest = manifest(&objects);
    let missing = objects.iter().skip(1).cloned().collect::<Vec<_>>();
    assert!(reconstruct_source_object(&source_manifest, &missing, MAXIMUM_SOURCE_BYTES).is_err());
    let reordered = changed_manifest(&source_manifest, |value| {
        value["chunks"].as_array_mut().unwrap().swap(0, 1)
    });
    assert!(reconstruct_source_object(&reordered, &objects, MAXIMUM_SOURCE_BYTES).is_err());
    let mut changed = objects.clone();
    changed[0].bytes[0] ^= 1;
    assert!(reconstruct_source_object(&source_manifest, &changed, MAXIMUM_SOURCE_BYTES).is_err());
}

#[test]
fn unknown_edition_or_decoded_extent_over_credit_refuses() {
    let objects = fragment_source_object(source()).unwrap();
    let source_manifest = manifest(&objects);
    let unknown = changed_manifest(&source_manifest, |value| {
        value["schema_version"] = serde_json::json!(2)
    });
    assert!(reconstruct_source_object(&unknown, &objects, MAXIMUM_SOURCE_BYTES).is_err());
    assert!(reconstruct_source_object(&source_manifest, &objects, 100_006).is_err());
    let excessive = changed_manifest(&source_manifest, |value| {
        value["original"]["length"] =
            serde_json::json!((MAXIMUM_SOURCE_BYTES as u64 + 1).to_string())
    });
    assert!(reconstruct_source_object(&excessive, &[], MAXIMUM_SOURCE_BYTES).is_err());
}

#[test]
fn valid_original_chunk_bytes_under_another_media_role_refuse() {
    let mut objects = fragment_source_object(source()).unwrap();
    let original_manifest = manifest(&objects);
    objects[0].reference.media_type = "application/json".into();
    objects[0].reference.verify(&objects[0].bytes).unwrap();
    let changed = changed_manifest(&original_manifest, |value| {
        value["chunks"][0]["content"]["media_type"] = serde_json::json!("application/json");
    });
    assert!(reconstruct_source_object(&changed, &objects, MAXIMUM_SOURCE_BYTES).is_err());
}

#[test]
fn invalid_original_typed_reference_refuses_before_reassembly() {
    let objects = fragment_source_object(source()).unwrap();
    let changed = changed_manifest(&manifest(&objects), |value| {
        value["original"]["hash"]["digest"] = serde_json::json!("non-canonical-digest");
    });
    assert!(reconstruct_source_object(&changed, &objects, MAXIMUM_SOURCE_BYTES).is_err());
}
