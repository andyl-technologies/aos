//! Exercises real inert body decoders without creating opaque Initial or Recipe.

use super::*;
use crate::reference_packet::service::complete_restore::import18::inert_bootstrap_fixtures::{
    boot, recipe, selected_launch,
};
use crate::retained_metadata::{MetadataObserver, requested_metadata_backing_storage_data};
use serde_json::json;

fn quote_boot(raw: &[u8], maximum: usize) -> Result<[usize; 3], ProviderError> {
    body(
        raw,
        private_body_typed_geometry_data()[2],
        private_body_typed_partials_data()[2],
        maximum,
    )
}

#[test]
fn selected9_quote_covers_actual_producer_and_reactive_launch_backing() {
    for reactive in [false, true] {
        let wire = selected_launch(reactive);
        let raw = canonical::canonical_json(&wire).unwrap();
        let row = body(
            &raw,
            private_body_typed_geometry_data()[1],
            private_body_typed_partials_data()[1],
            usize::MAX / 4,
        )
        .unwrap();
        let strict = canonical::parse_json(&raw, raw.len()).unwrap();
        let parsed: PacketNativeImport18SelectedLaunchWireData =
            serde_json::from_value(strict).unwrap();
        let actual =
            crate::retained_metadata::observe_retained_native_launch(&parsed.launch).unwrap();
        assert!(row[0] >= requested_metadata_backing_storage_data(&actual).unwrap());

        let recipe_raw = canonical::canonical_json(&recipe()).unwrap();
        let boot_raw = canonical::canonical_json(&boot(32, json!({}))).unwrap();
        let all = private_body_decode_backing_data([&recipe_raw, &raw, &boot_raw], usize::MAX / 4)
            .unwrap();
        assert_eq!(all[1], row);
        assert!(!private_body_typed_geometry_data()[0].has_heap_fields);
    }
}

#[test]
fn boot_decode_quote_covers_actual_backing_and_refuses_one_short_complete_work() {
    for length in [0, 1, 2, 3, 4, 31, 32, 33, 2049] {
        let wire = boot(length, json!({"dense": [[], {}, [1, 2, 3]], "text": "𝄞"}));
        let raw = canonical::canonical_json(&wire).unwrap();
        let row = quote_boot(&raw, usize::MAX / 4).unwrap();
        let strict = canonical::parse_json(&raw, raw.len()).unwrap();
        let parsed: PacketNativeImport18PrivateBootWireData =
            serde_json::from_value(strict).unwrap();

        let mut observer = MetadataObserver::new();
        observer.observe(&parsed.private_key).unwrap();
        observer.observe(&parsed.birth_id).unwrap();
        observer
            .observe(parsed.source_birth.declaration.source_birth_data())
            .unwrap();
        observer
            .observe(&parsed.expected_host_registration)
            .unwrap();
        observer.observe(&parsed.private_launch).unwrap();
        observer.observe(&parsed.host_executable).unwrap();
        let actual = requested_metadata_backing_storage_data(&observer.finish()).unwrap();
        assert!(row[0] >= actual);
        assert_eq!(
            parsed
                .source_birth
                .declaration
                .source_birth_data()
                .as_slice(),
            vec![255; length]
        );

        let peak = sum(&row).unwrap();
        assert_eq!(quote_boot(&raw, peak).unwrap(), row);
        assert!(quote_boot(&raw, peak - 1).is_err());
    }
}

#[test]
fn malformed_typed_prefixes_receive_error_storage_without_a_producer_recipe() {
    let original = boot(32, json!({"registration": []}));
    let mut bad_key = original.clone();
    bad_key["private_key"] = json!("!");
    let mut bad_birth = original.clone();
    bad_birth["birth_id"] = json!("AB");
    let mut missing_fresh = original.clone();
    missing_fresh["source_birth"]["declaration"]
        .as_object_mut()
        .unwrap()
        .remove("fresh_restore_allocation_selection");
    let mut unknown = original;
    unknown["unrecognized"] = json!({"retained": "prefix"});

    for malformed in [bad_key, bad_birth, missing_fresh, unknown] {
        let raw = canonical::canonical_json(&malformed).unwrap();
        let row = quote_boot(&raw, usize::MAX / 4).unwrap();
        let strict = canonical::parse_json(&raw, raw.len()).unwrap();
        let error = match serde_json::from_value::<PacketNativeImport18PrivateBootWireData>(strict)
        {
            Ok(_) => panic!("malformed private DATA parsed"),
            Err(error) => error,
        };
        assert!(row[0] >= error.to_string().len());
        assert!(row[1] >= error.to_string().len());
    }
}

#[test]
fn rawvalue_reset_quote_accounts_for_the_actual_owned_value_adapter() {
    let literal =
        json!({"$serde_json::private::RawValue": "{\"expanded\":[1,2,{\"v\":\"text\"}]}"});
    let wire = boot(32, literal.clone());
    let raw = canonical::canonical_json(&wire).unwrap();
    let row = quote_boot(&raw, usize::MAX / 4).unwrap();
    let extra = raw_value_reparse::quote_raw_json_data(&raw, usize::MAX / 4).unwrap();
    assert_eq!(extra.detected_strings_data(), 1);
    let strict = canonical::parse_json(&raw, raw.len()).unwrap();
    let parsed: PacketNativeImport18PrivateBootWireData = serde_json::from_value(strict).unwrap();
    let expected: Value = serde_json::from_value(literal).unwrap();
    assert_eq!(parsed.expected_host_registration, expected);
    let mut observer = MetadataObserver::new();
    observer
        .observe(&parsed.expected_host_registration)
        .unwrap();
    assert!(row[0] >= requested_metadata_backing_storage_data(&observer.finish()).unwrap());

    assert!(private_body_decode_backing_data([&raw; 3], 1).is_err());
    assert!(private_body_decode_backing_data([&raw; 3], usize::MAX / 4).is_ok());
}
