//! Checks full record18 definition identity and independent factory restrictions.

use super::*;
use serde_json::json;

#[test]
fn canonical_definition_authenticates_its_complete_body() {
    let body = native_import18_restored_record_contract_data().unwrap();
    let schema = native_import18_restored_record_schema_data().unwrap();

    schema.definition.verify(&body).unwrap();
    authenticate_native_import18_restored_record_schema_data(&schema).unwrap();
    let parsed = canonical::parse_json(&body, body.len()).unwrap();
    assert_eq!(canonical::canonical_json(&parsed).unwrap(), body);
    assert_ne!(schema, native_import18_schema_data().unwrap());
    assert_ne!(schema, native_import18_stage_schema_data().unwrap());
}

#[test]
fn full_reference_refuses_independently_changed_coordinates() {
    let schema = native_import18_restored_record_schema_data().unwrap();
    let original = serde_json::to_value(&schema).unwrap();
    let mut mutations = Vec::new();
    for (path, replacement) in [
        (vec!["id"], json!("source-owned.packet-restored-native/17")),
        (vec!["version"], json!(17)),
        (vec!["definition", "length"], json!("1")),
        (vec!["definition", "media_type"], json!("application/cbor")),
        (vec!["definition", "hash", "domain"], json!("other.domain")),
        (
            vec!["definition", "hash", "algorithm"],
            json!("other-algorithm"),
        ),
        (vec!["definition", "hash", "digest"], json!("a".repeat(64))),
        (vec!["extensions"], json!({"cnp.test/1": {"changed": true}})),
    ] {
        let mut changed = original.clone();
        let mut field = &mut changed;
        for key in path {
            field = &mut field[key];
        }
        *field = replacement;
        mutations.push(serde_json::from_value::<SchemaRef>(changed).unwrap());
    }
    for changed in mutations {
        assert!(authenticate_native_import18_restored_record_schema_data(&changed).is_err());
    }

    // A well-formed replacement body under the same ID/version must refuse too.
    let mut substituted = schema;
    substituted.definition = canonical::content_ref(b"{}", "application/json").unwrap();
    substituted.validate().unwrap();
    assert!(authenticate_native_import18_restored_record_schema_data(&substituted).is_err());
}

#[test]
fn old_record_editions_cannot_select_the_new_complete_definition() {
    let original = native_import18_restored_record_schema_data().unwrap();
    for edition in [5, 12, 13, 17] {
        let mut old = original.clone();
        old.id = Id::new(format!("source-owned.packet-restored-native/{edition}")).unwrap();
        old.version = edition;
        old.validate().unwrap();

        assert!(authenticate_native_import18_restored_record_schema_data(&old).is_err());
    }
}

#[test]
fn factory_and_enclosing_selection_require_their_complete_independent_rows() {
    let (temporary, scratch) =
        native_import18_restored_record_contract_storage_data(usize::MAX).unwrap();
    let peak = temporary.checked_add(scratch).unwrap();
    assert!(temporary > CONTRACT.len());
    assert!(scratch > native_import18_restored_record_contract_counter_scratch_data());
    assert_eq!(
        native_import18_restored_record_contract_storage_data(peak).unwrap(),
        (temporary, scratch)
    );
    assert!(native_import18_restored_record_contract_storage_data(peak - 1).is_err());

    let selection = native_import18_selection_construction_storage_data(usize::MAX).unwrap();
    assert!(selection.0 >= temporary);
    assert!(selection.1 > scratch);
    let selection_peak = selection.0.checked_add(selection.1).unwrap();
    assert_eq!(
        native_import18_selection_construction_storage_data(selection_peak).unwrap(),
        selection
    );
    assert!(native_import18_selection_construction_storage_data(selection_peak - 1).is_err());
}
