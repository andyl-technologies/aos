//! Compares prospective geometry with independent actual closed wire constructors.
//!
//! Fixtures construct inert wire DATA only, never an opaque Initial or Recipe.

use super::*;
use crate::reference_packet::service::complete_restore::import18::inert_bootstrap_fixtures;
use serde_json::json;

#[test]
fn prospective_actual_fields_cover_each_native_parser_axis_and_future_decimal_width() {
    for reactive in [false, true] {
        for length in [1, 2, 3, 32, 2049] {
            for decimal in [1u64, u64::MAX] {
                let mut selected = inert_bootstrap_fixtures::selected_launch(reactive);
                selected["launch"]["fresh_restore_allocation_selection"] =
                    json!("completed_admit13");
                let registration = json!({"nested": [{"$serde_json::private::RawValue": "[0]"}]});
                let mut boot = inert_bootstrap_fixtures::boot(length, registration.clone());
                let mut recipe = inert_bootstrap_fixtures::recipe();
                // These remain unvalidated announcements. Choosing a decimal
                // width exercises geometry, never a producer recipe factory.
                recipe["generation"] = json!(decimal.to_string());
                for row in [
                    &mut selected["initial_funding"],
                    &mut boot["source_birth"]["initial_funding"],
                ] {
                    *row = json!({
                        "retained_requested_bytes": decimal.to_string(),
                        "maximum_simultaneous_transient_bytes": decimal.to_string(),
                        "declared_counter_scratch_bytes": decimal.to_string(),
                    });
                }
                boot["source_birth"]["prebirth_recipe"] = recipe.clone();
                let parsed_recipe: PacketNativeImport18PrebirthRecipeWireData =
                    serde_json::from_value(recipe.clone()).unwrap();
                let parsed_selected: PacketNativeImport18SelectedLaunchWireData =
                    serde_json::from_value(selected.clone()).unwrap();
                let key = Bytes::new(vec![23; 32]);
                let birth = Bytes::new(vec![17; 32]);
                let source = vec![255; length];
                let selected_launch = &parsed_selected.launch;
                let declaration =
                    native_import18_source_declaration_bank_view_data(&source, selected_launch)
                        .unwrap();
                let private_launch = Id::new("private.data").unwrap();
                let executable =
                    canonical::content_ref(b"inert", "application/octet-stream").unwrap();
                let operands = PrivateOperands {
                    declaration,
                    private_key: &key,
                    birth_id: &birth,
                    expected_host_registration: &registration,
                    private_launch: &private_launch,
                    host_executable: &executable,
                };
                let quote = quote(
                    &parsed_recipe,
                    &[0; 32],
                    selected_launch,
                    &operands,
                    usize::MAX / 4,
                )
                .unwrap();
                let banks = [&recipe, &selected, &boot]
                    .map(|value| canonical::canonical_json(value).unwrap());
                let actual = private_body_decode_backing_data(
                    banks.each_ref().map(Vec::as_slice),
                    usize::MAX / 4,
                )
                .unwrap();
                let mut slots = OriginalImport18DecodedBodies::empty();
                let owned = slots
                    .construction_data(banks.each_ref().map(Vec::as_slice), usize::MAX / 4)
                    .unwrap();
                for index in 0..3 {
                    assert!(banks[index].len() <= quote.maximum_encoded_bytes[index]);
                    for axis in 0..3 {
                        assert!(
                            actual[index][axis] <= quote.parser_rows[index][axis],
                            "body={index}, axis={axis}"
                        );
                        assert!(
                            owned[index][axis] <= quote.parser_rows[index][axis],
                            "owned body={index}, axis={axis}"
                        );
                    }
                }
            }
        }
    }
}

#[test]
fn invalid_actual_private_widths_and_small_complete_restrictions_refuse() {
    let selected: PacketNativeImport18SelectedLaunchWireData =
        serde_json::from_value(inert_bootstrap_fixtures::selected_launch(false)).unwrap();
    let recipe: PacketNativeImport18PrebirthRecipeWireData =
        serde_json::from_value(inert_bootstrap_fixtures::recipe()).unwrap();
    let source = [255; 32];
    let short_key = Bytes::new(vec![23; 31]);
    let key = Bytes::new(vec![23; 32]);
    let birth = Bytes::new(vec![17; 32]);
    let registration = json!({});
    let private_launch = Id::new("private.data").unwrap();
    let executable = canonical::content_ref(b"inert", "application/octet-stream").unwrap();
    let mut operands = PrivateOperands {
        declaration: native_import18_source_declaration_bank_view_data(&source, &selected.launch)
            .unwrap(),
        private_key: &short_key,
        birth_id: &birth,
        expected_host_registration: &registration,
        private_launch: &private_launch,
        host_executable: &executable,
    };
    assert!(
        quote(
            &recipe,
            &[0; 32],
            &selected.launch,
            &operands,
            usize::MAX / 4
        )
        .is_err()
    );
    operands.private_key = &key;
    assert!(quote(&recipe, &[0; 32], &selected.launch, &operands, 1).is_err());
}
