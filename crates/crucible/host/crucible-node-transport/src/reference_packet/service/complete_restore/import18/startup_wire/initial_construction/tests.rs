//! Checks shared constructor arithmetic against independently decoded owners.

use super::*;
use crate::reference_packet::service::complete_restore::import18::inert_bootstrap_fixtures;
use serde_json::json;

fn bodies(reactive: bool, decimal: u64) -> [Vec<u8>; 3] {
    let recipe = inert_bootstrap_fixtures::recipe();
    let mut selected = inert_bootstrap_fixtures::selected_launch(reactive);
    let launch: PacketNativeImport18SelectedLaunchWireData =
        serde_json::from_value(selected.clone()).unwrap();
    let source = inert_bootstrap_fixtures::source_birth(launch.launch_data());
    let mut boot = inert_bootstrap_fixtures::boot(1, json!({"actual": [1, "host"]}));
    boot["source_birth"]["declaration"]["source_birth"] =
        json!(Bytes::new(canonical::canonical_json(&source).unwrap()));
    boot["source_birth"]["declaration"]["fresh_restore_allocation_selection"] = json!(null);
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
    [recipe, selected, boot]
        .each_ref()
        .map(|body| canonical::canonical_json(body).unwrap())
}

fn decoded(raw: &[Vec<u8>; 3]) -> OriginalImport18DecodedBodies {
    let mut slots = OriginalImport18DecodedBodies::empty();
    slots
        .construction_data(raw.each_ref().map(Vec::as_slice), usize::MAX / 4)
        .unwrap();
    slots.decode_recipe(&raw[0]).unwrap();
    slots.decode_launch(&raw[1]).unwrap();
    slots.decode_boot(&raw[2]).unwrap();
    slots
}

#[test]
fn reconstructed_initial_uses_no_announced_row_and_covers_actual_overlapping_owners() {
    for reactive in [false, true] {
        let mut prior = None;
        for decimal in [1, u64::MAX] {
            let raw = bodies(reactive, decimal);
            let mut slots = decoded(&raw);
            let parsers = slots
                .construction_data(raw.each_ref().map(Vec::as_slice), usize::MAX / 4)
                .unwrap();
            let typed = slots.bodies_data().unwrap();
            let actual = initial_construction_from_wire_data(
                typed.recipe,
                typed.launch,
                typed.boot,
                usize::MAX / 4,
            )
            .unwrap();
            let source = source_authentication_construction_data(
                typed.boot.source_binding_data().declaration_data(),
                typed.launch.launch_data(),
                usize::MAX / 4,
            )
            .unwrap();
            let physical =
                original_import18_raw_bootstrap_storage_data(raw.each_ref().map(Vec::len)).unwrap();
            let actual_retained =
                physical[0] + parsers.iter().map(|row| row[0]).sum::<usize>() + source[0];
            let parser_t = parsers.iter().map(|row| row[1]).max().unwrap();
            let parser_s = parsers.iter().map(|row| row[2]).max().unwrap();

            assert!(actual.row[0] >= actual_retained);
            assert!(actual.row[1] >= physical[1].max(parser_t).max(source[1]));
            assert!(actual.row[2] >= physical[2] + parser_s + source[2]);
            for (bank, maximum) in raw.iter().zip(actual.maximum_encoded_bytes) {
                assert!(bank.len() <= maximum);
            }
            typed
                .boot
                .source_binding_data()
                .declaration_data()
                .authenticate_launch_data(typed.launch.launch_data())
                .unwrap();
            let quote = initial_quote_formatter_data(typed.launch.launch_data()).unwrap();
            assert!(actual.row[1] >= quote[1]);
            assert!(actual.row[2] >= quote[2]);
            let exact = actual.row.iter().sum();
            assert_eq!(
                initial_construction_from_wire_data(typed.recipe, typed.launch, typed.boot, exact)
                    .unwrap()
                    .row,
                actual.row
            );
            assert!(
                initial_construction_from_wire_data(
                    typed.recipe,
                    typed.launch,
                    typed.boot,
                    exact - 1
                )
                .is_err()
            );
            if let Some((row, maximum)) = prior {
                assert_eq!(actual.row, row);
                assert_eq!(actual.maximum_encoded_bytes, maximum);
            }
            prior = Some((actual.row, actual.maximum_encoded_bytes));
        }
    }
}

#[test]
fn complete_initial_population_and_policy_refuse_overflow() {
    let bodies = || ProspectiveBodyConstructionData {
        maximum_encoded_bytes: [1; 3],
        parser_rows: [[1; 3]; 3],
    };
    assert!(combine(bodies(), [usize::MAX, 1, 1], [0; 3], usize::MAX).is_err());
    assert!(combine(bodies(), [1, 1, usize::MAX], [0; 3], usize::MAX).is_err());
    assert!(combine(bodies(), [1; 3], [0; 3], 1).is_err());
}
