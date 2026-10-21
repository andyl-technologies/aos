//! Checks shared constructor arithmetic against independently decoded owners.

use super::*;
use crate::reference_packet::service::complete_restore::import18::inert_bootstrap_fixtures;
use serde_json::json;

fn bodies(reactive: bool, decimal: u64) -> [Vec<u8>; 3] {
    let recipe = inert_bootstrap_fixtures::recipe();
    let mut selected = inert_bootstrap_fixtures::initial_selected_launch(reactive);
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
            let actual =
                initial_construction_from_wire_data(typed.launch, typed.boot, usize::MAX / 4)
                    .unwrap();
            // Parent construction has no Recipe or announced-row operand. Its
            // private fields remain borrowed and the Source bank stays opaque.
            let private = PrivateOperands {
                declaration: native_import18_source_declaration_bank_view_data(
                    typed
                        .boot
                        .source_birth
                        .declaration
                        .source_birth_data()
                        .as_slice(),
                    typed.launch.launch_data(),
                )
                .unwrap(),
                expected_host_registration: &typed.boot.expected_host_registration,
                private_launch: &typed.boot.private_launch,
                host_executable: &typed.boot.host_executable,
            };
            let parent = initial_construction_projection_data(
                typed.launch.launch_data(),
                &private,
                usize::MAX / 4,
            )
            .unwrap();
            assert_eq!(parent.row, actual.row);
            assert_eq!(parent.maximum_encoded_bytes, actual.maximum_encoded_bytes);
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
                initial_construction_from_wire_data(typed.launch, typed.boot, exact)
                    .unwrap()
                    .row,
                actual.row
            );
            assert!(
                initial_construction_from_wire_data(typed.launch, typed.boot, exact - 1).is_err()
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
    assert!(
        combine(
            bodies(),
            [usize::MAX, 1, 1],
            [0; 3],
            (0, 0),
            [0; 3],
            [0; 3],
            usize::MAX
        )
        .is_err()
    );
    assert!(
        combine(
            bodies(),
            [1, 1, usize::MAX],
            [0; 3],
            (0, 0),
            [0; 3],
            [0; 3],
            usize::MAX
        )
        .is_err()
    );
    assert!(combine(bodies(), [1; 3], [0; 3], (0, 0), [0; 3], [0; 3], 1).is_err());
    assert!(
        combine(
            bodies(),
            [1; 3],
            [0; 3],
            (usize::MAX, 1),
            [0; 3],
            [0; 3],
            usize::MAX
        )
        .is_err()
    );
    assert!(
        combine(
            bodies(),
            [1; 3],
            [0; 3],
            (1, usize::MAX),
            [0; 3],
            [0; 3],
            usize::MAX
        )
        .is_err()
    );
}

#[test]
fn original_typed_host_projection_matches_native_value_without_secret_operands() {
    use crucible_source_birth_data::source_birth::views::RegistrationView;

    let mut raw = bodies(false, 1);
    let originals = decoded(&raw);
    let original = originals.bodies_data().unwrap();
    let launch = original.launch.launch_data();
    let [binding] = launch.selection.realization.bindings.as_slice() else {
        panic!("the original fixture must have its sole launch binding");
    };
    let features = crucible_node_format::IdSet::default();
    let envelope_extensions = ["$serde_json::private::RawValue".to_owned()];
    let host = RegistrationView {
        schema: "source-owned.packet-canonical-ack-registration/5",
        role: "controller",
        connection_id: &original.boot.private_launch,
        session_id: &binding.authority.session_id,
        incarnation_id: &binding.authority.incarnation_id,
        limits: &launch.limits,
        features: &features,
        extensions: &[],
        envelope_extensions: &envelope_extensions,
    };
    let mut boot: Value = canonical::parse_json(&raw[2], raw[2].len()).unwrap();
    boot["expected_host_registration"] = serde_json::to_value(&host).unwrap();
    raw[2] = canonical::canonical_json(&boot).unwrap();
    let slots = decoded(&raw);
    let typed = slots.bodies_data().unwrap();
    let launch = typed.launch.launch_data();
    let declaration = native_import18_source_declaration_bank_view_data(
        typed
            .boot
            .source_birth
            .declaration
            .source_birth_data()
            .as_slice(),
        launch,
    )
    .unwrap();
    let parent = native_import18_initial_construction_data(
        launch,
        declaration,
        &host,
        &typed.boot.private_launch,
        &typed.boot.host_executable,
        usize::MAX / 4,
    )
    .unwrap();
    let native =
        initial_construction_from_wire_data(typed.launch, typed.boot, usize::MAX / 4).unwrap();
    assert_eq!(parent.requested_storage_data(), native.row);
    assert_eq!(
        parent.maximum_encoded_bytes_data(),
        native.maximum_encoded_bytes
    );

    // Received Bytes remain untrusted even though the defining parent Birth
    // fields have fixed widths. No announcement can widen that original type.
    for field in ["private_key", "birth_id"] {
        let mut changed = boot.clone();
        changed[field] = json!(Bytes::new(vec![0; 31]));
        let short: PacketNativeImport18PrivateBootWireData =
            serde_json::from_value(changed).unwrap();
        assert!(initial_construction_from_wire_data(typed.launch, &short, usize::MAX / 4).is_err());
    }
}

#[test]
fn initial_projection_requires_the_actual_closed_native_hello_selectors() {
    let raw = bodies(false, 1);
    for changed in [
        "ack_emitter_selection",
        "confirmation_selection",
        "protocol_metadata_limits",
        "missing_binding",
        "duplicate_binding",
    ] {
        let mut selected = canonical::parse_json(&raw[1], usize::MAX).unwrap();
        match changed {
            "missing_binding" => {
                selected["launch"]["selection"]["realization"]["bindings"] = json!([])
            }
            "duplicate_binding" => {
                let binding = selected["launch"]["selection"]["realization"]["bindings"][0].clone();
                selected["launch"]["selection"]["realization"]["bindings"]
                    .as_array_mut()
                    .unwrap()
                    .push(binding);
            }
            field => selected["launch"][field] = json!(null),
        }
        let mut changed = raw.clone();
        changed[1] = canonical::canonical_json(&selected).unwrap();
        let slots = decoded(&changed);
        let borrowed = slots.bodies_data().unwrap();
        assert!(
            initial_construction_from_wire_data(borrowed.launch, borrowed.boot, usize::MAX / 4)
                .is_err()
        );
    }
}
