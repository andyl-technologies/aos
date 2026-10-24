//! Checks funding symmetry and actual original Source DATA correspondence.

use super::*;
use crate::reference_packet::service::complete_restore::import18::{
    PacketNativeImport18SelectedLaunchWireData, inert_bootstrap_fixtures,
};
use serde_json::json;

fn launch(reactive: bool) -> PacketNativeImport18SelectedLaunchWireData {
    serde_json::from_value(inert_bootstrap_fixtures::selected_launch(reactive)).unwrap()
}

fn declaration(source: &Value) -> PacketNativeImport18SourceDeclarationWireData {
    declaration_bytes(canonical::canonical_json(source).unwrap())
}

fn declaration_bytes(bytes: Vec<u8>) -> PacketNativeImport18SourceDeclarationWireData {
    serde_json::from_value(json!({
        "schema": NATIVE_IMPORT18_SOURCE_DECLARATION_SCHEMA,
        "source_birth": Bytes::new(bytes),
        "fresh_restore_allocation_selection": null,
    }))
    .unwrap()
}

#[test]
fn opaque_parent_and_actual_native_bank_derive_identical_complete_rows() {
    for reactive in [false, true] {
        let selected = launch(reactive);
        let launch = selected.launch_data();
        let source = inert_bootstrap_fixtures::source_birth(launch);
        let declaration = declaration(&source);
        let bank = declaration.source_birth_data().as_slice();
        let original = bank.to_vec();
        let view = native_import18_source_declaration_bank_view_data(bank, launch).unwrap();
        let native =
            source_authentication_construction_data(&declaration, launch, usize::MAX).unwrap();
        let parent = source_authentication_projection_data(&view, launch, usize::MAX).unwrap();

        assert_eq!(native, parent);
        assert!(native.iter().all(|n| *n > 0));
        assert_eq!(bank, original);
        let exact = native.iter().sum();
        assert_eq!(
            source_authentication_construction_data(&declaration, launch, exact).unwrap(),
            native
        );
        assert!(source_authentication_construction_data(&declaration, launch, exact - 1).is_err());
        let quote = source_authentication_quote_construction_data(launch).unwrap();
        assert_eq!(quote[0], 0);
        assert!(quote[1] > 0);
        assert!(quote[2] > 0);
        declaration.authenticate_launch_data(launch).unwrap();
    }
}

#[test]
fn quoting_never_interprets_the_original_opaque_source_bank() {
    let selected = launch(false);
    let launch = selected.launch_data();
    for bank in [
        vec![255; 2049],
        b"{\"$serde_json::private::RawValue\":\"[0]\"}".to_vec(),
    ] {
        let declaration = declaration_bytes(bank.clone());
        let view = native_import18_source_declaration_bank_view_data(&bank, launch).unwrap();
        assert_eq!(
            source_authentication_construction_data(&declaration, launch, usize::MAX).unwrap(),
            source_authentication_projection_data(&view, launch, usize::MAX).unwrap(),
        );
        assert!(declaration.authenticate_launch_data(launch).is_err());
        assert_eq!(declaration.source_birth_data().as_slice(), bank);
    }
}

#[test]
fn constructor_rows_ignore_parent_spare_capacity_without_discounting_its_ownership() {
    let mut selected = launch(false);
    let original = inert_bootstrap_fixtures::source_birth(selected.launch_data());
    let declaration = declaration(&original);
    let before =
        source_authentication_construction_data(&declaration, selected.launch_data(), usize::MAX)
            .unwrap();
    let mut spare = Vec::with_capacity(4096);
    spare.extend_from_slice(selected.launch.admission_token.as_slice());
    selected.launch.admission_token = Bytes::new(spare);
    if let crate::reference_packet::service::PacketConnectedSourceProgram::Producer { program } =
        &mut selected.launch.program
    {
        program.events.reserve_exact(1024);
    }
    let after =
        source_authentication_construction_data(&declaration, selected.launch_data(), usize::MAX)
            .unwrap();

    assert_eq!(before, after);
    assert!(selected.launch.admission_token.allocation_capacity() >= 4096);
    assert_eq!(
        original,
        inert_bootstrap_fixtures::source_birth(selected.launch_data())
    );
    declaration
        .authenticate_launch_data(selected.launch_data())
        .unwrap();
}

#[test]
fn actual_source_checker_refuses_changed_fields_reports_and_noncanonical_banks() {
    let selected = launch(false);
    let launch = selected.launch_data();
    let source = inert_bootstrap_fixtures::source_birth(launch);
    for field in [
        "schema",
        "program",
        "selection",
        "limits",
        "storage",
        "coordinator",
    ] {
        let mut changed = source.clone();
        changed[field] = json!("changed");
        assert!(
            declaration(&changed)
                .authenticate_launch_data(launch)
                .is_err()
        );
    }
    let mut report = source.clone();
    report["native_startup_allocation"] = json!((["1"; 3]));
    assert!(
        declaration(&report)
            .authenticate_launch_data(launch)
            .is_err()
    );

    let mut noncanonical = canonical::canonical_json(&source).unwrap();
    noncanonical.push(b' ');
    assert!(
        declaration_bytes(noncanonical)
            .authenticate_launch_data(launch)
            .is_err()
    );
    assert!(for_bank_length(usize::MAX, launch, usize::MAX).is_err());
    assert!(for_bank_length(1, launch, 1).is_err());
}
