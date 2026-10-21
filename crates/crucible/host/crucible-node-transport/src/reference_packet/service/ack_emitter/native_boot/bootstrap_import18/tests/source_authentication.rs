//! Exercises funded Source DATA correspondence on the actual inherited socket.

use super::*;
use crate::reference_packet::service::complete_restore::import18::{
    PacketNativeImport18SelectedLaunchWireData, inert_bootstrap_fixtures,
    source_authentication_construction_data,
};
use crucible_node_format::{Bytes, canonical};
use serde_json::json;

fn bodies(case: &str) -> [Vec<u8>; 3] {
    let selected = inert_bootstrap_fixtures::selected_launch(case == "source_reactive");
    let launch: PacketNativeImport18SelectedLaunchWireData =
        serde_json::from_value(selected.clone()).unwrap();
    let mut source = inert_bootstrap_fixtures::source_birth(launch.launch_data());
    if case == "source_changed_field" {
        source["program"] = json!("changed");
    }
    if case == "source_report" {
        source["native_startup_allocation"] = json!((["1"; 3]));
    }
    let mut bytes = canonical::canonical_json(&source).unwrap();
    if case == "source_malformed" {
        bytes[0] = 255;
    }
    if case == "source_noncanonical" {
        bytes.push(b' ');
    }
    let mut boot = inert_bootstrap_fixtures::boot(1, json!({"inert": true}));
    boot["source_birth"]["declaration"]["source_birth"] = json!(Bytes::new(bytes));
    boot["source_birth"]["declaration"]["fresh_restore_allocation_selection"] = json!(null);
    [
        canonical::canonical_json(&inert_bootstrap_fixtures::recipe()).unwrap(),
        canonical::canonical_json(&selected).unwrap(),
        canonical::canonical_json(&boot).unwrap(),
    ]
}

fn row(bodies: &[Vec<u8>; 3]) -> [usize; 3] {
    let raw = raw_storage_floor(bodies.each_ref().map(Vec::len)).unwrap();
    let mut slots = OriginalImport18DecodedBodies::empty();
    let parsers = slots
        .construction_data(
            bodies.each_ref().map(Vec::as_slice),
            typed::bounds().requested_peak,
        )
        .unwrap();
    slots.decode_recipe(&bodies[0]).unwrap();
    slots.decode_launch(&bodies[1]).unwrap();
    slots.decode_boot(&bodies[2]).unwrap();
    let base = super::super::decoding::combine(raw, parsers).unwrap();
    let typed = slots.bodies_data().unwrap();
    let source = source_authentication_construction_data(
        typed.boot.source_binding_data().declaration_data(),
        typed.launch.launch_data(),
        typed::bounds().requested_peak,
    )
    .unwrap();
    super::super::source_authentication::combine(base, source).unwrap()
}

pub(super) fn required_peak(case: &str) -> usize {
    row(&bodies(case)).iter().sum()
}

fn flight(case: &str, short_axis: Option<usize>) {
    let bodies = bodies(case);
    let mut required = row(&bodies);
    if let Some(axis) = short_axis {
        required[axis] -= 1;
    }
    let mut wire = prefix_for_bodies(required, bodies.each_ref().map(Vec::as_slice)).to_vec();
    for body in &bodies {
        wire.extend_from_slice(body);
    }
    child(case, &wire);
}

pub(super) fn assert_child(
    case: &str,
    mut owner: OriginalImport18RawBootstrap,
    received: Result<(), ProviderError>,
) {
    received.unwrap();
    owner.decode_bodies_data().unwrap();
    let retained = owner.retained_requested_bytes().unwrap();
    if case == "source_expired" {
        owner.cut = OperationalDeadline::expired_fixture();
    }
    if case == "source_changed_raw" {
        owner.bodies[2][0] ^= 1;
    }
    if case == "source_foreign" {
        with_foreign_thread_record(&mut owner, |owner| {
            assert!(owner.authenticate_source_data().is_err());
            assert!(!owner.source_authenticated);
        });
    } else {
        let outcome = owner.authenticate_source_data();
        if matches!(case, "source_producer" | "source_reactive") {
            outcome.unwrap();
            assert!(owner.source_authenticated);
        } else {
            assert!(outcome.is_err());
            assert!(!owner.source_authenticated);
        }
    }
    assert!(owner.source_authentication_started);
    assert!(owner.authenticate_source_data().is_err());
    assert_eq!(owner.retained_requested_bytes().unwrap(), retained);
    assert!(owner.inputs.is_empty_data());
    if case != "source_changed_raw" && case != "source_expired" {
        let original = bodies(case);
        assert_eq!(
            owner.bodies_data().unwrap(),
            original.each_ref().map(Vec::as_slice)
        );
    }
}

#[test]
fn actual_socket_checks_both_original_source_program_families() {
    for case in ["source_producer", "source_reactive"] {
        flight(case, None);
    }
}

#[test]
fn each_complete_source_axis_and_independent_policy_refuse_without_retained_growth() {
    for (axis, case) in [
        "source_short_retained",
        "source_short_transient",
        "source_short_scratch",
    ]
    .into_iter()
    .enumerate()
    {
        flight(case, Some(axis));
    }
    flight("source_independent_peak", None);
}

#[test]
fn actual_source_parser_refuses_malformed_changed_report_and_noncanonical_banks() {
    for case in [
        "source_malformed",
        "source_changed_field",
        "source_report",
        "source_noncanonical",
    ] {
        flight(case, None);
    }
}

#[test]
fn original_source_custody_and_cut_remain_mandatory() {
    for case in ["source_foreign", "source_changed_raw", "source_expired"] {
        flight(case, None);
    }
}

#[test]
fn source_check_population_combination_refuses_overflow() {
    assert!(super::super::source_authentication::combine([usize::MAX, 1, 1], [1, 1, 1]).is_err());
    assert!(super::super::source_authentication::combine([1, 1, usize::MAX], [1, 1, 1]).is_err());
}
