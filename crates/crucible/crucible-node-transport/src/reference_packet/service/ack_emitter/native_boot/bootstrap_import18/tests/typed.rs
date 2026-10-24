//! Exercises actual typed parsing over the original inherited descriptor.
//!
//! Fixtures contain only inert wire announcements. No control issues an opaque
//! Initial/Recipe, validates a Source program or enables native startup.

use super::*;
use crate::reference_packet::service::complete_restore::import18::inert_bootstrap_fixtures;
use crucible_node_format::canonical;
use serde_json::json;

pub(super) fn bounds() -> Import18RawBootstrapBounds {
    Import18RawBootstrapBounds {
        bodies: [512 * 1024; 3],
        complete_private_bytes: NATIVE_IMPORT18_PRIVATE_PREFIX_BYTES + 3 * 512 * 1024,
        requested_peak: 256 * 1024 * 1024,
    }
}

fn bodies(case: &str) -> [Vec<u8>; 3] {
    let registration = if case == "typed_reset" {
        json!({"$serde_json::private::RawValue": format!("{}0{}", "[".repeat(70), "]".repeat(70))})
    } else {
        json!({"actual": [1, 2, "retained"]})
    };
    let mut boot = inert_bootstrap_fixtures::boot(2049, registration);
    if case == "typed_bad_boot" {
        boot["private_key"] = json!("!");
    }
    let mut recipe = inert_bootstrap_fixtures::recipe();
    if case == "typed_bad_recipe" {
        recipe["schema"] = json!("invalid-recipe");
    }
    let mut launch = inert_bootstrap_fixtures::selected_launch(case == "typed_reactive");
    if case == "typed_bad_launch" {
        launch["launch"]["program"]["kind"] = json!("invalid-program");
    }
    [
        canonical::canonical_json(&recipe).unwrap(),
        canonical::canonical_json(&launch).unwrap(),
        canonical::canonical_json(&boot).unwrap(),
    ]
}

fn row(bodies: &[Vec<u8>; 3]) -> [usize; 3] {
    let raw = raw_storage_floor(bodies.each_ref().map(Vec::len)).unwrap();
    let mut slots = OriginalImport18DecodedBodies::empty();
    let parsers = slots
        .construction_data(
            bodies.each_ref().map(Vec::as_slice),
            bounds().requested_peak,
        )
        .unwrap();
    super::super::decoding::combine(raw, parsers).unwrap()
}

pub(super) fn required_peak(case: &str) -> usize {
    row(&bodies(case)).iter().sum()
}

fn flight(case: &str, short_axis: Option<usize>) {
    let bodies = bodies(case);
    let mut initial = row(&bodies);
    if let Some(axis) = short_axis {
        initial[axis] -= 1;
    }
    assert!(initial.iter().sum::<usize>() <= bounds().requested_peak);
    let mut wire = prefix_for_bodies(initial, bodies.each_ref().map(Vec::as_slice)).to_vec();
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
    let expected = bodies(case);
    assert_eq!(
        owner.bodies_data().unwrap(),
        expected.each_ref().map(Vec::as_slice)
    );
    let raw_retained = owner.retained_requested_bytes().unwrap();
    if case == "typed_cut_before_decode" {
        owner.cut = OperationalDeadline::expired_fixture();
        assert!(owner.decode_bodies_data().is_err());
        assert!(owner.decode_started);
        assert!(owner.decode_bodies_data().is_err());
        assert_eq!(owner.parsed.partial_presence_data(), [false; 3]);
        assert_eq!(owner.retained_requested_bytes().unwrap(), raw_retained);
        return;
    }
    assert_eq!(owner.parsed.partial_presence_data(), [false; 3]);
    let decoded = owner.decode_bodies_data();

    if case.starts_with("typed_short_") || case == "typed_independent_peak" {
        assert!(decoded.is_err());
        assert_eq!(owner.parsed.partial_presence_data(), [false; 3]);
        assert_eq!(owner.retained_requested_bytes().unwrap(), raw_retained);
        assert!(owner.typed_bodies_data().is_err());
    } else if case.starts_with("typed_bad_") {
        assert!(decoded.is_err());
        let partials = match case {
            "typed_bad_recipe" => [false; 3],
            "typed_bad_launch" => [true, false, false],
            "typed_bad_boot" => [true, true, false],
            _ => panic!("unknown typed failure fixture"),
        };
        assert_eq!(owner.parsed.partial_presence_data(), partials);
        if partials[1] {
            assert!(owner.retained_requested_bytes().unwrap() > raw_retained);
        } else {
            assert_eq!(owner.retained_requested_bytes().unwrap(), raw_retained);
        }
        assert!(owner.typed_bodies_data().is_err());
    } else {
        decoded.unwrap();
        assert_eq!(owner.parsed.partial_presence_data(), [true; 3]);
        let bodies = owner.typed_bodies_data().unwrap();
        assert_eq!(bodies.launch.launch_data().schema_version, 5);
        assert_eq!(
            bodies
                .boot
                .source_binding_data()
                .declaration_data()
                .source_birth_data()
                .as_slice(),
            vec![255; 2049]
        );
        assert!(owner.retained_requested_bytes().unwrap() > raw_retained);
    }

    let retained = owner.retained_requested_bytes().unwrap();
    assert!(retained <= owner.decoding_row.unwrap()[0]);
    assert!(owner.decode_bodies_data().is_err());
    assert_eq!(owner.retained_requested_bytes().unwrap(), retained);
    assert_eq!(
        owner.bodies_data().unwrap(),
        expected.each_ref().map(Vec::as_slice)
    );
    assert!(owner.inputs.is_empty_data());

    if case == "typed_foreign" {
        with_foreign_thread_record(&mut owner, |owner| {
            assert!(owner.typed_bodies_data().is_err());
            assert!(owner.retained_requested_bytes().is_err());
        });
        owner.typed_bodies_data().unwrap();
    }
    if case == "typed_changed_raw" {
        owner.bodies[0][0] ^= 1;
        assert!(owner.typed_bodies_data().is_err());
        assert_eq!(owner.retained_requested_bytes().unwrap(), retained);
    }
    owner.cut = OperationalDeadline::expired_fixture();
    assert!(owner.typed_bodies_data().is_err());
    assert!(owner.decode_bodies_data().is_err());
    assert_eq!(owner.retained_requested_bytes().unwrap(), retained);
}

#[test]
fn actual_parent_child_decodes_both_program_families_under_the_original_cut() {
    for case in [
        "typed_producer",
        "typed_reactive",
        "typed_foreign",
        "typed_changed_raw",
    ] {
        flight(case, None);
    }
}

#[test]
fn each_complete_parser_axis_refuses_before_any_typed_output() {
    for (axis, case) in [
        "typed_short_retained",
        "typed_short_transient",
        "typed_short_scratch",
    ]
    .into_iter()
    .enumerate()
    {
        flight(case, Some(axis));
    }
}

#[test]
fn later_malformed_boot_keeps_the_original_raw_banks_and_successful_typed_prefix() {
    for case in ["typed_bad_recipe", "typed_bad_launch", "typed_bad_boot"] {
        flight(case, None);
    }
}

#[test]
fn rawvalue_reset_retains_actual_expanded_backing_without_the_ordinary_depth_cap() {
    flight("typed_reset", None);
}

#[test]
fn whole_parser_ownership_sum_refuses_arithmetic_overflow() {
    assert!(super::super::decoding::combine([usize::MAX, 1, 1], [[1, 1, 1]; 3]).is_err());
    assert!(super::super::decoding::combine([1, 1, usize::MAX], [[1, 1, 1]; 3]).is_err());
}

#[test]
fn independent_complete_peak_and_expired_original_cut_refuse_parsing() {
    flight("typed_independent_peak", None);
    flight("typed_cut_before_decode", None);
}
