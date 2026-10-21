//! Exercises exact reconstructed initial DATA over the real inherited socket.
//!
//! Announced recipe/row fixtures remain inert. These checks construct no opaque
//! Initial/Recipe, Source purpose, native model, phase claim or readiness grant.

use super::*;
use crate::reference_packet::service::complete_restore::import18::{
    inert_bootstrap_fixtures, initial_construction_from_wire_data,
};
use crucible_node_format::{Bytes, canonical};
use serde_json::{Value, json};

fn operands(case: &str) -> [Value; 3] {
    let mut recipe = inert_bootstrap_fixtures::recipe();
    recipe["decoder_limits"][9] = json!("268435456");
    recipe["phases"] = json!(([["10485760", "167772160", "4194304"]; 5]));
    recipe["escrow"] = json!(["52428800", "167772160", "4194304"]);
    if case == "initial_small_escrow" {
        recipe["phases"] = json!(([["1", "1", "1"]; 5]));
        recipe["escrow"] = json!(["5", "1", "1"]);
    }
    let selected = inert_bootstrap_fixtures::selected_launch(case == "initial_reactive");
    let launch: crate::reference_packet::service::complete_restore::import18::PacketNativeImport18SelectedLaunchWireData = serde_json::from_value(selected.clone()).unwrap();
    let source = inert_bootstrap_fixtures::source_birth(launch.launch_data());
    let mut boot = inert_bootstrap_fixtures::boot(1, json!({"actual": "host DATA"}));
    boot["source_birth"]["declaration"]["source_birth"] =
        json!(Bytes::new(canonical::canonical_json(&source).unwrap()));
    boot["source_birth"]["declaration"]["fresh_restore_allocation_selection"] = json!(null);
    boot["source_birth"]["prebirth_recipe"] = recipe.clone();
    [recipe, selected, boot]
}

fn encode(values: &[Value; 3]) -> [Vec<u8>; 3] {
    values
        .each_ref()
        .map(|value| canonical::canonical_json(value).unwrap())
}

fn required(values: &[Value; 3]) -> [usize; 3] {
    let raw = encode(values);
    let mut slots = OriginalImport18DecodedBodies::empty();
    slots
        .construction_data(
            raw.each_ref().map(Vec::as_slice),
            typed::bounds().requested_peak,
        )
        .unwrap();
    slots.decode_recipe(&raw[0]).unwrap();
    slots.decode_launch(&raw[1]).unwrap();
    slots.decode_boot(&raw[2]).unwrap();
    let typed = slots.bodies_data().unwrap();
    initial_construction_from_wire_data(typed.launch, typed.boot, typed::bounds().requested_peak)
        .unwrap()
        .row
}

pub(super) fn required_peak(case: &str) -> usize {
    required(&operands(case)).iter().sum()
}

fn flight(case: &str) {
    let mut values = operands(case);
    let mut row = required(&values);
    let row_value = json!({
        "retained_requested_bytes": row[0].to_string(),
        "maximum_simultaneous_transient_bytes": row[1].to_string(),
        "declared_counter_scratch_bytes": row[2].to_string(),
    });
    values[1]["initial_funding"] = row_value.clone();
    values[2]["source_birth"]["initial_funding"] = row_value;
    match case {
        "initial_bad_boot_row" => {
            values[2]["source_birth"]["initial_funding"]["retained_requested_bytes"] = json!("1")
        }
        "initial_bad_selected_row" => {
            values[1]["initial_funding"]["retained_requested_bytes"] = json!("1")
        }
        "initial_bad_selected_recipe" => values[1]["prebirth_recipe_identity"] = json!(([9; 32])),
        "initial_bad_recipe_copy" => {
            values[2]["source_birth"]["prebirth_recipe"]["nonce"] = json!(([1; 32]))
        }
        "initial_bad_key" => values[2]["private_key"] = json!(Bytes::new(vec![24; 32])),
        "initial_short_key" => values[2]["private_key"] = json!(Bytes::new(vec![23; 31])),
        "initial_short_birth" => values[2]["birth_id"] = json!(Bytes::new(vec![17; 31])),
        "initial_overstated_prefix" => row[0] += 1,
        _ => {}
    }
    let raw = encode(&values);
    let mut prefix = prefix_for_bodies(row, raw.each_ref().map(Vec::as_slice));
    prefix[136..168].fill(if case == "initial_bad_prefix_recipe" {
        9
    } else {
        0
    });
    let key = blake3::derive_key(NATIVE_IMPORT17_PRIVATE_PREFIX_DOMAIN, &[23; 32]);
    let mac = blake3::keyed_hash(&key, &prefix[..224]);
    prefix[224..].copy_from_slice(mac.as_bytes());
    let mut wire = prefix.to_vec();
    for bank in &raw {
        wire.extend_from_slice(bank);
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
    if case != "initial_unchecked_source" {
        owner.authenticate_source_data().unwrap();
    }
    let retained = owner.retained_requested_bytes().unwrap();
    if case == "initial_expired" {
        owner.cut = OperationalDeadline::expired_fixture();
    }
    if case == "initial_changed_raw" {
        owner.bodies[0][0] ^= 1;
    }
    if case == "initial_foreign" {
        owner = std::thread::spawn(move || {
            assert!(owner.reconstruct_initial_data().is_err());
            assert!(!owner.initial_reconstructed);
            owner
        })
        .join()
        .unwrap();
    } else {
        let result = owner.reconstruct_initial_data();
        if matches!(case, "initial_producer" | "initial_reactive") {
            result.unwrap();
            assert!(owner.initial_reconstructed);
            assert!(owner.initial_construction.is_some());
        } else {
            assert!(result.is_err());
            assert!(!owner.initial_reconstructed);
        }
    }
    assert!(owner.initial_reconstruction_started);
    assert!(owner.reconstruct_initial_data().is_err());
    assert_eq!(owner.retained_requested_bytes().unwrap(), retained);
    assert!(owner.inputs.is_empty_data());
}

#[test]
fn actual_initial_reconstruction_joins_both_program_family_announcements() {
    for case in ["initial_producer", "initial_reactive"] {
        flight(case);
    }
}

#[test]
fn independent_formula_rejects_each_changed_header_operand_and_small_escrow() {
    for case in [
        "initial_bad_boot_row",
        "initial_bad_selected_row",
        "initial_bad_selected_recipe",
        "initial_bad_recipe_copy",
        "initial_bad_key",
        "initial_short_key",
        "initial_short_birth",
        "initial_bad_prefix_recipe",
        "initial_overstated_prefix",
        "initial_small_escrow",
    ] {
        flight(case);
    }
}

#[test]
fn initial_reconstruction_requires_original_source_cut_and_custody() {
    for case in [
        "initial_unchecked_source",
        "initial_expired",
        "initial_changed_raw",
        "initial_foreign",
        "initial_independent_peak",
    ] {
        flight(case);
    }
}
