//! Exercises exact reconstructed initial DATA over the real inherited socket.
//!
//! Announced recipe/row fixtures remain inert. These checks construct no opaque
//! Initial/Recipe, Source purpose, native model, phase claim or readiness grant.

use super::*;
use crate::reference_packet::service::ack_emitter::native_boot::measure_original_restore_current_executable;
use crate::reference_packet::service::complete_restore::import18::{
    PacketNativeImport18PrebirthRecipeWireData, PacketNativeImport18SelectedLaunchWireData,
    derive_native_import18_launch_identity_data, inert_bootstrap_fixtures,
    initial_construction_from_wire_data,
};
use crucible_node_format::{Bytes, Id, canonical};
use serde_json::{Value, json};

#[path = "initial_reconstruction/bootstrap_kernel.rs"]
mod bootstrap_kernel;

#[path = "initial_reconstruction/completed_inputs.rs"]
mod completed_inputs;

#[path = "initial_reconstruction/native_framing.rs"]
mod native_framing;

#[path = "initial_reconstruction/normalization.rs"]
mod normalization;

#[path = "initial_reconstruction/normalized_framing.rs"]
mod normalized_framing;

#[path = "initial_reconstruction/hello_selection.rs"]
mod hello_selection;

#[path = "initial_reconstruction/hello_request.rs"]
mod hello_request;

#[path = "initial_reconstruction/hello_registrar.rs"]
mod hello_registrar;

#[path = "initial_reconstruction/hello_sdk_request.rs"]
mod hello_sdk_request;

#[path = "initial_reconstruction/hello_publication.rs"]
mod hello_publication;
pub(super) fn assert_hello_publication_bytes(case: &str, bytes: &[u8]) {
    if case.starts_with("initial_policy_") {
        if immutable_policy::publishes(case) {
            hello_publication::assert_parent_bytes("initial_hello_publication_complete", bytes);
        } else {
            assert!(bytes.is_empty());
        }
    } else {
        hello_publication::assert_parent_bytes(case, bytes);
    }
}

#[path = "initial_reconstruction/hello_admission.rs"]
mod hello_admission;
#[path = "initial_reconstruction/hello_envelope.rs"]
mod hello_envelope;
#[path = "initial_reconstruction/hello_response.rs"]
mod hello_response;
#[path = "initial_reconstruction/hello_result.rs"]
mod hello_result;
#[path = "initial_reconstruction/hello_verifier.rs"]
mod hello_verifier;

pub(super) fn hello_request_body_data(case: &str) -> Vec<u8> {
    hello_request::body_data(case)
}

#[path = "initial_reconstruction/hello_value.rs"]
mod hello_value;

pub(super) fn hello_value_body_data(case: &str) -> Vec<u8> {
    hello_value::body_data(case)
}

#[path = "initial_reconstruction/hello_literal.rs"]
mod hello_literal;

#[path = "initial_reconstruction/hello_exchange.rs"]
mod hello_exchange;

#[path = "initial_reconstruction/public_channel.rs"]
mod public_channel;
pub(super) use public_channel::retain_before_read as retain_public_before_read;

#[path = "initial_reconstruction/hello_frames.rs"]
mod hello_frames;

#[path = "initial_reconstruction/selection.rs"]
mod selection;

#[path = "initial_reconstruction/launch_validation.rs"]
mod launch_validation;

#[path = "initial_reconstruction/immutable_policy.rs"]
mod immutable_policy;

fn operands(case: &str) -> [Value; 3] {
    let mut recipe = inert_bootstrap_fixtures::recipe();
    recipe["decoder_limits"][9] = json!("268435456");
    // Prepare owns the independently derived initial retained population. The
    // later inert rows share the remaining eight MiB of the same eighty-eight-MiB sum.
    recipe["phases"] = json!([
        ["83886080", "167772160", "4194304"],
        ["2097152", "167772160", "4194304"],
        ["2097152", "167772160", "4194304"],
        ["2097152", "167772160", "4194304"],
        ["2097152", "167772160", "4194304"]
    ]);
    recipe["escrow"] = json!(["92274688", "167772160", "4194304"]);
    if case == "initial_small_escrow" {
        recipe["phases"] = json!(([["1", "1", "1"]; 5]));
        recipe["escrow"] = json!(["5", "1", "1"]);
    }
    if let Some(axis) = match case {
        "initial_short_prepare_retained" => Some(0),
        "initial_short_prepare_transient" => Some(1),
        "initial_short_prepare_scratch" => Some(2),
        _ => None,
    } {
        recipe["phases"][0][axis] = json!("1");
        if axis == 0 {
            // Move exactly the missing retained partition to Commit. The sum
            // and all whole-escrow axes still match the ordinary positive case.
            recipe["phases"][1][0] = json!("85983231");
        }
    }
    if case.starts_with("initial_context_") {
        normalized_framing::commit_recipe(case, &mut recipe);
    }
    if case.starts_with("initial_inputs_") {
        completed_inputs::commit_recipe(&mut recipe);
    }
    if case.starts_with("initial_framing_") {
        native_framing::commit_recipe(case, &mut recipe);
    }
    if case.starts_with("initial_normalization_") {
        normalization::commit_recipe(case, &mut recipe);
    }
    let mut selected = inert_bootstrap_fixtures::initial_selected_launch(matches!(
        case,
        "initial_reactive"
            | "initial_hello_reactive"
            | "initial_selection_reactive"
            | "initial_hello_frames_reactive"
            | "initial_hello_channel_reactive"
            | "initial_hello_exchange_reactive"
            | "initial_hello_literal_reactive"
            | "initial_hello_value_reactive"
            | "initial_hello_request_reactive"
            | "initial_hello_registrar_reactive"
            | "initial_hello_sdk_request_reactive"
            | "initial_hello_result_reactive"
            | "initial_hello_envelope_reactive"
            | "initial_hello_response_reactive"
            | "initial_hello_verifier_reactive"
            | "initial_hello_admission_reactive"
            | "initial_hello_publication_reactive"
    ));
    if case.starts_with("initial_selection_") || case.starts_with("initial_hello_") {
        selection::prepare_selected(case, &mut selected);
    }
    if case.starts_with("initial_hello_registrar_")
        || case.starts_with("initial_hello_sdk_request_")
        || case.starts_with("initial_hello_result_")
        || case.starts_with("initial_hello_envelope_")
        || case.starts_with("initial_hello_response_")
        || case.starts_with("initial_hello_verifier_")
        || case.starts_with("initial_hello_admission_")
        || case.starts_with("initial_hello_publication_")
    {
        hello_registrar::prepare_selected(case, &mut selected);
    }
    if case.starts_with("initial_hello_admission_")
        || case.starts_with("initial_hello_publication_")
    {
        hello_admission::prepare_selected(case, &mut selected);
    }
    if case.starts_with("initial_hello_publication_") {
        hello_publication::prepare_selected(case, &mut selected);
    }
    if case.starts_with("initial_launch_validation_") {
        launch_validation::prepare_selected(case, &mut selected);
    }
    if case.starts_with("initial_policy_") {
        immutable_policy::prepare_selected(case, &mut selected);
    }
    let executable = measure_original_restore_current_executable().unwrap();
    selected["launch"]["controller_executable"] = json!(executable);
    if case == "initial_unmeasured_controller_executable" {
        // Both announced references agree; the actual running image differs.
        selected["launch"]["controller_executable"]["hash"]["digest"] = json!("a".repeat(64));
    }
    let actual_pid = u64::from(std::process::id());
    let actual_uid = u64::from(rustix::process::geteuid().as_raw());
    selected["launch"]["controller_pid"] =
        json!((actual_pid + u64::from(case == "initial_bad_controller_pid")).to_string());
    selected["launch"]["controller_uid"] =
        json!((actual_uid + u64::from(case == "initial_bad_controller_uid")).to_string());
    let launch: PacketNativeImport18SelectedLaunchWireData =
        serde_json::from_value(selected.clone()).unwrap();
    let source = inert_bootstrap_fixtures::source_birth(launch.launch_data());
    let mut boot = inert_bootstrap_fixtures::boot(1, json!({"actual": "host DATA"}));
    let private_launch: Id = serde_json::from_value(boot["private_launch"].clone()).unwrap();
    let actual_identity = derive_native_import18_launch_identity_data(
        launch.launch_data(),
        &private_launch,
        typed::bounds().requested_peak,
    )
    .unwrap();
    recipe["selected_launch_identity"] = json!(actual_identity.selected_launch_identity_data());
    recipe["private_launch_identity"] = json!(actual_identity.private_launch_identity_data());
    if case == "initial_bad_selected_launch_identity" {
        recipe["selected_launch_identity"] = json!(([11; 32]));
    }
    if case == "initial_bad_private_launch_identity" {
        recipe["private_launch_identity"] = json!(([13; 32]));
    }
    if case == "initial_changed_private_launch" {
        let length = boot["private_launch"].as_str().unwrap().len();
        boot["private_launch"] = json!("x".repeat(length));
    }
    boot["source_birth"]["declaration"]["source_birth"] =
        json!(Bytes::new(canonical::canonical_json(&source).unwrap()));
    boot["source_birth"]["declaration"]["fresh_restore_allocation_selection"] = json!(null);
    let commitment =
        serde_json::from_value::<PacketNativeImport18PrebirthRecipeWireData>(recipe.clone())
            .unwrap()
            .reconstructed_identity_data(typed::bounds().requested_peak)
            .unwrap();
    recipe["identity"] = json!(commitment);
    if case == "initial_bad_recipe_identity" {
        recipe["identity"] = json!(([7u8; 32]));
    }
    if case == "initial_changed_recipe_operand" {
        recipe["geometry_identity"] = json!(([1u8; 32]));
    }
    selected["prebirth_recipe_identity"] = recipe["identity"].clone();
    boot["source_birth"]["prebirth_recipe"] = recipe.clone();
    boot["host_executable"] = selected["launch"]["controller_executable"].clone();
    boot["birth_id"] = json!(Bytes::new(
        blake3::derive_key("source-owned.packet-canonical-ack-birth/5", &[23; 32]).to_vec()
    ));
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

fn flight(case: &str) {
    let mut values = operands(case);
    let mut row = required(&values);
    if case.starts_with("initial_launch_validation_") || case.starts_with("initial_policy_") {
        launch_validation::fund_initial_partition(&mut values, row);
        assert_eq!(required(&values), row);
    }
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
        "initial_bad_birth" => values[2]["birth_id"] = json!(Bytes::new(vec![42; 32])),
        "initial_bad_host_executable" => {
            values[2]["host_executable"]["hash"]["digest"] = json!("a".repeat(64));
        }
        "initial_short_key" => values[2]["private_key"] = json!(Bytes::new(vec![23; 31])),
        "initial_short_birth" => values[2]["birth_id"] = json!(Bytes::new(vec![17; 31])),
        "initial_overstated_prefix" => row[0] += 1,
        _ => {}
    }
    let raw = encode(&values);
    let mut prefix = prefix_for_bodies(row, raw.each_ref().map(Vec::as_slice));
    let recipe_identity: [u8; 32] = serde_json::from_value(values[0]["identity"].clone()).unwrap();
    prefix[136..168].copy_from_slice(&recipe_identity);
    if case == "initial_bad_prefix_recipe" {
        prefix[136..168].fill(9);
    }
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
    if case == "initial_independent_peak" {
        // The child must price the actual parent's received launch. Regenerating
        // operands here substitutes the child's PID and derived commitments.
        let bodies = owner.typed_bodies_data().unwrap();
        let row = initial_construction_from_wire_data(
            bodies.launch,
            bodies.boot,
            typed::bounds().requested_peak,
        )
        .unwrap()
        .row;
        owner.bounds.requested_peak = row.into_iter().sum::<usize>() - 1;
    }
    if case == "initial_expired" {
        owner.cut = OperationalDeadline::expired_fixture();
    }
    if case == "initial_changed_raw" {
        owner.bodies[0][0] ^= 1;
    }
    if case == "initial_foreign" {
        with_foreign_thread_record(&mut owner, |owner| {
            assert!(owner.reconstruct_initial_data().is_err());
            assert!(!owner.initial_reconstructed);
        });
    } else {
        let result = owner.reconstruct_initial_data();
        if matches!(
            case,
            "initial_short_prepare_retained"
                | "initial_short_prepare_transient"
                | "initial_short_prepare_scratch"
        ) {
            assert!(matches!(
                &result,
                Err(ProviderError::ResourceExhausted(
                    "original import18 initial Prepare partition"
                ))
            ));
        }
        if matches!(case, "initial_bad_birth" | "initial_bad_host_executable") {
            // Canonical extents, raw hashes and all funding announcements still
            // match. The actual new private-identity join must reject this DATA.
            assert!(matches!(
                &result,
                Err(ProviderError::Correlation(
                    "original import18 private Birth DATA"
                ))
            ));
        }
        if matches!(
            case,
            "initial_bad_controller_pid" | "initial_bad_controller_uid"
        ) {
            assert!(matches!(
                &result,
                Err(ProviderError::Correlation(
                    "original import18 controller kernel DATA"
                ))
            ));
        }
        if case == "initial_unmeasured_controller_executable" {
            assert!(matches!(
                &result,
                Err(ProviderError::Correlation(
                    "original import18 controller executable DATA"
                ))
            ));
        }
        if matches!(
            case,
            "initial_bad_selected_launch_identity"
                | "initial_bad_private_launch_identity"
                | "initial_changed_private_launch"
        ) {
            assert!(matches!(
                &result,
                Err(ProviderError::Correlation(
                    "original import18 recipe launch DATA"
                ))
            ));
        }
        if matches!(
            case,
            "initial_bad_recipe_identity" | "initial_changed_recipe_operand"
        ) {
            assert!(matches!(
                &result,
                Err(ProviderError::Correlation(
                    "original import18 recipe commitment DATA"
                ))
            ));
        }
        if matches!(case, "initial_producer" | "initial_reactive")
            || case.starts_with("initial_inputs_")
            || case.starts_with("initial_framing_")
            || case.starts_with("initial_normalization_")
            || case.starts_with("initial_context_")
            || case.starts_with("initial_hello_")
            || case.starts_with("initial_selection_")
            || case.starts_with("initial_launch_validation_")
            || case.starts_with("initial_policy_")
        {
            if result.is_err() && case.starts_with("initial_launch_validation_") {
                eprintln!(
                    "{case}: initial {:?}, validator {:?}",
                    owner.initial_construction.as_ref().map(|data| data.row),
                    super::super::launch_validation::construction_data(
                        owner.typed_bodies_data().unwrap().launch.launch_data(),
                        owner.bounds.requested_peak,
                    )
                );
            }
            result.unwrap();
            assert!(owner.initial_reconstructed);
            assert!(owner.initial_construction.is_some());
        } else {
            assert!(
                result.is_err(),
                "{case}: initial reconstruction unexpectedly accepted"
            );
            assert!(!owner.initial_reconstructed);
        }
    }
    if case.starts_with("initial_policy_") {
        immutable_policy::assert_child(case, &mut owner);
        return;
    }
    if case.starts_with("initial_launch_validation_") {
        launch_validation::assert_child(case, &mut owner);
        return;
    }
    if case.starts_with("initial_selection_") {
        selection::assert_child(case, &mut owner);
        return;
    }
    if case.starts_with("initial_hello_publication_") {
        hello_publication::assert_child(case, &mut owner);
        return;
    }
    if case.starts_with("initial_hello_admission_") {
        hello_admission::assert_child(case, &mut owner);
        return;
    }
    if case.starts_with("initial_hello_verifier_") {
        hello_verifier::assert_child(&mut owner);
        return;
    }
    if case.starts_with("initial_hello_response_") {
        hello_response::assert_child(case, &mut owner);
        return;
    }
    if case.starts_with("initial_hello_envelope_") {
        hello_envelope::assert_child(case, &mut owner);
        return;
    }
    if case.starts_with("initial_hello_result_") {
        hello_result::assert_child(case, &mut owner);
        return;
    }
    if case.starts_with("initial_hello_sdk_request_") {
        hello_sdk_request::assert_child(case, &mut owner);
        return;
    }
    if case.starts_with("initial_hello_registrar_") {
        hello_registrar::assert_child(case, &mut owner);
        return;
    }
    if case.starts_with("initial_hello_request_") {
        hello_request::assert_child(case, &mut owner);
        return;
    }
    if case.starts_with("initial_hello_value_") {
        hello_value::assert_child(case, &mut owner);
        return;
    }
    if case.starts_with("initial_hello_literal_") {
        hello_literal::assert_child(case, &mut owner);
        return;
    }
    if case.starts_with("initial_hello_exchange_") {
        hello_exchange::assert_child(case, &mut owner);
        return;
    }
    if case.starts_with("initial_hello_channel_") {
        public_channel::assert_child(case, &mut owner);
        return;
    }
    if case.starts_with("initial_hello_frames_") {
        hello_frames::assert_child(case, &mut owner);
        return;
    }
    if case.starts_with("initial_hello_") {
        hello_selection::assert_child(case, &mut owner);
        return;
    }
    if case.starts_with("initial_context_") {
        normalized_framing::assert_child(case, &mut owner);
        return;
    }
    if case.starts_with("initial_inputs_") {
        completed_inputs::assert_child(case, &mut owner);
        return;
    }
    if case.starts_with("initial_framing_") {
        native_framing::assert_child(case, &mut owner);
        return;
    }
    if case.starts_with("initial_normalization_") {
        normalization::fill_child(case, &mut owner);
        normalization::assert_child(case, &owner);
        return;
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
        "initial_bad_birth",
        "initial_bad_host_executable",
        "initial_bad_controller_pid",
        "initial_bad_controller_uid",
        "initial_unmeasured_controller_executable",
        "initial_bad_selected_launch_identity",
        "initial_bad_private_launch_identity",
        "initial_changed_private_launch",
        "initial_bad_recipe_identity",
        "initial_changed_recipe_operand",
        "initial_short_key",
        "initial_short_birth",
        "initial_bad_prefix_recipe",
        "initial_overstated_prefix",
        "initial_small_escrow",
        "initial_short_prepare_retained",
        "initial_short_prepare_transient",
        "initial_short_prepare_scratch",
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

#[test]
fn strict_hello_population_is_funded_inside_the_original_independent_peak() {
    for case in [
        "initial_producer",
        "initial_reactive",
        "initial_hello_value_complete",
    ] {
        let row = required(&operands(case));
        let limits = [83_886_080, 167_772_160, 4_194_304];
        assert!(
            row.iter()
                .zip(limits)
                .all(|(actual, limit)| *actual <= limit),
            "all actual constructor axes must fit the original Prepare partition for {case}: {row:?}"
        );
    }
    let row = required(&operands("initial_hello_value_complete"));
    assert!(
        row[0] > 44_040_192,
        "the actual strict tree exceeds the prior inert Prepare row: {row:?}"
    );
    assert!(
        row[0] <= 83_886_080,
        "the enlarged inert Prepare row must fund the actual tree: {row:?}"
    );
    assert!(row.iter().sum::<usize>() <= 268_435_456);
}
