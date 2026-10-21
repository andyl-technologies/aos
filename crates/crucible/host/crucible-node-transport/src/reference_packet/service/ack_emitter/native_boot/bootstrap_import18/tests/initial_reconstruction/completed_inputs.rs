//! Exercises original completed input loans over real inherited socket custody.
//!
//! Actual Blob transfers and reference matching are DATA controls. The inert
//! bodies deliberately supply no semantic model, Prepare token or opaque recipe.

use super::*;
use crate::bodies::{BlobBeginRequest, BlobChunkRequest, BlobFinishRequest};
use crate::reference_packet::service::complete_restore::import18::{
    PacketNativeImport18SemanticSpendFamily, native_import18_reference_identity_data,
};
use crucible_node_format::{ContentRef, Extensions, U64};

fn bodies() -> [&'static [u8]; 7] {
    [
        b"native protocol",
        b"logical control",
        b"captured anchor",
        b"owner snapshot",
        b"source journal",
        b"normalization",
        b"semantic spend",
    ]
}

fn references() -> [ContentRef; 7] {
    std::array::from_fn(|index| {
        canonical::content_ref(
            bodies()[index],
            if index == 6 {
                PacketNativeImport18SemanticSpendFamily::Complete18.media_type_data()
            } else {
                "application/octet-stream"
            },
        )
        .unwrap()
    })
}

pub(super) fn commit_recipe(recipe: &mut Value) {
    let references = references();
    let [after, control, anchor, snapshot, journal, _, semantic] = references.each_ref();
    let archive = [snapshot, after, control, anchor, journal];
    recipe["archived_reference_identities"] =
        json!(archive.map(|reference| native_import18_reference_identity_data(reference).unwrap()));
    recipe["archived_lengths"] = json!(archive.map(|reference| reference.length));
    recipe["semantic_reference_identity"] =
        json!(native_import18_reference_identity_data(semantic).unwrap());
    recipe["semantic_length"] = json!(semantic.length);
    recipe["semantic_spend_maximum"] = json!(semantic.length);
    for (index, reference) in archive.into_iter().enumerate() {
        recipe["decoder_limits"][index] = json!(reference.length);
    }
}

fn fill(owner: &mut OriginalImport18RawBootstrap, swap: bool, complete: bool) {
    let mut references = references();
    let mut bodies = bodies();
    if swap {
        references.swap(0, 1);
        bodies.swap(0, 1);
    }
    owner
        .inputs
        .reserve_data(references.each_ref(), bodies.map(<[u8]>::len), usize::MAX)
        .unwrap();
    for index in 0..if complete { 7 } else { 6 } {
        let transfer_id = Id::new(format!("input-{index}")).unwrap();
        owner
            .inputs
            .begin_data(&BlobBeginRequest {
                transfer_id: transfer_id.clone(),
                content: references[index].clone(),
                extensions: Extensions::new(),
            })
            .unwrap();
        owner
            .inputs
            .chunk_data(&BlobChunkRequest {
                transfer_id: transfer_id.clone(),
                offset: U64::new(0),
                bytes: Bytes::new(bodies[index].to_vec()),
                extensions: Extensions::new(),
            })
            .unwrap();
        owner
            .inputs
            .finish_data(&BlobFinishRequest {
                transfer_id,
                extensions: Extensions::new(),
            })
            .unwrap();
    }
}

pub(super) fn assert_child(case: &str, owner: &mut OriginalImport18RawBootstrap) {
    fill(
        owner,
        case == "initial_inputs_swapped",
        case != "initial_inputs_incomplete",
    );
    let retained = owner.retained_requested_bytes().unwrap();
    if case == "initial_inputs_unchecked" {
        owner.initial_reconstructed = false;
    }
    if case == "initial_inputs_expired" {
        owner.cut = OperationalDeadline::expired_fixture();
    }
    if case == "initial_inputs_foreign" {
        std::thread::scope(|scope| {
            scope
                .spawn(|| {
                    let mut called = false;
                    assert!(
                        owner
                            .with_completed_inputs_data(|_| {
                                called = true;
                                Ok(())
                            })
                            .is_err()
                    );
                    assert!(!called);
                })
                .join()
                .unwrap();
        });
        assert_eq!(owner.retained_requested_bytes().unwrap(), retained);
        return;
    }

    let mut called = false;
    let outcome = owner.with_completed_inputs_data(|loans| {
        called = true;
        assert!(std::ptr::eq(
            loans.recipe,
            owner.parsed.bodies_data().unwrap().recipe
        ));
        let expected = references();
        for (index, (reference, body)) in loans.inputs.into_iter().enumerate() {
            assert_eq!(reference, &expected[index]);
            assert_eq!(body, bodies()[index]);
            assert!(std::ptr::eq(
                reference,
                owner.inputs.references_data().unwrap()[index]
            ));
            assert!(std::ptr::eq(
                body.as_ptr(),
                owner.inputs.bodies_data().unwrap()[index].as_ptr()
            ));
        }
        if case == "initial_inputs_terminal_expired" {
            // The original operational cut advances during the real callback;
            // no copied deadline or caller-provided row can renew it.
            std::thread::sleep(Duration::from_secs(5));
        }
        if case == "initial_inputs_callback_error" {
            return Err(ProviderError::Conflict("actual input inspection refused"));
        }
        Ok(())
    });
    match case {
        "initial_inputs_complete" => {
            outcome.unwrap();
            assert!(called);
        }
        "initial_inputs_callback_error" => {
            assert!(called);
            assert!(matches!(
                outcome,
                Err(ProviderError::Conflict("actual input inspection refused"))
            ));
        }
        "initial_inputs_terminal_expired" => {
            assert!(called);
            assert!(outcome.is_err());
        }
        _ => {
            assert!(!called);
            assert!(outcome.is_err());
        }
    }
    assert_eq!(owner.retained_requested_bytes().unwrap(), retained);
    assert!(OriginalImport18RawBootstrap::completed_input_loan_counter_scratch_data::<()>() > 0);
}

#[test]
fn original_completed_input_loans_match_actual_banks_and_retain_refusal_custody() {
    for case in [
        "initial_inputs_complete",
        "initial_inputs_swapped",
        "initial_inputs_incomplete",
        "initial_inputs_unchecked",
        "initial_inputs_expired",
        "initial_inputs_foreign",
        "initial_inputs_terminal_expired",
        "initial_inputs_callback_error",
    ] {
        flight(case);
    }
}
