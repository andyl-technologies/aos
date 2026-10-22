//! Exercises typed DATA custody on actual inherited channels and original SDKs.

use super::*;
use crate::reference_packet::service::complete_restore::PACKET_COMPLETE_RESTORE_ALGORITHM;
use crate::reference_packet::service::complete_restore::import18::bootstrap_ack::{
    NATIVE_IMPORT18_BOOTSTRAP_ACK_PROOF, NATIVE_IMPORT18_BOOTSTRAP_REQUEST_SCHEMA,
};
use crate::reference_packet::service::complete_restore::import18::{
    NATIVE_IMPORT18_PRIVATE_PREFIX_BYTES, PacketNativeImport18PrebirthRecipeWireData,
    PacketNativeImport18SelectedLaunchWireData, decode_native_import18_private_prefix_data,
};
use crucible_node_format::Bytes;
use std::{cell::Cell, io::Write};

const PREFIX: &str = "initial_policy_kernel_normalizations_host_codec_";

/// Builds public DATA from the parent's actual committed private wire fixture.
pub(in super::super::super) fn write_parent_frame(case: &str, peer: &mut UnixStream, wire: &[u8]) {
    let prefix = decode_native_import18_private_prefix_data(
        &wire[..NATIVE_IMPORT18_PRIVATE_PREFIX_BYTES],
        [usize::MAX; 3],
        usize::MAX,
    )
    .unwrap();
    let lengths = prefix.body_lengths_data().unwrap();
    let recipe_end = NATIVE_IMPORT18_PRIVATE_PREFIX_BYTES + lengths[0];
    let recipe: PacketNativeImport18PrebirthRecipeWireData =
        serde_json::from_slice(&wire[NATIVE_IMPORT18_PRIVATE_PREFIX_BYTES..recipe_end]).unwrap();
    let selected: PacketNativeImport18SelectedLaunchWireData =
        serde_json::from_slice(&wire[recipe_end..recipe_end + lengths[1]]).unwrap();
    let binding = &selected.launch_data().selection.realization.bindings[0];
    let mut value = serde_json::json!({
        "protocol": "CNP/1", "message": "request", "session_id": binding.authority.session_id,
        "incarnation_id": binding.authority.incarnation_id, "node_id": null,
        "execution_owner_id": null, "capture_owner_id": null, "request_id": "bootstrap",
        "operation_id": null, "sequence": "2", "method": "native_import18_bootstrap",
        "body": {"schema": NATIVE_IMPORT18_BOOTSTRAP_REQUEST_SCHEMA,
            "recipe_identity": Bytes::new(recipe.announced_identity_data().to_vec()),
            "initial_funding": prefix.initial_funding_data().unwrap()},
        "extensions": {(NATIVE_IMPORT18_BOOTSTRAP_ACK_PROOF): {
            "schema": NATIVE_IMPORT18_BOOTSTRAP_ACK_PROOF, "algorithm": PACKET_COMPLETE_RESTORE_ALGORITHM,
            "context_digest": Bytes::new(vec![0; 32]), "mac": Bytes::new(vec![0; 32])}},
    });
    let suffix = case.strip_prefix(PREFIX).unwrap();
    match suffix {
        "extra" => value["extra"] = serde_json::json!(true),
        "missing" => {
            value.as_object_mut().unwrap().remove("operation_id");
        }
        "nested_extra" => value["body"]["extra"] = serde_json::json!(true),
        "algorithm" => {
            value["extensions"][NATIVE_IMPORT18_BOOTSTRAP_ACK_PROOF]["algorithm"] =
                serde_json::json!("foreign")
        }
        "id" => value["operation_id"] = serde_json::json!("invalid id"),
        "numeric" => value["sequence"] = serde_json::json!("18446744073709551616"),
        "sequence" => value["sequence"] = serde_json::json!("3"),
        "session" => value["session_id"] = serde_json::json!("foreign"),
        "incarnation" => value["incarnation_id"] = serde_json::json!("foreign"),
        "recipe_decode" => value["body"]["recipe_identity"] = serde_json::json!("!".repeat(43)),
        "recipe_join" => {
            value["body"]["recipe_identity"] = serde_json::json!(Bytes::new(vec![7; 32]))
        }
        "initial_decode" => {
            value["body"]["initial_funding"]["retained_requested_bytes"] =
                serde_json::json!("18446744073709551616")
        }
        "initial_join" => {
            value["body"]["initial_funding"]["retained_requested_bytes"] = serde_json::json!("1")
        }
        "proof_decode" => {
            value["extensions"][NATIVE_IMPORT18_BOOTSTRAP_ACK_PROOF]["mac"] =
                serde_json::json!("!".repeat(43))
        }
        _ => {}
    }
    let body = serde_json::to_vec(&value).unwrap();
    peer.write_all(&(body.len() as u32).to_be_bytes()).unwrap();
    peer.write_all(&body).unwrap();
    peer.write_all(b"unconsumed suffix").unwrap();
}

struct Model<'a> {
    suffix: &'a str,
    retained: [usize; 4],
    calls: Cell<usize>,
}

impl Model<'_> {
    fn census(
        &self,
        original: &OriginalImport18RawBootstrap,
        normalizations: &Normalizations,
        literal: &Literal,
        parsed: &Parsed,
    ) {
        assert_eq!(
            [
                original.retained_requested_bytes().unwrap(),
                normalizations
                    .retained_requested_bytes_data(original)
                    .unwrap(),
                literal.retained_requested_bytes_data(original).unwrap(),
                parsed.retained_requested_bytes_data(original).unwrap(),
            ],
            self.retained
        );
    }

    fn action(
        &self,
        original: &OriginalImport18RawBootstrap,
        label: &str,
    ) -> Result<(), ProviderError> {
        if self.suffix == format!("expire_{label}") {
            std::thread::sleep(Duration::from_secs(5));
        }
        if self.suffix == format!("revoke_{label}") {
            original
                .hello_registrar
                .retained_authority_fixture_data()
                .unwrap()
                .revoke_epoch_fixture_data();
        }
        if self.suffix == format!("reject_{label}") {
            return Err(ProviderError::Conflict("typed codec admission model"));
        }
        Ok(())
    }
}

impl Admission for Model<'_> {
    fn construct_data(
        &self,
        original: &OriginalImport18RawBootstrap,
        normalizations: &Normalizations,
        literal: &Literal,
        parsed: &Parsed,
        attempt: &Attempt,
        row: [usize; 3],
    ) -> Result<(), ProviderError> {
        assert_eq!(self.calls.replace(1), 0);
        self.census(original, normalizations, literal, parsed);
        assert!(original.bootstrap_codec_started && attempt.started);
        assert_eq!(attempt.row, Some(row));
        assert_eq!(
            attempt.retained_requested_bytes_data(original).unwrap(),
            size_of::<Attempt>()
        );
        assert!(attempt.envelope.is_none() && attempt.request.is_none() && attempt.proof.is_none());
        self.action(original, "construction")
    }

    fn observe_data(
        &self,
        original: &OriginalImport18RawBootstrap,
        normalizations: &Normalizations,
        literal: &Literal,
        parsed: &Parsed,
        attempt: &Attempt,
        step: Option<Step>,
        actual: usize,
    ) -> Result<(), ProviderError> {
        println!(
            "bootstrap fixture codec observe {step:?} before census: remaining={:?}",
            original.cut.remaining()
        );
        let call = self.calls.get();
        self.calls.set(call + 1);
        self.census(original, normalizations, literal, parsed);
        assert_eq!(
            actual,
            attempt.retained_requested_bytes_data(original).unwrap()
        );
        assert!(actual <= attempt.row.unwrap()[0]);
        let label = match step {
            None => {
                assert_eq!(call, 1);
                assert!(attempt.envelope.is_none());
                "preflight"
            }
            Some(Step::Envelope) => {
                assert_eq!(call, 1);
                "envelope"
            }
            Some(Step::Request) => {
                assert_eq!(call, 2);
                assert!(attempt.envelope.is_some());
                "request"
            }
            Some(Step::Proof) => {
                assert_eq!(call, 3);
                assert!(attempt.envelope.is_some() && attempt.request.is_some());
                "proof"
            }
        };
        println!(
            "bootstrap fixture codec observe {step:?} after census: remaining={:?}",
            original.cut.remaining()
        );
        self.action(original, label)
    }
}

/// Checks retained prefixes and once-only failure under the real current SDK.
pub(in super::super::super) fn assert_child(
    case: &str,
    original: &mut OriginalImport18RawBootstrap,
) {
    let suffix = case.strip_prefix(PREFIX).unwrap();
    let (normalizations, literal, parsed) =
        super::super::bootstrap_value::tests::complete_for_codec(original);
    let mut attempt = Attempt::empty_data();
    let model = Model {
        suffix,
        retained: [
            original.retained_requested_bytes().unwrap(),
            normalizations
                .retained_requested_bytes_data(original)
                .unwrap(),
            literal.retained_requested_bytes_data(original).unwrap(),
            parsed.retained_requested_bytes_data(original).unwrap(),
        ],
        calls: Cell::new(0),
    };
    let raw = original.bodies.each_ref().map(Vec::as_ptr);
    let launch = Rc::as_ptr(original.parsed.shared_launch_data().unwrap());
    let cut = original.cut;
    if suffix == "changed_cut" {
        original.cut = OperationalDeadline::after(Duration::from_secs(3)).unwrap();
    }
    let outcome = original.decode_bootstrap_codec_data(
        &normalizations,
        &literal,
        &parsed,
        &mut attempt,
        &model,
    );
    let success = matches!(
        suffix,
        "complete" | "reactive" | "callback_refused" | "loan_expired"
    );
    assert_eq!(
        outcome.is_ok(),
        success,
        "{case}: {outcome:?}; expired={}",
        original.cut.is_expired()
    );
    assert!(original.bootstrap_codec_started && attempt.started);
    assert_eq!(attempt.complete, success);
    assert_eq!(attempt.failed, !success);
    model.census(original, &normalizations, &literal, &parsed);
    assert_eq!(original.bodies.each_ref().map(Vec::as_ptr), raw);
    assert_eq!(
        Rc::as_ptr(original.parsed.shared_launch_data().unwrap()),
        launch
    );
    let calls = match suffix {
        "changed_cut" => 0,
        "reject_construction" | "expire_construction" | "revoke_construction" => 1,
        "extra" | "missing" | "nested_extra" | "algorithm" | "id" | "numeric" | "sequence"
        | "session" | "incarnation" | "reject_envelope" | "expire_envelope" | "revoke_envelope" => {
            2
        }
        "recipe_decode" | "recipe_join" | "initial_decode" | "initial_join" | "reject_request"
        | "expire_request" | "revoke_request" => 3,
        _ => 4,
    };
    assert_eq!(model.calls.get(), calls);
    assert_eq!(
        attempt.envelope.is_some(),
        calls >= 2
            && !matches!(
                suffix,
                "extra" | "missing" | "nested_extra" | "algorithm" | "id" | "numeric"
            )
    );
    assert_eq!(
        attempt.request.is_some(),
        calls >= 3 && !matches!(suffix, "recipe_decode" | "initial_decode")
    );
    assert_eq!(
        attempt.proof.is_some(),
        calls >= 4 && suffix != "proof_decode"
    );
    if matches!(
        suffix,
        "id" | "numeric" | "recipe_decode" | "initial_decode" | "proof_decode"
    ) {
        let failure = attempt.failure.as_ref().unwrap();
        assert!(matches!(
            failure.category,
            serde_json::error::Category::Data
        ));
        assert_eq!((failure.line, failure.column), (0, 0));
    }
    if success {
        let entered = Cell::new(false);
        let loan = attempt.with_request_data(
            original,
            &normalizations,
            &literal,
            &parsed,
            |envelope, request, proof| {
                entered.set(true);
                assert_eq!(envelope.sequence.get(), 2);
                assert_eq!(
                    request.recipe_identity.as_slice(),
                    original
                        .typed_bodies_data()
                        .unwrap()
                        .recipe
                        .announced_identity_data()
                );
                // Structurally valid all-zero proofs are deliberately unauthenticated DATA.
                assert_eq!(proof.mac.as_slice(), &[0; 32]);
                if suffix == "loan_expired" {
                    std::thread::sleep(Duration::from_secs(5));
                }
                if suffix == "callback_refused" {
                    return Err(ProviderError::Conflict("typed loan model"));
                }
                Ok(())
            },
        );
        assert!(entered.get());
        assert_eq!(loan.is_ok(), matches!(suffix, "complete" | "reactive"));
    } else {
        assert!(
            attempt
                .with_request_data::<()>(
                    original,
                    &normalizations,
                    &literal,
                    &parsed,
                    |_, _, _| panic!("failed DTO loan entered")
                )
                .is_err()
        );
    }
    let retained = attempt.retained_requested_bytes_data(original).unwrap();
    let pointers = (
        attempt.envelope.as_ref().map(std::ptr::from_ref),
        attempt.request.as_ref().map(std::ptr::from_ref),
        attempt.proof.as_ref().map(std::ptr::from_ref),
    );
    original.cut = cut;
    assert!(
        original
            .decode_bootstrap_codec_data(&normalizations, &literal, &parsed, &mut attempt, &model)
            .is_err()
    );
    assert!(
        original
            .decode_bootstrap_codec_data(
                &normalizations,
                &literal,
                &parsed,
                &mut Attempt::empty_data(),
                &model
            )
            .is_err()
    );
    assert_eq!(model.calls.get(), calls);
    assert_eq!(
        attempt.retained_requested_bytes_data(original).unwrap(),
        retained
    );
    assert_eq!(
        (
            attempt.envelope.as_ref().map(std::ptr::from_ref),
            attempt.request.as_ref().map(std::ptr::from_ref),
            attempt.proof.as_ref().map(std::ptr::from_ref)
        ),
        pointers
    );
}

#[test]
fn typed_quote_checks_exact_peak_and_counts_real_base64_decoder_capacity() {
    use crate::reference_packet::service::complete_restore::import18::inert_bootstrap_fixtures;
    let selected: PacketNativeImport18SelectedLaunchWireData =
        serde_json::from_value(inert_bootstrap_fixtures::initial_selected_launch(false)).unwrap();
    let row = construction_data(selected.launch_data(), usize::MAX).unwrap();
    let peak = row.into_iter().sum::<usize>();
    assert_eq!(
        construction_data(selected.launch_data(), peak).unwrap(),
        row
    );
    assert!(construction_data(selected.launch_data(), peak - 1).is_err());
    assert_eq!(
        construction_data(selected.launch_data(), peak + 4096).unwrap(),
        row
    );
    let bytes: Bytes = serde_json::from_value(serde_json::json!("A".repeat(43))).unwrap();
    assert_eq!(bytes.as_slice().len(), 32);
    assert_eq!(bytes.allocation_capacity(), 33);
    assert!(
        Attempt::request_loan_counter_scratch_data::<[u8; 4096]>().unwrap()
            >= Attempt::request_loan_counter_scratch_data::<()>().unwrap() + 4096
    );
}

#[test]
fn closed_maximum_covers_actual_nullable_ids_maps_and_three_decoded_banks() {
    let mut value = serde_json::json!({
        "protocol": "CNP/1", "message": "request", "method": "native_import18_bootstrap",
        "session_id": null, "incarnation_id": null, "node_id": null,
        "execution_owner_id": null, "capture_owner_id": null, "request_id": null,
        "operation_id": null, "sequence": u64::MAX.to_string(),
        "body": {"schema": NATIVE_IMPORT18_BOOTSTRAP_REQUEST_SCHEMA,
            "recipe_identity": "A".repeat(43), "initial_funding": {
                "retained_requested_bytes": u64::MAX.to_string(),
                "maximum_simultaneous_transient_bytes": u64::MAX.to_string(),
                "declared_counter_scratch_bytes": u64::MAX.to_string()}},
        "extensions": {(NATIVE_IMPORT18_BOOTSTRAP_ACK_PROOF): {
            "schema": NATIVE_IMPORT18_BOOTSTRAP_ACK_PROOF,
            "algorithm": PACKET_COMPLETE_RESTORE_ALGORITHM,
            "context_digest": "A".repeat(43), "mac": "A".repeat(43)}},
    });
    for field in [
        "session_id",
        "incarnation_id",
        "node_id",
        "execution_owner_id",
        "capture_owner_id",
        "request_id",
        "operation_id",
    ] {
        value[field] = serde_json::json!("a".repeat(crucible_node_format::values::MAX_ID_BYTES));
    }
    let closed = prewalk::inspect_data(&value).unwrap();
    let mut attempt = Attempt::empty_data();
    attempt.envelope = Some(serde::Deserialize::deserialize(&value).unwrap());
    attempt.request = Some(serde::Deserialize::deserialize(closed.request).unwrap());
    attempt.proof = Some(serde::Deserialize::deserialize(closed.proof).unwrap());
    let row = storage::construction_data(usize::MAX).unwrap();
    assert!(attempt.requested_storage_data().unwrap() <= row[0]);
    assert_eq!(
        attempt
            .request
            .as_ref()
            .unwrap()
            .recipe_identity
            .allocation_capacity(),
        33
    );
    assert_eq!(
        attempt
            .proof
            .as_ref()
            .unwrap()
            .context_digest
            .allocation_capacity(),
        33
    );
    assert_eq!(
        attempt.proof.as_ref().unwrap().mac.allocation_capacity(),
        33
    );

    value["operation_id"] =
        serde_json::json!("a".repeat(crucible_node_format::values::MAX_ID_BYTES + 1));
    assert!(prewalk::inspect_data(&value).is_err());
    value["operation_id"] = Value::Null;
    value["extensions"]["extra"] = serde_json::json!({});
    assert!(prewalk::inspect_data(&value).is_err());
}

/// Completes typed DATA without opening another full original loan.
pub(in super::super::super) fn complete_for_correlation(
    original: &mut OriginalImport18RawBootstrap,
) -> (Normalizations, Literal, Parsed, Attempt) {
    println!(
        "bootstrap fixture codec inputs begin: remaining={:?}",
        original.cut.remaining()
    );
    let (normalizations, literal, parsed) =
        super::super::bootstrap_value::tests::complete_for_codec(original);
    println!(
        "bootstrap fixture codec inputs complete: remaining={:?}",
        original.cut.remaining()
    );
    let mut attempt = Attempt::empty_data();
    let model = Model {
        suffix: "complete",
        retained: [
            original.retained_requested_bytes().unwrap(),
            normalizations
                .retained_requested_bytes_data(original)
                .unwrap(),
            literal.retained_requested_bytes_data(original).unwrap(),
            parsed.retained_requested_bytes_data(original).unwrap(),
        ],
        calls: Cell::new(0),
    };
    original
        .decode_bootstrap_codec_data(&normalizations, &literal, &parsed, &mut attempt, &model)
        .unwrap_or_else(|error| {
            panic!(
                "bootstrap codec fixture preparation: {error:?}; step={:?}; expired={}",
                attempt.step,
                original.cut.is_expired()
            )
        });
    assert_eq!(model.calls.get(), 4);
    (normalizations, literal, parsed, attempt)
}
