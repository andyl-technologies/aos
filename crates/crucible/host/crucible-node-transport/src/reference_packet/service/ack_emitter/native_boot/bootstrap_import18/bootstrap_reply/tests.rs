//! Exercises actual retained reply construction on independent inherited flights.

use super::*;
use std::cell::Cell;

const PREFIX: &str = "initial_policy_kernel_normalizations_host_reply_";

struct Model<'a> {
    suffix: &'a str,
    retained: [usize; 7],
    calls: Cell<usize>,
}

impl Model<'_> {
    fn census(&self, inputs: Inputs<'_>) {
        let prior = inputs.prior.prior;
        let mut expected = self.retained;
        let proof = inputs
            .proof
            .retained_requested_bytes_data(prior.original)
            .unwrap();
        if proof == size_of::<Proof>() {
            expected[6] = proof;
        }
        assert_eq!(
            [
                prior.original.retained_requested_bytes().unwrap(),
                prior
                    .normalizations
                    .retained_requested_bytes_data(prior.original)
                    .unwrap(),
                prior
                    .literal
                    .retained_requested_bytes_data(prior.original)
                    .unwrap(),
                prior
                    .parsed
                    .retained_requested_bytes_data(prior.original)
                    .unwrap(),
                prior
                    .codec
                    .retained_requested_bytes_data(prior.original)
                    .unwrap(),
                inputs
                    .prior
                    .correlation
                    .retained_requested_bytes_data(prior.original)
                    .unwrap(),
                inputs
                    .proof
                    .retained_requested_bytes_data(prior.original)
                    .unwrap(),
            ],
            expected
        );
    }

    fn action(&self, inputs: Inputs<'_>, label: &str) -> Result<(), ProviderError> {
        if self.suffix == format!("expire_{label}") {
            std::thread::sleep(Duration::from_secs(5));
        }
        if self.suffix == format!("revoke_{label}") {
            inputs
                .prior
                .prior
                .original
                .hello_registrar
                .retained_authority_fixture_data()
                .unwrap()
                .revoke_epoch_fixture_data();
        }
        if self.suffix == format!("reject_{label}") {
            return Err(ProviderError::Conflict("bootstrap reply admission model"));
        }
        Ok(())
    }
}

impl Admission for Model<'_> {
    fn construct_data(
        &self,
        inputs: Inputs<'_>,
        attempt: &Attempt,
        row: [usize; 3],
    ) -> Result<(), ProviderError> {
        super::super::bootstrap_proof::tests::assert_reply_verification_pending(inputs.proof);
        assert!(
            inputs
                .proof
                .with_verified_context_data::<()>(inputs.prior, |_| panic!(
                    "pending verification escaped aggregate"
                ))
                .is_err()
        );
        assert_eq!(self.calls.replace(1), 0);
        self.census(inputs);
        assert!(attempt.started && inputs.prior.prior.original.bootstrap_reply_started);
        assert_eq!(attempt.row, Some(row));
        assert!(
            attempt.result.is_none()
                && attempt.envelope.is_none()
                && attempt.assigned.is_none()
                && attempt.receipt.is_none()
        );
        assert_eq!(
            attempt
                .retained_requested_bytes_data(inputs.prior.prior.original)
                .unwrap(),
            size_of::<Attempt>()
        );
        self.action(inputs, "construction")
    }

    fn step_data(
        &self,
        inputs: Inputs<'_>,
        attempt: &Attempt,
        step: Step,
    ) -> Result<(), ProviderError> {
        super::super::bootstrap_proof::tests::assert_reply_verification_pending(inputs.proof);
        assert!(
            inputs
                .proof
                .with_verified_context_data::<()>(inputs.prior, |_| panic!(
                    "pending verification escaped aggregate"
                ))
                .is_err()
        );
        let (index, label) = match step {
            Step::Result => (1, "result"),
            Step::Envelope => (3, "envelope"),
            Step::Assigned => (5, "assignment"),
            Step::Receipt => (7, "receipt"),
            Step::Seal => (9, "seal"),
            Step::ReserveLiteral => (11, "literal_reservation"),
            Step::SerializeLiteral => (13, "literal_value"),
            Step::MeasureLiteral => (15, "literal_measurement"),
            Step::EncodeLiteral => (17, "literal_encoding"),
        };
        assert_eq!(self.calls.replace(index + 1), index);
        assert_eq!(attempt.result.is_some(), index >= 3);
        assert_eq!(attempt.envelope.is_some(), index >= 5);
        assert_eq!(attempt.assigned.is_some(), index >= 7);
        assert_eq!(attempt.receipt.is_some(), index >= 9);
        self.action(inputs, label)
    }

    fn observe_data(
        &self,
        inputs: Inputs<'_>,
        attempt: &Attempt,
        step: Step,
        actual: usize,
    ) -> Result<(), ProviderError> {
        self.census(inputs);
        assert_eq!(
            attempt
                .retained_requested_bytes_data(inputs.prior.prior.original)
                .unwrap(),
            actual
        );
        assert!(actual <= attempt.row.unwrap()[0]);
        super::super::bootstrap_proof::tests::assert_reply_verification_pending(inputs.proof);
        assert!(
            inputs
                .proof
                .with_verified_context_data::<()>(inputs.prior, |_| panic!(
                    "pending verification escaped aggregate"
                ))
                .is_err()
        );
        let (index, label) = match step {
            Step::Result => (2, "result_built"),
            Step::Envelope => (4, "envelope_built"),
            Step::Assigned => (6, "assigned"),
            Step::Receipt => (8, "receipt_built"),
            Step::Seal => (10, "sealed"),
            Step::ReserveLiteral => (12, "literal_reserved"),
            Step::SerializeLiteral => (14, "literal_serialized"),
            Step::MeasureLiteral => (16, "literal_measured"),
            Step::EncodeLiteral => (18, "literal_encoded"),
        };
        assert_eq!(self.calls.replace(index + 1), index);
        assert!(attempt.result.is_some());
        assert_eq!(attempt.envelope.is_some(), index >= 4);
        assert_eq!(attempt.assigned.is_some(), index >= 6);
        assert_eq!(attempt.receipt.is_some(), index >= 8);
        if let Some(receipt) = &attempt.receipt {
            assert_eq!(
                receipt.assigned_response.as_slice(),
                attempt.assigned.unwrap()
            );
        }
        if step == Step::Seal {
            let result = attempt.result.as_ref().unwrap();
            let reply = attempt.envelope.as_ref().unwrap();
            let receipt = attempt.receipt.as_ref().unwrap();
            assert_eq!(reply.sequence.get(), 2);
            assert_eq!(
                reply.method,
                crate::envelope::Method::NativeImport18Bootstrap
            );
            assert_eq!(reply.message, crate::envelope::MessageKind::Response);
            assert_eq!(reply.body.len(), 4);
            let completed = crate::bodies::decode_response_shape(&reply.body).unwrap();
            crucible_node_format::Validate::validate(&completed).unwrap();
            assert!(matches!(
                completed,
                crate::bodies::ResponseShape::Completed { .. }
            ));
            assert_eq!(reply.body["status"], "completed");
            assert_eq!(reply.body["result"], serde_json::to_value(result).unwrap());
            assert_eq!(reply.extensions.len(), 1);
            assert_eq!(
                reply.extensions[NATIVE_IMPORT18_BOOTSTRAP_ACK_RECEIPT],
                serde_json::to_value(receipt).unwrap()
            );
            receipt.validate_data().unwrap();
            assert_eq!(
                receipt.state,
                PacketNativeImport18BootstrapAckState::BootstrapOnly
            );
            assert_eq!(
                receipt.assigned_response.as_slice(),
                attempt.assigned.unwrap()
            );
            super::super::bootstrap_proof::tests::assert_reply_receipt(
                inputs.proof,
                inputs.prior.prior.original,
                &attempt.assigned.unwrap(),
                receipt,
            );
        }
        if step == Step::EncodeLiteral {
            attempt
                .literal
                .assert_prepared_data(attempt.envelope.as_ref().unwrap());
        }
        self.action(inputs, label)
    }
}

/// Preserves every predecessor and reply output across refusal and retry.
pub(in super::super::super) fn assert_child(
    case: &str,
    original: &mut OriginalImport18RawBootstrap,
) {
    let suffix = case.strip_prefix(PREFIX).unwrap();
    let (normalizations, literal, parsed, codec, mut correlation, mut proof) =
        super::super::bootstrap_proof::tests::complete_for_reply(original);
    let mut attempt = Attempt::empty_data();
    let model = Model {
        suffix,
        calls: Cell::new(0),
        retained: [
            original.retained_requested_bytes().unwrap(),
            normalizations
                .retained_requested_bytes_data(original)
                .unwrap(),
            literal.retained_requested_bytes_data(original).unwrap(),
            parsed.retained_requested_bytes_data(original).unwrap(),
            codec.retained_requested_bytes_data(original).unwrap(),
            correlation.retained_requested_bytes_data(original).unwrap(),
            super::super::bootstrap_proof::construction_data(
                original.parsed.bodies_data().unwrap().launch.launch_data(),
                usize::MAX,
            )
            .unwrap()[0],
        ],
    };
    let pointers = original.bodies.each_ref().map(Vec::as_ptr);
    let launch = Rc::as_ptr(original.parsed.shared_launch_data().unwrap());
    let cut = original.cut;
    if suffix == "changed_cut" {
        original.cut = OperationalDeadline::after(Duration::from_secs(3)).unwrap();
    }
    let outcome = if suffix == "missing_proof" {
        original.construct_bootstrap_reply_data(
            &normalizations,
            &literal,
            &parsed,
            &codec,
            &mut correlation,
            &proof,
            &mut attempt,
            &model,
        )
    } else {
        super::super::bootstrap_proof::tests::verify_and_construct_reply(
            original,
            &normalizations,
            &literal,
            &parsed,
            &codec,
            &mut correlation,
            &mut proof,
            &mut attempt,
            &model,
        )
    };
    let success = matches!(suffix, "complete" | "reactive");
    assert_eq!(
        outcome.is_ok(),
        success,
        "{case}: {outcome:?}; step={:?}; expired={}",
        attempt.step,
        original.cut.is_expired()
    );
    assert!(attempt.started && original.bootstrap_reply_started);
    assert_eq!(attempt.complete, success);
    assert_eq!(attempt.failed, !success);
    if suffix != "missing_proof" {
        super::super::bootstrap_proof::tests::assert_reply_aggregate_outcome(&proof, success);
    }
    let inputs = Inputs {
        prior: proof::Inputs {
            prior: super::super::bootstrap_correlation::Inputs {
                original,
                normalizations: &normalizations,
                literal: &literal,
                parsed: &parsed,
                codec: &codec,
            },
            correlation: &correlation,
        },
        proof: &proof,
    };
    model.census(inputs);
    assert_eq!(original.bodies.each_ref().map(Vec::as_ptr), pointers);
    assert_eq!(
        Rc::as_ptr(original.parsed.shared_launch_data().unwrap()),
        launch
    );
    if success {
        assert_eq!(model.calls.get(), 19);
    } else {
        assert!(
            correlation
                .with_received_data::<()>(inputs.prior.prior, |_, _| panic!(
                    "failed reply correlation entered"
                ))
                .is_err()
        );
        super::super::bootstrap_correlation::tests::assert_fenced_record(&mut correlation);
    }
    let proof_retained = proof.retained_requested_bytes_data(original).unwrap();
    let retained = attempt.retained_requested_bytes_data(original).unwrap();
    let envelope = attempt.envelope.as_ref().map(std::ptr::from_ref);
    let receipt = attempt.receipt.as_ref().map(std::ptr::from_ref);
    original.cut = cut;
    assert!(
        super::super::bootstrap_proof::tests::verify_and_construct_reply(
            original,
            &normalizations,
            &literal,
            &parsed,
            &codec,
            &mut correlation,
            &mut proof,
            &mut attempt,
            &model
        )
        .is_err()
    );
    assert_eq!(
        proof.retained_requested_bytes_data(original).unwrap(),
        proof_retained
    );
    assert!(
        original
            .construct_bootstrap_reply_data(
                &normalizations,
                &literal,
                &parsed,
                &codec,
                &mut correlation,
                &proof,
                &mut attempt,
                &model
            )
            .is_err()
    );
    assert!(
        original
            .construct_bootstrap_reply_data(
                &normalizations,
                &literal,
                &parsed,
                &codec,
                &mut correlation,
                &proof,
                &mut Attempt::empty_data(),
                &model
            )
            .is_err()
    );
    assert_eq!(
        attempt.retained_requested_bytes_data(original).unwrap(),
        retained
    );
    assert_eq!(attempt.envelope.as_ref().map(std::ptr::from_ref), envelope);
    assert_eq!(attempt.receipt.as_ref().map(std::ptr::from_ref), receipt);
}

#[test]
fn reply_quote_uses_exact_independent_peak_and_refuses_short_credit() {
    let selected: PacketNativeImport18SelectedLaunchWireData = serde_json::from_value(
        crate::reference_packet::service::complete_restore::import18::inert_bootstrap_fixtures::initial_selected_launch(false)).unwrap();
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
}

#[test]
fn reply_closed_population_covers_maximal_actual_outputs_and_serializer_trees() {
    use crate::envelope::{MessageKind, Method, Nullable};
    use crate::reference_packet::service::complete_restore::import18::bootstrap_ack::{
        NATIVE_IMPORT18_BOOTSTRAP_ACK_CONTEXT, NATIVE_IMPORT18_BOOTSTRAP_ACK_PROOF,
        NATIVE_IMPORT18_BOOTSTRAP_REQUEST_SCHEMA,
        native_import18_bootstrap_ack_assigned_request_digest,
        native_import18_bootstrap_ack_proof_data, native_import18_bootstrap_ack_receipt_data,
        verify_native_import18_bootstrap_ack_receipt_data,
    };
    use crate::reference_packet::service::native_startup::PacketNativeStartupAllocationRow;
    use crucible_node_format::{Id, U64, canonical, values::MAX_ID_BYTES};
    use serde_json::Value;
    use std::collections::BTreeSet;

    let identifier = Id::new("x".repeat(MAX_ID_BYTES)).unwrap();
    let initial = PacketNativeStartupAllocationRow {
        retained_requested_bytes: U64::new(10_000_000_000_000_000_000),
        maximum_simultaneous_transient_bytes: U64::new(1),
        declared_counter_scratch_bytes: U64::new(1),
    };
    let request = Request {
        schema: NATIVE_IMPORT18_BOOTSTRAP_REQUEST_SCHEMA.into(),
        recipe_identity: Bytes::new(vec![9; 32]),
        initial_funding: initial,
    };
    let mut original = crate::envelope::tests::request();
    original.method = Method::NativeImport18Bootstrap;
    original.sequence = U64::new(2);
    for field in [
        &mut original.session_id,
        &mut original.incarnation_id,
        &mut original.node_id,
        &mut original.execution_owner_id,
        &mut original.capture_owner_id,
        &mut original.request_id,
        &mut original.operation_id,
    ] {
        *field = Nullable(Some(identifier.clone()));
    }
    original.body = serde_json::to_value(&request)
        .unwrap()
        .as_object()
        .unwrap()
        .clone();
    original.extensions.clear();
    let mut context = Context {
        schema: NATIVE_IMPORT18_BOOTSTRAP_ACK_CONTEXT.into(),
        algorithm: PACKET_COMPLETE_RESTORE_ALGORITHM.into(),
        source_birth: Bytes::new(vec![1; 32]),
        kernel_binding: Bytes::new(vec![2; 32]),
        policy_binding: Bytes::new(vec![3; 32]),
        host_registration: Bytes::new(vec![4; 32]),
        native_registration: Bytes::new(vec![5; 32]),
        hello_request: Bytes::new(vec![6; 32]),
        hello_response: Bytes::new(vec![7; 32]),
        assigned_request: Bytes::new(vec![8; 32]),
        recipe_identity: request.recipe_identity.clone(),
        initial_funding: initial,
    };
    let maximum = crate::transport::MAX_FRAME_BYTES;
    context.assigned_request = Bytes::new(
        native_import18_bootstrap_ack_assigned_request_digest(&original, maximum)
            .unwrap()
            .to_vec(),
    );
    let key = [11; 32];
    let proof = native_import18_bootstrap_ack_proof_data(&key, &context).unwrap();
    original.extensions.insert(
        NATIVE_IMPORT18_BOOTSTRAP_ACK_PROOF.into(),
        serde_json::to_value(proof).unwrap(),
    );
    let mut guard = crate::session::CorrelationGuard::new(
        identifier.clone(),
        identifier,
        2,
        BTreeSet::from([
            NATIVE_IMPORT18_BOOTSTRAP_ACK_PROOF.into(),
            NATIVE_IMPORT18_BOOTSTRAP_ACK_RECEIPT.into(),
        ]),
    )
    .unwrap();
    assert!(
        guard
            .original_bootstrap_response_sequence_data(&original)
            .is_err()
    );
    guard.receive(&original).unwrap();

    let mut attempt = Attempt::empty_data();
    attempt.result = Some(ReplyResult {
        schema: NATIVE_IMPORT18_BOOTSTRAP_RESULT_SCHEMA.into(),
        state: PacketNativeImport18BootstrapAckState::BootstrapOnly,
        recipe_identity: request.recipe_identity,
        initial_funding: initial,
    });
    attempt.envelope =
        Some(response::build_data(&original, &guard, attempt.result.as_ref().unwrap()).unwrap());
    let assigned = native_import18_bootstrap_ack_assigned_response_digest(
        &original,
        attempt.envelope.as_ref().unwrap(),
        maximum,
    )
    .unwrap();
    attempt.assigned = Some(assigned);
    attempt.receipt =
        Some(native_import18_bootstrap_ack_receipt_data(&key, &context, &assigned).unwrap());
    attempt.envelope.as_mut().unwrap().extensions.insert(
        NATIVE_IMPORT18_BOOTSTRAP_ACK_RECEIPT.into(),
        serde_json::to_value(attempt.receipt.as_ref().unwrap()).unwrap(),
    );
    let reply = attempt.envelope.as_ref().unwrap();
    assert_eq!(reply.message, MessageKind::Response);
    assert_eq!(
        native_import18_bootstrap_ack_assigned_response_digest(&original, reply, maximum).unwrap(),
        assigned
    );
    verify_native_import18_bootstrap_ack_receipt_data(
        &key,
        &context,
        &assigned,
        attempt.receipt.as_ref().unwrap(),
    )
    .unwrap();

    fn population(value: &Value) -> (usize, usize, usize) {
        match value {
            Value::Object(fields) => fields.iter().fold(
                (1, fields.len(), 0),
                |(nodes, members, text), (key, value)| {
                    let nested = population(value);
                    (
                        nodes + 1 + nested.0,
                        members + nested.1,
                        text + key.len() + nested.2,
                    )
                },
            ),
            Value::String(text) => (1, 0, text.len()),
            Value::Array(_) => panic!("unexpected array in the closed reply grammar"),
            _ => (1, 0, 0),
        }
    }

    let value = serde_json::to_value(reply).unwrap();
    let (nodes, members, text) = population(&value);
    let extent = storage::extent_data().unwrap();
    let completed = crate::bodies::decode_response_shape(&reply.body).unwrap();
    crucible_node_format::Validate::validate(&completed).unwrap();
    assert!(matches!(
        completed,
        crate::bodies::ResponseShape::Completed { .. }
    ));
    assert_eq!((nodes, members), (63, 31));
    assert!(text <= extent.maximum_decoded_string_bytes);
    assert!(
        canonical::canonical_json(&value).unwrap().len() <= extent.maximum_canonical_encoded_bytes
    );
    let mut observer = crate::retained_metadata::MetadataObserver::new();
    observer.observe(&value).unwrap();
    let actual =
        crate::retained_metadata::requested_metadata_backing_storage_data(&observer.finish())
            .unwrap();
    assert!(actual + size_of::<Value>() <= extent.value_dom_requested_bytes);
    let selected: PacketNativeImport18SelectedLaunchWireData = serde_json::from_value(
        crate::reference_packet::service::complete_restore::import18::inert_bootstrap_fixtures::initial_selected_launch(false)).unwrap();
    let row = construction_data(selected.launch_data(), usize::MAX).unwrap();
    assert!(storage::retained_data(&attempt).unwrap() <= row[0]);

    attempt
        .literal
        .reserve_data(extent.maximum_canonical_encoded_bytes)
        .unwrap();
    attempt.literal.serialize_data(reply).unwrap();
    attempt.literal.measure_data(maximum, 64).unwrap();
    attempt
        .literal
        .encode_data(reply.request_id.0.as_ref().unwrap())
        .unwrap();
    attempt.literal.assert_prepared_data(reply);
    assert!(storage::retained_data(&attempt).unwrap() <= row[0]);

    guard.register_outgoing(reply.clone()).unwrap();
    assert!(
        guard
            .original_bootstrap_response_sequence_data(&original)
            .is_err()
    );
    assert_eq!(guard.incoming_requests().count(), 1);
    guard.confirm_response_sent(reply).unwrap();
    assert!(
        guard
            .original_bootstrap_response_sequence_data(&original)
            .is_err()
    );
    assert_eq!(guard.incoming_requests().count(), 0);
}
