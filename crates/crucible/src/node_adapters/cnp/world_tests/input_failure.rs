//! Native accepted-input transcripts and exact unresolved custody assertions.

use std::cell::Cell;

use super::*;
use crate::node_contract::EffectKnowledge;
use crate::node_scheduling::RuntimeInputBatch;

/// Retains bounded actual authenticated input frames before a test-only rejection.
#[derive(Default)]
pub(super) struct InputTranscript {
    requests: RefCell<BTreeMap<Id, Envelope>>,
    responses: RefCell<BTreeMap<Id, Envelope>>,
    pub(super) reject_completed: Cell<bool>,
}

impl BodySchemaVerifier for InputTranscript {
    fn verify(
        &self,
        authority: &ConnectionAuthority,
        envelope: &Envelope,
        body: &ReceivedBody,
    ) -> Result<(), ProviderError> {
        Schemas.verify(authority, envelope, body)?;
        if envelope.method != Method::Input {
            return Ok(());
        }
        let request_id = envelope
            .request_id
            .0
            .as_ref()
            .ok_or(ProviderError::Correlation("actual input request ID absent"))?;
        match body {
            ReceivedBody::Request(_) => {
                let mut requests = self.requests.borrow_mut();
                assert!(requests.len() < 4 || requests.contains_key(request_id));
                if let Some(original) = requests.insert(request_id.clone(), envelope.clone()) {
                    assert_eq!(original, *envelope);
                }
            }
            ReceivedBody::Response(response) => {
                let mut responses = self.responses.borrow_mut();
                assert!(responses.len() < 4 || responses.contains_key(request_id));
                if let Some(original) = responses.insert(request_id.clone(), envelope.clone()) {
                    assert_eq!(original, *envelope);
                }
                if self.reject_completed.get()
                    && matches!(response.result, Some(MethodResult::Input(_)))
                {
                    return Err(ProviderError::Correlation(
                        "test rejected the actual accepted input response",
                    ));
                }
            }
            ReceivedBody::Notification(_) => {
                panic!("actual input control cannot become a notification")
            }
        }
        Ok(())
    }
}

impl InputTranscript {
    pub(super) fn accepted(&self, stage: &Id) -> (Envelope, Envelope, InputResult) {
        let request_id = crate::node_adapters::cnp::control::original_id("input", stage).unwrap();
        let request = self.requests.borrow()[&request_id].clone();
        let response = self.responses.borrow()[&request_id].clone();
        let RequestBody::Input(original) = decode_request(Method::Input, &request.body).unwrap()
        else {
            panic!("actual peer input request changed method");
        };
        let parsed = decode_response(&RequestBody::Input(original), &response.body).unwrap();
        assert!(matches!(parsed.shape, ResponseShape::Completed { .. }));
        let Some(MethodResult::Input(result)) = parsed.result else {
            panic!("actual peer did not accept original input");
        };
        (request, response, result)
    }

    pub(super) fn counts(&self) -> (usize, usize) {
        (self.requests.borrow().len(), self.responses.borrow().len())
    }
}

/// Checks the peer-produced complete custody records, never a host-only counter.
pub(super) fn assert_peer_input(
    controller: &ReferenceController,
    result: &InputResult,
    batch: &InputBatch,
    reference: &ContentRef,
) {
    let receipt: ControlReceipt = controller.record(&result.custody_receipt).unwrap();
    let custody: InputCustodyRecord = controller.record(&receipt.record_ref).unwrap();
    let pending: PendingInventory = controller.record(&custody.pending_inventory).unwrap();
    let stored: InputBatch = controller.record(reference).unwrap();

    assert_eq!(stored, *batch);
    assert_eq!(receipt.kind, ControlReceiptKind::InputCustody);
    assert_eq!(custody.batch_hashes, vec![batch.identity().unwrap()]);
    assert_eq!(custody.input_watermark, batch.batch_sequence);
    assert_eq!(result.input_watermark, batch.batch_sequence);
    assert_eq!(pending.input_watermark, batch.batch_sequence);
    assert_eq!(pending.input_epoch, batch.input_epoch);
    assert_eq!(pending.execution_owner_id, batch.execution_owner_id);
    assert_eq!(
        pending.world_binding_hash,
        controller.bootstrap.world_binding_hash
    );
    assert_eq!(
        pending.activation_id,
        Some(controller.bootstrap.activation_id.clone())
    );
    assert_eq!(
        pending.world_generation,
        controller.bootstrap.world_generation
    );
    assert!(pending.complete);
    assert_eq!(pending.entries.len(), 1);
    assert_eq!(pending.entries[0].id, id("accepted-input"));
    assert_eq!(pending.entries[0].kind, PendingKind::Input);
    assert_eq!(pending.entries[0].state_ref, *reference);
    assert_eq!(pending.entries[0].owner_id, batch.execution_owner_id);
    assert_eq!(result.inventory_hash, custody.pending_inventory.hash);
}

/// Checks every opaque original after accepted input remains unresolved.
pub(super) fn assert_retained_input(
    custody: &CnpPeerCustody,
    original: &RuntimeInputBatch,
    public: &InputBatch,
    accepted_response: &Envelope,
) {
    let runtime = custody.runtime.as_ref().unwrap();
    let retained = runtime.input.as_ref().unwrap();
    let expected = original.retained_copy();

    assert_eq!(
        retained.original.stage_operation(),
        expected.stage_operation()
    );
    assert_eq!(retained.original.batch(), expected.batch());
    assert_eq!(retained.original.cutoff(), expected.cutoff());
    assert_eq!(retained.original.deliveries(), expected.deliveries());
    assert_eq!(retained.original.payloads(), expected.payloads());
    assert_eq!(retained.original.inventory(), expected.inventory());
    assert_eq!(
        retained.original.activation().record(),
        expected.activation().record()
    );
    assert_eq!(retained.public, *public);
    assert_eq!(retained.bytes, expected.payloads()[0].bytes);
    assert_eq!(
        runtime.next_input_sequence,
        public.batch_sequence.checked_add(U64::new(1)).unwrap()
    );
    assert!(retained.acknowledgement.is_none());
    let provenance = retained.provenance.as_ref().unwrap();
    assert_eq!(provenance.stage_operation(), expected.stage_operation());
    assert_eq!(provenance.batch(), expected.batch());
    assert_eq!(provenance.inventory(), expected.inventory());
    assert!(
        provenance
            .objects()
            .iter()
            .any(|object| { object.reference == expected.deliveries()[0].provenance_ref })
    );
    assert_eq!(accepted_response.method, Method::Input);
    assert_eq!(accepted_response.message, MessageKind::Response);
    assert_eq!(
        accepted_response.session_id.0.as_ref(),
        Some(&runtime.binding.authority.session_id)
    );
    assert_eq!(
        accepted_response.incarnation_id.0.as_ref(),
        Some(&runtime.binding.authority.incarnation_id)
    );
}

pub(super) fn assert_unknown(failure: &crate::node_contract::OperationFailure) {
    assert_eq!(failure.effects, EffectKnowledge::Unknown);
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(super) enum FailureMode {
    None,
    RegistryCredit,
    ResponseValidation,
}

pub(super) fn fail_original_input(
    runtime: &mut NodeRuntime,
    graph: &crate::node_admission::AdmittedGraph,
    activation: &crate::node_contract::WorldActivation,
    transcript: &InputTranscript,
    mode: FailureMode,
) -> RuntimeInputBatch {
    let original = runtime
        .scheduler(graph, activation)
        .unwrap()
        .prepare_input_batch(
            &id("consumer"),
            id("stage/consumer/1"),
            id("batch/consumer/1"),
            position(1001, Phase::BoundaryControl),
        )
        .unwrap();
    assert_eq!(original.deliveries().len(), 1);
    let retained = original.retained_copy();
    let result = match mode {
        FailureMode::RegistryCredit => {
            crate::node_adapters::cnp::boundary::input_test_credit::with_exhausted_registry(|| {
                runtime.stage_inputs(original)
            })
        }
        FailureMode::ResponseValidation => {
            transcript.reject_completed.set(true);
            runtime.stage_inputs(original)
        }
        FailureMode::None => panic!("failure fixture requires an adverse mode"),
    };
    let Err(crate::node_contract::RuntimePollFailure::Native(failure)) = result else {
        panic!("accepted native input must preserve an Unknown original failure");
    };
    assert_unknown(&failure);
    let (request, _, response) = transcript.accepted(retained.stage_operation());
    assert_eq!(response.input_watermark, U64::new(2));
    assert_eq!(response.accepted_event_ids, vec![id("checksum-1")]);
    assert_eq!(
        request.execution_owner_id.0.as_ref(),
        Some(&id("consumer-owner"))
    );
    let counts = transcript.counts();
    let Err(crate::node_contract::RuntimePollFailure::Native(recovered)) =
        runtime.recover_input_staging(activation, retained.stage_operation())
    else {
        panic!("Unknown input cannot become a positive host acknowledgement");
    };
    assert_eq!(recovered, failure);
    assert!(runtime.stage_inputs(retained.retained_copy()).is_err());
    assert_eq!(
        transcript.counts(),
        counts,
        "retry must not repeat an accepted native input"
    );
    retained
}

#[test]
#[ignore = "requires source-built CRUCIBLE_REFERENCE_PROVIDER_EXECUTABLE and CRUCIBLE_REFERENCE_DEVICE_EXECUTABLE"]
fn actual_accepted_input_registry_exhaustion_retains_original_unknown_custody() {
    run_actual_world(FailureMode::RegistryCredit);
}

#[test]
#[ignore = "requires source-built CRUCIBLE_REFERENCE_PROVIDER_EXECUTABLE and CRUCIBLE_REFERENCE_DEVICE_EXECUTABLE"]
fn actual_accepted_input_response_validation_failure_retains_original_unknown_custody() {
    run_actual_world(FailureMode::ResponseValidation);
}
