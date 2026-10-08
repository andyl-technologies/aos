//! Historical legacy Storage response-envelope fixture.
//!
//! These codecs and exact negative assertions predate authenticated production
//! sessions. They do not cover canonical OutcomeUnknown custody, sealed
//! observation/CAS recovery, or consuming session completion.
//!
//! This temporary test-only fixture preserves the old nonretryable responses
//! until canonical post-effect fault coverage can replace it entirely. It is
//! not a production compatibility surface or evidence of current wire behavior.

#![allow(clippy::unwrap_used)]

use aos_proto::aos::sandbox::local::v1::{BrokerErrorCode, BrokerMethod, BrokerRequestEnvelope};
use aos_sandbox_core::ProtocolId;
use aos_sandbox_protocol::{
    ProtocolValidationError, ValidatedBrokerRequestEnvelope, encode_error_response_envelope,
    encode_success_response_envelope,
};
use buffa::Message as _;

use super::StorageConnectionOutcome;
use crate::broker::StorageBrokerError;
use crate::runtime::StorageRuntimeError;

fn encode_success_or_resource_exhausted(
    request_id: &[u8; 16],
    request: &ValidatedBrokerRequestEnvelope,
    body: Vec<u8>,
    maximum_bytes: u32,
    exhausted_message: &'static str,
    retryable: bool,
) -> Result<(Vec<u8>, StorageConnectionOutcome), ProtocolValidationError> {
    match encode_success_response_envelope(request_id, request, body, &[], &[], maximum_bytes) {
        Ok(response) => Ok((response, StorageConnectionOutcome::Served)),
        Err(
            ProtocolValidationError::ResponseTooLarge
            | ProtocolValidationError::InvalidResponseBound,
        ) => encode_safe_error(
            request_id,
            request,
            BrokerErrorCode::BROKER_ERROR_CODE_RESOURCE_EXHAUSTED,
            exhausted_message,
            retryable,
            maximum_bytes,
        ),
        Err(error) => Err(error),
    }
}

fn encode_runtime_error(
    request_id: &[u8; 16],
    request: &ValidatedBrokerRequestEnvelope,
    error: &StorageRuntimeError,
    maximum_bytes: u32,
) -> Result<(Vec<u8>, StorageConnectionOutcome), ProtocolValidationError> {
    let (code, message) = match error {
        StorageRuntimeError::Admission(
            StorageBrokerError::Request | StorageBrokerError::Authority,
        ) => (
            BrokerErrorCode::BROKER_ERROR_CODE_INVALID_REQUEST,
            "Storage request authority was rejected",
        ),
        StorageRuntimeError::Configuration(_)
        | StorageRuntimeError::Bootstrap
        | StorageRuntimeError::State(_)
        | StorageRuntimeError::WorkspaceCatalog(_) => (
            BrokerErrorCode::BROKER_ERROR_CODE_INTEGRITY_FAILURE,
            "protected Storage state is unavailable",
        ),
        StorageRuntimeError::Worker(_)
        | StorageRuntimeError::Transaction(_)
        | StorageRuntimeError::Recovery
        | StorageRuntimeError::ReopenRequired
        | StorageRuntimeError::WorkspacePinScope
        | StorageRuntimeError::OperatorProvision(_)
        | StorageRuntimeError::OperatorProvisionCredentials(_)
        | StorageRuntimeError::Admission(_) => (
            BrokerErrorCode::BROKER_ERROR_CODE_BACKEND_FAILURE,
            "Storage request requires reconciliation",
        ),
    };

    // A public caller must reconcile inventory and obtain new authority before
    // another mutation. No ambiguous failure is labelled safely retryable.
    encode_safe_error(request_id, request, code, message, false, maximum_bytes)
}

fn encode_safe_error(
    request_id: &[u8; 16],
    request: &ValidatedBrokerRequestEnvelope,
    code: BrokerErrorCode,
    message: &'static str,
    retryable: bool,
    maximum_bytes: u32,
) -> Result<(Vec<u8>, StorageConnectionOutcome), ProtocolValidationError> {
    encode_error_response_envelope(
        request_id,
        request,
        code,
        message,
        retryable,
        None,
        &[],
        maximum_bytes,
    )
    .map(|response| (response, StorageConnectionOutcome::RequestRejected))
}

#[test]
fn ambiguous_runtime_failures_are_never_labelled_retryable() {
    let request_id = [7; 16];
    let raw = BrokerRequestEnvelope {
        method: BrokerMethod::BROKER_METHOD_STORAGE_REPAIR_WORKSPACE_PIN.into(),
        body: vec![1],
        ..Default::default()
    };
    let request = aos_sandbox_protocol::decode_request_envelope(
        &raw.encode_to_vec(),
        ProtocolId::StorageBroker,
        0,
    )
    .unwrap();
    let (encoded, outcome) =
        encode_runtime_error(&request_id, &request, &StorageRuntimeError::Recovery, 4096).unwrap();
    let response =
        aos_proto::aos::sandbox::local::v1::BrokerResponseEnvelope::decode_from_slice(&encoded)
            .unwrap();

    assert_eq!(outcome, StorageConnectionOutcome::RequestRejected);
    assert_eq!(
        response.error.as_option().unwrap().code.as_known(),
        Some(BrokerErrorCode::BROKER_ERROR_CODE_BACKEND_FAILURE)
    );
    assert!(!response.error.as_option().unwrap().retryable);
    assert!(response.body.is_empty());
}

#[test]
fn oversized_post_repair_success_is_never_labelled_retryable() {
    let request_id = [8; 16];
    let raw = BrokerRequestEnvelope {
        method: BrokerMethod::BROKER_METHOD_STORAGE_REPAIR_WORKSPACE_PIN.into(),
        body: vec![1],
        ..Default::default()
    };
    let request = aos_sandbox_protocol::decode_request_envelope(
        &raw.encode_to_vec(),
        ProtocolId::StorageBroker,
        0,
    )
    .unwrap();
    let (encoded, outcome) = encode_success_or_resource_exhausted(
        &request_id,
        &request,
        vec![0; 4_096],
        4_096,
        "Storage repair result exceeds the response ceiling",
        false,
    )
    .unwrap();
    let response =
        aos_proto::aos::sandbox::local::v1::BrokerResponseEnvelope::decode_from_slice(&encoded)
            .unwrap();

    assert_eq!(outcome, StorageConnectionOutcome::RequestRejected);
    assert_eq!(
        response.error.as_option().unwrap().code.as_known(),
        Some(BrokerErrorCode::BROKER_ERROR_CODE_RESOURCE_EXHAUSTED)
    );
    assert!(!response.error.as_option().unwrap().retryable);
    assert!(response.body.is_empty());
}
