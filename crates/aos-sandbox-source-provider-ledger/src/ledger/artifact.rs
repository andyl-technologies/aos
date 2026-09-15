//! Pure retained request and response artifact validation.

use super::LedgerFormatErrorV1;
use super::model::AttemptRecordV1;
use aos_sandbox_core::ObjectDigest;
use aos_sandbox_source_provider_protocol::{
    SignedSourceProviderRequestV1, SourceProviderMethod, decode_acquire_request,
    decode_acquire_response, decode_inventory_request, decode_inventory_response,
    decode_release_request, decode_release_response, digest_acquire_request,
    digest_inventory_request, digest_release_request, encode_acquire_response,
    encode_inventory_response, encode_release_response, source_provider_inventory_intent_digest_v1,
    source_provider_release_intent_digest_v1,
};

pub use aos_sandbox_source_provider_protocol::provider_response_artifact_digest_v1 as response_artifact_digest;

pub(super) fn typed_request_digest(
    request: &SignedSourceProviderRequestV1,
) -> Result<ObjectDigest, LedgerFormatErrorV1> {
    match request.method() {
        SourceProviderMethod::Acquire => decode_acquire_request(request.subject())
            .map(|value| digest_acquire_request(&value))
            .map_err(|_| LedgerFormatErrorV1::Corrupt("retained typed Acquire request")),
        SourceProviderMethod::Release => decode_release_request(request.subject())
            .map(|value| digest_release_request(&value))
            .map_err(|_| LedgerFormatErrorV1::Corrupt("retained typed Release request")),
        SourceProviderMethod::Inventory => decode_inventory_request(request.subject())
            .map(|value| digest_inventory_request(&value))
            .map_err(|_| LedgerFormatErrorV1::Corrupt("retained typed Inventory request")),
        SourceProviderMethod::Hello => Err(LedgerFormatErrorV1::Corrupt("retained Hello request")),
    }
}

pub(super) fn validate_request_cross_links(
    attempt: &AttemptRecordV1,
    signed: &SignedSourceProviderRequestV1,
) -> Result<(), LedgerFormatErrorV1> {
    let exact = match attempt.method {
        SourceProviderMethod::Acquire => {
            let request = decode_acquire_request(signed.subject())
                .map_err(|_| LedgerFormatErrorV1::Corrupt("retained typed Acquire request"))?;
            request.request_id() == attempt.request_id
                && request.session_binding() == attempt.session_binding
                && request.sequence() == attempt.request_sequence
                && request.deadline_seconds() == attempt.deadline_seconds
                && request.holder_authority_id() == attempt.holder.authority_id()
                && request.holder_generation() == attempt.holder.authority_generation()
                && request.holder_authority_digest() == attempt.holder.authority_digest()
                && request.acquisition_sequence() == attempt.acquisition_sequence
        }
        SourceProviderMethod::Release => {
            let request = decode_release_request(signed.subject())
                .map_err(|_| LedgerFormatErrorV1::Corrupt("retained typed Release request"))?;
            request.request_id() == attempt.request_id
                && request.session_binding() == attempt.session_binding
                && request.sequence() == attempt.request_sequence
                && request.deadline_seconds() == attempt.deadline_seconds
                && request.holder_authority_id() == attempt.holder.authority_id()
                && request.holder_generation() == attempt.holder.authority_generation()
                && request.holder_authority_digest() == attempt.holder.authority_digest()
                && attempt.acquisition_sequence > 0
                && source_provider_release_intent_digest_v1(&request)
                    == attempt.operation_intent_digest
        }
        SourceProviderMethod::Inventory => {
            let request = decode_inventory_request(signed.subject())
                .map_err(|_| LedgerFormatErrorV1::Corrupt("retained typed Inventory request"))?;
            request.request_id() == attempt.request_id
                && request.session_binding() == attempt.session_binding
                && request.sequence() == attempt.request_sequence
                && request.deadline_seconds() == attempt.deadline_seconds
                && request.holder_authority_id() == attempt.holder.authority_id()
                && request.holder_generation() == attempt.holder.authority_generation()
                && request.holder_authority_digest() == attempt.holder.authority_digest()
                && attempt.acquisition_sequence == 0
                && source_provider_inventory_intent_digest_v1(&request)
                    == attempt.operation_intent_digest
        }
        SourceProviderMethod::Hello => false,
    };
    if exact {
        Ok(())
    } else {
        Err(LedgerFormatErrorV1::Corrupt("retained request cross-link"))
    }
}

pub(super) fn validate_completed_response(
    value: &AttemptRecordV1,
) -> Result<(), LedgerFormatErrorV1> {
    let (signed_status, canonical) = match value.method {
        SourceProviderMethod::Acquire => {
            let response = decode_acquire_response(&value.completed_response)
                .map_err(|_| LedgerFormatErrorV1::Corrupt("retained Acquire response"))?;
            (
                response.signed_status().clone(),
                encode_acquire_response(&response),
            )
        }
        SourceProviderMethod::Release => {
            let response = decode_release_response(&value.completed_response)
                .map_err(|_| LedgerFormatErrorV1::Corrupt("retained Release response"))?;
            (
                response.signed_status().clone(),
                encode_release_response(&response),
            )
        }
        SourceProviderMethod::Inventory => {
            let response = decode_inventory_response(&value.completed_response)
                .map_err(|_| LedgerFormatErrorV1::Corrupt("retained Inventory response"))?;
            if let Some(bytes) = response.signed_inventory() {
                let inventory = aos_sandbox_source_provider_protocol::SignedSourceProviderInventoryV1::from_canonical_bytes(bytes)
                    .map_err(|_| LedgerFormatErrorV1::Corrupt("retained Inventory artifact"))?;
                if inventory.subject().catalog_generation() != value.response_catalog_generation
                    || inventory.subject().catalog_digest() != value.response_catalog_digest
                {
                    return Err(LedgerFormatErrorV1::Corrupt(
                        "retained Inventory catalog link",
                    ));
                }
            }
            (
                response.signed_status().clone(),
                encode_inventory_response(&response),
            )
        }
        SourceProviderMethod::Hello => {
            return Err(LedgerFormatErrorV1::Corrupt("retained Hello response"));
        }
    };
    let status = signed_status.subject();
    let signer = signed_status.signer();
    if status.request_id() != value.request_id
        || status.signed_request_digest() != value.signed_request_digest
        || status.provider_process_instance() != value.provider_process_instance
        || status.session_binding() != value.session_binding
        || Some(status.response_sequence()) != value.response_sequence
        || Some(status.status()) != value.status
        || Some(status.result_digest()) != value.result_digest
        || status.descriptor_commitment() != value.descriptor_commitment
        || signer.authority_id() != value.provider.authority_id()
        || signer.authority_generation() != value.provider.authority_generation()
        || signer.authority_digest() != value.provider.authority_digest()
        || canonical != value.completed_response
    {
        return Err(LedgerFormatErrorV1::Corrupt("retained response cross-link"));
    }
    Ok(())
}
