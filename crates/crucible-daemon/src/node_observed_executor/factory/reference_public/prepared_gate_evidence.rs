//! Reads exact original preparation gate bytes through inert observation custody.
//!
//! These historical bytes carry their original meaning. A parked gate status
//! does not describe a checksum, cursor or complete native snapshot. The caller
//! separately measures current native custody and the later original quantum.

use crucible_node_contract::{
    ClosedGateRecord, ContentRef, ControlReceipt, ControlReceiptKind, Id, ReceiptIssuer, U64,
    Validate, canonical,
};
use crucible_node_provider::{
    ProviderError,
    bodies::{MethodResult, RequestBody, ResponseShape, decode_request, decode_response},
    client::{ObservationHandle, ObservationLimits, ObservedContent, ObservedRequestKey},
    envelope::{Envelope, Method, RequestOrigin},
};
use serde::{Serialize, de::DeserializeOwned};

use super::installation::SourcePublicReferenceInstallation;
const MAXIMUM_BYTES: usize = 128 * 1024;

/// Retains untouched originals without issuing freshness or preservation authority.
#[derive(Serialize)]
pub(super) struct OriginalPreparedGate {
    schema: &'static str,
    original_request: Id,
    receipt: ObservedContent,
    record: ObservedContent,
    physical_status: ObservedContent,
}

/// Retains the already observed source-built realization gate closure.
///
/// # Errors
/// Refuses unavailable, incomplete or Unknown recording, changed original scope,
/// missing exact objects, invalid receipts or the bounded raw object ceiling.
pub(super) fn retain(
    installed: &SourcePublicReferenceInstallation,
    observations: &ObservationHandle,
) -> Result<OriginalPreparedGate, ProviderError> {
    let request_id = Id::new(format!(
        "prepare-realize-{}",
        installed.bootstrap.authority.realization_id,
    ))?;
    let key = ObservedRequestKey {
        origin: RequestOrigin::Controller,
        request_id: request_id.clone(),
    };
    let snapshot = observations.snapshot(std::slice::from_ref(&key), &[], limits())?;
    check_recording(&snapshot)?;
    let original = snapshot
        .evidence
        .requests
        .first()
        .ok_or(ProviderError::Correlation(
            "original prepared realization absent",
        ))?;
    let response = original
        .response
        .0
        .as_ref()
        .ok_or(ProviderError::Correlation(
            "original prepared realization response absent",
        ))?;
    original
        .request
        .reference
        .verify(original.request.bytes.as_slice())?;
    response.reference.verify(response.bytes.as_slice())?;
    let request = Envelope::decode(original.request.bytes.as_slice(), MAXIMUM_BYTES)?;
    let reply = Envelope::decode(response.bytes.as_slice(), MAXIMUM_BYTES)?;
    request.matches_response(&reply)?;
    let body = decode_request(request.method, &request.body)?;
    let RequestBody::Realize(realize) = &body else {
        return Err(ProviderError::Correlation(
            "original prepared request was not Realize",
        ));
    };
    if request.method != Method::Realize
        || request.request_id.0.as_ref() != Some(&request_id)
        || request.session_id.0.as_ref() != Some(&installed.bootstrap.authority.session_id)
        || request.incarnation_id.0.as_ref() != Some(&installed.bootstrap.authority.incarnation_id)
        || request.node_id.0.is_some()
        || request.operation_id.0.is_some()
        || request.execution_owner_id.0.is_some()
        || request.capture_owner_id.0.is_some()
        || !request.extensions.is_empty()
        || realize.realization_id != installed.bootstrap.authority.realization_id
        || realize.configuration != installed.profile.configuration_ref
        || realize.requested_node_ids != [installed.bootstrap.node_id.clone()]
        || realize.resource_limits != installed.bootstrap.resource_limits
        || !realize.extensions.is_empty()
    {
        return Err(ProviderError::Correlation(
            "original preparation request scope changed",
        ));
    }
    let response = decode_response(&body, &reply.body)?;
    if !matches!(response.shape, ResponseShape::Completed { .. }) {
        return Err(ProviderError::Correlation(
            "original preparation did not complete",
        ));
    }
    let Some(MethodResult::Realize(result)) = response.result else {
        return Err(ProviderError::Correlation(
            "original preparation result absent",
        ));
    };
    result.validate()?;
    if result.prepared_token != installed.bootstrap.prepared_token
        || result.realization_manifest.realization_id
            != installed.bootstrap.authority.realization_id
    {
        return Err(ProviderError::Correlation(
            "original prepared gate realization changed",
        ));
    }
    let receipt = object(observations, &key, &result.closed_gate_receipt)?;
    let control: ControlReceipt = decode(&receipt)?;
    if control.kind != ControlReceiptKind::ClosedGate
        || control.issuer != ReceiptIssuer::Provider
        || control.session_id != installed.bootstrap.authority.session_id
        || control.incarnation_id != installed.bootstrap.authority.incarnation_id
        || control.request_id != request_id
        || control.operation_id.is_some()
        || control.owner_ids != [installed.profile.owner.id.clone()]
        || control.world_generation != U64::new(0)
        || !control.extensions.is_empty()
    {
        return Err(ProviderError::Correlation(
            "original prepared receipt scope changed",
        ));
    }
    let record = object(observations, &key, &control.record_ref)?;
    let gate: ClosedGateRecord = decode(&record)?;
    if gate.gate_id != installed.bootstrap.gate_id
        || !gate.gate_closed
        || gate.prepared_token != installed.bootstrap.prepared_token
        || gate.owner_ids != [installed.profile.owner.id.clone()]
        || !gate.extensions.is_empty()
    {
        return Err(ProviderError::Correlation(
            "original prepared native gate changed",
        ));
    }
    let physical_status = object(observations, &key, &gate.physical_status_ref)?;
    Ok(OriginalPreparedGate {
        schema: "crucible.reference.original-prepared-gate.v1",
        original_request: request_id,
        receipt,
        record,
        physical_status,
    })
}

fn limits() -> ObservationLimits {
    ObservationLimits {
        maximum_requests: 1,
        maximum_objects: 1,
        maximum_bytes: MAXIMUM_BYTES,
    }
}

fn check_recording(
    snapshot: &crucible_node_provider::client::RecordedReferenceObservation,
) -> Result<(), ProviderError> {
    if !snapshot.recording_complete
        || snapshot.observed_unknown
        || snapshot.recording_failure.0.is_some()
    {
        return Err(ProviderError::Correlation(
            "original preparation recording incomplete",
        ));
    }
    Ok(())
}

fn object(
    observations: &ObservationHandle,
    key: &ObservedRequestKey,
    reference: &ContentRef,
) -> Result<ObservedContent, ProviderError> {
    let snapshot = observations.snapshot(
        std::slice::from_ref(key),
        std::slice::from_ref(reference),
        limits(),
    )?;
    check_recording(&snapshot)?;
    let object = snapshot
        .evidence
        .objects
        .into_iter()
        .next()
        .ok_or(ProviderError::Correlation(
            "original preparation object unavailable",
        ))?;
    if object.reference != *reference {
        return Err(ProviderError::Correlation(
            "original preparation content identity changed",
        ));
    }
    reference.verify(object.bytes.as_slice())?;
    Ok(object)
}

fn decode<T: DeserializeOwned + Validate>(object: &ObservedContent) -> Result<T, ProviderError> {
    Ok(canonical::decode(object.bytes.as_slice(), MAXIMUM_BYTES)?)
}
