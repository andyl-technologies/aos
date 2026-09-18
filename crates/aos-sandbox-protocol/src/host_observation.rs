//! Host runtime observation and historical-effect request semantics.
//!
//! These decoders validate controller-known portable fields only. They do not
//! inspect Host state, grant effect authority, or turn an opaque runtime handle
//! into a descriptor-use permit. Historical effect queries retain the original
//! Apply body byte-for-byte. Canonical bodies carry complete historical
//! semantics; noncanonical bodies remain opaque until a protected durable
//! effect proves that those exact bytes were admitted before canonical wire
//! enforcement.

use aos_proto::aos::sandbox::local::v1::{
    InventoryRuntimeRequest, ObserveRuntimeRequest, QueryRuntimeEffectRequest,
};
use aos_sandbox_core::ProtocolId;
use buffa::Message as _;

use crate::semantics::host::runtime_handle_v1;
use crate::session::MAXIMUM_HOST_QUERY_PACKET_BYTES;
use crate::{
    HistoricalRuntimeRequestCandidateV1, MAXIMUM_REQUEST_BYTES, PeerCredentials, PeerPolicy,
    ProtocolValidationError, ValidatedAssignmentFence, ValidatedHeader,
    classify_historical_runtime_request_v1, exact_nonzero, validate_fence, validate_request_header,
};

/// Carries one fully validated Host runtime-observation request.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ValidatedObserveRuntimeRequestV1 {
    header: ValidatedHeader,
    fence: ValidatedAssignmentFence,
    runtime_handle: [u8; 32],
}

impl ValidatedObserveRuntimeRequestV1 {
    /// Returns the validated common Host request header.
    #[must_use]
    pub const fn header(&self) -> &ValidatedHeader {
        &self.header
    }

    /// Returns the exact assignment fence naming the runtime.
    #[must_use]
    pub const fn fence(&self) -> &ValidatedAssignmentFence {
        &self.fence
    }

    /// Returns the deterministic opaque handle for the requested runtime.
    #[must_use]
    pub const fn runtime_handle(&self) -> &[u8; 32] {
        &self.runtime_handle
    }
}

/// Carries one validated query and its exact historical Host Apply request.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ValidatedQueryRuntimeEffectRequestV1 {
    header: ValidatedHeader,
    original_apply: HistoricalRuntimeRequestCandidateV1,
}

impl ValidatedQueryRuntimeEffectRequestV1 {
    /// Returns the validated common header for the query itself.
    #[must_use]
    pub const fn header(&self) -> &ValidatedHeader {
        &self.header
    }

    /// Returns the byte-exact historical Apply body committed by the query.
    #[must_use]
    pub fn original_apply_bytes(&self) -> &[u8] {
        self.original_apply.exact_bytes()
    }

    /// Returns the classified historical Apply candidate.
    ///
    /// Noncanonical candidates are opaque and must not be decoded until an
    /// exact protected durable effect proves their request ID and byte digest.
    #[must_use]
    pub const fn original_apply_candidate(&self) -> &HistoricalRuntimeRequestCandidateV1 {
        &self.original_apply
    }
}

/// Decodes one bounded request for a retained Host runtime observation.
///
/// # Errors
///
/// Returns [`ProtocolValidationError`] for an oversized or malformed body,
/// unknown fields, invalid peer/header/fence semantics, or a runtime handle
/// that is not the deterministic handle for the supplied assignment.
pub fn decode_observe_runtime_request_v1(
    bytes: &[u8],
    peer: PeerCredentials,
    policy: PeerPolicy,
    now_boottime_nanoseconds: u64,
) -> Result<ValidatedObserveRuntimeRequestV1, ProtocolValidationError> {
    if bytes.len() > MAXIMUM_REQUEST_BYTES {
        return Err(ProtocolValidationError::RequestTooLarge);
    }
    let request = ObserveRuntimeRequest::decode_from_slice(bytes)
        .map_err(|error| ProtocolValidationError::MalformedWire(error.to_string()))?;
    if !request.__buffa_unknown_fields.is_empty() || request.encode_to_vec() != bytes {
        return Err(ProtocolValidationError::UnknownFields);
    }

    let header = validate_request_header(
        request
            .header
            .as_option()
            .ok_or(ProtocolValidationError::MissingField("header"))?,
        peer,
        policy,
        ProtocolId::HostBroker,
        now_boottime_nanoseconds,
    )?;
    let fence = validate_fence(
        request
            .fence
            .as_option()
            .ok_or(ProtocolValidationError::MissingField("fence"))?,
    )?;
    let runtime_handle = exact_nonzero::<32>(&request.runtime_handle, "runtime_handle")?;
    let expected_runtime_handle = runtime_handle_v1(
        fence.incarnation_id(),
        fence.assignment_epoch(),
        fence.assignment_digest(),
    );
    if runtime_handle != expected_runtime_handle {
        return Err(ProtocolValidationError::InvalidField("runtime_handle"));
    }

    Ok(ValidatedObserveRuntimeRequestV1 {
        header,
        fence,
        runtime_handle,
    })
}

/// Decodes one bounded request for the complete Host runtime inventory.
///
/// # Errors
///
/// Returns [`ProtocolValidationError`] for an oversized or malformed body,
/// unknown fields, or invalid peer and common-header semantics.
pub fn decode_inventory_runtime_request_v1(
    bytes: &[u8],
    peer: PeerCredentials,
    policy: PeerPolicy,
    now_boottime_nanoseconds: u64,
) -> Result<ValidatedHeader, ProtocolValidationError> {
    if bytes.len() > MAXIMUM_REQUEST_BYTES {
        return Err(ProtocolValidationError::RequestTooLarge);
    }
    let request = InventoryRuntimeRequest::decode_from_slice(bytes)
        .map_err(|error| ProtocolValidationError::MalformedWire(error.to_string()))?;
    if !request.__buffa_unknown_fields.is_empty() || request.encode_to_vec() != bytes {
        return Err(ProtocolValidationError::UnknownFields);
    }

    validate_request_header(
        request
            .header
            .as_option()
            .ok_or(ProtocolValidationError::MissingField("header"))?,
        peer,
        policy,
        ProtocolId::HostBroker,
        now_boottime_nanoseconds,
    )
}

/// Decodes one bounded query for the durable outcome of an exact Host Apply.
///
/// The embedded Apply is historical evidence, so its own original deadline is
/// checked only for the nonzero protocol invariant once its semantics are
/// available. A noncanonical embedded Apply remains an opaque locator until a
/// caller proves its exact protected durable identity. The query's deadline is
/// checked against `now_boottime_nanoseconds` as the fresh read operation.
///
/// # Errors
///
/// Returns [`ProtocolValidationError`] for an oversized or malformed body,
/// unknown fields, invalid query-header semantics, a missing or invalid
/// historical Apply body, or request-ID substitution between the two layers.
pub fn decode_query_runtime_effect_request_v1(
    bytes: &[u8],
    peer: PeerCredentials,
    policy: PeerPolicy,
    now_boottime_nanoseconds: u64,
) -> Result<ValidatedQueryRuntimeEffectRequestV1, ProtocolValidationError> {
    if bytes.len() > MAXIMUM_HOST_QUERY_PACKET_BYTES {
        return Err(ProtocolValidationError::RequestTooLarge);
    }
    let request = QueryRuntimeEffectRequest::decode_from_slice(bytes)
        .map_err(|error| ProtocolValidationError::MalformedWire(error.to_string()))?;
    if !request.__buffa_unknown_fields.is_empty() || request.encode_to_vec() != bytes {
        return Err(ProtocolValidationError::UnknownFields);
    }

    let header = validate_request_header(
        request
            .header
            .as_option()
            .ok_or(ProtocolValidationError::MissingField("header"))?,
        peer,
        policy,
        ProtocolId::HostBroker,
        now_boottime_nanoseconds,
    )?;
    if request.original_apply_request.is_empty()
        || request.original_apply_request.len() > MAXIMUM_REQUEST_BYTES
    {
        return Err(ProtocolValidationError::InvalidField(
            "original_apply_request",
        ));
    }

    let original_apply =
        classify_historical_runtime_request_v1(&request.original_apply_request, peer, policy)?;
    if original_apply.request_id() != header.request_id() {
        return Err(ProtocolValidationError::InvalidField(
            "original_apply_request.header.request_id",
        ));
    }

    Ok(ValidatedQueryRuntimeEffectRequestV1 {
        header,
        original_apply,
    })
}
