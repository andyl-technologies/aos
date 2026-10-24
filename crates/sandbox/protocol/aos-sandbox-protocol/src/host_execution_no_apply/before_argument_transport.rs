//! Parses the explicit before-argument branch without inventing legacy H/T.
//!
//! The existing method39/40 envelope carries AOSNAB02 in canonical_attempt.
//! The legacy original_session_binding/original_signed_request_digest fields
//! MUST be absent in this branch. Actual terminal identity belongs to the
//! authenticated Session envelope, never a circular caller-supplied digest.

use aos_sandbox_api::aos::sandbox::local::v1::{
    QueryHostExecutionArgumentNoApplyRequestV1,
    QueryHostExecutionArgumentNoApplyResponseV1, HostExecutionNoApplyStatusV1,
    TerminalHostExecutionArgumentNoApplyRequestV1, TerminalHostExecutionArgumentNoApplyResponseV1,
};
use aos_sandbox_model::ProtocolId;
use buffa::Message as _;

use super::{BeforeArgumentNoApplySourceDataV2, ClosedBeforeArgumentNoApplyRecordV2};
use crate::{PeerCredentials, PeerPolicy, ProtocolValidationError, ValidatedHeader,
    validate_request_header};

const MAXIMUM_BODY: usize = 2 * 1_024;

/// Prices the reached early-branch decoder and retained canonical-body peak.
///
/// This is representation DATA only. The actual Session/native purpose must
/// admit it before decoding. It does not include outer signed-packet owners,
/// HostState semantic models, protected currentness or native append geometry.
#[must_use]
pub fn before_argument_no_apply_receiving_bytes_v2(body_bytes: usize) -> Option<usize> {
    use std::mem::size_of;
    if body_bytes == 0 || body_bytes > MAXIMUM_BODY { return None; }
    let fixed = size_of::<TerminalHostExecutionArgumentNoApplyRequestV1>()
        .checked_add(size_of::<QueryHostExecutionArgumentNoApplyRequestV1>())?
        .checked_add(size_of::<TerminalHostExecutionArgumentNoApplyResponseV1>())?
        .checked_add(size_of::<QueryHostExecutionArgumentNoApplyResponseV1>())?
        .checked_add(size_of::<ValidatedHostBeforeArgumentNoApplyRequestV2>())?
        .checked_add(size_of::<super::ClosedBeforeArgumentNoApplyRecordV2>())?
        .checked_mul(2)?;
    // A hostile repeated unknown field consumes at least one input tag. The
    // selected generic/branch parses and canonical reencodings coexist with
    // retained exact bytes; both raw-owner and Vec-growth planes are covered.
    fixed.checked_add(body_bytes.checked_mul(size_of::<buffa::UnknownField>())?.checked_mul(4)?)?
        .checked_add(body_bytes.checked_mul(8)?)?
        .checked_add(super::BEFORE_ARGUMENT_NO_APPLY_SOURCE_BYTES_V2.checked_mul(4)?)
}

/// Keeps complete argument custody and the explicit early branch distinct.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum HostExecutionNoApplyRequestV2 {
    /// Preserves the existing complete original argument identity literally.
    AfterArgument(super::ValidatedHostExecutionNoApplyRequestV1),
    /// Carries accepted-Create DATA with no invented original argument fields.
    BeforeArgument(ValidatedHostBeforeArgumentNoApplyRequestV2),
}

impl HostExecutionNoApplyRequestV2 {
    /// Borrows the current terminal or historical-query header.
    pub const fn header(&self) -> &ValidatedHeader {
        match self {
            Self::AfterArgument(request) => request.header(),
            Self::BeforeArgument(request) => request.header(),
        }
    }
}

/// Selects only the closed literal argument or explicit early terminal branch.
///
/// # Errors
/// Rejects malformed canonical wire or an invalid selected branch. An early
/// source with legacy original H/T fields is never accepted by either branch.
pub fn decode_host_execution_no_apply_request_v2(
    body: &[u8], peer: PeerCredentials, policy: PeerPolicy, now: u64,
) -> Result<HostExecutionNoApplyRequestV2, ProtocolValidationError> {
    if body.len() > MAXIMUM_BODY { return Err(ProtocolValidationError::RequestTooLarge); }
    let request = TerminalHostExecutionArgumentNoApplyRequestV1::decode_from_slice(body)
        .map_err(|cause| ProtocolValidationError::MalformedWire(cause.to_string()))?;
    if request.canonical_attempt.get(..8) == Some(b"AOSNAB02".as_slice()) {
        decode_host_before_argument_no_apply_request_v2(body, peer, policy, now)
            .map(HostExecutionNoApplyRequestV2::BeforeArgument)
    } else {
        super::decode_host_execution_argument_no_apply_request_v1(body, peer, policy, now)
            .map(HostExecutionNoApplyRequestV2::AfterArgument)
    }
}

/// Selects only the closed literal argument or explicit early historical query.
///
/// # Errors
/// Rejects malformed canonical wire, legacy fields on an early source, or an
/// invalid selected branch. This supplies no ownership lease or retry permit.
pub fn decode_host_execution_no_apply_query_request_v2(
    body: &[u8], peer: PeerCredentials, policy: PeerPolicy, now: u64,
) -> Result<HostExecutionNoApplyRequestV2, ProtocolValidationError> {
    if body.len() > MAXIMUM_BODY { return Err(ProtocolValidationError::RequestTooLarge); }
    let request = QueryHostExecutionArgumentNoApplyRequestV1::decode_from_slice(body)
        .map_err(|cause| ProtocolValidationError::MalformedWire(cause.to_string()))?;
    if request.canonical_attempt.get(..8) == Some(b"AOSNAB02".as_slice()) {
        decode_host_before_argument_no_apply_query_request_v2(body, peer, policy, now)
            .map(HostExecutionNoApplyRequestV2::BeforeArgument)
    } else {
        super::decode_host_execution_argument_query_no_apply_request_v1(body, peer, policy, now)
            .map(HostExecutionNoApplyRequestV2::AfterArgument)
    }
}

/// Retains the canonical before-argument request as nonauthorizing wire DATA.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ValidatedHostBeforeArgumentNoApplyRequestV2 {
    header: ValidatedHeader,
    source: BeforeArgumentNoApplySourceDataV2,
    exact_body: Vec<u8>,
    query: bool,
}

impl ValidatedHostBeforeArgumentNoApplyRequestV2 {
    /// Returns the current terminal or historical-query header.
    pub const fn header(&self) -> &ValidatedHeader { &self.header }

    /// Returns structurally validated accepted-Create comparison DATA.
    pub const fn source(&self) -> BeforeArgumentNoApplySourceDataV2 { self.source }

    /// Borrows the complete original canonical request bytes.
    pub fn exact_body(&self) -> &[u8] { &self.exact_body }

    /// Reports that this request is read-only historical inspection.
    pub const fn is_query(&self) -> bool { self.query }
}

/// Parses the explicit before-argument terminal branch of method39.
///
/// # Errors
/// Rejects noncanonical wire, another source version, stale headers, present
/// legacy H/T fields, or an insufficient response ceiling.
pub fn decode_host_before_argument_no_apply_request_v2(
    body: &[u8], peer: PeerCredentials, policy: PeerPolicy, now: u64,
) -> Result<ValidatedHostBeforeArgumentNoApplyRequestV2, ProtocolValidationError> {
    if body.len() > MAXIMUM_BODY { return Err(ProtocolValidationError::RequestTooLarge); }
    let request = TerminalHostExecutionArgumentNoApplyRequestV1::decode_from_slice(body)
        .map_err(|cause| ProtocolValidationError::MalformedWire(cause.to_string()))?;
    if !request.__buffa_unknown_fields.is_empty() || request.encode_to_vec() != body
        || !request.original_session_binding.is_empty()
        || !request.original_signed_request_digest.is_empty()
    { return Err(ProtocolValidationError::UnknownFields); }
    validate(body, request.header.as_option(), &request.canonical_attempt, peer, policy, now, false)
}

/// Parses the explicit before-argument historical-query branch of method40.
///
/// # Errors
/// Rejects noncanonical wire, stale headers, another source version or present
/// legacy H/T fields. Parsing never revives a native lease or effect permit.
pub fn decode_host_before_argument_no_apply_query_request_v2(
    body: &[u8], peer: PeerCredentials, policy: PeerPolicy, now: u64,
) -> Result<ValidatedHostBeforeArgumentNoApplyRequestV2, ProtocolValidationError> {
    if body.len() > MAXIMUM_BODY { return Err(ProtocolValidationError::RequestTooLarge); }
    let request = QueryHostExecutionArgumentNoApplyRequestV1::decode_from_slice(body)
        .map_err(|cause| ProtocolValidationError::MalformedWire(cause.to_string()))?;
    if !request.__buffa_unknown_fields.is_empty() || request.encode_to_vec() != body
        || !request.original_session_binding.is_empty()
        || !request.original_signed_request_digest.is_empty()
    { return Err(ProtocolValidationError::UnknownFields); }
    validate(body, request.header.as_option(), &request.canonical_attempt, peer, policy, now, true)
}

fn validate(
    body: &[u8], header: Option<&aos_sandbox_api::aos::sandbox::local::v1::RequestHeader>,
    source: &[u8], peer: PeerCredentials, policy: PeerPolicy, now: u64, query: bool,
) -> Result<ValidatedHostBeforeArgumentNoApplyRequestV2, ProtocolValidationError> {
    let header = validate_request_header(header.ok_or(ProtocolValidationError::MissingField("header"))?,
        peer, policy, ProtocolId::HostBroker, now)?;
    let source = BeforeArgumentNoApplySourceDataV2::decode_canonical(source)
        .map_err(|_| ProtocolValidationError::InvalidField("before_argument_source"))?;
    if header.maximum_response_bytes() < (super::BEFORE_ARGUMENT_NO_APPLY_RECORD_BYTES_V2 + 6) as u32 {
        return Err(ProtocolValidationError::InvalidField("maximum_response_bytes"));
    }
    Ok(ValidatedHostBeforeArgumentNoApplyRequestV2 {
        header, source, exact_body: body.to_vec(), query,
    })
}

/// Matches a signed terminal response to its exact before-argument request.
///
/// # Errors
/// Rejects another variant, changed source, session, signed request or identity.
pub fn decode_host_before_argument_no_apply_response_v2(
    body: &[u8], original: &ValidatedHostBeforeArgumentNoApplyRequestV2,
    terminal_session: [u8; 32], signed_terminal_request: [u8; 32],
) -> Result<ClosedBeforeArgumentNoApplyRecordV2, ProtocolValidationError> {
    if body.len() > MAXIMUM_BODY { return Err(ProtocolValidationError::ResponseTooLarge); }
    if original.query { return Err(ProtocolValidationError::InvalidField("terminal_method")); }
    let response = TerminalHostExecutionArgumentNoApplyResponseV1::decode_from_slice(body)
        .map_err(|cause| ProtocolValidationError::MalformedWire(cause.to_string()))?;
    if !response.__buffa_unknown_fields.is_empty() || response.encode_to_vec() != body {
        return Err(ProtocolValidationError::UnknownFields);
    }
    let record = ClosedBeforeArgumentNoApplyRecordV2::decode_canonical(&response.canonical_record)
        .map_err(|_| ProtocolValidationError::InvalidField("closed_before_argument_record"))?;
    let fields = record.fields();
    if fields.source != original.source || fields.terminal_request != *original.header.request_id()
        || fields.terminal_session != terminal_session || fields.signed_terminal_request != signed_terminal_request
    { return Err(ProtocolValidationError::InvalidField("closed_before_argument_record")); }
    Ok(record)
}

/// Reads the exact early historical marker or explicit absence from method40.
///
/// # Errors
/// Rejects noncanonical status/record pairs, a changed accepted source, or a
/// marker of another branch. Absence grants neither retry nor future Apply.
pub fn decode_host_before_argument_no_apply_query_response_v2(
    body: &[u8], original: &ValidatedHostBeforeArgumentNoApplyRequestV2,
) -> Result<Option<ClosedBeforeArgumentNoApplyRecordV2>, ProtocolValidationError> {
    if body.len() > MAXIMUM_BODY { return Err(ProtocolValidationError::ResponseTooLarge); }
    if !original.query { return Err(ProtocolValidationError::InvalidField("query_method")); }
    let response = QueryHostExecutionArgumentNoApplyResponseV1::decode_from_slice(body)
        .map_err(|cause| ProtocolValidationError::MalformedWire(cause.to_string()))?;
    if !response.__buffa_unknown_fields.is_empty() || response.encode_to_vec() != body {
        return Err(ProtocolValidationError::UnknownFields);
    }
    match response.status.as_known() {
        Some(HostExecutionNoApplyStatusV1::HOST_EXECUTION_NO_APPLY_STATUS_ABSENT)
            if response.canonical_record.is_empty() => Ok(None),
        Some(HostExecutionNoApplyStatusV1::HOST_EXECUTION_NO_APPLY_STATUS_RECORDED) => {
            let record = ClosedBeforeArgumentNoApplyRecordV2::decode_canonical(&response.canonical_record)
                .map_err(|_| ProtocolValidationError::InvalidField("closed_before_argument_record"))?;
            if record.fields().source != original.source
                || record.fields().terminal_request == *original.header.request_id()
            {
                return Err(ProtocolValidationError::InvalidField("before_argument_source"));
            }
            Ok(Some(record))
        }
        _ => Err(ProtocolValidationError::InvalidField("status")),
    }
}
