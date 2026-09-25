//! Strict method-39/40 Host terminal marker transport and source cross-links.
//!
//! Both methods carry the original AOSCIA02 and authenticated method-37
//! identity. Method 39 is a distinct signed mutation; method 40 reads only
//! historical Host custody. Neither response settles Controller Create.

use aos_proto::aos::sandbox::local::v1::{
    HostExecutionNoApplyStatusV1, QueryHostExecutionArgumentNoApplyRequestV1,
    QueryHostExecutionArgumentNoApplyResponseV1, TerminalHostExecutionArgumentNoApplyRequestV1,
    TerminalHostExecutionArgumentNoApplyResponseV1,
};
use aos_sandbox_core::ProtocolId;
use buffa::Message as _;

use super::HostExecutionNoApplyRecordV1;
use crate::host_execution_argument::HOST_EXECUTION_ARGUMENT_ATTEMPT_BYTES_V1;
use crate::semantics::host_execution_argument::canonical_attempt_request_id_v1;
use crate::{
    PeerCredentials, PeerPolicy, ProtocolValidationError, ValidatedHeader, validate_request_header,
};

const MAXIMUM_REQUEST_BODY_BYTES: usize = 2 * 1_024;
const MAXIMUM_RESPONSE_BODY_BYTES: usize = 1_024;

/// Retains a structurally validated, nonauthorizing terminal request source.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ValidatedHostExecutionNoApplyRequestV1 {
    header: ValidatedHeader,
    canonical_attempt: [u8; HOST_EXECUTION_ARGUMENT_ATTEMPT_BYTES_V1],
    original_request_id: [u8; 16],
    original_session_binding: [u8; 32],
    original_signed_request_digest: [u8; 32],
}

impl ValidatedHostExecutionNoApplyRequestV1 {
    /// Returns the current method-39 or method-40 request header.
    #[must_use]
    pub const fn header(&self) -> &ValidatedHeader {
        &self.header
    }

    /// Borrows the exact original, nonauthorizing AOSCIA02 bytes.
    #[must_use]
    pub const fn canonical_attempt(&self) -> &[u8; HOST_EXECUTION_ARGUMENT_ATTEMPT_BYTES_V1] {
        &self.canonical_attempt
    }

    /// Returns the original signed method-37 request ID.
    #[must_use]
    pub const fn original_request_id(&self) -> [u8; 16] {
        self.original_request_id
    }

    /// Returns the original authenticated method-37 session binding.
    #[must_use]
    pub const fn original_session_binding(&self) -> [u8; 32] {
        self.original_session_binding
    }

    /// Returns the signed original method-37 ClientRecord digest.
    #[must_use]
    pub const fn original_signed_request_digest(&self) -> [u8; 32] {
        self.original_signed_request_digest
    }
}

/// Distinguishes historical absence from one exact protected Host marker.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum HostExecutionNoApplyReadbackV1 {
    /// No matching marker is present; this does not authorize a retry.
    Absent,
    /// The exact canonical marker is present under Host custody.
    Recorded(HostExecutionNoApplyRecordV1),
}

/// Decodes a distinct mutating method-39 request without granting a mutation.
///
/// # Errors
///
/// Rejects malformed wire, invalid header or AOSCIA02, zero original signed
/// identity, or reuse of the original method-37 request ID.
pub fn decode_host_execution_argument_no_apply_request_v1(
    body: &[u8],
    peer: PeerCredentials,
    policy: PeerPolicy,
    now_boottime_nanoseconds: u64,
) -> Result<ValidatedHostExecutionNoApplyRequestV1, ProtocolValidationError> {
    if body.len() > MAXIMUM_REQUEST_BODY_BYTES {
        return Err(ProtocolValidationError::RequestTooLarge);
    }
    let request = TerminalHostExecutionArgumentNoApplyRequestV1::decode_from_slice(body)
        .map_err(|error| ProtocolValidationError::MalformedWire(error.to_string()))?;
    if !request.__buffa_unknown_fields.is_empty() || request.encode_to_vec() != body {
        return Err(ProtocolValidationError::UnknownFields);
    }
    validate_request(
        request.header.as_option(),
        &request.canonical_attempt,
        &request.original_session_binding,
        &request.original_signed_request_digest,
        peer,
        policy,
        now_boottime_nanoseconds,
    )
}

/// Decodes a distinct read-only method-40 query of the original attempt.
///
/// # Errors
///
/// Rejects malformed wire, invalid header or AOSCIA02, zero original signed
/// identity, or reuse of the original method-37 request ID.
pub fn decode_host_execution_argument_query_no_apply_request_v1(
    body: &[u8],
    peer: PeerCredentials,
    policy: PeerPolicy,
    now_boottime_nanoseconds: u64,
) -> Result<ValidatedHostExecutionNoApplyRequestV1, ProtocolValidationError> {
    if body.len() > MAXIMUM_REQUEST_BODY_BYTES {
        return Err(ProtocolValidationError::RequestTooLarge);
    }
    let request = QueryHostExecutionArgumentNoApplyRequestV1::decode_from_slice(body)
        .map_err(|error| ProtocolValidationError::MalformedWire(error.to_string()))?;
    if !request.__buffa_unknown_fields.is_empty() || request.encode_to_vec() != body {
        return Err(ProtocolValidationError::UnknownFields);
    }
    validate_request(
        request.header.as_option(),
        &request.canonical_attempt,
        &request.original_session_binding,
        &request.original_signed_request_digest,
        peer,
        policy,
        now_boottime_nanoseconds,
    )
}

fn validate_request(
    header: Option<&aos_proto::aos::sandbox::local::v1::RequestHeader>,
    source: &[u8],
    original_session: &[u8],
    original_signed_request: &[u8],
    peer: PeerCredentials,
    policy: PeerPolicy,
    now: u64,
) -> Result<ValidatedHostExecutionNoApplyRequestV1, ProtocolValidationError> {
    let header = validate_request_header(
        header.ok_or(ProtocolValidationError::MissingField("header"))?,
        peer,
        policy,
        ProtocolId::HostBroker,
        now,
    )?;
    let canonical_attempt: [u8; HOST_EXECUTION_ARGUMENT_ATTEMPT_BYTES_V1] = source
        .try_into()
        .map_err(|_| ProtocolValidationError::InvalidField("canonical_attempt"))?;
    let original_request_id = canonical_attempt_request_id_v1(&canonical_attempt)
        .map_err(|_| ProtocolValidationError::InvalidField("canonical_attempt"))?;
    let original_session_binding: [u8; 32] = original_session
        .try_into()
        .map_err(|_| ProtocolValidationError::InvalidField("original_session_binding"))?;
    let original_signed_request_digest: [u8; 32] = original_signed_request
        .try_into()
        .map_err(|_| ProtocolValidationError::InvalidField("original_signed_request_digest"))?;
    if original_request_id == *header.request_id()
        || original_session_binding == [0; 32]
        || original_signed_request_digest == [0; 32]
    {
        return Err(ProtocolValidationError::InvalidField(
            "original_request_identity",
        ));
    }
    Ok(ValidatedHostExecutionNoApplyRequestV1 {
        header,
        canonical_attempt,
        original_request_id,
        original_session_binding,
        original_signed_request_digest,
    })
}

/// Decodes method-39's exact committed Host marker and current session link.
///
/// # Errors
///
/// Rejects malformed wire or a marker that differs from the request source,
/// original signed identity, or current authenticated method-39 identity.
pub fn decode_host_execution_argument_no_apply_response_v1(
    body: &[u8],
    request: &ValidatedHostExecutionNoApplyRequestV1,
    terminal_session_binding: [u8; 32],
    terminal_signed_request_digest: [u8; 32],
) -> Result<HostExecutionNoApplyRecordV1, ProtocolValidationError> {
    if body.len() > MAXIMUM_RESPONSE_BODY_BYTES {
        return Err(ProtocolValidationError::ResponseTooLarge);
    }
    let response = TerminalHostExecutionArgumentNoApplyResponseV1::decode_from_slice(body)
        .map_err(|error| ProtocolValidationError::MalformedWire(error.to_string()))?;
    if !response.__buffa_unknown_fields.is_empty() || response.encode_to_vec() != body {
        return Err(ProtocolValidationError::UnknownFields);
    }
    let record = decode_record(&response.canonical_record, request)?;
    let fields = record.fields();
    if fields.terminal_request_id != *request.header.request_id()
        || fields.terminal_session_binding != terminal_session_binding
        || fields.terminal_signed_request_digest != terminal_signed_request_digest
    {
        return Err(ProtocolValidationError::InvalidField("canonical_record"));
    }
    Ok(record)
}

/// Decodes method-40's exact historical Host marker or absence.
///
/// ABSENT never authorizes a new method-39 attempt. RECORDED proves only the
/// exact Host marker under this authenticated response, not Controller failure.
///
/// # Errors
///
/// Rejects malformed wire, invalid status/marker pairing, or a marker with a
/// different original request, source, signed identity, or query request ID.
pub fn decode_host_execution_argument_query_no_apply_response_v1(
    body: &[u8],
    request: &ValidatedHostExecutionNoApplyRequestV1,
) -> Result<HostExecutionNoApplyReadbackV1, ProtocolValidationError> {
    if body.len() > MAXIMUM_RESPONSE_BODY_BYTES {
        return Err(ProtocolValidationError::ResponseTooLarge);
    }
    let response = QueryHostExecutionArgumentNoApplyResponseV1::decode_from_slice(body)
        .map_err(|error| ProtocolValidationError::MalformedWire(error.to_string()))?;
    if !response.__buffa_unknown_fields.is_empty() || response.encode_to_vec() != body {
        return Err(ProtocolValidationError::UnknownFields);
    }
    match response.status.as_known() {
        Some(HostExecutionNoApplyStatusV1::HOST_EXECUTION_NO_APPLY_STATUS_ABSENT)
            if response.canonical_record.is_empty() =>
        {
            Ok(HostExecutionNoApplyReadbackV1::Absent)
        }
        Some(HostExecutionNoApplyStatusV1::HOST_EXECUTION_NO_APPLY_STATUS_RECORDED) => {
            let record = decode_record(&response.canonical_record, request)?;
            if record.fields().terminal_request_id == *request.header.request_id() {
                return Err(ProtocolValidationError::InvalidField("canonical_record"));
            }
            Ok(HostExecutionNoApplyReadbackV1::Recorded(record))
        }
        _ => Err(ProtocolValidationError::InvalidField("status")),
    }
}

fn decode_record(
    bytes: &[u8],
    request: &ValidatedHostExecutionNoApplyRequestV1,
) -> Result<HostExecutionNoApplyRecordV1, ProtocolValidationError> {
    let record = HostExecutionNoApplyRecordV1::decode_canonical(bytes)
        .map_err(|_| ProtocolValidationError::InvalidField("canonical_record"))?;
    let source = request.canonical_attempt();
    let fields = record.fields();
    if fields.execution_id != source[8..24]
        || fields.create_operation_id != source[24..40]
        || fields.original_request_id != request.original_request_id
        || fields.host_boot_id != source[248..264]
        || fields.assignment_digest != source[184..216]
        || fields.source_record_digest != source[304..336]
        || fields.original_session_binding != request.original_session_binding
        || fields.original_signed_request_digest != request.original_signed_request_digest
    {
        return Err(ProtocolValidationError::InvalidField("canonical_record"));
    }
    Ok(record)
}

#[cfg(test)]
mod tests {
    use aos_proto::aos::sandbox::local::v1::{Audience, RequestHeader};
    use sha2::{Digest as _, Sha256};

    use super::*;
    use crate::host_execution_no_apply::HostExecutionNoApplyRecordFieldsV1;

    fn source() -> [u8; HOST_EXECUTION_ARGUMENT_ATTEMPT_BYTES_V1] {
        let mut source = [0; HOST_EXECUTION_ARGUMENT_ATTEMPT_BYTES_V1];
        source[..8].copy_from_slice(b"AOSCIA02");
        source[8..24].copy_from_slice(&[1; 16]);
        source[24..40].copy_from_slice(&[2; 16]);
        source[40..56].copy_from_slice(&[7; 16]);
        source[56..184].fill(3);
        source[184..216].copy_from_slice(&[5; 32]);
        source[216..248].fill(6);
        source[248..264].copy_from_slice(&[8; 16]);
        source[264..296].fill(9);
        // The expired original attempt is still a valid terminal locator.
        source[296..304].copy_from_slice(&1_u64.to_be_bytes());
        let checksum = Sha256::new()
            .chain_update(b"aos.sandbox.controller-argument-attempt.v1\0")
            .chain_update(&source[..304])
            .finalize();
        source[304..].copy_from_slice(&checksum);
        source
    }

    fn header(request_id: [u8; 16]) -> RequestHeader {
        RequestHeader {
            protocol_major: 1,
            request_id: request_id.to_vec(),
            audience: Audience::AUDIENCE_NODE_CONTROLLER.into(),
            deadline_boottime_nanoseconds: 100,
            maximum_response_bytes: 8192,
            ..Default::default()
        }
    }

    fn peer_policy() -> (PeerCredentials, PeerPolicy) {
        (
            PeerCredentials {
                uid: 0,
                gid: 0,
                pid: Some(9),
            },
            PeerPolicy {
                uid: 0,
                gid: Some(0),
                audience: Audience::AUDIENCE_NODE_CONTROLLER,
            },
        )
    }

    fn record(
        source: &[u8; HOST_EXECUTION_ARGUMENT_ATTEMPT_BYTES_V1],
    ) -> HostExecutionNoApplyRecordV1 {
        HostExecutionNoApplyRecordV1::new(HostExecutionNoApplyRecordFieldsV1 {
            execution_id: [1; 16],
            create_operation_id: [2; 16],
            original_request_id: [7; 16],
            terminal_request_id: [9; 16],
            host_boot_id: [8; 16],
            assignment_digest: [5; 32],
            source_record_digest: source[304..336].try_into().unwrap(),
            original_session_binding: [12; 32],
            original_signed_request_digest: [13; 32],
            terminal_session_binding: [14; 32],
            terminal_signed_request_digest: [15; 32],
            runtime_handle: [16; 32],
            execution_store_binding: [17; 32],
            commit_sequence: 18,
        })
        .unwrap()
    }

    #[test]
    fn terminal_and_query_bind_original_and_current_signed_identity() {
        let source = source();
        let (peer, policy) = peer_policy();
        let terminal = TerminalHostExecutionArgumentNoApplyRequestV1 {
            header: Some(header([9; 16])).into(),
            canonical_attempt: source.to_vec(),
            original_session_binding: vec![12; 32],
            original_signed_request_digest: vec![13; 32],
            ..Default::default()
        };
        let validated = decode_host_execution_argument_no_apply_request_v1(
            &terminal.encode_to_vec(),
            peer,
            policy,
            99,
        )
        .unwrap();
        assert_eq!(validated.original_request_id(), [7; 16]);
        let marker = record(&source);
        let response = TerminalHostExecutionArgumentNoApplyResponseV1 {
            canonical_record: marker.encode_canonical().to_vec(),
            ..Default::default()
        };
        assert_eq!(
            decode_host_execution_argument_no_apply_response_v1(
                &response.encode_to_vec(),
                &validated,
                [14; 32],
                [15; 32],
            ),
            Ok(marker),
        );
        assert!(
            decode_host_execution_argument_no_apply_response_v1(
                &response.encode_to_vec(),
                &validated,
                [19; 32],
                [15; 32],
            )
            .is_err()
        );

        let query = QueryHostExecutionArgumentNoApplyRequestV1 {
            header: Some(header([10; 16])).into(),
            canonical_attempt: source.to_vec(),
            original_session_binding: vec![12; 32],
            original_signed_request_digest: vec![13; 32],
            ..Default::default()
        };
        let validated_query = decode_host_execution_argument_query_no_apply_request_v1(
            &query.encode_to_vec(),
            peer,
            policy,
            99,
        )
        .unwrap();
        let recorded = QueryHostExecutionArgumentNoApplyResponseV1 {
            status: HostExecutionNoApplyStatusV1::HOST_EXECUTION_NO_APPLY_STATUS_RECORDED.into(),
            canonical_record: marker.encode_canonical().to_vec(),
            ..Default::default()
        };
        assert_eq!(
            decode_host_execution_argument_query_no_apply_response_v1(
                &recorded.encode_to_vec(),
                &validated_query,
            ),
            Ok(HostExecutionNoApplyReadbackV1::Recorded(marker)),
        );

        let absent = QueryHostExecutionArgumentNoApplyResponseV1 {
            status: HostExecutionNoApplyStatusV1::HOST_EXECUTION_NO_APPLY_STATUS_ABSENT.into(),
            ..Default::default()
        };
        assert_eq!(
            decode_host_execution_argument_query_no_apply_response_v1(
                &absent.encode_to_vec(),
                &validated_query,
            ),
            Ok(HostExecutionNoApplyReadbackV1::Absent),
        );
        let mut malformed_absent = absent;
        malformed_absent.canonical_record = marker.encode_canonical().to_vec();
        assert!(
            decode_host_execution_argument_query_no_apply_response_v1(
                &malformed_absent.encode_to_vec(),
                &validated_query,
            )
            .is_err()
        );
    }

    #[test]
    fn terminal_rejects_reused_or_substituted_original_identity() {
        let (peer, policy) = peer_policy();
        let mut request = TerminalHostExecutionArgumentNoApplyRequestV1 {
            header: Some(header([7; 16])).into(),
            canonical_attempt: source().to_vec(),
            original_session_binding: vec![12; 32],
            original_signed_request_digest: vec![13; 32],
            ..Default::default()
        };
        assert!(
            decode_host_execution_argument_no_apply_request_v1(
                &request.encode_to_vec(),
                peer,
                policy,
                99,
            )
            .is_err()
        );
        request.header = Some(header([9; 16])).into();
        request.original_session_binding = vec![0; 32];
        assert!(
            decode_host_execution_argument_no_apply_request_v1(
                &request.encode_to_vec(),
                peer,
                policy,
                99,
            )
            .is_err()
        );
        request.original_session_binding = vec![12; 32];
        request.canonical_attempt[88..120].fill(0);
        let checksum = Sha256::new()
            .chain_update(b"aos.sandbox.controller-argument-attempt.v1\0")
            .chain_update(&request.canonical_attempt[..304])
            .finalize();
        request.canonical_attempt[304..].copy_from_slice(&checksum);
        assert!(
            decode_host_execution_argument_no_apply_request_v1(
                &request.encode_to_vec(),
                peer,
                policy,
                99,
            )
            .is_err()
        );
        let query = QueryHostExecutionArgumentNoApplyRequestV1 {
            header: Some(header([10; 16])).into(),
            canonical_attempt: request.canonical_attempt,
            original_session_binding: request.original_session_binding,
            original_signed_request_digest: request.original_signed_request_digest,
            ..Default::default()
        };
        assert!(
            decode_host_execution_argument_query_no_apply_request_v1(
                &query.encode_to_vec(),
                peer,
                policy,
                99,
            )
            .is_err()
        );
    }
}
