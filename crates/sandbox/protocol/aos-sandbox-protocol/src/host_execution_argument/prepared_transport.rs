//! Exact versioned Prepare/Accept transport over the existing source decoder.

use aos_sandbox_api::aos::sandbox::local::v1::{
    AcceptHostExecutionArgumentRequestV2, PrepareHostExecutionArgumentRequestV2,
};
use buffa::Message as _;

use super::preparation::HostArgumentPreparationV2;
use super::{validate_source, ValidatedHostExecutionArgumentRequestV1, MAXIMUM_REQUEST_BODY_BYTES};
use crate::{
    PeerCredentials, PeerPolicy, ProtocolValidationError, validate_request_header,
};
use aos_sandbox_model::ProtocolId;

/// Carries the structurally exact accepted source and Host preparation DATA.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ValidatedHostExecutionArgumentAcceptV2 {
    source: ValidatedHostExecutionArgumentRequestV1,
    preparation: HostArgumentPreparationV2,
}

impl ValidatedHostExecutionArgumentAcceptV2 {
    /// Borrows the exact source bound to Accept's actual authenticated ID.
    #[must_use]
    pub const fn source(&self) -> &ValidatedHostExecutionArgumentRequestV1 { &self.source }

    /// Borrows canonical preparation DATA for independent native State checks.
    #[must_use]
    pub const fn preparation(&self) -> &HostArgumentPreparationV2 { &self.preparation }
}

/// Decodes non-consuming Prepare with the existing canonical source validator.
///
/// # Errors
/// Rejects oversized, noncanonical, expired or foreign request/source DATA.
pub fn decode_host_execution_argument_prepare_request_v2(
    body: &[u8], peer: PeerCredentials, policy: PeerPolicy, now: u64,
) -> Result<ValidatedHostExecutionArgumentRequestV1, ProtocolValidationError> {
    if body.len() > MAXIMUM_REQUEST_BODY_BYTES { return Err(ProtocolValidationError::RequestTooLarge); }
    let request = PrepareHostExecutionArgumentRequestV2::decode_from_slice(body)
        .map_err(|error| ProtocolValidationError::MalformedWire(error.to_string()))?;
    if !request.__buffa_unknown_fields.is_empty() || request.encode_to_vec() != body {
        return Err(ProtocolValidationError::UnknownFields);
    }
    let header = validate_request_header(
        request.header.as_option().ok_or(ProtocolValidationError::MissingField("header"))?,
        peer, policy, ProtocolId::HostBroker, now,
    )?;
    validate_source(header, &request.proposed_attempt, false)
}

/// Decodes Accept and checks the unchanged prepared source before native entry.
///
/// # Errors
/// Rejects noncanonical framing, preparation, source, changed fields or reused IDs.
pub fn decode_host_execution_argument_accept_request_v2(
    body: &[u8], peer: PeerCredentials, policy: PeerPolicy, now: u64,
) -> Result<ValidatedHostExecutionArgumentAcceptV2, ProtocolValidationError> {
    if body.len() > MAXIMUM_REQUEST_BODY_BYTES { return Err(ProtocolValidationError::RequestTooLarge); }
    let request = AcceptHostExecutionArgumentRequestV2::decode_from_slice(body)
        .map_err(|error| ProtocolValidationError::MalformedWire(error.to_string()))?;
    if !request.__buffa_unknown_fields.is_empty() || request.encode_to_vec() != body {
        return Err(ProtocolValidationError::UnknownFields);
    }
    let header = validate_request_header(
        request.header.as_option().ok_or(ProtocolValidationError::MissingField("header"))?,
        peer, policy, ProtocolId::HostBroker, now,
    )?;
    let source = validate_source(header, &request.canonical_attempt, false)?;
    let preparation = HostArgumentPreparationV2::decode(&request.canonical_preparation)?;
    preparation.require_accept_source(source.canonical_attempt())?;
    Ok(ValidatedHostExecutionArgumentAcceptV2 { source, preparation })
}
