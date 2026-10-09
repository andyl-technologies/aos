//! Historical Nix body comparison without peer, clock or current-owner admission.
//!
//! Exact canonical request/response/observation bodies reuse the live comparison
//! engines. Original signed-envelope/transcript coordinates are compared as
//! historical DATA; independently pinned complete signature replay remains the
//! concrete archive owner's responsibility. Nothing here constructs a live
//! validated request, Session, recipe admission, floor or currentness proof.

use aos_proto::aos::sandbox::local::v1::{Audience, BrokerMethod, NixBuildRequestV2, NixBuildResponseV2};
use aos_sandbox_broker_session_protocol::{
    BrokerSessionProtocolV1, CanonicalBrokerRequestEnvelopeV1, VerifiedBrokerSessionTranscriptV1,
};
use aos_sandbox_core::ProtocolId;

use super::{
    NixBuildObservationV2, NixRequestComparisonV2, compare_nix_build_response_v2,
    compare_nix_request_body, decode_nix_request_wire, is_nix_method, observation,
    require_nix_request_size,
};
use crate::{ProtocolValidationError, ValidatedAssignmentFence, exact_nonzero};

#[cfg(test)]
mod tests;

/// Retains canonical historical Nix comparison DATA, not live request admission.
///
/// The original absolute deadline is preserved in the wire header, without
/// consulting a current clock. Envelope/transcript equality does not verify the
/// request signature or independently establish the transcript's pin provenance;
/// the owner must replay complete signed history under its own retained pins.
#[derive(Clone, Debug, PartialEq)]
pub struct HistoricalNixBuildRequestV2 {
    wire: NixBuildRequestV2,
    fence: ValidatedAssignmentFence,
    request_id: [u8; 16],
    commitment: [u8; 32],
    method: BrokerMethod,
    session_binding: [u8; 32],
    client_process: [u8; 16],
}

impl HistoricalNixBuildRequestV2 {
    /// Borrows the canonical historical body, including its original deadline.
    #[must_use]
    pub const fn wire(&self) -> &NixBuildRequestV2 {
        &self.wire
    }

    /// Borrows structural assignment coordinates, not current assignment proof.
    #[must_use]
    pub const fn fence(&self) -> &ValidatedAssignmentFence {
        &self.fence
    }

    /// Returns the original nonzero request identifier.
    #[must_use]
    pub const fn request_id(&self) -> &[u8; 16] {
        &self.request_id
    }

    /// Returns the method-separated commitment of the complete canonical body.
    #[must_use]
    pub const fn commitment(&self) -> [u8; 32] {
        self.commitment
    }

    /// Returns the closed original Nix method.
    #[must_use]
    pub const fn method(&self) -> BrokerMethod {
        self.method
    }

    /// Returns the original hello-pair binding as historical comparison DATA.
    #[must_use]
    pub const fn session_binding(&self) -> [u8; 32] {
        self.session_binding
    }

    /// Returns the original signed client-process coordinate, not a live peer.
    #[must_use]
    pub const fn client_process(&self) -> [u8; 16] {
        self.client_process
    }

    fn comparison(&self) -> NixRequestComparisonV2<'_> {
        NixRequestComparisonV2 {
            request_id: &self.request_id,
            wire: &self.wire,
            commitment: self.commitment,
            method: self.method,
        }
    }
}

/// Decodes historical Nix DATA joined to its canonical envelope and transcript.
///
/// This comparison accepts an expired original deadline but never changes it.
/// The canonical envelope's signature must still be independently verified by
/// full historical traffic replay. No peer, policy or clock is fabricated.
///
/// # Errors
///
/// Rejects excess body/packet bounds, foreign methods/protocols, descriptors,
/// session/process mismatch, noncanonical wire, original header mismatch,
/// zero deadline, invalid response bound, fence or method-specific coordinates.
pub fn decode_historical_nix_build_request_v2(
    original: &CanonicalBrokerRequestEnvelopeV1,
    transcript: &VerifiedBrokerSessionTranscriptV1,
) -> Result<HistoricalNixBuildRequestV2, ProtocolValidationError> {
    let bytes = original.message().body.as_slice();
    require_nix_request_size(bytes)?;
    let method = original.signed_artifact().method();
    if !is_nix_method(method)
        || transcript.protocol() != BrokerSessionProtocolV1::Nix
        || transcript.audience() != Audience::AUDIENCE_NODE_CONTROLLER
        || original.message().method.as_known() != Some(method)
    {
        return Err(ProtocolValidationError::MethodMismatch);
    }

    let subject = original.signed_artifact().subject();
    if !original.message().descriptors.is_empty()
        || original.encoded_len() > transcript.negotiated_maximum_request_bytes()
        || subject.session_binding() != transcript.session_binding()
        || subject.client_process() != transcript.client_process()
        || subject.cleared_fields_digest() != original.cleared_fields_digest()
    {
        return Err(ProtocolValidationError::InvalidField("Nix historical session"));
    }

    let wire = decode_nix_request_wire(bytes)?;
    compare_historical_header(
        &wire,
        subject.request_id(),
        transcript.protocol_version(),
        transcript.negotiated_maximum_response_bytes(),
    )?;
    let (fence, commitment) = compare_nix_request_body(bytes, method, &wire)?;

    Ok(HistoricalNixBuildRequestV2 {
        wire,
        fence,
        request_id: subject.request_id(),
        commitment,
        method,
        session_binding: subject.session_binding(),
        client_process: subject.client_process(),
    })
}

// Only historical field comparisons occur here. In particular, a nonzero old
// deadline is not tested against a supplied or fabricated current time.
fn compare_historical_header(
    wire: &NixBuildRequestV2,
    original_request_id: [u8; 16],
    original_version: (u16, u16),
    original_response_bound: u32,
) -> Result<(), ProtocolValidationError> {
    let header = wire.header.as_option()
        .ok_or(ProtocolValidationError::MissingField("header"))?;
    if !header.__buffa_unknown_fields.is_empty() {
        return Err(ProtocolValidationError::UnknownFields);
    }
    if header.audience.as_known() != Some(Audience::AUDIENCE_NODE_CONTROLLER) {
        return Err(ProtocolValidationError::InvalidField("Nix historical audience"));
    }

    let version = crate::validate_header_protocol(header, ProtocolId::NixBuildBroker)?;
    let request_id = exact_nonzero::<16>(&header.request_id, "header.request_id")?;
    if (version.major(), version.minor()) != original_version || request_id != original_request_id {
        return Err(ProtocolValidationError::InvalidField("Nix historical header"));
    }
    if header.deadline_boottime_nanoseconds == 0 {
        return Err(ProtocolValidationError::DeadlineExpired);
    }
    if !(crate::MINIMUM_RESPONSE_BYTES..=crate::MAXIMUM_RESPONSE_BYTES)
        .contains(&header.maximum_response_bytes)
        || header.maximum_response_bytes > original_response_bound
    {
        return Err(ProtocolValidationError::InvalidResponseBound);
    }
    Ok(())
}

/// Decodes historical response DATA against its exact original request body.
///
/// Signature/outcome linkage, protected provenance and physical readback remain
/// separate owner obligations. This cannot construct a live request or outcome.
///
/// # Errors
///
/// Rejects the same response size, method, canonical-wire, original-coordinate
/// and observation mismatches as the shared live comparison engine.
pub fn decode_historical_nix_build_response_v2(
    bytes: &[u8],
    request: &HistoricalNixBuildRequestV2,
    method: BrokerMethod,
) -> Result<NixBuildResponseV2, ProtocolValidationError> {
    compare_nix_build_response_v2(bytes, &request.comparison(), method)
}

/// Decodes historical observation DATA against its exact original request.
///
/// No store/root observation, signature provenance or currentness is inferred.
///
/// # Errors
///
/// Rejects the same framing, canonical shape, method and coordinate mismatches
/// as the shared live observation comparison engine.
pub fn decode_historical_nix_build_observation_v2(
    bytes: &[u8],
    request: &HistoricalNixBuildRequestV2,
) -> Result<NixBuildObservationV2, ProtocolValidationError> {
    observation::compare_nix_build_observation_v2(bytes, &request.comparison())
}
