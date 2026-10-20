//! Shares strict framing for the two paid execution availability endpoints.
//!
//! Endpoint codecs own their finite proposal, accepted-source and observed
//! native coordinates. This framing authenticates no native custody and cannot
//! renew the original cutoff. Unknown fields and alternate protobuf encodings
//! are rejected before either endpoint can interpret its body.

use aos_proto::aos::sandbox::local::v1::{
    ExecutionAvailabilityPhaseV2 as WirePhase, PrepareExecutionAvailabilityRequestV2,
    PrepareExecutionAvailabilityResponseV2,
};
use aos_sandbox_core::ProtocolId;
use buffa::Message as _;

use crate::{
    PeerCredentials, PeerPolicy, ProtocolValidationError, ValidatedHeader, validate_request_header,
};

/// Bounds the common framing before endpoint-specific canonical validation.
pub const MAXIMUM_EXECUTION_AVAILABILITY_BODY_BYTES_V2: usize = 4 * 1024;

/// Selects one finite transition on an already retained native receiver.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ExecutionAvailabilityPhaseV2 {
    /// Enters the original paid interval before durable public acceptance.
    Preaccept,
    /// Binds actual accepted Create DATA to that same native interval.
    AcceptedBind,
}

/// Retains exact common framing while endpoint codecs validate its contents.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ValidatedExecutionAvailabilityRequestV2 {
    header: ValidatedHeader,
    phase: ExecutionAvailabilityPhaseV2,
    proposal: Vec<u8>,
    accepted_source: Vec<u8>,
}

impl ValidatedExecutionAvailabilityRequestV2 {
    /// Borrows the current authenticated request header.
    #[must_use]
    pub const fn header(&self) -> &ValidatedHeader {
        &self.header
    }

    /// Returns the finite native transition selected by this request.
    #[must_use]
    pub const fn phase(&self) -> ExecutionAvailabilityPhaseV2 {
        self.phase
    }

    /// Borrows the endpoint's exact original canonical proposal DATA.
    #[must_use]
    pub fn canonical_proposal(&self) -> &[u8] {
        &self.proposal
    }

    /// Borrows accepted-source DATA, empty only for the preaccept transition.
    #[must_use]
    pub fn canonical_accepted_source(&self) -> &[u8] {
        &self.accepted_source
    }
}

/// Decodes the sole shared availability request framing.
///
/// Endpoint callers must additionally validate both canonical payloads. This
/// function deliberately returns no service, Session or native capability.
///
/// # Errors
/// Rejects oversized/noncanonical protobuf, unknown fields, a foreign or expired
/// header, an unknown phase, an empty proposal or phase/source disagreement.
pub fn decode_execution_availability_request_v2(
    body: &[u8],
    peer: PeerCredentials,
    policy: PeerPolicy,
    protocol: ProtocolId,
    now: u64,
) -> Result<ValidatedExecutionAvailabilityRequestV2, ProtocolValidationError> {
    if body.len() > MAXIMUM_EXECUTION_AVAILABILITY_BODY_BYTES_V2 {
        return Err(ProtocolValidationError::RequestTooLarge);
    }
    let request = PrepareExecutionAvailabilityRequestV2::decode_from_slice(body)
        .map_err(|error| ProtocolValidationError::MalformedWire(error.to_string()))?;
    if !request.__buffa_unknown_fields.is_empty() || request.encode_to_vec() != body {
        return Err(ProtocolValidationError::UnknownFields);
    }
    let header = validate_request_header(
        request
            .header
            .as_option()
            .ok_or(ProtocolValidationError::MissingField("header"))?,
        peer,
        policy,
        protocol,
        now,
    )?;
    let phase = match request.phase.as_known() {
        Some(WirePhase::EXECUTION_AVAILABILITY_PHASE_PREACCEPT)
            if request.canonical_accepted_source.is_empty() =>
        {
            ExecutionAvailabilityPhaseV2::Preaccept
        }
        Some(WirePhase::EXECUTION_AVAILABILITY_PHASE_ACCEPTED_BIND)
            if !request.canonical_accepted_source.is_empty() =>
        {
            ExecutionAvailabilityPhaseV2::AcceptedBind
        }
        _ => {
            return Err(ProtocolValidationError::InvalidField(
                "execution availability phase",
            ));
        }
    };
    if request.canonical_proposal.is_empty() {
        return Err(ProtocolValidationError::MissingField("canonical_proposal"));
    }
    Ok(ValidatedExecutionAvailabilityRequestV2 {
        header,
        phase,
        proposal: request.canonical_proposal,
        accepted_source: request.canonical_accepted_source,
    })
}

/// Decodes the shared response before exact endpoint/Session cross-link checks.
///
/// # Errors
/// Rejects an oversized, empty or noncanonical response with unknown fields.
pub fn decode_execution_availability_response_v2(
    body: &[u8],
) -> Result<Vec<u8>, ProtocolValidationError> {
    if body.len() > MAXIMUM_EXECUTION_AVAILABILITY_BODY_BYTES_V2 {
        return Err(ProtocolValidationError::RequestTooLarge);
    }
    let response = PrepareExecutionAvailabilityResponseV2::decode_from_slice(body)
        .map_err(|error| ProtocolValidationError::MalformedWire(error.to_string()))?;
    if !response.__buffa_unknown_fields.is_empty() || response.encode_to_vec() != body {
        return Err(ProtocolValidationError::UnknownFields);
    }
    if response.canonical_observation.is_empty() {
        return Err(ProtocolValidationError::MissingField(
            "canonical_observation",
        ));
    }
    Ok(response.canonical_observation)
}

#[cfg(test)]
mod tests {
    use super::*;
    use aos_proto::aos::sandbox::local::v1::{Audience, RequestHeader};

    fn request() -> PrepareExecutionAvailabilityRequestV2 {
        PrepareExecutionAvailabilityRequestV2 {
            header: Some(RequestHeader {
                protocol_major: 1,
                request_id: vec![1; 16],
                audience: Audience::AUDIENCE_NODE_CONTROLLER.into(),
                deadline_boottime_nanoseconds: 100,
                maximum_response_bytes: 8192,
                ..Default::default()
            })
            .into(),
            phase: WirePhase::EXECUTION_AVAILABILITY_PHASE_PREACCEPT.into(),
            canonical_proposal: vec![2; 184],
            ..Default::default()
        }
    }

    fn decode(
        request: &PrepareExecutionAvailabilityRequestV2,
    ) -> Result<ValidatedExecutionAvailabilityRequestV2, ProtocolValidationError> {
        decode_execution_availability_request_v2(
            &request.encode_to_vec(),
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
            ProtocolId::HostBroker,
            10,
        )
    }

    #[test]
    fn framing_requires_distinct_preaccept_and_accepted_bind_payloads() {
        let mut request = request();
        assert_eq!(
            decode(&request).unwrap().phase(),
            ExecutionAvailabilityPhaseV2::Preaccept
        );
        request.canonical_accepted_source = vec![3; 216];
        assert!(decode(&request).is_err());
        request.phase = WirePhase::EXECUTION_AVAILABILITY_PHASE_ACCEPTED_BIND.into();
        assert_eq!(
            decode(&request).unwrap().phase(),
            ExecutionAvailabilityPhaseV2::AcceptedBind
        );
        request.canonical_accepted_source.clear();
        assert!(decode(&request).is_err());
        request.phase = WirePhase::EXECUTION_AVAILABILITY_PHASE_UNSPECIFIED.into();
        assert!(decode(&request).is_err());
    }

    #[test]
    fn canonical_protobuf_cannot_hide_unknown_or_repeated_scalar_fields() {
        let canonical = request().encode_to_vec();
        for appended in [&[0x10, 0x01][..], &[0x28, 0x01][..]] {
            let changed = [canonical.as_slice(), appended].concat();
            assert!(
                decode_execution_availability_request_v2(
                    &changed,
                    PeerCredentials {
                        uid: 0,
                        gid: 0,
                        pid: Some(9)
                    },
                    PeerPolicy {
                        uid: 0,
                        gid: Some(0),
                        audience: Audience::AUDIENCE_NODE_CONTROLLER
                    },
                    ProtocolId::HostBroker,
                    10
                )
                .is_err()
            );
        }
    }
}
