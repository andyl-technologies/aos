//! Bounded wire carrier for a signed guest-agent operation outcome.
//!
//! The `AOSAGE01` outcome frame is also used inside protected checkpoints,
//! where its signature has already been verified. On the Host/guest channel,
//! the detached Ed25519 signature must travel with that exact frame:
//!
//! ```text
//! "AOSAGW01" || frame_length:u32be || AOSAGE01 outcome_frame || signature[64]
//! ```
//!
//! Framing does not grant authority. The Host must verify the signature over
//! its outstanding request and protected peer binding before consuming it.

use crate::model::AgentExecutionOutcomeV1;
use crate::protocol::{
    AgentFrameV1, AgentProtocolError, MAX_AGENT_FRAME_BYTES, decode_frame_v1, encode_frame_v1,
};

const MAGIC: &[u8; 8] = b"AOSAGW01";
const PREFIX_BYTES: usize = MAGIC.len() + size_of::<u32>();
const SIGNATURE_BYTES: usize = 64;

/// Maximum complete signed outcome packet, including its detached signature.
pub const MAX_SIGNED_AGENT_OUTCOME_PACKET_BYTES: usize =
    PREFIX_BYTES + MAX_AGENT_FRAME_BYTES + SIGNATURE_BYTES;

/// Supplies the exact signed packet width for the existing outcome frame.
///
/// Returns `None` on arithmetic overflow or a frame beyond the existing limit.
#[must_use]
pub fn signed_outcome_packet_bytes_v5(frame_bytes: usize) -> Option<usize> {
    if frame_bytes > MAX_AGENT_FRAME_BYTES { return None; }
    PREFIX_BYTES.checked_add(frame_bytes)?.checked_add(SIGNATURE_BYTES)
}

/// Supplies the closed standard Observe reply ceiling before native receive.
///
/// Standard Guest Observe returns a PID or raw wait status in its existing
/// fixed envelope. A larger authenticated-channel reply must be retained and
/// refused by the selected monitor receiver; it cannot enlarge this invoice.
#[must_use]
pub fn observe_signed_outcome_packet_bytes_v5() -> Option<usize> {
    signed_outcome_packet_bytes_v5(crate::protocol::operation_outcome_frame_bytes_v5(
        crate::protocol::observe_result_bytes_v5())?)
}

/// Retains one untrusted outcome and its exact detached signature.
pub struct SignedAgentOutcomePacketV1 {
    outcome: AgentExecutionOutcomeV1,
    signature: [u8; SIGNATURE_BYTES],
}

impl SignedAgentOutcomePacketV1 {
    /// Wraps one outcome and nonzero detached signature without authenticating it.
    ///
    /// # Errors
    ///
    /// Returns [`SignedAgentOutcomePacketErrorV1::InvalidSignature`] for the
    /// all-zero signature sentinel.
    pub fn new(
        outcome: AgentExecutionOutcomeV1,
        signature: [u8; SIGNATURE_BYTES],
    ) -> Result<Self, SignedAgentOutcomePacketErrorV1> {
        if signature == [0; SIGNATURE_BYTES] {
            return Err(SignedAgentOutcomePacketErrorV1::InvalidSignature);
        }
        Ok(Self { outcome, signature })
    }

    /// Borrows the exact outcome carried by this packet.
    #[must_use]
    pub const fn outcome(&self) -> &AgentExecutionOutcomeV1 {
        &self.outcome
    }

    /// Borrows the untrusted detached signature.
    #[must_use]
    pub const fn signature(&self) -> &[u8; SIGNATURE_BYTES] {
        &self.signature
    }

    /// Splits the untrusted packet for exact protected-peer verification.
    #[must_use]
    pub fn into_parts(self) -> (AgentExecutionOutcomeV1, [u8; SIGNATURE_BYTES]) {
        (self.outcome, self.signature)
    }
}

/// Encodes one bounded outcome frame and its detached signature.
///
/// # Errors
///
/// Returns [`SignedAgentOutcomePacketErrorV1::FrameTooLarge`] if the encoded
/// outcome exceeds the `AOSAGE01` frame ceiling.
pub fn encode_signed_agent_outcome_packet_v1(
    packet: &SignedAgentOutcomePacketV1,
) -> Result<Vec<u8>, SignedAgentOutcomePacketErrorV1> {
    let frame = encode_frame_v1(&AgentFrameV1::OperationOutcome(packet.outcome.clone()));
    if frame.len() > MAX_AGENT_FRAME_BYTES {
        return Err(SignedAgentOutcomePacketErrorV1::FrameTooLarge);
    }
    let frame_length =
        u32::try_from(frame.len()).map_err(|_| SignedAgentOutcomePacketErrorV1::FrameTooLarge)?;

    let capacity = signed_outcome_packet_bytes_v5(frame.len())
        .ok_or(SignedAgentOutcomePacketErrorV1::FrameTooLarge)?;
    let mut bytes = Vec::with_capacity(capacity);
    bytes.extend_from_slice(MAGIC);
    bytes.extend_from_slice(&frame_length.to_be_bytes());
    bytes.extend_from_slice(&frame);
    bytes.extend_from_slice(&packet.signature);
    Ok(bytes)
}

/// Decodes one exact bounded signed-outcome packet without trusting its signer.
///
/// # Errors
///
/// Returns [`SignedAgentOutcomePacketErrorV1`] for an oversized, truncated,
/// noncanonical, wrong-kind, or unsigned packet.
pub fn decode_signed_agent_outcome_packet_v1(
    bytes: &[u8],
) -> Result<SignedAgentOutcomePacketV1, SignedAgentOutcomePacketErrorV1> {
    if bytes.len() > MAX_SIGNED_AGENT_OUTCOME_PACKET_BYTES {
        return Err(SignedAgentOutcomePacketErrorV1::FrameTooLarge);
    }
    let Some((prefix, body)) = bytes.split_at_checked(PREFIX_BYTES) else {
        return Err(SignedAgentOutcomePacketErrorV1::InvalidPacket);
    };
    if prefix.get(..MAGIC.len()) != Some(MAGIC.as_slice()) {
        return Err(SignedAgentOutcomePacketErrorV1::InvalidPacket);
    }
    let frame_length = u32::from_be_bytes(
        prefix[MAGIC.len()..]
            .try_into()
            .map_err(|_| SignedAgentOutcomePacketErrorV1::InvalidPacket)?,
    ) as usize;
    if frame_length > MAX_AGENT_FRAME_BYTES
        || body.len() != frame_length.saturating_add(SIGNATURE_BYTES)
    {
        return Err(SignedAgentOutcomePacketErrorV1::InvalidPacket);
    }
    let (frame, signature) = body.split_at(frame_length);
    let AgentFrameV1::OperationOutcome(outcome) = decode_frame_v1(frame)? else {
        return Err(SignedAgentOutcomePacketErrorV1::InvalidPacket);
    };
    SignedAgentOutcomePacketV1::new(
        outcome,
        signature
            .try_into()
            .map_err(|_| SignedAgentOutcomePacketErrorV1::InvalidPacket)?,
    )
}

/// Reports a malformed signed-outcome transport packet.
#[derive(Clone, Debug, Eq, PartialEq, thiserror::Error)]
pub enum SignedAgentOutcomePacketErrorV1 {
    /// The outcome exceeds its framing ceiling.
    #[error("signed agent outcome exceeds its byte limit")]
    FrameTooLarge,
    /// The packet has the wrong magic, length, frame kind, or trailing bytes.
    #[error("signed agent outcome packet is invalid")]
    InvalidPacket,
    /// The embedded `AOSAGE01` frame is invalid.
    #[error("signed agent outcome frame is invalid: {0}")]
    Frame(#[from] AgentProtocolError),
    /// The detached signature uses its all-zero sentinel.
    #[error("signed agent outcome signature is absent")]
    InvalidSignature,
}

#[cfg(test)]
mod observe_geometry_tests {
    use super::*;
    use crate::model::{AgentExecutionOperationV1, AgentExecutionPhaseV1,
        AgentOperationIdV1, AgentOperationRequestV1, AgentOperationSequenceV1,
        AgentSessionBindingV1};
    use aos_sandbox_model::{ExecutionId, ObjectDigest};

    #[test]
    fn actual_observe_request_and_signed_outcomes_match_closed_geometry() {
        let request = AgentOperationRequestV1::new(
            AgentSessionBindingV1::from_digest(ObjectDigest::from_bytes([1; 32])).unwrap(),
            AgentOperationSequenceV1::new(1).unwrap(),
            AgentOperationIdV1::new([2; 16]).unwrap(),
            ObjectDigest::from_bytes([3; 32]),
            AgentExecutionOperationV1::Observe { execution: ExecutionId::from_bytes([4; 16]) },
        ).unwrap();
        let frame = encode_frame_v1(&AgentFrameV1::OperationRequest(request.clone()));
        assert_eq!(frame.len(), crate::protocol::observe_request_frame_bytes_v5());
        assert_eq!(frame.len(), 146);
        assert!(matches!(decode_frame_v1(&frame).unwrap(), AgentFrameV1::OperationRequest(value) if value == request));

        for (magic, phase, kind) in [
            (b"AOSGER01", AgentExecutionPhaseV1::Running, 5),
            (b"AOSGER02", AgentExecutionPhaseV1::Exited, 6),
            (b"AOSGER02", AgentExecutionPhaseV1::Canceled, 7),
            (b"AOSGER03", AgentExecutionPhaseV1::Failed, 8),
        ] {
            let mut result = Vec::new();
            result.extend_from_slice(magic);
            result.push(kind);
            result.extend_from_slice(&4u32.to_be_bytes());
            result.extend_from_slice(&123u32.to_be_bytes());
            assert_eq!(result.len(), crate::protocol::observe_result_bytes_v5());
            let outcome = AgentExecutionOutcomeV1::new(&request, phase, result).unwrap();
            let packet = SignedAgentOutcomePacketV1::new(outcome.clone(), [9; 64]).unwrap();
            let bytes = encode_signed_agent_outcome_packet_v1(&packet).unwrap();
            assert_eq!(bytes.len(), observe_signed_outcome_packet_bytes_v5().unwrap());
            assert_eq!(bytes.len(), 227);
            assert_eq!(decode_signed_agent_outcome_packet_v1(&bytes).unwrap().outcome(), &outcome);
        }
    }
}
