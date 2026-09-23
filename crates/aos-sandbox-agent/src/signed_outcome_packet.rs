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

    let mut bytes = Vec::with_capacity(PREFIX_BYTES + frame.len() + SIGNATURE_BYTES);
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
