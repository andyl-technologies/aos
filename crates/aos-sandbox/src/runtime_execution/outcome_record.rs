//! Exact Host observation custody for one signed guest outcome.
//!
//! ```text
//! AOSHRO01 || observation_sequence:u64be || observation_commitment[32]
//! || packet_length:u32be || AOSAGW01 packet || record_digest[32]
//! ```
//!
//! The observation assignment is retained with the packet. Cold recovery
//! cannot silently assign the same guest result a second Host sequence.

use aos_sandbox_agent::signed_outcome_packet::MAX_SIGNED_AGENT_OUTCOME_PACKET_BYTES;
use aos_sandbox_agent::{
    SignedAgentOutcomePacketV1, decode_signed_agent_outcome_packet_v1,
    encode_signed_agent_outcome_packet_v1,
};
use aos_sandbox_core::{ObjectDigest, ObservationSequence};
use sha2::{Digest as _, Sha256};

use super::store::JournalRuntimeExecutionError;

const MAGIC: &[u8; 8] = b"AOSHRO01";
const HEADER_BYTES: usize = 8 + 8 + 32 + 4;
const DIGEST_BYTES: usize = 32;

/// Retains one immutable signed packet and its first Host observation identity.
pub(super) struct HostAgentOutcomeRecordV1 {
    observation_sequence: ObservationSequence,
    observation_commitment: ObjectDigest,
    packet: SignedAgentOutcomePacketV1,
}

impl HostAgentOutcomeRecordV1 {
    pub(super) fn new(
        packet: SignedAgentOutcomePacketV1,
        observation_sequence: ObservationSequence,
        observation_commitment: ObjectDigest,
    ) -> Result<Self, JournalRuntimeExecutionError> {
        if observation_sequence.get() == 0
            || observation_sequence.get() == u64::MAX
            || observation_commitment.as_bytes() == &[0; 32]
        {
            return Err(JournalRuntimeExecutionError::CorruptRecord);
        }
        Ok(Self {
            observation_sequence,
            observation_commitment,
            packet,
        })
    }

    pub(super) const fn packet(&self) -> &SignedAgentOutcomePacketV1 {
        &self.packet
    }

    pub(super) const fn observation_sequence(&self) -> ObservationSequence {
        self.observation_sequence
    }

    pub(super) const fn observation_commitment(&self) -> ObjectDigest {
        self.observation_commitment
    }

    pub(super) fn into_parts(
        self,
    ) -> (
        SignedAgentOutcomePacketV1,
        ObservationSequence,
        ObjectDigest,
    ) {
        (
            self.packet,
            self.observation_sequence,
            self.observation_commitment,
        )
    }

    pub(super) fn encode(&self) -> Result<Vec<u8>, JournalRuntimeExecutionError> {
        let packet = encode_signed_agent_outcome_packet_v1(&self.packet)
            .map_err(|_| JournalRuntimeExecutionError::CorruptRecord)?;
        if packet.len() > MAX_SIGNED_AGENT_OUTCOME_PACKET_BYTES {
            return Err(JournalRuntimeExecutionError::CorruptRecord);
        }
        let length =
            u32::try_from(packet.len()).map_err(|_| JournalRuntimeExecutionError::CorruptRecord)?;

        let mut bytes = Vec::with_capacity(HEADER_BYTES + packet.len() + DIGEST_BYTES);
        bytes.extend_from_slice(MAGIC);
        bytes.extend_from_slice(&self.observation_sequence.get().to_be_bytes());
        bytes.extend_from_slice(self.observation_commitment.as_bytes());
        bytes.extend_from_slice(&length.to_be_bytes());
        bytes.extend_from_slice(&packet);
        let digest: [u8; 32] = Sha256::digest(&bytes).into();
        bytes.extend_from_slice(&digest);
        Ok(bytes)
    }

    pub(super) fn decode(bytes: &[u8]) -> Result<Self, JournalRuntimeExecutionError> {
        if bytes.len() > HEADER_BYTES + MAX_SIGNED_AGENT_OUTCOME_PACKET_BYTES + DIGEST_BYTES
            || bytes.len() < HEADER_BYTES + DIGEST_BYTES
            || bytes.get(..MAGIC.len()) != Some(MAGIC.as_slice())
        {
            return Err(JournalRuntimeExecutionError::CorruptRecord);
        }
        let sequence = u64::from_be_bytes(
            bytes[8..16]
                .try_into()
                .map_err(|_| JournalRuntimeExecutionError::CorruptRecord)?,
        );
        let observation_commitment = ObjectDigest::from_bytes(
            bytes[16..48]
                .try_into()
                .map_err(|_| JournalRuntimeExecutionError::CorruptRecord)?,
        );
        let packet_length = u32::from_be_bytes(
            bytes[48..HEADER_BYTES]
                .try_into()
                .map_err(|_| JournalRuntimeExecutionError::CorruptRecord)?,
        ) as usize;
        if packet_length > MAX_SIGNED_AGENT_OUTCOME_PACKET_BYTES
            || bytes.len() != HEADER_BYTES + packet_length + DIGEST_BYTES
        {
            return Err(JournalRuntimeExecutionError::CorruptRecord);
        }
        let digest: [u8; 32] = Sha256::digest(&bytes[..HEADER_BYTES + packet_length]).into();
        if bytes[HEADER_BYTES + packet_length..] != digest {
            return Err(JournalRuntimeExecutionError::CorruptRecord);
        }
        let packet = decode_signed_agent_outcome_packet_v1(
            &bytes[HEADER_BYTES..HEADER_BYTES + packet_length],
        )
        .map_err(|_| JournalRuntimeExecutionError::CorruptRecord)?;
        let record = Self::new(
            packet,
            ObservationSequence::new(sequence),
            observation_commitment,
        )?;
        if record.encode()? != bytes {
            return Err(JournalRuntimeExecutionError::CorruptRecord);
        }
        Ok(record)
    }
}
