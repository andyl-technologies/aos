//! Exact protected custody for a Host-to-agent execution request.
//!
//! ```text
//! AOSHRQ01 || effect_request[32] || peer_authority[32]
//! || channel_binding[32] || route_binding[32] || frame_length:u32be
//! || AOSAGE01 operation_request || record_digest[32]
//! ```
//!
//! This record proves which request the Host prepared before it could send.
//! Cold recovery may inspect it, but it never mints a new dispatch permit.

use aos_sandbox_agent::protocol::MAX_AGENT_FRAME_BYTES;
use aos_sandbox_agent::{
    AgentFrameV1, AgentOperationRequestV1, SignedAgentOutcomePacketV1, decode_frame_v1,
    encode_frame_v1,
};
use aos_sandbox_core::ObjectDigest;
use aos_sandbox_core::runtime_backend::{
    BackendExecutionInspectionRequestV1, DurableExecutionEffectV1, EffectPhaseV1,
    backend_execution_inspection_binding_v1,
};
use ed25519_dalek::{Signature, VerifyingKey};
use sha2::{Digest as _, Sha256};

use super::agent_reducer::agent_outcome_signing_message_v1;
use super::store::JournalRuntimeExecutionError;

const MAGIC: &[u8; 8] = b"AOSHRQ01";
const HEADER_BYTES: usize = 8 + 32 * 4 + 4;
const DIGEST_BYTES: usize = 32;

pub(super) const ROUTE_KEY_PREFIX: u8 = b'q';

/// Fixes the only peer allowed to own Host request and outcome custody.
#[derive(Clone, Copy)]
pub(super) struct ProtectedAgentRoutePeerV1 {
    public_key: [u8; 32],
    channel_binding: ObjectDigest,
    authority_binding: ObjectDigest,
}

impl ProtectedAgentRoutePeerV1 {
    pub(super) fn new(
        public_key: [u8; 32],
        channel_binding: ObjectDigest,
        authority_binding: ObjectDigest,
    ) -> Result<Self, JournalRuntimeExecutionError> {
        if public_key == [0; 32]
            || channel_binding.as_bytes() == &[0; 32]
            || authority_binding.as_bytes() == &[0; 32]
            || VerifyingKey::from_bytes(&public_key).is_err()
        {
            return Err(JournalRuntimeExecutionError::InvalidBinding);
        }
        Ok(Self {
            public_key,
            channel_binding,
            authority_binding,
        })
    }
}

/// Retains one exact previously prepared request without granting redispatch.
pub(super) struct ProtectedAgentRouteRecordV1 {
    effect_request: ObjectDigest,
    peer_authority: ObjectDigest,
    channel_binding: ObjectDigest,
    route_binding: ObjectDigest,
    request: AgentOperationRequestV1,
}

impl ProtectedAgentRouteRecordV1 {
    pub(super) fn new(
        effect: &DurableExecutionEffectV1,
        request: AgentOperationRequestV1,
        peer_authority: ObjectDigest,
        channel_binding: ObjectDigest,
    ) -> Result<Self, JournalRuntimeExecutionError> {
        let record = Self {
            effect_request: effect.issue().idempotency().request_digest(),
            peer_authority,
            channel_binding,
            route_binding: route_binding(
                effect.issue().idempotency().request_digest(),
                &request,
                peer_authority,
            ),
            request,
        };
        record.validate_effect(effect, true)?;
        Ok(record)
    }

    pub(super) fn request(&self) -> &AgentOperationRequestV1 {
        &self.request
    }

    pub(super) const fn peer_authority(&self) -> ObjectDigest {
        self.peer_authority
    }

    pub(super) const fn channel_binding(&self) -> ObjectDigest {
        self.channel_binding
    }

    pub(super) const fn route_binding(&self) -> ObjectDigest {
        self.route_binding
    }

    pub(super) fn into_recovery_parts(
        self,
    ) -> (AgentOperationRequestV1, ObjectDigest, ObjectDigest) {
        (self.request, self.effect_request, self.route_binding)
    }

    pub(super) fn validate_peer(
        &self,
        peer: ProtectedAgentRoutePeerV1,
    ) -> Result<(), JournalRuntimeExecutionError> {
        if self.peer_authority != peer.authority_binding
            || self.channel_binding != peer.channel_binding
        {
            return Err(JournalRuntimeExecutionError::CorruptRecord);
        }
        Ok(())
    }

    pub(super) fn validate_signed_outcome(
        &self,
        packet: &SignedAgentOutcomePacketV1,
        peer: ProtectedAgentRoutePeerV1,
    ) -> Result<(), JournalRuntimeExecutionError> {
        self.validate_peer(peer)?;
        let outcome = packet.outcome();
        if outcome.session() != self.request.session()
            || outcome.sequence() != self.request.sequence()
            || outcome.operation_id() != self.request.operation_id()
            || outcome.request_commitment() != self.request.request_commitment()
        {
            return Err(JournalRuntimeExecutionError::CorruptRecord);
        }
        let message =
            agent_outcome_signing_message_v1(peer.channel_binding, &self.request, outcome);
        VerifyingKey::from_bytes(&peer.public_key)
            .map_err(|_| JournalRuntimeExecutionError::CorruptRecord)?
            .verify_strict(&message, &Signature::from_bytes(packet.signature()))
            .map_err(|_| JournalRuntimeExecutionError::CorruptRecord)
    }

    pub(super) fn validate_effect(
        &self,
        effect: &DurableExecutionEffectV1,
        require_issued: bool,
    ) -> Result<(), JournalRuntimeExecutionError> {
        if self.effect_request.as_bytes() == &[0; 32]
            || self.peer_authority.as_bytes() == &[0; 32]
            || self.channel_binding.as_bytes() == &[0; 32]
            || self.route_binding.as_bytes() == &[0; 32]
            || self.request.operation_id().as_bytes()
                != effect.issue().idempotency().operation().as_bytes()
            || self.effect_request != effect.issue().idempotency().request_digest()
            || self.route_binding
                != route_binding(self.effect_request, &self.request, self.peer_authority)
            || (require_issued && effect.phase() != EffectPhaseV1::Issued)
            || effect.phase() == EffectPhaseV1::Pending
        {
            return Err(JournalRuntimeExecutionError::CorruptRecord);
        }

        let admission = effect.admission();
        let inspection = BackendExecutionInspectionRequestV1::new(
            self.peer_authority,
            effect.issue().idempotency().operation(),
            effect.issue().sequence(),
            effect.issue().idempotency().request_digest(),
            admission.execution(),
            admission.specification_digest(),
            admission.admission_commitment(),
            *admission.currentness().runtime(),
            admission.currentness().payload_boot_id(),
        )
        .map_err(|_| JournalRuntimeExecutionError::CorruptRecord)?;
        if self.request.backend_request_binding()
            != backend_execution_inspection_binding_v1(&inspection)
        {
            return Err(JournalRuntimeExecutionError::CorruptRecord);
        }
        Ok(())
    }

    pub(super) fn encode(&self) -> Result<Vec<u8>, JournalRuntimeExecutionError> {
        let frame = encode_frame_v1(&AgentFrameV1::OperationRequest(self.request.clone()));
        if frame.len() > MAX_AGENT_FRAME_BYTES {
            return Err(JournalRuntimeExecutionError::CorruptRecord);
        }
        let length =
            u32::try_from(frame.len()).map_err(|_| JournalRuntimeExecutionError::CorruptRecord)?;

        let mut bytes = Vec::with_capacity(HEADER_BYTES + frame.len() + DIGEST_BYTES);
        bytes.extend_from_slice(MAGIC);
        bytes.extend_from_slice(self.effect_request.as_bytes());
        bytes.extend_from_slice(self.peer_authority.as_bytes());
        bytes.extend_from_slice(self.channel_binding.as_bytes());
        bytes.extend_from_slice(self.route_binding.as_bytes());
        bytes.extend_from_slice(&length.to_be_bytes());
        bytes.extend_from_slice(&frame);
        let digest: [u8; 32] = Sha256::digest(&bytes).into();
        bytes.extend_from_slice(&digest);
        Ok(bytes)
    }

    pub(super) fn decode(bytes: &[u8]) -> Result<Self, JournalRuntimeExecutionError> {
        if bytes.len() > HEADER_BYTES + MAX_AGENT_FRAME_BYTES + DIGEST_BYTES
            || bytes.len() < HEADER_BYTES + DIGEST_BYTES
            || bytes.get(..MAGIC.len()) != Some(MAGIC.as_slice())
        {
            return Err(JournalRuntimeExecutionError::CorruptRecord);
        }
        let length = u32::from_be_bytes(
            bytes[136..HEADER_BYTES]
                .try_into()
                .map_err(|_| JournalRuntimeExecutionError::CorruptRecord)?,
        ) as usize;
        if length > MAX_AGENT_FRAME_BYTES || bytes.len() != HEADER_BYTES + length + DIGEST_BYTES {
            return Err(JournalRuntimeExecutionError::CorruptRecord);
        }
        let digest: [u8; 32] = Sha256::digest(&bytes[..HEADER_BYTES + length]).into();
        if bytes[HEADER_BYTES + length..] != digest {
            return Err(JournalRuntimeExecutionError::CorruptRecord);
        }
        let AgentFrameV1::OperationRequest(request) =
            decode_frame_v1(&bytes[HEADER_BYTES..HEADER_BYTES + length])
                .map_err(|_| JournalRuntimeExecutionError::CorruptRecord)?
        else {
            return Err(JournalRuntimeExecutionError::CorruptRecord);
        };
        let record = Self {
            effect_request: digest_at(bytes, 8)?,
            peer_authority: digest_at(bytes, 40)?,
            channel_binding: digest_at(bytes, 72)?,
            route_binding: digest_at(bytes, 104)?,
            request,
        };
        if record.encode()? != bytes {
            return Err(JournalRuntimeExecutionError::CorruptRecord);
        }
        Ok(record)
    }
}

pub(super) fn route_key(operation: &[u8; 16]) -> Vec<u8> {
    let mut key = Vec::with_capacity(17);
    key.push(ROUTE_KEY_PREFIX);
    key.extend_from_slice(operation);
    key
}

pub(super) fn route_binding(
    effect_request: ObjectDigest,
    agent_request: &AgentOperationRequestV1,
    peer_authority: ObjectDigest,
) -> ObjectDigest {
    let mut digest = Sha256::new();
    digest.update(b"aos.sandbox.runtime-execution.coowned-agent-route.v1\0");
    digest.update(effect_request.as_bytes());
    digest.update(agent_request.request_commitment().as_bytes());
    digest.update(agent_request.session().digest().as_bytes());
    digest.update(peer_authority.as_bytes());
    ObjectDigest::from_bytes(digest.finalize().into())
}

fn digest_at(bytes: &[u8], offset: usize) -> Result<ObjectDigest, JournalRuntimeExecutionError> {
    let end = offset + 32;
    let digest = bytes
        .get(offset..end)
        .ok_or(JournalRuntimeExecutionError::CorruptRecord)?
        .try_into()
        .map_err(|_| JournalRuntimeExecutionError::CorruptRecord)?;
    Ok(ObjectDigest::from_bytes(digest))
}
