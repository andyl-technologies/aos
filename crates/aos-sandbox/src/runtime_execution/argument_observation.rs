//! One-shot protected custody for Guest runtime-argument observations.
//!
//! ```text
//! key   = 'g' || execution[16]
//! value = AOSGAO01 || execution[16] || create_operation[16]
//!         || phase:u8 || request_length:u16be || handshake_length:u16be
//!         || response_length:u16be || canonical_request
//!         || canonical_handshake || signed_handshake_response
//!         || signed_packet_digest[32] || sha256(prefix)[32]
//! ```
//!
//! A pending record is committed before the Host sends its challenge. A
//! completed record consumes that challenge for exactly one signed packet.

use aos_sandbox_agent::{
    AgentFeatureV1, AgentFrameV1, AgentHandshakeRequestV1, AgentHandshakeResponseV1,
    AgentSessionBindingV1, GuestRuntimeArgumentObserveRequestV1, decode_frame_v1, encode_frame_v1,
};
use aos_sandbox_core::{ExecutionId, ObjectDigest, OperationId};
use sha2::{Digest as _, Sha256};

const MAGIC: &[u8; 8] = b"AOSGAO01";
pub(super) const KEY_PREFIX: u8 = b'g';
const FIXED_BYTES: usize = 8 + 16 + 16 + 1 + 2 + 2 + 2 + 32 + 32;

/// Retains the current protected phase of one exact argument observation.
#[derive(Clone, Debug, Eq, PartialEq)]
pub(super) struct ArgumentObservationRecordV1 {
    pub(super) execution: ExecutionId,
    pub(super) create_operation: OperationId,
    pub(super) request: GuestRuntimeArgumentObserveRequestV1,
    pub(super) handshake: AgentHandshakeRequestV1,
    pub(super) response: AgentHandshakeResponseV1,
    pub(super) signed_packet_digest: Option<ObjectDigest>,
}

impl ArgumentObservationRecordV1 {
    pub(super) fn key(execution: ExecutionId) -> [u8; 17] {
        let mut key = [0_u8; 17];
        key[0] = KEY_PREFIX;
        key[1..].copy_from_slice(execution.as_bytes());
        key
    }

    pub(super) fn encode(&self) -> Result<Vec<u8>, ()> {
        let request = self.request.encode();
        let handshake = encode_frame_v1(&AgentFrameV1::HandshakeRequest(self.handshake.clone()));
        let response = encode_frame_v1(&AgentFrameV1::HandshakeResponse(self.response.clone()));
        let request_length = u16::try_from(request.len()).map_err(|_| ())?;
        let handshake_length = u16::try_from(handshake.len()).map_err(|_| ())?;
        let response_length = u16::try_from(response.len()).map_err(|_| ())?;
        let mut bytes =
            Vec::with_capacity(FIXED_BYTES + request.len() + handshake.len() + response.len());
        bytes.extend_from_slice(MAGIC);
        bytes.extend_from_slice(self.execution.as_bytes());
        bytes.extend_from_slice(self.create_operation.as_bytes());
        bytes.push(u8::from(self.signed_packet_digest.is_some()) + 1);
        bytes.extend_from_slice(&request_length.to_be_bytes());
        bytes.extend_from_slice(&handshake_length.to_be_bytes());
        bytes.extend_from_slice(&response_length.to_be_bytes());
        bytes.extend_from_slice(&request);
        bytes.extend_from_slice(&handshake);
        bytes.extend_from_slice(&response);
        bytes.extend_from_slice(
            self.signed_packet_digest
                .unwrap_or(ObjectDigest::from_bytes([0; 32]))
                .as_bytes(),
        );
        let checksum = Sha256::digest(&bytes);
        bytes.extend_from_slice(&checksum);
        Ok(bytes)
    }

    pub(super) fn decode(bytes: &[u8]) -> Result<Self, ()> {
        if bytes.len() < FIXED_BYTES || bytes.get(..8) != Some(MAGIC.as_slice()) {
            return Err(());
        }
        let execution = ExecutionId::from_bytes(bytes[8..24].try_into().map_err(|_| ())?);
        let create_operation = OperationId::from_bytes(bytes[24..40].try_into().map_err(|_| ())?);
        let phase = bytes[40];
        let request_length = usize::from(u16::from_be_bytes(
            bytes[41..43].try_into().map_err(|_| ())?,
        ));
        let handshake_length = usize::from(u16::from_be_bytes(
            bytes[43..45].try_into().map_err(|_| ())?,
        ));
        let response_length = usize::from(u16::from_be_bytes(
            bytes[45..47].try_into().map_err(|_| ())?,
        ));
        if execution.as_bytes() == &[0; 16]
            || create_operation.as_bytes() == &[0; 16]
            || !matches!(phase, 1 | 2)
            || handshake_length == 0
            || response_length == 0
            || bytes.len() != FIXED_BYTES + request_length + handshake_length + response_length
        {
            return Err(());
        }
        let request_end = 47 + request_length;
        let handshake_end = request_end + handshake_length;
        let response_end = handshake_end + response_length;
        let request = GuestRuntimeArgumentObserveRequestV1::decode(&bytes[47..request_end])
            .map_err(|_| ())?;
        let AgentFrameV1::HandshakeRequest(handshake) =
            decode_frame_v1(&bytes[request_end..handshake_end]).map_err(|_| ())?
        else {
            return Err(());
        };
        let AgentFrameV1::HandshakeResponse(response) =
            decode_frame_v1(&bytes[handshake_end..response_end]).map_err(|_| ())?
        else {
            return Err(());
        };
        let binding =
            AgentSessionBindingV1::derive(&handshake, response.agent_instance()).map_err(|_| ())?;
        if request.runtime() != handshake.runtime()
            || request.session() != binding
            || response.session_binding() != binding
            || request.channel() != handshake.host_channel_binding()
            || !response
                .features()
                .contains(AgentFeatureV1::RuntimeArgumentObservation)
        {
            return Err(());
        }
        let packet_digest = ObjectDigest::from_bytes(
            bytes[response_end..response_end + 32]
                .try_into()
                .map_err(|_| ())?,
        );
        let expected_checksum = Sha256::digest(&bytes[..bytes.len() - 32]);
        if bytes[bytes.len() - 32..] != expected_checksum[..]
            || (phase == 1 && packet_digest.as_bytes() != &[0; 32])
            || (phase == 2 && packet_digest.as_bytes() == &[0; 32])
        {
            return Err(());
        }
        let record = Self {
            execution,
            create_operation,
            request,
            handshake,
            response,
            signed_packet_digest: (phase == 2).then_some(packet_digest),
        };
        if record.encode().map_err(|_| ())? != bytes {
            return Err(());
        }
        Ok(record)
    }

    pub(super) fn digest(&self) -> Result<ObjectDigest, ()> {
        Ok(ObjectDigest::from_bytes(
            Sha256::digest(self.encode()?).into(),
        ))
    }
}

#[cfg(test)]
mod tests {
    use aos_sandbox_agent::{
        AgentFeatureSetV1, AgentFeatureV1, AgentNonceV1, AgentRuntimeBindingV1,
        AgentSessionBindingV1, AgentSessionIdV1,
    };
    use aos_sandbox_core::{
        AssignmentEpoch, DesiredGeneration, FeatureRef, IncarnationId, NamespaceGeneration,
        SandboxId,
    };

    use super::*;

    fn record() -> ArgumentObservationRecordV1 {
        let runtime = AgentRuntimeBindingV1::new(
            SandboxId::from_bytes([1; 16]),
            IncarnationId::from_bytes([2; 16]),
            AssignmentEpoch::new(3),
            ObjectDigest::from_bytes([4; 32]),
            DesiredGeneration::new(5),
            NamespaceGeneration::new(6),
            [7; 16],
        )
        .expect("runtime");
        let handshake = AgentHandshakeRequestV1::new(
            AgentSessionIdV1::new([8; 16]).expect("session ID"),
            runtime.clone(),
            AgentNonceV1::new([15; 32]).expect("nonce"),
            ObjectDigest::from_bytes([9; 32]),
        )
        .expect("handshake");
        let session = AgentSessionBindingV1::derive(&handshake, &[16; 16]).expect("session");
        let response = AgentHandshakeResponseV1::new(
            session,
            [16; 16],
            AgentFeatureSetV1::new(vec![
                AgentFeatureV1::Readiness,
                AgentFeatureV1::ExecutionHandoff,
                AgentFeatureV1::RuntimeArgumentObservation,
            ])
            .expect("features"),
            [17; 64],
        )
        .expect("response");
        let request = GuestRuntimeArgumentObserveRequestV1::new(
            runtime,
            session,
            ObjectDigest::from_bytes([9; 32]),
            [10; 32],
            FeatureRef::new("aos.sandbox.runtime.linux-systemd", 1, 0).expect("profile"),
            ObjectDigest::from_bytes([11; 32]),
        )
        .expect("request");
        ArgumentObservationRecordV1 {
            execution: ExecutionId::from_bytes([12; 16]),
            create_operation: OperationId::from_bytes([13; 16]),
            request,
            handshake,
            response,
            signed_packet_digest: None,
        }
    }

    #[test]
    fn pending_and_completed_records_round_trip_canonically() {
        let pending = record();
        assert_eq!(
            ArgumentObservationRecordV1::decode(&pending.encode().unwrap()),
            Ok(pending.clone())
        );

        let completed = ArgumentObservationRecordV1 {
            signed_packet_digest: Some(ObjectDigest::from_bytes([14; 32])),
            ..pending
        };
        assert_eq!(
            ArgumentObservationRecordV1::decode(&completed.encode().unwrap()),
            Ok(completed)
        );
    }

    #[test]
    fn record_rejects_phase_key_and_packet_substitution() {
        let valid = record().encode().unwrap();
        for offset in [8, 24, 40, 43, valid.len() - 33] {
            let mut corrupted = valid.clone();
            corrupted[offset] ^= 1;
            assert!(ArgumentObservationRecordV1::decode(&corrupted).is_err());
        }
    }

    #[test]
    fn record_rejects_a_new_session_paired_with_an_old_request() {
        let mut substituted = record();
        substituted.handshake = AgentHandshakeRequestV1::new(
            AgentSessionIdV1::new([18; 16]).unwrap(),
            substituted.handshake.runtime().clone(),
            AgentNonceV1::new([19; 32]).unwrap(),
            substituted.handshake.host_channel_binding(),
        )
        .unwrap();
        let bytes = substituted.encode().unwrap();

        assert!(ArgumentObservationRecordV1::decode(&bytes).is_err());
    }
}
