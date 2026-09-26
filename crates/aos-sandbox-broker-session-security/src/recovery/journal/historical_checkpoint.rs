//! Immutable hello and context evidence for read-only old-session replay.
//!
//! ```text
//! AOSBSCP1 | version:u16be | context-length:u32be | client-length:u32be |
//! broker-length:u32be | peer-uid:u32be | peer-gid:u32be | peer-pid:u32be |
//! canonical-context | signed-client-hello | signed-broker-hello | sha256:32
//! ```

use aos_sandbox_broker_session_protocol::{
    CLIENT_HELLO_MAXIMUM_BYTES, ProtectedBrokerSessionVerificationContextV1,
    SERVER_HELLO_MAXIMUM_BYTES, VerifiedBrokerSessionTranscriptV1,
    decode_canonical_client_hello_v1, decode_canonical_server_hello_v1,
    verify_broker_session_transcript_v1,
};
use aos_sandbox_protocol::PeerCredentials;
use sha2::{Digest as _, Sha256};

use super::{read_u16, read_u32};
use crate::BrokerSessionSecurityError;

const MAGIC: &[u8; 8] = b"AOSBSCP1";
const DOMAIN: &[u8] = b"aos.sandbox.broker-session.historical-checkpoint.v1\0";
const HEADER_BYTES: usize = 8 + 2 + 6 * 4;
const DIGEST_BYTES: usize = 32;
pub(super) const MAXIMUM_BYTES: usize =
    HEADER_BYTES + 1024 + CLIENT_HELLO_MAXIMUM_BYTES + SERVER_HELLO_MAXIMUM_BYTES + DIGEST_BYTES;

/// Retains only historical verification inputs, never session-send authority.
#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct HistoricalSessionCheckpointV1 {
    context: ProtectedBrokerSessionVerificationContextV1,
    client_hello: Vec<u8>,
    broker_hello: Vec<u8>,
    peer: PeerCredentials,
}

impl HistoricalSessionCheckpointV1 {
    pub(crate) fn new(
        context: ProtectedBrokerSessionVerificationContextV1,
        client_hello: &[u8],
        broker_hello: &[u8],
        peer: PeerCredentials,
        transcript: &VerifiedBrokerSessionTranscriptV1,
    ) -> Result<Self, BrokerSessionSecurityError> {
        let checkpoint = Self {
            context,
            client_hello: client_hello.to_vec(),
            broker_hello: broker_hello.to_vec(),
            peer,
        };
        if checkpoint.verify()? != *transcript {
            return Err(BrokerSessionSecurityError::Currentness);
        }
        Ok(checkpoint)
    }

    pub(super) fn context(&self) -> &ProtectedBrokerSessionVerificationContextV1 {
        &self.context
    }

    pub(super) const fn peer(&self) -> PeerCredentials {
        self.peer
    }

    pub(super) fn verify(
        &self,
    ) -> Result<VerifiedBrokerSessionTranscriptV1, BrokerSessionSecurityError> {
        let client = decode_canonical_client_hello_v1(&self.client_hello)
            .map_err(|_| BrokerSessionSecurityError::Currentness)?;
        let broker = decode_canonical_server_hello_v1(&self.broker_hello)
            .map_err(|_| BrokerSessionSecurityError::Currentness)?;
        verify_broker_session_transcript_v1(&client, &broker, &self.context)
            .map_err(|_| BrokerSessionSecurityError::Currentness)
    }

    pub(crate) fn digest(&self) -> Result<[u8; 32], BrokerSessionSecurityError> {
        let encoded = self.encode()?;
        encoded
            .get(encoded.len().saturating_sub(DIGEST_BYTES)..)
            .and_then(|digest| digest.try_into().ok())
            .ok_or(BrokerSessionSecurityError::Currentness)
    }

    pub(super) fn encode(&self) -> Result<Vec<u8>, BrokerSessionSecurityError> {
        let context = self.context.checkpoint_bytes();
        let context_len =
            u32::try_from(context.len()).map_err(|_| BrokerSessionSecurityError::Currentness)?;
        let client_len = u32::try_from(self.client_hello.len())
            .map_err(|_| BrokerSessionSecurityError::Currentness)?;
        let broker_len = u32::try_from(self.broker_hello.len())
            .map_err(|_| BrokerSessionSecurityError::Currentness)?;
        if self.client_hello.is_empty()
            || self.broker_hello.is_empty()
            || self.client_hello.len() > CLIENT_HELLO_MAXIMUM_BYTES
            || self.broker_hello.len() > SERVER_HELLO_MAXIMUM_BYTES
            || self.peer.pid.is_none_or(|pid| pid == 0)
        {
            return Err(BrokerSessionSecurityError::Currentness);
        }
        let mut bytes = Vec::with_capacity(
            HEADER_BYTES
                + context.len()
                + self.client_hello.len()
                + self.broker_hello.len()
                + DIGEST_BYTES,
        );
        bytes.extend_from_slice(MAGIC);
        bytes.extend_from_slice(&1_u16.to_be_bytes());
        bytes.extend_from_slice(&context_len.to_be_bytes());
        bytes.extend_from_slice(&client_len.to_be_bytes());
        bytes.extend_from_slice(&broker_len.to_be_bytes());
        bytes.extend_from_slice(&self.peer.uid.to_be_bytes());
        bytes.extend_from_slice(&self.peer.gid.to_be_bytes());
        bytes.extend_from_slice(&self.peer.pid.unwrap_or_default().to_be_bytes());
        bytes.extend_from_slice(&context);
        bytes.extend_from_slice(&self.client_hello);
        bytes.extend_from_slice(&self.broker_hello);
        let digest: [u8; 32] = Sha256::new()
            .chain_update(DOMAIN)
            .chain_update(&bytes)
            .finalize()
            .into();
        bytes.extend_from_slice(&digest);
        Ok(bytes)
    }

    pub(super) fn decode(bytes: &[u8]) -> Result<Self, BrokerSessionSecurityError> {
        if bytes.len() < HEADER_BYTES + DIGEST_BYTES
            || bytes.len() > MAXIMUM_BYTES
            || bytes.get(..8) != Some(MAGIC.as_slice())
            || read_u16(bytes, 8)? != 1
        {
            return Err(BrokerSessionSecurityError::Currentness);
        }
        let context_len = usize::try_from(read_u32(bytes, 10)?)
            .map_err(|_| BrokerSessionSecurityError::Currentness)?;
        let client_len = usize::try_from(read_u32(bytes, 14)?)
            .map_err(|_| BrokerSessionSecurityError::Currentness)?;
        let broker_len = usize::try_from(read_u32(bytes, 18)?)
            .map_err(|_| BrokerSessionSecurityError::Currentness)?;
        let peer = PeerCredentials {
            uid: read_u32(bytes, 22)?,
            gid: read_u32(bytes, 26)?,
            pid: Some(read_u32(bytes, 30)?),
        };
        let context_end = HEADER_BYTES
            .checked_add(context_len)
            .ok_or(BrokerSessionSecurityError::Currentness)?;
        let client_end = context_end
            .checked_add(client_len)
            .ok_or(BrokerSessionSecurityError::Currentness)?;
        let broker_end = client_end
            .checked_add(broker_len)
            .ok_or(BrokerSessionSecurityError::Currentness)?;
        if broker_end.checked_add(DIGEST_BYTES) != Some(bytes.len()) {
            return Err(BrokerSessionSecurityError::Currentness);
        }
        let context = ProtectedBrokerSessionVerificationContextV1::from_checkpoint_bytes(
            bytes
                .get(HEADER_BYTES..context_end)
                .ok_or(BrokerSessionSecurityError::Currentness)?,
        )
        .map_err(|_| BrokerSessionSecurityError::Currentness)?;
        let checkpoint = Self {
            context,
            client_hello: bytes
                .get(context_end..client_end)
                .ok_or(BrokerSessionSecurityError::Currentness)?
                .to_vec(),
            broker_hello: bytes
                .get(client_end..broker_end)
                .ok_or(BrokerSessionSecurityError::Currentness)?
                .to_vec(),
            peer,
        };
        checkpoint.verify()?;
        if checkpoint.encode()? != bytes {
            return Err(BrokerSessionSecurityError::Currentness);
        }
        Ok(checkpoint)
    }
}
