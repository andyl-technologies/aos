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
use crate::PeerCredentials;
use sha2::{Digest as _, Sha256};

/// Reports a noncanonical, inconsistent or unauthentic historical carrier.
#[derive(Clone, Copy, Debug, Eq, PartialEq, thiserror::Error)]
pub enum HistoricalCheckpointErrorV1 {
    /// The fixed canonical historical checkpoint could not be verified.
    #[error("invalid historical Broker Session Authentication checkpoint")]
    Invalid,
}

const MAGIC: &[u8; 8] = b"AOSBSCP1";
const DOMAIN: &[u8] = b"aos.sandbox.broker-session.historical-checkpoint.v1\0";
const HEADER_BYTES: usize = 8 + 2 + 6 * 4;
const DIGEST_BYTES: usize = 32;
/// Bounds the complete historical carrier before nested allocation.
pub const MAXIMUM_BYTES: usize =
    HEADER_BYTES + 1024 + CLIENT_HELLO_MAXIMUM_BYTES + SERVER_HELLO_MAXIMUM_BYTES + DIGEST_BYTES;

/// Retains historical verification inputs, never live or resend authority.
///
/// Its context and transcript are pure cryptographic data. Neither constructing
/// nor decoding this value yields a current session, live outcome, floor,
/// currentness or protected journal authorization.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct HistoricalSessionCheckpointV1 {
    context: ProtectedBrokerSessionVerificationContextV1,
    client_hello: Vec<u8>,
    broker_hello: Vec<u8>,
    peer: PeerCredentials,
}

impl HistoricalSessionCheckpointV1 {
    /// Constructs a historical carrier whose signed hello transcript agrees.
    ///
    /// # Errors
    /// Rejects a transcript/context/hello mismatch. Encoding separately checks
    /// the recorded peer PID and complete carrier bounds.
    pub fn new(
        context: ProtectedBrokerSessionVerificationContextV1,
        client_hello: &[u8],
        broker_hello: &[u8],
        peer: PeerCredentials,
        transcript: &VerifiedBrokerSessionTranscriptV1,
    ) -> Result<Self, HistoricalCheckpointErrorV1> {
        let checkpoint = Self {
            context,
            client_hello: client_hello.to_vec(),
            broker_hello: broker_hello.to_vec(),
            peer,
        };
        if checkpoint.verify()? != *transcript {
            return Err(HistoricalCheckpointErrorV1::Invalid);
        }
        Ok(checkpoint)
    }

    /// Borrows the historical shape-only verification context.
    #[must_use]
    pub fn context(&self) -> &ProtectedBrokerSessionVerificationContextV1 {
        &self.context
    }

    /// Returns the originally recorded nonauthorizing peer coordinates.
    #[must_use]
    pub const fn peer(&self) -> PeerCredentials {
        self.peer
    }

    /// Verifies the two signed historical hellos under this recorded context.
    ///
    /// # Errors
    /// Rejects canonical projection, signatures or transcript linkage failure.
    pub fn verify(
        &self,
    ) -> Result<VerifiedBrokerSessionTranscriptV1, HistoricalCheckpointErrorV1> {
        let client = decode_canonical_client_hello_v1(&self.client_hello)
            .map_err(|_| HistoricalCheckpointErrorV1::Invalid)?;
        let broker = decode_canonical_server_hello_v1(&self.broker_hello)
            .map_err(|_| HistoricalCheckpointErrorV1::Invalid)?;
        verify_broker_session_transcript_v1(&client, &broker, &self.context)
            .map_err(|_| HistoricalCheckpointErrorV1::Invalid)
    }

    /// Returns the unchanged purpose-separated canonical checkpoint digest.
    ///
    /// # Errors
    /// Rejects malformed or unencodable historical state.
    pub fn digest(&self) -> Result<[u8; 32], HistoricalCheckpointErrorV1> {
        let encoded = self.encode()?;
        encoded
            .get(encoded.len().saturating_sub(DIGEST_BYTES)..)
            .and_then(|digest| digest.try_into().ok())
            .ok_or(HistoricalCheckpointErrorV1::Invalid)
    }

    /// Encodes the exact bounded original AOSBSCP1 carrier.
    ///
    /// # Errors
    /// Rejects invalid peer PID, hello bounds or length overflow.
    pub fn encode(&self) -> Result<Vec<u8>, HistoricalCheckpointErrorV1> {
        let context = self.context.checkpoint_bytes();
        let context_len =
            u32::try_from(context.len()).map_err(|_| HistoricalCheckpointErrorV1::Invalid)?;
        let client_len = u32::try_from(self.client_hello.len())
            .map_err(|_| HistoricalCheckpointErrorV1::Invalid)?;
        let broker_len = u32::try_from(self.broker_hello.len())
            .map_err(|_| HistoricalCheckpointErrorV1::Invalid)?;
        if self.client_hello.is_empty()
            || self.broker_hello.is_empty()
            || self.client_hello.len() > CLIENT_HELLO_MAXIMUM_BYTES
            || self.broker_hello.len() > SERVER_HELLO_MAXIMUM_BYTES
            || self.peer.pid.is_none_or(|pid| pid == 0)
        {
            return Err(HistoricalCheckpointErrorV1::Invalid);
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

    /// Decodes and verifies an exact canonical historical carrier.
    ///
    /// # Errors
    /// Rejects wrong header, aggregate or nested bounds, checked-length overflow,
    /// malformed context, invalid hello signatures and noncanonical digest bytes.
    pub fn decode(bytes: &[u8]) -> Result<Self, HistoricalCheckpointErrorV1> {
        if bytes.len() < HEADER_BYTES + DIGEST_BYTES
            || bytes.len() > MAXIMUM_BYTES
            || bytes.get(..8) != Some(MAGIC.as_slice())
            || read_u16(bytes, 8)? != 1
        {
            return Err(HistoricalCheckpointErrorV1::Invalid);
        }
        let context_len = usize::try_from(read_u32(bytes, 10)?)
            .map_err(|_| HistoricalCheckpointErrorV1::Invalid)?;
        let client_len = usize::try_from(read_u32(bytes, 14)?)
            .map_err(|_| HistoricalCheckpointErrorV1::Invalid)?;
        let broker_len = usize::try_from(read_u32(bytes, 18)?)
            .map_err(|_| HistoricalCheckpointErrorV1::Invalid)?;
        let peer = PeerCredentials {
            uid: read_u32(bytes, 22)?,
            gid: read_u32(bytes, 26)?,
            pid: Some(read_u32(bytes, 30)?),
        };
        let context_end = HEADER_BYTES
            .checked_add(context_len)
            .ok_or(HistoricalCheckpointErrorV1::Invalid)?;
        let client_end = context_end
            .checked_add(client_len)
            .ok_or(HistoricalCheckpointErrorV1::Invalid)?;
        let broker_end = client_end
            .checked_add(broker_len)
            .ok_or(HistoricalCheckpointErrorV1::Invalid)?;
        if broker_end.checked_add(DIGEST_BYTES) != Some(bytes.len()) {
            return Err(HistoricalCheckpointErrorV1::Invalid);
        }
        let context = ProtectedBrokerSessionVerificationContextV1::from_checkpoint_bytes(
            bytes
                .get(HEADER_BYTES..context_end)
                .ok_or(HistoricalCheckpointErrorV1::Invalid)?,
        )
        .map_err(|_| HistoricalCheckpointErrorV1::Invalid)?;
        let checkpoint = Self {
            context,
            client_hello: bytes
                .get(context_end..client_end)
                .ok_or(HistoricalCheckpointErrorV1::Invalid)?
                .to_vec(),
            broker_hello: bytes
                .get(client_end..broker_end)
                .ok_or(HistoricalCheckpointErrorV1::Invalid)?
                .to_vec(),
            peer,
        };
        checkpoint.verify()?;
        if checkpoint.encode()? != bytes {
            return Err(HistoricalCheckpointErrorV1::Invalid);
        }
        Ok(checkpoint)
    }
}

fn read_array<const N: usize>(
    input: &[u8],
    offset: usize,
) -> Result<[u8; N], HistoricalCheckpointErrorV1> {
    let end = offset.checked_add(N).ok_or(HistoricalCheckpointErrorV1::Invalid)?;
    input.get(offset..end).and_then(|bytes| bytes.try_into().ok())
        .ok_or(HistoricalCheckpointErrorV1::Invalid)
}

fn read_u16(input: &[u8], offset: usize) -> Result<u16, HistoricalCheckpointErrorV1> {
    Ok(u16::from_be_bytes(read_array(input, offset)?))
}

fn read_u32(input: &[u8], offset: usize) -> Result<u32, HistoricalCheckpointErrorV1> {
    Ok(u32::from_be_bytes(read_array(input, offset)?))
}
