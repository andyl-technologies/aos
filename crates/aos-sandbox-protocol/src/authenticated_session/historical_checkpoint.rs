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
mod capture;
mod construction;
#[doc(hidden)]
pub use construction::HistoricalSessionCheckpointConstructionCaptureV1;
#[doc(hidden)]
pub use capture::{
    HistoricalSessionCheckpointDecodeCaptureV1, HistoricalSessionCheckpointEncodeCaptureV1,
    HistoricalSessionCheckpointVerifyCaptureV1,
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
        let mut capture = HistoricalSessionCheckpointConstructionCaptureV1::ordinary();
        let _classification = capture.capture_once(context, client_hello, broker_hello, peer, transcript);
        capture.into_ordinary_result()
    }

    /// Retains the provisional checkpoint before verifying its actual hellos.
    ///
    /// This uses the same constructor and verification engine as [`Self::new`].
    /// The destination holds reached models and original nested causes on
    /// refusal; it provides historical DATA only.
    ///
    /// # Errors
    /// Rejects a transcript/context/hello mismatch or repeated destination entry.
    #[doc(hidden)]
    pub fn new_retaining(
        context: ProtectedBrokerSessionVerificationContextV1,
        client_hello: &[u8],
        broker_hello: &[u8],
        peer: PeerCredentials,
        transcript: &VerifiedBrokerSessionTranscriptV1,
        capture: &mut HistoricalSessionCheckpointConstructionCaptureV1,
    ) -> Result<(), HistoricalCheckpointErrorV1> {
        capture.capture_once(context, client_hello, broker_hello, peer, transcript)
    }

    /// Returns the actual retained HELLO byte extent without encoding or IO.
    ///
    /// The extent describes existing historical DATA and grants no admission.
    /// It remains independent of a possibly empty durable traffic journal.
    #[must_use]
    pub fn encoded_hello_bytes_v1(&self) -> Option<usize> {
        self.client_hello.len().checked_add(self.broker_hello.len())
    }

    /// Borrows the historical shape-only verification context.
    #[must_use]
    pub fn context(&self) -> &ProtectedBrokerSessionVerificationContextV1 {
        &self.context
    }

    /// Borrows the exact original signed ClientHello as historical DATA.
    ///
    /// This borrow neither re-verifies it nor establishes current peer custody.
    #[must_use]
    pub fn client_hello_bytes(&self) -> &[u8] {
        &self.client_hello
    }

    /// Borrows the exact original signed BrokerHello as historical DATA.
    ///
    /// This borrow neither re-verifies it nor establishes a live Session.
    #[must_use]
    pub fn broker_hello_bytes(&self) -> &[u8] {
        &self.broker_hello
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
        let mut capture = HistoricalSessionCheckpointVerifyCaptureV1::ordinary();
        let _classification = capture.capture_once(self);
        capture.into_ordinary_result()
    }

    /// Retains partial hello projections, negotiation and the actual transcript.
    ///
    /// # Errors
    /// Returns the existing historical classification while the destination
    /// borrows its original nested cause; repeated entry refuses before work.
    #[doc(hidden)]
    pub fn verify_retaining(
        &self, capture: &mut HistoricalSessionCheckpointVerifyCaptureV1,
    ) -> Result<(), HistoricalCheckpointErrorV1> {
        capture.capture_once(self)
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

    /// Encodes the original carrier only within a conservative caller bound.
    ///
    /// The existing encoder remains the sole byte assembly. This check runs
    /// before collecting either hello into its output and uses the same 1024
    /// byte context allowance as the global carrier limit. It can refuse a
    /// near-bound carrier even when its exact context would fit.
    ///
    /// This method returns historical DATA, never a currentness or role permit.
    ///
    /// # Errors
    /// Rejects checked size overflow or a conservative size above the caller
    /// ceiling, followed by all unchanged errors of the ordinary encoder.
    #[doc(hidden)]
    pub fn encode_bounded(
        &self,
        maximum_bytes: usize,
    ) -> Result<Vec<u8>, HistoricalCheckpointErrorV1> {
        require_encoding_bound(self, maximum_bytes)?;
        self.encode()
    }

    /// Encodes the exact bounded original AOSBSCP1 carrier.
    ///
    /// # Errors
    /// Rejects invalid peer PID, hello bounds or length overflow.
    pub fn encode(&self) -> Result<Vec<u8>, HistoricalCheckpointErrorV1> {
        let mut capture = HistoricalSessionCheckpointEncodeCaptureV1::new();
        let _classification = capture.capture_once(self, None);
        capture.into_ordinary_result()
    }

    /// Retains the same canonical context and output buffers before refusal.
    ///
    /// # Errors
    /// Returns the ordinary encoder classification or a repeated-entry refusal.
    #[doc(hidden)]
    pub fn encode_retaining(
        &self, capture: &mut HistoricalSessionCheckpointEncodeCaptureV1,
    ) -> Result<(), HistoricalCheckpointErrorV1> {
        capture.capture_once(self, None)
    }

    /// Retains encoding only after the unchanged conservative size frontier.
    ///
    /// # Errors
    /// Rejects overflow, a caller ceiling mismatch, malformed input or reentry.
    #[doc(hidden)]
    pub fn encode_bounded_retaining(
        &self, maximum_bytes: usize, capture: &mut HistoricalSessionCheckpointEncodeCaptureV1,
    ) -> Result<(), HistoricalCheckpointErrorV1> {
        capture.capture_once(self, Some(maximum_bytes))
    }

    /// Retains reached context, hello projections and canonical mismatch bytes.
    ///
    /// # Errors
    /// Returns the unchanged historical classification and keeps all reached
    /// nested original causes in the destination; repeated entry refuses.
    #[doc(hidden)]
    pub fn decode_retaining(
        bytes: &[u8], capture: &mut HistoricalSessionCheckpointDecodeCaptureV1,
    ) -> Result<(), HistoricalCheckpointErrorV1> {
        capture.capture_once(bytes)
    }

    /// Decodes and verifies an exact canonical historical carrier.
    ///
    /// # Errors
    /// Rejects wrong header, aggregate or nested bounds, checked-length overflow,
    /// malformed context, invalid hello signatures and noncanonical digest bytes.
    pub fn decode(bytes: &[u8]) -> Result<Self, HistoricalCheckpointErrorV1> {
        let mut capture = HistoricalSessionCheckpointDecodeCaptureV1::ordinary();
        let _classification = capture.capture_once(bytes);
        capture.into_ordinary_result()
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

// Both adapters refuse at the same cheap frontier before context allocation.
fn require_encoding_bound(
    checkpoint: &HistoricalSessionCheckpointV1, maximum_bytes: usize,
) -> Result<(), HistoricalCheckpointErrorV1> {
    let conservative_bytes = HEADER_BYTES
        .checked_add(1024)
        .and_then(|size| size.checked_add(checkpoint.client_hello.len()))
        .and_then(|size| size.checked_add(checkpoint.broker_hello.len()))
        .and_then(|size| size.checked_add(DIGEST_BYTES))
        .ok_or(HistoricalCheckpointErrorV1::Invalid)?;
    if conservative_bytes > maximum_bytes {
        return Err(HistoricalCheckpointErrorV1::Invalid);
    }
    Ok(())
}
