//! Security compatibility wrapper for the sole lower AOSBSCP1 codec.
//!
//! Canonical historical parsing and transcript checks live below Security.
//! Every existing wrapper failure remains the original redacted Currentness
//! error. Historical data never becomes a live session or a floor grant.

use aos_sandbox_broker_session_protocol::{
    ProtectedBrokerSessionVerificationContextV1, VerifiedBrokerSessionTranscriptV1,
};
use aos_sandbox_protocol::PeerCredentials;
use aos_sandbox_protocol::authenticated_session::historical_checkpoint::{
    HistoricalSessionCheckpointV1 as CanonicalHistoricalCheckpointV1,
    MAXIMUM_BYTES as CANONICAL_MAXIMUM_BYTES,
};

use crate::BrokerSessionSecurityError;

pub(super) const MAXIMUM_BYTES: usize = CANONICAL_MAXIMUM_BYTES;

#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct HistoricalSessionCheckpointV1(CanonicalHistoricalCheckpointV1);

impl HistoricalSessionCheckpointV1 {
    // These conversions expose historical DATA only, not protected custody.
    pub(super) fn as_canonical(&self) -> &CanonicalHistoricalCheckpointV1 {
        &self.0
    }

    pub(super) fn from_canonical(checkpoint: CanonicalHistoricalCheckpointV1) -> Self {
        Self(checkpoint)
    }

    pub(crate) fn new(
        context: ProtectedBrokerSessionVerificationContextV1,
        client_hello: &[u8],
        broker_hello: &[u8],
        peer: PeerCredentials,
        transcript: &VerifiedBrokerSessionTranscriptV1,
    ) -> Result<Self, BrokerSessionSecurityError> {
        CanonicalHistoricalCheckpointV1::new(
            context, client_hello, broker_hello, peer, transcript,
        )
        .map(Self)
        .map_err(|_| BrokerSessionSecurityError::Currentness)
    }

    pub(super) fn context(&self) -> &ProtectedBrokerSessionVerificationContextV1 {
        self.0.context()
    }

    pub(super) const fn peer(&self) -> PeerCredentials {
        self.0.peer()
    }

    pub(super) fn verify(
        &self,
    ) -> Result<VerifiedBrokerSessionTranscriptV1, BrokerSessionSecurityError> {
        self.0.verify().map_err(|_| BrokerSessionSecurityError::Currentness)
    }

    pub(crate) fn digest(&self) -> Result<[u8; 32], BrokerSessionSecurityError> {
        self.0.digest().map_err(|_| BrokerSessionSecurityError::Currentness)
    }

    pub(super) fn encode(&self) -> Result<Vec<u8>, BrokerSessionSecurityError> {
        self.0.encode().map_err(|_| BrokerSessionSecurityError::Currentness)
    }

    pub(super) fn decode(bytes: &[u8]) -> Result<Self, BrokerSessionSecurityError> {
        CanonicalHistoricalCheckpointV1::decode(bytes)
            .map(Self)
            .map_err(|_| BrokerSessionSecurityError::Currentness)
    }
}
