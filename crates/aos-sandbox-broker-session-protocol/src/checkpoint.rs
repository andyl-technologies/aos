//! Fixed non-authorizing checkpoint companion records.
//!
//! These records preserve exact signed-artifact bytes and recorded request
//! timing fields for a future caller-owned durability transaction. Decoding
//! validates only the closed structural format and artifact cross-links. It
//! does not verify a signature, select protected context, validate method
//! semantics, write a journal, commit an effect, or confer authority.
//!
//! ```text
//! request (336 bytes):
//! AOSBSJ01 | version:u16be=1 | kind=1 | protocol:u8 | method:u8 |
//! reserved[3]=0 | deadline:u64be | maximum-response:u32be |
//! signed-client-record[308]
//!
//! outcome (416 bytes):
//! AOSBSJ01 | version:u16be=1 | kind=2 | protocol:u8 | method:u8 |
//! reserved[3]=0 | request-id[16] | client-sequence:u64be |
//! maximum-response:u32be | complete-signed-request-digest[32] |
//! signed-broker-outcome[340]
//! ```

use aos_proto::aos::sandbox::local::v1::BrokerMethod;
use buffa::Enumeration as _;

use crate::artifact::{SignedBrokerOutcomeV1, SignedBrokerRequestV1};
use crate::model::{
    BrokerSessionProtocolV1, SIGNED_BROKER_OUTCOME_BYTES, SIGNED_BROKER_REQUEST_BYTES, method_code,
};
use crate::profile::method_matches_protocol;
use crate::projection::{
    AUTHENTICATED_RESPONSE_MAXIMUM_BYTES, AUTHENTICATED_RESPONSE_MINIMUM_BYTES,
};

const CHECKPOINT_MAGIC: &[u8; 8] = b"AOSBSJ01";
const CHECKPOINT_VERSION: u16 = 1;
const REQUEST_KIND: u8 = 1;
const OUTCOME_KIND: u8 = 2;
const HEADER_BYTES: usize = 16;
const REQUEST_ARTIFACT_OFFSET: usize = 28;
const OUTCOME_ARTIFACT_OFFSET: usize = 76;

/// Exact encoded width of a request checkpoint companion.
pub const BROKER_SESSION_REQUEST_COMPANION_BYTES: usize = 336;
/// Exact encoded width of an outcome checkpoint companion.
pub const BROKER_SESSION_OUTCOME_COMPANION_BYTES: usize = 416;

const _: [(); BROKER_SESSION_REQUEST_COMPANION_BYTES] =
    [(); REQUEST_ARTIFACT_OFFSET + SIGNED_BROKER_REQUEST_BYTES];
const _: [(); BROKER_SESSION_OUTCOME_COMPANION_BYTES] =
    [(); OUTCOME_ARTIFACT_OFFSET + SIGNED_BROKER_OUTCOME_BYTES];
const _: [(); REQUEST_ARTIFACT_OFFSET] = [(); HEADER_BYTES + 8 + 4];
const _: [(); OUTCOME_ARTIFACT_OFFSET] = [(); HEADER_BYTES + 16 + 8 + 4 + 32];

/// Reports a malformed or internally inconsistent checkpoint companion.
#[derive(Clone, Debug, Eq, PartialEq, thiserror::Error)]
pub enum BrokerSessionCheckpointError {
    /// The record does not have its one exact fixed width.
    #[error("invalid broker-session checkpoint length")]
    InvalidLength,
    /// The format magic differs from `AOSBSJ01`.
    #[error("invalid broker-session checkpoint magic")]
    InvalidMagic,
    /// The format version is not exactly version one.
    #[error("unsupported broker-session checkpoint version")]
    InvalidVersion,
    /// The record kind does not match the requested codec.
    #[error("invalid broker-session checkpoint kind")]
    InvalidKind,
    /// The protocol byte is not one of the four broker protocols.
    #[error("invalid broker-session checkpoint protocol")]
    InvalidProtocol,
    /// The method byte is zero, reserved, or unknown.
    #[error("invalid broker-session checkpoint method")]
    InvalidMethod,
    /// The reserved header bytes are not all zero.
    #[error("nonzero broker-session checkpoint reserved bytes")]
    NonzeroReserved,
    /// A required scalar or fixed-width value uses its zero sentinel.
    #[error("zero broker-session checkpoint required field")]
    ZeroRequiredField,
    /// A request or outcome uses the sequence value reserved for exhaustion.
    #[error("reserved broker-session checkpoint sequence")]
    ReservedSequence,
    /// The response ceiling lies outside the authenticated response profile.
    #[error("invalid broker-session checkpoint response ceiling")]
    InvalidResponseBound,
    /// The embedded signed artifact is malformed or noncanonical.
    #[error("invalid broker-session checkpoint signed artifact")]
    InvalidArtifact,
    /// The method is not assigned to the encoded broker protocol.
    #[error("broker-session checkpoint protocol and method disagree")]
    ProtocolMethodMismatch,
    /// The header method differs from the embedded signed artifact.
    #[error("broker-session checkpoint header and artifact disagree")]
    ArtifactMethodMismatch,
    /// The outcome request ID differs from its signed subject.
    #[error("broker-session outcome checkpoint request ID disagrees")]
    OutcomeRequestMismatch,
    /// The outcome request digest differs from its signed subject.
    #[error("broker-session outcome checkpoint request digest disagrees")]
    OutcomeDigestMismatch,
    /// The recorded client sequence differs from the paired outcome sequence.
    #[error("broker-session outcome checkpoint sequence disagrees")]
    OutcomeSequenceMismatch,
}

/// Retains one structurally checked request companion without authority.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct BrokerSessionRequestCompanionV1 {
    protocol: BrokerSessionProtocolV1,
    method: BrokerMethod,
    method_code: u8,
    deadline_boottime_nanoseconds: u64,
    maximum_response_bytes: u32,
    signed_request: SignedBrokerRequestV1,
}

impl BrokerSessionRequestCompanionV1 {
    /// Constructs a companion after checking every scalar and artifact cross-link.
    ///
    /// # Errors
    ///
    /// Returns [`BrokerSessionCheckpointError`] for an invalid response ceiling,
    /// reserved sequence, wrong protocol/method pairing, or artifact mismatch.
    pub fn try_from_parts(
        protocol: BrokerSessionProtocolV1,
        method: BrokerMethod,
        deadline_boottime_nanoseconds: u64,
        maximum_response_bytes: u32,
        signed_request: SignedBrokerRequestV1,
    ) -> Result<Self, BrokerSessionCheckpointError> {
        let method_code = validate_common(protocol, method, maximum_response_bytes)?;
        if signed_request.method() != method {
            return Err(BrokerSessionCheckpointError::ArtifactMethodMismatch);
        }
        if signed_request.subject().sequence() == u64::MAX {
            return Err(BrokerSessionCheckpointError::ReservedSequence);
        }
        validate_request_artifact(&signed_request)?;

        Ok(Self {
            protocol,
            method,
            method_code,
            deadline_boottime_nanoseconds,
            maximum_response_bytes,
            signed_request,
        })
    }

    /// Decodes the exact fixed record without verifying trust or semantics.
    ///
    /// # Errors
    ///
    /// Returns [`BrokerSessionCheckpointError`] for every wrong length, magic,
    /// version, kind, reserved byte, closed value, bound, or artifact cross-link.
    pub fn decode(bytes: &[u8]) -> Result<Self, BrokerSessionCheckpointError> {
        if bytes.len() != BROKER_SESSION_REQUEST_COMPANION_BYTES {
            return Err(BrokerSessionCheckpointError::InvalidLength);
        }
        let (protocol, method) = decode_header(bytes, REQUEST_KIND)?;
        let deadline = u64::from_be_bytes(take_array(bytes, 16)?);
        let maximum_response_bytes = u32::from_be_bytes(take_array(bytes, 24)?);
        let signed_request = SignedBrokerRequestV1::from_canonical_bytes(
            bytes
                .get(REQUEST_ARTIFACT_OFFSET..)
                .ok_or(BrokerSessionCheckpointError::InvalidLength)?,
        )
        .map_err(|_| BrokerSessionCheckpointError::InvalidArtifact)?;

        Self::try_from_parts(
            protocol,
            method,
            deadline,
            maximum_response_bytes,
            signed_request,
        )
    }

    /// Encodes the exact 336-byte canonical record.
    #[must_use]
    pub fn encode(&self) -> [u8; BROKER_SESSION_REQUEST_COMPANION_BYTES] {
        let mut bytes = [0_u8; BROKER_SESSION_REQUEST_COMPANION_BYTES];
        encode_header(
            &mut bytes[..HEADER_BYTES],
            REQUEST_KIND,
            self.protocol,
            self.method_code,
        );
        bytes[16..24].copy_from_slice(&self.deadline_boottime_nanoseconds.to_be_bytes());
        bytes[24..28].copy_from_slice(&self.maximum_response_bytes.to_be_bytes());
        bytes[REQUEST_ARTIFACT_OFFSET..].copy_from_slice(&self.signed_request.to_canonical_bytes());
        bytes
    }

    /// Returns the closed broker protocol.
    #[must_use]
    pub const fn protocol(&self) -> BrokerSessionProtocolV1 {
        self.protocol
    }

    /// Returns the exact nonzero broker method.
    #[must_use]
    pub const fn method(&self) -> BrokerMethod {
        self.method
    }

    /// Returns the recorded request deadline.
    #[must_use]
    pub const fn deadline_boottime_nanoseconds(&self) -> u64 {
        self.deadline_boottime_nanoseconds
    }

    /// Returns the recorded total response ceiling.
    #[must_use]
    pub const fn maximum_response_bytes(&self) -> u32 {
        self.maximum_response_bytes
    }

    /// Returns the exact canonical signed ClientRecord artifact.
    #[must_use]
    pub const fn signed_request(&self) -> &SignedBrokerRequestV1 {
        &self.signed_request
    }
}

/// Retains one structurally checked outcome companion without authority.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct BrokerSessionOutcomeCompanionV1 {
    protocol: BrokerSessionProtocolV1,
    method: BrokerMethod,
    method_code: u8,
    request_id: [u8; 16],
    client_sequence: u64,
    maximum_response_bytes: u32,
    signed_request_digest: [u8; 32],
    signed_outcome: SignedBrokerOutcomeV1,
}

impl BrokerSessionOutcomeCompanionV1 {
    /// Constructs a companion after checking every scalar and outcome cross-link.
    ///
    /// # Errors
    ///
    /// Returns [`BrokerSessionCheckpointError`] for an invalid field, bound,
    /// protocol/method pairing, artifact, request tuple, digest, or sequence.
    #[allow(clippy::too_many_arguments)]
    pub fn try_from_parts(
        protocol: BrokerSessionProtocolV1,
        method: BrokerMethod,
        request_id: [u8; 16],
        client_sequence: u64,
        maximum_response_bytes: u32,
        signed_request_digest: [u8; 32],
        signed_outcome: SignedBrokerOutcomeV1,
    ) -> Result<Self, BrokerSessionCheckpointError> {
        let method_code = validate_common(protocol, method, maximum_response_bytes)?;
        if is_zero(&request_id) || client_sequence == 0 || is_zero(&signed_request_digest) {
            return Err(BrokerSessionCheckpointError::ZeroRequiredField);
        }
        if client_sequence == u64::MAX || signed_outcome.subject().sequence() == u64::MAX {
            return Err(BrokerSessionCheckpointError::ReservedSequence);
        }
        if signed_outcome.method() != method {
            return Err(BrokerSessionCheckpointError::ArtifactMethodMismatch);
        }
        validate_outcome_artifact(&signed_outcome)?;

        let subject = signed_outcome.subject();
        if subject.request_id() != request_id {
            return Err(BrokerSessionCheckpointError::OutcomeRequestMismatch);
        }
        if subject.signed_request_digest() != signed_request_digest {
            return Err(BrokerSessionCheckpointError::OutcomeDigestMismatch);
        }
        if subject.sequence() != client_sequence {
            return Err(BrokerSessionCheckpointError::OutcomeSequenceMismatch);
        }

        Ok(Self {
            protocol,
            method,
            method_code,
            request_id,
            client_sequence,
            maximum_response_bytes,
            signed_request_digest,
            signed_outcome,
        })
    }

    /// Decodes the exact fixed record without verifying trust or semantics.
    ///
    /// # Errors
    ///
    /// Returns [`BrokerSessionCheckpointError`] for every wrong length, magic,
    /// version, kind, reserved byte, closed value, bound, or artifact cross-link.
    pub fn decode(bytes: &[u8]) -> Result<Self, BrokerSessionCheckpointError> {
        if bytes.len() != BROKER_SESSION_OUTCOME_COMPANION_BYTES {
            return Err(BrokerSessionCheckpointError::InvalidLength);
        }
        let (protocol, method) = decode_header(bytes, OUTCOME_KIND)?;
        let request_id = take_array(bytes, 16)?;
        let client_sequence = u64::from_be_bytes(take_array(bytes, 32)?);
        let maximum_response_bytes = u32::from_be_bytes(take_array(bytes, 40)?);
        let signed_request_digest = take_array(bytes, 44)?;
        let signed_outcome = SignedBrokerOutcomeV1::from_canonical_bytes(
            bytes
                .get(OUTCOME_ARTIFACT_OFFSET..)
                .ok_or(BrokerSessionCheckpointError::InvalidLength)?,
        )
        .map_err(|_| BrokerSessionCheckpointError::InvalidArtifact)?;

        Self::try_from_parts(
            protocol,
            method,
            request_id,
            client_sequence,
            maximum_response_bytes,
            signed_request_digest,
            signed_outcome,
        )
    }

    /// Encodes the exact 416-byte canonical record.
    #[must_use]
    pub fn encode(&self) -> [u8; BROKER_SESSION_OUTCOME_COMPANION_BYTES] {
        let mut bytes = [0_u8; BROKER_SESSION_OUTCOME_COMPANION_BYTES];
        encode_header(
            &mut bytes[..HEADER_BYTES],
            OUTCOME_KIND,
            self.protocol,
            self.method_code,
        );
        bytes[16..32].copy_from_slice(&self.request_id);
        bytes[32..40].copy_from_slice(&self.client_sequence.to_be_bytes());
        bytes[40..44].copy_from_slice(&self.maximum_response_bytes.to_be_bytes());
        bytes[44..76].copy_from_slice(&self.signed_request_digest);
        bytes[OUTCOME_ARTIFACT_OFFSET..].copy_from_slice(&self.signed_outcome.to_canonical_bytes());
        bytes
    }

    /// Returns the closed broker protocol.
    #[must_use]
    pub const fn protocol(&self) -> BrokerSessionProtocolV1 {
        self.protocol
    }

    /// Returns the exact nonzero broker method.
    #[must_use]
    pub const fn method(&self) -> BrokerMethod {
        self.method
    }

    /// Returns the request ID paired with the outcome.
    #[must_use]
    pub const fn request_id(&self) -> [u8; 16] {
        self.request_id
    }

    /// Returns the client request sequence paired with the outcome.
    #[must_use]
    pub const fn client_sequence(&self) -> u64 {
        self.client_sequence
    }

    /// Returns the recorded total response ceiling.
    #[must_use]
    pub const fn maximum_response_bytes(&self) -> u32 {
        self.maximum_response_bytes
    }

    /// Returns the complete signed-request digest paired with the outcome.
    #[must_use]
    pub const fn signed_request_digest(&self) -> [u8; 32] {
        self.signed_request_digest
    }

    /// Returns the exact canonical signed BrokerOutcome artifact.
    #[must_use]
    pub const fn signed_outcome(&self) -> &SignedBrokerOutcomeV1 {
        &self.signed_outcome
    }
}

fn validate_common(
    protocol: BrokerSessionProtocolV1,
    method: BrokerMethod,
    maximum_response_bytes: u32,
) -> Result<u8, BrokerSessionCheckpointError> {
    let code = validate_protocol_method(protocol, method)?;
    let maximum = u32::try_from(AUTHENTICATED_RESPONSE_MAXIMUM_BYTES)
        .map_err(|_| BrokerSessionCheckpointError::InvalidResponseBound)?;
    if !(AUTHENTICATED_RESPONSE_MINIMUM_BYTES..=maximum).contains(&maximum_response_bytes) {
        return Err(BrokerSessionCheckpointError::InvalidResponseBound);
    }
    Ok(code)
}

fn validate_protocol_method(
    protocol: BrokerSessionProtocolV1,
    method: BrokerMethod,
) -> Result<u8, BrokerSessionCheckpointError> {
    if method == BrokerMethod::BROKER_METHOD_UNSPECIFIED {
        return Err(BrokerSessionCheckpointError::InvalidMethod);
    }
    let code = method_code(method).map_err(|_| BrokerSessionCheckpointError::InvalidMethod)?;
    if !method_matches_protocol(method, protocol) {
        return Err(BrokerSessionCheckpointError::ProtocolMethodMismatch);
    }
    Ok(code)
}

fn validate_request_artifact(
    artifact: &SignedBrokerRequestV1,
) -> Result<(), BrokerSessionCheckpointError> {
    SignedBrokerRequestV1::from_canonical_bytes(&artifact.to_canonical_bytes())
        .map(|_| ())
        .map_err(|_| BrokerSessionCheckpointError::InvalidArtifact)
}

fn validate_outcome_artifact(
    artifact: &SignedBrokerOutcomeV1,
) -> Result<(), BrokerSessionCheckpointError> {
    SignedBrokerOutcomeV1::from_canonical_bytes(&artifact.to_canonical_bytes())
        .map(|_| ())
        .map_err(|_| BrokerSessionCheckpointError::InvalidArtifact)
}

fn decode_header(
    bytes: &[u8],
    expected_kind: u8,
) -> Result<(BrokerSessionProtocolV1, BrokerMethod), BrokerSessionCheckpointError> {
    if bytes.get(..8) != Some(CHECKPOINT_MAGIC) {
        return Err(BrokerSessionCheckpointError::InvalidMagic);
    }
    if bytes.get(8..10) != Some(CHECKPOINT_VERSION.to_be_bytes().as_slice()) {
        return Err(BrokerSessionCheckpointError::InvalidVersion);
    }
    if bytes.get(10).copied() != Some(expected_kind) {
        return Err(BrokerSessionCheckpointError::InvalidKind);
    }
    if bytes
        .get(13..HEADER_BYTES)
        .is_none_or(|reserved| reserved.iter().any(|byte| *byte != 0))
    {
        return Err(BrokerSessionCheckpointError::NonzeroReserved);
    }

    let protocol = BrokerSessionProtocolV1::from_code(
        bytes
            .get(11)
            .copied()
            .ok_or(BrokerSessionCheckpointError::InvalidLength)?,
    )
    .map_err(|_| BrokerSessionCheckpointError::InvalidProtocol)?;
    let method = BrokerMethod::from_i32(i32::from(
        bytes
            .get(12)
            .copied()
            .ok_or(BrokerSessionCheckpointError::InvalidLength)?,
    ))
    .filter(|method| *method != BrokerMethod::BROKER_METHOD_UNSPECIFIED)
    .ok_or(BrokerSessionCheckpointError::InvalidMethod)?;
    validate_protocol_method(protocol, method)?;

    Ok((protocol, method))
}

fn encode_header(bytes: &mut [u8], kind: u8, protocol: BrokerSessionProtocolV1, method_code: u8) {
    bytes[..8].copy_from_slice(CHECKPOINT_MAGIC);
    bytes[8..10].copy_from_slice(&CHECKPOINT_VERSION.to_be_bytes());
    bytes[10] = kind;
    bytes[11] = protocol.code();
    bytes[12] = method_code;
}

fn take_array<const N: usize>(
    bytes: &[u8],
    offset: usize,
) -> Result<[u8; N], BrokerSessionCheckpointError> {
    bytes
        .get(offset..offset.saturating_add(N))
        .and_then(|slice| slice.try_into().ok())
        .ok_or(BrokerSessionCheckpointError::InvalidLength)
}

fn is_zero<const N: usize>(bytes: &[u8; N]) -> bool {
    bytes.iter().all(|byte| *byte == 0)
}
