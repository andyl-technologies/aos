//! Canonical allocation-bounded `AOSAGE01` guest-agent framing.
//!
//! ```text
//! frame = "AOSAGE01" || kind || kind-specific-body
//! kind  = 1 handshake-request
//!       / 2 handshake-response
//!       / 3 operation-request
//!       / 4 operation-outcome
//!       / 5 OpenSSH gate install/readback request
//!       / 6 signed OpenSSH gate readback
//!       / 8 sealed Authorize reference with one SCM_RIGHTS descriptor
//! ```
//!
//! Integers are big-endian. Variable bytes use a `u32be` length and every
//! decoder applies its semantic maximum before allocation. Closed values have
//! no unknown-value pass-through and trailing bytes are forbidden.

use aos_sandbox_core::{
    AssignmentEpoch, AuditId, DesiredGeneration, ExecutionId, IncarnationId, NamespaceGeneration,
    ObjectDigest, PrincipalId, SandboxId,
};
use sha2::{Digest as _, Sha256};

use crate::model::{
    AgentExecutionOperationV1, AgentExecutionOutcomeV1, AgentExecutionPhaseV1, AgentFeatureSetV1,
    AgentFeatureV1, AgentHandshakeRequestV1, AgentHandshakeResponseV1, AgentNonceV1,
    AgentOperationIdV1, AgentOperationRequestV1, AgentOperationSequenceV1, AgentRuntimeBindingV1,
    AgentSessionBindingV1, AgentSessionIdV1, InvalidAgentModel,
};

const MAGIC: &[u8; 8] = b"AOSAGE01";
/// Maximum complete agent frame, including header.
pub const MAX_AGENT_FRAME_BYTES: usize = 16 * 1_048_576 + 1_024;
/// Maximum canonical execution-specification bytes carried in a sealed memfd.
pub const MAX_AGENT_SEALED_SPEC_BYTES_V1: usize = 15 * 1_048_576;

/// Binds a compact Authorize frame to one exact sealed specification descriptor.
///
/// The transferred descriptor is not authority by itself. The Guest checks its
/// seals, exact size, raw digest, canonical specification, and complete request
/// commitment before the operation can reach the protected effect owner.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct AgentSealedAuthorizeReferenceV1 {
    session: AgentSessionBindingV1,
    sequence: AgentOperationSequenceV1,
    operation_id: AgentOperationIdV1,
    backend_request_binding: ObjectDigest,
    execution: ExecutionId,
    content_bytes: u64,
    content_digest: ObjectDigest,
    specification_digest: ObjectDigest,
    admission_commitment: ObjectDigest,
    principal: PrincipalId,
    audit: AuditId,
    request_commitment: ObjectDigest,
}

impl AgentSealedAuthorizeReferenceV1 {
    /// Derives the descriptor reference from a validated full Authorize request.
    ///
    /// # Errors
    ///
    /// Rejects a non-Authorize request or an empty/oversized specification.
    pub fn from_request(request: &AgentOperationRequestV1) -> Result<Self, AgentProtocolError> {
        let AgentExecutionOperationV1::Authorize {
            execution,
            specification_bytes,
            specification_digest,
            admission_commitment,
            principal,
            audit,
        } = request.operation()
        else {
            return Err(AgentProtocolError::InvalidDescriptorReference);
        };
        if specification_bytes.is_empty()
            || specification_bytes.len() > MAX_AGENT_SEALED_SPEC_BYTES_V1
        {
            return Err(AgentProtocolError::InvalidLength);
        }
        Ok(Self {
            session: request.session(),
            sequence: request.sequence(),
            operation_id: request.operation_id(),
            backend_request_binding: request.backend_request_binding(),
            execution: *execution,
            content_bytes: u64::try_from(specification_bytes.len())
                .map_err(|_| AgentProtocolError::InvalidLength)?,
            content_digest: ObjectDigest::from_bytes(Sha256::digest(specification_bytes).into()),
            specification_digest: *specification_digest,
            admission_commitment: *admission_commitment,
            principal: *principal,
            audit: *audit,
            request_commitment: request.request_commitment(),
        })
    }

    /// Returns the exact sealed descriptor size expected by the Guest.
    #[must_use]
    pub const fn content_bytes(self) -> u64 {
        self.content_bytes
    }

    /// Reconstructs and verifies the complete operation from sealed bytes.
    ///
    /// # Errors
    ///
    /// Rejects a length/raw-hash mismatch, invalid canonical specification,
    /// allocation failure, or a changed full request commitment.
    pub fn reconstruct(
        self,
        content: &[u8],
    ) -> Result<AgentOperationRequestV1, AgentProtocolError> {
        if u64::try_from(content.len()).map_err(|_| AgentProtocolError::InvalidLength)?
            != self.content_bytes
            || ObjectDigest::from_bytes(Sha256::digest(content).into()) != self.content_digest
        {
            return Err(AgentProtocolError::CommitmentMismatch);
        }
        let mut specification_bytes = Vec::new();
        specification_bytes
            .try_reserve_exact(content.len())
            .map_err(|_| AgentProtocolError::AllocationFailed)?;
        specification_bytes.extend_from_slice(content);
        let request = AgentOperationRequestV1::new(
            self.session,
            self.sequence,
            self.operation_id,
            self.backend_request_binding,
            AgentExecutionOperationV1::Authorize {
                execution: self.execution,
                specification_bytes,
                specification_digest: self.specification_digest,
                admission_commitment: self.admission_commitment,
                principal: self.principal,
                audit: self.audit,
            },
        )?;
        if request.request_commitment() != self.request_commitment {
            return Err(AgentProtocolError::CommitmentMismatch);
        }
        Ok(request)
    }
}

/// Defines the exact frame shapes in agent protocol 1.0.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum AgentFrameV1 {
    /// Starts an exact incarnation handshake.
    HandshakeRequest(AgentHandshakeRequestV1),
    /// Proves challenge possession and advertises the agent feature set.
    HandshakeResponse(AgentHandshakeResponseV1),
    /// Carries one stop-and-wait execution or quiesce operation.
    OperationRequest(AgentOperationRequestV1),
    /// Returns the exact result for one operation.
    OperationOutcome(AgentExecutionOutcomeV1),
    /// Carries bounded canonical JSON for an exact gate installation/readback.
    OpenSshGateObserveRequest(Vec<u8>),
    /// Returns a bounded signed physical readback packet.
    OpenSshGateReadback(Vec<u8>),
    /// Carries one bounded Authorize reference with exactly one sealed memfd.
    SealedAuthorizeRequest(AgentSealedAuthorizeReferenceV1),
}

/// Encodes one exact protocol frame.
#[must_use]
pub fn encode_frame_v1(frame: &AgentFrameV1) -> Vec<u8> {
    let mut bytes = Vec::new();
    bytes.extend_from_slice(MAGIC);
    match frame {
        AgentFrameV1::HandshakeRequest(request) => {
            bytes.push(1);
            encode_handshake_request(&mut bytes, request);
        }
        AgentFrameV1::HandshakeResponse(response) => {
            bytes.push(2);
            encode_handshake_response(&mut bytes, response);
        }
        AgentFrameV1::OperationRequest(request) => {
            bytes.push(3);
            encode_operation_request(&mut bytes, request);
        }
        AgentFrameV1::OperationOutcome(outcome) => {
            bytes.push(4);
            encode_operation_outcome(&mut bytes, outcome);
        }
        AgentFrameV1::OpenSshGateObserveRequest(request) => {
            bytes.push(5);
            put_bytes(&mut bytes, request);
        }
        AgentFrameV1::OpenSshGateReadback(packet) => {
            bytes.push(6);
            put_bytes(&mut bytes, packet);
        }
        AgentFrameV1::SealedAuthorizeRequest(reference) => {
            bytes.push(8);
            encode_sealed_authorize_reference(&mut bytes, reference);
        }
    }
    bytes
}

/// Decodes one exact protocol frame under pre-allocation bounds.
///
/// # Errors
///
/// Returns [`AgentProtocolError`] for an oversized/truncated frame, wrong
/// version, unknown closed value, invalid semantic binding, or trailing bytes.
pub fn decode_frame_v1(bytes: &[u8]) -> Result<AgentFrameV1, AgentProtocolError> {
    if bytes.len() > MAX_AGENT_FRAME_BYTES {
        return Err(AgentProtocolError::FrameTooLarge);
    }
    let mut cursor = Cursor::new(bytes);
    cursor.exact(MAGIC)?;
    let frame = match cursor.u8()? {
        1 => AgentFrameV1::HandshakeRequest(decode_handshake_request(&mut cursor)?),
        2 => AgentFrameV1::HandshakeResponse(decode_handshake_response(&mut cursor)?),
        3 => AgentFrameV1::OperationRequest(decode_operation_request(&mut cursor)?),
        4 => AgentFrameV1::OperationOutcome(decode_operation_outcome(&mut cursor)?),
        5 => AgentFrameV1::OpenSshGateObserveRequest(cursor.length_prefixed(4096)?.to_vec()),
        6 => AgentFrameV1::OpenSshGateReadback(cursor.length_prefixed(8192)?.to_vec()),
        8 => AgentFrameV1::SealedAuthorizeRequest(decode_sealed_authorize_reference(&mut cursor)?),
        _ => return Err(AgentProtocolError::UnknownValue),
    };
    cursor.finish()?;
    Ok(frame)
}

fn encode_sealed_authorize_reference(
    output: &mut Vec<u8>,
    reference: &AgentSealedAuthorizeReferenceV1,
) {
    output.extend_from_slice(reference.session.digest().as_bytes());
    output.extend_from_slice(&reference.sequence.get().to_be_bytes());
    output.extend_from_slice(reference.operation_id.as_bytes());
    output.extend_from_slice(reference.backend_request_binding.as_bytes());
    output.extend_from_slice(reference.execution.as_bytes());
    output.extend_from_slice(&reference.content_bytes.to_be_bytes());
    output.extend_from_slice(reference.content_digest.as_bytes());
    output.extend_from_slice(reference.specification_digest.as_bytes());
    output.extend_from_slice(reference.admission_commitment.as_bytes());
    output.extend_from_slice(reference.principal.as_bytes());
    output.extend_from_slice(reference.audit.as_bytes());
    output.extend_from_slice(reference.request_commitment.as_bytes());
}

fn decode_sealed_authorize_reference(
    cursor: &mut Cursor<'_>,
) -> Result<AgentSealedAuthorizeReferenceV1, AgentProtocolError> {
    let reference = AgentSealedAuthorizeReferenceV1 {
        session: AgentSessionBindingV1::from_digest(ObjectDigest::from_bytes(cursor.array()?))?,
        sequence: AgentOperationSequenceV1::new(cursor.u64()?)?,
        operation_id: AgentOperationIdV1::new(cursor.array()?)?,
        backend_request_binding: ObjectDigest::from_bytes(cursor.array()?),
        execution: ExecutionId::from_bytes(cursor.array()?),
        content_bytes: cursor.u64()?,
        content_digest: ObjectDigest::from_bytes(cursor.array()?),
        specification_digest: ObjectDigest::from_bytes(cursor.array()?),
        admission_commitment: ObjectDigest::from_bytes(cursor.array()?),
        principal: PrincipalId::from_bytes(cursor.array()?),
        audit: AuditId::from_bytes(cursor.array()?),
        request_commitment: ObjectDigest::from_bytes(cursor.array()?),
    };
    if reference.content_bytes == 0
        || reference.content_bytes > MAX_AGENT_SEALED_SPEC_BYTES_V1 as u64
    {
        return Err(AgentProtocolError::InvalidLength);
    }
    Ok(reference)
}

fn encode_runtime(output: &mut Vec<u8>, runtime: &AgentRuntimeBindingV1) {
    output.extend_from_slice(runtime.sandbox().as_bytes());
    output.extend_from_slice(runtime.incarnation().as_bytes());
    output.extend_from_slice(&runtime.assignment_epoch().get().to_be_bytes());
    output.extend_from_slice(runtime.assignment_digest().as_bytes());
    output.extend_from_slice(&runtime.desired_generation().get().to_be_bytes());
    output.extend_from_slice(&runtime.namespace_generation().get().to_be_bytes());
    output.extend_from_slice(runtime.payload_boot_id());
}

fn decode_runtime(cursor: &mut Cursor<'_>) -> Result<AgentRuntimeBindingV1, AgentProtocolError> {
    AgentRuntimeBindingV1::new(
        SandboxId::from_bytes(cursor.array()?),
        IncarnationId::from_bytes(cursor.array()?),
        AssignmentEpoch::new(cursor.u64()?),
        ObjectDigest::from_bytes(cursor.array()?),
        DesiredGeneration::new(cursor.u64()?),
        NamespaceGeneration::new(cursor.u64()?),
        cursor.array()?,
    )
    .map_err(Into::into)
}

fn encode_handshake_request(output: &mut Vec<u8>, request: &AgentHandshakeRequestV1) {
    output.extend_from_slice(request.session().as_bytes());
    output.extend_from_slice(&request.version().major().to_be_bytes());
    output.extend_from_slice(&request.version().minor().to_be_bytes());
    encode_runtime(output, request.runtime());
    output.extend_from_slice(request.challenge().as_bytes());
    output.extend_from_slice(request.host_channel_binding().as_bytes());
}

fn decode_handshake_request(
    cursor: &mut Cursor<'_>,
) -> Result<AgentHandshakeRequestV1, AgentProtocolError> {
    let session = AgentSessionIdV1::new(cursor.array()?)?;
    if cursor.u16()? != 1 || cursor.u16()? != 0 {
        return Err(AgentProtocolError::WrongVersion);
    }
    let runtime = decode_runtime(cursor)?;
    let challenge = AgentNonceV1::new(cursor.array()?)?;
    let channel = ObjectDigest::from_bytes(cursor.array()?);
    AgentHandshakeRequestV1::new(session, runtime, challenge, channel).map_err(Into::into)
}

fn encode_handshake_response(output: &mut Vec<u8>, response: &AgentHandshakeResponseV1) {
    output.extend_from_slice(response.session_binding().digest().as_bytes());
    output.extend_from_slice(response.agent_instance());
    output.extend_from_slice(&(response.features().as_slice().len() as u16).to_be_bytes());
    for feature in response.features().as_slice() {
        output.push(*feature as u8);
    }
    output.extend_from_slice(response.challenge_signature());
}

fn decode_handshake_response(
    cursor: &mut Cursor<'_>,
) -> Result<AgentHandshakeResponseV1, AgentProtocolError> {
    let session = AgentSessionBindingV1::from_digest(ObjectDigest::from_bytes(cursor.array()?))?;
    let agent_instance = cursor.array()?;
    let feature_count = usize::from(cursor.u16()?);
    if feature_count == 0 || feature_count > 16 {
        return Err(AgentProtocolError::InvalidLength);
    }
    let mut features = Vec::new();
    features
        .try_reserve_exact(feature_count)
        .map_err(|_| AgentProtocolError::AllocationFailed)?;
    for _ in 0..feature_count {
        features.push(decode_feature(cursor.u8()?)?);
    }
    let features = AgentFeatureSetV1::new(features)?;
    let signature = cursor.array()?;
    AgentHandshakeResponseV1::new(session, agent_instance, features, signature).map_err(Into::into)
}

fn encode_operation_request(output: &mut Vec<u8>, request: &AgentOperationRequestV1) {
    output.extend_from_slice(request.session().digest().as_bytes());
    output.extend_from_slice(&request.sequence().get().to_be_bytes());
    output.extend_from_slice(request.operation_id().as_bytes());
    output.extend_from_slice(request.backend_request_binding().as_bytes());
    output.push(request.operation().code());
    match request.operation() {
        AgentExecutionOperationV1::Authorize {
            execution,
            specification_bytes,
            specification_digest,
            admission_commitment,
            principal,
            audit,
        } => {
            output.extend_from_slice(execution.as_bytes());
            put_bytes(output, specification_bytes);
            output.extend_from_slice(specification_digest.as_bytes());
            output.extend_from_slice(admission_commitment.as_bytes());
            output.extend_from_slice(principal.as_bytes());
            output.extend_from_slice(audit.as_bytes());
        }
        AgentExecutionOperationV1::ResizeTerminal {
            execution,
            rows,
            columns,
        } => {
            output.extend_from_slice(execution.as_bytes());
            output.extend_from_slice(&rows.to_be_bytes());
            output.extend_from_slice(&columns.to_be_bytes());
        }
        AgentExecutionOperationV1::Signal {
            execution,
            signal_code,
        } => {
            output.extend_from_slice(execution.as_bytes());
            output.push(*signal_code);
        }
        AgentExecutionOperationV1::Cancel { execution }
        | AgentExecutionOperationV1::Observe { execution } => {
            output.extend_from_slice(execution.as_bytes())
        }
        AgentExecutionOperationV1::BeginQuiesce | AgentExecutionOperationV1::EndQuiesce => {}
    }
    output.extend_from_slice(request.request_commitment().as_bytes());
}

fn decode_operation_request(
    cursor: &mut Cursor<'_>,
) -> Result<AgentOperationRequestV1, AgentProtocolError> {
    let session = AgentSessionBindingV1::from_digest(ObjectDigest::from_bytes(cursor.array()?))?;
    let sequence = AgentOperationSequenceV1::new(cursor.u64()?)?;
    let operation_id = AgentOperationIdV1::new(cursor.array()?)?;
    let backend_request_binding = ObjectDigest::from_bytes(cursor.array()?);
    let operation = match cursor.u8()? {
        1 => AgentExecutionOperationV1::Authorize {
            execution: ExecutionId::from_bytes(cursor.array()?),
            specification_bytes: cursor
                .length_prefixed(MAX_AGENT_SEALED_SPEC_BYTES_V1)?
                .to_vec(),
            specification_digest: ObjectDigest::from_bytes(cursor.array()?),
            admission_commitment: ObjectDigest::from_bytes(cursor.array()?),
            principal: PrincipalId::from_bytes(cursor.array()?),
            audit: AuditId::from_bytes(cursor.array()?),
        },
        2 => AgentExecutionOperationV1::ResizeTerminal {
            execution: ExecutionId::from_bytes(cursor.array()?),
            rows: cursor.u16()?,
            columns: cursor.u16()?,
        },
        3 => AgentExecutionOperationV1::Signal {
            execution: ExecutionId::from_bytes(cursor.array()?),
            signal_code: cursor.u8()?,
        },
        4 => AgentExecutionOperationV1::Cancel {
            execution: ExecutionId::from_bytes(cursor.array()?),
        },
        5 => AgentExecutionOperationV1::Observe {
            execution: ExecutionId::from_bytes(cursor.array()?),
        },
        6 => AgentExecutionOperationV1::BeginQuiesce,
        7 => AgentExecutionOperationV1::EndQuiesce,
        _ => return Err(AgentProtocolError::UnknownValue),
    };
    let claimed_commitment = ObjectDigest::from_bytes(cursor.array()?);
    let request = AgentOperationRequestV1::new(
        session,
        sequence,
        operation_id,
        backend_request_binding,
        operation,
    )?;
    if request.request_commitment() != claimed_commitment {
        return Err(AgentProtocolError::CommitmentMismatch);
    }
    Ok(request)
}

fn encode_operation_outcome(output: &mut Vec<u8>, outcome: &AgentExecutionOutcomeV1) {
    output.extend_from_slice(outcome.session().digest().as_bytes());
    output.extend_from_slice(&outcome.sequence().get().to_be_bytes());
    output.extend_from_slice(outcome.operation_id().as_bytes());
    output.extend_from_slice(outcome.request_commitment().as_bytes());
    output.push(outcome.phase().code());
    put_bytes(output, outcome.result_bytes());
    output.extend_from_slice(outcome.result_digest().as_bytes());
}

fn decode_operation_outcome(
    cursor: &mut Cursor<'_>,
) -> Result<AgentExecutionOutcomeV1, AgentProtocolError> {
    let session = AgentSessionBindingV1::from_digest(ObjectDigest::from_bytes(cursor.array()?))?;
    let sequence = AgentOperationSequenceV1::new(cursor.u64()?)?;
    let operation_id = AgentOperationIdV1::new(cursor.array()?)?;
    let request_commitment = ObjectDigest::from_bytes(cursor.array()?);
    let phase =
        AgentExecutionPhaseV1::from_code(cursor.u8()?).ok_or(AgentProtocolError::UnknownValue)?;
    let result_bytes = cursor.length_prefixed(1_048_576)?.to_vec();
    let result_digest = ObjectDigest::from_bytes(cursor.array()?);
    AgentExecutionOutcomeV1::restore(
        session,
        sequence,
        operation_id,
        request_commitment,
        phase,
        result_bytes,
        result_digest,
    )
    .map_err(Into::into)
}

fn put_bytes(output: &mut Vec<u8>, bytes: &[u8]) {
    output.extend_from_slice(&(bytes.len() as u32).to_be_bytes());
    output.extend_from_slice(bytes);
}

fn decode_feature(code: u8) -> Result<AgentFeatureV1, AgentProtocolError> {
    match code {
        1 => Ok(AgentFeatureV1::Readiness),
        2 => Ok(AgentFeatureV1::ExecutionHandoff),
        3 => Ok(AgentFeatureV1::ExecutionObservation),
        4 => Ok(AgentFeatureV1::TerminalResize),
        5 => Ok(AgentFeatureV1::ExecutionSignal),
        6 => Ok(AgentFeatureV1::Quiesce),
        7 => Ok(AgentFeatureV1::RuntimeArgumentObservation),
        _ => Err(AgentProtocolError::UnknownValue),
    }
}

/// Reports framing, bound, closed-value, or semantic rejection.
#[derive(Clone, Debug, Eq, PartialEq, thiserror::Error)]
pub enum AgentProtocolError {
    /// The complete frame exceeds its fixed maximum.
    #[error("agent frame exceeds its byte limit")]
    FrameTooLarge,
    /// A bounded allocation could not be reserved.
    #[error("agent frame allocation failed")]
    AllocationFailed,
    /// Input ends before a fixed or declared field completes.
    #[error("agent frame is truncated")]
    Truncated,
    /// The format magic does not name agent protocol 1.0.
    #[error("agent frame has the wrong magic")]
    WrongMagic,
    /// The exact protocol version is unsupported.
    #[error("agent protocol version is unsupported")]
    WrongVersion,
    /// A length is empty, oversized, or exceeds remaining input.
    #[error("agent frame length is invalid")]
    InvalidLength,
    /// A closed frame, operation, feature, or phase code is unknown.
    #[error("agent frame contains an unknown closed value")]
    UnknownValue,
    /// Bytes remain after the exact frame.
    #[error("agent frame has trailing bytes")]
    TrailingBytes,
    /// A claimed request or result commitment cannot be reproduced.
    #[error("agent frame commitment does not match")]
    CommitmentMismatch,
    /// A sealed reference was requested for a different operation.
    #[error("agent descriptor reference does not name an Authorize operation")]
    InvalidDescriptorReference,
    /// The decoded portable model is invalid.
    #[error("agent frame semantics are invalid: {0}")]
    Model(#[from] InvalidAgentModel),
}

struct Cursor<'a> {
    bytes: &'a [u8],
    position: usize,
}

impl<'a> Cursor<'a> {
    const fn new(bytes: &'a [u8]) -> Self {
        Self { bytes, position: 0 }
    }

    fn exact(&mut self, expected: &[u8]) -> Result<(), AgentProtocolError> {
        if self.take(expected.len())? == expected {
            Ok(())
        } else {
            Err(AgentProtocolError::WrongMagic)
        }
    }

    fn finish(&self) -> Result<(), AgentProtocolError> {
        if self.position == self.bytes.len() {
            Ok(())
        } else {
            Err(AgentProtocolError::TrailingBytes)
        }
    }

    fn take(&mut self, length: usize) -> Result<&'a [u8], AgentProtocolError> {
        let end = self
            .position
            .checked_add(length)
            .ok_or(AgentProtocolError::InvalidLength)?;
        let value = self
            .bytes
            .get(self.position..end)
            .ok_or(AgentProtocolError::Truncated)?;
        self.position = end;
        Ok(value)
    }

    fn array<const N: usize>(&mut self) -> Result<[u8; N], AgentProtocolError> {
        self.take(N)?
            .try_into()
            .map_err(|_| AgentProtocolError::Truncated)
    }

    fn u8(&mut self) -> Result<u8, AgentProtocolError> {
        Ok(self.array::<1>()?[0])
    }

    fn u16(&mut self) -> Result<u16, AgentProtocolError> {
        Ok(u16::from_be_bytes(self.array()?))
    }

    fn u32(&mut self) -> Result<u32, AgentProtocolError> {
        Ok(u32::from_be_bytes(self.array()?))
    }

    fn u64(&mut self) -> Result<u64, AgentProtocolError> {
        Ok(u64::from_be_bytes(self.array()?))
    }

    fn length_prefixed(&mut self, maximum: usize) -> Result<&'a [u8], AgentProtocolError> {
        let length = usize::try_from(self.u32()?).map_err(|_| AgentProtocolError::InvalidLength)?;
        if length == 0 || length > maximum {
            return Err(AgentProtocolError::InvalidLength);
        }
        self.take(length)
    }
}

#[cfg(test)]
mod openssh_gate_tests {
    use super::{AgentFrameV1, AgentProtocolError, decode_frame_v1, encode_frame_v1};

    #[test]
    fn gate_frames_round_trip_and_reject_trailing_or_unbounded_payloads() {
        let request = AgentFrameV1::OpenSshGateObserveRequest(b"{}".to_vec());
        let encoded = encode_frame_v1(&request);
        assert_eq!(decode_frame_v1(&encoded), Ok(request));

        let response = AgentFrameV1::OpenSshGateReadback(b"AOSSGR01".to_vec());
        assert_eq!(decode_frame_v1(&encode_frame_v1(&response)), Ok(response));

        let mut trailing = encoded.clone();
        trailing.push(0);
        assert_eq!(
            decode_frame_v1(&trailing),
            Err(AgentProtocolError::TrailingBytes)
        );

        let oversized = AgentFrameV1::OpenSshGateObserveRequest(vec![1; 4097]);
        assert_eq!(
            decode_frame_v1(&encode_frame_v1(&oversized)),
            Err(AgentProtocolError::InvalidLength)
        );
    }
}

#[cfg(test)]
mod sealed_authorize_tests {
    use std::time::{Duration, Instant};

    use aos_sandbox_core::{AuditId, ExecutionId, ObjectDigest, PrincipalId};
    use aos_sandbox_linux::immutable_file::{SealedMemfdMapping, SealedReadOnlyCredential};
    use aos_sandbox_linux::seqpacket::{SeqpacketError, SeqpacketSocket};
    use sha2::{Digest as _, Sha256};

    use super::{
        AgentFrameV1, AgentOperationIdV1, AgentOperationSequenceV1, AgentProtocolError,
        AgentSealedAuthorizeReferenceV1, AgentSessionBindingV1, MAX_AGENT_SEALED_SPEC_BYTES_V1,
        decode_frame_v1, encode_frame_v1,
    };

    fn reference(content: &[u8]) -> AgentSealedAuthorizeReferenceV1 {
        AgentSealedAuthorizeReferenceV1 {
            session: AgentSessionBindingV1::from_digest(ObjectDigest::from_bytes([1; 32])).unwrap(),
            sequence: AgentOperationSequenceV1::new(1).unwrap(),
            operation_id: AgentOperationIdV1::new([2; 16]).unwrap(),
            backend_request_binding: ObjectDigest::from_bytes([3; 32]),
            execution: ExecutionId::from_bytes([4; 16]),
            content_bytes: content.len() as u64,
            content_digest: ObjectDigest::from_bytes(Sha256::digest(content).into()),
            specification_digest: ObjectDigest::from_bytes([5; 32]),
            admission_commitment: ObjectDigest::from_bytes([6; 32]),
            principal: PrincipalId::from_bytes([7; 16]),
            audit: AuditId::from_bytes([8; 16]),
            request_commitment: ObjectDigest::from_bytes([9; 32]),
        }
    }

    #[test]
    fn sealed_reference_is_small_and_rejects_changed_length_or_hash() {
        let reference = reference(b"x");
        let frame = encode_frame_v1(&AgentFrameV1::SealedAuthorizeRequest(reference));
        assert!(frame.len() < 512);
        assert_eq!(
            decode_frame_v1(&frame),
            Ok(AgentFrameV1::SealedAuthorizeRequest(reference))
        );
        assert_eq!(
            reference.reconstruct(b"y"),
            Err(AgentProtocolError::CommitmentMismatch)
        );
        assert_eq!(
            reference.reconstruct(b"xx"),
            Err(AgentProtocolError::CommitmentMismatch)
        );
        assert!(matches!(
            reference.reconstruct(b"x"),
            Err(AgentProtocolError::Model(_))
        ));

        let content_size_offset = 8 + 1 + 32 + 8 + 16 + 32 + 16;
        let mut zero_length = frame.clone();
        zero_length[content_size_offset..content_size_offset + 8].fill(0);
        assert_eq!(
            decode_frame_v1(&zero_length),
            Err(AgentProtocolError::InvalidLength)
        );
        let mut oversized = frame;
        oversized[content_size_offset..content_size_offset + 8]
            .copy_from_slice(&(MAX_AGENT_SEALED_SPEC_BYTES_V1 as u64 + 1).to_be_bytes());
        assert_eq!(
            decode_frame_v1(&oversized),
            Err(AgentProtocolError::InvalidLength)
        );
    }

    #[test]
    fn maximum_size_content_crosses_one_sealed_descriptor_not_a_large_datagram() {
        let content = vec![0xa5; MAX_AGENT_SEALED_SPEC_BYTES_V1];
        let reference = reference(&content);
        let frame = encode_frame_v1(&AgentFrameV1::SealedAuthorizeRequest(reference));
        let credential = SealedReadOnlyCredential::create(
            "agent-spec-maximum-test",
            &content,
            MAX_AGENT_SEALED_SPEC_BYTES_V1,
        )
        .unwrap();
        let (mut receiver, sender) = SeqpacketSocket::pair_with_record_subjects().unwrap();
        let mut sender = SeqpacketSocket::from_owned(sender).unwrap();
        sender
            .send_with_descriptors(&frame, &[credential.as_fd()])
            .unwrap();

        let deadline = Instant::now() + Duration::from_secs(5);
        let record = loop {
            match receiver.receive_with_optional_descriptor(512) {
                Ok(record) => break record,
                Err(SeqpacketError::WouldBlock | SeqpacketError::Interrupted) => {
                    assert!(Instant::now() < deadline, "descriptor receive timed out");
                    std::thread::yield_now();
                }
                Err(error) => panic!("descriptor receive failed: {error}"),
            }
        };
        let (received, _, mut descriptors) = record.into_parts();
        assert_eq!(
            decode_frame_v1(&received),
            Ok(AgentFrameV1::SealedAuthorizeRequest(reference))
        );
        assert_eq!(descriptors.len(), 1);
        let descriptor = descriptors.pop().unwrap();
        let actual_digest = SealedMemfdMapping::run(
            descriptor,
            reference.content_bytes(),
            MAX_AGENT_SEALED_SPEC_BYTES_V1 as u64,
            |bytes, _| ObjectDigest::from_bytes(Sha256::digest(bytes).into()),
        )
        .unwrap();
        assert_eq!(actual_digest, reference.content_digest);
    }
}
