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
//!       / 7 immutable original ticket binding-only request (v2 carrier)
//!       / 8 sealed Authorize reference with one SCM_RIGHTS descriptor
//!       / 9 signed physical original ticket readback (v2 carrier)
//! ```
//!
//! Integers are big-endian. Variable bytes use a `u32be` length and every
//! decoder applies its semantic maximum before allocation. Closed values have
//! no unknown-value pass-through and trailing bytes are forbidden.

use aos_sandbox_core::bounded_codec::{BoundedReader, ReadError};
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
    /// Carries original immutable ticket bytes for binding-only installation.
    OpenSshTicketBindRequestV2(Vec<u8>),
    /// Returns a fresh physical measurement, never authenticated SSH custody.
    OpenSshTicketReadbackV2(Vec<u8>),
    /// Polls or consumes one original ticket on the provisioned root channel.
    OriginalAttachRequestV3(Vec<u8>),
    /// Returns non-authorizing custody or the exact transfer completion.
    OriginalAttachResponseV3(Vec<u8>),
    /// Polls or applies an exact original-monitor control on the protected channel.
    OriginalControlRequestV5(Vec<u8>),
    /// Returns signed original-monitor queue or completed effect evidence.
    OriginalControlResponseV5(Vec<u8>),
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
        AgentFrameV1::OpenSshTicketBindRequestV2(request) => {
            bytes.push(7);
            put_bytes(&mut bytes, request);
        }
        AgentFrameV1::OpenSshTicketReadbackV2(packet) => {
            bytes.push(9);
            put_bytes(&mut bytes, packet);
        }
        AgentFrameV1::OriginalAttachRequestV3(packet) => {
            bytes.push(10);
            put_bytes(&mut bytes, packet);
        }
        AgentFrameV1::OriginalAttachResponseV3(packet) => {
            bytes.push(11);
            put_bytes(&mut bytes, packet);
        }
        AgentFrameV1::OriginalControlRequestV5(packet) => {
            bytes.push(12);
            put_bytes(&mut bytes, packet);
        }
        AgentFrameV1::OriginalControlResponseV5(packet) => {
            bytes.push(13);
            put_bytes(&mut bytes, packet);
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
    let mut cursor = BoundedReader::new(bytes, frame_read_error);
    if cursor.bytes(MAGIC.len())? != MAGIC {
        return Err(AgentProtocolError::WrongMagic);
    }
    let frame = match cursor.u8()? {
        1 => AgentFrameV1::HandshakeRequest(decode_handshake_request(&mut cursor)?),
        2 => AgentFrameV1::HandshakeResponse(decode_handshake_response(&mut cursor)?),
        3 => AgentFrameV1::OperationRequest(decode_operation_request(&mut cursor)?),
        4 => AgentFrameV1::OperationOutcome(decode_operation_outcome(&mut cursor)?),
        5 => AgentFrameV1::OpenSshGateObserveRequest(
            read_length_prefixed(&mut cursor, 4096)?.to_vec(),
        ),
        6 => AgentFrameV1::OpenSshGateReadback(read_length_prefixed(&mut cursor, 8192)?.to_vec()),
        7 => AgentFrameV1::OpenSshTicketBindRequestV2(
            read_length_prefixed(
                &mut cursor,
                crate::openssh_ticket::MAXIMUM_TICKET_GATE_BYTES_V2,
            )?
            .to_vec(),
        ),
        9 => AgentFrameV1::OpenSshTicketReadbackV2(
            read_length_prefixed(
                &mut cursor,
                crate::openssh_ticket::MAXIMUM_TICKET_GATE_BYTES_V2,
            )?
            .to_vec(),
        ),
        8 => AgentFrameV1::SealedAuthorizeRequest(decode_sealed_authorize_reference(&mut cursor)?),
        10 => AgentFrameV1::OriginalAttachRequestV3(
            read_length_prefixed(
                &mut cursor,
                crate::openssh_consume::MAXIMUM_CONSUME_BYTES_V3,
            )?
            .to_vec(),
        ),
        11 => AgentFrameV1::OriginalAttachResponseV3(
            read_length_prefixed(
                &mut cursor,
                crate::openssh_consume::MAXIMUM_CONSUME_BYTES_V3,
            )?
            .to_vec(),
        ),
        12 => AgentFrameV1::OriginalControlRequestV5(
            read_length_prefixed(
                &mut cursor,
                crate::openssh_control_channel::MAXIMUM_ORIGINAL_CONTROL_BYTES_V5,
            )?
            .to_vec(),
        ),
        13 => AgentFrameV1::OriginalControlResponseV5(
            read_length_prefixed(
                &mut cursor,
                crate::openssh_control_channel::MAXIMUM_ORIGINAL_CONTROL_BYTES_V5,
            )?
            .to_vec(),
        ),
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
    cursor: &mut BoundedReader<'_, AgentProtocolError>,
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

fn decode_runtime(
    cursor: &mut BoundedReader<'_, AgentProtocolError>,
) -> Result<AgentRuntimeBindingV1, AgentProtocolError> {
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
    cursor: &mut BoundedReader<'_, AgentProtocolError>,
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
    cursor: &mut BoundedReader<'_, AgentProtocolError>,
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
    cursor: &mut BoundedReader<'_, AgentProtocolError>,
) -> Result<AgentOperationRequestV1, AgentProtocolError> {
    let session = AgentSessionBindingV1::from_digest(ObjectDigest::from_bytes(cursor.array()?))?;
    let sequence = AgentOperationSequenceV1::new(cursor.u64()?)?;
    let operation_id = AgentOperationIdV1::new(cursor.array()?)?;
    let backend_request_binding = ObjectDigest::from_bytes(cursor.array()?);
    let operation = match cursor.u8()? {
        1 => AgentExecutionOperationV1::Authorize {
            execution: ExecutionId::from_bytes(cursor.array()?),
            specification_bytes: read_length_prefixed(cursor, MAX_AGENT_SEALED_SPEC_BYTES_V1)?
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
    cursor: &mut BoundedReader<'_, AgentProtocolError>,
) -> Result<AgentExecutionOutcomeV1, AgentProtocolError> {
    let session = AgentSessionBindingV1::from_digest(ObjectDigest::from_bytes(cursor.array()?))?;
    let sequence = AgentOperationSequenceV1::new(cursor.u64()?)?;
    let operation_id = AgentOperationIdV1::new(cursor.array()?)?;
    let request_commitment = ObjectDigest::from_bytes(cursor.array()?);
    let phase =
        AgentExecutionPhaseV1::from_code(cursor.u8()?).ok_or(AgentProtocolError::UnknownValue)?;
    let result_bytes = read_length_prefixed(cursor, 1_048_576)?.to_vec();
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

fn frame_read_error(error: ReadError) -> AgentProtocolError {
    match error {
        ReadError::LengthOverflow | ReadError::NonzeroReserved => AgentProtocolError::InvalidLength,
        ReadError::Truncated => AgentProtocolError::Truncated,
        ReadError::TrailingBytes => AgentProtocolError::TrailingBytes,
    }
}

/// Applies the frame-owned nonempty ceiling before reading or allocating payload bytes.
fn read_length_prefixed<'a>(
    cursor: &mut BoundedReader<'a, AgentProtocolError>,
    maximum: usize,
) -> Result<&'a [u8], AgentProtocolError> {
    let length = usize::try_from(cursor.u32()?).map_err(|_| AgentProtocolError::InvalidLength)?;
    if length == 0 || length > maximum {
        return Err(AgentProtocolError::InvalidLength);
    }
    cursor.bytes(length)
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
mod reader_frontier_tests {
    use super::*;

    #[test]
    fn frame_magic_version_and_model_refusals_precede_later_reads_and_eof() {
        for length in 0..=MAGIC.len() {
            assert_eq!(
                decode_frame_v1(&MAGIC[..length]),
                Err(AgentProtocolError::Truncated)
            );
        }
        assert_eq!(
            decode_frame_v1(b"NOTAGE01"),
            Err(AgentProtocolError::WrongMagic)
        );

        let mut unknown = MAGIC.to_vec();
        unknown.extend_from_slice(&[14, 0x55]);
        assert_eq!(
            decode_frame_v1(&unknown),
            Err(AgentProtocolError::UnknownValue)
        );

        let mut handshake = MAGIC.to_vec();
        handshake.push(1);
        handshake.extend_from_slice(&[1; 16]);
        handshake.extend_from_slice(&2_u16.to_be_bytes());
        assert_eq!(
            decode_frame_v1(&handshake),
            Err(AgentProtocolError::WrongVersion)
        );

        let major_offset = MAGIC.len() + 1 + 16;
        handshake[major_offset..].copy_from_slice(&1_u16.to_be_bytes());
        assert_eq!(
            decode_frame_v1(&handshake),
            Err(AgentProtocolError::Truncated)
        );
        handshake.extend_from_slice(&1_u16.to_be_bytes());
        assert_eq!(
            decode_frame_v1(&handshake),
            Err(AgentProtocolError::WrongVersion)
        );

        let mut response = MAGIC.to_vec();
        response.push(2);
        response.extend_from_slice(&[1; 32]);
        response.extend_from_slice(&[2; 16]);
        response.extend_from_slice(&2_u16.to_be_bytes());
        response.extend_from_slice(&[1, 2]);
        response.extend_from_slice(&[3; 64]);
        assert!(matches!(
            decode_frame_v1(&response),
            Ok(AgentFrameV1::HandshakeResponse(_))
        ));

        response.push(0x55);
        assert_eq!(
            decode_frame_v1(&response),
            Err(AgentProtocolError::TrailingBytes)
        );
        let instance_offset = MAGIC.len() + 1 + 32;
        response[instance_offset..instance_offset + 16].fill(0);
        assert_eq!(
            decode_frame_v1(&response),
            Err(AgentProtocolError::Model(InvalidAgentModel::Unspecified))
        );
    }

    #[test]
    fn failed_ranges_and_nonempty_length_limits_preserve_original_input_positions() {
        let bytes = [1, 2, 3];
        let mut cursor = BoundedReader::new(&bytes, frame_read_error);
        assert_eq!(cursor.u8(), Ok(1));
        assert_eq!(
            cursor.bytes(usize::MAX),
            Err(AgentProtocolError::InvalidLength)
        );
        assert_eq!(cursor.remaining_bytes(), &bytes[1..]);
        assert_eq!(cursor.array::<3>(), Err(AgentProtocolError::Truncated));
        assert_eq!(cursor.remaining_bytes(), &bytes[1..]);
        assert_eq!(cursor.finish(), Err(AgentProtocolError::TrailingBytes));

        let short_prefix = [0; 3];
        let mut cursor = BoundedReader::new(&short_prefix, frame_read_error);
        assert_eq!(
            read_length_prefixed(&mut cursor, 4),
            Err(AgentProtocolError::Truncated)
        );
        assert_eq!(cursor.remaining_bytes(), &short_prefix);

        for (length, error) in [
            (0_u32, AgentProtocolError::InvalidLength),
            (5, AgentProtocolError::InvalidLength),
            (4, AgentProtocolError::Truncated),
        ] {
            let mut bytes = length.to_be_bytes().to_vec();
            bytes.push(0x55);
            let mut cursor = BoundedReader::new(&bytes, frame_read_error);
            assert_eq!(read_length_prefixed(&mut cursor, 4), Err(error));
            assert_eq!(cursor.remaining_bytes(), &bytes[4..]);
        }

        let bytes = [0, 0, 0, 1, 0x55];
        let mut cursor = BoundedReader::new(&bytes, frame_read_error);
        let payload = read_length_prefixed(&mut cursor, 4).unwrap();
        assert_eq!(payload, &bytes[4..]);
        assert_eq!(payload.as_ptr(), bytes[4..].as_ptr());
        assert_eq!(cursor.finish(), Ok(()));
    }
}
