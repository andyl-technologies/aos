//! Canonical durable agent checkpoints, bounded history, and authenticated reopen.
//!
//! ```text
//! checkpoint = "AOSAGC01" || sequence || provisioning-commitment
//!              || session? || executions || quiesced || sha256(prefix)
//! ```
//!
//! Requests and outcomes inside a checkpoint retain their canonical
//! `AOSAGE01` frames. Protected stores authenticate the complete checkpoint
//! and provenance before allowing reducer restore. This crate only validates
//! canonical checkpoint bytes; protected-store authority stays in the concrete
//! controller adapter.

use aos_sandbox_core::{ExecutionId, ObjectDigest};
use sha2::{Digest as _, Sha256};

use aos_sandbox_agent::{
    AgentExecutionOutcomeV1, AgentExecutionPhaseV1, AgentFrameV1, AgentOperationIdV1,
    AgentOperationRequestV1, AgentOperationSequenceV1, AgentProtocolError, AgentSessionBindingV1,
    InvalidAgentModel, decode_frame_v1, encode_frame_v1,
};

use super::agent_reducer::{
    AgentOperationCasError, AgentOperationReservationV1, AgentProvisioningV1, AgentReducerError,
    AgentReservationDispositionV1, AgentReservationRecoveryTokenV1, GuestAgentReducerV1,
};

const MAGIC: &[u8; 8] = b"AOSAGC01";
const MAX_CHECKPOINT_BYTES: usize = 16 * 1_048_576 - 1_024;
const MAX_HISTORY: usize = 1_024;
const MAX_EXECUTIONS: usize = 4_096;

/// Stores one canonical durable agent reducer checkpoint.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct AgentDurableCheckpointV1 {
    sequence: u64,
    provisioning_commitment: ObjectDigest,
    bytes: Vec<u8>,
    checkpoint_commitment: ObjectDigest,
    pub(crate) state: ReducerCheckpointState,
}

/// Carries one canonical checkpoint candidate projected by a reducer.
///
/// The wrapper has no public constructor and is deliberately distinct from a
/// checkpoint returned by [`decode_checkpoint_v1`]. It conveys shape, not
/// persistence authority: a protected store must independently replay its
/// complete retained history before accepting the candidate.
pub struct AgentCheckpointCandidateV1 {
    checkpoint: AgentDurableCheckpointV1,
}

impl AgentCheckpointCandidateV1 {
    /// Returns the exact reducer-projected canonical checkpoint.
    #[must_use]
    pub const fn checkpoint(&self) -> &AgentDurableCheckpointV1 {
        &self.checkpoint
    }
}

impl AgentDurableCheckpointV1 {
    /// Returns the protected checkpoint sequence.
    #[must_use]
    pub const fn sequence(&self) -> u64 {
        self.sequence
    }

    /// Returns the exact provisioning commitment.
    #[must_use]
    pub const fn provisioning_commitment(&self) -> ObjectDigest {
        self.provisioning_commitment
    }

    /// Returns canonical `AOSAGC01` bytes.
    #[must_use]
    pub fn as_bytes(&self) -> &[u8] {
        &self.bytes
    }

    /// Returns the commitment to the complete checkpoint prefix.
    #[must_use]
    pub const fn checkpoint_commitment(&self) -> ObjectDigest {
        self.checkpoint_commitment
    }
}

pub(crate) fn checkpoint_from_reducer(
    reducer: &GuestAgentReducerV1,
    sequence: u64,
) -> Result<AgentCheckpointCandidateV1, AgentReducerError> {
    if sequence == 0 {
        return Err(AgentReducerError::InvalidCheckpoint);
    }
    let provisioning_commitment = provisioning_commitment(reducer.provisioning());
    let state = reducer.checkpoint_state();
    let bytes = encode_state(sequence, provisioning_commitment, &state)?;
    let checkpoint_commitment = checkpoint_digest(&bytes[..bytes.len() - 32]);
    Ok(AgentCheckpointCandidateV1 {
        checkpoint: AgentDurableCheckpointV1 {
            sequence,
            provisioning_commitment,
            bytes,
            checkpoint_commitment,
            state,
        },
    })
}

pub(crate) fn reopen_reducer(
    provisioning: AgentProvisioningV1,
    checkpoint: AgentDurableCheckpointV1,
) -> Result<GuestAgentReducerV1, AgentReducerError> {
    if provisioning_commitment(&provisioning) != checkpoint.provisioning_commitment {
        return Err(AgentReducerError::CheckpointProvisioningMismatch);
    }
    GuestAgentReducerV1::from_checkpoint_state(provisioning, checkpoint.state)
}

/// Decodes one canonical bounded `AOSAGC01` checkpoint.
///
/// # Errors
///
/// Returns [`AgentCheckpointError`] for truncation, invalid values, excessive
/// allocation, noncanonical embedded frames, or commitment mismatch.
pub fn decode_checkpoint_v1(
    bytes: &[u8],
) -> Result<AgentDurableCheckpointV1, AgentCheckpointError> {
    if bytes.len() > MAX_CHECKPOINT_BYTES || bytes.len() < 8 + 8 + 32 + 1 + 2 + 1 + 32 {
        return Err(AgentCheckpointError::Bounds);
    }
    let (prefix, claimed_digest) = bytes.split_at(bytes.len() - 32);
    let checkpoint_commitment = checkpoint_digest(prefix);
    if claimed_digest != checkpoint_commitment.as_bytes() {
        return Err(AgentCheckpointError::Corrupt);
    }
    let mut cursor = Cursor::new(prefix);
    cursor.exact(MAGIC)?;
    let sequence = cursor.u64()?;
    if sequence == 0 {
        return Err(AgentCheckpointError::Corrupt);
    }
    let provisioning_commitment = ObjectDigest::from_bytes(cursor.array()?);
    if provisioning_commitment.as_bytes() == &[0; 32] {
        return Err(AgentCheckpointError::Corrupt);
    }
    let session = match cursor.u8()? {
        0 => None,
        1 => Some(decode_session(&mut cursor)?),
        _ => return Err(AgentCheckpointError::Corrupt),
    };
    let execution_count = usize::from(cursor.u16()?);
    if execution_count > MAX_EXECUTIONS {
        return Err(AgentCheckpointError::Bounds);
    }
    let mut executions = Vec::new();
    executions
        .try_reserve_exact(execution_count)
        .map_err(|_| AgentCheckpointError::Bounds)?;
    let mut previous = None;
    for _ in 0..execution_count {
        let execution = ExecutionId::from_bytes(cursor.array()?);
        if execution.as_bytes() == &[0; 16] || previous.is_some_and(|value| value >= execution) {
            return Err(AgentCheckpointError::Corrupt);
        }
        previous = Some(execution);
        executions.push((execution, decode_phase(cursor.u8()?)?));
    }
    let quiesced = match cursor.u8()? {
        0 => false,
        1 => true,
        _ => return Err(AgentCheckpointError::Corrupt),
    };
    cursor.finish()?;
    let state = ReducerCheckpointState {
        session,
        executions,
        quiesced,
    };
    let decoded = SelfEncoded {
        sequence,
        provisioning_commitment,
        state: &state,
    };
    let canonical = encode_state(
        decoded.sequence,
        decoded.provisioning_commitment,
        decoded.state,
    )
    .map_err(|_| AgentCheckpointError::Bounds)?;
    if canonical != bytes {
        return Err(AgentCheckpointError::Corrupt);
    }
    Ok(AgentDurableCheckpointV1 {
        sequence,
        provisioning_commitment,
        bytes: bytes.to_vec(),
        checkpoint_commitment,
        state,
    })
}

struct SelfEncoded<'state> {
    sequence: u64,
    provisioning_commitment: ObjectDigest,
    state: &'state ReducerCheckpointState,
}

fn encode_state(
    sequence: u64,
    provisioning: ObjectDigest,
    state: &ReducerCheckpointState,
) -> Result<Vec<u8>, AgentReducerError> {
    let mut bytes = Vec::new();
    bytes.extend_from_slice(MAGIC);
    bytes.extend_from_slice(&sequence.to_be_bytes());
    bytes.extend_from_slice(provisioning.as_bytes());
    match &state.session {
        None => bytes.push(0),
        Some(session) => {
            bytes.push(1);
            encode_session(&mut bytes, session)?;
        }
    }
    let count =
        u16::try_from(state.executions.len()).map_err(|_| AgentReducerError::InvalidCheckpoint)?;
    bytes.extend_from_slice(&count.to_be_bytes());
    for (execution, phase) in &state.executions {
        bytes.extend_from_slice(execution.as_bytes());
        bytes.push(phase_code(*phase));
    }
    bytes.push(u8::from(state.quiesced));
    let digest = checkpoint_digest(&bytes);
    bytes.extend_from_slice(digest.as_bytes());
    if bytes.len() > MAX_CHECKPOINT_BYTES {
        return Err(AgentReducerError::InvalidCheckpoint);
    }
    Ok(bytes)
}

fn encode_session(
    bytes: &mut Vec<u8>,
    session: &SessionCheckpointState,
) -> Result<(), AgentReducerError> {
    bytes.extend_from_slice(session.binding.digest().as_bytes());
    bytes.extend_from_slice(&session.next_sequence.get().to_be_bytes());
    bytes.push(u8::from(session.poisoned));
    match &session.outstanding {
        None => bytes.push(0),
        Some(OutstandingCheckpointState::Reserved {
            reservation,
            request,
        }) => {
            bytes.push(1);
            bytes.extend_from_slice(&reservation.sequence().get().to_be_bytes());
            bytes.extend_from_slice(reservation.operation_id().as_bytes());
            bytes.extend_from_slice(reservation.request_commitment().as_bytes());
            bytes.extend_from_slice(reservation.store_commitment().as_bytes());
            bytes.push(match reservation.disposition() {
                AgentReservationDispositionV1::Created => 1,
                AgentReservationDispositionV1::ExactReplay => 2,
            });
            put_frame(bytes, &AgentFrameV1::OperationRequest(request.clone()))?;
        }
        Some(OutstandingCheckpointState::ReservationRecovery { token, request }) => {
            bytes.push(2);
            bytes.extend_from_slice(&token.sequence().get().to_be_bytes());
            bytes.extend_from_slice(token.operation_id().as_bytes());
            bytes.extend_from_slice(token.request_commitment().as_bytes());
            bytes.extend_from_slice(token.store_commitment().as_bytes());
            bytes.extend_from_slice(token.predecessor_commitment().as_bytes());
            bytes.extend_from_slice(token.recovery_binding().as_bytes());
            put_frame(bytes, &AgentFrameV1::OperationRequest(request.clone()))?;
        }
    }
    let count = u16::try_from(session.completed_history.len())
        .map_err(|_| AgentReducerError::InvalidCheckpoint)?;
    bytes.extend_from_slice(&count.to_be_bytes());
    for outcome in &session.completed_history {
        put_frame(bytes, &AgentFrameV1::OperationOutcome(outcome.clone()))?;
    }
    Ok(())
}

fn decode_session(cursor: &mut Cursor<'_>) -> Result<SessionCheckpointState, AgentCheckpointError> {
    let binding = AgentSessionBindingV1::from_digest(ObjectDigest::from_bytes(cursor.array()?))?;
    let next_sequence = AgentOperationSequenceV1::new(cursor.u64()?)?;
    let poisoned = match cursor.u8()? {
        0 => false,
        1 => true,
        _ => return Err(AgentCheckpointError::Corrupt),
    };
    let outstanding = match cursor.u8()? {
        0 => None,
        1 => {
            let sequence = AgentOperationSequenceV1::new(cursor.u64()?)?;
            let operation = AgentOperationIdV1::new(cursor.array()?)?;
            let request_commitment = ObjectDigest::from_bytes(cursor.array()?);
            let store_commitment = ObjectDigest::from_bytes(cursor.array()?);
            let disposition = match cursor.u8()? {
                1 => AgentReservationDispositionV1::Created,
                2 => AgentReservationDispositionV1::ExactReplay,
                _ => return Err(AgentCheckpointError::Corrupt),
            };
            let AgentFrameV1::OperationRequest(request) = cursor.frame()? else {
                return Err(AgentCheckpointError::Corrupt);
            };
            let reservation = AgentOperationReservationV1::new(
                binding,
                sequence,
                operation,
                request_commitment,
                store_commitment,
                disposition,
            )?;
            if request.session() != binding
                || request.sequence() != sequence
                || request.operation_id() != operation
                || request.request_commitment() != request_commitment
            {
                return Err(AgentCheckpointError::Corrupt);
            }
            Some(OutstandingCheckpointState::Reserved {
                reservation,
                request,
            })
        }
        2 => {
            let sequence = AgentOperationSequenceV1::new(cursor.u64()?)?;
            let operation = AgentOperationIdV1::new(cursor.array()?)?;
            let request_commitment = ObjectDigest::from_bytes(cursor.array()?);
            let store_commitment = ObjectDigest::from_bytes(cursor.array()?);
            let predecessor_commitment = ObjectDigest::from_bytes(cursor.array()?);
            let recovery_binding = ObjectDigest::from_bytes(cursor.array()?);
            let AgentFrameV1::OperationRequest(request) = cursor.frame()? else {
                return Err(AgentCheckpointError::Corrupt);
            };
            let token = AgentReservationRecoveryTokenV1::from_store_ambiguity(
                &request,
                store_commitment,
                predecessor_commitment,
                recovery_binding,
            )?;
            if request.session() != binding
                || request.sequence() != sequence
                || request.operation_id() != operation
                || request.request_commitment() != request_commitment
                || token.session() != binding
                || token.sequence() != sequence
                || token.operation_id() != operation
                || token.request_commitment() != request_commitment
            {
                return Err(AgentCheckpointError::Corrupt);
            }
            Some(OutstandingCheckpointState::ReservationRecovery { token, request })
        }
        _ => return Err(AgentCheckpointError::Corrupt),
    };
    let history_count = usize::from(cursor.u16()?);
    if history_count > MAX_HISTORY {
        return Err(AgentCheckpointError::Bounds);
    }
    let mut completed_history = Vec::new();
    completed_history
        .try_reserve_exact(history_count)
        .map_err(|_| AgentCheckpointError::Bounds)?;
    let mut previous = None;
    for _ in 0..history_count {
        let AgentFrameV1::OperationOutcome(outcome) = cursor.frame()? else {
            return Err(AgentCheckpointError::Corrupt);
        };
        if outcome.session() != binding
            || previous.is_some_and(|sequence| sequence >= outcome.sequence())
        {
            return Err(AgentCheckpointError::Corrupt);
        }
        previous = Some(outcome.sequence());
        completed_history.push(outcome);
    }
    Ok(SessionCheckpointState {
        binding,
        next_sequence,
        outstanding,
        completed_history,
        poisoned,
    })
}

fn put_frame(bytes: &mut Vec<u8>, frame: &AgentFrameV1) -> Result<(), AgentReducerError> {
    let frame = encode_frame_v1(frame);
    let length = u32::try_from(frame.len()).map_err(|_| AgentReducerError::InvalidCheckpoint)?;
    bytes.extend_from_slice(&length.to_be_bytes());
    bytes.extend_from_slice(&frame);
    Ok(())
}

fn provisioning_commitment(provisioning: &AgentProvisioningV1) -> ObjectDigest {
    let runtime = provisioning.runtime();
    let mut digest = Sha256::new();
    digest.update(b"aos-sandbox-agent-provisioning-v1\0");
    digest.update(runtime.sandbox().as_bytes());
    digest.update(runtime.incarnation().as_bytes());
    digest.update(runtime.assignment_epoch().get().to_be_bytes());
    digest.update(runtime.assignment_digest().as_bytes());
    digest.update(runtime.desired_generation().get().to_be_bytes());
    digest.update(runtime.namespace_generation().get().to_be_bytes());
    digest.update(runtime.payload_boot_id());
    digest.update(provisioning.host_channel_binding().as_bytes());
    digest.update(provisioning.agent_instance());
    digest.update(provisioning.recovery_authority_binding().as_bytes());
    digest.update((provisioning.features().as_slice().len() as u16).to_be_bytes());
    for feature in provisioning.features().as_slice() {
        digest.update([*feature as u8]);
    }
    ObjectDigest::from_bytes(digest.finalize().into())
}

fn checkpoint_digest(bytes: &[u8]) -> ObjectDigest {
    let mut digest = Sha256::new();
    digest.update(b"aos-sandbox-agent-checkpoint-v1\0");
    digest.update((bytes.len() as u64).to_be_bytes());
    digest.update(bytes);
    ObjectDigest::from_bytes(digest.finalize().into())
}

fn phase_code(phase: AgentExecutionPhaseV1) -> u8 {
    match phase {
        AgentExecutionPhaseV1::Authorized => 1,
        AgentExecutionPhaseV1::Starting => 2,
        AgentExecutionPhaseV1::Running => 3,
        AgentExecutionPhaseV1::Exited => 4,
        AgentExecutionPhaseV1::Canceled => 5,
        AgentExecutionPhaseV1::Failed => 6,
        AgentExecutionPhaseV1::Lost => 7,
        AgentExecutionPhaseV1::Quiesced => 8,
        AgentExecutionPhaseV1::Ready => 9,
    }
}

fn decode_phase(code: u8) -> Result<AgentExecutionPhaseV1, AgentCheckpointError> {
    match code {
        1 => Ok(AgentExecutionPhaseV1::Authorized),
        2 => Ok(AgentExecutionPhaseV1::Starting),
        3 => Ok(AgentExecutionPhaseV1::Running),
        4 => Ok(AgentExecutionPhaseV1::Exited),
        5 => Ok(AgentExecutionPhaseV1::Canceled),
        6 => Ok(AgentExecutionPhaseV1::Failed),
        7 => Ok(AgentExecutionPhaseV1::Lost),
        8 => Ok(AgentExecutionPhaseV1::Quiesced),
        9 => Ok(AgentExecutionPhaseV1::Ready),
        _ => Err(AgentCheckpointError::Corrupt),
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct ReducerCheckpointState {
    pub(crate) session: Option<SessionCheckpointState>,
    pub(crate) executions: Vec<(ExecutionId, AgentExecutionPhaseV1)>,
    pub(crate) quiesced: bool,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct SessionCheckpointState {
    pub(crate) binding: AgentSessionBindingV1,
    pub(crate) next_sequence: AgentOperationSequenceV1,
    pub(crate) outstanding: Option<OutstandingCheckpointState>,
    pub(crate) completed_history: Vec<AgentExecutionOutcomeV1>,
    pub(crate) poisoned: bool,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) enum OutstandingCheckpointState {
    Reserved {
        reservation: AgentOperationReservationV1,
        request: AgentOperationRequestV1,
    },
    ReservationRecovery {
        token: AgentReservationRecoveryTokenV1,
        request: AgentOperationRequestV1,
    },
}

struct Cursor<'bytes> {
    bytes: &'bytes [u8],
    offset: usize,
}

impl<'bytes> Cursor<'bytes> {
    fn new(bytes: &'bytes [u8]) -> Self {
        Self { bytes, offset: 0 }
    }

    fn exact(&mut self, expected: &[u8]) -> Result<(), AgentCheckpointError> {
        if self.take(expected.len())? != expected {
            return Err(AgentCheckpointError::Corrupt);
        }
        Ok(())
    }

    fn u8(&mut self) -> Result<u8, AgentCheckpointError> {
        self.take(1)?
            .first()
            .copied()
            .ok_or(AgentCheckpointError::Truncated)
    }

    fn u16(&mut self) -> Result<u16, AgentCheckpointError> {
        Ok(u16::from_be_bytes(self.array()?))
    }

    fn u32(&mut self) -> Result<u32, AgentCheckpointError> {
        Ok(u32::from_be_bytes(self.array()?))
    }

    fn u64(&mut self) -> Result<u64, AgentCheckpointError> {
        Ok(u64::from_be_bytes(self.array()?))
    }

    fn array<const N: usize>(&mut self) -> Result<[u8; N], AgentCheckpointError> {
        self.take(N)?
            .try_into()
            .map_err(|_| AgentCheckpointError::Truncated)
    }

    fn frame(&mut self) -> Result<AgentFrameV1, AgentCheckpointError> {
        let length = usize::try_from(self.u32()?).map_err(|_| AgentCheckpointError::Bounds)?;
        decode_frame_v1(self.take(length)?).map_err(Into::into)
    }

    fn take(&mut self, length: usize) -> Result<&'bytes [u8], AgentCheckpointError> {
        let end = self
            .offset
            .checked_add(length)
            .ok_or(AgentCheckpointError::Bounds)?;
        let value = self
            .bytes
            .get(self.offset..end)
            .ok_or(AgentCheckpointError::Truncated)?;
        self.offset = end;
        Ok(value)
    }

    fn finish(self) -> Result<(), AgentCheckpointError> {
        if self.offset == self.bytes.len() {
            Ok(())
        } else {
            Err(AgentCheckpointError::Corrupt)
        }
    }
}

/// Reports durable agent checkpoint rejection.
#[derive(Clone, Debug, Eq, PartialEq, thiserror::Error)]
pub enum AgentCheckpointError {
    /// Checkpoint input is truncated.
    #[error("agent checkpoint is truncated")]
    Truncated,
    /// Checkpoint allocation or encoded size exceeds a fixed bound.
    #[error("agent checkpoint exceeds a fixed bound")]
    Bounds,
    /// Canonical bytes or retained state are corrupt.
    #[error("agent checkpoint is corrupt")]
    Corrupt,
    /// Protected store provenance is missing.
    #[error("agent checkpoint is unauthenticated")]
    Unauthenticated,
    /// Protected persistence is unavailable or ambiguous.
    #[error("agent checkpoint store is unavailable")]
    StoreUnavailable,
    /// Embedded `AOSAGE01` framing is invalid.
    #[error("agent checkpoint protocol failed: {0}")]
    Protocol(#[from] AgentProtocolError),
    /// Embedded model state is invalid.
    #[error("agent checkpoint model failed: {0}")]
    Model(#[from] InvalidAgentModel),
    /// Embedded CAS receipt is invalid.
    #[error("agent checkpoint reservation failed: {0}")]
    Reservation(#[from] AgentOperationCasError),
}
