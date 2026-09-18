//! Exact bounded durable codecs for execution admission and effect records.
//!
//! Admission records use the fixed `AOSREA01` binary schema:
//!
//! ```text
//! magic[8] || u32be(spec_len) || spec || operation[16] || request_digest[32]
//! || runtime_currentness || plan[32] || runtime_handle[32]
//! || payload_boot_id[16] || backend_probe_currentness || authority[32]
//! || resource_ledger[32] || output_reservation[32]
//! || u64be(journal_sequence) || transaction[32]
//! || record[32]
//! ```
//!
//! Effect records use `AOSREF01`, embed one length-prefixed complete admission
//! record, then encode the closed operation, operation sequence, idempotency,
//! phase, optional bounded result, journal sequence, transaction commitment,
//! and complete record commitment. Integer fields are big-endian and no
//! optional trailing extension area exists, so one semantic value has one
//! byte representation.

use crate::{
    AssignmentEpoch, DecodeLimits, DesiredGeneration, IncarnationId, NamespaceGeneration, NodeId,
    ObjectDigest, ObservationSequence, PayloadBootId, SandboxId,
};

use super::{
    AdmissionCommitDispositionV1, AdmissionCommitError, AdmissionCurrentnessV1,
    AdmissionIdempotencyV1, AdmittedExecutionV1, BackendOperationIdV1, BackendOperationSequenceV1,
    BackendProbeCurrentnessV1, DurableAdmissionCommitV1, DurableExecutionEffectV1,
    EffectCommitError, EffectCompletionStatusV1, EffectCompletionV1, EffectIdempotencyV1,
    EffectIssueV1, EffectOperationV1, EffectPhaseV1, ExecutionAdmissionDraftV1,
    RuntimeCurrentnessV1,
};

const ADMISSION_MAGIC: &[u8; 8] = b"AOSREA01";
const EFFECT_MAGIC: &[u8; 8] = b"AOSREF01";
const MAX_DURABLE_RECORD_BYTES: usize = 32 * 1_048_576;

/// Encodes one exact durable execution admission record.
#[must_use]
pub fn encode_durable_execution_admission_v1(admission: &AdmittedExecutionV1) -> Vec<u8> {
    let currentness = admission.currentness();
    let runtime = currentness.runtime();
    let probe = currentness.backend_probe();
    let mut bytes = Vec::new();
    bytes.extend_from_slice(ADMISSION_MAGIC);
    put_bytes(&mut bytes, admission.specification_bytes());
    bytes.extend_from_slice(admission.idempotency().operation().as_bytes());
    bytes.extend_from_slice(admission.idempotency().request_digest().as_bytes());
    put_runtime_currentness(&mut bytes, runtime.currentness());
    bytes.extend_from_slice(runtime.plan_commitment().as_bytes());
    bytes.extend_from_slice(runtime.handle().as_bytes());
    bytes.extend_from_slice(currentness.payload_boot_id().as_bytes());
    bytes.extend_from_slice(probe.node().as_bytes());
    bytes.extend_from_slice(probe.backend_build().as_bytes());
    bytes.extend_from_slice(&probe.probe_epoch().get().to_be_bytes());
    bytes.extend_from_slice(probe.protected_context().as_bytes());
    bytes.extend_from_slice(currentness.authority_context().as_bytes());
    bytes.extend_from_slice(currentness.resource_ledger().as_bytes());
    bytes.extend_from_slice(currentness.output_reservation().as_bytes());
    bytes.extend_from_slice(&admission.journal_sequence().to_be_bytes());
    bytes.extend_from_slice(admission.transaction_commitment().as_bytes());
    bytes.extend_from_slice(admission.admission_commitment().as_bytes());
    bytes
}

/// Decodes one exact bounded durable execution admission record.
///
/// # Errors
///
/// Returns [`DurableExecutionCodecError`] for truncation, trailing bytes,
/// oversized nested execution bytes, noncanonical execution CBOR, sentinel
/// fields, binding mismatch, or a commitment that cannot be reproduced.
pub fn decode_durable_execution_admission_v1(
    bytes: &[u8],
) -> Result<AdmittedExecutionV1, DurableExecutionCodecError> {
    if bytes.len() > MAX_DURABLE_RECORD_BYTES {
        return Err(DurableExecutionCodecError::RecordTooLarge);
    }
    let mut cursor = Cursor::new(bytes);
    cursor.exact(ADMISSION_MAGIC)?;
    let specification_bytes = cursor.length_prefixed(16 * 1_048_576)?;
    let operation = BackendOperationIdV1::new(cursor.array()?)?;
    let request_digest = ObjectDigest::from_bytes(cursor.array()?);
    let runtime_currentness = read_runtime_currentness(&mut cursor)?;
    let runtime = super::RuntimeHandleCommitmentV1::new(
        runtime_currentness,
        ObjectDigest::from_bytes(cursor.array()?),
        ObjectDigest::from_bytes(cursor.array()?),
    )?;
    let payload_boot_id = PayloadBootId::new(cursor.array()?)
        .map_err(|_| DurableExecutionCodecError::CommitmentMismatch)?;
    let probe_node = NodeId::from_bytes(cursor.array()?);
    let backend_build = ObjectDigest::from_bytes(cursor.array()?);
    let probe_epoch = crate::Revision::new(cursor.u64()?);
    let protected_context = ObjectDigest::from_bytes(cursor.array()?);
    let authority_context = ObjectDigest::from_bytes(cursor.array()?);
    let resource_ledger = ObjectDigest::from_bytes(cursor.array()?);
    let output_reservation = ObjectDigest::from_bytes(cursor.array()?);
    let journal_sequence = cursor.u64()?;
    let transaction_commitment = ObjectDigest::from_bytes(cursor.array()?);
    let record_commitment = ObjectDigest::from_bytes(cursor.array()?);
    cursor.finish()?;

    let specification = crate::decode_execution_spec_v1(
        specification_bytes,
        execution_limits(specification_bytes.len()),
    )?;
    let idempotency = AdmissionIdempotencyV1::new(operation, request_digest)?;
    let probe =
        BackendProbeCurrentnessV1::new(probe_node, backend_build, probe_epoch, protected_context)?;
    let currentness = AdmissionCurrentnessV1::new(
        runtime,
        payload_boot_id,
        probe,
        authority_context,
        resource_ledger,
        output_reservation,
    )?;
    let draft = ExecutionAdmissionDraftV1::new(&specification, idempotency, currentness)?;
    if draft.specification_bytes() != specification_bytes
        || draft.record_commitment() != record_commitment
    {
        return Err(DurableExecutionCodecError::CommitmentMismatch);
    }
    let commit = DurableAdmissionCommitV1::new(
        record_commitment,
        journal_sequence,
        transaction_commitment,
        AdmissionCommitDispositionV1::Created,
    )?;
    Ok(AdmittedExecutionV1::from_commit(draft, commit))
}

/// Encodes one exact durable execution effect record.
#[must_use]
pub fn encode_durable_execution_effect_v1(effect: &DurableExecutionEffectV1) -> Vec<u8> {
    let admission = encode_durable_execution_admission_v1(effect.admission());
    let issue = effect.issue();
    let mut bytes = Vec::new();
    bytes.extend_from_slice(EFFECT_MAGIC);
    put_bytes(&mut bytes, &admission);
    bytes.push(issue.operation().code());
    bytes.extend_from_slice(&issue.operation().arguments());
    bytes.extend_from_slice(&issue.sequence().get().to_be_bytes());
    bytes.extend_from_slice(issue.idempotency().operation().as_bytes());
    bytes.extend_from_slice(issue.idempotency().request_digest().as_bytes());
    bytes.push(phase_code(effect.phase()));
    match effect.completion() {
        Some(completion) => {
            bytes.push(1);
            bytes.push(completion_status_code(completion.status()));
            bytes.extend_from_slice(&completion.observation_sequence().get().to_be_bytes());
            put_bytes(&mut bytes, completion.result_bytes());
            bytes.extend_from_slice(completion.result_digest().as_bytes());
        }
        None => bytes.push(0),
    }
    bytes.extend_from_slice(&effect.journal_sequence().to_be_bytes());
    bytes.extend_from_slice(effect.transaction_commitment().as_bytes());
    bytes.extend_from_slice(effect.record_commitment().as_bytes());
    bytes
}

/// Decodes one exact bounded durable execution effect record.
///
/// # Errors
///
/// Returns [`DurableExecutionCodecError`] for any malformed nested admission,
/// invalid operation/phase/result, trailing byte, or commitment mismatch.
pub fn decode_durable_execution_effect_v1(
    bytes: &[u8],
) -> Result<DurableExecutionEffectV1, DurableExecutionCodecError> {
    if bytes.len() > MAX_DURABLE_RECORD_BYTES {
        return Err(DurableExecutionCodecError::RecordTooLarge);
    }
    let mut cursor = Cursor::new(bytes);
    cursor.exact(EFFECT_MAGIC)?;
    let admission_bytes = cursor.length_prefixed(MAX_DURABLE_RECORD_BYTES)?;
    let admission = decode_durable_execution_admission_v1(admission_bytes)?;
    let operation_code = cursor.u8()?;
    let arguments: [u8; 4] = cursor.array()?;
    let operation = decode_operation(operation_code, arguments)?;
    let sequence = BackendOperationSequenceV1::new(cursor.u64()?)?;
    let idempotency_operation = BackendOperationIdV1::new(cursor.array()?)?;
    let idempotency_request = ObjectDigest::from_bytes(cursor.array()?);
    let phase = decode_phase(cursor.u8()?)?;
    let completion = match cursor.u8()? {
        0 => None,
        1 => {
            let status = decode_completion_status(cursor.u8()?)?;
            let observation_sequence = ObservationSequence::new(cursor.u64()?);
            let result = cursor.length_prefixed(15 * 1_048_576)?.to_vec();
            let result_digest = ObjectDigest::from_bytes(cursor.array()?);
            let completion = EffectCompletionV1::new(status, observation_sequence, result)?;
            if completion.result_digest() != result_digest {
                return Err(DurableExecutionCodecError::CommitmentMismatch);
            }
            Some(completion)
        }
        _ => return Err(DurableExecutionCodecError::UnknownValue),
    };
    let journal_sequence = cursor.u64()?;
    let transaction_commitment = ObjectDigest::from_bytes(cursor.array()?);
    let record_commitment = ObjectDigest::from_bytes(cursor.array()?);
    cursor.finish()?;

    let idempotency = EffectIdempotencyV1::new(idempotency_operation, idempotency_request)?;
    let issue = EffectIssueV1::new(operation, sequence, idempotency)?;
    DurableExecutionEffectV1::restore(
        admission,
        issue,
        phase,
        completion,
        record_commitment,
        journal_sequence,
        transaction_commitment,
    )
    .map_err(Into::into)
}

/// Reports exact durable-record framing or semantic failure.
#[derive(Clone, Debug, Eq, PartialEq, thiserror::Error)]
pub enum DurableExecutionCodecError {
    /// The outer record exceeds the fixed 32-MiB ceiling.
    #[error("durable execution record exceeds its byte limit")]
    RecordTooLarge,
    /// The record ends before a fixed or declared field completes.
    #[error("durable execution record is truncated")]
    Truncated,
    /// The record has another magic/version prefix.
    #[error("durable execution record has an unknown format")]
    WrongMagic,
    /// A length cannot fit the configured bound or remaining input.
    #[error("durable execution record contains an invalid length")]
    InvalidLength,
    /// A closed discriminant has an unknown value or invalid reserved bytes.
    #[error("durable execution record contains an unknown closed value")]
    UnknownValue,
    /// Bytes remain after the exact record.
    #[error("durable execution record has trailing bytes")]
    TrailingBytes,
    /// An internally derived record commitment differs from stored bytes.
    #[error("durable execution record commitment does not match")]
    CommitmentMismatch,
    /// The embedded execution specification is malformed or noncanonical.
    #[error("durable execution specification is invalid: {0}")]
    Execution(#[from] crate::CanonicalCborError),
    /// Admission semantics are invalid.
    #[error("durable execution admission is invalid: {0}")]
    Admission(#[from] AdmissionCommitError),
    /// Effect semantics are invalid.
    #[error("durable execution effect is invalid: {0}")]
    Effect(#[from] EffectCommitError),
    /// Runtime model fields are invalid.
    #[error("durable execution runtime is invalid: {0}")]
    Runtime(#[from] super::RuntimeModelError),
    /// Backend probe fields are invalid.
    #[error("durable execution backend probe is invalid: {0}")]
    Probe(#[from] super::BackendCapabilityViolation),
}

fn put_bytes(output: &mut Vec<u8>, bytes: &[u8]) {
    output.extend_from_slice(&(bytes.len() as u32).to_be_bytes());
    output.extend_from_slice(bytes);
}

fn put_runtime_currentness(output: &mut Vec<u8>, value: &RuntimeCurrentnessV1) {
    output.extend_from_slice(value.sandbox().as_bytes());
    output.extend_from_slice(value.incarnation().as_bytes());
    output.extend_from_slice(value.node().as_bytes());
    output.extend_from_slice(&value.assignment_epoch().get().to_be_bytes());
    output.extend_from_slice(value.assignment_digest().as_bytes());
    output.extend_from_slice(&value.desired_generation().get().to_be_bytes());
    output.extend_from_slice(&value.namespace_generation().get().to_be_bytes());
}

fn read_runtime_currentness(
    cursor: &mut Cursor<'_>,
) -> Result<RuntimeCurrentnessV1, DurableExecutionCodecError> {
    RuntimeCurrentnessV1::new(
        SandboxId::from_bytes(cursor.array()?),
        IncarnationId::from_bytes(cursor.array()?),
        NodeId::from_bytes(cursor.array()?),
        AssignmentEpoch::new(cursor.u64()?),
        ObjectDigest::from_bytes(cursor.array()?),
        DesiredGeneration::new(cursor.u64()?),
        NamespaceGeneration::new(cursor.u64()?),
    )
    .map_err(Into::into)
}

fn decode_operation(
    code: u8,
    arguments: [u8; 4],
) -> Result<EffectOperationV1, DurableExecutionCodecError> {
    let all_zero = arguments == [0; 4];
    match code {
        1 if all_zero => Ok(EffectOperationV1::AuthorizeExecution),
        2 => Ok(EffectOperationV1::ResizeTerminal {
            rows: u16::from_be_bytes([arguments[0], arguments[1]]),
            columns: u16::from_be_bytes([arguments[2], arguments[3]]),
        }),
        3 if arguments[1..] == [0; 3] => Ok(EffectOperationV1::Signal {
            signal_code: arguments[0],
        }),
        4 if all_zero => Ok(EffectOperationV1::Cancel),
        5 if all_zero => Ok(EffectOperationV1::Observe),
        _ => Err(DurableExecutionCodecError::UnknownValue),
    }
}

const fn phase_code(phase: EffectPhaseV1) -> u8 {
    match phase {
        EffectPhaseV1::Pending => 1,
        EffectPhaseV1::Issued => 2,
        EffectPhaseV1::Indeterminate => 3,
        EffectPhaseV1::Complete => 4,
    }
}

fn decode_phase(code: u8) -> Result<EffectPhaseV1, DurableExecutionCodecError> {
    match code {
        1 => Ok(EffectPhaseV1::Pending),
        2 => Ok(EffectPhaseV1::Issued),
        3 => Ok(EffectPhaseV1::Indeterminate),
        4 => Ok(EffectPhaseV1::Complete),
        _ => Err(DurableExecutionCodecError::UnknownValue),
    }
}

const fn completion_status_code(status: EffectCompletionStatusV1) -> u8 {
    match status {
        EffectCompletionStatusV1::Succeeded => 1,
        EffectCompletionStatusV1::RejectedBeforeEffect => 2,
        EffectCompletionStatusV1::FailedPermanent => 3,
    }
}

fn decode_completion_status(
    code: u8,
) -> Result<EffectCompletionStatusV1, DurableExecutionCodecError> {
    match code {
        1 => Ok(EffectCompletionStatusV1::Succeeded),
        2 => Ok(EffectCompletionStatusV1::RejectedBeforeEffect),
        3 => Ok(EffectCompletionStatusV1::FailedPermanent),
        _ => Err(DurableExecutionCodecError::UnknownValue),
    }
}

fn execution_limits(maximum_bytes: usize) -> DecodeLimits {
    DecodeLimits {
        maximum_bytes,
        maximum_collection_items: 65_536,
        maximum_total_items: 262_144,
        maximum_byte_string_bytes: 16 * 1_048_576,
        maximum_text_bytes: 1_048_576,
        maximum_depth: 128,
    }
}

struct Cursor<'a> {
    bytes: &'a [u8],
    position: usize,
}

impl<'a> Cursor<'a> {
    const fn new(bytes: &'a [u8]) -> Self {
        Self { bytes, position: 0 }
    }
    fn exact(&mut self, expected: &[u8]) -> Result<(), DurableExecutionCodecError> {
        let actual = self.take(expected.len())?;
        if actual == expected {
            Ok(())
        } else {
            Err(DurableExecutionCodecError::WrongMagic)
        }
    }
    fn finish(&self) -> Result<(), DurableExecutionCodecError> {
        if self.position == self.bytes.len() {
            Ok(())
        } else {
            Err(DurableExecutionCodecError::TrailingBytes)
        }
    }
    fn take(&mut self, length: usize) -> Result<&'a [u8], DurableExecutionCodecError> {
        let end = self
            .position
            .checked_add(length)
            .ok_or(DurableExecutionCodecError::InvalidLength)?;
        let value = self
            .bytes
            .get(self.position..end)
            .ok_or(DurableExecutionCodecError::Truncated)?;
        self.position = end;
        Ok(value)
    }
    fn array<const N: usize>(&mut self) -> Result<[u8; N], DurableExecutionCodecError> {
        self.take(N)?
            .try_into()
            .map_err(|_| DurableExecutionCodecError::Truncated)
    }
    fn u8(&mut self) -> Result<u8, DurableExecutionCodecError> {
        Ok(self.array::<1>()?[0])
    }
    fn u32(&mut self) -> Result<u32, DurableExecutionCodecError> {
        Ok(u32::from_be_bytes(self.array()?))
    }
    fn u64(&mut self) -> Result<u64, DurableExecutionCodecError> {
        Ok(u64::from_be_bytes(self.array()?))
    }
    fn length_prefixed(&mut self, maximum: usize) -> Result<&'a [u8], DurableExecutionCodecError> {
        let length =
            usize::try_from(self.u32()?).map_err(|_| DurableExecutionCodecError::InvalidLength)?;
        if length == 0 || length > maximum {
            return Err(DurableExecutionCodecError::InvalidLength);
        }
        self.take(length)
    }
}
