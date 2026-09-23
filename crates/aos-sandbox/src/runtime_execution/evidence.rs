//! Operation-specific completion evidence for durable execution effects.
//!
//! ```text
//! AOSEEO01 = authenticated backend observation
//! AOSEL001 = authenticated complete-inventory absence
//! AOSEQ001 = authenticated conflicting-inventory quarantine
//! magic || operation_and_admission_binding || phase || observation_sequence
//!       || observation_or_inventory_commitment || evidence_digest
//! ```

use aos_sandbox_core::ObjectDigest;
use aos_sandbox_core::runtime_backend::{
    BackendExecutionInspectionV1, BackendExecutionInventoryV1, BackendExecutionPhaseV1,
    DurableExecutionEffectV1, EffectCommitError, EffectCompletionStatusV1, EffectCompletionV1,
    EffectOperationV1,
};
use sha2::{Digest as _, Sha256};

const EVIDENCE_MAGIC: &[u8; 8] = b"AOSEEO01";
const LOST_EVIDENCE_MAGIC: &[u8; 8] = b"AOSEL001";
const QUARANTINE_EVIDENCE_MAGIC: &[u8; 8] = b"AOSEQ001";
const EVIDENCE_BYTES: usize = 298;

/// Owns a completion derived from an exact backend observation.
///
/// Its fields are private so callers cannot substitute arbitrary result bytes
/// at the protected journal completion boundary.
pub struct JournalExecutionCompletionV1 {
    completion: EffectCompletionV1,
}

impl JournalExecutionCompletionV1 {
    /// Borrows the exact portable completion for an atomic journal commit.
    #[must_use]
    pub const fn completion(&self) -> &EffectCompletionV1 {
        &self.completion
    }
}

/// Derives operation-specific completion bytes from backend evidence.
///
/// # Errors
///
/// Returns [`RuntimeExecutionEvidenceError`] when the observation targets
/// another execution, specification, runtime handle, payload boot, or an
/// execution phase that cannot complete this operation.
pub fn completion_from_backend_observation_v1(
    effect: &DurableExecutionEffectV1,
    observation: BackendExecutionInspectionV1,
) -> Result<JournalExecutionCompletionV1, RuntimeExecutionEvidenceError> {
    validate_observation(effect, &observation)?;
    let status = completion_status(effect.issue().operation(), observation.phase())?;
    let bytes = encode_observation(effect.issue().operation(), &observation);
    let completion = EffectCompletionV1::new(status, observation.sequence(), bytes)?;
    Ok(JournalExecutionCompletionV1 { completion })
}

/// Reads the observed phase from a Host-authenticated Cancel completion.
///
/// The caller must first authenticate the Host outcome and its result digest.
/// This check then binds the fixed evidence to the exact controller operation,
/// source request, execution, and observation sequence. It does not replace
/// the Host's full protected admission and guest-signature verification.
///
/// # Errors
///
/// Returns an error for a foreign, malformed, or non-Cancel observation.
pub fn decode_cancel_completion_phase_v1(
    bytes: &[u8],
    operation_id: [u8; 16],
    source_commitment: [u8; 32],
    execution_id: [u8; 16],
    observation_sequence: u64,
) -> Result<BackendExecutionPhaseV1, RuntimeExecutionEvidenceError> {
    if bytes.len() != EVIDENCE_BYTES
        || bytes.get(..8) != Some(EVIDENCE_MAGIC.as_slice())
        || bytes.get(266..298) != Some(evidence_digest(&bytes[..266]).as_bytes().as_slice())
    {
        return Err(RuntimeExecutionEvidenceError::MalformedEvidence);
    }
    if bytes[8] != EffectOperationV1::Cancel.code()
        || bytes.get(9..25) != Some(operation_id.as_slice())
        || bytes.get(33..65) != Some(source_commitment.as_slice())
        || bytes.get(65..81) != Some(execution_id.as_slice())
        || observation_sequence == 0
        || bytes.get(226..234) != Some(observation_sequence.to_be_bytes().as_slice())
    {
        return Err(RuntimeExecutionEvidenceError::OperationMismatch);
    }
    let phase = decode_phase(bytes[225])?;
    if !matches!(
        phase,
        BackendExecutionPhaseV1::Canceled | BackendExecutionPhaseV1::Exited
    ) {
        return Err(RuntimeExecutionEvidenceError::PhaseMismatch);
    }
    Ok(phase)
}

pub(crate) fn completion_from_authenticated_absence_v1(
    effect: &DurableExecutionEffectV1,
    inventory: &BackendExecutionInventoryV1,
) -> Result<JournalExecutionCompletionV1, RuntimeExecutionEvidenceError> {
    completion_from_recovery_inventory(effect, inventory, LOST_EVIDENCE_MAGIC)
}

pub(crate) fn completion_from_authenticated_quarantine_v1(
    effect: &DurableExecutionEffectV1,
    inventory: &BackendExecutionInventoryV1,
) -> Result<JournalExecutionCompletionV1, RuntimeExecutionEvidenceError> {
    completion_from_recovery_inventory(effect, inventory, QUARANTINE_EVIDENCE_MAGIC)
}

pub(crate) fn validate_completion(
    effect: &DurableExecutionEffectV1,
    completion: &EffectCompletionV1,
) -> Result<(), RuntimeExecutionEvidenceError> {
    let bytes = completion.result_bytes();
    let magic = bytes.get(..8);
    let recognized_magic = magic == Some(EVIDENCE_MAGIC.as_slice())
        || magic == Some(LOST_EVIDENCE_MAGIC.as_slice())
        || magic == Some(QUARANTINE_EVIDENCE_MAGIC.as_slice());
    if bytes.len() != EVIDENCE_BYTES || !recognized_magic {
        return Err(RuntimeExecutionEvidenceError::MalformedEvidence);
    }
    if bytes[8] != effect.issue().operation().code() {
        return Err(RuntimeExecutionEvidenceError::OperationMismatch);
    }
    if bytes.get(9..25)
        != Some(
            effect
                .issue()
                .idempotency()
                .operation()
                .as_bytes()
                .as_slice(),
        )
        || bytes.get(25..33) != Some(effect.issue().sequence().get().to_be_bytes().as_slice())
        || bytes.get(33..65)
            != Some(
                effect
                    .issue()
                    .idempotency()
                    .request_digest()
                    .as_bytes()
                    .as_slice(),
            )
        || bytes.get(65..81) != Some(effect.admission().execution().as_bytes().as_slice())
        || bytes.get(81..113)
            != Some(
                effect
                    .admission()
                    .specification_digest()
                    .as_bytes()
                    .as_slice(),
            )
        || bytes.get(113..145)
            != Some(
                effect
                    .admission()
                    .admission_commitment()
                    .as_bytes()
                    .as_slice(),
            )
        || bytes.get(145..177)
            != Some(
                effect
                    .admission()
                    .currentness()
                    .runtime()
                    .plan_commitment()
                    .as_bytes()
                    .as_slice(),
            )
        || bytes.get(177..209)
            != Some(
                effect
                    .admission()
                    .currentness()
                    .runtime()
                    .handle()
                    .as_bytes()
                    .as_slice(),
            )
        || bytes.get(209..225)
            != Some(
                effect
                    .admission()
                    .currentness()
                    .payload_boot_id()
                    .as_bytes()
                    .as_slice(),
            )
    {
        return Err(RuntimeExecutionEvidenceError::BindingMismatch);
    }
    let phase = decode_phase(bytes[225])?;
    let status = completion_status(effect.issue().operation(), phase)?;
    if magic != Some(EVIDENCE_MAGIC.as_slice())
        && (phase != BackendExecutionPhaseV1::Lost
            || status != EffectCompletionStatusV1::FailedPermanent)
    {
        return Err(RuntimeExecutionEvidenceError::MalformedEvidence);
    }
    let evidence_digest = evidence_digest(&bytes[..266]);
    if completion.status() != status
        || bytes.get(226..234)
            != Some(
                completion
                    .observation_sequence()
                    .get()
                    .to_be_bytes()
                    .as_slice(),
            )
        || bytes.get(266..298) != Some(evidence_digest.as_bytes().as_slice())
    {
        return Err(RuntimeExecutionEvidenceError::MalformedEvidence);
    }
    Ok(())
}

pub(crate) fn completion_observes_terminal_execution(
    effect: &DurableExecutionEffectV1,
    completion: &EffectCompletionV1,
) -> Result<bool, RuntimeExecutionEvidenceError> {
    validate_completion(effect, completion)?;
    let phase = completion
        .result_bytes()
        .get(225)
        .copied()
        .ok_or(RuntimeExecutionEvidenceError::MalformedEvidence)
        .and_then(decode_phase)?;
    Ok(matches!(
        phase,
        BackendExecutionPhaseV1::Exited
            | BackendExecutionPhaseV1::Canceled
            | BackendExecutionPhaseV1::Failed
            | BackendExecutionPhaseV1::Lost
    ))
}

fn validate_observation(
    effect: &DurableExecutionEffectV1,
    observation: &BackendExecutionInspectionV1,
) -> Result<(), RuntimeExecutionEvidenceError> {
    let currentness = effect.admission().currentness();
    if observation.authority_binding() != currentness.authority_context()
        || observation.execution() != effect.admission().execution()
        || observation.operation() != effect.issue().idempotency().operation()
        || observation.operation_sequence() != effect.issue().sequence()
        || observation.effect_request_digest() != effect.issue().idempotency().request_digest()
        || observation.specification_digest() != effect.admission().specification_digest()
        || observation.admission_commitment() != effect.admission().admission_commitment()
        || observation.runtime() != currentness.runtime()
        || observation.payload_boot_id() != currentness.payload_boot_id()
    {
        return Err(RuntimeExecutionEvidenceError::BindingMismatch);
    }
    completion_status(effect.issue().operation(), observation.phase())?;
    Ok(())
}

fn encode_observation(
    operation: EffectOperationV1,
    observation: &BackendExecutionInspectionV1,
) -> Vec<u8> {
    let mut bytes = Vec::with_capacity(EVIDENCE_BYTES);
    bytes.extend_from_slice(EVIDENCE_MAGIC);
    bytes.push(operation.code());
    bytes.extend_from_slice(observation.operation().as_bytes());
    bytes.extend_from_slice(&observation.operation_sequence().get().to_be_bytes());
    bytes.extend_from_slice(observation.effect_request_digest().as_bytes());
    bytes.extend_from_slice(observation.execution().as_bytes());
    bytes.extend_from_slice(observation.specification_digest().as_bytes());
    bytes.extend_from_slice(observation.admission_commitment().as_bytes());
    bytes.extend_from_slice(observation.runtime().plan_commitment().as_bytes());
    bytes.extend_from_slice(observation.runtime().handle().as_bytes());
    bytes.extend_from_slice(observation.payload_boot_id().as_bytes());
    bytes.push(phase_code(observation.phase()));
    bytes.extend_from_slice(&observation.sequence().get().to_be_bytes());
    bytes.extend_from_slice(observation.observation_commitment().as_bytes());
    let evidence_digest = evidence_digest(&bytes);
    bytes.extend_from_slice(evidence_digest.as_bytes());
    bytes
}

fn completion_from_recovery_inventory(
    effect: &DurableExecutionEffectV1,
    inventory: &BackendExecutionInventoryV1,
    evidence_magic: &[u8; 8],
) -> Result<JournalExecutionCompletionV1, RuntimeExecutionEvidenceError> {
    if effect.admission().currentness().authority_context() != inventory.authority_binding()
        || effect.admission().currentness().runtime() != inventory.runtime()
        || effect.admission().currentness().payload_boot_id() != inventory.payload_boot_id()
    {
        return Err(RuntimeExecutionEvidenceError::BindingMismatch);
    }
    let observation_commitment =
        recovery_observation_commitment(effect, inventory, evidence_magic.as_slice());
    let bytes = encode_bound_evidence(
        effect,
        evidence_magic,
        BackendExecutionPhaseV1::Lost,
        inventory.sequence_floor(),
        observation_commitment,
    );
    let completion = EffectCompletionV1::new(
        EffectCompletionStatusV1::FailedPermanent,
        inventory.sequence_floor(),
        bytes,
    )?;
    Ok(JournalExecutionCompletionV1 { completion })
}

fn encode_bound_evidence(
    effect: &DurableExecutionEffectV1,
    evidence_magic: &[u8; 8],
    phase: BackendExecutionPhaseV1,
    sequence: aos_sandbox_core::ObservationSequence,
    observation_commitment: ObjectDigest,
) -> Vec<u8> {
    let currentness = effect.admission().currentness();
    let mut bytes = Vec::with_capacity(EVIDENCE_BYTES);
    bytes.extend_from_slice(evidence_magic);
    bytes.push(effect.issue().operation().code());
    bytes.extend_from_slice(effect.issue().idempotency().operation().as_bytes());
    bytes.extend_from_slice(&effect.issue().sequence().get().to_be_bytes());
    bytes.extend_from_slice(effect.issue().idempotency().request_digest().as_bytes());
    bytes.extend_from_slice(effect.admission().execution().as_bytes());
    bytes.extend_from_slice(effect.admission().specification_digest().as_bytes());
    bytes.extend_from_slice(effect.admission().admission_commitment().as_bytes());
    bytes.extend_from_slice(currentness.runtime().plan_commitment().as_bytes());
    bytes.extend_from_slice(currentness.runtime().handle().as_bytes());
    bytes.extend_from_slice(currentness.payload_boot_id().as_bytes());
    bytes.push(phase_code(phase));
    bytes.extend_from_slice(&sequence.get().to_be_bytes());
    bytes.extend_from_slice(observation_commitment.as_bytes());
    let digest = evidence_digest(&bytes);
    bytes.extend_from_slice(digest.as_bytes());
    bytes
}

fn recovery_observation_commitment(
    effect: &DurableExecutionEffectV1,
    inventory: &BackendExecutionInventoryV1,
    disposition: &[u8],
) -> ObjectDigest {
    let mut digest = Sha256::new();
    digest.update(b"aos-sandbox-runtime-execution-recovery-observation-v1\0");
    digest.update(effect.record_commitment().as_bytes());
    digest.update(inventory.authority_binding().as_bytes());
    digest.update(inventory.inventory_commitment().as_bytes());
    digest.update(inventory.provenance_commitment().as_bytes());
    digest.update(inventory.inventory_generation().to_be_bytes());
    digest.update(inventory.sequence_floor().get().to_be_bytes());
    digest.update((disposition.len() as u64).to_be_bytes());
    digest.update(disposition);
    ObjectDigest::from_bytes(digest.finalize().into())
}

fn evidence_digest(bytes: &[u8]) -> ObjectDigest {
    let mut digest = Sha256::new();
    digest.update(b"aos-sandbox-runtime-execution-evidence-v1\0");
    digest.update((bytes.len() as u64).to_be_bytes());
    digest.update(bytes);
    ObjectDigest::from_bytes(digest.finalize().into())
}

fn completion_status(
    operation: EffectOperationV1,
    phase: BackendExecutionPhaseV1,
) -> Result<EffectCompletionStatusV1, RuntimeExecutionEvidenceError> {
    let allowed = match operation {
        EffectOperationV1::AuthorizeExecution => matches!(
            phase,
            BackendExecutionPhaseV1::Authorized
                | BackendExecutionPhaseV1::Starting
                | BackendExecutionPhaseV1::Running
                | BackendExecutionPhaseV1::Exited
                | BackendExecutionPhaseV1::Canceled
                | BackendExecutionPhaseV1::Failed
                | BackendExecutionPhaseV1::Lost
        ),
        EffectOperationV1::ResizeTerminal { .. } | EffectOperationV1::Signal { .. } => matches!(
            phase,
            BackendExecutionPhaseV1::Running
                | BackendExecutionPhaseV1::Exited
                | BackendExecutionPhaseV1::Canceled
                | BackendExecutionPhaseV1::Failed
                | BackendExecutionPhaseV1::Lost
        ),
        EffectOperationV1::Cancel => matches!(
            phase,
            BackendExecutionPhaseV1::Exited
                | BackendExecutionPhaseV1::Canceled
                | BackendExecutionPhaseV1::Failed
                | BackendExecutionPhaseV1::Lost
        ),
        EffectOperationV1::Observe => true,
    };
    if !allowed {
        return Err(RuntimeExecutionEvidenceError::PhaseMismatch);
    }
    Ok(match phase {
        BackendExecutionPhaseV1::Failed | BackendExecutionPhaseV1::Lost => {
            EffectCompletionStatusV1::FailedPermanent
        }
        BackendExecutionPhaseV1::Authorized
        | BackendExecutionPhaseV1::Starting
        | BackendExecutionPhaseV1::Running
        | BackendExecutionPhaseV1::Exited
        | BackendExecutionPhaseV1::Canceled => EffectCompletionStatusV1::Succeeded,
    })
}

const fn phase_code(phase: BackendExecutionPhaseV1) -> u8 {
    match phase {
        BackendExecutionPhaseV1::Authorized => 1,
        BackendExecutionPhaseV1::Starting => 2,
        BackendExecutionPhaseV1::Running => 3,
        BackendExecutionPhaseV1::Exited => 4,
        BackendExecutionPhaseV1::Canceled => 5,
        BackendExecutionPhaseV1::Failed => 6,
        BackendExecutionPhaseV1::Lost => 7,
    }
}

fn decode_phase(code: u8) -> Result<BackendExecutionPhaseV1, RuntimeExecutionEvidenceError> {
    match code {
        1 => Ok(BackendExecutionPhaseV1::Authorized),
        2 => Ok(BackendExecutionPhaseV1::Starting),
        3 => Ok(BackendExecutionPhaseV1::Running),
        4 => Ok(BackendExecutionPhaseV1::Exited),
        5 => Ok(BackendExecutionPhaseV1::Canceled),
        6 => Ok(BackendExecutionPhaseV1::Failed),
        7 => Ok(BackendExecutionPhaseV1::Lost),
        _ => Err(RuntimeExecutionEvidenceError::MalformedEvidence),
    }
}

/// Reports rejected or malformed operation-specific completion evidence.
#[derive(Clone, Copy, Debug, Eq, PartialEq, thiserror::Error)]
pub enum RuntimeExecutionEvidenceError {
    /// Execution, specification, runtime handle, or payload boot differs.
    #[error("runtime execution evidence binding does not match")]
    BindingMismatch,
    /// The evidence operation differs from the durable effect operation.
    #[error("runtime execution evidence operation does not match")]
    OperationMismatch,
    /// The observation phase cannot complete the exact operation.
    #[error("runtime execution evidence phase does not match the operation")]
    PhaseMismatch,
    /// Fixed evidence bytes or their internal commitments are malformed.
    #[error("runtime execution evidence is malformed")]
    MalformedEvidence,
    /// Portable effect completion validation failed.
    #[error("runtime execution completion is invalid: {0}")]
    Completion(#[from] EffectCommitError),
}

#[cfg(test)]
mod tests {
    use aos_sandbox_core::runtime_backend::BackendExecutionPhaseV1;

    use super::{
        EVIDENCE_BYTES, EVIDENCE_MAGIC, RuntimeExecutionEvidenceError,
        decode_cancel_completion_phase_v1, evidence_digest,
    };

    #[test]
    fn cancel_completion_phase_requires_exact_bound_evidence() {
        let operation = [1; 16];
        let source = [2; 32];
        let execution = [3; 16];
        let sequence = 4_u64;
        let mut bytes = vec![0; EVIDENCE_BYTES];
        bytes[..8].copy_from_slice(EVIDENCE_MAGIC);
        bytes[8] = 4;
        bytes[9..25].copy_from_slice(&operation);
        bytes[33..65].copy_from_slice(&source);
        bytes[65..81].copy_from_slice(&execution);
        bytes[225] = 5;
        bytes[226..234].copy_from_slice(&sequence.to_be_bytes());
        let digest = evidence_digest(&bytes[..266]);
        bytes[266..298].copy_from_slice(digest.as_bytes());

        assert_eq!(
            decode_cancel_completion_phase_v1(&bytes, operation, source, execution, sequence),
            Ok(BackendExecutionPhaseV1::Canceled)
        );
        assert_eq!(
            decode_cancel_completion_phase_v1(&bytes, [9; 16], source, execution, sequence),
            Err(RuntimeExecutionEvidenceError::OperationMismatch)
        );
        bytes[225] = 3;
        let digest = evidence_digest(&bytes[..266]);
        bytes[266..298].copy_from_slice(digest.as_bytes());
        assert_eq!(
            decode_cancel_completion_phase_v1(&bytes, operation, source, execution, sequence),
            Err(RuntimeExecutionEvidenceError::PhaseMismatch)
        );
    }
}
