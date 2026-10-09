//! Durable execution-effect issuance, completion, and ambiguity handling.

use sha2::{Digest as _, Sha256};

use crate::{ObjectDigest, ObservationSequence};

use super::{
    AdmittedExecutionV1, BackendExecutionRequestV1, BackendOperationIdV1,
    BackendOperationSequenceV1,
};

const EFFECT_RECORD_DOMAIN: &[u8] = b"aos-sandbox-execution-effect-v1\0";
const MAX_EFFECT_RESULT_BYTES: usize = 15 * 1_048_576;

/// Names one closed execution-control effect.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum EffectOperationV1 {
    /// Hands the exact admitted command to the authenticated guest agent.
    AuthorizeExecution,
    /// Changes terminal geometry for an already running PTY execution.
    ResizeTerminal {
        /// Positive terminal row count.
        rows: u16,
        /// Positive terminal column count.
        columns: u16,
    },
    /// Delivers one portable closed signal code.
    Signal {
        /// Portable signal number in the closed range 1 through 64.
        signal_code: u8,
    },
    /// Cancels the exact execution if it is not already terminal.
    Cancel,
    /// Obtains a fresh authenticated execution observation without mutation.
    Observe,
}

impl EffectOperationV1 {
    /// Returns the closed portable operation code.
    #[must_use]
    pub const fn code(self) -> u8 {
        match self {
            Self::AuthorizeExecution => 1,
            Self::ResizeTerminal { .. } => 2,
            Self::Signal { .. } => 3,
            Self::Cancel => 4,
            Self::Observe => 5,
        }
    }

    /// Returns operation arguments in a fixed portable projection.
    #[must_use]
    pub const fn arguments(self) -> [u8; 4] {
        match self {
            Self::ResizeTerminal { rows, columns } => {
                let row_bytes = rows.to_be_bytes();
                let column_bytes = columns.to_be_bytes();
                [row_bytes[0], row_bytes[1], column_bytes[0], column_bytes[1]]
            }
            Self::Signal { signal_code } => [signal_code, 0, 0, 0],
            Self::AuthorizeExecution | Self::Cancel | Self::Observe => [0; 4],
        }
    }
}

/// Binds effect replay to an exact operation identity and request digest.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct EffectIdempotencyV1 {
    operation: BackendOperationIdV1,
    request_digest: ObjectDigest,
}

impl EffectIdempotencyV1 {
    /// Constructs a non-sentinel effect replay binding.
    ///
    /// # Errors
    ///
    /// Returns [`EffectCommitError::InvalidEffect`] for a zero request digest.
    pub fn new(
        operation: BackendOperationIdV1,
        request_digest: ObjectDigest,
    ) -> Result<Self, EffectCommitError> {
        if request_digest.as_bytes() == &[0; 32] {
            return Err(EffectCommitError::InvalidEffect);
        }
        Ok(Self {
            operation,
            request_digest,
        })
    }

    /// Returns the durable operation identity.
    #[must_use]
    pub const fn operation(&self) -> BackendOperationIdV1 {
        self.operation
    }

    /// Returns the normalized effect-request digest.
    #[must_use]
    pub const fn request_digest(&self) -> ObjectDigest {
        self.request_digest
    }
}

/// Stores immutable inputs to one execution effect.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct EffectIssueV1 {
    operation: EffectOperationV1,
    sequence: BackendOperationSequenceV1,
    idempotency: EffectIdempotencyV1,
}

impl EffectIssueV1 {
    /// Constructs one exact proposed effect.
    ///
    /// # Errors
    ///
    /// Returns [`EffectCommitError::InvalidEffect`] for zero terminal geometry
    /// or for a signal outside the portable `1..=64` closed range.
    pub fn new(
        operation: EffectOperationV1,
        sequence: BackendOperationSequenceV1,
        idempotency: EffectIdempotencyV1,
    ) -> Result<Self, EffectCommitError> {
        match operation {
            EffectOperationV1::ResizeTerminal { rows: 0, .. }
            | EffectOperationV1::ResizeTerminal { columns: 0, .. }
            | EffectOperationV1::Signal {
                signal_code: 0 | 65..=u8::MAX,
            } => {
                return Err(EffectCommitError::InvalidEffect);
            }
            _ => {}
        }
        if sequence.get() == 0 {
            return Err(EffectCommitError::InvalidEffect);
        }
        Ok(Self {
            operation,
            sequence,
            idempotency,
        })
    }

    /// Returns the closed execution operation.
    #[must_use]
    pub const fn operation(&self) -> EffectOperationV1 {
        self.operation
    }

    /// Returns the exact per-runtime operation sequence.
    #[must_use]
    pub const fn sequence(&self) -> BackendOperationSequenceV1 {
        self.sequence
    }

    /// Returns the exact effect replay binding.
    #[must_use]
    pub const fn idempotency(&self) -> EffectIdempotencyV1 {
        self.idempotency
    }
}

/// Defines durable effect progress across crashes.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum EffectPhaseV1 {
    /// Exact effect intent is durable but backend issuance is not reserved.
    Pending,
    /// Issuance is durably reserved; backend status may require inspection.
    Issued,
    /// An effect boundary returned without a provable result.
    Indeterminate,
    /// The exact backend outcome is durably committed.
    Complete,
}

/// Classifies the exact terminal outcome committed for an effect.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum EffectCompletionStatusV1 {
    /// The requested semantic effect and its postconditions completed.
    Succeeded,
    /// No effect began and the exact request was rejected.
    RejectedBeforeEffect,
    /// The effect failed permanently and must not be retried.
    FailedPermanent,
}

/// Carries bounded canonical result bytes and their exact observation binding.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct EffectCompletionV1 {
    status: EffectCompletionStatusV1,
    observation_sequence: ObservationSequence,
    result_bytes: Vec<u8>,
    result_digest: ObjectDigest,
}

impl EffectCompletionV1 {
    /// Constructs one exact bounded effect result.
    ///
    /// # Errors
    ///
    /// Returns [`EffectCommitError::InvalidCompletion`] for a zero sequence,
    /// empty bytes, or bytes beyond the 15-MiB portable ceiling. The result
    /// digest is derived internally and cannot be substituted by the caller.
    pub fn new(
        status: EffectCompletionStatusV1,
        observation_sequence: ObservationSequence,
        result_bytes: Vec<u8>,
    ) -> Result<Self, EffectCommitError> {
        if observation_sequence.get() == 0
            || result_bytes.is_empty()
            || result_bytes.len() > MAX_EFFECT_RESULT_BYTES
        {
            return Err(EffectCommitError::InvalidCompletion);
        }
        let result_digest = effect_result_digest(&result_bytes);
        Ok(Self {
            status,
            observation_sequence,
            result_bytes,
            result_digest,
        })
    }

    /// Returns the closed terminal status.
    #[must_use]
    pub const fn status(&self) -> EffectCompletionStatusV1 {
        self.status
    }

    /// Returns the backend/agent observation sequence.
    #[must_use]
    pub const fn observation_sequence(&self) -> ObservationSequence {
        self.observation_sequence
    }

    /// Returns exact canonical result bytes.
    #[must_use]
    pub fn result_bytes(&self) -> &[u8] {
        &self.result_bytes
    }

    /// Returns the exact result-byte digest.
    #[must_use]
    pub const fn result_digest(&self) -> ObjectDigest {
        self.result_digest
    }
}

/// Stores one execution effect at its exact durable lifecycle phase.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct DurableExecutionEffectV1 {
    admission: AdmittedExecutionV1,
    issue: EffectIssueV1,
    phase: EffectPhaseV1,
    completion: Option<EffectCompletionV1>,
    record_commitment: ObjectDigest,
    journal_sequence: u64,
    transaction_commitment: ObjectDigest,
}

impl DurableExecutionEffectV1 {
    /// Reconstructs a Pending value from an exact protected-store receipt.
    ///
    /// This grants no dispatch authority; the journal owner must separately
    /// mint a consuming dispatch permit after the Issued transition commits.
    ///
    /// # Errors
    ///
    /// Returns [`EffectCommitError::ReceiptMismatch`] when the receipt does not
    /// commit the exact Pending record.
    pub fn pending_from_store(
        admission: AdmittedExecutionV1,
        issue: EffectIssueV1,
        commit: EffectStoreCommitV1,
    ) -> Result<Self, EffectCommitError> {
        let expected = effect_commitment(&admission, issue, EffectPhaseV1::Pending, None);
        verify_commit(&commit, expected)?;
        Ok(Self::pending(admission, issue, commit))
    }

    /// Reconstructs a successor phase from an exact protected-store receipt.
    ///
    /// # Errors
    ///
    /// Returns [`EffectCommitError`] for an invalid phase edge, completion
    /// shape, or receipt that does not commit the exact successor bytes.
    pub fn transitioned_from_store(
        &self,
        phase: EffectPhaseV1,
        completion: Option<EffectCompletionV1>,
        commit: EffectStoreCommitV1,
    ) -> Result<Self, EffectCommitError> {
        let edge_is_valid = matches!(
            (self.phase, phase),
            (EffectPhaseV1::Pending, EffectPhaseV1::Issued)
                | (EffectPhaseV1::Issued, EffectPhaseV1::Indeterminate)
                | (EffectPhaseV1::Issued, EffectPhaseV1::Complete)
                | (EffectPhaseV1::Indeterminate, EffectPhaseV1::Complete)
        );
        if !edge_is_valid || (phase == EffectPhaseV1::Complete) != completion.is_some() {
            return Err(EffectCommitError::WrongPhase);
        }
        let expected = effect_commitment(&self.admission, self.issue, phase, completion.as_ref());
        verify_commit(&commit, expected)?;
        Ok(self.transitioned(phase, completion, commit))
    }

    /// Returns the exact immutable admission.
    #[must_use]
    pub const fn admission(&self) -> &AdmittedExecutionV1 {
        &self.admission
    }

    /// Returns the immutable effect issue.
    #[must_use]
    pub const fn issue(&self) -> &EffectIssueV1 {
        &self.issue
    }

    /// Returns current durable effect progress.
    #[must_use]
    pub const fn phase(&self) -> EffectPhaseV1 {
        self.phase
    }

    /// Returns the terminal completion only in `Complete` phase.
    #[must_use]
    pub const fn completion(&self) -> Option<&EffectCompletionV1> {
        self.completion.as_ref()
    }

    /// Returns the phase-specific complete record commitment.
    #[must_use]
    pub const fn record_commitment(&self) -> ObjectDigest {
        self.record_commitment
    }

    /// Returns the current journal sequence.
    #[must_use]
    pub const fn journal_sequence(&self) -> u64 {
        self.journal_sequence
    }

    /// Returns the complete transaction commitment.
    #[must_use]
    pub const fn transaction_commitment(&self) -> ObjectDigest {
        self.transaction_commitment
    }

    /// Projects an issued authorization into the backend handoff request.
    ///
    /// # Errors
    ///
    /// Returns [`EffectCommitError::WrongPhase`] unless the record is `Issued`,
    /// or [`EffectCommitError::WrongOperation`] for a non-authorize effect.
    pub fn backend_execution_request(
        &self,
    ) -> Result<BackendExecutionRequestV1, EffectCommitError> {
        if self.phase != EffectPhaseV1::Issued {
            return Err(EffectCommitError::WrongPhase);
        }
        if self.issue.operation() != EffectOperationV1::AuthorizeExecution {
            return Err(EffectCommitError::WrongOperation);
        }
        BackendExecutionRequestV1::new(
            self.issue.idempotency().operation(),
            self.issue.sequence(),
            self.admission.specification_bytes().to_vec(),
            self.admission.specification_digest(),
            self.admission.admission_commitment(),
            self.issue.idempotency().request_digest(),
        )
        .map_err(|_| EffectCommitError::InvalidEffect)
    }

    pub(super) fn pending(
        admission: AdmittedExecutionV1,
        issue: EffectIssueV1,
        commit: EffectStoreCommitV1,
    ) -> Self {
        let record_commitment = effect_commitment(&admission, issue, EffectPhaseV1::Pending, None);
        Self {
            admission,
            issue,
            phase: EffectPhaseV1::Pending,
            completion: None,
            record_commitment,
            journal_sequence: commit.journal_sequence(),
            transaction_commitment: commit.transaction_commitment(),
        }
    }

    pub(super) fn transitioned(
        &self,
        phase: EffectPhaseV1,
        completion: Option<EffectCompletionV1>,
        commit: EffectStoreCommitV1,
    ) -> Self {
        let record_commitment =
            effect_commitment(&self.admission, self.issue, phase, completion.as_ref());
        Self {
            admission: self.admission.clone(),
            issue: self.issue,
            phase,
            completion,
            record_commitment,
            journal_sequence: commit.journal_sequence(),
            transaction_commitment: commit.transaction_commitment(),
        }
    }

    pub(super) fn restore(
        admission: AdmittedExecutionV1,
        issue: EffectIssueV1,
        phase: EffectPhaseV1,
        completion: Option<EffectCompletionV1>,
        record_commitment: ObjectDigest,
        journal_sequence: u64,
        transaction_commitment: ObjectDigest,
    ) -> Result<Self, EffectCommitError> {
        if journal_sequence == 0 || transaction_commitment.as_bytes() == &[0; 32] {
            return Err(EffectCommitError::CorruptRecord);
        }
        if (phase == EffectPhaseV1::Complete) != completion.is_some() {
            return Err(EffectCommitError::CorruptRecord);
        }
        let expected = effect_commitment(&admission, issue, phase, completion.as_ref());
        if expected != record_commitment {
            return Err(EffectCommitError::CorruptRecord);
        }
        Ok(Self {
            admission,
            issue,
            phase,
            completion,
            record_commitment,
            journal_sequence,
            transaction_commitment,
        })
    }
}

/// Classifies whether a store transition was created or exactly replayed.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum EffectCommitDispositionV1 {
    /// The store created the requested transition.
    Created,
    /// The store returned its existing byte-identical transition.
    ExactReplay,
}

/// Reports a definitive effect-store commit or opaque recovery authority.
#[must_use]
pub enum EffectStoreTransitionV1<R> {
    /// The exact phase transition is durably committed.
    Committed(EffectStoreCommitV1),
    /// Commit durability is ambiguous and only the store can resolve it.
    RecoveryRequired(R),
    /// Authenticated reopen proves that the attempted transition did not commit.
    NotCommitted,
}

/// Reports a durable effect transition or its store-owned recovery token.
#[must_use]
pub enum ExecutionEffectTransitionV1<R> {
    /// The effect reached the requested durable phase.
    Committed(DurableExecutionEffectV1),
    /// The prior state remains authoritative until this token is resolved.
    RecoveryRequired(R),
    /// Protected reopen proved absence; the prior effect state remains current.
    NotCommitted,
}

/// Reports one completed atomic execution-effect store transition.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct EffectStoreCommitV1 {
    record_commitment: ObjectDigest,
    journal_sequence: u64,
    transaction_commitment: ObjectDigest,
    disposition: EffectCommitDispositionV1,
}

impl EffectStoreCommitV1 {
    /// Constructs a non-sentinel protected store receipt.
    ///
    /// # Errors
    ///
    /// Returns [`EffectCommitError::InvalidReceipt`] for zero fields.
    pub fn new(
        record_commitment: ObjectDigest,
        journal_sequence: u64,
        transaction_commitment: ObjectDigest,
        disposition: EffectCommitDispositionV1,
    ) -> Result<Self, EffectCommitError> {
        if record_commitment.as_bytes() == &[0; 32]
            || journal_sequence == 0
            || transaction_commitment.as_bytes() == &[0; 32]
        {
            return Err(EffectCommitError::InvalidReceipt);
        }
        Ok(Self {
            record_commitment,
            journal_sequence,
            transaction_commitment,
            disposition,
        })
    }

    /// Returns the committed record digest.
    #[must_use]
    pub const fn record_commitment(&self) -> ObjectDigest {
        self.record_commitment
    }

    /// Returns the resulting journal sequence.
    #[must_use]
    pub const fn journal_sequence(&self) -> u64 {
        self.journal_sequence
    }

    /// Returns the complete atomic transaction commitment.
    #[must_use]
    pub const fn transaction_commitment(&self) -> ObjectDigest {
        self.transaction_commitment
    }

    /// Returns whether this transition was newly created or exactly replayed.
    #[must_use]
    pub const fn disposition(&self) -> EffectCommitDispositionV1 {
        self.disposition
    }
}

/// Defines the atomic durable transitions surrounding backend effects.
pub trait ExecutionEffectStore {
    /// Opaque authority required to resolve an ambiguous effect-store commit.
    type RecoveryToken;

    /// Atomically creates or exactly replays a Pending effect record.
    ///
    /// # Errors
    ///
    /// Returns [`EffectCommitError`] for stale currentness, sequence or
    /// idempotency conflict, invalid input, or ambiguous durability.
    fn commit_pending_effect(
        &mut self,
        admission: &AdmittedExecutionV1,
        issue: &EffectIssueV1,
        expected_record: ObjectDigest,
    ) -> Result<EffectStoreTransitionV1<Self::RecoveryToken>, EffectCommitError>;
    /// Atomically reserves backend issuance before the effect boundary.
    ///
    /// # Errors
    ///
    /// Returns [`EffectCommitError`] unless the exact Pending record can be
    /// replaced durably by the supplied Issued commitment.
    fn commit_effect_issued(
        &mut self,
        effect: &DurableExecutionEffectV1,
        expected_record: ObjectDigest,
    ) -> Result<EffectStoreTransitionV1<Self::RecoveryToken>, EffectCommitError>;
    /// Atomically records ambiguity without permitting another issuance.
    ///
    /// # Errors
    ///
    /// Returns [`EffectCommitError`] unless the exact Issued record can be
    /// replaced durably by the supplied Indeterminate commitment.
    fn commit_effect_indeterminate(
        &mut self,
        effect: &DurableExecutionEffectV1,
        expected_record: ObjectDigest,
    ) -> Result<EffectStoreTransitionV1<Self::RecoveryToken>, EffectCommitError>;
    /// Atomically commits the exact terminal result and replay response.
    ///
    /// # Errors
    ///
    /// Returns [`EffectCommitError`] unless the exact Issued/Indeterminate
    /// record and result can be replaced atomically by Complete.
    fn commit_effect_complete(
        &mut self,
        effect: &DurableExecutionEffectV1,
        completion: &EffectCompletionV1,
        expected_record: ObjectDigest,
    ) -> Result<EffectStoreTransitionV1<Self::RecoveryToken>, EffectCommitError>;

    /// Resolves one ambiguous transition without issuing a new transaction.
    ///
    /// # Errors
    ///
    /// Returns [`EffectCommitError`] for a foreign token, expected-record
    /// mismatch, corrupt replay, or another ambiguous durable read.
    fn recover_effect_transition(
        &mut self,
        token: Self::RecoveryToken,
        expected_record: ObjectDigest,
    ) -> Result<EffectStoreTransitionV1<Self::RecoveryToken>, EffectCommitError>;
}

/// Durably prepares one effect without authorizing backend invocation.
///
/// # Errors
///
/// Returns [`EffectCommitError`] for stale authority, sequence conflict,
/// idempotency equivocation, store ambiguity, or a mismatched receipt.
pub fn prepare_effect<S: ExecutionEffectStore>(
    store: &mut S,
    admission: &AdmittedExecutionV1,
    issue: EffectIssueV1,
) -> Result<ExecutionEffectTransitionV1<S::RecoveryToken>, EffectCommitError> {
    let expected = effect_commitment(admission, issue, EffectPhaseV1::Pending, None);
    transition_pending(
        admission,
        issue,
        expected,
        store.commit_pending_effect(admission, &issue, expected)?,
    )
}

/// Durably reserves one exact backend issuance.
///
/// # Errors
///
/// Returns [`EffectCommitError::WrongPhase`] unless `effect` is Pending, or a
/// store/CAS error without exposing an issued token.
pub fn reserve_effect_issue<S: ExecutionEffectStore>(
    store: &mut S,
    effect: &DurableExecutionEffectV1,
) -> Result<ExecutionEffectTransitionV1<S::RecoveryToken>, EffectCommitError> {
    if effect.phase() != EffectPhaseV1::Pending {
        return Err(EffectCommitError::WrongPhase);
    }
    let expected = effect_commitment(
        effect.admission(),
        *effect.issue(),
        EffectPhaseV1::Issued,
        None,
    );
    transition_existing(
        effect,
        EffectPhaseV1::Issued,
        None,
        expected,
        store.commit_effect_issued(effect, expected)?,
    )
}

/// Persists ambiguity after an issued effect loses its exact outcome.
///
/// # Errors
///
/// Returns [`EffectCommitError::WrongPhase`] unless the effect is Issued, or a
/// store/CAS failure. The old Issued record must remain recoverable on error.
pub fn mark_effect_indeterminate<S: ExecutionEffectStore>(
    store: &mut S,
    effect: &DurableExecutionEffectV1,
) -> Result<ExecutionEffectTransitionV1<S::RecoveryToken>, EffectCommitError> {
    if effect.phase() != EffectPhaseV1::Issued {
        return Err(EffectCommitError::WrongPhase);
    }
    let expected = effect_commitment(
        effect.admission(),
        *effect.issue(),
        EffectPhaseV1::Indeterminate,
        None,
    );
    transition_existing(
        effect,
        EffectPhaseV1::Indeterminate,
        None,
        expected,
        store.commit_effect_indeterminate(effect, expected)?,
    )
}

/// Commits one exact effect result after live execution or recovery.
///
/// # Errors
///
/// Returns [`EffectCommitError::WrongPhase`] for Pending/Complete input or a
/// store/CAS failure. Ambiguous commit requires exclusive reopen recovery.
pub fn complete_effect<S: ExecutionEffectStore>(
    store: &mut S,
    effect: &DurableExecutionEffectV1,
    completion: &EffectCompletionV1,
) -> Result<ExecutionEffectTransitionV1<S::RecoveryToken>, EffectCommitError> {
    if !matches!(
        effect.phase(),
        EffectPhaseV1::Issued | EffectPhaseV1::Indeterminate
    ) {
        return Err(EffectCommitError::WrongPhase);
    }
    let expected = effect_commitment(
        effect.admission(),
        *effect.issue(),
        EffectPhaseV1::Complete,
        Some(&completion),
    );
    transition_existing(
        effect,
        EffectPhaseV1::Complete,
        Some(completion.clone()),
        expected,
        store.commit_effect_complete(effect, completion, expected)?,
    )
}

/// Resolves an ambiguous Pending creation without creating a new transaction.
///
/// # Errors
///
/// Returns [`EffectCommitError`] for a foreign token, corrupt replay, another
/// ambiguous reopen, or a receipt that does not match the exact Pending bytes.
pub fn recover_pending_effect<S: ExecutionEffectStore>(
    store: &mut S,
    admission: &AdmittedExecutionV1,
    issue: EffectIssueV1,
    token: S::RecoveryToken,
) -> Result<ExecutionEffectTransitionV1<S::RecoveryToken>, EffectCommitError> {
    let expected = effect_commitment(admission, issue, EffectPhaseV1::Pending, None);
    let recovered = store.recover_effect_transition(token, expected)?;
    transition_pending(admission, issue, expected, recovered)
}

/// Resolves an ambiguous Issued transition without reserving issuance again.
///
/// # Errors
///
/// Returns [`EffectCommitError`] for wrong prior phase, token mismatch,
/// corruption, another ambiguous reopen, or a mismatched receipt.
pub fn recover_effect_issue<S: ExecutionEffectStore>(
    store: &mut S,
    effect: &DurableExecutionEffectV1,
    token: S::RecoveryToken,
) -> Result<ExecutionEffectTransitionV1<S::RecoveryToken>, EffectCommitError> {
    if effect.phase() != EffectPhaseV1::Pending {
        return Err(EffectCommitError::WrongPhase);
    }
    recover_existing_transition(store, effect, EffectPhaseV1::Issued, None, token)
}

/// Resolves an ambiguous Indeterminate transition without touching the backend.
///
/// # Errors
///
/// Returns [`EffectCommitError`] for wrong prior phase, token mismatch,
/// corruption, another ambiguous reopen, or a mismatched receipt.
pub fn recover_effect_indeterminate<S: ExecutionEffectStore>(
    store: &mut S,
    effect: &DurableExecutionEffectV1,
    token: S::RecoveryToken,
) -> Result<ExecutionEffectTransitionV1<S::RecoveryToken>, EffectCommitError> {
    if effect.phase() != EffectPhaseV1::Issued {
        return Err(EffectCommitError::WrongPhase);
    }
    recover_existing_transition(store, effect, EffectPhaseV1::Indeterminate, None, token)
}

/// Resolves an ambiguous Complete transition from exact retained evidence.
///
/// # Errors
///
/// Returns [`EffectCommitError`] for wrong prior phase, token mismatch,
/// corruption, another ambiguous reopen, or a mismatched completion receipt.
pub fn recover_effect_completion<S: ExecutionEffectStore>(
    store: &mut S,
    effect: &DurableExecutionEffectV1,
    completion: &EffectCompletionV1,
    token: S::RecoveryToken,
) -> Result<ExecutionEffectTransitionV1<S::RecoveryToken>, EffectCommitError> {
    if !matches!(
        effect.phase(),
        EffectPhaseV1::Issued | EffectPhaseV1::Indeterminate
    ) {
        return Err(EffectCommitError::WrongPhase);
    }
    recover_existing_transition(
        store,
        effect,
        EffectPhaseV1::Complete,
        Some(completion.clone()),
        token,
    )
}

fn recover_existing_transition<S: ExecutionEffectStore>(
    store: &mut S,
    effect: &DurableExecutionEffectV1,
    phase: EffectPhaseV1,
    completion: Option<EffectCompletionV1>,
    token: S::RecoveryToken,
) -> Result<ExecutionEffectTransitionV1<S::RecoveryToken>, EffectCommitError> {
    let expected = effect_commitment(
        effect.admission(),
        *effect.issue(),
        phase,
        completion.as_ref(),
    );
    let recovered = store.recover_effect_transition(token, expected)?;
    transition_existing(effect, phase, completion, expected, recovered)
}

fn transition_pending<R>(
    admission: &AdmittedExecutionV1,
    issue: EffectIssueV1,
    expected: ObjectDigest,
    transition: EffectStoreTransitionV1<R>,
) -> Result<ExecutionEffectTransitionV1<R>, EffectCommitError> {
    match transition {
        EffectStoreTransitionV1::Committed(commit) => {
            verify_commit(&commit, expected)?;
            Ok(ExecutionEffectTransitionV1::Committed(
                DurableExecutionEffectV1::pending(admission.clone(), issue, commit),
            ))
        }
        EffectStoreTransitionV1::RecoveryRequired(token) => {
            Ok(ExecutionEffectTransitionV1::RecoveryRequired(token))
        }
        EffectStoreTransitionV1::NotCommitted => Ok(ExecutionEffectTransitionV1::NotCommitted),
    }
}

fn transition_existing<R>(
    effect: &DurableExecutionEffectV1,
    phase: EffectPhaseV1,
    completion: Option<EffectCompletionV1>,
    expected: ObjectDigest,
    transition: EffectStoreTransitionV1<R>,
) -> Result<ExecutionEffectTransitionV1<R>, EffectCommitError> {
    match transition {
        EffectStoreTransitionV1::Committed(commit) => {
            verify_commit(&commit, expected)?;
            Ok(ExecutionEffectTransitionV1::Committed(
                effect.transitioned(phase, completion, commit),
            ))
        }
        EffectStoreTransitionV1::RecoveryRequired(token) => {
            Ok(ExecutionEffectTransitionV1::RecoveryRequired(token))
        }
        EffectStoreTransitionV1::NotCommitted => Ok(ExecutionEffectTransitionV1::NotCommitted),
    }
}

/// Reports failure at an execution-effect durable boundary.
#[derive(Clone, Copy, Debug, Eq, PartialEq, thiserror::Error)]
pub enum EffectCommitError {
    /// Effect arguments, sequence, or digest are malformed.
    #[error("execution effect is invalid")]
    InvalidEffect,
    /// Completion bytes, sequence, or digest are malformed.
    #[error("execution effect completion is invalid")]
    InvalidCompletion,
    /// The requested transition is not valid from the durable phase.
    #[error("execution effect is in the wrong durable phase")]
    WrongPhase,
    /// The operation cannot be projected into the requested adapter call.
    #[error("execution effect operation is incompatible with this adapter")]
    WrongOperation,
    /// The operation sequence is stale, has a gap, or is exhausted.
    #[error("execution effect operation sequence conflicts")]
    SequenceConflict,
    /// The operation identity already binds different request bytes.
    #[error("execution effect idempotency key equivocated")]
    IdempotencyConflict,
    /// Assignment, admission, or session currentness changed before commit.
    #[error("execution effect authority is stale")]
    StaleAuthority,
    /// A protected store returned an invalid receipt.
    #[error("execution effect store receipt is invalid")]
    InvalidReceipt,
    /// A store receipt does not commit the exact proposed record.
    #[error("execution effect store receipt does not match")]
    ReceiptMismatch,
    /// A durable record could not decode under exact bounds and version.
    #[error("execution effect durable record is corrupt")]
    CorruptRecord,
}

fn verify_commit(
    commit: &EffectStoreCommitV1,
    expected: ObjectDigest,
) -> Result<(), EffectCommitError> {
    if commit.record_commitment() != expected {
        Err(EffectCommitError::ReceiptMismatch)
    } else {
        Ok(())
    }
}

fn effect_commitment(
    admission: &AdmittedExecutionV1,
    issue: EffectIssueV1,
    phase: EffectPhaseV1,
    completion: Option<&EffectCompletionV1>,
) -> ObjectDigest {
    let mut digest = Sha256::new();
    digest.update(EFFECT_RECORD_DOMAIN);
    digest.update(admission.execution().as_bytes());
    digest.update(admission.specification_digest().as_bytes());
    digest.update(admission.admission_commitment().as_bytes());
    digest.update([issue.operation().code()]);
    digest.update(issue.operation().arguments());
    digest.update(issue.sequence().get().to_be_bytes());
    digest.update(issue.idempotency().operation().as_bytes());
    digest.update(issue.idempotency().request_digest().as_bytes());
    digest.update([match phase {
        EffectPhaseV1::Pending => 1,
        EffectPhaseV1::Issued => 2,
        EffectPhaseV1::Indeterminate => 3,
        EffectPhaseV1::Complete => 4,
    }]);
    match completion {
        Some(value) => {
            digest.update([1]);
            digest.update([match value.status() {
                EffectCompletionStatusV1::Succeeded => 1,
                EffectCompletionStatusV1::RejectedBeforeEffect => 2,
                EffectCompletionStatusV1::FailedPermanent => 3,
            }]);
            digest.update(value.observation_sequence().get().to_be_bytes());
            digest.update((value.result_bytes().len() as u64).to_be_bytes());
            digest.update(value.result_bytes());
            digest.update(value.result_digest().as_bytes());
        }
        None => digest.update([0]),
    }
    ObjectDigest::from_bytes(digest.finalize().into())
}

fn effect_result_digest(bytes: &[u8]) -> ObjectDigest {
    let mut digest = Sha256::new();
    digest.update(b"aos-sandbox-execution-effect-result-v1\0");
    digest.update((bytes.len() as u64).to_be_bytes());
    digest.update(bytes);
    ObjectDigest::from_bytes(digest.finalize().into())
}
