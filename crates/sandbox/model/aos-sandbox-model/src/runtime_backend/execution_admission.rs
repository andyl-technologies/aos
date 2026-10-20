//! Durable execution admission ownership and exact replay binding.

use sha2::{Digest as _, Sha256};

use crate::{ExecutionId, ObjectDigest, PayloadBootId};

use super::model::RuntimeModelError;
use super::{BackendOperationIdV1, BackendProbeCurrentnessV1, RuntimeHandleCommitmentV1};

const ADMISSION_RECORD_DOMAIN: &[u8] = b"aos-sandbox-execution-admission-v1\0";
// Leaves room for the fixed durable envelope under the default 16-MiB
// protected-journal record ceiling.
const MAX_EXECUTION_SPECIFICATION_BYTES: usize = 15 * 1_048_576;

/// Binds accepted request replay to an exact operation and normalized request.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct AdmissionIdempotencyV1 {
    operation: BackendOperationIdV1,
    request_digest: ObjectDigest,
}

impl AdmissionIdempotencyV1 {
    /// Constructs a non-sentinel idempotency binding.
    ///
    /// # Errors
    ///
    /// Returns [`AdmissionCommitError::InvalidDraft`] for a zero digest.
    pub fn new(
        operation: BackendOperationIdV1,
        request_digest: ObjectDigest,
    ) -> Result<Self, AdmissionCommitError> {
        if request_digest.as_bytes() == &[0; 32] {
            return Err(AdmissionCommitError::InvalidDraft);
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

    /// Returns the normalized public-request commitment.
    #[must_use]
    pub const fn request_digest(&self) -> ObjectDigest {
        self.request_digest
    }
}

/// Joins controller authority, runtime generation, and backend probe currentness.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct AdmissionCurrentnessV1 {
    runtime: RuntimeHandleCommitmentV1,
    payload_boot_id: PayloadBootId,
    backend_probe: BackendProbeCurrentnessV1,
    authority_context: ObjectDigest,
    resource_ledger: ObjectDigest,
    output_reservation: ObjectDigest,
}

impl AdmissionCurrentnessV1 {
    /// Constructs exact protected currentness for one admission transaction.
    ///
    /// `authority_context` is a generic protected authority commitment. Runtime
    /// execution admissions set it to the exact backend evidence-authority
    /// binding derived from the provisioned verification key, trust context,
    /// and channel; completion and recovery reject evidence from another
    /// binding.
    ///
    /// # Errors
    ///
    /// Returns [`AdmissionCommitError::CurrentnessMismatch`] when the probe is
    /// for another node, and `InvalidDraft` for zero commitments.
    pub fn new(
        runtime: RuntimeHandleCommitmentV1,
        payload_boot_id: PayloadBootId,
        backend_probe: BackendProbeCurrentnessV1,
        authority_context: ObjectDigest,
        resource_ledger: ObjectDigest,
        output_reservation: ObjectDigest,
    ) -> Result<Self, AdmissionCommitError> {
        if runtime.currentness().node() != backend_probe.node() {
            return Err(AdmissionCommitError::CurrentnessMismatch);
        }
        if authority_context.as_bytes() == &[0; 32]
            || resource_ledger.as_bytes() == &[0; 32]
            || output_reservation.as_bytes() == &[0; 32]
        {
            return Err(AdmissionCommitError::InvalidDraft);
        }
        Ok(Self {
            runtime,
            payload_boot_id,
            backend_probe,
            authority_context,
            resource_ledger,
            output_reservation,
        })
    }

    /// Returns the exact assignment and runtime-generation fence.
    #[must_use]
    pub const fn runtime(&self) -> &RuntimeHandleCommitmentV1 {
        &self.runtime
    }

    /// Returns the exact observed payload boot identity.
    #[must_use]
    pub const fn payload_boot_id(&self) -> PayloadBootId {
        self.payload_boot_id
    }

    /// Returns the protected backend probe binding.
    #[must_use]
    pub const fn backend_probe(&self) -> &BackendProbeCurrentnessV1 {
        &self.backend_probe
    }

    /// Returns the protected authorization-context commitment.
    ///
    /// Runtime execution paths interpret this value as the expected backend
    /// evidence-authority binding. Other admission users may assign a different
    /// domain-specific protected authority commitment without changing this
    /// portable container's representation.
    #[must_use]
    pub const fn authority_context(&self) -> ObjectDigest {
        self.authority_context
    }

    /// Returns the protected resource-ledger head expected by this admission.
    #[must_use]
    pub const fn resource_ledger(&self) -> ObjectDigest {
        self.resource_ledger
    }

    /// Returns the separately committed output-byte reservation.
    #[must_use]
    pub const fn output_reservation(&self) -> ObjectDigest {
        self.output_reservation
    }
}

/// Stores immutable bytes proposed for one atomic execution admission.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ExecutionAdmissionDraftV1 {
    execution: ExecutionId,
    specification_bytes: Vec<u8>,
    specification_digest: ObjectDigest,
    idempotency: AdmissionIdempotencyV1,
    currentness: AdmissionCurrentnessV1,
    record_commitment: ObjectDigest,
}

impl ExecutionAdmissionDraftV1 {
    /// Constructs a draft from an already validated execution specification.
    ///
    /// The canonical v1 specification encoder supplies bytes and digest; the
    /// runtime currentness must match its exact target. This constructor does
    /// not reserve resources or authorize a backend effect.
    ///
    /// # Errors
    ///
    /// Returns [`AdmissionCommitError`] for a target mismatch or oversized
    /// canonical specification.
    pub fn new(
        specification: &crate::ExecutionSpecV1,
        idempotency: AdmissionIdempotencyV1,
        currentness: AdmissionCurrentnessV1,
    ) -> Result<Self, AdmissionCommitError> {
        let target = specification.target();
        let runtime = currentness.runtime().currentness();
        if target.sandbox() != runtime.sandbox()
            || target.incarnation() != runtime.incarnation()
            || target.assignment_epoch() != runtime.assignment_epoch()
            || target.assignment_digest() != runtime.assignment_digest()
            || target.namespace_generation() != runtime.namespace_generation()
            || target.payload_boot_id() != currentness.payload_boot_id()
        {
            return Err(AdmissionCommitError::CurrentnessMismatch);
        }

        let specification_bytes = crate::encode_execution_spec_v1(specification);
        if specification_bytes.is_empty()
            || specification_bytes.len() > MAX_EXECUTION_SPECIFICATION_BYTES
        {
            return Err(AdmissionCommitError::InvalidDraft);
        }
        let specification_digest = crate::execution_spec_digest_v1(specification);
        let record_commitment = admission_commitment(
            specification.execution(),
            &specification_bytes,
            specification_digest,
            idempotency,
            &currentness,
        );
        Ok(Self {
            execution: specification.execution(),
            specification_bytes,
            specification_digest,
            idempotency,
            currentness,
            record_commitment,
        })
    }

    /// Returns the durable execution identity.
    #[must_use]
    pub const fn execution(&self) -> ExecutionId {
        self.execution
    }

    /// Returns the exact canonical specification bytes.
    #[must_use]
    pub fn specification_bytes(&self) -> &[u8] {
        &self.specification_bytes
    }

    /// Returns the exact specification digest.
    #[must_use]
    pub const fn specification_digest(&self) -> ObjectDigest {
        self.specification_digest
    }

    /// Returns the exact replay binding.
    #[must_use]
    pub const fn idempotency(&self) -> AdmissionIdempotencyV1 {
        self.idempotency
    }

    /// Returns protected admission currentness.
    #[must_use]
    pub const fn currentness(&self) -> &AdmissionCurrentnessV1 {
        &self.currentness
    }

    /// Returns the internally derived complete record commitment.
    #[must_use]
    pub const fn record_commitment(&self) -> ObjectDigest {
        self.record_commitment
    }
}

/// Classifies whether an admission commit created or replayed the exact record.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum AdmissionCommitDispositionV1 {
    /// The transaction created a new immutable admission record.
    Created,
    /// The transaction found the byte-identical previously committed record.
    ExactReplay,
}

/// Reports a definitive admission commit or store-owned recovery authority.
#[must_use]
pub enum AdmissionStoreCommitV1<R> {
    /// The exact admission transaction is durably committed.
    Committed(DurableAdmissionCommitV1),
    /// Commit durability is ambiguous and only the store can resolve it.
    RecoveryRequired(R),
    /// Authenticated reopen proves that the attempted transaction did not commit.
    NotCommitted,
}

/// Returns an admitted execution or retains its exact draft for recovery.
#[must_use]
pub enum ExecutionAdmissionOutcomeV1<R> {
    /// The execution admission is durable and may proceed to effect preparation.
    Admitted(AdmittedExecutionV1),
    /// The exact draft must be resolved with the opaque store recovery token.
    RecoveryRequired {
        /// Immutable admission bytes whose durability is being recovered.
        draft: ExecutionAdmissionDraftV1,
        /// Store-owned recovery authority that cannot be synthesized by callers.
        token: R,
    },
    /// Protected reopen proved absence; fresh admission may be attempted.
    NotCommitted(ExecutionAdmissionDraftV1),
}

/// Reports the protected store's completed atomic admission transaction.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct DurableAdmissionCommitV1 {
    record_commitment: ObjectDigest,
    journal_sequence: u64,
    transaction_commitment: ObjectDigest,
    disposition: AdmissionCommitDispositionV1,
}

impl DurableAdmissionCommitV1 {
    /// Constructs a store-produced commit receipt.
    ///
    /// # Errors
    ///
    /// Returns [`AdmissionCommitError::InvalidReceipt`] for zero fields.
    pub fn new(
        record_commitment: ObjectDigest,
        journal_sequence: u64,
        transaction_commitment: ObjectDigest,
        disposition: AdmissionCommitDispositionV1,
    ) -> Result<Self, AdmissionCommitError> {
        if record_commitment.as_bytes() == &[0; 32]
            || journal_sequence == 0
            || transaction_commitment.as_bytes() == &[0; 32]
        {
            return Err(AdmissionCommitError::InvalidReceipt);
        }
        Ok(Self {
            record_commitment,
            journal_sequence,
            transaction_commitment,
            disposition,
        })
    }

    /// Returns the committed admission-record digest.
    #[must_use]
    pub const fn record_commitment(&self) -> ObjectDigest {
        self.record_commitment
    }

    /// Returns the resulting nonzero journal sequence.
    #[must_use]
    pub const fn journal_sequence(&self) -> u64 {
        self.journal_sequence
    }

    /// Returns the complete atomic transaction commitment.
    #[must_use]
    pub const fn transaction_commitment(&self) -> ObjectDigest {
        self.transaction_commitment
    }

    /// Returns whether the exact record was created or replayed.
    #[must_use]
    pub const fn disposition(&self) -> AdmissionCommitDispositionV1 {
        self.disposition
    }
}

/// Owns one durably admitted execution and its exact immutable spec bytes.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct AdmittedExecutionV1 {
    draft: ExecutionAdmissionDraftV1,
    journal_sequence: u64,
    transaction_commitment: ObjectDigest,
}

impl AdmittedExecutionV1 {
    pub(super) fn from_commit(
        draft: ExecutionAdmissionDraftV1,
        commit: DurableAdmissionCommitV1,
    ) -> Self {
        Self {
            draft,
            journal_sequence: commit.journal_sequence(),
            transaction_commitment: commit.transaction_commitment(),
        }
    }

    /// Reconstructs an admitted value from an exact protected-store receipt.
    ///
    /// This validates structural agreement only and grants no effect authority;
    /// callers must obtain `commit` from their authenticated durable store.
    ///
    /// # Errors
    ///
    /// Returns [`AdmissionCommitError::ReceiptMismatch`] when the receipt does
    /// not commit the exact draft bytes.
    pub fn from_store_commit(
        draft: ExecutionAdmissionDraftV1,
        commit: DurableAdmissionCommitV1,
    ) -> Result<Self, AdmissionCommitError> {
        if draft.record_commitment() != commit.record_commitment() {
            return Err(AdmissionCommitError::ReceiptMismatch);
        }
        Ok(Self::from_commit(draft, commit))
    }

    /// Returns the durable execution identity.
    #[must_use]
    pub const fn execution(&self) -> ExecutionId {
        self.draft.execution()
    }

    /// Returns exact canonical execution-specification bytes.
    #[must_use]
    pub fn specification_bytes(&self) -> &[u8] {
        self.draft.specification_bytes()
    }

    /// Returns the exact specification digest.
    #[must_use]
    pub const fn specification_digest(&self) -> ObjectDigest {
        self.draft.specification_digest()
    }

    /// Returns the immutable admission record commitment.
    #[must_use]
    pub const fn admission_commitment(&self) -> ObjectDigest {
        self.draft.record_commitment()
    }

    /// Returns the exact idempotency binding.
    #[must_use]
    pub const fn idempotency(&self) -> AdmissionIdempotencyV1 {
        self.draft.idempotency()
    }

    /// Returns the protected admission currentness.
    #[must_use]
    pub const fn currentness(&self) -> &AdmissionCurrentnessV1 {
        self.draft.currentness()
    }

    /// Returns the admission transaction's journal sequence.
    #[must_use]
    pub const fn journal_sequence(&self) -> u64 {
        self.journal_sequence
    }

    /// Returns the complete admission transaction commitment.
    #[must_use]
    pub const fn transaction_commitment(&self) -> ObjectDigest {
        self.transaction_commitment
    }
}

/// Defines the protected atomic admission boundary owned by a durable journal.
pub trait ExecutionAdmissionStore {
    /// Opaque authority required to resolve an ambiguous admission commit.
    type RecoveryToken;

    /// Atomically revalidates currentness, reserves execution resources,
    /// indexes idempotency, and commits the immutable admission record.
    ///
    /// # Errors
    ///
    /// Returns [`AdmissionCommitError`] without exposing a usable admission
    /// when authority is stale, replay equivocates, capacity is unavailable,
    /// or commit durability is ambiguous.
    fn commit_execution_admission(
        &mut self,
        draft: &ExecutionAdmissionDraftV1,
    ) -> Result<AdmissionStoreCommitV1<Self::RecoveryToken>, AdmissionCommitError>;

    /// Resolves one exact ambiguous commit without creating a new transaction.
    ///
    /// # Errors
    ///
    /// Returns [`AdmissionCommitError`] for a token from another store, an
    /// equivocal draft, corrupt replay, or another ambiguous durable read.
    fn recover_execution_admission(
        &mut self,
        token: Self::RecoveryToken,
        draft: &ExecutionAdmissionDraftV1,
    ) -> Result<AdmissionStoreCommitV1<Self::RecoveryToken>, AdmissionCommitError>;
}

/// Commits one execution admission and verifies the store's exact receipt.
///
/// # Errors
///
/// Returns [`AdmissionCommitError`] for store rejection, ambiguity, or any
/// receipt that does not bind the exact proposed record.
pub fn admit_execution<S: ExecutionAdmissionStore>(
    store: &mut S,
    draft: ExecutionAdmissionDraftV1,
) -> Result<ExecutionAdmissionOutcomeV1<S::RecoveryToken>, AdmissionCommitError> {
    match store.commit_execution_admission(&draft)? {
        AdmissionStoreCommitV1::Committed(commit) => {
            verify_admission_commit(draft, commit).map(ExecutionAdmissionOutcomeV1::Admitted)
        }
        AdmissionStoreCommitV1::RecoveryRequired(token) => {
            Ok(ExecutionAdmissionOutcomeV1::RecoveryRequired { draft, token })
        }
        AdmissionStoreCommitV1::NotCommitted => {
            Ok(ExecutionAdmissionOutcomeV1::NotCommitted(draft))
        }
    }
}

/// Resolves an ambiguous admission using only the originating store token.
///
/// # Errors
///
/// Returns [`AdmissionCommitError`] for token mismatch, equivocation,
/// corruption, another ambiguous reopen, or a mismatched durable receipt.
pub fn recover_execution_admission<S: ExecutionAdmissionStore>(
    store: &mut S,
    draft: ExecutionAdmissionDraftV1,
    token: S::RecoveryToken,
) -> Result<ExecutionAdmissionOutcomeV1<S::RecoveryToken>, AdmissionCommitError> {
    match store.recover_execution_admission(token, &draft)? {
        AdmissionStoreCommitV1::Committed(commit) => {
            verify_admission_commit(draft, commit).map(ExecutionAdmissionOutcomeV1::Admitted)
        }
        AdmissionStoreCommitV1::RecoveryRequired(token) => {
            Ok(ExecutionAdmissionOutcomeV1::RecoveryRequired { draft, token })
        }
        AdmissionStoreCommitV1::NotCommitted => {
            Ok(ExecutionAdmissionOutcomeV1::NotCommitted(draft))
        }
    }
}

fn verify_admission_commit(
    draft: ExecutionAdmissionDraftV1,
    commit: DurableAdmissionCommitV1,
) -> Result<AdmittedExecutionV1, AdmissionCommitError> {
    if commit.record_commitment() != draft.record_commitment() {
        return Err(AdmissionCommitError::ReceiptMismatch);
    }
    Ok(AdmittedExecutionV1::from_commit(draft, commit))
}

/// Reports failure at the durable execution-admission boundary.
#[derive(Clone, Copy, Debug, Eq, PartialEq, thiserror::Error)]
pub enum AdmissionCommitError {
    /// Draft bytes, bindings, or commitments are malformed.
    #[error("execution admission draft is invalid")]
    InvalidDraft,
    /// Runtime, assignment, probe, and execution targets do not agree exactly.
    #[error("execution admission currentness does not match")]
    CurrentnessMismatch,
    /// The idempotency key already binds different normalized request bytes.
    #[error("execution admission idempotency key equivocated")]
    IdempotencyConflict,
    /// The governing assignment or authorization is no longer current.
    #[error("execution admission authority is stale")]
    StaleAuthority,
    /// Resource or output-retention admission cannot reserve the exact request.
    #[error("execution admission capacity is unavailable")]
    CapacityUnavailable,
    /// A store receipt contains a zero or otherwise invalid field.
    #[error("execution admission receipt is invalid")]
    InvalidReceipt,
    /// A store receipt does not bind the exact proposed record.
    #[error("execution admission receipt does not match the draft")]
    ReceiptMismatch,
    /// A durable record could not decode under its exact version and limits.
    #[error("execution admission durable record is corrupt")]
    CorruptRecord,
    /// A nested portable runtime value is malformed.
    #[error("execution admission runtime model is invalid: {0}")]
    Runtime(#[from] RuntimeModelError),
}

fn admission_commitment(
    execution: ExecutionId,
    specification_bytes: &[u8],
    specification_digest: ObjectDigest,
    idempotency: AdmissionIdempotencyV1,
    currentness: &AdmissionCurrentnessV1,
) -> ObjectDigest {
    let runtime_handle = currentness.runtime();
    let runtime = runtime_handle.currentness();
    let probe = currentness.backend_probe();
    let mut digest = Sha256::new();
    digest.update(ADMISSION_RECORD_DOMAIN);
    digest.update(execution.as_bytes());
    digest.update((specification_bytes.len() as u64).to_be_bytes());
    digest.update(specification_bytes);
    digest.update(specification_digest.as_bytes());
    digest.update(idempotency.operation().as_bytes());
    digest.update(idempotency.request_digest().as_bytes());
    digest.update(runtime.sandbox().as_bytes());
    digest.update(runtime.incarnation().as_bytes());
    digest.update(runtime.node().as_bytes());
    digest.update(runtime.assignment_epoch().get().to_be_bytes());
    digest.update(runtime.assignment_digest().as_bytes());
    digest.update(runtime.desired_generation().get().to_be_bytes());
    digest.update(runtime.namespace_generation().get().to_be_bytes());
    digest.update(runtime_handle.plan_commitment().as_bytes());
    digest.update(runtime_handle.handle().as_bytes());
    digest.update(currentness.payload_boot_id().as_bytes());
    digest.update(probe.node().as_bytes());
    digest.update(probe.backend_build().as_bytes());
    digest.update(probe.probe_epoch().get().to_be_bytes());
    digest.update(probe.protected_context().as_bytes());
    digest.update(currentness.authority_context().as_bytes());
    digest.update(currentness.resource_ledger().as_bytes());
    digest.update(currentness.output_reservation().as_bytes());
    ObjectDigest::from_bytes(digest.finalize().into())
}
