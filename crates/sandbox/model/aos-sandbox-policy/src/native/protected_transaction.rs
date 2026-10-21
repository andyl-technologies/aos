//! Owns Policy's private prepared, pending and same-instance transaction custody.
//!
//! The real fixed Policy native journal remains borrowed through planning,
//! actual typed final-gated append, exact readback, recovery and consumption.
//! Canonical DATA comparisons cannot construct these private-field capabilities.
//! The complete commit/recovery/sealing bodies are the frozen shared recipes;
//! no native engine or Domain Journal facade is copied into this role owner.

use std::marker::PhantomData;
use std::sync::Arc;

use aos_sandbox_broker::domain_transaction_custody::transaction_state::{
    self, DomainRecoveryImageComparisonDataV1,
};
use aos_sandbox_model::ObjectDigest;
use aos_sandbox_protocol::domain_ledger::records::{
    DomainPreparedTransactionDataV1, ProtectedCurrentRecordCandidateV1, ProtectedDomainEnvelopeV1,
    ProtectedDomainKeyV1, ProtectedDomainProjectionV1, ProtectedDomainReplayPhaseV1,
    ProtectedDomainSchemaV1, ResidentCanonicalPayloadBudgetDataV1,
    current_record_candidates_from_rows, encode_checkpoint_payload, replay_projection_records,
};
use aos_sandbox_protocol::domain_ledger::transaction::{JournalRecord, JournalTransaction};
use aos_sandbox_protocol::domain_ledger::{DomainLedgerDataError, JournalTransactionDataError};

use super::PolicyNativeJournalErrorV1 as JournalError;
use super::append::PolicyMutationGateV1 as CacheMutationGateV1;
use super::journal::RootPolicyJournalV1 as Journal;

/// Bounds additional retained canonical byte payloads, without granting authority.
///
/// The current Journal graph is independently bounded and is not charged once
/// per leg. This does not measure decoded containers or allocator overhead.
pub(crate) struct ResidentDomainPayloadBudgetV1 {
    data: ResidentCanonicalPayloadBudgetDataV1,
}

impl ResidentDomainPayloadBudgetV1 {
    pub(crate) const fn new(maximum: usize) -> Self {
        Self {
            data: ResidentCanonicalPayloadBudgetDataV1::new(maximum),
        }
    }

    pub(crate) const fn retained(&self) -> usize {
        self.data.retained()
    }

    /// Reserves aggregate canonical bytes before retaining another member.
    ///
    /// # Errors
    /// Refuses overflow or exhaustion without changing the prior reservation.
    pub(crate) fn reserve(&mut self, bytes: usize) -> Result<(), ProtectedDomainJournalErrorV1> {
        self.data
            .reserve(bytes)
            .map_err(ProtectedDomainJournalErrorV1::from)
    }
}

pub use crate::publication::ProtectedDomainJournalErrorV1;

/// Seals one exact protected-journal currentness boundary.
#[derive(Clone, Debug)]
pub struct ProtectedDomainSnapshotV1<S: ProtectedDomainSchemaV1> {
    instance: Arc<AdapterInstanceV1>,
    sequence: u64,
    root: ObjectDigest,
    marker: PhantomData<S>,
}

impl<S: ProtectedDomainSchemaV1> ProtectedDomainSnapshotV1<S> {
    /// Returns the exact shared-journal sequence at this sealed boundary.
    #[must_use]
    pub const fn journal_sequence(&self) -> u64 {
        self.sequence
    }

    /// Returns the complete materialized domain projection commitment.
    #[must_use]
    pub const fn projection_root(&self) -> ObjectDigest {
        self.root
    }
}

/// Holds one exact compare-and-swap transaction before durable mutation.
#[must_use = "a prepared journal transaction must be committed or deliberately discarded"]
pub struct PreparedDomainTransactionV1<S: ProtectedDomainSchemaV1> {
    snapshot: ProtectedDomainSnapshotV1<S>,
    data: DomainPreparedTransactionDataV1,
}

impl<S: ProtectedDomainSchemaV1> PreparedDomainTransactionV1<S> {
    /// Borrows prepared canonical members for a same-owner atomic composition.
    ///
    /// These records retain the existing framing and digest algorithm; they
    /// grant no commit, postcommit, live custody or publication authority.
    pub(crate) fn journal_records(&self) -> &[JournalRecord] {
        self.data.transaction.records()
    }

    pub(crate) fn journal_transaction_v1(&self) -> &JournalTransaction {
        &self.data.transaction
    }

    /// Returns the stable transaction identifier bound into durable members.
    #[must_use]
    pub const fn transaction_id(&self) -> [u8; 16] {
        *self.data.transaction.id()
    }

    /// Returns the exact canonical domain transaction commitment.
    #[must_use]
    pub const fn transaction_digest(&self) -> ObjectDigest {
        self.data.digest
    }
}

/// Retains the exact transaction after an ambiguous append or synchronization.
#[must_use = "outcome-unknown state must be resolved against a reopened journal"]
pub struct DomainOutcomeUnknownV1<S: ProtectedDomainSchemaV1> {
    prepared: PreparedDomainTransactionV1<S>,
}

/// Retains one composite exact-readback capability for a whole transaction.
#[must_use = "postcommit authority must be revalidated and consumed as one transaction"]
pub struct DomainPostcommitCapabilityV1<S: ProtectedDomainSchemaV1> {
    instance: Arc<AdapterInstanceV1>,
    transaction: ObjectDigest,
    set_digest: ObjectDigest,
    sequence: u64,
    root: ObjectDigest,
    records: Vec<DomainPostcommitRecordV1<S>>,
    marker: PhantomData<S>,
}

impl<S: ProtectedDomainSchemaV1> DomainPostcommitCapabilityV1<S> {
    /// Returns the transaction represented by this composite capability.
    #[must_use]
    pub const fn transaction_digest(&self) -> ObjectDigest {
        self.transaction
    }

    /// Returns the commitment to every ordered transaction member.
    #[must_use]
    pub const fn transaction_set_digest(&self) -> ObjectDigest {
        self.set_digest
    }

    /// Returns the exact postcommit shared-journal sequence.
    #[must_use]
    pub const fn journal_sequence(&self) -> u64 {
        self.sequence
    }

    /// Returns the complete postcommit materialized domain projection.
    #[must_use]
    pub const fn projection_root(&self) -> ObjectDigest {
        self.root
    }

    /// Consumes the composite capability after exact current-envelope replay.
    ///
    /// # Errors
    ///
    /// Returns [`ProtectedDomainJournalErrorV1::StaleAuthority`] if the journal
    /// is unhealthy, another commit advanced it, or any transaction member is
    /// no longer byte-exact current state.
    pub fn consume<'current>(
        self,
        authority: &'current ProtectedDomainJournalV1<'_, S>,
    ) -> Result<ValidatedDomainPostcommitV1<'current, S>, ProtectedDomainJournalErrorV1> {
        self.validate_current(authority)?;
        Ok(ValidatedDomainPostcommitV1 {
            transaction: self.transaction,
            set_digest: self.set_digest,
            records: ValidatedPostcommitRecordsV1::Owned(self.records),
            current: PhantomData,
        })
    }

    /// Borrows the original capability records after unchanged current checks.
    ///
    /// # Errors
    /// Refuses a changed writer instance, head, member set or current authority.
    pub(crate) fn validate_borrowed<'current>(
        &'current self,
        authority: &'current ProtectedDomainJournalV1<'_, S>,
    ) -> Result<ValidatedDomainPostcommitV1<'current, S>, ProtectedDomainJournalErrorV1> {
        self.validate_current(authority)?;
        Ok(ValidatedDomainPostcommitV1 {
            transaction: self.transaction,
            set_digest: self.set_digest,
            records: ValidatedPostcommitRecordsV1::Borrowed(&self.records),
            current: PhantomData,
        })
    }

    fn validate_current(
        &self,
        authority: &ProtectedDomainJournalV1<'_, S>,
    ) -> Result<(), ProtectedDomainJournalErrorV1> {
        let current = authority.snapshot()?;
        if !Arc::ptr_eq(&self.instance, &authority.instance)
            || self.sequence != current.sequence
            || self.root != current.root
            || !transaction_state::postcommit_rows_match_v1(
                authority.journal.historical_read_view_v1(),
                &self.records,
            )
        {
            return Err(ProtectedDomainJournalErrorV1::StaleAuthority);
        }
        Ok(())
    }
}

/// Carries a consumed, current postcommit transaction to a dormant domain seam.
#[must_use = "validated postcommit authority must be consumed by one dormant action"]
pub struct ValidatedDomainPostcommitV1<'current, S: ProtectedDomainSchemaV1> {
    transaction: ObjectDigest,
    set_digest: ObjectDigest,
    records: ValidatedPostcommitRecordsV1<'current, S>,
    current: PhantomData<&'current ()>,
}

impl<S: ProtectedDomainSchemaV1> ValidatedDomainPostcommitV1<'_, S> {
    /// Returns the exact atomic transaction commitment.
    #[must_use]
    pub const fn transaction_digest(&self) -> ObjectDigest {
        self.transaction
    }

    /// Returns the commitment to every ordered transaction member.
    #[must_use]
    pub const fn transaction_set_digest(&self) -> ObjectDigest {
        self.set_digest
    }

    /// Returns the complete ordered transaction member set.
    #[must_use]
    pub fn records(&self) -> &[DomainPostcommitRecordV1<S>] {
        match &self.records {
            ValidatedPostcommitRecordsV1::Owned(records) => records,
            ValidatedPostcommitRecordsV1::Borrowed(records) => records,
        }
    }
}

// Borrowing keeps the original composite capability parked while the same
// current checks lend its exact records to one resident physical handoff.
enum ValidatedPostcommitRecordsV1<'current, S: ProtectedDomainSchemaV1> {
    Owned(Vec<DomainPostcommitRecordV1<S>>),
    Borrowed(&'current [DomainPostcommitRecordV1<S>]),
}

/// Retains the first phase-specific failure while Prepared stays in its owner.
#[derive(Debug, thiserror::Error)]
pub(crate) enum ResidentDomainCommitFailureV1 {
    #[error("resident preappend validation failed: {0}")]
    Before(#[source] ProtectedDomainJournalErrorV1),
    #[error("resident append durability is unknown: {0}")]
    Append(#[source] JournalError),
    #[error("resident exact readback failed: {0}")]
    Readback(#[source] ProtectedDomainJournalErrorV1),
    #[error("resident postcommit sealing failed: {0}")]
    Sealing(#[source] ProtectedDomainJournalErrorV1),
}

/// Reports a successful exact readback and any role-specific authority.
#[must_use = "postcommit capabilities must be consumed or deliberately discarded"]
pub struct AppliedDomainTransactionV1<S: ProtectedDomainSchemaV1> {
    transaction: ObjectDigest,
    snapshot: ProtectedDomainSnapshotV1<S>,
    capability: Option<DomainPostcommitCapabilityV1<S>>,
}

impl<S: ProtectedDomainSchemaV1> AppliedDomainTransactionV1<S> {
    /// Returns the exact canonical transaction commitment.
    #[must_use]
    pub const fn transaction_digest(&self) -> ObjectDigest {
        self.transaction
    }

    /// Returns the sealed postcommit journal snapshot.
    #[must_use]
    pub const fn snapshot(&self) -> &ProtectedDomainSnapshotV1<S> {
        &self.snapshot
    }

    /// Takes the composite transaction capability for current revalidation.
    #[must_use]
    pub fn take_postcommit(&mut self) -> Option<DomainPostcommitCapabilityV1<S>> {
        self.capability.take()
    }
}

impl<S: ProtectedDomainSchemaV1> AppliedDomainTransactionV1<S> {
    // An actual positive owner first consumes its unused composite. Its Arc
    // snapshot then retains only this private adapter allocation; no row or
    // native owner is replaced with a reconstructed success value.
    pub(crate) fn completed_resident_backing_bytes_v1(&self) -> Option<usize> {
        if self.capability.is_some() {
            return None;
        }
        std::mem::size_of::<AdapterInstanceV1>().checked_add(2 * std::mem::size_of::<usize>())
    }
}

/// Distinguishes exact commit success from an outcome requiring reopen.
#[must_use = "ambiguous commits must retain their recovery token"]
pub enum DomainCommitOutcomeV1<S: ProtectedDomainSchemaV1> {
    /// Every successor was durably committed and read back exactly.
    Applied(AppliedDomainTransactionV1<S>),
    /// The append or synchronization result is unknown until protected reopen.
    OutcomeUnknown {
        /// Retains the exact predecessor and successor transaction.
        pending: DomainOutcomeUnknownV1<S>,
        /// Reports the underlying durability failure.
        cause: JournalError,
    },
}

/// Classifies recovery of one exact outcome-unknown transaction.
#[must_use = "recovered transactions must be applied, retried, or quarantined"]
pub enum DomainRecoveryV1<S: ProtectedDomainSchemaV1> {
    /// Reopen found every exact successor value.
    Applied(AppliedDomainTransactionV1<S>),
    /// Reopen found every exact predecessor and permits only the retained retry.
    Retry(PreparedDomainTransactionV1<S>),
    /// Reopen found mixed or substituted state and retains the evidence.
    Diverged(DomainOutcomeUnknownV1<S>),
}

/// Retains original local custody without granting retry or effect authority.
///
/// The stages describe this Journal call only, not earlier Root effects. No
/// branch permits dropping the surrounding held owner cut after Root.
#[must_use = "strict commit failures must keep original custody in the held owner"]
pub(crate) enum RetainedCommitFailureV1<Prepared, Pending> {
    /// Keeps the original prepared value before this engine attempted append.
    BeforeJournalAppend {
        prepared: Prepared,
        cause: ProtectedDomainJournalErrorV1,
    },
    /// Keeps the original pending value after append but failed exact readback.
    AfterAppendReadback {
        pending: Pending,
        cause: ProtectedDomainJournalErrorV1,
    },
    /// Keeps pending custody when the actual applied-token sealing fails.
    AfterAppendSealing {
        pending: Pending,
        cause: ProtectedDomainJournalErrorV1,
    },
}

/// Retains an outcome-unknown token when cold recovery cannot be evaluated.
#[must_use]
pub enum DomainRetainedRecoveryV1<S: ProtectedDomainSchemaV1> {
    /// Recovery reached its ordinary applied, retry, or diverged classification.
    Outcome(DomainRecoveryV1<S>),
    /// Reopen validation failed before consuming the opaque pending token.
    Retryable {
        /// Exact pending transaction remains available for another cold reopen.
        pending: DomainOutcomeUnknownV1<S>,
        /// Fail-closed protected replay diagnostic.
        error: ProtectedDomainJournalErrorV1,
    },
}

/// Carries a complete current transaction reconstructed during cold replay.
#[must_use = "cold-replayed authority must be revalidated and consumed"]
pub enum ReplayedDomainPostcommitV1<S: ProtectedDomainSchemaV1> {
    /// The complete current transaction retains an effect eligible to run.
    Prepared(DomainPostcommitCapabilityV1<S>),
    /// The complete current transaction contains a terminal publication.
    Terminal(DomainPostcommitCapabilityV1<S>),
}

#[derive(Debug)]
struct AdapterInstanceV1;

/// Owns dormant protected currentness for one closed journal domain.
pub struct ProtectedDomainJournalV1<'journal, S: ProtectedDomainSchemaV1> {
    journal: &'journal mut Journal,
    instance: Arc<AdapterInstanceV1>,
    validator: S::ReplayValidator,
    marker: PhantomData<S>,
}

pub use aos_sandbox_protocol::domain_ledger::records::DomainPostcommitRecordDataV1 as DomainPostcommitRecordV1;

pub(crate) type DomainRetainedCommitFailureV1<S> =
    RetainedCommitFailureV1<PreparedDomainTransactionV1<S>, DomainOutcomeUnknownV1<S>>;

impl<'journal, S: ProtectedDomainSchemaV1> ProtectedDomainJournalV1<'journal, S> {
    /// Claims a protected-open journal without activating any runtime consumer.
    ///
    /// # Errors
    ///
    /// Returns [`JournalError`] unless the journal retains protected storage
    /// provenance and is healthy.
    /// Claims a journal with the trusted evidence used for typed replay.
    pub(crate) fn claim_with_validator(
        journal: &'journal mut Journal,
        validator: S::ReplayValidator,
    ) -> Result<Self, ProtectedDomainJournalErrorV1> {
        journal.ensure_protected_authority()?;
        Ok(Self {
            journal,
            instance: Arc::new(AdapterInstanceV1),
            validator,
            marker: PhantomData,
        })
    }

    /// Replays and validates the complete materialized domain projection.
    ///
    /// # Errors
    ///
    /// Returns [`ProtectedDomainJournalErrorV1`] for poison, malformed keys,
    /// foreign namespace mappings, alternate encodings, or allocation bounds.
    pub fn replay(&self) -> Result<ProtectedDomainProjectionV1<S>, ProtectedDomainJournalErrorV1> {
        self.journal.ensure_healthy()?;
        replay_projection::<S>(self.journal, &self.validator)
    }

    /// Reconstructs current pending or terminal authority from durable members.
    ///
    /// Incomplete or state-only groups never become postcommit authority. The
    /// returned composite remains bound to this adapter instance and must pass
    /// [`DomainPostcommitCapabilityV1::consume`] before use.
    ///
    /// # Errors
    ///
    /// Returns [`ProtectedDomainJournalErrorV1`] for malformed grouping,
    /// excessive replay state, poison, or a substituted current envelope.
    pub fn recover_current_postcommit(
        &self,
        transaction_id: [u8; 16],
    ) -> Result<Option<ReplayedDomainPostcommitV1<S>>, ProtectedDomainJournalErrorV1> {
        self.recover_current_postcommit_with_payload_budget(transaction_id, None)
    }

    /// Uses the same cold scan with a checked retained-payload destination.
    ///
    /// # Errors
    /// Returns unchanged replay errors or aggregate payload exhaustion.
    pub(crate) fn recover_current_postcommit_with_payload_budget(
        &self,
        transaction_id: [u8; 16],
        mut budget: Option<&mut ResidentDomainPayloadBudgetV1>,
    ) -> Result<Option<ReplayedDomainPostcommitV1<S>>, ProtectedDomainJournalErrorV1> {
        let snapshot = self.snapshot()?;
        let candidate = transaction_state::current_postcommit_candidate_v1::<S>(
            self.journal.historical_read_view_v1(),
            transaction_id,
            &self.validator,
            budget.as_deref_mut().map(|budget| &mut budget.data),
        )?;
        let Some(candidate) = candidate else {
            return Ok(None);
        };
        let (transaction, transaction_digest, set_digest, records) = candidate.into_parts();
        let capability = DomainPostcommitCapabilityV1 {
            instance: Arc::clone(&self.instance),
            transaction: transaction_digest,
            set_digest,
            sequence: snapshot.sequence,
            root: snapshot.root,
            records,
            marker: PhantomData,
        };
        Ok(Some(match transaction.phase() {
            ProtectedDomainReplayPhaseV1::Prepared => {
                ReplayedDomainPostcommitV1::Prepared(capability)
            }
            ProtectedDomainReplayPhaseV1::Terminal => {
                ReplayedDomainPostcommitV1::Terminal(capability)
            }
            ProtectedDomainReplayPhaseV1::Observed
            | ProtectedDomainReplayPhaseV1::Superseded
            | ProtectedDomainReplayPhaseV1::Incomplete => {
                return Ok(None);
            }
        }))
    }

    /// Captures a sealed exact current-state boundary.
    ///
    /// # Errors
    ///
    /// Returns [`ProtectedDomainJournalErrorV1`] when replay validation fails.
    pub fn snapshot(&self) -> Result<ProtectedDomainSnapshotV1<S>, ProtectedDomainJournalErrorV1> {
        let projection = self.replay()?;
        Ok(ProtectedDomainSnapshotV1 {
            instance: Arc::clone(&self.instance),
            sequence: self.journal.snapshot_sequence(),
            root: projection.root(),
            marker: PhantomData,
        })
    }

    /// Revalidates one sealed snapshot without exposing raw journal authority.
    ///
    /// # Errors
    ///
    /// Returns [`ProtectedDomainJournalErrorV1::StaleAuthority`] unless the
    /// adapter instance, shared sequence, and projection root remain exact.
    pub(crate) fn revalidate_snapshot(
        &self,
        snapshot: &ProtectedDomainSnapshotV1<S>,
    ) -> Result<(), ProtectedDomainJournalErrorV1> {
        self.validate_snapshot(snapshot)
    }

    /// Constructs the canonical payload for a checkpoint of current state.
    ///
    /// The payload binds the protected shared-journal sequence and the exact
    /// materialized domain root. [`Self::plan`] accepts no alternate checkpoint
    /// payload. This per-domain adapter deliberately exposes no compaction;
    /// only a complete shared-journal owner may establish a global floor.
    ///
    /// # Errors
    ///
    /// Returns [`ProtectedDomainJournalErrorV1`] when replay validation fails.
    fn checkpoint_payload(&self) -> Result<Vec<u8>, ProtectedDomainJournalErrorV1> {
        let snapshot = self.snapshot()?;
        Ok(encode_checkpoint_payload::<S>(
            snapshot.sequence,
            snapshot.root,
        ))
    }

    /// Constructs a checkpoint successor bound to the exact current snapshot.
    ///
    /// # Errors
    ///
    /// Returns [`ProtectedDomainJournalErrorV1`] unless `key` names the closed
    /// checkpoint kind or the requested revision/predecessor shape is invalid.
    pub fn checkpoint_successor(
        &self,
        key: ProtectedDomainKeyV1<S>,
        revision: u64,
        predecessor: Option<ObjectDigest>,
    ) -> Result<ProtectedDomainEnvelopeV1<S>, ProtectedDomainJournalErrorV1> {
        if !S::is_checkpoint(key.kind()) {
            return Err(ProtectedDomainJournalErrorV1::NonCanonicalRecord);
        }
        let payload = self.checkpoint_payload()?;
        ProtectedDomainEnvelopeV1::new_with_validator(
            key,
            revision,
            predecessor,
            payload,
            &self.validator,
        )
        .map_err(ProtectedDomainJournalErrorV1::from)
    }

    /// Plans one exact ordered atomic compare-and-swap transaction.
    ///
    /// Successors are sorted by the schema's closed kind order and canonical
    /// key. Each must directly extend the currently materialized envelope.
    ///
    /// # Errors
    ///
    /// Returns [`ProtectedDomainJournalErrorV1`] for duplicate keys, stale
    /// predecessors, skipped revisions, malformed current state, or journal
    /// preflight failure.
    pub fn plan(
        &self,
        transaction_id: [u8; 16],
        successors: Vec<ProtectedDomainEnvelopeV1<S>>,
    ) -> Result<PreparedDomainTransactionV1<S>, ProtectedDomainJournalErrorV1> {
        self.plan_with_cache_gate(transaction_id, successors, CacheMutationGateV1::Ordinary)
    }

    // Policy owns no Source/Create/Start/Stop provisioning exception.
    // Its genuine publication loan stays in the private concrete mutation gate.
    fn plan_with_cache_gate(
        &self,
        transaction_id: [u8; 16],
        successors: Vec<ProtectedDomainEnvelopeV1<S>>,
        mut gate: CacheMutationGateV1<'_, '_, '_, '_, '_>,
    ) -> Result<PreparedDomainTransactionV1<S>, ProtectedDomainJournalErrorV1> {
        let snapshot = self.snapshot()?;
        let members = aos_sandbox_broker::domain_transaction_custody::plan_members_v1::<S>(
            self.journal.historical_read_view_v1(),
            snapshot.sequence,
            snapshot.root,
            transaction_id,
            successors,
            &self.validator,
        )?;
        gate.preflight(self.journal, std::slice::from_ref(members.transaction()))?;
        let data = members.into_prepared_data_v1();
        Ok(PreparedDomainTransactionV1 { snapshot, data })
    }

    /// Commits a plan and releases authority only after exact readback.
    ///
    /// # Errors
    ///
    /// Returns [`ProtectedDomainJournalErrorV1::StaleAuthority`] for a plan
    /// issued by another instance or invalidated by an intervening commit.
    pub fn commit(
        &mut self,
        prepared: PreparedDomainTransactionV1<S>,
    ) -> Result<DomainCommitOutcomeV1<S>, ProtectedDomainJournalErrorV1> {
        self.commit_with_check(prepared, |_| Ok(()))
    }

    fn commit_with_check(
        &mut self,
        prepared: PreparedDomainTransactionV1<S>,
        check: impl FnMut(&Journal) -> Result<(), JournalError>,
    ) -> Result<DomainCommitOutcomeV1<S>, ProtectedDomainJournalErrorV1> {
        match self.commit_with_custody(prepared, check, CacheMutationGateV1::Ordinary) {
            Ok(outcome) => Ok(outcome),
            Err(
                RetainedCommitFailureV1::BeforeJournalAppend { cause, .. }
                | RetainedCommitFailureV1::AfterAppendSealing { cause, .. },
            ) => Err(cause),
            Err(RetainedCommitFailureV1::AfterAppendReadback { pending, .. }) => {
                Ok(DomainCommitOutcomeV1::OutcomeUnknown {
                    pending,
                    cause: JournalError::Mechanical(aos_sandbox_broker::canonical_journal::CanonicalJournalMechanicalErrorV1::AuthorityPreflightMismatch),
                })
            }
        }
    }

    /// Keeps Prepared or Pending under the actual resident Cache interlock.
    ///
    /// # Errors
    /// Returns the complete original token and typed failure without refreshing
    /// its snapshot or granting retry permission.
    pub(crate) fn commit_strict_with_original_cache_gate_v1(
        &mut self,
        prepared: PreparedDomainTransactionV1<S>,
        gate: CacheMutationGateV1<'_, '_, '_, '_, '_>,
    ) -> Result<DomainCommitOutcomeV1<S>, DomainRetainedCommitFailureV1<S>> {
        self.commit_with_custody(prepared, |_| Ok(()), gate)
    }

    /// Resolves an ambiguous transaction after protected reopen.
    ///
    /// # Errors
    ///
    /// Returns [`ProtectedDomainJournalErrorV1`] if the reopened journal is
    /// poisoned or its domain projection is malformed.
    pub fn recover(
        &self,
        pending: DomainOutcomeUnknownV1<S>,
    ) -> Result<DomainRecoveryV1<S>, ProtectedDomainJournalErrorV1> {
        self.replay()?;
        let prepared = pending.prepared;
        let DomainRecoveryImageComparisonDataV1 { before, after } =
            transaction_state::compare_recovery_images_v1(
                self.journal.historical_read_view_v1(),
                &prepared.data,
            );
        if after {
            return self.applied(prepared).map(DomainRecoveryV1::Applied);
        }
        if before {
            let mut prepared = prepared;
            prepared.snapshot = self.snapshot()?;
            self.journal
                .preflight_transactions(std::slice::from_ref(&prepared.data.transaction))?;
            return Ok(DomainRecoveryV1::Retry(prepared));
        }
        Ok(DomainRecoveryV1::Diverged(DomainOutcomeUnknownV1 {
            prepared,
        }))
    }

    /// Recovers while retaining the opaque pending token on transient failure.
    pub fn recover_retaining(
        &self,
        pending: DomainOutcomeUnknownV1<S>,
    ) -> DomainRetainedRecoveryV1<S> {
        self.recover_retaining_with_cache_gate(pending, CacheMutationGateV1::Ordinary)
    }

    aos_sandbox_broker::define_protected_commit_control_v1!(Journal, gate = CacheMutationGateV1<'_, '_, '_, '_, '_>);

    aos_sandbox_broker::define_protected_recovery_control_v1!(Journal, gate = CacheMutationGateV1<'_, '_, '_, '_, '_>);

    aos_sandbox_broker::define_protected_sealing_control_v1!(Journal);
}

fn postcommit_records<S: ProtectedDomainSchemaV1>(
    prepared: &PreparedDomainTransactionV1<S>,
    validator: &S::ReplayValidator,
) -> Result<Vec<DomainPostcommitRecordV1<S>>, ProtectedDomainJournalErrorV1> {
    aos_sandbox_broker::domain_transaction_custody::members::postcommit_records_v1::<S>(
        &prepared.data.transaction,
        &prepared.data.roles,
        &prepared.data.after,
        validator,
    )
    .map_err(ProtectedDomainJournalErrorV1::from)
}

fn validate_expected_values<S: ProtectedDomainSchemaV1>(
    journal: &Journal,
    prepared: &PreparedDomainTransactionV1<S>,
    after: bool,
) -> Result<(), ProtectedDomainJournalErrorV1> {
    values_match(journal, prepared, after)
        .then_some(())
        .ok_or(ProtectedDomainJournalErrorV1::CompareAndSwapFailed)
}

fn values_match<S: ProtectedDomainSchemaV1>(
    journal: &Journal,
    prepared: &PreparedDomainTransactionV1<S>,
    after: bool,
) -> bool {
    transaction_state::prepared_image_matches_v1(
        journal.historical_read_view_v1(),
        &prepared.data,
        after,
    )
}

pub(crate) fn replay_projection<S: ProtectedDomainSchemaV1>(
    journal: &Journal,
    validator: &S::ReplayValidator,
) -> Result<ProtectedDomainProjectionV1<S>, ProtectedDomainJournalErrorV1> {
    replay_projection_records::<S>(journal.all_records(), validator)
        .map_err(ProtectedDomainJournalErrorV1::from)
}

/// Structurally authenticates every current record for one domain without
/// interpreting its reducer body.
///
/// # Errors
///
/// Returns [`ProtectedDomainJournalErrorV1`] for an unprotected or unhealthy
/// journal, malformed framing, incorrect namespace mapping, or any failed
/// canonical hash check.
pub(crate) fn protected_current_record_candidates_v1<S: ProtectedDomainSchemaV1>(
    journal: &Journal,
) -> Result<Vec<ProtectedCurrentRecordCandidateV1<S>>, ProtectedDomainJournalErrorV1> {
    journal.ensure_protected_authority()?;

    current_record_candidates_from_rows::<S>(journal.all_records())
        .map_err(ProtectedDomainJournalErrorV1::from)
}

// The actual role adds this private adapter/handle component before first claim.
// Schema maps/decoders and encoded member backing are independent components.
pub(in crate::native) fn receiving_control_bytes_v1<S: ProtectedDomainSchemaV1>() -> Option<usize> {
    use std::mem::{align_of, size_of};
    let adapters = size_of::<ProtectedDomainJournalV1<'_, S>>()
        .checked_add(size_of::<Result<ProtectedDomainJournalV1<'_, S>, ProtectedDomainJournalErrorV1>>())?
        .checked_add(size_of::<ProtectedDomainSnapshotV1<S>>())?
        .checked_add(size_of::<Result<ProtectedDomainSnapshotV1<S>, ProtectedDomainJournalErrorV1>>())?;
    let custody = size_of::<PreparedDomainTransactionV1<S>>()
        .checked_add(size_of::<DomainOutcomeUnknownV1<S>>())?
        .checked_add(size_of::<AppliedDomainTransactionV1<S>>())?
        .checked_add(size_of::<DomainPostcommitCapabilityV1<S>>())?
        .checked_add(size_of::<Result<DomainCommitOutcomeV1<S>, DomainRetainedCommitFailureV1<S>>>())?
        .checked_add(size_of::<Result<PreparedDomainTransactionV1<S>, ProtectedDomainJournalErrorV1>>())?
        .checked_add(size_of::<DomainPostcommitRecordV1<S>>().checked_mul(4)?)?;
    adapters.checked_add(custody)?.checked_mul(3)?
        // One actual fresh instance Arc, its strong/weak header and alignment.
        .checked_add(size_of::<AdapterInstanceV1>().checked_mul(2)?)?
        .checked_add(size_of::<usize>().checked_mul(2)?)?
        .checked_add(align_of::<AdapterInstanceV1>().checked_mul(2)?)
}
