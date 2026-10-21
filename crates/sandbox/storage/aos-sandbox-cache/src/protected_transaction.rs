//! Retains Cache's own instance-bound plans, pending writes and capabilities.
//!
//! Canonical member planning and commit/recovery/sealing control are shared
//! Broker mechanisms. This private adapter owns the actual Cache journal
//! borrow, replay validator and move-only capability fields. Only its real
//! Cache gate may cross the native append frontier; decoded records and bound
//! requests cannot construct an effect-facing capability.
//!
//! Reducer bytes retain the canonical Protocol formats:
//!
//! ```text
//! AOSRDP01 reducer envelope -> AOSDTX01 durable transaction member
//! ```

use std::marker::PhantomData;
use std::sync::Arc;

use aos_sandbox_broker::domain_transaction_custody::transaction_state::{
    self, DomainRecoveryImageComparisonDataV1,
};
use aos_sandbox_model::ObjectDigest;
use aos_sandbox_protocol::domain_ledger::records::{
    DomainPreparedTransactionDataV1, ProtectedDomainEnvelopeV1, ProtectedDomainProjectionV1,
    ProtectedDomainReplayPhaseV1, ProtectedDomainSchemaV1, ResidentCanonicalPayloadBudgetDataV1,
    replay_projection_records,
};
use aos_sandbox_protocol::domain_ledger::{DomainLedgerDataError, JournalTransactionDataError};

use crate::journal::{
    CacheMutationGateV1, HeldCacheMutationGateV1, Journal, JournalError, JournalRecord,
    JournalTransaction,
};

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

/// Reports malformed domain records, stale plans, and journal failures.
#[derive(Debug, thiserror::Error)]
pub enum ProtectedDomainJournalErrorV1 {
    /// A key, envelope, revision, predecessor, or payload is noncanonical.
    #[error("protected domain journal record is noncanonical")]
    NonCanonicalRecord,
    /// A successor does not exactly extend the currently materialized value.
    #[error("protected domain journal compare-and-swap failed")]
    CompareAndSwapFailed,
    /// A plan or capability was issued by another adapter instance or snapshot.
    #[error("protected domain journal authority is stale or substituted")]
    StaleAuthority,
    /// Durable recovery found a mixture of predecessor and successor values.
    #[error("protected domain journal recovery found divergent state")]
    DivergentRecovery,
    /// The underlying journal rejected or could not durably perform an action.
    #[error(transparent)]
    Journal(#[from] JournalError),
}

impl From<DomainLedgerDataError> for ProtectedDomainJournalErrorV1 {
    fn from(error: DomainLedgerDataError) -> Self {
        match error {
            DomainLedgerDataError::NonCanonicalRecord => Self::NonCanonicalRecord,
            DomainLedgerDataError::CompareAndSwapFailed => Self::CompareAndSwapFailed,
            DomainLedgerDataError::Transaction(error) => Self::Journal(JournalError::from(error)),
        }
    }
}

impl From<JournalTransactionDataError> for ProtectedDomainJournalErrorV1 {
    fn from(error: JournalTransactionDataError) -> Self {
        <Self as From<JournalError>>::from(JournalError::from(error))
    }
}

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

/// Carries a consumed, current postcommit transaction to a dormant domain seam.
#[must_use = "validated postcommit authority must be consumed by one dormant action"]
pub struct ValidatedDomainPostcommitV1<'current, S: ProtectedDomainSchemaV1> {
    transaction: ObjectDigest,
    set_digest: ObjectDigest,
    records: ValidatedPostcommitRecordsV1<'current, S>,
    current: PhantomData<&'current ()>,
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

/// Borrows canonical record DATA only through an independently admitted composite.
///
/// The record alone grants no effect. This module privately constructs the
/// current transaction composite only after its real native role guards.
pub use aos_sandbox_protocol::domain_ledger::records::DomainPostcommitRecordDataV1 as DomainPostcommitRecordV1;

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

/// Specializes strict custody failures to the existing domain token types.
pub(crate) type DomainRetainedCommitFailureV1<S> =
    RetainedCommitFailureV1<PreparedDomainTransactionV1<S>, DomainOutcomeUnknownV1<S>>;

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

    /// Captures the same fully replayed current boundary for this actual adapter.
    ///
    /// # Errors
    /// Returns the original typed replay failure without issuing a snapshot.
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

    /// Plans the same canonical transition under an original Cache gate.
    ///
    /// # Errors
    /// Returns ordinary replay/CAS/preflight errors or changed-gate refusal.
    pub(crate) fn plan_with_retained_cache_gate_v1(
        &self,
        transaction_id: [u8; 16],
        successors: Vec<ProtectedDomainEnvelopeV1<S>>,
        gate: &mut HeldCacheMutationGateV1,
    ) -> Result<PreparedDomainTransactionV1<S>, ProtectedDomainJournalErrorV1> {
        self.plan_with_cache_gate(
            transaction_id,
            successors,
            CacheMutationGateV1::Retained(gate),
        )
    }

    pub(crate) fn plan_with_cache_gate(
        &self,
        transaction_id: [u8; 16],
        successors: Vec<ProtectedDomainEnvelopeV1<S>>,
        mut gate: CacheMutationGateV1<'_>,
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

    /// Reserves the resident prepared/readback payload before the planner copies it.
    ///
    /// # Errors
    /// Refuses checked aggregate payload overflow or configured exhaustion.
    pub(crate) fn reserve_resident_plan_payload(
        &self,
        successors: &[ProtectedDomainEnvelopeV1<S>],
        budget: &mut ResidentDomainPayloadBudgetV1,
    ) -> Result<(), ProtectedDomainJournalErrorV1> {
        let bytes = aos_sandbox_broker::domain_transaction_custody::members::resident_plan_payload_bytes_v1::<S>(
            self.journal.historical_read_view_v1(), successors,
        ).map_err(JournalError::from)?;
        budget.reserve(bytes)
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
                    cause: JournalError::preflight_mismatch(),
                })
            }
        }
    }

    /// Keeps original Prepared/Pending on every failure; never refreshes a head.
    ///
    /// # Errors
    /// Returns exact local custody and the typed preappend or postappend cause.
    pub(crate) fn commit_strict_with_retained_cache_gate_v1(
        &mut self,
        prepared: PreparedDomainTransactionV1<S>,
        gate: &mut HeldCacheMutationGateV1,
    ) -> Result<DomainCommitOutcomeV1<S>, DomainRetainedCommitFailureV1<S>> {
        self.commit_with_custody(prepared, |_| Ok(()), CacheMutationGateV1::Retained(gate))
    }

    /// Keeps Prepared or Pending under the actual resident Cache interlock.
    ///
    /// # Errors
    /// Returns the complete original token and typed failure without refreshing
    /// its snapshot or granting retry permission.
    pub(crate) fn commit_strict_with_original_cache_gate_v1(
        &mut self,
        prepared: PreparedDomainTransactionV1<S>,
        gate: CacheMutationGateV1<'_>,
    ) -> Result<DomainCommitOutcomeV1<S>, DomainRetainedCommitFailureV1<S>> {
        self.commit_with_custody(prepared, |_| Ok(()), gate)
    }

    aos_sandbox_broker::define_protected_commit_control_v1!(Journal);

    aos_sandbox_broker::define_protected_recovery_control_v1!(Journal);

    aos_sandbox_broker::define_protected_sealing_control_v1!(Journal);
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
