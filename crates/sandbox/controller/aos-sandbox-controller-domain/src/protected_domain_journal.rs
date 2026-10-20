//! Shared native transaction custody for protected domain journals.
//!
//! This crate-private owner retains the original Journal borrow across planning,
//! append, exact readback, recovery and postcommit consumption. Domain modules
//! supply closed schemas and trusted validators; decoded DATA grants no authority.
//!
//! Protocol's reducer payloads use one canonical wrapper:
//!
//! ```text
//! AOSRDP01 | version:u16 | family:u8 | kind:u8 | phase:u8 | reserved:u8 | companions:u16 |
//! body-length:u32 | sorted-companion-digests | canonical-body | digest
//! ```
//!
//! Materialized values wrap that canonical envelope in one durable transaction
//! member, allowing bounded cold replay to reconstruct grouping and phase:
//!
//! ```text
//! AOSDTX01 | version:u16 | reserved:u16 | transaction-id:[u8;16] |
//! member-index:u16 | member-count:u16 | set-digest:[u8;32] |
//! envelope-length:u32 | canonical-envelope | member-digest:[u8;32]
//! ```

mod capacity;

use std::marker::PhantomData;
use std::path::Path;
use std::sync::Arc;

use aos_sandbox_model::ObjectDigest;
use aos_sandbox_broker::domain_transaction_custody::transaction_state::{
    self, DomainRecoveryImageComparisonDataV1,
};

use crate::journal::{
    CacheMutationGateV1, GlobalCapacityReservationPurposeV1,
    GlobalCapacityReservationRecoveryBindingV1, GlobalCapacityReservationRequestV1,
    GlobalCapacityReservationV1, HeldCacheMutationGateV1, Journal, JournalError, JournalLimits,
    JournalRecord, JournalTransaction, PreparedGlobalCapacityReservationV1,
    ProtectedJournalPreflight, RecordNamespace, capacity_reservation_identity_is_exact_v1,
};

#[cfg(test)]
use aos_sandbox_protocol::domain_ledger::records::encode_reducer_payload_with_validator;
use aos_sandbox_protocol::domain_ledger::records::{
    ProtectedCurrentRecordCandidateV1, aggregate_semantic_phases, capacity_request_binds_schema,
    decode_reducer_payload_with_validator,
    encode_checkpoint_payload,
    replay_projection_records, validate_domain_capacity_lineage_v1,
};
use aos_sandbox_protocol::domain_ledger::records::{
    ProtectedCapacitySettlementMemberV1, ProtectedDomainEnvelopeV1, ProtectedDomainKeyV1,
    ProtectedDomainProjectionV1, ProtectedDomainReplayPhaseV1, ProtectedDomainSchemaV1,
    DomainPreparedTransactionDataV1, ResidentCanonicalPayloadBudgetDataV1,
    ProtectedRecordRoleV1, ProtectedReducerPhaseV1,
};

use aos_sandbox_protocol::domain_ledger::records::current_record_candidates_from_rows;
use aos_sandbox_protocol::domain_ledger::{DomainLedgerDataError, JournalTransactionDataError};

/// Bounds additional retained canonical byte payloads, without granting authority.
///
/// The current Journal graph is independently bounded and is not charged once
/// per leg. This does not measure decoded containers or allocator overhead.
pub(crate) struct ResidentDomainPayloadBudgetV1 {
    data: ResidentCanonicalPayloadBudgetDataV1,
}

impl ResidentDomainPayloadBudgetV1 {
    pub(crate) const fn new(maximum: usize) -> Self {
        Self { data: ResidentCanonicalPayloadBudgetDataV1::new(maximum) }
    }

    pub(crate) const fn retained(&self) -> usize {
        self.data.retained()
    }

    /// Reserves aggregate canonical bytes before retaining another member.
    ///
    /// # Errors
    /// Refuses overflow or exhaustion without changing the prior reservation.
    pub(crate) fn reserve(&mut self, bytes: usize) -> Result<(), ProtectedDomainJournalErrorV1> {
        self.data.reserve(bytes).map_err(ProtectedDomainJournalErrorV1::from)
    }
}

#[cfg(test)]
mod resident_payload_tests {
    use super::*;

    #[test]
    fn completed_leg_payloads_share_one_checked_ceiling() {
        let mut budget = ResidentDomainPayloadBudgetV1::new(13);

        budget.reserve(5).unwrap();
        budget.reserve(8).unwrap();
        let returned = budget.reserve(1);

        assert!(matches!(
            returned,
            Err(ProtectedDomainJournalErrorV1::Journal(
                JournalError::LimitExceeded("resident canonical payload bytes")
            ))
        ));
        assert_eq!(budget.retained(), 13);
    }

    #[test]
    fn payload_overflow_does_not_replace_prior_retention() {
        let mut budget = ResidentDomainPayloadBudgetV1::new(usize::MAX);
        budget.reserve(usize::MAX).unwrap();

        assert!(budget.reserve(1).is_err());
        assert_eq!(budget.retained(), usize::MAX);
    }
}
#[cfg(test)]
mod data_error_projection_tests {
    use super::*;
    use aos_sandbox_journal::framing::FrameError;

    #[test]
    fn domain_data_errors_preserve_original_adapter_classes_and_native_cause() {
        let cases = [
            (
                DomainLedgerDataError::NonCanonicalRecord,
                ProtectedDomainJournalErrorV1::NonCanonicalRecord,
            ),
            (
                DomainLedgerDataError::CompareAndSwapFailed,
                ProtectedDomainJournalErrorV1::CompareAndSwapFailed,
            ),
            (
                DomainLedgerDataError::Transaction(JournalTransactionDataError::InvalidTransaction),
                ProtectedDomainJournalErrorV1::Journal(JournalError::InvalidTransaction),
            ),
        ];
        for (data, expected) in cases {
            let actual = ProtectedDomainJournalErrorV1::from(data);

            assert_eq!(
                std::mem::discriminant(&actual),
                std::mem::discriminant(&expected)
            );
            assert_eq!(actual.to_string(), expected.to_string());
        }

        let original = std::io::Error::other(std::io::Error::from_raw_os_error(9));
        let cause = original.get_ref().unwrap() as *const _;
        let projected = ProtectedDomainJournalErrorV1::from(DomainLedgerDataError::Transaction(
            JournalTransactionDataError::Frame(FrameError::Io(original)),
        ));
        let ProtectedDomainJournalErrorV1::Journal(JournalError::Io(actual)) = projected else {
            panic!("domain DATA projection changed original nested native cause");
        };

        assert!(std::ptr::eq(cause, actual.get_ref().unwrap() as *const _));
        assert_eq!(
            actual
                .get_ref()
                .unwrap()
                .downcast_ref::<std::io::Error>()
                .unwrap()
                .raw_os_error(),
            Some(9)
        );
    }
}

#[cfg(test)]
mod retained_tests;

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

/// Holds one exact domain admission transaction joined to retained capacity.
#[must_use = "a capacity-reserved admission must be committed or deliberately discarded"]
pub struct PreparedCapacityReservedDomainTransactionV1<S: ProtectedDomainSchemaV1> {
    prepared: PreparedDomainTransactionV1<S>,
    combined: JournalTransaction,
    request: GlobalCapacityReservationRequestV1,
    reservation_id: [u8; 32],
    reservation: PreparedGlobalCapacityReservationV1,
    preflight: ProtectedJournalPreflight,
}

/// Retains exact capacity admission state after an ambiguous durable append.
#[must_use = "capacity admission ambiguity must be resolved against protected reopen"]
pub struct DomainCapacityAdmissionUnknownV1<S: ProtectedDomainSchemaV1> {
    prepared: PreparedDomainTransactionV1<S>,
    combined: JournalTransaction,
    request: GlobalCapacityReservationRequestV1,
    reservation_id: [u8; 32],
}

/// Holds one move-only terminal-capacity authority without exposing the journal.
#[must_use = "reserved capacity must be consumed by one exact terminal settlement"]
pub struct DomainCapacityReservationV1<S: ProtectedDomainSchemaV1> {
    reservation: GlobalCapacityReservationV1,
    request: GlobalCapacityReservationRequestV1,
    admission_transaction_id: [u8; 16],
    marker: PhantomData<S>,
}

impl<S: ProtectedDomainSchemaV1> DomainCapacityReservationV1<S> {
    /// Returns the authenticated request and admission transaction for lineage checks.
    #[must_use]
    pub const fn authenticated_binding(&self) -> (GlobalCapacityReservationRequestV1, [u8; 16]) {
        (self.request, self.admission_transaction_id)
    }

    /// Returns the authenticated deterministic reservation identity.
    #[must_use]
    pub const fn reservation_id(&self) -> [u8; 32] {
        self.reservation.reservation_id()
    }

    /// Returns the authenticated digest of the exact admitted domain transaction.
    #[must_use]
    pub(crate) const fn owner_digest(&self) -> ObjectDigest {
        ObjectDigest::from_bytes(self.request.owner_digest)
    }

    /// Returns the authenticated transaction ID that admitted the reservation.
    #[must_use]
    pub(crate) const fn admission_transaction_id(&self) -> [u8; 16] {
        self.admission_transaction_id
    }
}

/// Holds one exact terminal domain transaction and its capacity deletion.
#[must_use = "a reserved terminal transaction must be committed or deliberately discarded"]
pub struct PreparedCapacitySettlementDomainTransactionV1<S: ProtectedDomainSchemaV1> {
    prepared: PreparedDomainTransactionV1<S>,
    combined: JournalTransaction,
    reservation: DomainCapacityReservationV1<S>,
    preflight: ProtectedJournalPreflight,
}

/// Retains an exact reserved terminal transaction after ambiguous durability.
#[must_use = "capacity settlement ambiguity must be resolved against protected reopen"]
pub struct DomainCapacitySettlementUnknownV1<S: ProtectedDomainSchemaV1> {
    prepared: PreparedDomainTransactionV1<S>,
    combined: JournalTransaction,
    request: GlobalCapacityReservationRequestV1,
    admission_transaction_id: [u8; 16],
    reservation_id: [u8; 32],
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
pub use aos_sandbox_protocol::domain_ledger::records::DomainPostcommitRecordDataV1
    as DomainPostcommitRecordV1;

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

/// Retains a prepared transaction when commit preflight fails before mutation.
#[must_use]
pub enum DomainRetainedCommitV1<S: ProtectedDomainSchemaV1> {
    /// Commit reached its ordinary applied or outcome-unknown classification.
    Outcome(DomainCommitOutcomeV1<S>),
    /// Preflight failed without consuming the exact prepared transaction.
    Retryable {
        /// Exact transaction remains move-only retry custody.
        prepared: PreparedDomainTransactionV1<S>,
        /// Fail-closed preflight diagnostic.
        error: ProtectedDomainJournalErrorV1,
    },
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

/// Distinguishes capacity-reserved admission success from ambiguous durability.
#[must_use = "ambiguous capacity admissions must retain their recovery token"]
pub enum DomainCapacityAdmissionCommitOutcomeV1<S: ProtectedDomainSchemaV1> {
    /// Domain successors and their global reservation were read back exactly.
    Applied {
        /// Carries the ordinary exact-readback domain result.
        domain: AppliedDomainTransactionV1<S>,
        /// Authorizes one later bounded terminal settlement.
        reservation: DomainCapacityReservationV1<S>,
    },
    /// Admission may or may not have reached durable storage.
    OutcomeUnknown {
        /// Retains the exact domain and capacity admission transaction.
        pending: DomainCapacityAdmissionUnknownV1<S>,
        /// Reports the underlying append or synchronization failure.
        cause: JournalError,
    },
}

/// Classifies protected-reopen recovery of a capacity admission.
#[must_use = "recovered capacity admission state must be applied, retried, or quarantined"]
pub enum DomainCapacityAdmissionRecoveryV1<S: ProtectedDomainSchemaV1> {
    /// Reopen found the exact domain successors and reservation.
    Applied {
        /// Carries the ordinary exact-readback domain result.
        domain: AppliedDomainTransactionV1<S>,
        /// Authorizes one later bounded terminal settlement.
        reservation: DomainCapacityReservationV1<S>,
    },
    /// Reopen found every predecessor and no reservation.
    Retry(PreparedCapacityReservedDomainTransactionV1<S>),
    /// Reopen found mixed, substituted, or incomplete state.
    Diverged(DomainCapacityAdmissionUnknownV1<S>),
}

/// Distinguishes capacity settlement success from ambiguous durability.
#[must_use = "ambiguous capacity settlements must retain their recovery token"]
pub enum DomainCapacitySettlementCommitOutcomeV1<S: ProtectedDomainSchemaV1> {
    /// Terminal domain successors were read back and capacity was released.
    Applied(AppliedDomainTransactionV1<S>),
    /// Settlement may or may not have reached durable storage.
    OutcomeUnknown {
        /// Retains the exact terminal transaction and reservation identity.
        pending: DomainCapacitySettlementUnknownV1<S>,
        /// Reports the underlying append or synchronization failure.
        cause: JournalError,
    },
}

/// Classifies protected-reopen recovery of a capacity settlement.
#[must_use = "recovered capacity settlement must be applied, retried, or quarantined"]
pub enum DomainCapacitySettlementRecoveryV1<S: ProtectedDomainSchemaV1> {
    /// Reopen found terminal successors and no retained reservation.
    Applied(AppliedDomainTransactionV1<S>),
    /// Reopen found every predecessor and the exact retained reservation.
    Retry(PreparedCapacitySettlementDomainTransactionV1<S>),
    /// Reopen found mixed, substituted, or incomplete state.
    Diverged(DomainCapacitySettlementUnknownV1<S>),
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
            self.journal.historical_read_view_v1(), transaction_id, &self.validator,
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
        Ok(encode_checkpoint_payload::<S>(snapshot.sequence, snapshot.root))
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
        ).map_err(ProtectedDomainJournalErrorV1::from)
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
        self.plan_with_source_selection_v1(transaction_id, successors, gate, None)
    }

    pub(crate) fn plan_with_source_provisioning_v1(
        &self, transaction_id: [u8; 16], successors: Vec<ProtectedDomainEnvelopeV1<S>>,
        original: &crate::controller_resource_reservation::SourceAdmissionAuthorizationV1<'_>,
    ) -> Result<PreparedDomainTransactionV1<S>, ProtectedDomainJournalErrorV1> {
        self.plan_with_source_selection_v1(transaction_id, successors,
            CacheMutationGateV1::Ordinary, Some(crate::controller_resource_reservation::SourceAppendBoundaryV1::Create(original)))
    }

    pub(crate) fn plan_with_start_source_v1(
        &self,transaction_id:[u8;16],successors:Vec<ProtectedDomainEnvelopeV1<S>>,
        original:&crate::controller_resource_reservation::StartSourceAdmissionAuthorizationV1<'_>,
    )->Result<PreparedDomainTransactionV1<S>,ProtectedDomainJournalErrorV1> {
        self.plan_with_source_selection_v1(transaction_id,successors,CacheMutationGateV1::Ordinary,
            Some(crate::controller_resource_reservation::SourceAppendBoundaryV1::Start(original)))
    }

    fn plan_with_source_selection_v1(
        &self, transaction_id: [u8; 16], successors: Vec<ProtectedDomainEnvelopeV1<S>>,
        mut gate: CacheMutationGateV1<'_>,
        source: Option<crate::controller_resource_reservation::SourceAppendBoundaryV1<'_>>,
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
        if let Some(original) = source {
            let loan = self.journal.source_provisioning_loan_v1(original, members.transaction())?;
            CacheMutationGateV1::SourceProvisioning(loan)
                .preflight(self.journal, std::slice::from_ref(members.transaction()))?;
        } else {
            gate.preflight(self.journal, std::slice::from_ref(members.transaction()))?;
        }
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

    /// Commits with an independently configured protected-name check at both
    /// sides of the durability boundary. Post-commit name loss is ambiguous.
    pub(crate) fn commit_at_named_location(
        &mut self,
        prepared: PreparedDomainTransactionV1<S>,
        directory: &Path,
        name: &str,
        expected_uid: u32,
        limits: JournalLimits,
    ) -> Result<DomainCommitOutcomeV1<S>, ProtectedDomainJournalErrorV1> {
        self.commit_with_check(prepared, |journal| {
            journal.require_protected_named_location(directory, name, expected_uid, limits)
        })
    }

    #[cfg(test)]
    pub(crate) fn commit_with_test_check(
        &mut self,
        prepared: PreparedDomainTransactionV1<S>,
        check: impl FnMut(&Journal) -> Result<(), JournalError>,
    ) -> Result<DomainCommitOutcomeV1<S>, ProtectedDomainJournalErrorV1> {
        self.commit_with_check(prepared, check)
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
                    cause: JournalError::AuthorityPreflightMismatch,
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

    fn commit_with_custody(
        &mut self,
        prepared: PreparedDomainTransactionV1<S>,
        mut check: impl FnMut(&Journal) -> Result<(), JournalError>,
        mut gate: CacheMutationGateV1<'_>,
    ) -> Result<DomainCommitOutcomeV1<S>, DomainRetainedCommitFailureV1<S>> {
        let before = self.check_prepared_before_append(&prepared, &mut gate, &mut check);
        if let Err(cause) = before {
            return Err(RetainedCommitFailureV1::BeforeJournalAppend { prepared, cause });
        }
        if let Err(cause) = gate.commit(self.journal, &prepared.data.transaction) {
            return Ok(DomainCommitOutcomeV1::OutcomeUnknown {
                pending: DomainOutcomeUnknownV1 { prepared },
                cause,
            });
        }
        if let Err(cause) = validate_expected_values(self.journal, &prepared, true) {
            return Err(RetainedCommitFailureV1::AfterAppendReadback {
                pending: DomainOutcomeUnknownV1 { prepared },
                cause,
            });
        }
        if let Err(cause) = check(self.journal) {
            return Ok(DomainCommitOutcomeV1::OutcomeUnknown {
                pending: DomainOutcomeUnknownV1 { prepared },
                cause,
            });
        }
        self.applied_retaining(prepared)
            .map(DomainCommitOutcomeV1::Applied)
            .map_err(
                |(prepared, cause)| RetainedCommitFailureV1::AfterAppendSealing {
                    pending: DomainOutcomeUnknownV1 { prepared },
                    cause,
                },
            )
    }

    fn check_prepared_before_append(
        &self,
        prepared: &PreparedDomainTransactionV1<S>,
        gate: &mut CacheMutationGateV1<'_>,
        check: &mut impl FnMut(&Journal) -> Result<(), JournalError>,
    ) -> Result<(), ProtectedDomainJournalErrorV1> {
        self.validate_snapshot(&prepared.snapshot)?;
        validate_expected_values(self.journal, prepared, false)?;
        gate.preflight(self.journal, std::slice::from_ref(&prepared.data.transaction))?;
        check(self.journal)?;
        Ok(())
    }

    pub(crate) fn commit_resident_source_prepared_v1(
        &mut self, prepared: &PreparedDomainTransactionV1<S>,
        original: &crate::controller_resource_reservation::SourceAdmissionAuthorizationV1<'_>,
    ) -> Result<AppliedDomainTransactionV1<S>, ResidentDomainCommitFailureV1> {
        let loan = self.journal.source_provisioning_loan_v1(
            crate::controller_resource_reservation::SourceAppendBoundaryV1::Create(original), prepared.journal_transaction_v1())
            .map_err(|cause| ResidentDomainCommitFailureV1::Before(cause.into()))?;
        self.commit_resident_prepared(prepared, CacheMutationGateV1::SourceProvisioning(loan))
    }

    pub(crate) fn commit_resident_start_source_prepared_v1(
        &mut self,prepared:&PreparedDomainTransactionV1<S>,
        original:&crate::controller_resource_reservation::StartSourceAdmissionAuthorizationV1<'_>,
    )->Result<AppliedDomainTransactionV1<S>,ResidentDomainCommitFailureV1> {
        let loan=self.journal.source_provisioning_loan_v1(
            crate::controller_resource_reservation::SourceAppendBoundaryV1::Start(original),
            prepared.journal_transaction_v1())
            .map_err(|cause|ResidentDomainCommitFailureV1::Before(cause.into()))?;
        self.commit_resident_prepared(prepared,CacheMutationGateV1::SourceProvisioning(loan))
    }

    pub(crate) fn commit_resident_stop_cleanup_prepared_v1(
        &mut self, prepared: &PreparedDomainTransactionV1<S>,
        native: &mut aos_sandbox_broker::source_receiving::SourceProvisioningCurrentnessOriginalV1,
        original: &crate::controller_lifecycle_stop::StopCleanupSourceAppendAuthorizationV1<'_>,
    ) -> Result<AppliedDomainTransactionV1<S>, ResidentDomainCommitFailureV1> {
        original.bind_prepared_source_once_v1(self.journal, native, prepared.journal_transaction_v1())
            .map_err(|cause| ResidentDomainCommitFailureV1::Before(cause.into()))?;
        self.commit_resident_prepared(prepared, CacheMutationGateV1::StopCleanupSource(original))
    }

    pub(crate) fn require_stop_cleanup_published_v1(
        &self, prepared: &PreparedDomainTransactionV1<S>,
        native: &mut aos_sandbox_broker::source_receiving::SourceProvisioningCurrentnessOriginalV1,
        original: &crate::controller_lifecycle_stop::StopCleanupSourceAppendAuthorizationV1<'_>,
    ) -> Result<(), JournalError> {
        original.require_published_source_successor_once_v1(self.journal, native, prepared.journal_transaction_v1())
    }

    /// Appends while borrowing the resident Prepared instead of taking it.
    ///
    /// The caller parks this complete Result before any final owner checks.
    /// An append failure keeps both exact before/after bytes and its native
    /// error in the same resident owner; it is not retry authorization.
    ///
    /// # Errors
    /// Returns the first preappend, append, readback or sealing failure.
    pub(crate) fn commit_resident_prepared(
        &mut self,
        prepared: &PreparedDomainTransactionV1<S>,
        mut gate: CacheMutationGateV1<'_>,
    ) -> Result<AppliedDomainTransactionV1<S>, ResidentDomainCommitFailureV1> {
        self.check_prepared_before_append(prepared, &mut gate, &mut |_| Ok(()))
            .map_err(ResidentDomainCommitFailureV1::Before)?;
        gate.commit(self.journal, &prepared.data.transaction)
            .map_err(ResidentDomainCommitFailureV1::Append)?;
        validate_expected_values(self.journal, prepared, true)
            .map_err(ResidentDomainCommitFailureV1::Readback)?;
        self.applied_borrowed(prepared)
            .map_err(ResidentDomainCommitFailureV1::Sealing)
    }

    /// Commits while retaining the exact prepared token on preflight failure.
    pub fn commit_retaining(
        &mut self,
        mut prepared: PreparedDomainTransactionV1<S>,
    ) -> DomainRetainedCommitV1<S> {
        if self.validate_snapshot(&prepared.snapshot).is_err() {
            if let Err(error) = self.replay() {
                return DomainRetainedCommitV1::Retryable { prepared, error };
            }
            if values_match(self.journal, &prepared, true) {
                return match self.applied_retaining(prepared) {
                    Ok(applied) => {
                        DomainRetainedCommitV1::Outcome(DomainCommitOutcomeV1::Applied(applied))
                    }
                    Err((prepared, _)) => {
                        DomainRetainedCommitV1::Outcome(DomainCommitOutcomeV1::OutcomeUnknown {
                            pending: DomainOutcomeUnknownV1 { prepared },
                            cause: JournalError::AuthorityPreflightMismatch,
                        })
                    }
                };
            }
            if !values_match(self.journal, &prepared, false) {
                return DomainRetainedCommitV1::Retryable {
                    prepared,
                    error: ProtectedDomainJournalErrorV1::CompareAndSwapFailed,
                };
            }
            prepared.snapshot = match self.snapshot() {
                Ok(snapshot) => snapshot,
                Err(error) => return DomainRetainedCommitV1::Retryable { prepared, error },
            };
        }
        if let Err(error) = validate_expected_values(self.journal, &prepared, false) {
            return DomainRetainedCommitV1::Retryable { prepared, error };
        }
        if let Err(error) = self
            .journal
            .preflight_transactions(std::slice::from_ref(&prepared.data.transaction))
            .map_err(ProtectedDomainJournalErrorV1::from)
        {
            return DomainRetainedCommitV1::Retryable { prepared, error };
        }
        if let Err(cause) = self.journal.commit(&prepared.data.transaction) {
            return DomainRetainedCommitV1::Outcome(DomainCommitOutcomeV1::OutcomeUnknown {
                pending: DomainOutcomeUnknownV1 { prepared },
                cause,
            });
        }
        if validate_expected_values(self.journal, &prepared, true).is_err() {
            return DomainRetainedCommitV1::Outcome(DomainCommitOutcomeV1::OutcomeUnknown {
                pending: DomainOutcomeUnknownV1 { prepared },
                cause: JournalError::AuthorityPreflightMismatch,
            });
        }
        match self.applied_retaining(prepared) {
            Ok(applied) => DomainRetainedCommitV1::Outcome(DomainCommitOutcomeV1::Applied(applied)),
            Err((prepared, _)) => {
                DomainRetainedCommitV1::Outcome(DomainCommitOutcomeV1::OutcomeUnknown {
                    pending: DomainOutcomeUnknownV1 { prepared },
                    cause: JournalError::AuthorityPreflightMismatch,
                })
            }
        }
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
                self.journal.historical_read_view_v1(), &prepared.data,
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

    /// Classifies the same pending event without reopening a resident writer.
    ///
    /// A before image must still match its original snapshot and pass the same
    /// gate and preflight. Classification is not permission to retry an effect.
    pub(crate) fn recover_retaining_with_cache_gate(
        &self,
        pending: DomainOutcomeUnknownV1<S>,
        mut gate: CacheMutationGateV1<'_>,
    ) -> DomainRetainedRecoveryV1<S> {
        if let Err(error) = self.replay() {
            return DomainRetainedRecoveryV1::Retryable { pending, error };
        }
        let prepared = pending.prepared;
        let DomainRecoveryImageComparisonDataV1 { before, after } =
            transaction_state::compare_recovery_images_v1(
                self.journal.historical_read_view_v1(), &prepared.data,
            );
        if after {
            return match self.applied_retaining(prepared) {
                Ok(applied) => {
                    DomainRetainedRecoveryV1::Outcome(DomainRecoveryV1::Applied(applied))
                }
                Err((prepared, error)) => DomainRetainedRecoveryV1::Retryable {
                    pending: DomainOutcomeUnknownV1 { prepared },
                    error,
                },
            };
        }
        if before {
            let mut prepared = prepared;
            if matches!(&gate, CacheMutationGateV1::Ordinary) {
                prepared.snapshot = match self.snapshot() {
                    Ok(snapshot) => snapshot,
                    Err(error) => {
                        return DomainRetainedRecoveryV1::Retryable {
                            pending: DomainOutcomeUnknownV1 { prepared },
                            error,
                        };
                    }
                };
            } else if let Err(error) = self.validate_snapshot(&prepared.snapshot) {
                return DomainRetainedRecoveryV1::Retryable {
                    pending: DomainOutcomeUnknownV1 { prepared },
                    error,
                };
            }
            if let Err(error) = gate
                .preflight(self.journal, std::slice::from_ref(&prepared.data.transaction))
                .map_err(ProtectedDomainJournalErrorV1::from)
            {
                return DomainRetainedRecoveryV1::Retryable {
                    pending: DomainOutcomeUnknownV1 { prepared },
                    error,
                };
            }
            return DomainRetainedRecoveryV1::Outcome(DomainRecoveryV1::Retry(prepared));
        }
        DomainRetainedRecoveryV1::Outcome(DomainRecoveryV1::Diverged(DomainOutcomeUnknownV1 {
            prepared,
        }))
    }

    fn validate_snapshot(
        &self,
        snapshot: &ProtectedDomainSnapshotV1<S>,
    ) -> Result<(), ProtectedDomainJournalErrorV1> {
        let current = self.snapshot()?;
        if !Arc::ptr_eq(&snapshot.instance, &self.instance)
            || snapshot.sequence != current.sequence
            || snapshot.root != current.root
        {
            return Err(ProtectedDomainJournalErrorV1::StaleAuthority);
        }
        Ok(())
    }

    fn applied(
        &self,
        prepared: PreparedDomainTransactionV1<S>,
    ) -> Result<AppliedDomainTransactionV1<S>, ProtectedDomainJournalErrorV1> {
        self.applied_borrowed(&prepared)
    }

    fn applied_borrowed(
        &self,
        prepared: &PreparedDomainTransactionV1<S>,
    ) -> Result<AppliedDomainTransactionV1<S>, ProtectedDomainJournalErrorV1> {
        let snapshot = self.snapshot()?;
        let records = postcommit_records(prepared, &self.validator)?;
        let capability = Some(DomainPostcommitCapabilityV1 {
            instance: Arc::clone(&self.instance),
            transaction: prepared.data.digest,
            set_digest: prepared.data.set_digest,
            sequence: snapshot.sequence,
            root: snapshot.root,
            records,
            marker: PhantomData,
        });
        Ok(AppliedDomainTransactionV1 {
            transaction: prepared.data.digest,
            snapshot,
            capability,
        })
    }

    fn applied_retaining(
        &self,
        prepared: PreparedDomainTransactionV1<S>,
    ) -> Result<
        AppliedDomainTransactionV1<S>,
        (
            PreparedDomainTransactionV1<S>,
            ProtectedDomainJournalErrorV1,
        ),
    > {
        let snapshot = match self.snapshot() {
            Ok(snapshot) => snapshot,
            Err(error) => return Err((prepared, error)),
        };
        let records = match postcommit_records(&prepared, &self.validator) {
            Ok(records) => records,
            Err(error) => return Err((prepared, error)),
        };
        let capability = Some(DomainPostcommitCapabilityV1 {
            instance: Arc::clone(&self.instance),
            transaction: prepared.data.digest,
            set_digest: prepared.data.set_digest,
            sequence: snapshot.sequence,
            root: snapshot.root,
            records,
            marker: PhantomData,
        });
        Ok(AppliedDomainTransactionV1 {
            transaction: prepared.data.digest,
            snapshot,
            capability,
        })
    }
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
                authority.journal.historical_read_view_v1(), &self.records,
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
        &prepared.data.transaction, &prepared.data.roles, &prepared.data.after, validator,
    ).map_err(ProtectedDomainJournalErrorV1::from)
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
        journal.historical_read_view_v1(), &prepared.data, after,
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


impl<S: ProtectedDomainSchemaV1> AppliedDomainTransactionV1<S> {
    // An actual positive owner first consumes its unused composite. Its Arc
    // snapshot then retains only this private adapter allocation; no row or
    // native owner is replaced with a reconstructed success value.
    pub(crate) fn completed_resident_backing_bytes_v1(&self) -> Option<usize> {
        if self.capability.is_some() { return None; }
        std::mem::size_of::<AdapterInstanceV1>()
            .checked_add(2 * std::mem::size_of::<usize>())
    }
}
