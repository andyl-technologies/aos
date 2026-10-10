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

use std::marker::PhantomData;
use std::path::Path;
use std::sync::Arc;

use aos_sandbox_core::ObjectDigest;

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
    DURABLE_MEMBER_FIXED_BYTES, ENVELOPE_FIXED_BYTES, MAXIMUM_COLD_REPLAY_MEMBERS,
    ProtectedCurrentRecordCandidateV1, aggregate_semantic_phases, capacity_request_binds_schema,
    decode_durable_member, decode_reducer_payload_with_validator, domain_transaction_set_digest,
    encode_checkpoint_payload, encode_durable_member, reconstruct_transactions, reducer_phase,
    replay_projection_records, transaction_digest, validate_domain_capacity_lineage_v1,
    validate_successor,
};
use aos_sandbox_protocol::domain_ledger::records::{
    ProtectedCapacitySettlementMemberV1, ProtectedDomainEnvelopeV1, ProtectedDomainKeyV1,
    ProtectedDomainProjectionV1, ProtectedDomainReplayPhaseV1, ProtectedDomainSchemaV1,
    ProtectedRecordRoleV1, ProtectedReducerPhaseV1,
};

use aos_sandbox_protocol::domain_ledger::records::current_record_candidates_from_rows;
use aos_sandbox_protocol::domain_ledger::{DomainLedgerDataError, JournalTransactionDataError};

/// Bounds additional retained canonical byte payloads, without granting authority.
///
/// The current Journal graph is independently bounded and is not charged once
/// per leg. This does not measure decoded containers or allocator overhead.
pub(crate) struct ResidentDomainPayloadBudgetV1 {
    maximum: usize,
    retained: usize,
}

impl ResidentDomainPayloadBudgetV1 {
    pub(crate) const fn new(maximum: usize) -> Self {
        Self {
            maximum,
            retained: 0,
        }
    }

    pub(crate) const fn retained(&self) -> usize {
        self.retained
    }

    /// Reserves aggregate canonical bytes before retaining another member.
    ///
    /// # Errors
    /// Refuses overflow or exhaustion without changing the prior reservation.
    pub(crate) fn reserve(&mut self, bytes: usize) -> Result<(), ProtectedDomainJournalErrorV1> {
        let retained = self
            .retained
            .checked_add(bytes)
            .filter(|bytes| *bytes <= self.maximum)
            .ok_or(JournalError::LimitExceeded("resident canonical payload bytes"))?;
        self.retained = retained;
        Ok(())
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
    transaction: JournalTransaction,
    before: Vec<Option<Vec<u8>>>,
    after: Vec<Vec<u8>>,
    roles: Vec<ProtectedRecordRoleV1>,
    digest: ObjectDigest,
    set_digest: ObjectDigest,
}

impl<S: ProtectedDomainSchemaV1> PreparedDomainTransactionV1<S> {
    /// Borrows prepared canonical members for a same-owner atomic composition.
    ///
    /// These records retain the existing framing and digest algorithm; they
    /// grant no commit, postcommit, live custody or publication authority.
    pub(crate) fn journal_records(&self) -> &[JournalRecord] {
        self.transaction.records()
    }

    /// Returns the stable transaction identifier bound into durable members.
    #[must_use]
    pub const fn transaction_id(&self) -> [u8; 16] {
        *self.transaction.id()
    }

    /// Returns the exact canonical domain transaction commitment.
    #[must_use]
    pub const fn transaction_digest(&self) -> ObjectDigest {
        self.digest
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

/// Retains one exact typed envelope proven by postcommit readback.
#[derive(Debug)]
pub struct DomainPostcommitRecordV1<S: ProtectedDomainSchemaV1> {
    namespace: RecordNamespace,
    role: ProtectedRecordRoleV1,
    phase: ProtectedReducerPhaseV1,
    transaction_phase: ProtectedReducerPhaseV1,
    envelope: ProtectedDomainEnvelopeV1<S>,
    encoded: Vec<u8>,
}

impl<S: ProtectedDomainSchemaV1> DomainPostcommitRecordV1<S> {
    /// Returns the fixed shared-journal namespace selected by the domain kind.
    #[must_use]
    pub const fn namespace(&self) -> RecordNamespace {
        self.namespace
    }

    /// Returns the exact canonical envelope read back after durable commit.
    #[must_use]
    pub const fn envelope(&self) -> &ProtectedDomainEnvelopeV1<S> {
        &self.envelope
    }

    /// Reports whether decoded terminal state may publish protected current state.
    #[must_use]
    pub fn is_publication(&self) -> bool {
        matches!(self.role, ProtectedRecordRoleV1::Publication)
            && self.phase == ProtectedReducerPhaseV1::Terminal
            && self.transaction_phase == ProtectedReducerPhaseV1::Terminal
    }

    /// Reports whether decoded state still admits exactly one external effect.
    #[must_use]
    pub fn is_effect(&self) -> bool {
        matches!(self.role, ProtectedRecordRoleV1::Effect)
            && self.phase == ProtectedReducerPhaseV1::Prepared
            && self.transaction_phase == ProtectedReducerPhaseV1::Prepared
    }

    /// Returns the phase decoded from the canonical reducer body.
    #[must_use]
    pub const fn phase(&self) -> ProtectedReducerPhaseV1 {
        self.phase
    }
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
        let mut members = Vec::new();
        for (namespace, key_bytes, value) in self.journal.all_records() {
            if !key_bytes.starts_with(S::KEY_PREFIX) {
                continue;
            }
            let key = ProtectedDomainKeyV1::<S>::decode(key_bytes)?;
            if namespace != S::namespace(key.kind()) {
                return Err(ProtectedDomainJournalErrorV1::NonCanonicalRecord);
            }
            let member = decode_durable_member::<S>(key, value, &self.validator)?;
            if member.transaction_id() == transaction_id {
                if let Some(budget) = budget.as_deref_mut() {
                    // One retained encoded member and its decoded envelope.
                    // Reserve before keeping it beyond this bounded scan.
                    let payload = member
                        .encoded()
                        .len()
                        .checked_add(member.envelope().payload().len())
                        .and_then(|bytes| bytes.checked_add(member.envelope().key().as_bytes().len()))
                        .and_then(|bytes| bytes.checked_add(member.envelope().key().identity().len()))
                        .ok_or(JournalError::LimitExceeded("resident canonical payload bytes"))?;
                    budget.reserve(payload)?;
                }
                if members.len() >= MAXIMUM_COLD_REPLAY_MEMBERS {
                    return Err(ProtectedDomainJournalErrorV1::NonCanonicalRecord);
                }
                members.push(member);
            }
        }
        if members.is_empty() {
            return Ok(None);
        }
        members.sort_by_key(|member| member.member_index());
        let transactions = reconstruct_transactions::<S>(&members)?;
        let transaction = transactions
            .into_iter()
            .next()
            .ok_or(ProtectedDomainJournalErrorV1::NonCanonicalRecord)?;
        if transaction.transaction_id() != transaction_id
            || transaction.phase() == ProtectedDomainReplayPhaseV1::Incomplete
            || transaction.phase() == ProtectedDomainReplayPhaseV1::Observed
            || transaction.phase() == ProtectedDomainReplayPhaseV1::Superseded
        {
            return Ok(None);
        }
        let transaction_digest = transaction.transaction_digest();
        let set_digest = transaction.set_digest();
        let mut records = Vec::with_capacity(members.len());
        for member in members {
            let namespace = S::namespace(member.envelope().key().kind());
            let role = S::role(member.envelope().key().kind());
            let phase = reducer_phase(member.envelope())?;
            let transaction_phase = match transaction.phase() {
                ProtectedDomainReplayPhaseV1::Prepared => ProtectedReducerPhaseV1::Prepared,
                ProtectedDomainReplayPhaseV1::Observed => ProtectedReducerPhaseV1::Observed,
                ProtectedDomainReplayPhaseV1::Terminal => ProtectedReducerPhaseV1::Terminal,
                ProtectedDomainReplayPhaseV1::Superseded => ProtectedReducerPhaseV1::Superseded,
                ProtectedDomainReplayPhaseV1::Incomplete => return Ok(None),
            };
            let (_, _, _, _, envelope, encoded) = member.into_parts();
            records.push(DomainPostcommitRecordV1 {
                namespace,
                role,
                phase,
                transaction_phase,
                envelope,
                encoded,
            });
        }
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
        mut successors: Vec<ProtectedDomainEnvelopeV1<S>>,
        mut gate: CacheMutationGateV1<'_>,
    ) -> Result<PreparedDomainTransactionV1<S>, ProtectedDomainJournalErrorV1> {
        let snapshot = self.snapshot()?;
        successors.sort_by(|left, right| {
            (S::order(left.key().kind()), left.key().as_bytes())
                .cmp(&(S::order(right.key().kind()), right.key().as_bytes()))
        });
        if successors.is_empty()
            || successors.windows(2).any(|pair| pair[0].key() == pair[1].key())
            || (successors.len() != 1
                && successors
                    .iter()
                    .any(|successor| S::is_checkpoint(successor.key().kind())))
        {
            return Err(ProtectedDomainJournalErrorV1::NonCanonicalRecord);
        }

        let mut records = Vec::with_capacity(successors.len());
        let mut before = Vec::with_capacity(successors.len());
        let mut after = Vec::with_capacity(successors.len());
        let mut roles = Vec::with_capacity(successors.len());
        let member_count = u16::try_from(successors.len())
            .map_err(|_| ProtectedDomainJournalErrorV1::NonCanonicalRecord)?;
        let set_digest = domain_transaction_set_digest::<S>(transaction_id, &successors);
        let mut checkpoint = false;
        for (index, successor) in successors.into_iter().enumerate() {
            if S::is_checkpoint(successor.key().kind()) {
                if checkpoint || successor.payload() != encode_checkpoint_payload::<S>(snapshot.sequence, snapshot.root) {
                    return Err(ProtectedDomainJournalErrorV1::NonCanonicalRecord);
                }
                checkpoint = true;
            }
            let namespace = S::namespace(successor.key().kind());
            let previous = self.journal.get(namespace, successor.key().as_bytes());
            validate_successor(previous, &successor, &self.validator)?;
            let member_index = u16::try_from(index)
                .map_err(|_| ProtectedDomainJournalErrorV1::NonCanonicalRecord)?;
            let durable = encode_durable_member(
                transaction_id,
                member_index,
                member_count,
                set_digest,
                successor,
            )?;
            let key = durable.envelope().key().as_bytes().to_vec();
            let (_, _, _, _, envelope, encoded) = durable.into_parts();

            before.push(previous.map(<[u8]>::to_vec));
            after.push(encoded.clone());
            roles.push(S::role(envelope.key().kind()));
            records.push(JournalRecord::put(namespace, key, encoded));
        }
        let transaction = JournalTransaction::new(transaction_id, records)?;
        gate.preflight(self.journal, std::slice::from_ref(&transaction))?;
        let digest = transaction_digest::<S>(&transaction);
        Ok(PreparedDomainTransactionV1 {
            snapshot,
            transaction,
            before,
            after,
            roles,
            digest,
            set_digest,
        })
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
        let bytes = successors.iter().try_fold(0_usize, |sum, successor| {
            let key = successor.key().as_bytes();
            let previous = self
                .journal
                .get(S::namespace(successor.key().kind()), key)
                .map_or(0, <[u8]>::len);
            // Prepared: two new durable values + one old value + one key.
            // Postcommit: one encoded value + decoded payload + one key.
            let durable = successor
                .payload()
                .len()
                .checked_add(ENVELOPE_FIXED_BYTES)
                .and_then(|bytes| bytes.checked_add(DURABLE_MEMBER_FIXED_BYTES));
            durable
                .and_then(|bytes| bytes.checked_mul(3))
                .and_then(|bytes| bytes.checked_add(previous))
                .and_then(|bytes| bytes.checked_add(successor.payload().len()))
                .and_then(|bytes| key.len().checked_mul(2).and_then(|keys| bytes.checked_add(keys)))
                .and_then(|bytes| bytes.checked_add(successor.key().identity().len()))
                .and_then(|bytes| sum.checked_add(bytes))
                .ok_or(JournalError::LimitExceeded("resident canonical payload bytes"))
        })?;
        budget.reserve(bytes)
    }

    /// Joins an exact prepared domain admission to a global capacity reservation.
    ///
    /// The purpose guard validates the complete closed namespace set. Neither
    /// the underlying journal nor the prepared [`JournalTransaction`] leaves
    /// this engine.
    ///
    /// # Errors
    ///
    /// Returns an error for stale domain CAS state, an unbound request digest,
    /// a foreign purpose namespace set, or failed capacity preflight.
    pub fn prepare_capacity_reserved_admission(
        &mut self,
        prepared: PreparedDomainTransactionV1<S>,
        request: GlobalCapacityReservationRequestV1,
    ) -> Result<PreparedCapacityReservedDomainTransactionV1<S>, ProtectedDomainJournalErrorV1> {
        self.validate_snapshot(&prepared.snapshot)?;
        validate_expected_values(self.journal, &prepared, false)?;
        if request.owner_digest != *prepared.digest.as_bytes()
            || !capacity_request_binds_schema::<S>(&request)
        {
            return Err(ProtectedDomainJournalErrorV1::NonCanonicalRecord);
        }
        validate_capacity_domain_shape(&prepared.transaction, request.purpose)?;

        let transaction_id = *prepared.transaction.id();
        let authority = self
            .journal
            .claim_global_capacity_reservation_authority(request.purpose)?;
        let reservation =
            authority.prepare_global_capacity_reservation_v1(request, transaction_id)?;
        let reservation_id = reservation.reservation_id();
        let combined = capacity_admission_transaction(&prepared.transaction, reservation.record())?;
        let preflight =
            authority.preflight_global_capacity_reservation_v1(&reservation, &combined)?;

        Ok(PreparedCapacityReservedDomainTransactionV1 {
            prepared,
            combined,
            request,
            reservation_id,
            reservation,
            preflight,
        })
    }

    /// Commits an exact domain admission and capacity record atomically.
    ///
    /// # Errors
    ///
    /// Returns an error when the domain snapshot or predecessor values changed.
    /// Durability failures are returned as retained outcome-unknown state.
    pub fn commit_capacity_reserved_admission(
        &mut self,
        prepared: PreparedCapacityReservedDomainTransactionV1<S>,
    ) -> Result<DomainCapacityAdmissionCommitOutcomeV1<S>, ProtectedDomainJournalErrorV1> {
        self.validate_snapshot(&prepared.prepared.snapshot)?;
        validate_expected_values(self.journal, &prepared.prepared, false)?;
        if prepared.request.owner_digest != *prepared.prepared.digest.as_bytes()
            || !capacity_request_binds_schema::<S>(&prepared.request)
            || prepared.reservation_id != prepared.reservation.reservation_id()
            || capacity_admission_transaction(
                &prepared.prepared.transaction,
                prepared.reservation.record(),
            )? != prepared.combined
        {
            return Err(ProtectedDomainJournalErrorV1::NonCanonicalRecord);
        }
        validate_capacity_domain_shape(&prepared.prepared.transaction, prepared.request.purpose)?;

        let PreparedCapacityReservedDomainTransactionV1 {
            prepared: domain,
            combined,
            request,
            reservation_id,
            reservation,
            preflight,
        } = prepared;
        let commit = {
            let mut authority = self
                .journal
                .claim_global_capacity_reservation_authority(request.purpose)?;
            authority.commit_global_capacity_reservation_v1(&preflight, reservation, &combined)
        };
        let (_, reservation) = match commit {
            Ok(applied) => applied,
            Err(cause) => {
                return Ok(DomainCapacityAdmissionCommitOutcomeV1::OutcomeUnknown {
                    pending: DomainCapacityAdmissionUnknownV1 {
                        prepared: domain,
                        combined,
                        request,
                        reservation_id,
                    },
                    cause,
                });
            }
        };
        if validate_expected_values(self.journal, &domain, true).is_err()
            || !reservation.matches_request(&request, *domain.transaction.id())
            || reservation.reservation_id() != reservation_id
        {
            return Ok(DomainCapacityAdmissionCommitOutcomeV1::OutcomeUnknown {
                pending: DomainCapacityAdmissionUnknownV1 {
                    prepared: domain,
                    combined,
                    request,
                    reservation_id,
                },
                cause: JournalError::AuthorityPreflightMismatch,
            });
        }
        let admission_transaction_id = *domain.transaction.id();
        let domain = self.applied(domain)?;
        Ok(DomainCapacityAdmissionCommitOutcomeV1::Applied {
            domain,
            reservation: DomainCapacityReservationV1 {
                reservation,
                request,
                admission_transaction_id,
                marker: PhantomData,
            },
        })
    }

    /// Recovers one exact capacity admission after protected reopen.
    ///
    /// # Errors
    ///
    /// Returns an error when protected replay or the purpose authority cannot
    /// be validated. Mixed state is retained as [`DomainCapacityAdmissionRecoveryV1::Diverged`].
    pub fn recover_capacity_reserved_admission(
        &mut self,
        pending: DomainCapacityAdmissionUnknownV1<S>,
    ) -> Result<DomainCapacityAdmissionRecoveryV1<S>, ProtectedDomainJournalErrorV1> {
        self.replay()?;
        let DomainCapacityAdmissionUnknownV1 {
            mut prepared,
            combined,
            request,
            reservation_id,
        } = pending;
        let before = values_match(self.journal, &prepared, false);
        let after = values_match(self.journal, &prepared, true);
        let admission_transaction_id = *prepared.transaction.id();
        if !validate_domain_capacity_lineage_v1::<S>(
            &request,
            admission_transaction_id,
            reservation_id,
        ) {
            return Err(ProtectedDomainJournalErrorV1::NonCanonicalRecord);
        }

        if after {
            let reservation = {
                let authority = self
                    .journal
                    .claim_global_capacity_reservation_authority(request.purpose)?;
                authority.recover_global_capacity_reservation_v1(reservation_id)
            };
            if let Ok(reservation) = reservation {
                if reservation.matches_request(&request, admission_transaction_id) {
                    let domain = self.applied(prepared)?;
                    return Ok(DomainCapacityAdmissionRecoveryV1::Applied {
                        domain,
                        reservation: DomainCapacityReservationV1 {
                            reservation,
                            request,
                            admission_transaction_id,
                            marker: PhantomData,
                        },
                    });
                }
            }
            return Ok(DomainCapacityAdmissionRecoveryV1::Diverged(
                DomainCapacityAdmissionUnknownV1 {
                    prepared,
                    combined,
                    request,
                    reservation_id,
                },
            ));
        }

        if before {
            prepared.snapshot = self.snapshot()?;
            let (reservation, preflight) = {
                let authority = self
                    .journal
                    .claim_global_capacity_reservation_authority(request.purpose)?;
                let reservation = authority
                    .prepare_global_capacity_reservation_v1(request, admission_transaction_id)?;
                if reservation.reservation_id() != reservation_id
                    || capacity_admission_transaction(&prepared.transaction, reservation.record())?
                        != combined
                {
                    return Ok(DomainCapacityAdmissionRecoveryV1::Diverged(
                        DomainCapacityAdmissionUnknownV1 {
                            prepared,
                            combined,
                            request,
                            reservation_id,
                        },
                    ));
                }
                let preflight =
                    authority.preflight_global_capacity_reservation_v1(&reservation, &combined)?;
                (reservation, preflight)
            };
            return Ok(DomainCapacityAdmissionRecoveryV1::Retry(
                PreparedCapacityReservedDomainTransactionV1 {
                    prepared,
                    combined,
                    request,
                    reservation_id,
                    reservation,
                    preflight,
                },
            ));
        }

        Ok(DomainCapacityAdmissionRecoveryV1::Diverged(
            DomainCapacityAdmissionUnknownV1 {
                prepared,
                combined,
                request,
                reservation_id,
            },
        ))
    }

    /// Recovers one move-only capacity authority from an exact durable identity.
    ///
    /// # Errors
    ///
    /// Returns an error unless the retained reservation exactly matches the
    /// request, admission transaction, domain binding, and purpose authority.
    pub fn recover_domain_capacity_reservation(
        &mut self,
        request: GlobalCapacityReservationRequestV1,
        admission_transaction_id: [u8; 16],
        reservation_id: [u8; 32],
    ) -> Result<DomainCapacityReservationV1<S>, ProtectedDomainJournalErrorV1> {
        if !validate_domain_capacity_lineage_v1::<S>(
            &request,
            admission_transaction_id,
            reservation_id,
        ) {
            return Err(ProtectedDomainJournalErrorV1::NonCanonicalRecord);
        }
        let reservation = {
            let authority = self
                .journal
                .claim_global_capacity_reservation_authority(request.purpose)?;
            authority.recover_global_capacity_reservation_v1(reservation_id)?
        };
        if !reservation.matches_request(&request, admission_transaction_id) {
            return Err(ProtectedDomainJournalErrorV1::NonCanonicalRecord);
        }
        Ok(DomainCapacityReservationV1 {
            reservation,
            request,
            admission_transaction_id,
            marker: PhantomData,
        })
    }

    /// Recovers capacity by its complete deterministic request binding.
    ///
    /// This endpoint avoids requiring a reducer to persist the reservation ID,
    /// which would otherwise form a cycle with the domain transaction digest.
    ///
    /// # Errors
    ///
    /// Returns an error unless exactly one current reservation matches the
    /// request and admission transaction under the closed purpose authority.
    pub fn recover_domain_capacity_reservation_for_request(
        &mut self,
        request: GlobalCapacityReservationRequestV1,
        admission_transaction_id: [u8; 16],
    ) -> Result<DomainCapacityReservationV1<S>, ProtectedDomainJournalErrorV1> {
        if !capacity_request_binds_schema::<S>(&request) {
            return Err(ProtectedDomainJournalErrorV1::NonCanonicalRecord);
        }
        let reservation_ids = self
            .journal
            .records(RecordNamespace::GlobalCapacityReservation)
            .filter_map(|(key, _)| key.get(key.len().checked_sub(32)?..)?.try_into().ok())
            .collect::<Vec<[u8; 32]>>();
        let mut matching = None;
        let authority = self
            .journal
            .claim_global_capacity_reservation_authority(request.purpose)?;
        for reservation_id in reservation_ids {
            let reservation = match authority.recover_global_capacity_reservation_v1(reservation_id)
            {
                Ok(reservation) => reservation,
                Err(JournalError::ForeignAuthorityNamespace) => continue,
                Err(error) => return Err(error.into()),
            };
            if !reservation.matches_request(&request, admission_transaction_id) {
                continue;
            }
            if matching.replace(reservation).is_some() {
                return Err(ProtectedDomainJournalErrorV1::NonCanonicalRecord);
            }
        }
        let reservation = matching.ok_or(ProtectedDomainJournalErrorV1::NonCanonicalRecord)?;
        Ok(DomainCapacityReservationV1 {
            reservation,
            request,
            admission_transaction_id,
            marker: PhantomData,
        })
    }

    /// Recovers a domain reservation after the original owner digest was superseded.
    ///
    /// The namespace-46 record remains the sole source of the authenticated
    /// original owner digest and admission transaction identity. The caller
    /// supplies every stable lineage field plus the deterministic reservation
    /// ID, and the purpose guard rejects substitutions before returning the
    /// move-only settlement authority.
    ///
    /// # Errors
    ///
    /// Returns an error unless the retained record is canonical, provenance
    /// backed, schema-owned, and exactly matches the stable recovery binding.
    pub fn recover_domain_capacity_reservation_by_binding(
        &mut self,
        reservation_id: [u8; 32],
        binding: GlobalCapacityReservationRecoveryBindingV1,
    ) -> Result<DomainCapacityReservationV1<S>, ProtectedDomainJournalErrorV1> {
        let reservation = {
            let authority = self
                .journal
                .claim_global_capacity_reservation_authority(binding.purpose)?;
            authority.recover_global_capacity_reservation_by_binding_v1(reservation_id, &binding)?
        };
        let request = reservation.request();
        let admission_transaction_id = reservation.admission_transaction_id();
        if !validate_domain_capacity_lineage_v1::<S>(
            &request,
            admission_transaction_id,
            reservation_id,
        ) {
            return Err(ProtectedDomainJournalErrorV1::NonCanonicalRecord);
        }
        Ok(DomainCapacityReservationV1 {
            reservation,
            request,
            admission_transaction_id,
            marker: PhantomData,
        })
    }

    /// Recovers the unique domain reservation from stable lineage alone.
    ///
    /// Enumeration and authentication of namespace 46 stay inside the sealed
    /// purpose guard. The returned request and admission transaction are those
    /// retained by the unique canonical record, never caller-shaped values.
    ///
    /// # Errors
    ///
    /// Returns an error for zero or multiple matches, malformed provenance, a
    /// foreign purpose, or a request that does not bind this domain schema.
    pub fn recover_unique_domain_capacity_reservation_by_binding(
        &mut self,
        binding: GlobalCapacityReservationRecoveryBindingV1,
    ) -> Result<DomainCapacityReservationV1<S>, ProtectedDomainJournalErrorV1> {
        let reservation = {
            let authority = self
                .journal
                .claim_global_capacity_reservation_authority(binding.purpose)?;
            authority.recover_unique_global_capacity_reservation_v1(&binding)?
        };
        let request = reservation.request();
        let admission_transaction_id = reservation.admission_transaction_id();
        if !validate_domain_capacity_lineage_v1::<S>(
            &request,
            admission_transaction_id,
            reservation.reservation_id(),
        ) {
            return Err(ProtectedDomainJournalErrorV1::NonCanonicalRecord);
        }
        Ok(DomainCapacityReservationV1 {
            reservation,
            request,
            admission_transaction_id,
            marker: PhantomData,
        })
    }

    /// Joins an exact terminal domain transaction to its reservation deletion.
    ///
    /// # Errors
    ///
    /// Returns an error for stale domain CAS, nonterminal semantic state,
    /// substituted reservation binding, foreign namespaces, or capacity bounds.
    pub fn prepare_capacity_settlement(
        &mut self,
        prepared: PreparedDomainTransactionV1<S>,
        reservation: DomainCapacityReservationV1<S>,
    ) -> Result<PreparedCapacitySettlementDomainTransactionV1<S>, ProtectedDomainJournalErrorV1>
    {
        self.validate_snapshot(&prepared.snapshot)?;
        validate_expected_values(self.journal, &prepared, false)?;
        let phases = postcommit_records(&prepared, &self.validator)?;
        if aggregate_semantic_phases(&phases.iter().map(|record| record.phase).collect::<Vec<_>>())
            != ProtectedReducerPhaseV1::Terminal
            || !reservation
                .reservation
                .matches_request(&reservation.request, reservation.admission_transaction_id)
            || !capacity_request_binds_schema::<S>(&reservation.request)
        {
            return Err(ProtectedDomainJournalErrorV1::NonCanonicalRecord);
        }
        let decoded = phases
            .iter()
            .map(|record| {
                decode_reducer_payload_with_validator::<S>(
                    record.envelope.key(),
                    record.envelope.payload(),
                    &self.validator,
                ).map_err(ProtectedDomainJournalErrorV1::from)
            })
            .collect::<Result<Vec<_>, _>>()?;
        let members = phases
            .iter()
            .zip(&decoded)
            .map(|(record, payload)| ProtectedCapacitySettlementMemberV1::from_unvalidated_data(
                record.envelope.key().kind(),
                record.envelope.key().identity(),
                payload.body(),
            ))
            .collect::<Vec<_>>();
        if !S::validates_capacity_settlement(
            &reservation.request,
            reservation.admission_transaction_id,
            &members,
        ) {
            return Err(ProtectedDomainJournalErrorV1::NonCanonicalRecord);
        }
        validate_capacity_domain_shape(&prepared.transaction, reservation.request.purpose)?;

        let combined = capacity_settlement_transaction(
            &prepared.transaction,
            reservation.reservation.settlement_record(),
        )?;
        let preflight = {
            let authority = self
                .journal
                .claim_global_capacity_reservation_authority(reservation.request.purpose)?;
            authority.preflight_reserved_terminal_v1(&reservation.reservation, &combined)?
        };
        Ok(PreparedCapacitySettlementDomainTransactionV1 {
            prepared,
            combined,
            reservation,
            preflight,
        })
    }

    /// Commits one exact terminal branch and releases its retained capacity.
    ///
    /// # Errors
    ///
    /// Returns an error when the domain snapshot or predecessor values changed.
    /// Durability failure retains exact outcome-unknown settlement state.
    pub fn commit_capacity_settlement(
        &mut self,
        prepared: PreparedCapacitySettlementDomainTransactionV1<S>,
    ) -> Result<DomainCapacitySettlementCommitOutcomeV1<S>, ProtectedDomainJournalErrorV1> {
        self.validate_snapshot(&prepared.prepared.snapshot)?;
        validate_expected_values(self.journal, &prepared.prepared, false)?;
        let PreparedCapacitySettlementDomainTransactionV1 {
            prepared: domain,
            combined,
            reservation,
            preflight,
        } = prepared;
        let DomainCapacityReservationV1 {
            reservation: raw_reservation,
            request,
            admission_transaction_id,
            marker: _,
        } = reservation;
        let reservation_id = raw_reservation.reservation_id();
        let commit = {
            let mut authority = self
                .journal
                .claim_global_capacity_reservation_authority(request.purpose)?;
            authority.commit_reserved_terminal_v1(&preflight, raw_reservation, &combined)
        };
        if let Err(cause) = commit {
            return Ok(DomainCapacitySettlementCommitOutcomeV1::OutcomeUnknown {
                pending: DomainCapacitySettlementUnknownV1 {
                    prepared: domain,
                    combined,
                    request,
                    admission_transaction_id,
                    reservation_id,
                },
                cause,
            });
        }
        if validate_expected_values(self.journal, &domain, true).is_err() {
            return Ok(DomainCapacitySettlementCommitOutcomeV1::OutcomeUnknown {
                pending: DomainCapacitySettlementUnknownV1 {
                    prepared: domain,
                    combined,
                    request,
                    admission_transaction_id,
                    reservation_id,
                },
                cause: JournalError::AuthorityPreflightMismatch,
            });
        }
        self.applied(domain)
            .map(DomainCapacitySettlementCommitOutcomeV1::Applied)
    }

    /// Recovers one ambiguous capacity settlement after protected reopen.
    ///
    /// # Errors
    ///
    /// Returns an error when protected replay or the purpose authority fails.
    pub fn recover_capacity_settlement(
        &mut self,
        pending: DomainCapacitySettlementUnknownV1<S>,
    ) -> Result<DomainCapacitySettlementRecoveryV1<S>, ProtectedDomainJournalErrorV1> {
        self.replay()?;
        let DomainCapacitySettlementUnknownV1 {
            mut prepared,
            combined,
            request,
            admission_transaction_id,
            reservation_id,
        } = pending;
        let before = values_match(self.journal, &prepared, false);
        let after = values_match(self.journal, &prepared, true);
        if !validate_domain_capacity_lineage_v1::<S>(
            &request,
            admission_transaction_id,
            reservation_id,
        ) {
            return Err(ProtectedDomainJournalErrorV1::NonCanonicalRecord);
        }

        if after {
            let reservation = {
                let authority = self
                    .journal
                    .claim_global_capacity_reservation_authority(request.purpose)?;
                authority.lookup_global_capacity_reservation_v1(reservation_id)?
            };
            if reservation.is_none() {
                return self
                    .applied(prepared)
                    .map(DomainCapacitySettlementRecoveryV1::Applied);
            }
        } else if before {
            prepared.snapshot = self.snapshot()?;
            let reservation = self.recover_domain_capacity_reservation(
                request,
                admission_transaction_id,
                reservation_id,
            )?;
            if capacity_settlement_transaction(
                &prepared.transaction,
                reservation.reservation.settlement_record(),
            )? == combined
            {
                let preflight = {
                    let authority = self
                        .journal
                        .claim_global_capacity_reservation_authority(request.purpose)?;
                    authority.preflight_reserved_terminal_v1(&reservation.reservation, &combined)?
                };
                return Ok(DomainCapacitySettlementRecoveryV1::Retry(
                    PreparedCapacitySettlementDomainTransactionV1 {
                        prepared,
                        combined,
                        reservation,
                        preflight,
                    },
                ));
            }
        }

        Ok(DomainCapacitySettlementRecoveryV1::Diverged(
            DomainCapacitySettlementUnknownV1 {
                prepared,
                combined,
                request,
                admission_transaction_id,
                reservation_id,
            },
        ))
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
        if let Err(cause) = gate.commit(self.journal, &prepared.transaction) {
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
        gate.preflight(self.journal, std::slice::from_ref(&prepared.transaction))?;
        check(self.journal)?;
        Ok(())
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
        gate.commit(self.journal, &prepared.transaction)
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
            .preflight_transactions(std::slice::from_ref(&prepared.transaction))
            .map_err(ProtectedDomainJournalErrorV1::from)
        {
            return DomainRetainedCommitV1::Retryable { prepared, error };
        }
        if let Err(cause) = self.journal.commit(&prepared.transaction) {
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
        let before = values_match(self.journal, &prepared, false);
        let after = values_match(self.journal, &prepared, true);
        if after {
            return self.applied(prepared).map(DomainRecoveryV1::Applied);
        }
        if before {
            let mut prepared = prepared;
            prepared.snapshot = self.snapshot()?;
            self.journal
                .preflight_transactions(std::slice::from_ref(&prepared.transaction))?;
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
        let before = values_match(self.journal, &prepared, false);
        let after = values_match(self.journal, &prepared, true);
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
                .preflight(self.journal, std::slice::from_ref(&prepared.transaction))
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
            transaction: prepared.digest,
            set_digest: prepared.set_digest,
            sequence: snapshot.sequence,
            root: snapshot.root,
            records,
            marker: PhantomData,
        });
        Ok(AppliedDomainTransactionV1 {
            transaction: prepared.digest,
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
            transaction: prepared.digest,
            set_digest: prepared.set_digest,
            sequence: snapshot.sequence,
            root: snapshot.root,
            records,
            marker: PhantomData,
        });
        Ok(AppliedDomainTransactionV1 {
            transaction: prepared.digest,
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
            || self.records.iter().any(|record| {
                authority
                    .journal
                    .get(record.namespace, record.envelope.key().as_bytes())
                    != Some(record.encoded.as_slice())
            })
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
    if prepared.transaction.records().len() != prepared.roles.len()
        || prepared.transaction.records().len() != prepared.after.len()
    {
        return Err(ProtectedDomainJournalErrorV1::NonCanonicalRecord);
    }
    let mut records = Vec::new();
    for ((record, role), value) in prepared
        .transaction
        .records()
        .iter()
        .zip(&prepared.roles)
        .zip(&prepared.after)
    {
        if record.value() != Some(value.as_slice()) {
            return Err(ProtectedDomainJournalErrorV1::NonCanonicalRecord);
        }
        let key = ProtectedDomainKeyV1::<S>::decode(record.key())?;
        if record.namespace() != S::namespace(key.kind()) {
            return Err(ProtectedDomainJournalErrorV1::NonCanonicalRecord);
        }
        let durable = decode_durable_member::<S>(key, value, validator)?;
        let namespace = record.namespace();
        let role = *role;
        let phase = reducer_phase(durable.envelope())?;
        let (_, _, _, _, envelope, encoded) = durable.into_parts();
        let postcommit = DomainPostcommitRecordV1 {
            namespace,
            role,
            phase,
            transaction_phase: ProtectedReducerPhaseV1::Observed,
            envelope,
            encoded,
        };
        records.push(postcommit);
    }
    let transaction_phase = aggregate_semantic_phases(
        &records
            .iter()
            .map(|record| record.phase)
            .collect::<Vec<_>>(),
    );
    for record in &mut records {
        record.transaction_phase = transaction_phase;
    }
    Ok(records)
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
    let records = prepared.transaction.records();
    if records.len() != prepared.before.len() || records.len() != prepared.after.len() {
        return false;
    }
    records
        .iter()
        .zip(prepared.before.iter().zip(&prepared.after))
        .all(|(record, (before, after_value))| {
            let expected = if after {
                Some(after_value.as_slice())
            } else {
                before.as_deref()
            };
            journal.get(record.namespace(), record.key()) == expected
        })
}

fn capacity_admission_transaction(
    domain: &JournalTransaction,
    reservation: &JournalRecord,
) -> Result<JournalTransaction, JournalError> {
    if reservation.namespace() != RecordNamespace::GlobalCapacityReservation
        || domain
            .records()
            .iter()
            .any(|record| record.namespace() == RecordNamespace::GlobalCapacityReservation)
    {
        return Err(JournalError::InvalidTransaction);
    }
    let mut records = domain.records().to_vec();
    records.push(reservation.clone());
    JournalTransaction::new(*domain.id(), records).map_err(JournalError::from)
}

fn validate_capacity_domain_shape(
    transaction: &JournalTransaction,
    purpose: GlobalCapacityReservationPurposeV1,
) -> Result<(), JournalError> {
    let mut publisher_authority = false;
    let mut publication = false;
    let mut effect = false;
    for record in transaction.records() {
        match record.namespace() {
            RecordNamespace::PublisherAuthority => publisher_authority = true,
            RecordNamespace::AuthorityPublication => publication = true,
            RecordNamespace::Effect => effect = true,
            _ => return Err(JournalError::ForeignAuthorityNamespace),
        }
    }
    let closed = match purpose {
        GlobalCapacityReservationPurposeV1::PublisherCompletion => {
            publisher_authority && publication
        }
        GlobalCapacityReservationPurposeV1::RuntimeExecution => {
            effect && !publisher_authority && !publication
        }
        GlobalCapacityReservationPurposeV1::RootProjectAdmission
        | GlobalCapacityReservationPurposeV1::SourceProviderNativeTerminal
        | GlobalCapacityReservationPurposeV1::ControllerProjectAdmission
        | GlobalCapacityReservationPurposeV1::RootSourceGenesisAnchor
        | GlobalCapacityReservationPurposeV1::ControllerConsumerResource
        | GlobalCapacityReservationPurposeV1::RootFirstSourceSuccessorAnchor
        | GlobalCapacityReservationPurposeV1::SourceFirstSourceSuccessorAck
        | GlobalCapacityReservationPurposeV1::ControllerFirstSourceSuccessorComplete => false,
    };
    closed
        .then_some(())
        .ok_or(JournalError::ForeignAuthorityNamespace)
}

fn capacity_settlement_transaction(
    domain: &JournalTransaction,
    settlement: JournalRecord,
) -> Result<JournalTransaction, JournalError> {
    capacity_admission_transaction(domain, &settlement)
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
