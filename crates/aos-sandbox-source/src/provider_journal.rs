//! Owns Provider's fixed journal, challenge writer and native Source lenders.
//!
//! The common journal holder owns acquisition, parsing, index and native append
//! mechanics. Source owns the fixed purposes, same-instance snapshots, complete
//! original replay and exact one-shot signing bases. Provider and Security keep
//! their separate runtime, configuration, key, Session and final effect checks.
//!
//! ```text
//! /var/lib/aos/source-provider/
//!   provider.journal                 namespace41 owners + namespace46 floors
//!   native-hold-challenges.journal   independently locked namespace41 history
//! ```
//!
//! These stores are distinct from Controller's Source-domain writer and the
//! fixed Source signer. Neither their history nor an ordinary allocation recipe
//! supplies another role's financial original or native writer authority.

mod authority;
mod capacity_reservation;
mod claims;
mod delete_batch;
pub mod native_held;
mod opening;
mod ordinary_guards;
mod original;
mod original_release;
mod owner;
mod readonly;
mod reread;
mod scope;
mod semantic_append;
mod semantic_replay;

#[cfg(test)]
mod tests;

pub use aos_sandbox_broker::canonical_journal::CanonicalJournalMechanicalErrorV1 as JournalError;
use aos_sandbox_broker::canonical_journal::CommitResult;
use aos_sandbox_core::RecordNamespace;
use aos_sandbox_ledger_replay::replay::root_original_inventory;
use aos_sandbox_protocol::domain_ledger::transaction::{
    JournalLimits, JournalRecord, JournalTransaction,
};

pub use capacity_reservation::{
    GlobalCapacityReservationPurposeV1, GlobalCapacityReservationRecoveryBindingV1,
    GlobalCapacityReservationRequestV1, GlobalCapacityReservationV1,
    PreparedGlobalCapacityReservationV1,
};
pub use original::{
    OriginalSourceProtectedReadbackV5, PreparedOriginalSourceAppendV5,
    SOURCE_NATIVE_DISPATCH_TERMINAL_BYTES_V1, SOURCE_NATIVE_DISPATCH_TERMINAL_RECORDS_V1,
    SOURCE_NATIVE_NO_DISPATCH_TERMINAL_BYTES_V1, SourceCapacityStateV5,
    SourceCapacityUnionComparisonDataV5, SourceOriginalAdmissionDataV5,
    SourceOriginalAdmissionInputV5, SourceOriginalAppendSubjectV5,
    SourceOriginalChallengeCheckpointV5, SourceOriginalChallengeHistoryViewV5,
    SourceOriginalNativeJournalAuthorityV5, SourceOriginalPhysicalCutV5,
    SourceOriginalReplayViewV5, compare_source_capacity_union_data_v5,
    compare_source_original_admission_data_v5, source_native_ordinary_capacity_request_v1,
    source_native_release_status_capacity_request_v1,
};
pub use owner::SourceProviderJournalV1;
pub use readonly::SourceProviderHeldReadOnlyJournalAuthorityV1;
pub use scope::{ProtectedJournalPreflight, ProtectedJournalSnapshot};

use original_release::OriginalReleaseSourceCutCaptureV1;
use owner::SourceProviderJournalV1 as Journal;
use scope::{JournalAuthorityInstance, ProtectedAuthorityScope};

/// Borrows the actual Source provider writer for its exact private purpose.
///
/// Construction remains with the same journal's protected claims. A copied
/// snapshot, namespace, preflight or committed row cannot create this borrower.
pub struct ProtectedJournalAuthority<'journal> {
    journal: &'journal mut Journal,
    namespace: RecordNamespace,
    scope: ProtectedAuthorityScope,
}

/// Borrows the same fixed Provider claim through its genuine Session handoff.
#[must_use = "a fixed provider journal handoff must be consumed by its session owner"]
pub struct FixedSourceProviderJournalHandoffV1<'authority, 'journal> {
    authority: &'authority ProtectedJournalAuthority<'journal>,
    sequence: u64,
}

impl core::fmt::Debug for FixedSourceProviderJournalHandoffV1<'_, '_> {
    fn fmt(&self, formatter: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        formatter.write_str("FixedSourceProviderJournalHandoffV1([protected handoff])")
    }
}

impl FixedSourceProviderJournalHandoffV1<'_, '_> {
    /// Consumes and revalidates the exact fixed journal borrow.
    ///
    /// The retained immutable borrow prevents an intervening commit through
    /// the same owner while this handoff exists.
    ///
    /// # Errors
    /// Refuses owner replacement, reopen, compaction or a changed fixed scope.
    #[doc(hidden)]
    pub fn validate_current(self) -> Result<(), JournalError> {
        self.authority
            .validate_fixed_source_provider_session_handoff(&self)
    }
}

fn authority_preflight_digest(transactions: &[JournalTransaction]) -> [u8; 32] {
    aos_sandbox_protocol::domain_ledger::transaction::transaction_preflight_comparison_digest_v1(
        transactions,
    )
}

fn validate_transaction(
    transaction: &JournalTransaction,
    limits: JournalLimits,
) -> Result<(), JournalError> {
    aos_sandbox_protocol::domain_ledger::transaction::validate_transaction(transaction, limits)
        .map_err(JournalError::from)
}

fn encoded_transaction_append_bytes(transaction: &JournalTransaction) -> Result<u64, JournalError> {
    aos_sandbox_protocol::domain_ledger::transaction::encoded_transaction_append_bytes(transaction)
        .map_err(JournalError::from)
}

fn projected_materialized_record_count(
    state: &std::collections::BTreeMap<(RecordNamespace, Vec<u8>), Vec<u8>>,
    records: &[JournalRecord],
) -> Result<usize, JournalError> {
    aos_sandbox_journal::materialized::projected_record_count(
        state,
        records
            .iter()
            .map(aos_sandbox_journal::materialized::RecordMutationRef::from),
    )
    .map_err(JournalError::from)
}

fn validate_materialized_change(
    state: &std::collections::BTreeMap<(RecordNamespace, Vec<u8>), Vec<u8>>,
    current_bytes: usize,
    records: &[JournalRecord],
    limits: JournalLimits,
) -> Result<usize, JournalError> {
    aos_sandbox_journal::materialized::validate_change(
        state,
        current_bytes,
        records
            .iter()
            .map(aos_sandbox_journal::materialized::RecordMutationRef::from),
        limits.maximum_materialized_bytes,
        limits.maximum_materialized_records,
    )
    .map_err(JournalError::from)
}
