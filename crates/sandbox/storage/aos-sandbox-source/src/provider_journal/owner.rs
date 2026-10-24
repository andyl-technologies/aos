//! Owns the actual provider or challenge writer and its Source replay history.
//!
//! The common holder is produced by its own native opening and indexed cursor.
//! This module accepts no supplied file, map, Arc, replay state or successful
//! DATA constructor. Its snapshots use that same holder's original allocation.

use std::path::Path;
use std::sync::Arc;

use aos_sandbox_broker::canonical_journal::CanonicalOrdinaryHeldJournalV1;
use aos_sandbox_broker::canonical_journal::coordinator::{
    CanonicalCoordinatorAppendV1, CanonicalWriterReadViewV1,
};
use aos_sandbox_protocol::domain_ledger::readonly::HistoricalLedgerReadViewV1;

use super::original::replay::SourceOriginalReplayCacheV5;
use super::{
    JournalAuthorityInstance, JournalError, JournalLimits, JournalTransaction, RecordNamespace,
    SourceCapacityUnionComparisonDataV5, SourceOriginalAdmissionDataV5,
    SourceOriginalChallengeCheckpointV5, compare_source_capacity_union_data_v5,
    encoded_transaction_append_bytes,
};

/// Owns one actual Source provider or separately locked challenge journal.
///
/// Its ordinary construction policy is unchanged. Native Source authority is
/// lent only by the fixed-purpose claims after protected currentness, complete
/// replay and the separately held challenge history have passed their checks.
pub struct SourceProviderJournalV1 {
    pub(super) held: CanonicalOrdinaryHeldJournalV1<(), JournalAuthorityInstance>,
    // This aliases the holder's same late allocation at the old upper Drop
    // position. Neither a second identity nor a supplied Arc is admitted.
    pub(super) authority_instance: Arc<JournalAuthorityInstance>,
    pub(super) source_challenge_history: Vec<SourceOriginalChallengeCheckpointV5>,
    pub(super) source_original_replay: SourceOriginalReplayCacheV5,
    pub(super) source_history_compacted: bool,
}

impl SourceProviderJournalV1 {
    pub(super) fn native_view(&self) -> CanonicalWriterReadViewV1<'_, ()> {
        self.held.read_view_v1()
    }

    pub(super) fn poison(&mut self) {
        self.held.poison();
    }

    /// Checks whether an earlier ambiguous native append poisoned this writer.
    ///
    /// Cached rows remain diagnostic after refusal; health alone supplies no
    /// protected path, scope, Source original or effect authority.
    ///
    /// # Errors
    /// Returns the unchanged poisoned-writer refusal after native ambiguity.
    pub fn ensure_healthy(&self) -> Result<(), JournalError> {
        if self.native_view().is_poisoned() {
            Err(JournalError::Poisoned)
        } else {
            Ok(())
        }
    }

    pub(super) fn ensure_protected_authority(&self) -> Result<(), JournalError> {
        self.ensure_healthy()?;
        if !self.native_view().is_protected() {
            return Err(JournalError::ProtectedBoundary);
        }
        Ok(())
    }

    pub(super) fn historical_read_view_v1(&self) -> HistoricalLedgerReadViewV1<'_> {
        self.native_view().historical_view()
    }

    /// Borrows a diagnostic materialized value without proving current custody.
    #[must_use]
    pub fn get(&self, namespace: RecordNamespace, key: &[u8]) -> Option<&[u8]> {
        self.historical_read_view_v1().get(namespace, key)
    }

    /// Borrows diagnostic rows in the same canonical namespace/key ordering.
    ///
    /// The immutable borrow cannot span a mutation. A purpose-bound authority
    /// must separately validate currentness before relying on these bytes.
    pub fn records(&self, namespace: RecordNamespace) -> impl Iterator<Item = (&[u8], &[u8])> {
        self.historical_read_view_v1().records(namespace)
    }

    /// Borrows all diagnostic rows without creating a protected claim.
    pub fn all_records(&self) -> impl Iterator<Item = (RecordNamespace, &[u8], &[u8])> {
        self.historical_read_view_v1().all_records()
    }

    /// Reports diagnostic emptiness without certifying healthy current storage.
    #[must_use]
    pub fn is_materialized_empty(&self) -> bool {
        self.native_view().state().is_empty()
    }

    /// Returns the actual next frame sequence as nonauthorizing comparison DATA.
    #[must_use]
    pub fn snapshot_sequence(&self) -> u64 {
        self.native_view().next_sequence()
    }

    /// Returns the actual opened ceilings without granting capacity or mutation.
    #[must_use]
    pub fn opened_limits_data_v1(&self) -> JournalLimits {
        self.native_view().limits()
    }

    /// Rechecks the same protected journal and lock inside its retained directory.
    ///
    /// # Errors
    /// Refuses unprotected or poisoned custody, changed names or invalid files.
    pub fn validate_held_protected_names(&self) -> Result<(), JournalError> {
        self.ensure_protected_authority()?;
        self.require_protected_names_current()
    }

    pub(super) fn require_protected_names_current(&self) -> Result<(), JournalError> {
        self.native_view()
            .protected_view()
            .ok_or(JournalError::ProtectedBoundary)?
            .require_names::<JournalError>()
    }

    /// Rechecks the actual root-owned directory, basename, journal and lock.
    ///
    /// The independent directory observation remains held through the health
    /// bookend. A successful path observation alone grants no Source purpose.
    ///
    /// # Errors
    /// Refuses changed physical custody, owner, names or a poisoned writer.
    pub fn validate_held_root_owned_at(
        &self,
        directory: impl AsRef<Path>,
        name: &str,
    ) -> Result<(), JournalError> {
        let native = self.native_view();
        let retained = native
            .protected_view()
            .ok_or(JournalError::ProtectedBoundary)?;
        if retained.name() != name || retained.expected_uid() != 0 {
            return Err(JournalError::ProtectedBoundary);
        }
        let _current = retained.require_directory::<JournalError>(directory.as_ref(), 0)?;
        self.ensure_healthy()?;
        self.require_protected_names_current()
    }
}

impl SourceProviderJournalV1 {
    /// Compares Stage A Source DATA against this actual handle's opened ceilings.
    ///
    /// This advisory does not mint preflight, grant, writer or physical origin
    /// evidence. A future protected adapter must revalidate currentness/custody.
    ///
    /// # Errors
    ///
    /// Rejects a poisoned handle, repeated transaction, incomplete Source union,
    /// insufficient full-transaction/current debt headroom or sequence exhaustion.
    pub(super) fn compare_source_capacity_advisory_v5(
        &self,
        transaction: Option<&JournalTransaction>,
        origins: &[SourceOriginalAdmissionDataV5],
        challenges: &[aos_sandbox_source_provider_ledger::ledger::source_capacity::OriginalSourceChallengeDataV5<'_>],
    ) -> Result<SourceCapacityUnionComparisonDataV5, JournalError> {
        self.ensure_healthy()?;
        if transaction.is_some_and(|transaction| {
            self.native_view()
                .transaction_ids()
                .contains(transaction.id())
        }) {
            return Err(JournalError::DuplicateTransaction);
        }
        let comparison = compare_source_capacity_union_data_v5(
            self.native_view().state(),
            transaction,
            origins,
            challenges,
            self.native_view().limits(),
        )?;
        let (append_bytes, added_transactions, added_frames) = match transaction {
            Some(transaction) => (
                encoded_transaction_append_bytes(transaction)?,
                1_usize,
                (transaction.records().len() as u64)
                    .checked_add(2)
                    .ok_or(JournalError::SequenceExhausted)?,
            ),
            None => (0, 0, 0),
        };
        let journal_bytes = self
            .native_view()
            .metadata()?
            .len()
            .checked_add(append_bytes)
            .ok_or(JournalError::JournalTooLarge)?;
        let transactions = self
            .native_view()
            .committed_transactions()
            .checked_add(added_transactions)
            .ok_or(JournalError::LimitExceeded("transaction count"))?;
        let next_sequence = self
            .native_view()
            .next_sequence()
            .checked_add(added_frames)
            .ok_or(JournalError::SequenceExhausted)?;
        // The complete union already checked every exact changed floor. Reuse
        // the shared all-family fold on the after cut, with no pretend generic
        // settlement identifier or weaker legacy decoder.
        super::original::replay::require_advisory_bounds(
            &comparison,
            self.native_view().limits(),
            journal_bytes,
            transactions,
            next_sequence,
        )?;
        Ok(comparison)
    }
}
