//! Bounded native namespace6 history from the same protected Storage writer.
//!
//! The sole Journal COMMIT parser supplies exact transactions and boundaries:
//!
//! ```text
//! BEGIN(sequence, uuid, 1) | PUT(namespace6, key48, opaque value) | COMMIT
//! ```
//!
//! A lending cursor reconstructs two prefixes with the existing materializer.
//! Values remain opaque: Storage alone validates legacy/held schemas, signed
//! archives, transition witnesses and funding. This module grants no admission,
//! floor, append, signing, descriptor custody or installed readiness.

use std::collections::BTreeMap;
use std::fmt;
use std::mem::{self, size_of};
use std::path::Path;

use super::runtime_deployment_history::ReadAtCursorV1;
use super::{
    DeploymentHistoryObserverV1, Journal, JournalError, JournalLimits, JournalRecord,
    JournalTransaction, ProtectedWriterNameWitness, RecordNamespace, ReplayState,
    encoded_transaction_append_bytes, replay_original_observed, root_original_inventory,
    validate_limits, validate_materialized_change,
};

const DIRECTORY: &str = "/var/lib/aos/sandbox-storage";
const NAME: &str = "storage-native-issuance.journal";
const NAMESPACE: RecordNamespace = RecordNamespace::AuthorityPublication;
const KEY_BYTES: usize = 48;
const MAXIMUM_JOURNAL_BYTES: u64 = 256 * 1024 * 1024;
const MAXIMUM_MATERIALIZED_BYTES: usize = 128 * 1024 * 1024;
const MAXIMUM_ROWS: usize = 1024;
// This is a capture ceiling, never a live reservation or a limit increase.
const MAXIMUM_TRANSACTIONS: usize = 8 * MAXIMUM_ROWS;

type State = BTreeMap<(RecordNamespace, Vec<u8>), Vec<u8>>;
type Result<T> = std::result::Result<T, StorageNativeIssuanceHistoryErrorV1>;

/// Retains the first original failure and any first final-bookend failure.
#[derive(Debug, thiserror::Error)]
#[error("Storage native issuance history failed: {first}")]
pub struct StorageNativeIssuanceHistoryErrorV1 {
    #[source]
    first: JournalError,
    final_bookend: Option<JournalError>,
}

impl StorageNativeIssuanceHistoryErrorV1 {
    /// Borrows the unchanged first parser, allocation or physical-check cause.
    #[must_use]
    pub fn first_cause(&self) -> &JournalError {
        &self.first
    }

    /// Borrows a subsequent failed physical bookend without replacing the cause.
    #[must_use]
    pub fn final_bookend_cause(&self) -> Option<&JournalError> {
        self.final_bookend.as_ref()
    }
}

impl From<JournalError> for StorageNativeIssuanceHistoryErrorV1 {
    fn from(first: JournalError) -> Self {
        Self {
            first,
            final_bookend: None,
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum HistoryPhase {
    Available,
    Lending,
    Ended,
}

/// Borrows the original writer and owns bounded, immutable native history DATA.
///
/// Private construction requires the fixed healthy protected writer and full
/// same-parser replay equality. It does not authenticate Storage row values,
/// current role claims, a held descriptor or any permission to perform effects.
/// The writer cannot be mutably used while this borrow lives.
pub struct StorageNativeIssuanceHistoryDataV1<'journal> {
    journal: &'journal Journal,
    witness: ProtectedWriterNameWitness,
    transactions: Vec<NativeTransactionData>,
    committed_records: usize,
    next_sequence: u64,
    materialized_bytes: usize,
    phase: HistoryPhase,
}

impl fmt::Debug for StorageNativeIssuanceHistoryDataV1<'_> {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("StorageNativeIssuanceHistoryDataV1")
            .field("physical_bytes", &self.physical_bytes())
            .field("committed_transactions", &self.committed_transactions())
            .field("committed_records", &self.committed_records)
            .field("next_sequence", &self.next_sequence)
            .field("phase", &self.phase)
            .finish_non_exhaustive()
    }
}

impl<'journal> StorageNativeIssuanceHistoryDataV1<'journal> {
    /// Returns all eight ceilings opened by the same writer, as DATA only.
    #[must_use]
    pub fn opened_limits(&self) -> JournalLimits {
        self.journal.limits
    }

    /// Returns the complete captured physical extent, including native framing.
    #[must_use]
    pub const fn physical_bytes(&self) -> u64 {
        self.witness.file.size
    }

    /// Returns every validated committed transaction, not the final row count.
    #[must_use]
    pub fn committed_transactions(&self) -> usize {
        self.transactions.len()
    }

    /// Returns every validated committed record, including replaced values.
    #[must_use]
    pub const fn committed_records(&self) -> usize {
        self.committed_records
    }

    /// Returns the exact captured NEXT boundary, not an append permit.
    #[must_use]
    pub const fn next_sequence(&self) -> u64 {
        self.next_sequence
    }

    /// Rechecks the original fixed physical cut without reopening its writer.
    ///
    /// # Errors
    ///
    /// Rejects physical/name drift, poison or an already lending/ended history.
    /// Failure or unwind permanently ends this history.
    pub fn recheck(&mut self) -> Result<()> {
        if self.phase != HistoryPhase::Available {
            return Err(ended().into());
        }
        self.phase = HistoryPhase::Ended;
        self.recheck_cut()?;
        self.phase = HistoryPhase::Available;
        Ok(())
    }

    /// Lends one one-shot cursor over the original authenticated transactions.
    ///
    /// Prefix cloning uses the existing materializer's ordinary allocation.
    /// Bounds precede each clone; this is not fallible allocator or owner-custody
    /// proof. A caller's genuine owner must remain prearmed during the loan.
    ///
    /// # Errors
    ///
    /// Rejects an already used history or a changed original physical cut.
    /// Failure, unwind, cursor completion or cursor Drop permanently ends it.
    pub fn replay(&mut self) -> Result<StorageNativeIssuanceHistoryCursorV1<'_, 'journal>> {
        if self.phase != HistoryPhase::Available {
            return Err(ended().into());
        }
        self.phase = HistoryPhase::Ended;
        self.recheck_cut()?;
        self.phase = HistoryPhase::Lending;
        Ok(StorageNativeIssuanceHistoryCursorV1 {
            history: self,
            prefix: PrefixReplay::new(),
            phase: CursorPhase::Ready,
        })
    }

    fn recheck_cut(&self) -> std::result::Result<(), JournalError> {
        require_bookend(self.journal, &self.witness)
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum CursorPhase {
    Ready,
    Exhausted,
    Ended,
}

/// Lends at most two native prefix maps under the same original writer borrow.
///
/// An edge borrows this cursor, so it cannot escape an advance or be held across
/// a writer mutation. No method commits, repairs, extracts or transfers owners.
pub struct StorageNativeIssuanceHistoryCursorV1<'history, 'journal> {
    history: &'history mut StorageNativeIssuanceHistoryDataV1<'journal>,
    prefix: PrefixReplay,
    phase: CursorPhase,
}

impl StorageNativeIssuanceHistoryCursorV1<'_, '_> {
    /// Advances once and lends the exact native transaction and complete edge.
    ///
    /// Returns None only after all captured transactions have been consumed;
    /// callers must then finish. The exhausted cursor cannot be repolled.
    ///
    /// # Errors
    ///
    /// Rejects ended/exhausted use, changed original custody, prefix bounds or
    /// native discontinuity. The cursor ends before any fallible work or clone.
    pub fn next_edge(&mut self) -> Result<Option<StorageNativeIssuanceEdgeDataV1<'_>>> {
        if self.phase != CursorPhase::Ready {
            self.end();
            return Err(ended().into());
        }
        self.end();

        let result = (|| {
            self.history.recheck_cut()?;
            self.prefix.advance(&self.history.transactions, self.history.opened_limits())
        })();
        let bookend = self.history.recheck_cut();
        let Some(index) = combine(result, bookend)? else {
            self.phase = CursorPhase::Exhausted;
            self.history.phase = HistoryPhase::Lending;
            return Ok(None);
        };
        let transaction = self.history.transactions.get(index)
            .ok_or_else(|| StorageNativeIssuanceHistoryErrorV1::from(ended()))?;

        self.phase = CursorPhase::Ready;
        self.history.phase = HistoryPhase::Lending;
        Ok(Some(StorageNativeIssuanceEdgeDataV1 {
            transaction,
            before: &self.prefix.before,
            after: &self.prefix.after,
        }))
    }

    /// Ends the loan after complete prefix equality and original bookends.
    ///
    /// An empty original history can finish as empty DATA; this grants no
    /// admission, new generation, recovery, capacity or current role authority.
    ///
    /// # Errors
    ///
    /// Rejects incomplete consumption, any final-map/count/NEXT/extent mismatch,
    /// changed original custody or an ended cursor. All outcomes end the loan.
    pub fn finish(&mut self) -> Result<()> {
        if self.phase == CursorPhase::Ended {
            return Err(ended().into());
        }
        self.end();

        let result = (|| {
            self.history.recheck_cut()?;
            if self.prefix.index != self.history.transactions.len()
                || self.prefix.next_sequence != self.history.next_sequence
                || self.prefix.end_offset != self.history.physical_bytes()
                || self.prefix.materialized_bytes != self.history.materialized_bytes
                || self.prefix.after != self.history.journal.state
            {
                return Err(JournalError::StaleAuthoritySnapshot);
            }
            Ok(())
        })();
        combine(result, self.history.recheck_cut())
    }

    fn end(&mut self) {
        self.phase = CursorPhase::Ended;
        self.history.phase = HistoryPhase::Ended;
    }
}

impl Drop for StorageNativeIssuanceHistoryCursorV1<'_, '_> {
    fn drop(&mut self) {
        self.end();
    }
}

/// Borrows one complete native before/after edge, never a transition permission.
///
/// Storage must separately join exact canonical rows, witnesses, archived
/// signatures and the actual native transaction through its existing reducer.
pub struct StorageNativeIssuanceEdgeDataV1<'edge> {
    transaction: &'edge NativeTransactionData,
    before: &'edge State,
    after: &'edge State,
}

impl StorageNativeIssuanceEdgeDataV1<'_> {
    /// Borrows the complete prefix before this original native transaction.
    #[must_use]
    pub fn before(&self) -> &BTreeMap<(RecordNamespace, Vec<u8>), Vec<u8>> {
        self.before
    }

    /// Borrows the complete prefix after this original native transaction.
    #[must_use]
    pub fn after(&self) -> &BTreeMap<(RecordNamespace, Vec<u8>), Vec<u8>> {
        self.after
    }

    /// Borrows the actual original UUID and complete ordered record bytes.
    #[must_use]
    pub fn transaction(&self) -> &JournalTransaction {
        &self.transaction.transaction
    }

    /// Returns the exact pre-append NEXT, which is this transaction's BEGIN.
    #[must_use]
    pub const fn begin_sequence(&self) -> u64 {
        self.transaction.begin_sequence
    }

    /// Returns the validated original COMMIT sequence.
    #[must_use]
    pub const fn commit_sequence(&self) -> u64 {
        self.transaction.commit_sequence
    }

    /// Returns the checked NEXT immediately following that original COMMIT.
    #[must_use]
    pub const fn next_sequence(&self) -> u64 {
        self.transaction.next_sequence
    }

    /// Returns the original complete native transaction's starting byte offset.
    #[must_use]
    pub const fn begin_offset(&self) -> u64 {
        self.transaction.begin_offset
    }

    /// Returns the byte offset immediately after the original complete COMMIT.
    #[must_use]
    pub const fn end_offset(&self) -> u64 {
        self.transaction.end_offset
    }
}

struct NativeTransactionData {
    transaction: JournalTransaction,
    begin_sequence: u64,
    commit_sequence: u64,
    next_sequence: u64,
    begin_offset: u64,
    end_offset: u64,
}

// Only the closed parser observer can construct retained native DATA.
pub(super) struct StorageHistoryObserverV1 {
    limits: JournalLimits,
    physical_bytes: u64,
    transactions: Vec<NativeTransactionData>,
    retained_bytes: usize,
    maximum_retained_bytes: usize,
    next_sequence: u64,
    end_offset: u64,
}

impl StorageHistoryObserverV1 {
    fn new(limits: JournalLimits, physical_bytes: u64) -> std::result::Result<Self, JournalError> {
        require_capture_limits(limits, physical_bytes)?;
        let overhead = size_of::<NativeTransactionData>()
            .checked_add(size_of::<JournalRecord>())
            .and_then(|size| size.checked_mul(limits.maximum_transactions))
            .ok_or_else(retention_limit)?;
        let maximum_retained_bytes = usize::try_from(physical_bytes)
            .ok()
            .and_then(|bytes| bytes.checked_add(overhead))
            .ok_or_else(retention_limit)?;
        Ok(Self {
            limits,
            physical_bytes,
            transactions: Vec::new(),
            retained_bytes: 0,
            maximum_retained_bytes,
            next_sequence: 1,
            end_offset: 0,
        })
    }

    pub(super) fn observe(
        &mut self,
        transaction: &JournalTransaction,
        begin_sequence: u64,
        commit_sequence: u64,
        begin_offset: u64,
        end_offset: u64,
    ) -> std::result::Result<(), JournalError> {
        let [record] = transaction.records() else {
            return Err(JournalError::ProtectedBoundary);
        };
        if record.namespace() != NAMESPACE {
            return Err(JournalError::ForeignAuthorityNamespace);
        }
        let value = record.value().ok_or(JournalError::ProtectedBoundary)?;
        let next_sequence = commit_sequence.checked_add(1)
            .filter(|next| *next != u64::MAX)
            .ok_or(JournalError::SequenceExhausted)?;
        if record.key().len() != KEY_BYTES
            || transaction.id() == &[0; 16]
            || &transaction.id()[8..] == b"compact1"
            || begin_sequence != self.next_sequence
            || begin_sequence.checked_add(2) != Some(commit_sequence)
            || begin_offset != self.end_offset
            || end_offset <= begin_offset
            || end_offset > self.physical_bytes
        {
            return Err(JournalError::ProtectedBoundary);
        }

        let count = self.transactions.len().checked_add(1)
            .filter(|count| *count <= self.limits.maximum_transactions)
            .ok_or_else(retention_limit)?;
        let charge = size_of::<NativeTransactionData>()
            .checked_add(size_of::<JournalRecord>())
            .and_then(|bytes| bytes.checked_add(record.key().len()))
            .and_then(|bytes| bytes.checked_add(value.len()))
            .and_then(|bytes| bytes.checked_add(self.retained_bytes))
            .filter(|bytes| *bytes <= self.maximum_retained_bytes)
            .ok_or_else(retention_limit)?;
        // The existing encoder allocates ordinarily under the already checked
        // parser ceilings. No independent framing formula or codec is added.
        let encoded_bytes = encoded_transaction_append_bytes(transaction)?;
        if begin_offset.checked_add(encoded_bytes) != Some(end_offset) {
            return Err(JournalError::StaleAuthoritySnapshot);
        }

        self.transactions.try_reserve_exact(1).map_err(|_| retention_limit())?;
        let mut records = Vec::new();
        records.try_reserve_exact(1).map_err(|_| retention_limit())?;
        records.push(JournalRecord::put(NAMESPACE, copy_bytes(record.key())?, copy_bytes(value)?));
        let transaction = JournalTransaction::new(*transaction.id(), records)?;
        self.transactions.push(NativeTransactionData {
            transaction,
            begin_sequence,
            commit_sequence,
            next_sequence,
            begin_offset,
            end_offset,
        });
        if self.transactions.len() != count {
            return Err(JournalError::StaleAuthoritySnapshot);
        }
        self.retained_bytes = charge;
        self.next_sequence = next_sequence;
        self.end_offset = end_offset;
        Ok(())
    }

    fn finish(&self, replayed: &ReplayState) -> std::result::Result<(), JournalError> {
        if self.transactions.len() != replayed.committed_transactions
            || self.transactions.len() != replayed.committed_records
            || self.next_sequence != replayed.next_sequence
            || self.end_offset != self.physical_bytes
            || replayed.durable_end != self.physical_bytes
        {
            return Err(JournalError::StaleAuthoritySnapshot);
        }
        Ok(())
    }
}

struct PrefixReplay {
    before: State,
    after: State,
    index: usize,
    next_sequence: u64,
    end_offset: u64,
    materialized_bytes: usize,
}

impl PrefixReplay {
    fn new() -> Self {
        Self {
            before: State::new(),
            after: State::new(),
            index: 0,
            next_sequence: 1,
            end_offset: 0,
            materialized_bytes: 0,
        }
    }

    fn advance(
        &mut self,
        transactions: &[NativeTransactionData],
        limits: JournalLimits,
    ) -> std::result::Result<Option<usize>, JournalError> {
        let Some(native) = transactions.get(self.index) else {
            return Ok(None);
        };
        if native.begin_sequence != self.next_sequence || native.begin_offset != self.end_offset {
            return Err(JournalError::StaleAuthoritySnapshot);
        }
        let bytes = validate_materialized_change(
            &self.after, self.materialized_bytes, native.transaction.records(), limits,
        )?;
        self.materialized_bytes.checked_add(bytes)
            .filter(|charge| {
                limits.maximum_materialized_bytes.checked_mul(2)
                    .is_some_and(|maximum| *charge <= maximum)
            })
            .ok_or(JournalError::LimitExceeded("Storage two-prefix bytes"))?;
        limits.maximum_materialized_records.checked_mul(2)
            .and_then(|rows| rows.checked_mul(size_of::<((RecordNamespace, Vec<u8>), Vec<u8>)>()))
            .ok_or(JournalError::LimitExceeded("Storage two-prefix rows"))?;

        // The previous before-map is gone before the existing materializer
        // clones the current prefix. At most two full prefix maps are live.
        self.before.clear();
        self.before = mem::take(&mut self.after);
        self.after = root_original_inventory::materialize(&self.before, &native.transaction);
        let index = self.index;
        self.index = self.index.checked_add(1).ok_or_else(retention_limit)?;
        self.next_sequence = native.next_sequence;
        self.end_offset = native.end_offset;
        self.materialized_bytes = bytes;
        Ok(Some(index))
    }
}

impl Journal {
    /// Captures exact native DATA from this original fixed Storage issuance writer.
    ///
    /// The same exclusively held writer is immutably borrowed, never consumed.
    /// Independent-offset replay preserves its append OFD position. Storage
    /// must separately validate all row/transition/signature/funding rules and
    /// retain its genuine startup and original owners through failures.
    ///
    /// # Errors
    ///
    /// Rejects the wrong fixed protected path/name/owner, poison, resource
    /// ceilings, foreign namespace/key/record shape, compaction, incomplete
    /// tails, replay mismatch or physical/name drift. The first cause is kept
    /// alongside any subsequent final-bookend failure. Existing opener-internal
    /// pre-return ownership and ordinary allocator gaps are not solved here.
    pub fn capture_storage_native_issuance_history_v1(
        &self,
    ) -> Result<StorageNativeIssuanceHistoryDataV1<'_>> {
        require_fixed_location(self)?;
        let witness = self.protected_writer_name_witness()?;
        let result = (|| {
            let mut observer = StorageHistoryObserverV1::new(self.limits, witness.file.size)?;
            let mut reader = ReadAtCursorV1::new(&self.file, witness.file.size);
            let replayed = replay_original_observed(
                &mut reader, self.limits, None,
                Some(DeploymentHistoryObserverV1::Storage(&mut observer)),
            )?;
            observer.finish(&replayed)?;
            require_replayed_snapshot(self, &replayed, witness.file.size)?;
            Ok((observer.transactions, replayed.committed_records))
        })();
        let (transactions, committed_records) = combine(result, require_bookend(self, &witness))?;
        Ok(StorageNativeIssuanceHistoryDataV1 {
            journal: self,
            witness,
            transactions,
            committed_records,
            next_sequence: self.next_sequence,
            materialized_bytes: self.materialized_bytes,
            phase: HistoryPhase::Available,
        })
    }
}

fn require_fixed_location(journal: &Journal) -> std::result::Result<(), JournalError> {
    journal.require_protected_named_location(Path::new(DIRECTORY), NAME, 0, journal.limits)
}

fn require_bookend(
    journal: &Journal,
    witness: &ProtectedWriterNameWitness,
) -> std::result::Result<(), JournalError> {
    require_fixed_location(journal)?;
    journal.validate_protected_writer_name_witness(witness)
}

fn require_capture_limits(
    limits: JournalLimits,
    physical_bytes: u64,
) -> std::result::Result<(), JournalError> {
    validate_limits(limits)?;
    let maximum_payload = usize::try_from(MAXIMUM_JOURNAL_BYTES)
        .ok()
        .and_then(|bytes| bytes.checked_sub(7))
        .ok_or(JournalError::JournalTooLarge)?;
    if physical_bytes > limits.maximum_journal_bytes
        || limits.maximum_journal_bytes > MAXIMUM_JOURNAL_BYTES
    {
        return Err(JournalError::JournalTooLarge);
    }
    if limits.maximum_record_bytes > maximum_payload
        || limits.maximum_key_bytes != KEY_BYTES
        || limits.maximum_records_per_transaction != 1
        || limits.maximum_transaction_bytes > maximum_payload
        || limits.maximum_transactions > MAXIMUM_TRANSACTIONS
        || limits.maximum_materialized_bytes > MAXIMUM_MATERIALIZED_BYTES
        || limits.maximum_materialized_records > MAXIMUM_ROWS
    {
        return Err(JournalError::ProtectedBoundary);
    }
    Ok(())
}

fn require_replayed_snapshot(
    journal: &Journal,
    replayed: &ReplayState,
    physical_bytes: u64,
) -> std::result::Result<(), JournalError> {
    if replayed.durable_end != physical_bytes
        || replayed.next_sequence != journal.next_sequence
        || replayed.committed_transactions != journal.committed_transactions
        || replayed.committed_records != replayed.committed_transactions
        || replayed.transaction_ids != journal.transaction_ids
        || replayed.committed_namespaces != journal.committed_namespaces
        || replayed.state != journal.state
        || replayed.materialized_bytes != journal.materialized_bytes
        || replayed.idempotency != journal.idempotency
        || !replayed.idempotency.is_empty()
        || replayed.committed_namespaces.iter().any(|namespace| *namespace != NAMESPACE)
        || !replayed.source_challenge_history.is_empty()
        || !journal.source_challenge_history.is_empty()
        || replayed.source_original_replay.has_dependencies()
        || journal.source_original_replay.has_dependencies()
        || replayed.source_history_compacted
        || journal.source_history_compacted
    {
        return Err(JournalError::StaleAuthoritySnapshot);
    }
    Ok(())
}

fn combine<T>(
    result: std::result::Result<T, JournalError>,
    bookend: std::result::Result<(), JournalError>,
) -> Result<T> {
    match (result, bookend) {
        (Ok(value), Ok(())) => Ok(value),
        (Err(first), bookend) => Err(StorageNativeIssuanceHistoryErrorV1 {
            first,
            final_bookend: bookend.err(),
        }),
        (Ok(_), Err(first)) => Err(first.into()),
    }
}

fn copy_bytes(bytes: &[u8]) -> std::result::Result<Vec<u8>, JournalError> {
    let mut copied = Vec::new();
    copied.try_reserve_exact(bytes.len()).map_err(|_| retention_limit())?;
    copied.extend_from_slice(bytes);
    Ok(copied)
}

fn retention_limit() -> JournalError {
    JournalError::LimitExceeded("Storage native history retention")
}

fn ended() -> JournalError {
    JournalError::MalformedTransaction("Storage native history loan has ended")
}

#[cfg(test)]
mod tests {
    use std::io::{Seek as _, Write as _};

    use super::*;

    fn limits() -> JournalLimits {
        JournalLimits {
            maximum_journal_bytes: 1024 * 1024,
            maximum_record_bytes: 4096,
            maximum_key_bytes: KEY_BYTES,
            maximum_records_per_transaction: 1,
            maximum_transaction_bytes: 4096,
            maximum_transactions: 32,
            maximum_materialized_bytes: 64 * 1024,
            maximum_materialized_records: 16,
        }
    }

    fn put(id: u8, key: u8, value: &[u8]) -> JournalTransaction {
        JournalTransaction::new(
            [id; 16],
            vec![JournalRecord::put(NAMESPACE, vec![key; KEY_BYTES], value.to_vec())],
        )
        .unwrap()
    }

    fn encoded(transactions: &[JournalTransaction]) -> Vec<u8> {
        let mut bytes = Vec::new();
        let mut sequence = 1;
        for transaction in transactions {
            for frame in super::super::encode_transaction(transaction, sequence).unwrap() {
                bytes.extend_from_slice(&frame);
            }
            sequence += transaction.records().len() as u64 + 2;
        }
        bytes
    }

    fn observe(
        bytes: &[u8],
    ) -> std::result::Result<(Vec<NativeTransactionData>, ReplayState), JournalError> {
        // Inert same-codec DATA, not the fixed protected production owner.
        let mut file = tempfile::tempfile()?;
        file.write_all(bytes)?;
        let position = file.stream_position()?;
        let length = file.metadata()?.len();
        let mut observer = StorageHistoryObserverV1::new(limits(), length)?;
        let mut reader = ReadAtCursorV1::new(&file, length);
        let result = replay_original_observed(
            &mut reader, limits(), None,
            Some(DeploymentHistoryObserverV1::Storage(&mut observer)),
        );
        drop(reader);
        assert_eq!(file.stream_position()?, position);
        let replayed = result?;
        observer.finish(&replayed)?;
        Ok((observer.transactions, replayed))
    }

    #[test]
    fn empty_native_data_keeps_sequence_one_and_zero_counts() {
        let (native, replayed) = observe(&[]).unwrap();

        assert!(native.is_empty());
        assert_eq!(replayed.next_sequence, 1);
        assert_eq!(replayed.committed_transactions, 0);
        assert_eq!(replayed.committed_records, 0);
        assert_eq!(replayed.durable_end, 0);
        assert!(replayed.state.is_empty());
    }

    #[test]
    fn every_actual_opened_limit_is_checked_before_retention() {
        let original = limits();
        let mut cases = [original; 8];
        cases[0].maximum_journal_bytes = MAXIMUM_JOURNAL_BYTES + 1;
        cases[1].maximum_record_bytes = usize::MAX;
        cases[2].maximum_key_bytes = KEY_BYTES + 1;
        cases[3].maximum_records_per_transaction = 2;
        cases[4].maximum_transaction_bytes = usize::MAX;
        cases[5].maximum_transactions = MAXIMUM_TRANSACTIONS + 1;
        cases[6].maximum_materialized_bytes = MAXIMUM_MATERIALIZED_BYTES + 1;
        cases[7].maximum_materialized_records = MAXIMUM_ROWS + 1;

        assert!(require_capture_limits(original, 0).is_ok());
        for (index, ceilings) in cases.into_iter().enumerate() {
            assert!(require_capture_limits(ceilings, 0).is_err(), "limit {index}");
        }
        assert!(matches!(
            require_capture_limits(original, original.maximum_journal_bytes + 1),
            Err(JournalError::JournalTooLarge),
        ));
    }

    #[test]
    fn overwritten_values_keep_genuine_before_after_and_native_boundaries() {
        let transactions = [put(1, 9, b"initial"), put(2, 9, b"unsigned"), put(3, 9, b"cold")];
        let (native, replayed) = observe(&encoded(&transactions)).unwrap();
        let mut prefix = PrefixReplay::new();
        let key = (NAMESPACE, vec![9; KEY_BYTES]);

        assert_eq!(prefix.advance(&native, limits()).unwrap(), Some(0));
        assert!(prefix.before.is_empty());
        assert_eq!(prefix.after.get(&key).unwrap(), b"initial");
        assert_eq!(native[0].begin_sequence, 1);
        assert_eq!(native[0].commit_sequence, 3);

        assert_eq!(prefix.advance(&native, limits()).unwrap(), Some(1));
        assert_eq!(prefix.before.get(&key).unwrap(), b"initial");
        assert_eq!(prefix.after.get(&key).unwrap(), b"unsigned");
        assert_eq!(native[1].begin_sequence, 4);
        assert_eq!(native[1].begin_offset, native[0].end_offset);

        assert_eq!(prefix.advance(&native, limits()).unwrap(), Some(2));
        assert_eq!(prefix.before.get(&key).unwrap(), b"unsigned");
        assert_eq!(prefix.after.get(&key).unwrap(), b"cold");
        assert_eq!(native[2].begin_sequence, 7);
        assert_eq!(native[2].next_sequence, 10);
        assert_eq!(prefix.after, replayed.state);
        assert_eq!(prefix.end_offset, replayed.durable_end);
        assert_eq!(prefix.advance(&native, limits()).unwrap(), None);
    }

    #[test]
    fn full_prefixes_include_unchanged_other_issuance_rows() {
        let (native, _) = observe(&encoded(&[
            put(1, 1, b"old"), put(2, 2, b"other"), put(3, 1, b"new"),
        ]))
        .unwrap();
        let mut prefix = PrefixReplay::new();
        for _ in 0..3 {
            prefix.advance(&native, limits()).unwrap();
        }

        assert_eq!(prefix.before.len(), 2);
        assert_eq!(prefix.after.len(), 2);
        assert_eq!(prefix.before.get(&(NAMESPACE, vec![1; KEY_BYTES])).unwrap(), b"old");
        assert_eq!(prefix.after.get(&(NAMESPACE, vec![1; KEY_BYTES])).unwrap(), b"new");
        assert_eq!(prefix.after.get(&(NAMESPACE, vec![2; KEY_BYTES])).unwrap(), b"other");
    }

    #[test]
    fn deleted_namespace6_records_cannot_stand_for_retirement() {
        let transaction = JournalTransaction::new(
            [1; 16],
            vec![JournalRecord::delete(NAMESPACE, vec![1; KEY_BYTES])],
        )
        .unwrap();

        assert!(matches!(
            observe(&encoded(&[transaction])).err().unwrap(),
            JournalError::ProtectedBoundary,
        ));
    }

    #[test]
    fn foreign_native_namespace_and_nonexact_key_fail_closed() {
        let foreign = JournalTransaction::new(
            [1; 16],
            vec![JournalRecord::put(
                RecordNamespace::DesiredState, vec![1; KEY_BYTES], b"value".to_vec(),
            )],
        )
        .unwrap();
        let short = JournalTransaction::new(
            [2; 16],
            vec![JournalRecord::put(NAMESPACE, vec![1; KEY_BYTES - 1], b"value".to_vec())],
        )
        .unwrap();

        assert!(matches!(
            observe(&encoded(&[foreign])).err().unwrap(),
            JournalError::ForeignAuthorityNamespace,
        ));
        assert!(matches!(
            observe(&encoded(&[short])).err().unwrap(),
            JournalError::ProtectedBoundary,
        ));
    }

    #[test]
    fn compaction_uuid_is_refused_before_materialized_import() {
        let mut id = [0; 16];
        id[..8].copy_from_slice(&1_u64.to_le_bytes());
        id[8..].copy_from_slice(b"compact1");
        let transaction = JournalTransaction::new(
            id,
            vec![JournalRecord::put(NAMESPACE, vec![1; KEY_BYTES], b"snapshot".to_vec())],
        )
        .unwrap();

        assert!(matches!(
            observe(&encoded(&[transaction])).err().unwrap(),
            JournalError::ProtectedBoundary,
        ));
    }

    #[test]
    fn partial_and_uncommitted_tails_are_not_repaired_or_accepted() {
        let committed = encoded(&[put(1, 1, b"committed")]);
        let second = super::super::encode_transaction(&put(2, 2, b"pending"), 4).unwrap();
        let mut partial = committed.clone();
        partial.push(0);
        let mut uncommitted = committed;
        uncommitted.extend_from_slice(&second[0]);
        uncommitted.extend_from_slice(&second[1]);

        for bytes in [partial, uncommitted] {
            assert!(matches!(
                observe(&bytes).err().unwrap(),
                JournalError::StaleAuthoritySnapshot,
            ));
        }
    }

    #[test]
    fn original_parser_checksum_and_duplicate_causes_are_not_replaced() {
        let mut corrupt = encoded(&[put(1, 1, b"value")]);
        corrupt[super::super::CHECKSUM_OFFSET] ^= 1;
        let reused = encoded(&[put(1, 1, b"first"), put(1, 2, b"second")]);

        assert!(matches!(
            observe(&corrupt).err().unwrap(),
            JournalError::ChecksumMismatch(0),
        ));
        assert!(matches!(
            observe(&reused).err().unwrap(),
            JournalError::DuplicateTransaction,
        ));
    }

    #[test]
    fn materialized_refusal_precedes_prefix_replacement_clone() {
        let (native, _) = observe(&encoded(&[put(1, 1, b"value")])).unwrap();
        let mut prefix = PrefixReplay::new();
        let mut too_small = limits();
        too_small.maximum_materialized_bytes = KEY_BYTES;

        assert!(matches!(
            prefix.advance(&native, too_small),
            Err(JournalError::LimitExceeded("materialized state bytes")),
        ));
        assert!(prefix.before.is_empty());
        assert!(prefix.after.is_empty());
        assert_eq!(prefix.index, 0);
    }

    #[test]
    fn secondary_bookend_preserves_the_original_owned_io_cause() {
        let original = JournalError::Io(std::io::Error::new(
            std::io::ErrorKind::PermissionDenied, "original fixture error",
        ));
        let error = combine::<()>(Err(original), Err(JournalError::ProtectedBoundary)).unwrap_err();

        assert!(matches!(
            error.first_cause(),
            JournalError::Io(cause) if cause.kind() == std::io::ErrorKind::PermissionDenied,
        ));
        assert!(matches!(
            error.final_bookend_cause(),
            Some(JournalError::ProtectedBoundary),
        ));
        let error = combine(Ok(()), Err(JournalError::Poisoned)).unwrap_err();
        assert!(matches!(error.first_cause(), JournalError::Poisoned));
        assert!(error.final_bookend_cause().is_none());
    }
}
