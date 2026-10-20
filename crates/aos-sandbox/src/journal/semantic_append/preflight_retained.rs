//! Retains advisory preflight models on the original canonical recipe.
//!
//! These inert destinations grant no protected claim, token, writer or payment.
//! The real caller pays the complete source geometry before entry and keeps
//! this owner beside the actual returned token and independent native posts.

use std::collections::{BTreeMap, BTreeSet};
use std::error::Error;
use std::mem::size_of;

use aos_sandbox_core::{ResourceDimension as D, ResourceVector};
use aos_sandbox_journal::transaction::{NativeRecordKeyIndexV1, NativeRecordRef,
    NativeTransactionEncodeOriginalsV1, encode_transaction_retaining_v1};
use aos_sandbox_protocol::domain_ledger::transaction::{TransactionValidationCaptureV1,
    validate_transaction_retaining_v1};

use super::*;
use super::super::{IdempotencyDecision, ProtectedJournalPreflight,
    ProtectedJournalPreopenReplayExtentV1};

pub(super) struct PreflightModelsV2 {
    pub(super) state: BTreeMap<(RecordNamespace, Vec<u8>), Vec<u8>>,
    pub(super) idempotency: BTreeMap<Vec<u8>, IdempotencyDecision>,
    pub(super) transaction_ids: BTreeSet<[u8; 16]>,
    pub(super) materialized_bytes: usize,
    pub(super) next_sequence: u64,
    pub(super) committed_transactions: usize,
}

struct TransactionOriginalV2 {
    validation: TransactionValidationCaptureV1,
    encoder: NativeTransactionEncodeOriginalsV1,
    frames: Option<Vec<Vec<u8>>>,
}

impl TransactionOriginalV2 {
    const fn new() -> Self {
        Self { validation: TransactionValidationCaptureV1::new(),
            encoder: NativeTransactionEncodeOriginalsV1::new(), frames: None }
    }
}

/// Keeps actual prospective maps, indices and reached encoder prefixes.
///
/// Construction allocates nothing. This once-owned DATA sink cannot substitute
/// for current protected authority, real funding or an effect token. The
/// original advisory preflight still runs every guard and validator.
#[must_use = "retain the failed advisory preflight with its actual native interval"]
pub struct ProtectedJournalPreflightOriginalV2 {
    metadata: Option<std::io::Result<std::fs::Metadata>>,
    allocation: Option<Result<(), std::collections::TryReserveError>>,
    transactions: Vec<TransactionOriginalV2>,
    models: Option<PreflightModelsV2>,
    returned: Option<Result<(), JournalError>>,
    reentry: Option<JournalError>,
    entered: bool,
}

impl Default for ProtectedJournalPreflightOriginalV2 {
    fn default() -> Self { Self::new() }
}

impl ProtectedJournalPreflightOriginalV2 {
    /// Creates empty fixed destinations without allocation or writer entry.
    #[must_use]
    pub const fn new() -> Self {
        Self { metadata: None, allocation: None, transactions: Vec::new(),
            models: None, returned: None, reentry: None, entered: false }
    }

    /// Prices the same source maps and each actual transaction's encoder/index.
    ///
    /// The extent must come from the actual held prefix before these incoming
    /// transactions. Their exact append widths forecast the cloned prospective
    /// maps and indices through the same canonical native/semantic suppliers.
    /// This passive method
    /// authenticates neither its public fields nor payment. Only actual map,
    /// transaction and duplicate-index entries add metadata; control and codec
    /// destinations add memory only.
    ///
    /// # Errors
    /// Refuses invalid native/record geometry or checked representation overflow.
    pub fn receiving_demand_v2(extent: &ProtectedJournalPreopenReplayExtentV1,
        transactions: &[JournalTransaction]) -> Result<ResourceVector, JournalError>
    {
        let invalid = || JournalError::LimitExceeded("retained advisory preflight geometry");
        let mut bytes = size_of::<Self>().checked_mul(2)
            .and_then(|bytes| bytes.checked_add(size_of::<PreflightModelsV2>().checked_mul(2)?))
            .and_then(|bytes| bytes.checked_add(transactions.len()
                .checked_mul(size_of::<TransactionOriginalV2>())?))
            .ok_or_else(invalid)?;
        let mut names = 0usize;
        let mut future_prefix = extent.native_bytes;
        for transaction in transactions {
            let mut keys = 0usize;
            let mut largest_key = 0usize;
            let mut largest_payload = 0usize;
            let mut largest_value = 0usize;
            for record in transaction.records() {
                keys = keys.checked_add(record.key().len()).ok_or_else(invalid)?;
                largest_key = largest_key.max(record.key().len());
                largest_value = largest_value.max(record.value().map_or(0, <[u8]>::len));
                let payload = aos_sandbox_journal::geometry::EncodedRecordLayout::new(
                    record.key().len(), record.value().map(<[u8]>::len),
                ).map_err(JournalError::from)?.payload_bytes;
                largest_payload = largest_payload.max(payload);
            }
            let rows = transaction.records().len();
            let index = NativeRecordKeyIndexV1::dynamic_bytes_v1(rows, keys, largest_key)
                .ok_or_else(invalid)?;
            let encoded = encoded_transaction_append_bytes(transaction)?;
            future_prefix = future_prefix.checked_add(encoded).ok_or_else(invalid)?;
            let encoded = usize::try_from(encoded).map_err(|_| invalid())?;
            let frames = rows.checked_add(2)
                .and_then(|rows| rows.checked_mul(size_of::<Vec<u8>>()))
                .ok_or_else(invalid)?;
            // The lower encoder has exact-capacity frame slots, completed
            // frame bytes, one reached RECORD payload and COMMIT scratch.
            // The validator separately owns its key index and input copy.
            bytes = bytes.checked_add(size_of::<TransactionOriginalV2>())
                .and_then(|bytes| bytes.checked_add(index))
                .and_then(|bytes| bytes.checked_add(largest_value))
                .and_then(|bytes| bytes.checked_add(frames))
                .and_then(|bytes| bytes.checked_add(encoded))
                .and_then(|bytes| bytes.checked_add(largest_payload))
                .and_then(|bytes| bytes.checked_add(aos_sandbox_journal::framing::COMMIT_PAYLOAD_BYTES))
                .ok_or_else(invalid)?;
            names = names.checked_add(rows).ok_or_else(invalid)?;
        }
        let extra = ResourceVector::ZERO
            .with(D::MemoryBytes, u64::try_from(bytes).map_err(|_| invalid())?)
            .with(D::MetadataEntries, u64::try_from(names).map_err(|_| invalid())?);
        // Preview also clones inserted key/value rows and grows the TX-ID and
        // Idempotency indices. The same canonical future-prefix supplier pays
        // those actual incoming planes, in addition to this sink's encoders.
        let future = super::super::protected_journal_preopen_replay_extent_for_prefix_v1(
            extent.limits, future_prefix,
        )?;
        future.dominant_native_receiving_demand_v1()?
            .checked_add(future.dominant_semantic_receiving_demand_v1()?)
            .and_then(|demand| demand.checked_add(extra))
            .map_err(JournalError::ReceivingAccounting)
    }

    /// Borrows the original reached allocation, validation or native refusal.
    #[must_use]
    pub fn failure(&self) -> Option<&(dyn Error + 'static)> {
        self.metadata.as_ref().and_then(|result| result.as_ref().err())
            .map(|cause| cause as &(dyn Error + 'static))
            .or_else(|| self.allocation.as_ref()?.as_ref().err().map(|cause| cause as _))
            .or_else(|| self.transactions.iter().find_map(|transaction|
                transaction.validation.failure().map(|cause| cause as _)))
            .or_else(|| self.returned.as_ref()?.as_ref().err().map(|cause| cause as _))
            .or_else(|| self.reentry.as_ref().map(|cause| cause as _))
    }

    pub(super) fn reserve_transactions_v2(&mut self, count: usize) -> Result<(), JournalError> {
        self.allocation = Some(self.transactions.try_reserve_exact(count));
        if matches!(self.allocation, Some(Ok(()))) { Ok(()) }
        else { Err(JournalError::LimitExceeded("retained advisory preflight allocation")) }
    }

    pub(super) fn metadata_once_v2(&mut self, journal: &Journal) -> Result<u64, JournalError> {
        self.metadata = Some(journal.native.metadata());
        self.metadata.as_ref().and_then(|result| result.as_ref().ok()).map(|metadata| metadata.len())
            .ok_or(JournalError::ProtectedBoundary)
    }

    pub(super) fn begin_transaction_v2(&mut self) {
        self.transactions.push(TransactionOriginalV2::new());
    }

    pub(super) fn validate_transaction_v2(&mut self, transaction: &JournalTransaction,
        limits: JournalLimits) -> Result<(), JournalError>
    {
        let original = self.transactions.last_mut().ok_or(JournalError::ProtectedBoundary)?;
        validate_transaction_retaining_v1(transaction, limits, &mut original.validation)
            .map_err(JournalError::from)
    }

    pub(super) fn encode_transaction_v2(&mut self, transaction: &JournalTransaction,
        sequence: u64) -> Result<Vec<Vec<u8>>, JournalError>
    {
        let original = self.transactions.last_mut().ok_or(JournalError::ProtectedBoundary)?;
        encode_transaction_retaining_v1(*transaction.id(), sequence,
            transaction.records().iter().map(|record| NativeRecordRef {
                namespace_byte: record.namespace() as u8, key: record.key(), value: record.value(),
            }), &mut original.encoder).map_err(JournalError::from)
    }

    pub(super) fn retain_frames_v2(&mut self, frames: Option<Vec<Vec<u8>>>) {
        if let Some(original) = self.transactions.last_mut() { original.frames = frames; }
    }

    pub(super) fn retain_models_v2(&mut self, models: PreflightModelsV2) {
        self.models = Some(models);
    }

    fn finish_v2<T>(&mut self, result: Result<T, JournalError>) -> Result<T, JournalError> {
        match result {
            Ok(value) => { self.returned = Some(Ok(())); Ok(value) }
            Err(cause) => {
                self.returned = Some(Err(cause));
                Err(JournalError::ProtectedBoundary)
            }
        }
    }
}

impl Journal {
    /// Runs the same advisory preflight with once-owned failed DATA destinations.
    ///
    /// No protected token, mutation or financial receipt is issued. The caller
    /// prepays receiving_demand_v2 and keeps the complete sink after refusal.
    ///
    /// # Errors
    /// Preserves the original preflight cause in original.failure(), returns a
    /// coarse refusal, and refuses reentry without replacing its first prefix.
    ///
    /// # Panics
    /// Preserves the ordinary encoder's allocation and count panic conditions.
    pub fn preflight_transactions_retaining_v2(&self, transactions: &[JournalTransaction],
        original: &mut ProtectedJournalPreflightOriginalV2) -> Result<(), JournalError>
    {
        if original.entered {
            original.reentry.get_or_insert(JournalError::ProtectedBoundary);
            return Err(JournalError::ProtectedBoundary);
        }
        original.entered = true;
        let result = self.preflight_with_source_selection_engine_v2(
            PreflightTransactionViewV1::Ordinary(transactions), PreflightScope::default(),
            CacheMutationGateV1::Ordinary, None, None, Some(&mut *original),
        );
        original.finish_v2(result)
    }
}

impl ProtectedJournalAuthority<'_> {
    /// Runs the canonical preflight while retaining its reached DATA.
    ///
    /// The caller prepays and retains `original` with its actual native
    /// interval. The returned token has the ordinary protected snapshot and
    /// transaction binding; the sink grants none.
    ///
    /// # Errors
    /// Refuses the same authority, namespace, native and semantic failures.
    /// The returned error is coarse; `original.failure()` borrows the actual
    /// cause. Reentry preserves the first complete prefix unchanged.
    ///
    /// # Panics
    /// Preserves the ordinary encoder's allocation and count panic conditions.
    pub fn preflight_transactions_retaining_v2(&self, transactions: &[JournalTransaction],
        original: &mut ProtectedJournalPreflightOriginalV2)
        -> Result<ProtectedJournalPreflight, JournalError>
    {
        if original.entered {
            original.reentry.get_or_insert(JournalError::ProtectedBoundary);
            return Err(JournalError::ProtectedBoundary);
        }
        original.entered = true;
        let result = (|| {
            self.validate_generic_authority_mutation()?;
            self.journal.ensure_protected_authority()?;
            self.validate_transaction_namespaces(transactions)?;
            self.journal.preflight_with_source_selection_engine_v2(
                PreflightTransactionViewV1::Ordinary(transactions), PreflightScope::default(),
                CacheMutationGateV1::Ordinary, None, None, Some(&mut *original),
            )?;
            Ok(ProtectedJournalPreflight { snapshot: self.current_snapshot(),
                transaction_digest: super::super::authority_preflight_digest(transactions) })
        })();
        original.finish_v2(result)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn later_duplicate_retains_prior_projection_frames_and_original_journal() {
        let directory = tempfile::tempdir().unwrap();
        let path = directory.path().join("journal");
        let (journal, _) = Journal::open(&path, JournalLimits::default()).unwrap();
        let transaction = JournalTransaction::new([1; 16], vec![JournalRecord::put(
            RecordNamespace::BrokerSessionTraffic, b"actual-key".to_vec(), b"first-value".to_vec(),
        )]).unwrap();
        let second = JournalTransaction::new([1; 16], vec![JournalRecord::put(
            RecordNamespace::BrokerSessionTraffic, b"later-key".to_vec(), b"second-value".to_vec(),
        )]).unwrap();
        let transactions = [transaction, second];
        let sequence = journal.snapshot_sequence();
        let length = std::fs::metadata(&path).unwrap().len();
        let mut original = ProtectedJournalPreflightOriginalV2::new();

        let ordinary = journal.preflight_transactions(&transactions);
        let retained = journal.preflight_transactions_retaining_v2(&transactions, &mut original);

        assert!(matches!(ordinary, Err(JournalError::DuplicateTransaction)));
        assert!(matches!(retained, Err(JournalError::ProtectedBoundary)));
        assert!(matches!(original.failure().unwrap().downcast_ref::<JournalError>(),
            Some(JournalError::DuplicateTransaction)));
        let models = original.models.as_ref().unwrap();
        assert_eq!(models.state.get(&(RecordNamespace::BrokerSessionTraffic, b"actual-key".to_vec()))
            .map(Vec::as_slice), Some(b"first-value".as_slice()));
        assert!(!models.state.contains_key(&(RecordNamespace::BrokerSessionTraffic, b"later-key".to_vec())));
        assert_eq!(models.transaction_ids.len(), 1);
        assert_eq!(original.transactions.len(), 2);
        assert_eq!(original.transactions[0].frames.as_ref().unwrap().len(), 3);
        assert!(original.transactions[1].frames.is_none());
        assert_eq!(journal.snapshot_sequence(), sequence);
        assert_eq!(std::fs::metadata(&path).unwrap().len(), length);
        assert!(journal.records(RecordNamespace::BrokerSessionTraffic).next().is_none());

        let first_models = original.models.as_ref().unwrap() as *const PreflightModelsV2;
        let first_frames = original.transactions[0].frames.as_ref().unwrap().as_ptr();
        assert!(journal.preflight_transactions_retaining_v2(&[], &mut original).is_err());
        assert_eq!(original.models.as_ref().unwrap() as *const PreflightModelsV2, first_models);
        assert_eq!(original.transactions[0].frames.as_ref().unwrap().as_ptr(), first_frames);
        assert!(matches!(original.failure().unwrap().downcast_ref::<JournalError>(),
            Some(JournalError::DuplicateTransaction)));
    }
}
