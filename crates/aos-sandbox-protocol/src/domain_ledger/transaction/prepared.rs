//! Retains reached preparation DATA through the existing native decoder.
//!
//! No input, retained transaction or validator index grants a Journal, physical
//! floor, current predecessor or receiving allowance. A real owner prepays the
//! actual encoded extent and keeps this capture before entering the decoder.

use std::error::Error;
use std::mem::size_of;

use super::{JournalLimits, JournalRecord, JournalTransaction, JournalTransactionDataError,
    TransactionValidationCaptureV1, HEADER_BYTES};
use aos_sandbox_journal::transaction::NativeRecordKeyIndexV1;

/// Owns partial records and the actual failed transaction validation.
///
/// One selected decoding attempt keeps every completed record before a later
/// framing error. Once all records exist, their same transaction is parked
/// before semantic validation; its real owning key index stays alongside it.
#[must_use = "retain failed preparation records and native validation partials"]
#[derive(Default)]
pub struct PreparedTransactionDecodeCaptureV1 {
    pub(super) records: Vec<JournalRecord>,
    pub(super) transaction: Option<JournalTransaction>,
    pub(super) validation: TransactionValidationCaptureV1,
    returned: Option<Result<JournalTransaction, JournalTransactionDataError>>,
    entered: bool,
    reentry: Option<JournalTransactionDataError>,
}

impl PreparedTransactionDecodeCaptureV1 {
    /// Creates empty destinations without parsing or allocating.
    #[must_use]
    pub fn new() -> Self { Self::default() }

    /// Decodes once while retaining every reached record or validation failure.
    ///
    /// The caller owns the original bytes for this whole interval; this method
    /// neither copies those inputs nor binds them to a file or financial owner.
    ///
    /// # Errors
    /// Preserves the same preparation framing, record or semantic refusal.
    /// Reentry leaves the original failed partials and cause unchanged.
    pub fn decode_once_v1(&mut self, bytes: &[u8], limits: JournalLimits)
        -> Result<&JournalTransaction, JournalTransactionDataError>
    {
        if self.entered {
            self.reentry.get_or_insert(JournalTransactionDataError::InvalidTransaction);
            return Err(JournalTransactionDataError::InvalidTransaction);
        }
        self.entered = true;
        self.returned = Some(JournalTransaction::decode_prepared_engine(bytes, limits, Some(self)));
        self.completed_v1().ok_or(JournalTransactionDataError::InvalidTransaction)
    }

    /// Borrows the exact completed DATA without asserting persistence or authority.
    #[must_use]
    pub fn completed_v1(&self) -> Option<&JournalTransaction> {
        if self.failure().is_some() { return None; }
        self.returned.as_ref()?.as_ref().ok()
    }

    /// Moves only the completed DATA while keeping the one-shot fence.
    #[must_use]
    pub fn take_completed_v1(&mut self) -> Option<JournalTransaction> {
        self.completed_v1()?;
        match self.returned.take() {
            Some(Ok(transaction)) => Some(transaction),
            original => { self.returned = original; None }
        }
    }

    /// Borrows the earliest actual codec or retained semantic cause.
    #[must_use]
    pub fn failure(&self) -> Option<&(dyn Error + 'static)> {
        self.validation.failure().map(|cause| cause as &(dyn Error + 'static))
            .or_else(|| self.returned.as_ref().and_then(|result| result.as_ref().err())
                .map(|cause| cause as &(dyn Error + 'static)))
            .or_else(|| self.reentry.as_ref().map(|cause| cause as _))
    }

    fn record_bound_v2(encoded_bytes: usize, limits: JournalLimits) -> usize {
        (encoded_bytes.saturating_sub(HEADER_BYTES) / 12)
            .min(limits.maximum_records_per_transaction)
    }

    /// Counts retained ordered records and the actual validation-key index.
    ///
    /// The count uses the same preparation framing and configured record
    /// ceiling as the decoder. Parser fields and a current duplicate key are
    /// byte provision; they create no additional row or key-index entry.
    #[must_use]
    pub fn receiving_named_entries_v2(encoded_bytes: usize, limits: JournalLimits) -> Option<usize> {
        Self::record_bound_v2(encoded_bytes, limits).checked_mul(2)
    }

    /// Bounds this decoder's additional requested representations as DATA.
    ///
    /// The twelve-byte minimum is the SAME existing preparation count gate.
    /// Each admitted record has its own native model and owned index key; no
    /// largest-domain-model multiplier is applied to encoded input bytes.
    /// The original input and other sidecar/floor models remain additional.
    #[must_use]
    pub fn receiving_obligations_v1(encoded_bytes: usize, limits: JournalLimits)
        -> Option<(usize, usize)>
    {
        let records = Self::record_bound_v2(encoded_bytes, limits);
        let record_backing = records.checked_mul(size_of::<JournalRecord>())?.checked_mul(3)?;
        let current_key = encoded_bytes.min(limits.maximum_key_bytes);
        let index = NativeRecordKeyIndexV1::dynamic_bytes_v1(records, encoded_bytes, current_key)?;
        // Owned key/value bytes and the Idempotency parser's temporary copy.
        let payload = encoded_bytes.checked_mul(2)?;
        let bytes = size_of::<Self>().checked_mul(2)?.checked_add(record_backing)?
            .checked_add(index)?.checked_add(payload)?;
        // Parser: eight limit fields plus bytes/capture/id/count/cursor,
        // ordinary Vec/record borrow/payload count/ordinal/length/end/payload
        // and constructor/return destinations. The native validator's three
        // fields, eight bounds, key variant and six borrowed/return controls
        // coexist. Its own helper separately supplies actual retained owners.
        let parser_controls = 8 + 14;
        let validation_controls = 3 + 8 + 1 + 6;
        // Capture6, current-key tuple2, typed Idempotency2; each row has three
        // JournalRecord fields plus its index tuple/node namespaces3.
        let cells = TransactionValidationCaptureV1::receiving_metadata_cells_v1()?
            .checked_add(6 + parser_controls + validation_controls + 2 + 2)?
            .checked_add(records.checked_mul(3 + 3)?)?;
        Some((bytes, cells))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use aos_sandbox_core::RecordNamespace;

    fn transaction() -> JournalTransaction {
        JournalTransaction::new([1; 16], vec![
            JournalRecord::put(RecordNamespace::BrokerSessionTraffic, b"a".to_vec(), vec![1]),
            JournalRecord::put(RecordNamespace::BrokerSessionTraffic,
                b"b".to_vec(), vec![2]),
        ]).unwrap()
    }

    #[test]
    fn named_invoice_tracks_real_records_and_keys_without_control_field_entries() {
        let limits = JournalLimits::default();
        let bytes = transaction().encode_prepared_v1(limits).unwrap();
        let mut capture = PreparedTransactionDecodeCaptureV1::new();

        capture.decode_once_v1(&bytes, limits).unwrap();
        let reached = capture.completed_v1().unwrap().records().len()
            + capture.validation.index_v1().retained_key_count_v1();

        assert!(PreparedTransactionDecodeCaptureV1::receiving_named_entries_v2(
            bytes.len(), limits,
        ).unwrap() >= reached);
        assert_eq!(PreparedTransactionDecodeCaptureV1::receiving_named_entries_v2(
            HEADER_BYTES, limits,
        ), Some(0));
        assert!(PreparedTransactionDecodeCaptureV1::receiving_obligations_v1(
            HEADER_BYTES, limits,
        ).unwrap().0 > 0);
    }

    #[test]
    fn truncated_second_record_keeps_first_record_and_exact_cause_after_reentry() {
        let limits = JournalLimits::default();
        let mut bytes = transaction().encode_prepared_v1(limits).unwrap();
        bytes.pop();
        let mut capture = PreparedTransactionDecodeCaptureV1::new();

        assert!(capture.decode_once_v1(&bytes, limits).is_err());
        assert_eq!(capture.records.len(), 1);
        assert_eq!(capture.records[0].key(), b"a");
        let first = capture.failure().unwrap().downcast_ref::<JournalTransactionDataError>().unwrap()
            as *const JournalTransactionDataError;
        assert!(capture.decode_once_v1(&[], limits).is_err());
        assert_eq!(capture.failure().unwrap().downcast_ref::<JournalTransactionDataError>().unwrap()
            as *const JournalTransactionDataError, first);
        assert_eq!(capture.records.len(), 1);
    }

    #[test]
    fn duplicate_failure_keeps_transaction_and_owning_index() {
        let limits = JournalLimits::default();
        let mut bytes = transaction().encode_prepared_v1(limits).unwrap();
        // Equal one-byte keys preserve native widths and exact wrapper framing.
        let second_key = HEADER_BYTES + 4 + 9 + 4 + 7;
        bytes[second_key] = b'a';
        let mut capture = PreparedTransactionDecodeCaptureV1::new();

        assert!(capture.decode_once_v1(&bytes, limits).is_err());
        assert_eq!(capture.transaction.as_ref().unwrap().records().len(), 2);
        assert_eq!(capture.validation.index_v1().retained_key_count_v1(), 1);
        assert_eq!(capture.validation.index_v1().current_key_v1(), Some((RecordNamespace::BrokerSessionTraffic as u8, &b"a"[..])));
        assert!(capture.take_completed_v1().is_none());
    }

    #[test]
    fn positive_capture_matches_same_ordinary_codec_and_moves_without_redecode() {
        let limits = JournalLimits::default();
        let bytes = transaction().encode_prepared_v1(limits).unwrap();
        let ordinary = JournalTransaction::decode_prepared_v1(&bytes, limits).unwrap();
        let mut capture = PreparedTransactionDecodeCaptureV1::new();

        assert_eq!(capture.decode_once_v1(&bytes, limits).unwrap(), &ordinary);
        let address = capture.completed_v1().unwrap().records().as_ptr();
        let moved = capture.take_completed_v1().unwrap();
        assert_eq!(moved, ordinary);
        assert_eq!(moved.records().as_ptr(), address);
        assert!(capture.decode_once_v1(&bytes, limits).is_err());
    }
}
