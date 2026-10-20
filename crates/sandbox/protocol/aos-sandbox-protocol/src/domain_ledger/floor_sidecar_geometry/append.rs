//! Exact record and append widths for the established three-key floor format.
//!
//! These passive shapes borrow the actual main transaction and use the same
//! native record/preparation layouts as its encoder. They grant no writer,
//! floor, replay, capacity, mutation, or physical TPM authority.

use aos_sandbox_journal::geometry::{RecordShape, encoded_transaction_append_bytes};

use super::{CHECKPOINT_BYTES_V1, CHECKPOINT_KEY_V1, INTENT_BYTES_V1, INTENT_KEY_V1,
    TRANSACTION_KEY_V1};
use crate::domain_ledger::{JournalTransactionDataError, transaction::{JournalLimits, JournalTransaction}};

/// Describes the exact preparation and finalization suffix before encoding.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct FloorSidecarAppendGeometryDataV2 {
    /// Counts the actual main transaction's canonical preparation bytes.
    pub prepared_transaction_bytes: usize,
    /// Retains the two ordered PUT widths in the preparation transaction.
    pub preparation_records: [RecordShape; 2],
    /// Retains the ordered checkpoint PUT and two DELETE widths.
    pub finalization_records: [RecordShape; 3],
    /// Counts one preparation's complete native BEGIN/RECORD/COMMIT append.
    pub preparation_append_bytes: u64,
    /// Counts one finalization's complete native BEGIN/RECORD/COMMIT append.
    pub finalization_append_bytes: u64,
}

impl FloorSidecarAppendGeometryDataV2 {
    /// Measures the actual main transaction and both existing sidecar appends.
    ///
    /// No transaction, record, encoded bytes, map or native prefix is allocated.
    /// The original encoder independently retains all semantic validation.
    ///
    /// # Errors
    /// Rejects invalid main limits, unrepresentable preparation/native framing,
    /// or checked width overflow in the same native layout helpers.
    pub fn from_transaction_v2(transaction: &JournalTransaction, main_limits: JournalLimits)
        -> Result<Self, JournalTransactionDataError>
    {
        let prepared_transaction_bytes = transaction.prepared_encoded_bytes_v2(main_limits)?;
        let preparation_records = preparation_record_shapes_v2(prepared_transaction_bytes);
        let finalization_records = finalization_record_shapes_v2();
        let preparation_append_bytes = encoded_transaction_append_bytes(preparation_records.into_iter())?;
        let finalization_append_bytes = encoded_transaction_append_bytes(finalization_records.into_iter())?;
        Ok(Self { prepared_transaction_bytes, preparation_records, finalization_records,
            preparation_append_bytes, finalization_append_bytes })
    }
}

/// Returns the established intent and prepared-transaction PUT widths.
#[must_use]
pub const fn preparation_record_shapes_v2(prepared_transaction_bytes: usize) -> [RecordShape; 2] {
    [
        RecordShape { key_bytes: INTENT_KEY_V1.len(), value_bytes: Some(INTENT_BYTES_V1) },
        RecordShape { key_bytes: TRANSACTION_KEY_V1.len(), value_bytes: Some(prepared_transaction_bytes) },
    ]
}

/// Returns the established checkpoint PUT followed by intent/transaction DELETE.
#[must_use]
pub const fn finalization_record_shapes_v2() -> [RecordShape; 3] {
    [
        RecordShape { key_bytes: CHECKPOINT_KEY_V1.len(), value_bytes: Some(CHECKPOINT_BYTES_V1) },
        RecordShape { key_bytes: INTENT_KEY_V1.len(), value_bytes: None },
        RecordShape { key_bytes: TRANSACTION_KEY_V1.len(), value_bytes: None },
    ]
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::domain_ledger::transaction::JournalRecord;
    use aos_sandbox_model::RecordNamespace;

    #[test]
    fn two_appends_keep_the_existing_fixed_records_and_each_native_frame() {
        let transaction = JournalTransaction::new([1; 16], vec![JournalRecord::put(
            RecordNamespace::BrokerSessionTraffic, b"a".to_vec(), b"z".to_vec(),
        )]).unwrap();

        let geometry = FloorSidecarAppendGeometryDataV2::from_transaction_v2(
            &transaction, JournalLimits::default(),
        ).unwrap();

        // AOSJPT01 header32 + length4 + record(7+1+1). Each native
        // transaction separately keeps BEGIN76 and COMMIT108, with one72B
        // frame header for each actual ordered record.
        assert_eq!(geometry.prepared_transaction_bytes, 45);
        assert_eq!(geometry.preparation_append_bytes, 76 + (72 + 337) + (72 + 63) + 108);
        assert_eq!(geometry.finalization_append_bytes,
            76 + (72 + 173) + (72 + 13) + (72 + 18) + 108);
        assert_eq!(transaction.encode_prepared_v1(JournalLimits::default()).unwrap().len(), 45);
    }
}
