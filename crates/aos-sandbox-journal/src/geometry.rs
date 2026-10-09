//! Pure native record, append, and preparation geometry.
//!
//! Sizes are nonauthorizing DATA: they do not reserve capacity, open storage,
//! validate namespaces, or admit transitions. Domain owners supply sizes from
//! their actual ordered records and retain all semantic validation.
//!
//! ```text
//! native record width = 7 + key bytes + present value bytes
//! native append width = BEGIN(72+4) + sum(RECORD(72+payload)) + COMMIT(72+36)
//! prepared maximum    = 32 + 4*maximum records + maximum transaction bytes
//! ```

use crate::framing::{COMMIT_PAYLOAD_BYTES, EncodedFrameLayout, FrameError, HEADER_BYTES};

/// Specifies the canonical preparation wrapper's fixed header width.
pub const PREPARED_HEADER_BYTES: usize = 32;

/// Describes one record's actual lengths without namespace or record bytes.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct RecordShape {
    /// Carries the actual key length.
    pub key_bytes: usize,
    /// Distinguishes a DELETE from a present, possibly empty, PUT value.
    pub value_bytes: Option<usize>,
}

/// Shares checked native encoder fields and payload width without copying bytes.
pub struct EncodedRecordLayout {
    /// Carries the checked little-endian u16 key length.
    pub key_length: u16,
    /// Carries the checked u32 value length or the existing DELETE sentinel.
    pub value_length: u32,
    /// Counts the header, key, and actual present value bytes.
    pub payload_bytes: usize,
}

impl EncodedRecordLayout {
    /// Computes the existing native record fields and complete payload width.
    ///
    /// This is representation arithmetic, not nonempty-key or namespace admission.
    ///
    /// # Errors
    ///
    /// Rejects an unrepresentable key, then value, then aggregate usize width.
    pub fn new(key_bytes: usize, value_bytes: Option<usize>) -> Result<Self, FrameError> {
        let key_length = u16::try_from(key_bytes)
            .map_err(|_| FrameError::LimitExceeded("record key bytes"))?;
        let value_length = match value_bytes {
            Some(bytes) => u32::try_from(bytes)
                .map_err(|_| FrameError::LimitExceeded("record value bytes"))?,
            None => u32::MAX,
        };

        // Some(u32::MAX) retains its bytes despite sharing the DEL sentinel.
        // Checked usize arithmetic avoids wrapping the capacity sum on 32-bit.
        let payload_bytes = 7_usize
            .checked_add(key_bytes)
            .and_then(|bytes| bytes.checked_add(value_bytes.unwrap_or_default()))
            .ok_or(FrameError::JournalTooLarge)?;

        Ok(Self {
            key_length,
            value_length,
            payload_bytes,
        })
    }
}

/// Measures canonical append framing without granting admission or capacity.
///
/// The exact-size iterator supplies actual ordered record lengths. Measurement
/// preserves encoder error order and accepts empty or otherwise unadmitted
/// shapes; domain owners separately enforce transaction identity and semantics.
///
/// # Errors
///
/// Rejects unrepresentable record counts, record/frame widths, sequence space,
/// or aggregate append lengths, preserving the original encoder precedence.
pub fn encoded_transaction_append_bytes(
    records: impl ExactSizeIterator<Item = RecordShape>,
) -> Result<u64, FrameError> {
    let record_count = u32::try_from(records.len())
        .map_err(|_| FrameError::LimitExceeded("records per transaction"))?;
    let begin = EncodedFrameLayout::new(record_count.to_le_bytes().len())?;
    let mut total = Some(begin.frame_bytes as u64);
    let mut sequence = 0_u64;
    sequence = sequence
        .checked_add(1)
        .ok_or(FrameError::SequenceExhausted)?;

    // The encoder validates every frame before folding its lengths. Preserve
    // that precedence even after the aggregate can no longer fit in u64.
    for record in records {
        let record_layout = EncodedRecordLayout::new(record.key_bytes, record.value_bytes)?;
        let frame = EncodedFrameLayout::new(record_layout.payload_bytes)?;
        total = total.and_then(|bytes| bytes.checked_add(frame.frame_bytes as u64));
        sequence = sequence
            .checked_add(1)
            .ok_or(FrameError::SequenceExhausted)?;
    }

    let commit = EncodedFrameLayout::new(COMMIT_PAYLOAD_BYTES)?;
    total
        .and_then(|bytes| bytes.checked_add(commit.frame_bytes as u64))
        .ok_or(FrameError::JournalTooLarge)
}

/// Carries the existing eight native bounds as nonauthorizing geometry DATA.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct NativeGeometryBounds {
    /// Bounds the journal's native byte length.
    pub maximum_journal_bytes: u64,
    /// Bounds the complete native payload width of a record.
    pub maximum_record_bytes: usize,
    /// Bounds one logical key's byte length.
    pub maximum_key_bytes: usize,
    /// Bounds the declared records in one native transaction.
    pub maximum_records_per_transaction: usize,
    /// Bounds aggregate record payload bytes in one transaction.
    pub maximum_transaction_bytes: usize,
    /// Bounds the native committed transaction count.
    pub maximum_transactions: usize,
    /// Bounds logical materialized key and value bytes.
    pub maximum_materialized_bytes: usize,
    /// Bounds the materialized record count.
    pub maximum_materialized_records: usize,
}

/// Validates the existing native configuration's generic representation bounds.
///
/// This does not inspect a journal or grant capacity, authority, or admission.
///
/// # Errors
///
/// Returns the existing invalid-configuration error for any of the nine
/// undersized, zero, or unrepresentable native configuration conditions.
pub fn validate_native_bounds(limits: NativeGeometryBounds) -> Result<(), FrameError> {
    if limits.maximum_journal_bytes < HEADER_BYTES as u64
        || limits.maximum_record_bytes < 7
        || limits.maximum_key_bytes == 0
        || limits.maximum_key_bytes > u16::MAX as usize
        || limits.maximum_records_per_transaction == 0
        || limits.maximum_transaction_bytes < 7
        || limits.maximum_transactions == 0
        || limits.maximum_materialized_bytes == 0
        || limits.maximum_materialized_records == 0
    {
        return Err(FrameError::LimitExceeded("invalid journal configuration"));
    }
    Ok(())
}

/// Measures the existing maximum preparation width for all eight native bounds.
///
/// The canonical preparation uses a fixed32 header and BEu32 per-record lengths;
/// the contained native record payloads retain their own little-endian format.
///
/// # Errors
///
/// Validates the existing configuration first, then rejects overflowing
/// per-record framing, fixed-header, or aggregate payload arithmetic.
pub fn maximum_prepared_bytes(limits: NativeGeometryBounds) -> Result<usize, FrameError> {
    validate_native_bounds(limits)?;
    limits
        .maximum_records_per_transaction
        .checked_mul(4)
        .and_then(|framing| framing.checked_add(PREPARED_HEADER_BYTES))
        .and_then(|framing| framing.checked_add(limits.maximum_transaction_bytes))
        .ok_or(FrameError::LimitExceeded("prepared transaction bytes"))
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used)]

    use super::*;

    #[test]
    fn record_layout_preserves_length_order_and_delete_sentinel() {
        let deleted = EncodedRecordLayout::new(u16::MAX as usize, None).unwrap();
        let empty_put = EncodedRecordLayout::new(u16::MAX as usize, Some(0)).unwrap();

        assert_eq!(deleted.key_length, u16::MAX);
        assert_eq!(deleted.value_length, u32::MAX);
        assert_eq!(empty_put.value_length, 0);
        assert_eq!(deleted.payload_bytes, empty_put.payload_bytes);
        assert_eq!(deleted.payload_bytes, 7 + u16::MAX as usize);
        assert!(matches!(
            EncodedRecordLayout::new(usize::MAX, Some(usize::MAX)),
            Err(FrameError::LimitExceeded("record key bytes")),
        ));

        #[cfg(target_pointer_width = "64")]
        {
            let maximum_put = EncodedRecordLayout::new(0, Some(u32::MAX as usize)).unwrap();

            assert_eq!(maximum_put.value_length, deleted.value_length);
            assert_eq!(maximum_put.payload_bytes, 7 + u32::MAX as usize);
            assert!(matches!(
                EncodedRecordLayout::new(0, Some(u32::MAX as usize + 1)),
                Err(FrameError::LimitExceeded("record value bytes")),
            ));
            assert!(matches!(
                EncodedFrameLayout::new(maximum_put.payload_bytes),
                Err(FrameError::LimitExceeded("frame payload bytes")),
            ));
            let maximum_frame = EncodedFrameLayout::new(u32::MAX as usize).unwrap();
            assert_eq!(maximum_frame.frame_bytes, HEADER_BYTES + u32::MAX as usize);
        }

        #[cfg(target_pointer_width = "32")]
        {
            assert!(matches!(
                EncodedRecordLayout::new(0, Some(u32::MAX as usize)),
                Err(FrameError::JournalTooLarge),
            ));
            assert!(matches!(
                EncodedFrameLayout::new(u32::MAX as usize),
                Err(FrameError::JournalTooLarge),
            ));
        }
    }

    #[test]
    fn append_geometry_preserves_put_delete_and_empty_widths() {
        let cases = [
            (vec![], 184),
            (vec![RecordShape { key_bytes: 3, value_bytes: Some(2) }], 268),
            (vec![RecordShape { key_bytes: 3, value_bytes: None }], 266),
            (
                vec![
                    RecordShape { key_bytes: 3, value_bytes: Some(2) },
                    RecordShape { key_bytes: 4, value_bytes: None },
                ],
                351,
            ),
        ];

        for (records, expected) in cases {
            assert_eq!(
                encoded_transaction_append_bytes(records.into_iter()).unwrap(),
                expected,
            );
        }
    }

    fn minimum_bounds() -> NativeGeometryBounds {
        NativeGeometryBounds {
            maximum_journal_bytes: 72,
            maximum_record_bytes: 7,
            maximum_key_bytes: 1,
            maximum_records_per_transaction: 1,
            maximum_transaction_bytes: 7,
            maximum_transactions: 1,
            maximum_materialized_bytes: 1,
            maximum_materialized_records: 1,
        }
    }

    #[test]
    fn preparation_geometry_preserves_all_nine_configuration_checks() {
        let minimum = minimum_bounds();
        let invalid = [
            NativeGeometryBounds { maximum_journal_bytes: 71, ..minimum },
            NativeGeometryBounds { maximum_record_bytes: 6, ..minimum },
            NativeGeometryBounds { maximum_key_bytes: 0, ..minimum },
            NativeGeometryBounds { maximum_key_bytes: u16::MAX as usize + 1, ..minimum },
            NativeGeometryBounds { maximum_records_per_transaction: 0, ..minimum },
            NativeGeometryBounds { maximum_transaction_bytes: 6, ..minimum },
            NativeGeometryBounds { maximum_transactions: 0, ..minimum },
            NativeGeometryBounds { maximum_materialized_bytes: 0, ..minimum },
            NativeGeometryBounds { maximum_materialized_records: 0, ..minimum },
        ];

        assert_eq!(maximum_prepared_bytes(minimum).unwrap(), 43);
        for bounds in invalid {
            assert!(matches!(
                validate_native_bounds(bounds),
                Err(FrameError::LimitExceeded("invalid journal configuration")),
            ));
            assert!(matches!(
                maximum_prepared_bytes(bounds),
                Err(FrameError::LimitExceeded("invalid journal configuration")),
            ));
        }
    }

    #[test]
    fn preparation_geometry_preserves_checked_arithmetic() {
        let minimum = minimum_bounds();

        for bounds in [
            NativeGeometryBounds { maximum_records_per_transaction: usize::MAX, ..minimum },
            NativeGeometryBounds { maximum_transaction_bytes: usize::MAX, ..minimum },
        ] {
            assert!(matches!(
                maximum_prepared_bytes(bounds),
                Err(FrameError::LimitExceeded("prepared transaction bytes")),
            ));
        }
    }
}
