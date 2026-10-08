//! Borrowed native suffix accounting over exact before and after images.
//!
//! The accumulator owns map nodes, counters, and prefix observations, not the
//! supplied keys or values. Domain owners retain their actual mutation graphs,
//! closed namespaces, chronology, and capacity admission. Raw namespace bytes
//! and widths here are DATA, never evidence of currentness or permission.
//!
//! ```text
//! retained row = key bytes + present value bytes (DELETE retains no row)
//! prefix delta = current retained total - first-observed retained total
//! append width = BEGIN + ordered RECORD frames + COMMIT
//! ```

use std::collections::BTreeMap;

use crate::framing::FrameError;
use crate::geometry::{
    EncodedRecordLayout, NativeGeometryBounds, RecordShape, encoded_transaction_append_bytes,
};
use crate::transaction::{NativeRecordValidation, NativeRecordValidationError};

/// Borrows one exact mutation's before and after images.
#[derive(Clone, Copy, Debug)]
pub struct NativeBeforeAfterRef<'rows> {
    /// Borrows the original logical key.
    pub key: &'rows [u8],
    /// Borrows the prior value, or records an absent prior row.
    pub before: Option<&'rows [u8]>,
    /// Borrows the successor value, or records deletion.
    pub after: Option<&'rows [u8]>,
}

/// Carries one ordered raw record's encoding extents without copying its value.
#[derive(Clone, Copy, Debug)]
pub struct NativeRecordExtentRef<'record> {
    /// Carries the raw namespace byte solely for duplicate-key comparison.
    pub namespace_byte: u8,
    /// Borrows the exact logical key.
    pub key: &'record [u8],
    /// Distinguishes DELETE from a present, possibly empty, value's width.
    pub value_bytes: Option<usize>,
}

/// Reports accumulated native widths and positive retained-growth maxima.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct NativeSuffixGeometry {
    /// Counts measured appends.
    pub transactions: u32,
    /// Counts their ordered native records.
    pub records: u32,
    /// Counts their complete native framing bytes.
    pub append_bytes: u64,
    /// Records the greatest record count in one append.
    pub maximum_transaction_records: u32,
    /// Records the greatest aggregate record payload width in one append.
    pub maximum_transaction_record_bytes: u64,
    /// Records the greatest positive retained byte delta from the initial rows.
    pub maximum_retained_growth_bytes: u64,
    /// Records the greatest positive retained row delta from the initial rows.
    pub maximum_retained_growth_records: u32,
}

/// Reports one signed retained delta and its supplied schedule position.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct NativeSuffixPrefix {
    /// Carries current minus initially observed retained bytes.
    pub owner_bytes: i128,
    /// Carries current minus initially observed retained rows.
    pub owner_records: i64,
    /// Copies the caller's schedule flag without validating finality.
    pub final_append: bool,
}

/// Returns completed measurement DATA without granting headroom or admission.
pub struct NativeSuffixMeasured {
    /// Carries aggregate native geometry.
    pub geometry: NativeSuffixGeometry,
    /// Retains observations in supplied append order.
    pub prefixes: Vec<NativeSuffixPrefix>,
    /// Records the greatest supplied key width.
    pub maximum_key_bytes: usize,
    /// Records the greatest complete record payload width.
    pub maximum_record_payload_bytes: usize,
}

/// Describes native accounting refusals without domain-specific error causes.
#[derive(Debug, thiserror::Error)]
pub enum NativeSuffixError {
    /// Rejects a zero transaction ID, empty transaction, or invalid subtraction.
    #[error("invalid native suffix transaction")]
    InvalidTransaction,
    /// Rejects a before image differing from the exact retained successor.
    #[error("native capacity inconsistent before image")]
    InconsistentBeforeImage,
    /// Rejects a repeated raw namespace and key in one append.
    #[error("duplicate native suffix record key")]
    DuplicateRecordKey,
    /// Preserves a configured bound or native suffix count refusal.
    #[error("native suffix limit exceeded: {0}")]
    LimitExceeded(&'static str),
    /// Preserves checked retained or aggregate native byte overflow.
    #[error("native suffix journal too large")]
    JournalTooLarge,
    /// Preserves existing representational record and frame arithmetic errors.
    #[error(transparent)]
    Frame(#[from] FrameError),
}

impl From<NativeRecordValidationError> for NativeSuffixError {
    fn from(error: NativeRecordValidationError) -> Self {
        match error {
            NativeRecordValidationError::InvalidTransaction => Self::InvalidTransaction,
            NativeRecordValidationError::DuplicateRecordKey => Self::DuplicateRecordKey,
            NativeRecordValidationError::LimitExceeded(bound) => Self::LimitExceeded(bound),
            NativeRecordValidationError::Frame(error) => Self::Frame(error),
        }
    }
}

/// Owns one incremental measurement while borrowing the original row graph.
///
/// Successful appends publish geometry and a prefix only after all their raw
/// record checks. A failed observation can retain earlier row-accounting work;
/// callers discard that accumulator, just as they discarded the original fold.
/// This type performs no I/O and does not inspect or mutate a live journal.
#[derive(Default)]
pub struct NativeSuffixMeasurement<'rows> {
    // Prefix allocation precedes the map so disposal follows the original fold.
    prefixes: Vec<NativeSuffixPrefix>,
    states: BTreeMap<&'rows [u8], Option<&'rows [u8]>>,
    original_bytes: u64,
    current_bytes: u64,
    original_records: u32,
    current_records: u32,
    geometry: NativeSuffixGeometry,
    maximum_key_bytes: usize,
    maximum_record_payload_bytes: usize,
}

impl<'rows> NativeSuffixMeasurement<'rows> {
    /// Starts empty accounting without borrowing or authorizing a journal.
    pub fn new() -> Self {
        Self::default()
    }

    /// Observes exact row mutations and their ordered raw encoding extents.
    ///
    /// Images are checked and retained before transaction and record bounds,
    /// matching the original fold's failure frontiers. Duplicate namespace/key
    /// pairs are checked after each record's configured bounds. Namespaces have
    /// no semantic interpretation here; owners validate their closed schedules.
    /// The schedule flag is copied into the observation, not accepted as proof.
    ///
    /// # Errors
    ///
    /// Rejects inconsistent before images, invalid accounting or transaction
    /// identity, configured record bounds, duplicate raw keys, representational
    /// widths, or overflowing native geometry, in the original fold's order.
    pub fn observe_append(
        &mut self,
        transaction_id: [u8; 16],
        changes: impl IntoIterator<Item = NativeBeforeAfterRef<'rows>>,
        records: &[NativeRecordExtentRef<'_>],
        final_append: bool,
        bounds: NativeGeometryBounds,
    ) -> Result<(), NativeSuffixError> {
        for change in changes {
            if let Some(current) = self.states.get(change.key) {
                if *current != change.before {
                    return Err(NativeSuffixError::InconsistentBeforeImage);
                }
            } else {
                let (bytes, count) = retained(change.key, change.before)?;
                self.original_bytes = add(self.original_bytes, bytes)?;
                self.current_bytes = add(self.current_bytes, bytes)?;
                self.original_records = add_records(self.original_records, count)?;
                self.current_records = add_records(self.current_records, count)?;
            }
            let (before_bytes, before_count) = retained(change.key, change.before)?;
            let (after_bytes, after_count) = retained(change.key, change.after)?;
            self.current_bytes = add(
                self.current_bytes
                    .checked_sub(before_bytes)
                    .ok_or(NativeSuffixError::InvalidTransaction)?,
                after_bytes,
            )?;
            self.current_records = add_records(
                self.current_records
                    .checked_sub(before_count)
                    .ok_or(NativeSuffixError::InvalidTransaction)?,
                after_count,
            )?;
            self.states.insert(change.key, change.after);
        }

        // The duplicate index drops before width observations, at the original
        // validator boundary. Namespace semantics remain with the caller.
        {
            let mut validation =
                NativeRecordValidation::begin(transaction_id, records.len(), bounds)?;
            for record in records {
                validation.observe_extent(record.key, record.value_bytes)?;
                validation.register_key(record.namespace_byte, record.key)?;
            }
        }

        for record in records {
            self.maximum_key_bytes = self.maximum_key_bytes.max(record.key.len());
            self.maximum_record_payload_bytes = self
                .maximum_record_payload_bytes
                .max(record_layout(record)?.payload_bytes);
        }
        let append_bytes =
            encoded_transaction_append_bytes(records.iter().map(|record| RecordShape {
                key_bytes: record.key.len(),
                value_bytes: record.value_bytes,
            }))?;
        let record_bytes = records.iter().try_fold(0_u64, |total, record| {
            add(total, record_layout(record)?.payload_bytes as u64)
        })?;
        let record_count = u32::try_from(records.len())
            .map_err(|_| NativeSuffixError::LimitExceeded("native suffix records"))?;

        self.geometry.transactions = add_records(self.geometry.transactions, 1)?;
        self.geometry.records = add_records(self.geometry.records, record_count)?;
        self.geometry.append_bytes = add(self.geometry.append_bytes, append_bytes)?;
        self.geometry.maximum_transaction_records =
            self.geometry.maximum_transaction_records.max(record_count);
        self.geometry.maximum_transaction_record_bytes = self
            .geometry
            .maximum_transaction_record_bytes
            .max(record_bytes);
        self.geometry.maximum_retained_growth_bytes = self
            .geometry
            .maximum_retained_growth_bytes
            .max(self.current_bytes.saturating_sub(self.original_bytes));
        self.geometry.maximum_retained_growth_records = self
            .geometry
            .maximum_retained_growth_records
            .max(self.current_records.saturating_sub(self.original_records));
        self.prefixes.push(NativeSuffixPrefix {
            owner_bytes: i128::from(self.current_bytes) - i128::from(self.original_bytes),
            owner_records: i64::from(self.current_records) - i64::from(self.original_records),
            final_append,
        });
        Ok(())
    }

    /// Consumes accounting and returns raw observations without a headroom check.
    pub fn finish(self) -> NativeSuffixMeasured {
        NativeSuffixMeasured {
            geometry: self.geometry,
            prefixes: self.prefixes,
            maximum_key_bytes: self.maximum_key_bytes,
            maximum_record_payload_bytes: self.maximum_record_payload_bytes,
        }
    }
}

fn record_layout(record: &NativeRecordExtentRef<'_>) -> Result<EncodedRecordLayout, FrameError> {
    EncodedRecordLayout::new(record.key.len(), record.value_bytes)
}

fn retained(key: &[u8], value: Option<&[u8]>) -> Result<(u64, u32), NativeSuffixError> {
    match value {
        Some(value) => Ok((add(key.len() as u64, value.len() as u64)?, 1)),
        None => Ok((0, 0)),
    }
}

fn add(left: u64, right: u64) -> Result<u64, NativeSuffixError> {
    left.checked_add(right)
        .ok_or(NativeSuffixError::JournalTooLarge)
}

fn add_records(left: u32, right: u32) -> Result<u32, NativeSuffixError> {
    left.checked_add(right)
        .ok_or(NativeSuffixError::LimitExceeded("native suffix records"))
}

#[cfg(test)]
mod tests;
