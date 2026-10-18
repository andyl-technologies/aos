//! Reconstructs the exact native Blob leaf into an owning, permanently spent attempt.
//!
//! Record and pin trees use source-private native layout rows and independent
//! concrete target geometry. Their initialized child-header banks are retained
//! after completed values move, so later failures retain every nested owner.

use super::*;
use crate::connection::settled17::HistoricalByteBank17;
use crate::protocol_snapshot::owned11::typed::{HistoricalType, Native17Build};
use crate::retained_metadata::MetadataObserver;
use std::mem::{align_of, size_of};

mod key;
mod pins;
mod record;
mod retirement;

use key::{KeyReadAttempt, observe_key};
use pins::{PinsReadAttempt, observe_pins};
use record::{RecordReadAttempt, observe_record};
use retirement::{RetirementReadAttempt, observe_retirement};

/// Keeps exact source-census quantities beside reconstructed transfer owners.
#[derive(Default, Clone, Copy)]
struct BlobReadFacts {
    payload_bytes: usize,
    tree_entries: usize,
}

impl BlobReadFacts {
    fn tree_data(
        &mut self,
        count: usize,
        ledger: &Ledger<'_, '_, '_>,
    ) -> Result<(), ProviderError> {
        self.tree_entries = self
            .tree_entries
            .checked_add(count)
            .filter(|entries| *entries <= ledger.limits.maximum_tree_entries)
            .ok_or_else(invalid)?;
        Ok(())
    }
    fn payload_data<K, V>(&mut self, count: usize) -> Result<(), ProviderError> {
        self.payload_bytes = self
            .payload_bytes
            .checked_add(
                count
                    .checked_mul(
                        size_of::<K>()
                            .checked_add(size_of::<V>())
                            .ok_or_else(invalid)?,
                    )
                    .ok_or_else(invalid)?,
            )
            .ok_or_else(invalid)?;
        Ok(())
    }
}

/// Owns the complete ledger, completed records and every unfinished record child.
#[derive(Default)]
pub(crate) struct NativeBlobLedger17ReadAttempt {
    started: bool,
    completed: Option<HistoricalNativeBlobLedger>,
    facts: BlobReadFacts,
    reserved: Option<usize>,
    next_pin: Option<U64>,
    pins_created: Option<usize>,
    records: BTreeMap<TransferKey, HistoricalNativeBlobRecord>,
    children: Vec<RecordReadAttempt>,
    records_moved: bool,
}

impl HistoricalType for HistoricalNativeBlobLedger {
    fn read(
        input: &[u8],
        ledger: &mut Ledger<'_, '_, '_>,
        build: bool,
    ) -> Result<Option<Self>, ProviderError> {
        read_native17_blob_leaf_data(input, ledger, build).map(|result| result.0)
    }
}

impl Native17Build for HistoricalNativeBlobLedger {
    type Attempt = NativeBlobLedger17ReadAttempt;

    fn read_into_data(
        input: &[u8],
        ledger: &mut Ledger<'_, '_, '_>,
        attempt: &mut Self::Attempt,
    ) -> Result<(), ProviderError> {
        if attempt.started {
            return Err(ProviderError::Conflict(
                "native17 Blob ledger already attempted",
            ));
        }
        attempt.started = true;
        let mut fields = Fields::array(input)?;
        tag(&mut fields, "source-private.native-blob-ledger/11")?;
        attempt.reserved = ledger.read::<usize>(next(&mut fields)?, true)?;
        attempt.next_pin = ledger.read::<U64>(next(&mut fields)?, true)?;
        attempt.pins_created = ledger.read::<usize>(next(&mut fields)?, true)?;
        let count = record_rows(ledger, &mut attempt.facts)?;
        ledger.native17_target_vector_data::<RecordReadAttempt>(count)?;
        attempt
            .children
            .try_reserve_exact(count)
            .map_err(|_| exhausted())?;
        if attempt.children.capacity() != count {
            return Err(exhausted());
        }
        let mut records = Fields::array(next(&mut fields)?)?;
        let mut previous = None;
        while let Some(item) = records.next()? {
            if attempt.children.len() == count {
                return Err(invalid());
            }
            attempt.children.push(Default::default());
            let child = attempt.children.last_mut().ok_or_else(invalid)?;
            let order = child.read_into_data(item, ledger, &mut attempt.facts)?;
            if previous.is_some_and(|previous| previous >= order) {
                return Err(invalid());
            }
            previous = Some(order);
            // Both outputs remain in the retained row until all fallible row
            // checks complete. Target tree backing was funded at its source row.
            let value = child.completed_data().ok_or_else(invalid)?;
            let _ = value;
            let key = child.key.output_data().ok_or_else(invalid)?;
            let _ = key;
            attempt.records.insert(
                child.key.take_output_data().ok_or_else(invalid)?,
                child.take_output_data().ok_or_else(invalid)?,
            );
        }
        records.finish()?;
        fields.finish()?;
        if attempt.children.len() != count {
            return Err(invalid());
        }
        let reserved = attempt.reserved.ok_or_else(invalid)?;
        let next_pin = attempt.next_pin.ok_or_else(invalid)?;
        let pins_created = attempt.pins_created.ok_or_else(invalid)?;
        attempt.completed = Some(Self {
            reserved,
            next_pin,
            pins_created,
            records: std::mem::take(&mut attempt.records),
        });
        attempt.records_moved = true;
        Ok(())
    }

    fn preflight_data(input: &[u8], ledger: &mut Ledger<'_, '_, '_>) -> Result<(), ProviderError> {
        Self::preflight_native17_fields_data(input, ledger).map(|_| ())
    }
    fn output_data(attempt: &Self::Attempt) -> Option<&Self> {
        attempt.completed.as_ref()
    }
    fn take_output_data(attempt: &mut Self::Attempt) -> Option<Self> {
        attempt.completed.take()
    }
    fn observe_attempt_data(
        attempt: &Self::Attempt,
        observer: &mut MetadataObserver<'_>,
    ) -> Result<(), ProviderError> {
        if let Some(value) = &attempt.completed {
            Self::observe_output_data(value, observer)?;
        }
        if !attempt.records_moved {
            observe_records(&attempt.records, observer)?;
        }
        observer.vector::<RecordReadAttempt>(attempt.children.capacity())?;
        for child in &attempt.children {
            child.observe_attempt_data(observer)?;
        }
        Ok(())
    }
    fn observe_output_data(
        value: &Self,
        observer: &mut MetadataObserver<'_>,
    ) -> Result<(), ProviderError> {
        observe_records(&value.records, observer)
    }
}

impl HistoricalNativeBlobLedger {
    /// Checks source rows and target/build storage and returns map payload bytes.
    ///
    /// # Errors
    /// Refuses malformed keys/records, metadata, target demand or tree limits.
    pub(crate) fn preflight_native17_fields_data(
        input: &[u8],
        ledger: &mut Ledger<'_, '_, '_>,
    ) -> Result<usize, ProviderError> {
        let mut fields = Fields::array(input)?;
        tag(&mut fields, "source-private.native-blob-ledger/11")?;
        ledger.read::<usize>(next(&mut fields)?, false)?;
        ledger.read::<U64>(next(&mut fields)?, false)?;
        ledger.read::<usize>(next(&mut fields)?, false)?;
        let mut facts = BlobReadFacts::default();
        let count = record_rows(ledger, &mut facts)?;
        ledger.native17_target_vector_data::<RecordReadAttempt>(count)?;
        let mut records = Fields::array(next(&mut fields)?)?;
        let mut actual = 0usize;
        let mut previous = None;
        while let Some(item) = records.next()? {
            actual = actual
                .checked_add(1)
                .filter(|actual| *actual <= count)
                .ok_or_else(invalid)?;
            let order = RecordReadAttempt::preflight_data(item, ledger, &mut facts)?;
            if previous.is_some_and(|previous| previous >= order) {
                return Err(invalid());
            }
            previous = Some(order);
        }
        records.finish()?;
        fields.finish()?;
        if actual != count {
            return Err(invalid());
        }
        Ok(facts.payload_bytes)
    }
}

impl NativeBlobLedger17ReadAttempt {
    /// Returns the same-pass map payload quantity without estimating from JSON.
    pub(crate) fn historical_payload_bytes_data(&self) -> usize {
        self.facts.payload_bytes
    }
}

fn record_rows(
    ledger: &mut Ledger<'_, '_, '_>,
    facts: &mut BlobReadFacts,
) -> Result<usize, ProviderError> {
    let (_, alignment, _) = crate::blob::original_blob_alignment17_data();
    let count = ledger.row_aligned(
        MetadataRecordKind::Tree,
        crate::blob::original_blob_layouts().record_tree,
        alignment,
    )?;
    facts.tree_data(count, ledger)?;
    facts.payload_data::<TransferKey, HistoricalNativeBlobRecord>(count)?;
    ledger.native17_target_tree_data::<TransferKey, HistoricalNativeBlobRecord>(count)?;
    Ok(count)
}

fn observe_records(
    records: &BTreeMap<TransferKey, HistoricalNativeBlobRecord>,
    observer: &mut MetadataObserver<'_>,
) -> Result<(), ProviderError> {
    observer.tree::<TransferKey, HistoricalNativeBlobRecord>(records.len())?;
    for (key, record) in records {
        observe_key(key, observer)?;
        observe_record(record, observer)?;
    }
    Ok(())
}

fn owned<T: Native17Build>(
    input: &[u8],
    ledger: &mut Ledger<'_, '_, '_>,
    child: &mut T::Attempt,
    output: &mut Option<T>,
) -> Result<(), ProviderError> {
    T::read_into_data(input, ledger, child)?;
    *output = Some(T::take_output_data(child).ok_or_else(invalid)?);
    Ok(())
}

fn exhausted() -> ProviderError {
    ProviderError::ResourceExhausted("native17 retained Blob child storage")
}

#[cfg(test)]
mod tests;

// The contextual operation-pin grammar owns this exact native key leaf too.
pub(crate) use key::KeyReadAttempt as NativeBlobKey17ReadAttempt;
