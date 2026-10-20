//! Common append representation DATA from an actual held writer and typed widths.
//!
//! This prices ordinary Native preflight/frame/readback and common semantic
//! representations before the upper encoder constructs its real transaction.
//! It grants no writer, domain authority, funding or admission. External Source
//! challenge owners and each domain's own schema still need their own supplier.

use aos_sandbox_model::{AccountingError, ResourceDimension as D, ResourceVector};
use aos_sandbox_journal::geometry::{RecordShape, encoded_transaction_append_bytes};

use super::{Journal, JournalError, protected_journal_preopen_replay_extent_for_prefix_v1};

/// Preserves the actual native or checked-accounting append geometry failure.
#[derive(Debug, thiserror::Error)]
pub enum JournalAppendReceivingDemandErrorV1 {
    /// The same held writer, native widths or common representation is invalid.
    #[error(transparent)]
    Journal(#[from] JournalError),
    /// A checked resource aggregate cannot be represented.
    #[error(transparent)]
    Accounting(#[from] AccountingError),
}

impl Journal {
    /// Prices a real held prefix plus the upper encoder's actual record widths.
    ///
    /// The widths are nonauthorizing DATA. No synthetic records, transaction,
    /// frame or configured maximum transaction buffer is allocated. The current
    /// native file length, retained capacities and exact unchanged limits come
    /// from this same writer, including earlier overwritten/terminal history.
    ///
    /// The caller must separately admit its domain models and external challenge
    /// owners, then charge this bound through its own genuine payer before
    /// encoding or cloning. Native still applies every existing ordinary guard.
    ///
    /// # Errors
    ///
    /// Preserves unhealthy writer/metadata, native geometry/limit and arithmetic
    /// errors. A rejected forecast changes neither file nor materialized state.
    pub fn append_receiving_demand_v1(
        &self,
        records: impl ExactSizeIterator<Item = RecordShape>,
    ) -> Result<ResourceVector, JournalAppendReceivingDemandErrorV1> {
        self.append_sequence_receiving_demand_v1(std::iter::once(Ok(records)))
    }

    /// Prices a bounded sequence of real typed appends against this held writer.
    ///
    /// Each transaction preserves its own BEGIN/COMMIT framing. This borrows
    /// widths before any upper clone or encoding, and accounts for the complete
    /// resulting physical history rather than only its largest successor.
    /// Individual forecasts may retain their existing checked native error.
    /// This DATA neither authorizes nor executes any transition.
    ///
    /// # Errors
    ///
    /// Preserves forecast, held-writer, limit and checked-accounting failures.
    pub fn append_sequence_receiving_demand_v1<I, T>(
        &self,
        transactions: I,
    ) -> Result<ResourceVector, JournalAppendReceivingDemandErrorV1>
    where
        I: IntoIterator<Item = Result<T, JournalError>>,
        T: ExactSizeIterator<Item = RecordShape>,
    {
        self.append_sequence_receiving_engine_v6(transactions, None)
    }

    pub(crate) fn append_receiving_demand_retaining_metadata_v6(
        &self,
        records: impl ExactSizeIterator<Item = RecordShape>,
        metadata: &mut Option<std::io::Result<std::fs::Metadata>>,
    ) -> Result<ResourceVector, JournalAppendReceivingDemandErrorV1> {
        self.append_sequence_receiving_engine_v6(std::iter::once(Ok(records)), Some(metadata))
    }

    pub(crate) fn append_sequence_receiving_demand_retaining_metadata_v7<I, T>(
        &self,
        transactions: I,
        metadata: &mut Option<std::io::Result<std::fs::Metadata>>,
    ) -> Result<ResourceVector, JournalAppendReceivingDemandErrorV1>
    where
        I: IntoIterator<Item = Result<T, JournalError>>,
        T: ExactSizeIterator<Item = RecordShape>,
    {
        self.append_sequence_receiving_engine_v6(transactions, Some(metadata))
    }

    fn append_sequence_receiving_engine_v6<I, T>(
        &self,
        transactions: I,
        metadata: Option<&mut Option<std::io::Result<std::fs::Metadata>>>,
    ) -> Result<ResourceVector, JournalAppendReceivingDemandErrorV1>
    where
        I: IntoIterator<Item = Result<T, JournalError>>,
        T: ExactSizeIterator<Item = RecordShape>,
    {
        let mut append = 0_u64;
        for records in transactions {
            let bytes = encoded_transaction_append_bytes(records?)
                .map_err(JournalError::from)?;
            append = append.checked_add(bytes).ok_or(JournalError::JournalTooLarge)?;
        }
        let shape = self.first_global_allocation_shape_engine_v6(metadata)?;
        let future = shape
            .native_bytes
            .checked_add(append)
            .ok_or(JournalError::JournalTooLarge)?;
        let demand = append_prefix_representation_demand_v4(
            self.native.limits(), future, shape.retained_bytes, shape.cells,
            self.native.protected_view().map(|location| location.name()),
        )?;

        match &self.native {
            super::native_backing::JournalNativeBackingV1::Ordinary(ordinary) => {
                #[cfg(target_os = "linux")]
                if let Some(owner) = ordinary.captured_append.as_ref() {
                    // The captured interval replaces its embedded stage lanes
                    // with this same recipe; it needs no second stage invoice.
                    return Ok(demand.checked_add(owner.append_demand_v1(append)?)?);
                }
                #[cfg(not(target_os = "linux"))]
                let _ = ordinary;

                let bytes = aos_sandbox_broker::canonical_journal::CanonicalOrdinaryAppendStageV1::
                    receiving_construction_bytes_v1()
                    .and_then(|bytes| u64::try_from(bytes).ok())
                    .ok_or(JournalError::LimitExceeded("ordinary append representation"))?;
                Ok(demand.checked_add(ResourceVector::ZERO.with(D::MemoryBytes, bytes))?)
            }
            #[cfg(target_os = "linux")]
            _ => Ok(demand),
        }
    }
}

// Shares the actual append representation arithmetic with fixed-source maxima.
// The latter are passive limits, not captured metadata or authority.
pub(super) fn append_prefix_representation_demand_v4(
    limits: super::JournalLimits,
    future: u64,
    retained_bytes: usize,
    retained_cells: usize,
    name: Option<&str>,
) -> Result<ResourceVector, JournalAppendReceivingDemandErrorV1> {
    let extent = protected_journal_preopen_replay_extent_for_prefix_v1(
        limits,
        future,
    )?;
    let native = extent.dominant_native_receiving_demand_v1()?;
    let semantic = extent.dominant_semantic_receiving_demand_v1()?;

    let invalid = || AccountingError::ArithmeticOverflow {
        dimension: D::MemoryBytes,
    };
    let retained = u64::try_from(retained_bytes)
        .map_err(|_| invalid())?
        .checked_mul(16)
        .ok_or_else(invalid)?;
    let cells = u64::try_from(retained_cells)
        .map_err(|_| invalid())?
        .checked_mul(16)
        .ok_or_else(invalid)?;
    let retained = ResourceVector::ZERO
        .with(D::MemoryBytes, retained)
        .with(D::MetadataEntries, cells)
        .with(D::StorageBytes, future);

    // A selected retained append keeps one failed name pass, or actually
    // disposes its positive temporary pass before the next serial append.
    // The actual enclosing domain separately pays its independent final
    // name post; it cannot reuse this peak while a failed pass is held.
    let names = match name {
        Some(name) => super::ProtectedJournalCurrentnessOriginalsV1::named_demand_v1(name)?,
        None => ResourceVector::ZERO,
    };
    Ok(native.checked_add(semantic)?.checked_add(retained)?.checked_add(names)?)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{JournalLimits, JournalRecord, JournalTransaction, RecordNamespace};

    struct TestDirectory(std::path::PathBuf);

    impl Drop for TestDirectory {
        fn drop(&mut self) {
            let _ = std::fs::remove_dir_all(&self.0);
        }
    }

    #[test]
    fn an_overwritten_row_does_not_erase_actual_append_history_from_the_bound() {
        use aos_sandbox_protocol::domain_ledger::{
            operation::{OperationRecord, decode_operation, encode_operation_record},
            public_operation::OperationState,
        };

        static NEXT: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(0);
        let unique = NEXT.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
        let directory = TestDirectory(std::env::temp_dir().join(format!(
            "aos-append-receiving-{}-{unique}",
            std::process::id(),
        )));
        std::fs::create_dir(&directory.0).unwrap();
        let path = directory.0.join("journal");
        let (mut journal, _) = Journal::open(&path, JournalLimits::default()).unwrap();
        // The common kind3 guard must decode an existing Operation before a
        // replacement. An ordinary zero-effect row is canonical only after
        // Succeeded; this fixture carries no public owner or runtime authority.
        let record = OperationRecord::new(OperationState::Succeeded, 0, false, None, None);
        let value = encode_operation_record(record);
        assert_eq!(decode_operation(&value).unwrap(), record);
        let widths = || {
            [RecordShape {
                key_bytes: 16,
                value_bytes: Some(value.len()),
            }]
            .into_iter()
        };
        let mut previous_length = None;

        for id in [1, 2] {
            let records = vec![JournalRecord::put(
                RecordNamespace::Operation,
                vec![3; 16],
                value.clone(),
            )];
            let transaction = JournalTransaction::new([id; 16], records).unwrap();
            journal.commit(&transaction).unwrap();
            let actual = std::fs::metadata(&path).unwrap().len();
            if let Some(previous) = previous_length {
                assert!(actual > previous);
            }
            previous_length = Some(actual);
            let demand = journal.append_receiving_demand_v1(widths()).unwrap();
            let forecast = encoded_transaction_append_bytes(widths()).unwrap();

            assert_eq!(journal.all_records().count(), 1);
            assert_eq!(demand.get(D::StorageBytes), actual + forecast);
        }
    }

    #[test]
    fn a_sequence_preserves_each_real_transaction_framing() {
        static NEXT: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(0);
        let unique = NEXT.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
        let directory = TestDirectory(std::env::temp_dir().join(format!(
            "aos-append-sequence-{}-{unique}", std::process::id(),
        )));
        std::fs::create_dir(&directory.0).unwrap();
        let (journal, _) = Journal::open(directory.0.join("journal"), JournalLimits::default()).unwrap();
        let shapes = || [RecordShape { key_bytes: 16, value_bytes: Some(98) }].into_iter();
        let actual = std::fs::metadata(directory.0.join("journal")).unwrap().len();

        let demand = journal.append_sequence_receiving_demand_v1([
            Ok(shapes()), Ok(shapes()),
        ]).unwrap();
        let one = encoded_transaction_append_bytes(shapes()).unwrap();
        let flattened = encoded_transaction_append_bytes([
            RecordShape { key_bytes: 16, value_bytes: Some(98) },
            RecordShape { key_bytes: 16, value_bytes: Some(98) },
        ].into_iter()).unwrap();

        assert_eq!(demand.get(D::StorageBytes), actual + 2 * one);
        assert!(2 * one > flattened);
        assert_eq!(std::fs::metadata(directory.0.join("journal")).unwrap().len(), actual);
    }

}
