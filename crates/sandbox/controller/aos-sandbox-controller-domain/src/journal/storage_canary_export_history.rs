//! Fixed canary-export history DATA borrowed from the original Storage writer.
//!
//! The native issuance child owns the sole capture, COMMIT observer, positioned
//! reader and two-prefix replay engine. This child selects a separate fixed
//! recipe and names its lending DATA; it has no append or settlement authority.
//!
//! ```text
//! storage-canary-export.journal: four sole PUT(namespace6, key32, value1040)
//! ```
//!
//! Storage must validate every phase and immutable binding. A partial history
//! is not settlement, and complete history does not prove worker quiescence,
//! unused bootstrap lineage, funding or permission to acknowledge generation0.

use std::collections::BTreeMap;

use super::storage_native_issuance_history::{
    StorageNativeIssuanceEdgeDataV1, StorageNativeIssuanceHistoryCursorV1,
    StorageNativeIssuanceHistoryDataV1, StorageNativeIssuanceHistoryErrorV1,
};
use super::{Journal, JournalError, JournalLimits, JournalTransaction, RecordNamespace};

/// Retains the unchanged first history cause and any failed final bookend.
#[derive(Debug, thiserror::Error)]
#[error(transparent)]
pub struct StorageCanaryExportHistoryErrorV1(StorageNativeIssuanceHistoryErrorV1);

impl StorageCanaryExportHistoryErrorV1 {
    /// Borrows the original parser, allocation or physical-check failure.
    #[must_use]
    pub fn first_cause(&self) -> &JournalError {
        self.0.first_cause()
    }

    /// Borrows a failed final bookend without replacing the original cause.
    #[must_use]
    pub fn final_bookend_cause(&self) -> Option<&JournalError> {
        self.0.final_bookend_cause()
    }
}

impl From<StorageNativeIssuanceHistoryErrorV1> for StorageCanaryExportHistoryErrorV1 {
    fn from(error: StorageNativeIssuanceHistoryErrorV1) -> Self {
        Self(error)
    }
}

/// Borrows the original fixed canary writer and owns bounded historical DATA.
///
/// No constructor accepts a journal name, descriptor, key, limit or scalar
/// witness. The writer remains immutably borrowed throughout the one-shot loan.
pub struct StorageCanaryExportHistoryDataV1<'journal> {
    inner: StorageNativeIssuanceHistoryDataV1<'journal>,
}

impl<'journal> StorageCanaryExportHistoryDataV1<'journal> {
    /// Returns the fixed eight opened ceilings, not a reservation.
    #[must_use]
    pub fn opened_limits(&self) -> JournalLimits {
        self.inner.opened_limits()
    }

    /// Returns the complete captured physical extent including native frames.
    #[must_use]
    pub const fn physical_bytes(&self) -> u64 {
        self.inner.physical_bytes()
    }

    /// Returns every committed phase transaction, including superseded values.
    #[must_use]
    pub fn committed_transactions(&self) -> usize {
        self.inner.committed_transactions()
    }

    /// Returns every committed record, not the final materialized row count.
    #[must_use]
    pub const fn committed_records(&self) -> usize {
        self.inner.committed_records()
    }

    /// Returns the captured NEXT boundary without granting an append.
    #[must_use]
    pub const fn next_sequence(&self) -> u64 {
        self.inner.next_sequence()
    }

    /// Rechecks the same writer's original physical and named cut.
    ///
    /// # Errors
    ///
    /// Rejects drift, poison or a lending/ended loan. Error or unwind ends it.
    pub fn recheck(&mut self) -> Result<(), StorageCanaryExportHistoryErrorV1> {
        self.inner.recheck().map_err(Into::into)
    }

    /// Lends one one-shot cursor through the shared canonical prefix engine.
    ///
    /// # Errors
    ///
    /// Rejects a used loan or original-cut drift. Error, unwind and cursor Drop
    /// fence the loan; ordinary bounded materializer allocation is unchanged.
    pub fn replay(
        &mut self,
    ) -> Result<StorageCanaryExportHistoryCursorV1<'_, 'journal>, StorageCanaryExportHistoryErrorV1> {
        Ok(StorageCanaryExportHistoryCursorV1 {
            inner: self.inner.replay()?,
        })
    }
}

/// Lends exact canary transactions and at most two complete prefix maps.
pub struct StorageCanaryExportHistoryCursorV1<'history, 'journal> {
    inner: StorageNativeIssuanceHistoryCursorV1<'history, 'journal>,
}

impl StorageCanaryExportHistoryCursorV1<'_, '_> {
    /// Advances once and borrows the original transaction's complete edge.
    ///
    /// # Errors
    ///
    /// Rejects exhausted/ended use, drift or native discontinuity. None denotes
    /// complete consumption only; the caller must still finish the cursor.
    pub fn next_edge(
        &mut self,
    ) -> Result<Option<StorageCanaryExportEdgeDataV1<'_>>, StorageCanaryExportHistoryErrorV1> {
        Ok(self.inner.next_edge()?.map(|inner| StorageCanaryExportEdgeDataV1 { inner }))
    }

    /// Ends the loan after exact final-map/count/NEXT/extent equality.
    ///
    /// # Errors
    ///
    /// Rejects incomplete consumption, mismatch, drift or an ended cursor.
    /// Finishing empty or partial historical DATA grants no settlement.
    pub fn finish(&mut self) -> Result<(), StorageCanaryExportHistoryErrorV1> {
        self.inner.finish().map_err(Into::into)
    }
}

/// Borrows one original canary transaction and its complete before/after maps.
pub struct StorageCanaryExportEdgeDataV1<'edge> {
    inner: StorageNativeIssuanceEdgeDataV1<'edge>,
}

impl StorageCanaryExportEdgeDataV1<'_> {
    /// Borrows the complete prefix before the actual original transaction.
    #[must_use]
    pub fn before(&self) -> &BTreeMap<(RecordNamespace, Vec<u8>), Vec<u8>> {
        self.inner.before()
    }

    /// Borrows the complete prefix after the actual original transaction.
    #[must_use]
    pub fn after(&self) -> &BTreeMap<(RecordNamespace, Vec<u8>), Vec<u8>> {
        self.inner.after()
    }

    /// Borrows the actual UUID and ordered original record bytes.
    #[must_use]
    pub fn transaction(&self) -> &JournalTransaction {
        self.inner.transaction()
    }

    /// Returns the original BEGIN sequence.
    #[must_use]
    pub const fn begin_sequence(&self) -> u64 {
        self.inner.begin_sequence()
    }

    /// Returns the original validated COMMIT sequence.
    #[must_use]
    pub const fn commit_sequence(&self) -> u64 {
        self.inner.commit_sequence()
    }

    /// Returns the original NEXT immediately after that COMMIT.
    #[must_use]
    pub const fn next_sequence(&self) -> u64 {
        self.inner.next_sequence()
    }

    /// Returns the original transaction's physical starting offset.
    #[must_use]
    pub const fn begin_offset(&self) -> u64 {
        self.inner.begin_offset()
    }

    /// Returns the physical offset immediately following the original COMMIT.
    #[must_use]
    pub const fn end_offset(&self) -> u64 {
        self.inner.end_offset()
    }
}

impl Journal {
    /// Captures complete bootstrap-lineage DATA from the fixed primary writer.
    ///
    /// Unlike the separate issuance and canary recipes, this closed recipe
    /// retains every namespace, ordered record and DELETE under the original
    /// opened limits. Absence is historical DATA, not unused-bootstrap proof.
    ///
    /// # Errors
    ///
    /// Rejects the wrong protected name, poison, compaction, incomplete tails,
    /// retention overflow or physical/replay drift. The same error owner keeps
    /// the first cause and subsequent final-bookend failure.
    pub fn capture_storage_canary_bootstrap_primary_history_v1(
        &self,
    ) -> Result<StorageCanaryBootstrapPrimaryHistoryDataV1<'_>, StorageCanaryExportHistoryErrorV1> {
        Ok(StorageCanaryBootstrapPrimaryHistoryDataV1 {
            inner: self.capture_storage_primary_history_inner()?,
        })
    }

    /// Captures full canary-export history DATA from this same fixed writer.
    ///
    /// The protected name, key32, value1040 and exact eight-limit recipe are
    /// closed internally. Partial phases remain DATA, never settlement. The
    /// genuine Storage owner must separately validate phase semantics, all
    /// original bindings and actual quiescence before releasing its gate.
    ///
    /// # Errors
    ///
    /// Rejects the wrong protected location, geometry, record shape, poison,
    /// partial tails, replay mismatch or physical/name drift. The same native
    /// error owner preserves both the first cause and final-bookend failure.
    pub fn capture_storage_canary_export_history_v1(
        &self,
    ) -> Result<StorageCanaryExportHistoryDataV1<'_>, StorageCanaryExportHistoryErrorV1> {
        Ok(StorageCanaryExportHistoryDataV1 {
            inner: self.capture_storage_canary_history_inner()?,
        })
    }
}

/// Borrows complete primary lineage without creating or authenticating a floor.
///
/// Construction is fixed to the protected Storage primary name. The same
/// cursor/parser owns all observations; no caller can select its shape.
pub struct StorageCanaryBootstrapPrimaryHistoryDataV1<'journal> {
    inner: StorageNativeIssuanceHistoryDataV1<'journal>,
}

impl<'journal> StorageCanaryBootstrapPrimaryHistoryDataV1<'journal> {
    /// Returns all eight actual opened ceilings as DATA, not funding.
    #[must_use]
    pub fn opened_limits(&self) -> JournalLimits {
        self.inner.opened_limits()
    }

    /// Returns the complete captured physical extent.
    #[must_use]
    pub const fn physical_bytes(&self) -> u64 {
        self.inner.physical_bytes()
    }

    /// Returns the captured NEXT boundary without granting an append.
    #[must_use]
    pub const fn next_sequence(&self) -> u64 {
        self.inner.next_sequence()
    }

    /// Lends the sole canonical cursor over all original primary transactions.
    ///
    /// # Errors
    ///
    /// Rejects an ended loan or changed cut. All failure and cursor Drop paths
    /// fence the loan; the genuine owner must remain resident and prearmed.
    pub fn replay(
        &mut self,
    ) -> Result<StorageNativeIssuanceHistoryCursorV1<'_, 'journal>, StorageCanaryExportHistoryErrorV1> {
        self.inner.replay().map_err(Into::into)
    }
}
