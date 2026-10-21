//! Quotes the actual retained Cache storage before its native metadata sample.
//!
//! The census borrows the existing maps and Vec capacities. It constructs no
//! replay or writer and preserves the original capacity/count-before-metadata
//! order; an owning destination retains any selected metadata failure.

use aos_sandbox_broker::canonical_journal::CanonicalJournalMechanicalErrorV1 as Mechanical;

use super::{Journal, JournalError};

/// Describes the same retained allocations and actual native extent as DATA.
pub(crate) struct JournalShape {
    pub(crate) retained_bytes: usize,
    pub(crate) cells: usize,
    pub(crate) native_bytes: u64,
    pub(crate) maximum_transaction_bytes: usize,
    pub(crate) maximum_record_bytes: usize,
}

impl Journal {
    /// Quotes the existing private owner's allocations and actual file length.
    ///
    /// # Errors
    /// Preserves poisoned-owner, arithmetic and native metadata refusals.
    pub(crate) fn first_global_allocation_shape_v1(&self) -> Result<JournalShape, JournalError> {
        self.first_global_allocation_shape_engine_v6(None)
    }

    /// Quotes the same shape while retaining the actual selected metadata.
    ///
    /// # Errors
    /// Refuses a reused metadata destination and preserves the native or
    /// arithmetic cause. Successful DATA cannot fund or enter native work.
    pub(crate) fn first_global_allocation_shape_engine_v6(
        &self,
        metadata: Option<&mut Option<std::io::Result<std::fs::Metadata>>>,
    ) -> Result<JournalShape, JournalError> {
        self.ensure_healthy()?;
        let actual = self.read_view();
        let mut retained_bytes = 0_usize;
        for ((_, key), value) in actual.state() {
            retained_bytes = retained_bytes.checked_add(key.capacity())
                .and_then(|bytes| bytes.checked_add(value.capacity()))
                .ok_or(Mechanical::JournalTooLarge)?;
        }
        for key in actual.idempotency_index().keys() {
            retained_bytes = retained_bytes.checked_add(key.capacity())
                .ok_or(Mechanical::JournalTooLarge)?;
        }
        let cells = actual.state().len().checked_add(actual.idempotency_index().len())
            .and_then(|count| count.checked_add(actual.transaction_ids().len()))
            .and_then(|count| count.checked_add(actual.committed_namespaces().len()))
            .ok_or(Mechanical::JournalTooLarge)?;

        // These five names keep ordinary native allocation/disposition. The
        // old actual captured-append selector was None for every Cache writer.
        let native_bytes = match metadata {
            Some(destination) => {
                if destination.is_some() {
                    return Err(JournalError::boundary());
                }
                *destination = Some(actual.metadata());
                match destination.as_ref() {
                    Some(Ok(metadata)) => metadata.len(),
                    _ => return Err(JournalError::boundary()),
                }
            }
            None => actual.metadata()?.len(),
        };
        Ok(JournalShape {
            retained_bytes,
            cells,
            native_bytes,
            maximum_transaction_bytes: self.limits().maximum_transaction_bytes,
            maximum_record_bytes: self.limits().maximum_record_bytes,
        })
    }
}
