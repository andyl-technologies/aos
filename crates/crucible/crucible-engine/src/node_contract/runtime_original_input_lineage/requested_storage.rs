//! Observes the actual original lineage allocation without exposing its issuer.

use std::{
    mem::{align_of, size_of},
    rc::Rc,
};

use super::{
    OriginalInputLineage, OriginalInputLineageData, OriginalPublicationClaim, RuntimeError,
};
use crate::{node_contract::NodeRuntime, node_scheduling::RuntimeInputBatch};

/// Borrows separately owned data and batch roots for consistent same-Rc accounting.
pub(crate) struct OriginalLineageStorageParts<'a> {
    pub(crate) identity: *const (),
    pub(crate) payload_bytes: usize,
    pub(crate) alignment: usize,
    pub(crate) original: &'a Rc<RuntimeInputBatch>,
}

impl OriginalInputLineage {
    /// Observes the lineage data allocation separately from its original batch.
    ///
    /// The payload excludes the shared header and all batch backing. No token,
    /// native authority or reconstructed original is produced.
    ///
    /// # Errors
    /// Refuses overflow or a requested payload beyond the supplied maximum.
    pub(crate) fn retained_storage_parts(
        &self,
        maximum: usize,
    ) -> Result<OriginalLineageStorageParts<'_>, RuntimeError> {
        let mut bytes = size_of::<OriginalInputLineageData>();
        for next in [
            self.data
                .publications
                .capacity()
                .checked_mul(size_of::<OriginalPublicationClaim>())
                .ok_or(RuntimeError::ResourceLimit)?,
            NodeRuntime::capture_original_scope_storage(&self.data.source_scope)?,
        ] {
            bytes = add(bytes, next, maximum)?;
        }
        for publication in &self.data.publications {
            bytes = add(
                bytes,
                NodeRuntime::capture_original_claim_storage(publication)?,
                maximum,
            )?;
        }
        if bytes > maximum {
            return Err(RuntimeError::ResourceLimit);
        }
        Ok(OriginalLineageStorageParts {
            identity: Rc::as_ptr(&self.data).cast(),
            payload_bytes: bytes,
            alignment: align_of::<OriginalInputLineageData>(),
            original: &self.data.original,
        })
    }

    /// Counts the same retained original data and independent batch heap banks.
    ///
    /// Includes Rc backing headers/inline values, actual publication slot spare
    /// capacity, full body banks, rows, dependency references and first scope,
    /// plus the batch's independent activation-record clone and input buffers.
    /// The batch's activation authority/validated-node/publication Rc backing
    /// remains owned by Core and is excluded. The caller counts its inline
    /// OriginalInputLineage slot and those shared Core owners separately.
    ///
    /// This allocates nothing and creates no lineage, source, capture or native
    /// permission. Equal encoded bodies never establish allocation identity.
    pub(crate) fn retained_requested_storage(&self, maximum: usize) -> Result<usize, RuntimeError> {
        let mut bytes =
            NodeRuntime::capture_shared_allocation_storage::<OriginalInputLineageData>();
        for next in [
            NodeRuntime::capture_shared_allocation_storage::<RuntimeInputBatch>(),
            self.data
                .publications
                .capacity()
                .checked_mul(size_of::<OriginalPublicationClaim>())
                .ok_or(RuntimeError::ResourceLimit)?,
            NodeRuntime::capture_original_scope_storage(&self.data.source_scope)?,
            NodeRuntime::capture_lineage_batch_storage(&self.data.original)?,
        ] {
            bytes = add(bytes, next, maximum)?;
        }
        for publication in &self.data.publications {
            bytes = add(
                bytes,
                NodeRuntime::capture_original_claim_storage(publication)?,
                maximum,
            )?;
        }
        if bytes > maximum {
            return Err(RuntimeError::ResourceLimit);
        }
        Ok(bytes)
    }

    /// Returns only the actual immutable data allocation address for accounting.
    ///
    /// This borrowed identity may deduplicate simultaneous same-Rc retention;
    /// it is never dereferenced, serialized or used as native/source authority.
    pub(crate) fn retained_allocation_identity(&self) -> *const () {
        Rc::as_ptr(&self.data).cast()
    }

    /// Returns the independently retained original batch allocation identity.
    pub(crate) fn original_batch_allocation_identity(&self) -> *const () {
        Rc::as_ptr(&self.data.original).cast()
    }
}

fn add(total: usize, next: usize, maximum: usize) -> Result<usize, RuntimeError> {
    total
        .checked_add(next)
        .filter(|bytes| *bytes <= maximum)
        .ok_or(RuntimeError::ResourceLimit)
}
