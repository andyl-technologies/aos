//! Observes actual first-sealed lineage owners without rebuilding their claims.

use super::*;
use crate::node_adapters::cnp::semantic::packet_complete_source::storage_error::StorageError;
use std::mem::size_of;

#[path = "retained_lineage/metadata.rs"]
mod metadata;

impl PacketConnectedSemanticSource {
    pub(in crate::node_adapters::cnp::semantic) fn complete_retained_lineage_storage(
        &self,
        maximum: usize,
    ) -> Result<usize, OperationFailure> {
        self.complete_retained_lineage_storage_with_error::<OperationFailure>(maximum)
    }

    pub(in crate::node_adapters::cnp::semantic) fn complete_retained_lineage_storage_with_error<
        E: StorageError,
    >(
        &self,
        maximum: usize,
    ) -> Result<usize, E> {
        self.local_owner_with_error::<E>()?;
        if !self.world.is_complete() {
            return Err(E::refused(
                "ordinary connected source has no complete lineage row",
            ));
        }
        let lineages = self
            .input_lineage
            .try_borrow()
            .map_err(|_| E::refused("retained complete lineage bank already borrowed"))?;
        if lineages.len() > self.installation.maximum_operations {
            return Err(E::refused(
                "retained complete lineage population exceeds original bound",
            ));
        }
        let mut bytes = lineages
            .capacity()
            .checked_mul(size_of::<OriginalInputLineage>())
            .filter(|bytes| *bytes <= maximum)
            .ok_or_else(|| E::refused("retained complete lineage Vec capacity exhausted"))?;
        for (index, lineage) in lineages.iter().enumerate() {
            // Both original backings must agree. The Core private observer
            // independently charges data and original batch allocations; sharing
            // only a batch across different data views receives no discount.
            let repeated = lineages[..index].iter().any(|previous| {
                previous.retained_allocation_identity() == lineage.retained_allocation_identity()
                    && previous.original_batch_allocation_identity()
                        == lineage.original_batch_allocation_identity()
            });
            if !repeated {
                let next = lineage
                    .retained_requested_storage(maximum)
                    .map_err(E::runtime)?;
                bytes = bytes
                    .checked_add(next)
                    .filter(|bytes| *bytes <= maximum)
                    .ok_or_else(|| E::refused("retained complete lineage backing exhausted"))?;
            }
        }
        self.local_owner_with_error::<E>()?;
        Ok(bytes)
    }
}

impl PacketConnectedSemanticSource {
    /// Refuses local Input lineage unsupported by the settled Source17 family.
    ///
    /// Imported input ancestry belongs to the separately retained Node family.
    /// This check neither erases nor reconstructs the actual local lineage bank.
    ///
    /// # Errors
    /// Refuses foreign origin, a busy actual lineage bank or local Input use.
    pub(in crate::node_adapters::cnp::semantic) fn require_unused_restored_source17_input_data(
        &self,
    ) -> Result<(), crate::node_contract::RuntimeError> {
        use crate::node_contract::RuntimeError;
        self.local_owner_with_error::<RuntimeError>()?;
        let lineages = self
            .input_lineage
            .try_borrow()
            .map_err(|_| RuntimeError::OwnerBusy)?;
        if !lineages.is_empty() {
            return Err(RuntimeError::UnsupportedFacet);
        }
        Ok(())
    }
}
