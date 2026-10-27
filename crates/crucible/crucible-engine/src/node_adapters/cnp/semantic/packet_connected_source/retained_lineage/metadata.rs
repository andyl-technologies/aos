//! Joins actual static and lineage views for the complete Source capacity census.

use super::*;
use crate::node_contract::{
    RuntimeError, restored_owner_history::OriginalOwnerCapacityMetadataData,
};
use std::cell::{BorrowError, Ref};

impl PacketConnectedSemanticSource {
    /// Includes static and every retained lineage view without alias discounts.
    ///
    /// # Errors
    /// Refuses foreign creation, an ordinary world, busy holders, invalid layout
    /// or exhausted selected rows. Failed static rows remain historical DATA.
    pub(in crate::node_adapters::cnp::semantic) fn record_complete_static_lineage_capacity_data(
        &self,
        census: &mut OriginalOwnerCapacityMetadataData<'_>,
    ) -> Result<(), RuntimeError> {
        self.local_owner_with_error::<RuntimeError>()?;
        if !self.world.is_complete() {
            return Err(RuntimeError::UnsupportedFacet);
        }
        let slot = self
            .complete_input_static
            .try_borrow()
            .map_err(|_| RuntimeError::OwnerBusy)?;
        if let Some(rows) = slot.as_ref() {
            rows.record_retained_capacity_data(census)?;
        }
        drop(slot);
        let lineages = self
            .input_lineage
            .try_borrow()
            .map_err(|_| RuntimeError::OwnerBusy)?;
        census.observe(&*lineages)?;
        self.local_owner_with_error::<RuntimeError>()
    }

    /// Names concrete static/lineage loans and their defining Core controls.
    pub(in crate::node_adapters::cnp::semantic) fn complete_static_lineage_capacity_counter_scratch_data()
    -> usize {
        use super::super::complete_static::CompleteInputStaticRows;
        CompleteInputStaticRows::retained_capacity_counter_scratch_data()
            + OriginalInputLineage::retained_capacity_counter_scratch_data()
            + size_of::<&Self>()
            + size_of::<Ref<'static, Option<CompleteInputStaticRows>>>()
            + size_of::<Result<Ref<'static, Option<CompleteInputStaticRows>>, BorrowError>>()
            + size_of::<Ref<'static, Vec<OriginalInputLineage>>>()
            + size_of::<Result<Ref<'static, Vec<OriginalInputLineage>>, BorrowError>>()
            + size_of::<&Vec<OriginalInputLineage>>()
            + size_of::<std::slice::Iter<'static, OriginalInputLineage>>()
            + size_of::<Result<(), RuntimeError>>()
    }
}
