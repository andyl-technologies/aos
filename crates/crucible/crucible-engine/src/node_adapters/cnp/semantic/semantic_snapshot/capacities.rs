//! Preserves semantic banks and original snapshot payload/activation capacities.
//!
//! The caller's enclosing allocation contains these inline headers. Origin is
//! checked without renewing custody or running a semantic operation. Shared Core
//! activation views retain independent rows without address-based discounts.

use super::*;
use crate::node_contract::{
    RuntimeError, restored_owner_history::OriginalOwnerCapacityMetadataData,
};
use std::mem::size_of;

impl CnpSemanticSnapshotReservation {
    pub(in crate::node_adapters::cnp::semantic) fn record_capacity_data(
        &self,
        census: &mut OriginalOwnerCapacityMetadataData<'_>,
    ) -> Result<(), RuntimeError> {
        let Self {
            storage_origin,
            bytes,
            maximum,
            started,
        } = self;
        storage_origin.check_precredit_data()?;
        census.observe_inline_data(maximum);
        census.observe_inline_data(started);
        census.observe(bytes)?;
        storage_origin.check_precredit_data()
    }
}

impl CnpOriginalSemanticSnapshot {
    pub(in crate::node_adapters::cnp::semantic) fn record_capacity_data(
        &self,
        census: &mut OriginalOwnerCapacityMetadataData<'_>,
    ) -> Result<(), RuntimeError> {
        let Self {
            storage_origin,
            payload,
            active,
        } = self;
        storage_origin.check_precredit_data()?;
        census.observe(payload)?;
        census.observe(active)?;
        storage_origin.check_precredit_data()
    }
}

pub(in crate::node_adapters::cnp::semantic) fn capacity_counter_scratch_data() -> usize {
    crate::node_contract::restored_owner_history::original_restored_owner_capacity_counter_scratch_data()
        + size_of::<&CnpSemanticSnapshotReservation>()
        + size_of::<&CnpOriginalSemanticSnapshot>()
        + size_of::<&super::super::retained_storage::StorageOrigin>()
        + size_of::<&Vec<u8>>()
        + size_of::<&usize>()
        + size_of::<&bool>()
        + size_of::<&InputPayload>()
        + size_of::<&WorldActivation>()
}

#[cfg(test)]
mod tests;
