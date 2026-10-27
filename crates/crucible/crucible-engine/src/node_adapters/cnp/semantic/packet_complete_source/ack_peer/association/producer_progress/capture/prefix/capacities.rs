//! Observes actual Capture prefix backing without verifying its payload or phase.

use super::super::capacities::{fields_layout_data, record_value_data, value_counter_scratch_data};
use super::*;
use crate::node_contract::restored_owner_history::OriginalOwnerCapacityMetadataData;
use std::mem::size_of;

impl CapturePrefixOwners {
    /// Observes independent checkpoint and prefix encodings without completion.
    ///
    /// # Errors
    /// Refuses exhausted rows or checked allocation geometry/depth overflow.
    pub(in super::super) fn record_capacity_data(
        &self,
        census: &mut OriginalOwnerCapacityMetadataData<'_>,
    ) -> Result<(), RuntimeError> {
        let Self {
            attempted,
            checkpoint_value,
            checkpoint_bytes,
            value,
            bytes,
            reference,
        } = self;
        census.observe_inline_data(attempted);

        if let Some(value) = checkpoint_value {
            record_value_data(value, census)?;
        }
        census.observe(checkpoint_bytes)?;
        if let Some(value) = value {
            record_value_data(value, census)?;
        }
        census.observe(bytes)?;
        census.observe(reference)
    }

    /// Names the borrowed prefix fields and defining JSON counter.
    pub(in super::super) fn capacity_counter_scratch_data() -> usize {
        fields_layout_data::<Self, _>(|owner| {
            let Self {
                attempted,
                checkpoint_value,
                checkpoint_bytes,
                value,
                bytes,
                reference,
            } = owner;
            (
                attempted,
                checkpoint_value,
                checkpoint_bytes,
                value,
                bytes,
                reference,
            )
        }) + size_of::<&Self>()
            + size_of::<&ContentRef>()
            + size_of::<&mut OriginalOwnerCapacityMetadataData<'_>>()
            + size_of::<Result<(), RuntimeError>>()
            + value_counter_scratch_data()
    }
}
