//! Observes actual born-object rows and imported Index backing as capacity DATA.

use super::super::super::super::capacities::{
    fields_layout_data, record_value_data, value_counter_scratch_data,
};
use super::*;
use crate::node_contract::restored_owner_history::OriginalOwnerCapacityMetadataData;

impl BornRow {
    fn record_capacity_data(
        &self,
        census: &mut OriginalOwnerCapacityMetadataData<'_>,
    ) -> Result<(), RuntimeError> {
        let Self {
            started,
            completed,
            reference,
            dependencies,
        } = self;
        census.observe_inline_data(started)?;
        census.observe_inline_data(completed)?;

        census.observe(reference)?;
        census.observe(dependencies)
    }

    fn capacity_counter_scratch_data() -> usize {
        fields_layout_data::<Self, _>(|owner| {
            let Self {
                started,
                completed,
                reference,
                dependencies,
            } = owner;
            (started, completed, reference, dependencies)
        }) + size_of::<&Self>()
            + size_of::<std::slice::Iter<'_, ContentRef>>()
            + size_of::<&mut OriginalOwnerCapacityMetadataData<'_>>()
            + size_of::<Result<(), RuntimeError>>()
    }
}

impl CaptureBornOwner {
    /// Observes every fixed row and independent Index encoding without eligibility.
    ///
    /// # Errors
    /// Refuses exhausted rows, unsupported children or checked geometry/depth overflow.
    pub(in super::super) fn record_capacity_data(
        &self,
        census: &mut OriginalOwnerCapacityMetadataData<'_>,
    ) -> Result<(), RuntimeError> {
        let Self {
            index_started,
            index_completed,
            index_dom,
            index_reference,
            index_bytes,
            index_output,
            rows,
        } = self;
        census.observe_inline_data(index_started)?;
        census.observe_inline_data(index_completed)?;

        if let Some(value) = index_dom {
            record_value_data(value, census)?;
        }
        census.observe(index_reference)?;
        census.observe(index_bytes)?;
        index_output.record_capacity_data(census)?;
        for row in rows {
            row.record_capacity_data(census)?;
        }
        Ok(())
    }

    /// Names actual borrowed Index fields and initialized fixed-row iteration.
    pub(in super::super) fn capacity_counter_scratch_data() -> usize {
        fields_layout_data::<Self, _>(|owner| {
            let Self {
                index_started,
                index_completed,
                index_dom,
                index_reference,
                index_bytes,
                index_output,
                rows,
            } = owner;
            (
                index_started,
                index_completed,
                index_dom,
                index_reference,
                index_bytes,
                index_output,
                rows,
            )
        }) + size_of::<&Self>()
            + size_of::<std::slice::Iter<'_, BornRow>>()
            + size_of::<&BornRow>()
            + size_of::<&mut OriginalOwnerCapacityMetadataData<'_>>()
            + size_of::<Result<(), RuntimeError>>()
            + PayloadCopy::capacity_counter_scratch_data()
            + BornRow::capacity_counter_scratch_data()
            + value_counter_scratch_data()
    }
}
