//! Observes retained Capture materialization copies before and after transfer.

use super::super::super::capacities::{
    fields_layout_data, native_key_counter_scratch_data, record_native_key_data,
};
use super::*;
use crate::node_contract::restored_owner_history::OriginalOwnerCapacityMetadataData;

impl PayloadCopy {
    /// Observes actual reference and bytes even if copying never completed.
    ///
    /// # Errors
    /// Refuses exhausted rows or checked geometry/depth overflow.
    pub(in super::super::super) fn record_capacity_data(
        &self,
        census: &mut OriginalOwnerCapacityMetadataData<'_>,
    ) -> Result<(), RuntimeError> {
        let Self {
            started,
            completed,
            reference,
            bytes,
        } = self;
        census.observe_inline_data(started);
        census.observe_inline_data(completed);

        census.observe(reference)?;
        census.observe(bytes)
    }

    /// Names the borrowed copy fields and observer controls.
    pub(in super::super::super) fn capacity_counter_scratch_data() -> usize {
        fields_layout_data::<Self, _>(|owner| {
            let Self {
                started,
                completed,
                reference,
                bytes,
            } = owner;
            (started, completed, reference, bytes)
        }) + size_of::<&Self>()
            + size_of::<&mut OriginalOwnerCapacityMetadataData<'_>>()
            + size_of::<Result<(), RuntimeError>>()
    }
}

impl CaptureMaterializationOwner {
    /// Observes all actual copies, evidence and born-object rows as DATA.
    ///
    /// # Errors
    /// Refuses exhausted rows, unsupported children or checked geometry/depth overflow.
    pub(in super::super::super) fn record_capacity_data(
        &self,
        census: &mut OriginalOwnerCapacityMetadataData<'_>,
    ) -> Result<(), RuntimeError> {
        let Self {
            started,
            failed,
            transferred,
            owner,
            participants,
            key,
            slots,
            evidence,
            born,
        } = self;
        census.observe_inline_data(started);
        census.observe_inline_data(failed);
        census.observe_inline_data(transferred);

        census.observe(owner)?;
        census.observe(participants)?;
        if let Some(key) = key {
            record_native_key_data(key, census)?;
        }
        for slot in slots {
            slot.record_capacity_data(census)?;
        }
        census.observe(evidence)?;
        born.record_capacity_data(census)
    }

    /// Names actual borrowed materialization fields and fixed-slot iterators.
    pub(in super::super::super) fn capacity_counter_scratch_data() -> usize {
        fields_layout_data::<Self, _>(|owner| {
            let Self {
                started,
                failed,
                transferred,
                owner,
                participants,
                key,
                slots,
                evidence,
                born,
            } = owner;
            (
                started,
                failed,
                transferred,
                owner,
                participants,
                key,
                slots,
                evidence,
                born,
            )
        }) + size_of::<&Self>()
            + size_of::<&NativeStateKey>()
            + size_of::<std::slice::Iter<'_, PayloadCopy>>()
            + size_of::<&PayloadCopy>()
            + size_of::<std::slice::Iter<'_, Id>>()
            + size_of::<std::slice::Iter<'_, crate::node_scheduling::InputPayload>>()
            + size_of::<&mut OriginalOwnerCapacityMetadataData<'_>>()
            + size_of::<Result<(), RuntimeError>>()
            + native_key_counter_scratch_data()
            + PayloadCopy::capacity_counter_scratch_data()
            + CaptureBornOwner::capacity_counter_scratch_data()
    }
}

#[cfg(test)]
#[path = "capacities/tests.rs"]
mod tests;
