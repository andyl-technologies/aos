//! Counts both original transfer phases and every retained failed signer body.
//!
//! Capacity DATA does not authenticate IDs, completed mapping, phase order or
//! signing claims. The enclosing Source checks its creator before lending rows.

use super::*;
use crate::node_adapters::cnp::semantic::packet_complete_source::retained_values::{
    record_value_capacity_data_with_error, value_capacity_counter_scratch_data,
};
use crate::node_contract::restored_owner_history::OriginalOwnerCapacityMetadataData;

impl OriginalSourceRestoreTransferAttempt {
    /// Records actual IDs and both independent normalized phase populations.
    ///
    /// # Errors
    /// Refuses selected-row/depth exhaustion, unavailable backing or checked layout overflow.
    pub(in crate::node_adapters::cnp::semantic::packet_complete_source) fn record_capacity_data(
        &self,
        census: &mut OriginalOwnerCapacityMetadataData<'_>,
    ) -> Result<(), RuntimeError> {
        let Self {
            prepare_id,
            commit_id,
            nonce,
            generation,
            prepare,
            commit,
            inputs_started,
            inputs_verified,
            failed,
        } = self;

        census.observe(prepare_id)?;
        census.observe(commit_id)?;
        census.observe_inline_data(nonce)?;
        census.observe_inline_data(generation)?;
        census.observe_inline_data(inputs_started)?;
        census.observe_inline_data(inputs_verified)?;
        census.observe_inline_data(failed)?;

        prepare.record_capacity_data(census)?;
        commit.record_capacity_data(census)
    }

    /// Names the defining signer/phase borrowed controls and private JSON cursors.
    pub(in crate::node_adapters::cnp::semantic::packet_complete_source) fn capacity_counter_scratch_data()
    -> usize {
        size_of::<&Self>()
            + size_of::<(
                &Option<Id>,
                &Option<Id>,
                &[u8; 32],
                &U64,
                &SourceTransferPhase,
                &SourceTransferPhase,
                &bool,
                &bool,
                &bool,
            )>()
            + size_of::<(&[Option<serde_json::Value>; 5], &bool, &bool, &bool, &bool)>()
            + size_of::<std::iter::Flatten<std::slice::Iter<'_, Option<serde_json::Value>>>>()
            + size_of::<&mut OriginalOwnerCapacityMetadataData<'_>>()
            + size_of::<Result<(), RuntimeError>>()
            + value_capacity_counter_scratch_data()
    }
}

impl SourceTransferPhase {
    fn record_capacity_data(
        &self,
        census: &mut OriginalOwnerCapacityMetadataData<'_>,
    ) -> Result<(), RuntimeError> {
        let Self {
            normalized,
            started,
            sealed,
            publishing_started,
            verified,
        } = self;

        census.observe_inline_data(started)?;
        census.observe_inline_data(sealed)?;
        census.observe_inline_data(publishing_started)?;
        census.observe_inline_data(verified)?;
        for value in normalized.iter().flatten() {
            record_value_capacity_data_with_error::<RuntimeError>(value, 0, census)?;
        }
        Ok(())
    }
}

#[cfg(test)]
#[path = "capacities/tests.rs"]
mod tests;
