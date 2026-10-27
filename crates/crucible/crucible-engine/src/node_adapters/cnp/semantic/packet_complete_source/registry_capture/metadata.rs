//! Preserves actual registry capture banks without reading alias lookup keys.
//!
//! The Source already owns the inline capture header. Its encoded Vec, record
//! Vec, independent alias row/lookup Vecs and optional completed payload retain
//! their defining capacities even after refusal. The census neither enters a
//! registry callback nor establishes a completed native or Source handoff.

use super::*;
use crate::node_contract::{
    RuntimeError, restored_owner_history::OriginalOwnerCapacityMetadataData,
};
use crucible_node_transport::retained_metadata::{
    RetainedProtocolMetadataFacts, records::PacketRuntimeMetadataRecordBank,
};
use std::cell::BorrowError;

impl OriginalCompleteRegistryCapture {
    /// Appends this original capture's actual retained backing to one census.
    ///
    /// # Errors
    /// Refuses invalid geometry, selected-row exhaustion or unavailable backing.
    fn record_retained_capacity_data(
        &self,
        census: &mut OriginalOwnerCapacityMetadataData<'_>,
    ) -> Result<(), RuntimeError> {
        let Self {
            maximum_encoded_bytes,
            maximum_rows,
            encoded,
            records,
            aliases,
            payload,
            reserved,
            attempted,
            failed,
        } = self;
        census.observe_inline_data(maximum_encoded_bytes)?;
        census.observe_inline_data(maximum_rows)?;
        census.observe_inline_data(reserved)?;
        census.observe_inline_data(attempted)?;
        census.observe_inline_data(failed)?;

        census.observe(encoded)?;
        if let Some(records) = records {
            census.record(records.retained_capacity_data())?;
        }
        if let Some(aliases) = aliases {
            for row in aliases.retained_capacity_data() {
                census.record(row)?;
            }
        }
        if let Some(payload) = payload {
            census.observe(payload)?;
        }
        Ok(())
    }

    pub(super) fn capacity_facts_data(
        &self,
        bank: Option<&mut PacketRuntimeMetadataRecordBank>,
    ) -> Result<RetainedProtocolMetadataFacts, RuntimeError> {
        let maximum = bank.as_ref().map_or(usize::MAX, |bank| bank.maximum_rows());
        let mut census = OriginalOwnerCapacityMetadataData::new(maximum, bank);
        self.record_retained_capacity_data(&mut census)?;
        Ok(census.finish())
    }
}

impl PacketCompleteSemanticSource {
    /// Reports actual original registry capture backing and optional physical rows.
    ///
    /// Callers first admit the selected bank and
    /// [`Self::original_complete_registry_capacity_counter_scratch_data`]. The
    /// walk preserves failed or incomplete backing and prior physical rows. The
    /// retained typed registry owner and its live callbacks remain separate.
    ///
    /// # Errors
    /// Refuses foreign creation, borrowed capture custody, invalid geometry,
    /// exhausted selected rows or unavailable physical backing.
    pub fn original_complete_registry_capacity_data(
        &self,
        bank: Option<&mut PacketRuntimeMetadataRecordBank>,
    ) -> Result<RetainedProtocolMetadataFacts, RuntimeError> {
        self.storage_origin_with_error::<RuntimeError>()?;
        let slot = self
            .registry_capture
            .try_borrow()
            .map_err(|_| RuntimeError::OwnerBusy)?;
        let facts = match slot.as_ref() {
            Some(capture) => capture.capacity_facts_data(bank)?,
            None => RetainedProtocolMetadataFacts::default(),
        };
        self.storage_origin_with_error::<RuntimeError>()?;
        Ok(facts)
    }

    /// Names the concrete capture, bank, row-array and borrowed census controls.
    pub fn original_complete_registry_capacity_counter_scratch_data() -> usize {
        OriginalOwnerCapacityMetadataData::counter_scratch_data()
            + MetadataRecordBank::retained_capacity_counter_scratch_data()
            + MetadataAliasBank::retained_capacity_counter_scratch_data()
            + size_of::<&Self>()
            + size_of::<&OriginalCompleteRegistryCapture>()
            + size_of::<Option<&OriginalCompleteRegistryCapture>>()
            + size_of::<Ref<'static, Option<OriginalCompleteRegistryCapture>>>()
            + size_of::<Result<Ref<'static, Option<OriginalCompleteRegistryCapture>>, BorrowError>>(
            )
            + size_of::<&Vec<u8>>()
            + size_of::<&MetadataRecordBank>()
            + size_of::<&MetadataAliasBank>()
            + size_of::<&InputPayload>()
            + size_of::<[MetadataCapacityRecord; 2]>()
            + size_of::<std::array::IntoIter<MetadataCapacityRecord, 2>>()
            + size_of::<RetainedProtocolMetadataFacts>()
            + size_of::<Result<RetainedProtocolMetadataFacts, RuntimeError>>()
            + size_of::<Option<&mut PacketRuntimeMetadataRecordBank>>()
            + size_of::<Result<(), RuntimeError>>()
            + size_of::<usize>()
    }
}

#[cfg(test)]
#[path = "metadata/tests.rs"]
mod tests;
