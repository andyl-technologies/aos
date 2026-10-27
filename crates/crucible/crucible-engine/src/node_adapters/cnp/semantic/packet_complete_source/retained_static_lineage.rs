//! Preserves static rows and every retained lineage's actual capacity geometry.
//!
//! The Source's inline headers are counted by its holder census. Core lineage
//! views include their independent data/batch allocations and nested activation
//! views. No address identity, copied body or alias discount enters packet rows.

use super::*;
use crate::node_contract::{
    RuntimeError, restored_owner_history::OriginalOwnerCapacityMetadataData,
};
use crucible_node_transport::retained_metadata::{
    RetainedProtocolMetadataFacts, records::PacketRuntimeMetadataRecordBank,
};
use std::mem::size_of;

impl PacketCompleteSemanticSource {
    /// Reports actual static/lineage capacities or appends their physical rows.
    ///
    /// Callers admit the bank and
    /// [`Self::original_complete_static_lineage_capacity_counter_scratch_data`]
    /// before this DATA walk. Repeated views keep every allocation occurrence;
    /// partial static rows cannot become installed graph or input authority.
    /// Legacy byte accounting and lifecycle eligibility remain independent.
    ///
    /// # Errors
    /// Refuses foreign creation, busy holders, unsupported layout, exhausted
    /// selected rows or unready physical backing, preserving earlier rows.
    pub fn original_complete_static_lineage_capacity_data(
        &self,
        bank: Option<&mut PacketRuntimeMetadataRecordBank>,
    ) -> Result<RetainedProtocolMetadataFacts, RuntimeError> {
        self.storage_origin_with_error::<RuntimeError>()?;
        let maximum = bank.as_ref().map_or(usize::MAX, |bank| bank.maximum_rows());
        let mut census = OriginalOwnerCapacityMetadataData::new(maximum, bank);
        match &self.original {
            CompletePacketOriginal::Producer(_) => {}
            CompletePacketOriginal::Reactive(source) => {
                source.record_complete_static_lineage_capacity_data(&mut census)?
            }
        }
        self.storage_origin_with_error::<RuntimeError>()?;
        Ok(census.finish())
    }

    /// Names actual Source, reactive static/lineage and Core census controls.
    pub fn original_complete_static_lineage_capacity_counter_scratch_data() -> usize {
        OriginalOwnerCapacityMetadataData::counter_scratch_data()
            + PacketConnectedSemanticSource::complete_static_lineage_capacity_counter_scratch_data()
            + size_of::<&Self>()
            + size_of::<Option<&mut PacketRuntimeMetadataRecordBank>>()
            + size_of::<RetainedProtocolMetadataFacts>()
            + size_of::<Result<RetainedProtocolMetadataFacts, RuntimeError>>()
            + size_of::<usize>()
    }
}

#[cfg(test)]
#[path = "retained_static_lineage/tests.rs"]
mod tests;
