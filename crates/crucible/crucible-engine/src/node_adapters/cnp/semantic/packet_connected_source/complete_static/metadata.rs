//! Preserves static row/dependency capacities independently of completion flags.

use super::*;
use crate::node_contract::restored_owner_history::OriginalOwnerCapacityMetadataData;
use crucible_node_transport::retained_metadata::records::{
    MetadataCapacityRecord, MetadataRecordKind,
};
use std::mem::{align_of, size_of};

impl CompleteInputStaticRows {
    /// Records every original row, body and dependency bank without cloning.
    ///
    /// The enclosing Source Box already contains this inline header. Partial or
    /// failed rows remain DATA; this walk grants no static-graph eligibility.
    ///
    /// # Errors
    /// Refuses invalid geometry, exhausted selected rows or unready backing.
    pub(in crate::node_adapters::cnp::semantic::packet_connected_source) fn record_retained_capacity_data(
        &self,
        census: &mut OriginalOwnerCapacityMetadataData<'_>,
    ) -> Result<(), RuntimeError> {
        let Self {
            rows,
            complete,
            failed,
        } = self;
        census.observe_inline_data(complete);
        census.observe_inline_data(failed);
        census.record(MetadataCapacityRecord {
            kind: MetadataRecordKind::Vector,
            extent: rows.capacity(),
            element_bytes: size_of::<(InputPayload, Vec<ContentRef>)>(),
            alignment: align_of::<(InputPayload, Vec<ContentRef>)>(),
        })?;
        for (body, dependencies) in rows {
            census.observe(body)?;
            census.observe(dependencies)?;
        }
        Ok(())
    }

    /// Names actual static row, tuple and dependency borrowed controls.
    pub(in crate::node_adapters::cnp::semantic::packet_connected_source) fn retained_capacity_counter_scratch_data()
    -> usize {
        size_of::<&Self>()
            + size_of::<&Vec<(InputPayload, Vec<ContentRef>)>>()
            + size_of::<std::slice::Iter<'static, (InputPayload, Vec<ContentRef>)>>()
            + size_of::<&(InputPayload, Vec<ContentRef>)>()
            + size_of::<&InputPayload>()
            + size_of::<&Vec<ContentRef>>()
            + size_of::<std::slice::Iter<'static, ContentRef>>()
            + size_of::<&bool>()
    }
}

#[cfg(test)]
#[path = "metadata/tests.rs"]
mod tests;
