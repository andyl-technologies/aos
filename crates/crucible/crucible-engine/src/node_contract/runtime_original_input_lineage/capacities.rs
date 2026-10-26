//! Walks actual sealed lineage backing without copying or renewing input custody.
//!
//! Each retained view includes the data Rc, original batch Rc and full Core
//! activation children. Repeated views receive no alias discount. Legacy byte
//! accounting and its distinct owning-row split remain unchanged.

use super::*;
use crate::node_contract::restored_owner_history::{
    OriginalRestoredOwnerCapacityRow, OriginalRestoredOwnerCapacityWalk,
};
use std::mem::size_of;

impl OriginalRestoredOwnerCapacityWalk for OriginalInputLineage {
    fn capacities(
        &self,
        depth: usize,
        sink: &mut dyn FnMut(OriginalRestoredOwnerCapacityRow) -> Result<(), RuntimeError>,
    ) -> Result<(), RuntimeError> {
        let Self { data } = self;
        data.capacities(depth, sink)
    }
}

impl OriginalRestoredOwnerCapacityWalk for OriginalInputLineageData {
    fn capacities(
        &self,
        depth: usize,
        sink: &mut dyn FnMut(OriginalRestoredOwnerCapacityRow) -> Result<(), RuntimeError>,
    ) -> Result<(), RuntimeError> {
        let Self {
            source_scope,
            original,
            publications,
        } = self;
        source_scope.capacities(depth, sink)?;
        original.capacities(depth, sink)?;
        publications.capacities(depth, sink)
    }
}

impl OriginalRestoredOwnerCapacityWalk for OriginalPublicationClaim {
    fn capacities(
        &self,
        depth: usize,
        sink: &mut dyn FnMut(OriginalRestoredOwnerCapacityRow) -> Result<(), RuntimeError>,
    ) -> Result<(), RuntimeError> {
        let Self {
            event,
            origin,
            published,
            objects,
            rows,
        } = self;
        event.capacities(depth, sink)?;
        origin.capacities(depth, sink)?;
        published.capacities(depth, sink)?;
        objects.capacities(depth, sink)?;
        rows.capacities(depth, sink)
    }
}

impl OriginalInputLineage {
    /// Names defining lineage loans and the shared Core capacity-walk controls.
    pub(crate) fn retained_capacity_counter_scratch_data() -> usize {
        crate::node_contract::restored_owner_history::original_restored_owner_capacity_counter_scratch_data()
            + size_of::<&Self>()
            + size_of::<&Rc<OriginalInputLineageData>>()
            + size_of::<&OriginalInputLineageData>()
            + size_of::<&SavedOriginalInputScope>()
            + size_of::<&Rc<RuntimeInputBatch>>()
            + size_of::<&Vec<OriginalPublicationClaim>>()
            + size_of::<std::slice::Iter<'static, OriginalPublicationClaim>>()
            + size_of::<&OriginalPublicationClaim>()
            + size_of::<&crucible_node_format::Event>()
            + size_of::<&OriginalPublicationOrigin>()
            + size_of::<&ContentRef>()
            + size_of::<&Vec<InputPayload>>()
            + size_of::<std::slice::Iter<'static, InputPayload>>()
            + size_of::<&Vec<OriginalLineageRow>>()
            + size_of::<std::slice::Iter<'static, OriginalLineageRow>>()
    }
}
