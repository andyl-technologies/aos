//! Quotes RuntimeJoin's actual administrative and original-Event temporaries.
//!
//! Publication bodies come from the genuine parent inventory. Their complete
//! parser/typed/validation row is independent of the already retained Runtime7.

use super::*;
use crate::node_contract::RuntimeError;
use crucible_node_format::{Event, Id};
use serde_json::Value;

impl OriginalInitial15ArchivedGroup {
    pub(in super::super) fn runtime_join_terminal_transient_data(
        &self,
        scope: &ParentArchive17ReadScope<'_, '_>,
    ) -> Result<usize, OperationFailure> {
        let runtime = self
            .runtime
            .as_ref()
            .ok_or_else(|| refused("initial15 Runtime7 absent"))?;
        let administrative = self
            .administrative
            .as_ref()
            .ok_or_else(|| refused("initial15 administrative absent"))?;
        let nodes = administrative
            .attempts
            .len()
            .checked_add(5)
            .and_then(|count| count.checked_mul(NodeRuntime::capture_map_node_storage::<&Id, ()>()))
            .ok_or_else(|| refused("initial15 RuntimeJoin administrative extent overflow"))?;
        let projection =
            NodeRuntime::capture_serialization_storage(&runtime.source_activation, self.maximum)
                .map_err(unknown)?;
        let metadata =
            NodeRuntime::capture_future_decode_storage(runtime, self.maximum).map_err(unknown)?;

        let mut event = 0usize;
        for input in &runtime.inputs {
            let Some(lineage) = &input.lineage else {
                continue;
            };
            for publication in &lineage.publications {
                let bytes = scope.body_data(&publication.published).map_err(unknown)?;
                // The defining validator decodes and drops one Event per loop.
                // Earlier Event temporaries do not accumulate with later ones.
                let selected = NodeRuntime::capture_selected_json_decode_storage(
                    bytes,
                    size_of::<Event>(),
                    NodeRuntime::capture_map_node_storage::<String, Value>(),
                    self.maximum,
                )
                .map_err(unknown)?;
                event = event.max(selected);
            }
        }
        // ContentRef::verify builds these three actual HashRef strings while
        // checking payload/provenance bodies. Each temporary drops before the
        // next verification or Event decode; no original body copy is made.
        let hash = "blake3-256".len() + "cnp.blob.v1".len() + 64;
        checked_sum([nodes, projection, metadata, event, hash], self.maximum)
    }
}

pub(super) fn counter_scratch_data() -> usize {
    size_of::<&OriginalInitial15ArchivedGroup>()
        + OriginalLineageRuntimeRecord::logical_identity_counter_scratch_data()
        + size_of::<&ParentArchive17ReadScope<'static, 'static>>()
        + size_of::<&OriginalLineageRuntimeRecord>()
        + size_of::<&RuntimeOriginalCaptureJournal>()
        + size_of::<std::slice::Iter<'static, crate::node_contract::OriginalLineageInputRecord>>()
        + size_of::<std::slice::Iter<'static, crate::node_contract::SavedOriginalPublication>>()
        + size_of::<[usize; 5]>()
        + size_of::<std::array::IntoIter<usize, 5>>()
        + size_of::<crucible_node_format::HashRef>()
        + size_of::<Result<crucible_node_format::HashRef, crucible_node_format::ContractError>>()
        + size_of::<blake3::Hasher>()
        + size_of::<blake3::Hash>()
        + size_of::<[u8; 64]>()
        + size_of::<Result<usize, RuntimeError>>()
        + NodeRuntime::capture_selected_json_decode_counter_scratch_data()
        + NodeRuntime::capture_serialization_counter_scratch_data()
}
