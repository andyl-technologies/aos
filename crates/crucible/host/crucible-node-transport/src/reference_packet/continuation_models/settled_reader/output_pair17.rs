//! Derives the same Capture boundary from the retained current typed model.

use super::*;

impl PacketSettledModel17Data {
    pub(crate) fn capture_boundary17_construction_counter_scratch_data() -> usize {
        std::mem::size_of::<ProducerInventoryData<'static>>()
            + std::mem::size_of::<crate::retained_metadata::MetadataObserver<'static>>()
            + std::mem::size_of::<crate::retained_metadata::RetainedProtocolMetadataFacts>()
            + std::mem::size_of::<
                crate::retained_metadata::serialization_storage::OriginalSerializationStorageData,
            >()
            + ReactiveModel17Data::capture_boundary17_construction_counter_scratch_data()
    }

    /// Quotes actual inventory and local-model validation temporary storage.
    ///
    /// # Errors
    /// Refuses missing current event geometry, overflow or the independent maximum.
    pub(crate) fn capture_boundary17_construction_data(
        &self,
        maximum: usize,
    ) -> Result<usize, ProviderError> {
        let mut observer = crate::retained_metadata::MetadataObserver::new();
        self.observe_settled_history_metadata_data(&mut observer)?;
        let facts = observer.finish();
        match &self.state {
            CurrentModel::Producer(state) => {
                let inventory = ProducerInventoryData {
                    reached: state.reached,
                    gate_closed: state.gate_closed,
                    pending: state.events.get(state.next_event..).ok_or_else(invalid)?,
                    retained_outputs: &state.outputs,
                    private_mutations: U64::new(state.private_mutations),
                    packet_effects: U64::new(state.packet_effects),
                };
                let row = crate::retained_metadata::serialization_storage::actual_serialization_storage_data(&inventory, facts, maximum)?;
                // authenticate_producer validates every original event ID in
                // an actual borrowed-ID BTreeSet before inventory hashing.
                let ids = crate::retained_metadata::requested_storage::tree_storage_data(
                    1,
                    state.events.len(),
                    std::mem::size_of::<&crucible_node_format::Id>(),
                    std::mem::align_of::<&crucible_node_format::Id>(),
                )?;
                let peak = row
                    .dom_and_canonical_scratch_bytes
                    .checked_add(row.canonical_output_requested_bytes)
                    .and_then(|bytes| bytes.checked_add(row.serializer_temporary_requested_bytes))
                    .and_then(|bytes| bytes.checked_add(ids))
                    .ok_or_else(invalid)?;
                if peak > maximum {
                    return Err(invalid());
                }
                Ok(peak)
            }
            CurrentModel::Reactive(state) => state.capture_boundary17_construction_data(maximum),
        }
    }

    /// Derives the actual current inventory without advancing modeled work.
    ///
    /// The caller separately funds canonical inventory DOM/byte transient
    /// storage under its actual current Control output capacity. The bounded
    /// projection completes and drops before any later MAC/anchor operation.
    ///
    /// # Errors
    /// Refuses inconsistent/failed models, unfinished grants, invalid inventory
    /// serialization or inventory bytes outside the independently supplied bound.
    pub(crate) fn capture_boundary17_data(
        &self,
        maximum_model_bytes: usize,
    ) -> Result<PacketModelCaptureBoundaryData, ProviderError> {
        self.authenticate_settled_adoption_eligibility_data()?;
        match &self.state {
            CurrentModel::Producer(state) => {
                let pending = state.events.get(state.next_event..).ok_or_else(invalid)?;
                let inventory = ProducerInventoryData {
                    reached: state.reached,
                    gate_closed: state.gate_closed,
                    pending,
                    retained_outputs: &state.outputs,
                    private_mutations: U64::new(state.private_mutations),
                    packet_effects: U64::new(state.packet_effects),
                };
                crate::connection::serialized_credit(&inventory, maximum_model_bytes)?;
                Ok(PacketModelCaptureBoundaryData {
                    local_cursor: state.reached,
                    gate_closed: state.gate_closed,
                    retained_outputs: state.outputs.len(),
                    earliest_pending_completion: pending.iter().map(|event| event.completion).min(),
                    inventory_hash: canonical::json_hash(
                        "source-owned.packet-inventory.v1",
                        &inventory,
                    )?,
                })
            }
            CurrentModel::Reactive(state) => state.capture_boundary17_data(maximum_model_bytes),
        }
    }
}
