//! Derives the same Capture boundary from the retained current typed model.

use super::*;

impl PacketSettledModel17Data {
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
