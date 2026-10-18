//! Projects the actual reactive inventory with its pending modeled work intact.

use super::*;

impl ReactiveModel17Data {
    pub(in crate::reference_packet) fn capture_boundary17_data(
        &self,
        maximum_model_bytes: usize,
    ) -> Result<
        crate::reference_packet::continuation_models::PacketModelCaptureBoundaryData,
        ProviderError,
    > {
        self.authenticate_settled_adoption_eligibility_data()?;
        let state = &self.0;
        let mut earliest = state.publications.iter().map(|row| row.publication).min();
        for reaction in &state.reactions {
            let completion = if state.definition.output.is_some() {
                reaction.evaluation.reaction_publication(U64::new(16))?
            } else {
                reaction.evaluation
            };
            earliest = Some(earliest.map_or(completion, |prior| prior.min(completion)));
        }
        let inventory = ConnectedInventoryData(state);
        crate::connection::serialized_credit(&inventory, maximum_model_bytes)?;
        Ok(
            crate::reference_packet::continuation_models::PacketModelCaptureBoundaryData {
                local_cursor: state.reached,
                gate_closed: state.gate_closed,
                retained_outputs: state.outputs.len(),
                earliest_pending_completion: earliest,
                inventory_hash: canonical::json_hash(
                    "source-owned.packet-connected-inventory/4",
                    &inventory,
                )?,
            },
        )
    }
}
