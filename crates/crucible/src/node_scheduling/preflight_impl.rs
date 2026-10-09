//! Native round validation on a private transient coordinator continuation.

use super::*;

impl CausalScheduler {
    // A private transient continuation validates the entire canonical round
    // before any real queue mutation or native ACK. It never issues authority.
    pub(crate) fn preflight_receipts(
        &self,
        receipts: &[SchedulingReceipt],
    ) -> Result<(), SchedulingError> {
        let mut preview = Self {
            activation: self.activation.clone(),
            node_owners: self.node_owners.clone(),
            node_routes: self.node_routes.clone(),
            input_batches: self
                .input_batches
                .iter()
                .map(|(owner, state)| {
                    (
                        owner.clone(),
                        InputBatchState {
                            batch: state.batch.retained_copy(),
                            acknowledgement: state.acknowledgement.clone(),
                            activated_by: state.activated_by.clone(),
                            consumed: state.consumed.clone(),
                        },
                    )
                })
                .collect(),
            used_input_batches: self.used_input_batches.clone(),
            owners: self.owners.clone(),
            bounds: self.bounds.clone(),
            pending: self.pending.clone(),
            operations: self.operations.clone(),
            used_operations: self.used_operations.clone(),
            sequences: self.sequences.clone(),
            routing: self.routing.clone(),
            output_endpoints: self.output_endpoints.clone(),
            external_roots: self.external_roots.clone(),
            external_closed_prefixes: self.external_closed_prefixes.clone(),
            closed_prefixes: self.closed_prefixes.clone(),
            native_sequences: self.native_sequences.clone(),
            payloads: self.payloads.clone(),
            maximum_pending_payload_bytes: self.maximum_pending_payload_bytes,
            maximum_microsteps: self.maximum_microsteps,
        };
        for receipt in receipts {
            let copied = SchedulingReceipt::new(
                receipt.activation.clone(),
                receipt.node.clone(),
                receipt.operation.clone(),
                receipt.progress.clone(),
                receipt.retained_outputs.clone(),
                receipt.observation.clone(),
            );
            preview.accept_receipt(copied)?;
        }
        Ok(())
    }
}
