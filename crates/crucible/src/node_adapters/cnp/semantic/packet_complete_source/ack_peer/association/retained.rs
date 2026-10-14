//! Observes source-owned original peer association backing without serialization.

use super::*;

impl OriginalAckPeerAssociation {
    pub(in crate::node_adapters::cnp::semantic::packet_complete_source) fn retained_heap_storage_data(
        &self,
        maximum: usize,
    ) -> Result<usize, OperationFailure> {
        use crate::node_adapters::cnp::semantic::packet_complete_source::retained_values::{
            sum, value_storage,
        };
        if let Some(restore) = self.restore.as_ref() {
            restore.authenticate_unpopulated_capture_metadata()?;
        }
        let mut bytes = self.allocated_bank_bytes()?;
        for value in self
            .normalized
            .iter()
            .chain(std::iter::once(&self.proof))
            .flatten()
        {
            bytes = sum([bytes, value_storage(value, 0, maximum)?], maximum)?;
        }
        if let Some(context) = &self.context {
            bytes = sum(
                [
                    bytes,
                    context.schema.capacity(),
                    context.algorithm.capacity(),
                    context.source_birth.allocation_capacity(),
                    context.kernel_binding.allocation_capacity(),
                    context.policy_binding.allocation_capacity(),
                    context.host_registration.allocation_capacity(),
                    context.native_registration.allocation_capacity(),
                    context.hello_request.allocation_capacity(),
                    context.hello_response.allocation_capacity(),
                    context.assigned_admit.allocation_capacity(),
                ],
                maximum,
            )?;
        }
        // These actual private observers include their retained shared views.
        // SDK byte/literal/metadata-bank owners outside this association remain
        // separately counted by the actual node/controller owning row.
        if let Some(emitter) = &self.emitter {
            bytes = sum(
                [
                    bytes,
                    PacketCompleteSemanticSource::complete_retained_metadata_storage_data(
                        &emitter
                            .original_retained_metadata_facts()
                            .map_err(unknown)?,
                        maximum,
                    )?,
                ],
                maximum,
            )?;
        }
        if let Some(emitter) = &self.restore_input_emitter {
            bytes = sum(
                [
                    bytes,
                    PacketCompleteSemanticSource::complete_retained_metadata_storage_data(
                        &emitter
                            .original_retained_metadata_facts()
                            .map_err(unknown)?,
                        maximum,
                    )?,
                ],
                maximum,
            )?;
        }
        if let Some(hello) = &self.hello {
            bytes = sum(
                [
                    bytes,
                    PacketCompleteSemanticSource::complete_retained_metadata_storage_data(
                        &hello.original_retained_metadata_facts().map_err(unknown)?,
                        maximum,
                    )?,
                ],
                maximum,
            )?;
        }
        Ok(bytes)
    }
}
