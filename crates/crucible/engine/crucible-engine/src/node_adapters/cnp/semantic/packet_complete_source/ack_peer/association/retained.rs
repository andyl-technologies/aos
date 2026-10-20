//! Observes source-owned original peer association backing without serialization.

use super::*;
use crate::node_adapters::cnp::semantic::packet_complete_source::storage_error::StorageError;

impl OriginalAckPeerAssociation {
    #[cfg(test)]
    pub(in crate::node_adapters::cnp::semantic::packet_complete_source) fn retained_heap_storage_data(
        &self,
        maximum: usize,
    ) -> Result<usize, OperationFailure> {
        self.retained_heap_storage_data_with_error::<OperationFailure>(maximum)
    }

    pub(in crate::node_adapters::cnp::semantic) fn retained_heap_storage_data_with_error<
        E: StorageError,
    >(
        &self,
        maximum: usize,
    ) -> Result<usize, E> {
        use crate::node_adapters::cnp::semantic::packet_complete_source::retained_values::{
            sum_with_error, value_storage_with_error,
        };
        if let Some(restore) = self.restore.as_ref() {
            restore.authenticate_unpopulated_capture_metadata_with_error::<E>()?;
        }
        let mut bytes =
            sum_with_error::<E, _>([self.allocated_bank_bytes_with_error::<E>()?], maximum)?;
        if let Some(transfer) = &self.restore_transfer_banks {
            bytes = sum_with_error::<E, _>(
                [
                    bytes,
                    transfer.retained_signer_storage_with_error::<E>(maximum)?,
                ],
                maximum,
            )?;
        }
        if let Some(activation) = &self.restoration_activation {
            bytes = sum_with_error::<E, _>(
                [
                    bytes,
                    activation.normalized_value_bytes_with_error::<E>(maximum)?,
                    activation.native_evidence_backing_bytes_with_error::<E>(maximum)?,
                ],
                maximum,
            )?;
        }
        let current = self
            .current_observations
            .try_borrow()
            .map_err(|_| E::unknown("current observation custody is borrowed"))?;
        bytes = sum_with_error::<E, _>(
            [bytes, current.retained_heap_bytes_with_error::<E>(maximum)?],
            maximum,
        )?;
        drop(current);
        let progress = self
            .producer_progress
            .try_borrow()
            .map_err(|_| E::unknown("Producer progress custody is borrowed"))?;
        bytes = sum_with_error::<E, _>(
            [
                bytes,
                progress.retained_heap_bytes_with_error::<E>(maximum)?,
            ],
            maximum,
        )?;
        drop(progress);
        let input = self
            .restored_inputs
            .try_borrow()
            .map_err(|_| E::unknown("Input17 custody is borrowed"))?;
        bytes = sum_with_error::<E, _>(
            [bytes, input.retained_heap_bytes_with_error::<E>(maximum)?],
            maximum,
        )?;
        drop(input);
        let capture = self
            .restored_capture
            .try_borrow()
            .map_err(|_| E::unknown("restored Capture custody is borrowed"))?;
        bytes = sum_with_error::<E, _>(
            [
                bytes,
                capture.retained_storage_data(maximum).map_err(E::unknown)?,
            ],
            maximum,
        )?;
        drop(capture);
        bytes = sum_with_error::<E, _>(
            [
                bytes,
                self.restored_observations17
                    .retained_heap_bytes_with_error::<E>(maximum)?,
            ],
            maximum,
        )?;
        if let Some(observation) = &self.restoration_observation {
            bytes = sum_with_error::<E, _>(
                [
                    bytes,
                    observation.retained_heap_bytes_with_error::<E>(maximum)?,
                ],
                maximum,
            )?;
        }
        {
            let suffix = self
                .restored_suffix
                .try_borrow()
                .map_err(|_| E::refused("retained suffix seed already borrowed"))?;
            if let Some(seed) = suffix.as_ref() {
                bytes = sum_with_error::<E, _>([bytes, seed.retained_heap_bytes_data()], maximum)?;
            }
        }
        for value in self
            .normalized
            .iter()
            .chain(std::iter::once(&self.proof))
            .flatten()
        {
            bytes = sum_with_error::<E, _>(
                [bytes, value_storage_with_error::<E>(value, 0, maximum)?],
                maximum,
            )?;
        }
        if let Some(context) = &self.context {
            bytes = sum_with_error::<E, _>(
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
            bytes = sum_with_error::<E, _>(
                [
                    bytes,
                    PacketCompleteSemanticSource::complete_retained_metadata_storage_with_error::<E>(
                        &emitter
                            .original_retained_metadata_facts()
                            .map_err(E::unknown)?,
                        maximum,
                    )?,
                ],
                maximum,
            )?;
        }
        if let Some(emitter) = &self.restore_input_emitter {
            bytes = sum_with_error::<E, _>(
                [
                    bytes,
                    PacketCompleteSemanticSource::complete_retained_metadata_storage_with_error::<E>(
                        &emitter
                            .original_retained_metadata_facts()
                            .map_err(E::unknown)?,
                        maximum,
                    )?,
                ],
                maximum,
            )?;
        }
        if let Some(hello) = &self.hello {
            bytes = sum_with_error::<E, _>(
                [
                    bytes,
                    PacketCompleteSemanticSource::complete_retained_metadata_storage_with_error::<E>(
                        &hello
                            .original_retained_metadata_facts()
                            .map_err(E::unknown)?,
                        maximum,
                    )?,
                ],
                maximum,
            )?;
        }
        Ok(bytes)
    }
}
