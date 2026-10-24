//! Quotes real same-query native and upload phases without moving their owners.
//!
//! Original Source banks represent semantic occurrences only. Native spare
//! capacities come from the original cold validator, not Source parse capacities.
//! A genuine installed window and later keyed proof/currentness checks remain
//! mandatory before any Prepare, mapping construction or publication effect.

use super::*;
use crate::{
    node_admission::{OriginalRestorationNodeConstructionData, OriginalRestorationNodeInputs},
    node_contract::RuntimeError,
};
use crucible_node_transport::{
    client::OriginalFreshRestoreQuery,
    connection::original_native_restore_input_construction_storage_data,
    reference_packet::service::ack_emitter::{
        PacketNativeRestoreCommitConstructionInputs,
        original_native_restore_commit_construction_storage_data,
    },
};
use std::rc::Rc;

impl PacketCompleteSemanticSource {
    pub(in crate::node_adapters::cnp::semantic) fn original_restoration_node_construction_data(
        &self,
        native: &crate::node_adapters::cnp::semantic::CnpSemanticProcessCustody,
        query: &OriginalFreshRestoreQuery,
        realization: &crucible_node_transport::bodies::RealizeResult,
        inputs: &OriginalRestorationNodeInputs<'_>,
    ) -> Result<OriginalRestorationNodeConstructionData, RuntimeError> {
        self.authenticate_original_fresh_host_query_native_data(native)?;
        self.authenticate_native_launch_data(inputs.launch)?;
        let retained = inputs.ticket.native_restoration_construction_data()?;
        let model = retained
            .selected_owner_construction_data()
            .ok_or(RuntimeError::UnsupportedFacet)?;
        let association = self
            .ack_peer_association
            .try_borrow()
            .map_err(|_| RuntimeError::OwnerBusy)?;
        let association = association.as_ref().ok_or(RuntimeError::OwnerUnavailable)?;
        let controller = native.controller().ok_or(RuntimeError::OwnerUnavailable)?;
        let emitter = association
            .emitter
            .as_ref()
            .ok_or(RuntimeError::OwnerUnavailable)?;
        query
            .authenticate_original_source_context_data(
                controller,
                emitter,
                &self.installation().owner,
            )
            .map_err(|_| RuntimeError::InvalidReceipt)?;
        let report = query.report_data().ok_or(RuntimeError::OwnerUnavailable)?;
        let scope = &report.data.scope;
        let expected = self.installation();
        if scope.native_pid.get() != u64::from(controller.peer_pid())
            || scope.world != expected.world_binding_hash
            || scope.owner_generation != expected.binding.authority.owner_generation
            || scope.admission != expected.admission
            || scope.prepared_token != realization.prepared_token
            || scope.closed_gate_receipt != realization.closed_gate_receipt
        {
            return Err(RuntimeError::InvalidReceipt);
        }
        let lengths = retained.archived_input_byte_extents_data();
        let maximum = inputs.maximum_requested_bytes;
        // The actual same Source base bank owns this finite mapping maximum;
        // it is not borrowed from an unrelated policy ceiling or report row.
        let mapping_maximum = super::complete_restore::MAPPING_BYTES;
        let upload = controller
            .quote_original_complete_restore_upload_before_mapping_data(
                emitter,
                query,
                inputs.prepare_id,
                lengths,
                mapping_maximum,
                maximum,
            )
            .map_err(|_| RuntimeError::ResourceLimit)?;
        let native_inputs = original_native_restore_input_construction_storage_data(
            inputs.launch,
            retained.native_demand_data(),
            retained.native_decoder_limits_data(),
            model,
            [
                lengths[0],
                lengths[1],
                lengths[2],
                lengths[3],
                lengths[4],
                mapping_maximum,
            ],
            report,
            maximum,
        )
        .map_err(|_| RuntimeError::ResourceLimit)?;
        let birth = self
            .ack_peer_birth
            .try_borrow()
            .map_err(|_| RuntimeError::OwnerBusy)?;
        let birth = birth.as_ref().ok_or(RuntimeError::OwnerUnavailable)?;
        let originals = birth.original_initial_lifecycle_inputs_data()?;
        if association.banks[1].is_empty() || association.banks[2].is_empty() {
            return Err(RuntimeError::OwnerUnavailable);
        }
        let native_commit = original_native_restore_commit_construction_storage_data(
            &PacketNativeRestoreCommitConstructionInputs {
                launch: inputs.launch,
                encoded_launch: inputs.encoded_launch,
                source_birth: originals.source_birth,
                host_registration: originals.host_registration,
                kernel_binding: &association.banks[1],
                policy_binding: &association.banks[2],
                model,
                maximum_requested_bytes: maximum,
            },
        )
        .map_err(|_| RuntimeError::ResourceLimit)?;
        let host_currentness_bytes = association
            .native
            .as_ref()
            .ok_or(RuntimeError::OwnerUnavailable)?
            .original_fresh_current_storage_data()?;
        query
            .authenticate_current(controller, emitter)
            .map_err(|_| RuntimeError::InvalidReceipt)?;
        native.read_owner.original_fresh_query_custody_data()?;
        let mut data = OriginalRestorationNodeConstructionData {
            source: Rc::downgrade(inputs.source),
            read_owner: Rc::as_ptr(&native.read_owner).cast(),
            upload,
            prepare_binding: controller
                .quote_original_fresh_restore_prepare_binding_storage_data(emitter, query, maximum)
                .map_err(|_| RuntimeError::ResourceLimit)?,
            native_allocation: native_inputs.original_input_allocation_data(),
            native_inputs,
            native_commit,
            host_currentness_bytes,
            mapping_construction_bytes: controller
                .original_archived_mapping_construction_storage_data()
                .map_err(|_| RuntimeError::ResourceLimit)?
                .checked_add(retained.mapping_reference_clone_bytes_data())
                .ok_or(RuntimeError::ResourceLimit)?,
            maximum_mapping_bytes: mapping_maximum,
            signer: None,
            installed_custody: None,
            source_activation: None,
            source_observation: None,
            restored_suffix: None,
        };
        if let Some(signing) = &inputs.signing {
            let construction = signing.cold.original_signing_construction_inputs_data(
                signing.inputs,
                inputs.plan,
                &data,
                controller,
                query,
                mapping_maximum,
                signing.maximum_record_bytes,
                signing.observed_other_retained_bytes,
            )?;
            let signer =
                self.original_restoration_signer_construction_data(&construction, maximum)?;
            // This is still only prospective DATA. A real installed window
            // must conjoin this exact row before any phase claim can exist.
            data.signer = Some(signer);
        }
        query
            .authenticate_current(controller, emitter)
            .map_err(|_| RuntimeError::InvalidReceipt)?;
        native.read_owner.original_fresh_query_custody_data()?;
        Ok(data)
    }
}

impl PacketCompleteSemanticSource {
    pub(in crate::node_adapters::cnp::semantic) fn original_restoration_source_counter_scratch_data()
    -> usize {
        std::mem::size_of::<std::cell::Ref<'static, Option<OriginalAckPeerAssociation>>>()
            + std::mem::size_of::<std::cell::Ref<'static, Option<OriginalAckPeerBirth>>>()
            + std::mem::size_of::<super::super::birth::OriginalAckPeerInputs<'static>>()
            + std::mem::size_of::<&crucible_node_transport::reference_packet::service::fresh_restore_allocation::PacketNativeFreshRestoreAllocationReport>()
            + crucible_node_transport::client::CnpController::original_fresh_restore_query_counter_scratch_data()
            + crucible_node_transport::client::CnpController::original_fresh_restore_prepare_binding_counter_scratch_data()
            + crucible_node_transport::client::CnpController::original_selected_archived_mapping_counter_scratch_data()
            + crate::node_state::CompleteOriginalNativeRestorationData::reference_counter_scratch_data()
            + crucible_node_transport::connection::original_native_restore_input_construction_counter_scratch_data()
            + crucible_node_transport::reference_packet::service::ack_emitter::original_native_restore_commit_construction_counter_scratch_data()
    }
}
