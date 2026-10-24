//! Requotes the same actual uploader through the Source's private emitter loan.
//!
//! These operations run only under genuine phase claims and existing admitted
//! work. They expose DATA rows, no emitter, controller extraction or new credit.

use super::*;
use crucible_node_transport::{
    client::{
        OriginalCompleteRestoreInputUploadProspectiveStorageData,
        OriginalCompleteRestoreInputUploadStorageData, OriginalFreshRestoreQuery,
    },
    protocol_snapshot::PreparedArchivedProtocolMapping,
};

impl PacketCompleteSemanticSource {
    pub(crate) fn quote_original_restore_transfer_upload_prospective_data(
        &self,
        controller: &CnpController,
        query: &OriginalFreshRestoreQuery,
        claim: &OriginalRestorationTransactionClaim<'_>,
        admitted: &OriginalSourceRestoreSignerConstructionData,
        mapping: &PreparedArchivedProtocolMapping,
    ) -> Result<OriginalCompleteRestoreInputUploadProspectiveStorageData, RuntimeError> {
        self.storage_origin_with_error::<RuntimeError>()?;
        if !matches!(claim.phase(), OriginalRestorationTransactionPhase::Prepare) {
            return Err(RuntimeError::OutstandingObligations);
        }
        claim.authenticate_current()?;
        let inputs = claim.original_inputs_data()?;
        self.authenticate_transfer_inputs_data(&inputs)?;
        admitted.authenticate_original_effect_data(self, controller, &inputs)?;
        if !std::ptr::eq(mapping, inputs.mapping) {
            return Err(RuntimeError::ForeignAuthority);
        }
        let association = self
            .ack_peer_association
            .try_borrow()
            .map_err(|_| RuntimeError::OwnerBusy)?;
        let original = association.as_ref().ok_or(RuntimeError::OwnerUnavailable)?;
        original.authenticate_transfer_ready_data()?;
        let emitter = original
            .emitter
            .as_ref()
            .ok_or(RuntimeError::OwnerUnavailable)?;
        let transfer = original
            .restore_transfer_banks
            .as_ref()
            .ok_or(RuntimeError::OwnerUnavailable)?;
        if !transfer.mapping_attempted || !transfer.mapping_complete || transfer.signer.is_some() {
            return Err(RuntimeError::OutstandingObligations);
        }
        query
            .authenticate_current(controller, emitter)
            .map_err(|_| RuntimeError::InvalidReceipt)?;
        let native = original
            .native
            .as_ref()
            .ok_or(RuntimeError::OwnerUnavailable)?;
        let mut scratch = native.original_fresh_current_scratch()?;
        let call = native.begin_original_fresh_query_call_data(&mut scratch)?;
        let owner = inputs.ticket.owner()?;
        let row = controller
            .quote_original_complete_restore_input_upload_prospective_storage_data(
                emitter,
                query,
                inputs.prepare_id,
                [
                    &inputs.journal.native_after_protocol,
                    &inputs.journal.native_control,
                    &inputs.journal.native_anchor,
                    &owner.state,
                    inputs.journal_reference,
                ],
                mapping,
                admitted.maximum_requested_bytes_data(),
            )
            .map_err(|_| RuntimeError::ResourceLimit)?;
        row.authenticate_original_inputs_data(
            controller,
            emitter,
            query,
            inputs.prepare_id,
            [
                &inputs.journal.native_after_protocol,
                &inputs.journal.native_control,
                &inputs.journal.native_anchor,
                &owner.state,
                inputs.journal_reference,
            ],
            mapping,
        )
        .map_err(|_| RuntimeError::InvalidReceipt)?;
        call.complete(&mut scratch, || claim.authenticate_current())?;
        Ok(row)
    }

    pub(crate) fn quote_original_restore_transfer_inputs_data(
        &self,
        controller: &CnpController,
        claim: &OriginalRestorationTransactionClaim<'_>,
        admitted: &OriginalSourceRestoreSignerConstructionData,
        prospective: &OriginalCompleteRestoreInputUploadProspectiveStorageData,
    ) -> Result<OriginalCompleteRestoreInputUploadStorageData, RuntimeError> {
        self.storage_origin_with_error::<RuntimeError>()?;
        if !matches!(claim.phase(), OriginalRestorationTransactionPhase::Inputs) {
            return Err(RuntimeError::OutstandingObligations);
        }
        claim.authenticate_current()?;
        let inputs = claim.original_inputs_data()?;
        self.authenticate_transfer_inputs_data(&inputs)?;
        admitted.authenticate_original_effect_data(self, controller, &inputs)?;
        let bodies = claim.original_input_bodies_data()?;
        let association = self
            .ack_peer_association
            .try_borrow()
            .map_err(|_| RuntimeError::OwnerBusy)?;
        let original = association.as_ref().ok_or(RuntimeError::OwnerUnavailable)?;
        original.authenticate_transfer_ready_data()?;
        let emitter = original
            .emitter
            .as_ref()
            .ok_or(RuntimeError::OwnerUnavailable)?;
        let input_emitter = original
            .restore_input_emitter
            .as_ref()
            .ok_or(RuntimeError::OwnerUnavailable)?;
        emitter
            .authenticate_original(controller)
            .map_err(|_| RuntimeError::ForeignAuthority)?;
        input_emitter
            .authenticate_original(controller)
            .map_err(|_| RuntimeError::ForeignAuthority)?;
        let transfer = original
            .restore_transfer_banks
            .as_ref()
            .ok_or(RuntimeError::OwnerUnavailable)?;
        transfer
            .signer()?
            .authenticate_ids(inputs.prepare_id, inputs.commit_id)?;
        let native = original
            .native
            .as_ref()
            .ok_or(RuntimeError::OwnerUnavailable)?;
        let birth = self
            .ack_peer_birth
            .try_borrow()
            .map_err(|_| RuntimeError::OwnerBusy)?;
        let key = birth
            .as_ref()
            .ok_or(RuntimeError::OwnerUnavailable)?
            .original_fresh_query_key_data()?;
        let mut scratch = native.original_fresh_current_scratch()?;
        let call = native.begin_original_fresh_query_call_data(&mut scratch)?;
        let pair = controller
            .original_completed_complete_restore_transfer(
                emitter,
                PacketCompleteRestoreTransferPhase::Prepare,
            )
            .map_err(|_| RuntimeError::InvalidReceipt)?;
        receipts::authenticate_prepare_pair(
            transfer,
            pair.original(),
            pair.response(),
            key,
            admitted.maximum_frame_bytes_data(),
        )?;
        let row = controller
            .quote_original_complete_restore_input_upload_storage_data(
                input_emitter,
                bodies,
                admitted.maximum_requested_bytes_data(),
            )
            .map_err(|_| RuntimeError::ResourceLimit)?;
        prospective
            .authenticate_actual_upload_data(controller, input_emitter, &row, bodies)
            .map_err(|_| RuntimeError::ResourceLimit)?;
        call.complete(&mut scratch, || claim.authenticate_current())?;
        Ok(row)
    }
}
