//! Keeps Source currentness and keyed Prepare custody through actual six-input IO.
//!
//! The claim lends bodies from the same retained archive and target-owned mapping
//! normalization. Neither a caller byte array nor SDK completion alone can mark
//! this Source phase verified; all partial SDK owners remain in the given slot.

use super::*;
use crucible_node_transport::client::{
    OriginalCompleteRestoreInputUpload, OriginalCompleteRestoreInputUploadStorageData,
};

impl PacketCompleteSemanticSource {
    pub(crate) fn call_original_restore_transfer_inputs_into<'a>(
        &'a self,
        controller: &'a mut CnpController,
        quote: &OriginalCompleteRestoreInputUploadStorageData,
        claim: OriginalRestorationTransactionClaim<'_>,
        admitted: &OriginalSourceRestoreSignerConstructionData,
        output: &mut Option<OriginalCompleteRestoreInputUpload>,
    ) -> Result<OriginalSourceRestoreVerifiedPhase<'a>, RuntimeError> {
        self.storage_origin_with_error::<RuntimeError>()?;
        if !matches!(claim.phase(), OriginalRestorationTransactionPhase::Inputs) || output.is_some()
        {
            return Err(RuntimeError::OutstandingObligations);
        }
        claim.authenticate_current()?;
        let inputs = claim.original_inputs_data()?;
        self.authenticate_transfer_inputs_data(&inputs)?;
        admitted.authenticate_original_effect_data(self, controller, &inputs)?;
        let bodies = claim.original_input_bodies_data()?;
        let mut association = self
            .ack_peer_association
            .try_borrow_mut()
            .map_err(|_| RuntimeError::OwnerBusy)?;
        let original = association.as_mut().ok_or(RuntimeError::OwnerUnavailable)?;
        original.authenticate_transfer_ready_data()?;
        let emitter = original
            .emitter
            .as_ref()
            .ok_or(RuntimeError::OwnerUnavailable)?;
        let input_emitter = original
            .restore_input_emitter
            .as_ref()
            .ok_or(RuntimeError::OwnerUnavailable)?;
        let native = original
            .native
            .as_ref()
            .ok_or(RuntimeError::OwnerUnavailable)?;
        let transfer = original
            .restore_transfer_banks
            .as_mut()
            .ok_or(RuntimeError::OwnerUnavailable)?;
        transfer
            .signer()?
            .authenticate_ids(inputs.prepare_id, inputs.commit_id)?;
        emitter
            .authenticate_original(controller)
            .map_err(|_| RuntimeError::ForeignAuthority)?;
        input_emitter
            .authenticate_original(controller)
            .map_err(|_| RuntimeError::ForeignAuthority)?;
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
        transfer.signer_mut()?.begin_inputs()?;
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
        // The actual quote authenticates the same six references/byte bodies and
        // original frontier again before it stores its owner or transmits.
        controller
            .publish_original_complete_restore_inputs_into(input_emitter, quote, bodies, output)
            .map_err(|_| RuntimeError::InvalidReceipt)?;
        output
            .as_ref()
            .ok_or(RuntimeError::OwnerUnavailable)?
            .authenticate_completed_original(controller, input_emitter)
            .map_err(|_| RuntimeError::InvalidReceipt)?;
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
        self.authenticate_transfer_inputs_data(&inputs)?;
        call.complete(&mut scratch, || claim.authenticate_current())?;
        transfer.signer_mut()?.finish_inputs()?;
        Ok(OriginalSourceRestoreVerifiedPhase::new(
            self,
            controller,
            SourceVerifiedPhase::Inputs,
        ))
    }
}
