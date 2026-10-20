//! Prepares the same sealed cold mapping beneath the original Source read fence.
//!
//! The genuine Prepare claim consumes a separate one-shot mapping step before
//! allocation. Both Source and target retain spent/partial custody on refusal;
//! no legacy restore bank, final context or portable permission is created.

use super::*;
use crucible_node_transport::protocol_snapshot::PreparedArchivedProtocolMapping;

impl PacketCompleteSemanticSource {
    pub(crate) fn prepare_original_restore_transfer_mapping_into(
        &self,
        controller: &mut CnpController,
        claim: &OriginalRestorationTransactionClaim<'_>,
        admitted: &OriginalSourceRestoreSignerConstructionData,
        output: &mut Option<PreparedArchivedProtocolMapping>,
    ) -> Result<(), RuntimeError> {
        self.storage_origin_with_error::<RuntimeError>()?;
        if output.is_some()
            || !matches!(claim.phase(), OriginalRestorationTransactionPhase::Prepare)
        {
            return Err(RuntimeError::OutstandingObligations);
        }
        claim.begin_original_mapping_data()?;
        let inputs = claim.original_mapping_inputs_data()?;
        self.authenticate_transfer_selection_data()?;
        admitted.authenticate_original_mapping_data(self, controller, &inputs)?;
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
        emitter
            .authenticate_original(controller)
            .map_err(|_| RuntimeError::ForeignAuthority)?;
        original
            .restore_input_emitter
            .as_ref()
            .ok_or(RuntimeError::OwnerUnavailable)?
            .authenticate_original(controller)
            .map_err(|_| RuntimeError::ForeignAuthority)?;
        let native = original
            .native
            .as_ref()
            .ok_or(RuntimeError::OwnerUnavailable)?;
        let transfer = original
            .restore_transfer_banks
            .as_mut()
            .ok_or(RuntimeError::OwnerUnavailable)?;
        if transfer.mapping_attempted || transfer.mapping_complete || transfer.signer.is_some() {
            return Err(RuntimeError::DuplicateOperation);
        }
        let birth = self
            .ack_peer_birth
            .try_borrow()
            .map_err(|_| RuntimeError::OwnerBusy)?;
        let key = birth
            .as_ref()
            .ok_or(RuntimeError::OwnerUnavailable)?
            .original_fresh_query_key_data()?;
        let nonce =
            blake3::derive_key("source-owned.packet-complete-restore-mapping-nonce/12", key);
        let mut scratch = native.original_fresh_current_scratch()?;
        let call = native.begin_original_fresh_query_call_data(&mut scratch)?;
        transfer.mapping_attempted = true;
        controller
            .prepare_original_selected_archived_mapping_into(
                inputs.host,
                &inputs.native,
                inputs.host_reference,
                inputs.native_reference,
                nonce,
                output,
            )
            .map_err(|_| RuntimeError::InvalidReceipt)?;
        controller
            .authenticate_archived_protocol_transfer_mapping(
                output.as_ref().ok_or(RuntimeError::OwnerUnavailable)?,
            )
            .map_err(|_| RuntimeError::InvalidReceipt)?;
        call.complete(&mut scratch, || claim.authenticate_current())?;
        transfer.mapping_complete = true;
        Ok(())
    }
}
