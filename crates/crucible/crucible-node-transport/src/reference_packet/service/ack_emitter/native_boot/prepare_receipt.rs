//! Signs only the same assigned native response after owning input reservation.

use super::*;
use crate::bodies::PrepareRestoreResult;
use crucible_node_format::Validate;

impl VerifiedCompleteRestorePrepare {
    pub(crate) fn prepare_receipt_data<S: ProviderStream>(
        &self,
        connection: &Connection<S>,
        response: &Envelope,
    ) -> Result<PacketCompleteRestorePrepareReceipt, ProviderError> {
        self.authenticate_installation(connection)?;
        let custody = connection.acknowledge_original_complete_restore_input_custody()?;
        let mut flight = self.attempt.try_borrow_mut().map_err(|_| borrowed())?;
        flight.ensure_origin()?;
        if flight.receipt_started
            || flight
                .custody
                .as_ref()
                .is_none_or(|original| !Rc::ptr_eq(original, &custody))
        {
            return Err(refused());
        }
        // A failed check or unwinding signer cannot renew this exact response.
        // The SDK already owns the complete assigned Envelope and its empty
        // literal slot before entering this private issuer.
        flight.receipt_started = true;
        connection.authenticate_original_assigned_restore_response(
            flight.original.as_ref().ok_or_else(refused)?,
            response,
            PacketCompleteRestoreTransferPhase::Prepare,
        )?;
        if !response.extensions.is_empty()
            || response.body.len() != 4
            || response
                .body
                .get("status")
                .and_then(serde_json::Value::as_str)
                != Some("completed")
            || response
                .body
                .get("operation_state")
                .and_then(serde_json::Value::as_str)
                != Some("completed")
            || response
                .body
                .get("extensions")
                .and_then(serde_json::Value::as_object)
                .is_none_or(|extensions| !extensions.is_empty())
        {
            return Err(refused());
        }
        flight.receipt_result = Some(
            PrepareRestoreResult::deserialize(response.body.get("result").ok_or_else(refused)?)
                .map_err(ContractError::from)?,
        );
        let request = flight.request.as_ref().ok_or_else(refused)?;
        let result = flight.receipt_result.as_ref().ok_or_else(refused)?;
        result.validate()?;
        let target = &request.restoration;
        if result.transaction_id != request.transaction_id
            || result.world_binding_hash != target.target_world
            || result.owner_binding_hash != target.target_owner_binding
            || result.staged_owner_ids.len() != 1
            || result.staged_owner_ids.first() != Some(&target.target_owner)
            || result.validated_manifest != target.capture_manifest
        {
            return Err(refused());
        }
        connection.authenticate_original_native_realize_receipt_data(
            flight.realize.as_ref().ok_or_else(refused)?,
            result,
        )?;
        let maximum =
            usize::try_from(self.authority.limits().frame_bytes.get()).map_err(|_| refused())?;
        let assigned = if self.policy.fresh_restore_allocation_selection()
            == Some(PacketNative5FreshRestoreAllocationSelection::CompletedAdmit13)
            && flight
                .original
                .as_ref()
                .ok_or_else(refused)?
                .extensions
                .contains_key(PACKET_FRESH_RESTORE_ALLOCATION_PREPARE_BINDING)
        {
            complete_restore_fresh_prepare_assigned_response_digest(
                flight.original.as_ref().ok_or_else(refused)?,
                response,
                maximum,
            )?
        } else {
            complete_restore_transfer_assigned_response_digest(
                flight.original.as_ref().ok_or_else(refused)?,
                response,
                PacketCompleteRestoreTransferPhase::Prepare,
                maximum,
            )?
        };
        let boot = self.boot.try_borrow().map_err(|_| borrowed())?;
        boot.ensure_origin()?;
        let key: &[u8; 32] = boot
            .data
            .private_key
            .as_slice()
            .try_into()
            .map_err(|_| refused())?;
        let receipt = complete_restore_prepare_receipt_data(
            key,
            request,
            flight.context.as_ref().ok_or_else(refused)?,
            response.sequence,
            &assigned,
        )?;
        if receipt.transfer_token.as_slice()
            != flight
                .transfer_token
                .as_ref()
                .ok_or_else(refused)?
                .as_slice()
        {
            return Err(refused());
        }
        let value = serde_json::to_value(&receipt).map_err(ContractError::from)?;
        let extent = crate::connection::serialized_credit(
            &value,
            MAXIMUM_COMPLETE_RESTORE_TRANSFER_RECEIPT_BYTES,
        )?;
        if !flight.receipt_body.is_empty() || extent > flight.receipt_body.capacity() {
            return Err(refused());
        }
        canonical::canonical_json_to_writer(&value, &mut flight.receipt_body)?;
        if flight.receipt_body.len() != extent {
            return Err(refused());
        }
        boot.ensure_origin()?;
        self.authority.ensure_live()?;
        Ok(receipt)
    }
}
