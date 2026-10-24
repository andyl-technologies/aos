//! Signs Commit only after the same keyed Prepare and exact six-role upload.
//!
//! No Query currency is renewed here. The prior SDK pair, Source comparison
//! history, actual uploader and mapping are rechecked before the new assigned
//! operation; the receipt still cannot substitute for final journal verification.

use super::*;
use crucible_node_transport::client::OriginalCompleteRestoreInputUpload;

impl PacketCompleteSemanticSource {
    pub(crate) fn call_original_restore_transfer_commit_into<'a>(
        &'a self,
        controller: &'a mut CnpController,
        uploaded: &OriginalCompleteRestoreInputUpload,
        claim: OriginalRestorationTransactionClaim<'_>,
        admitted: &OriginalSourceRestoreSignerConstructionData,
        completed: &mut Option<ResponseBody>,
    ) -> Result<OriginalSourceRestoreVerifiedPhase<'a>, RuntimeError> {
        self.storage_origin_with_error::<RuntimeError>()?;
        if !matches!(claim.phase(), OriginalRestorationTransactionPhase::Commit)
            || completed.is_some()
        {
            return Err(RuntimeError::OutstandingObligations);
        }
        claim.authenticate_current()?;
        let inputs = claim.original_inputs_data()?;
        self.authenticate_transfer_inputs_data(&inputs)?;
        admitted.authenticate_original_effect_data(self, controller, &inputs)?;
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
        let hello = original
            .hello
            .as_ref()
            .ok_or(RuntimeError::OwnerUnavailable)?;
        let transfer = original
            .restore_transfer_banks
            .as_mut()
            .ok_or(RuntimeError::OwnerUnavailable)?;
        transfer.signer()?.authenticate_inputs_verified()?;
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
        let birth = birth.as_ref().ok_or(RuntimeError::OwnerUnavailable)?;
        let key = birth.original_fresh_query_key_data()?;
        let mut scratch = native.original_fresh_current_scratch()?;
        let call = native.begin_original_fresh_query_call_data(&mut scratch)?;
        transfer.begin_original_commit(inputs.prepare_id, inputs.commit_id)?;
        let maximum = admitted.maximum_frame_bytes_data();
        let prior = controller
            .original_completed_complete_restore_transfer(
                emitter,
                PacketCompleteRestoreTransferPhase::Prepare,
            )
            .map_err(|_| RuntimeError::InvalidReceipt)?;
        receipts::authenticate_prepare_pair(
            transfer,
            prior.original(),
            prior.response(),
            key,
            maximum,
        )?;
        uploaded
            .authenticate_completed_original(controller, input_emitter)
            .map_err(|_| RuntimeError::InvalidReceipt)?;
        let request_digest = complete_restore_transfer_original_digest(prior.original(), maximum)
            .map_err(|_| RuntimeError::InvalidReceipt)?;
        let response_digest = complete_restore_transfer_original_digest(prior.response(), maximum)
            .map_err(|_| RuntimeError::InvalidReceipt)?;
        let receipt: PacketCompleteRestorePrepareReceipt = Deserialize::deserialize(
            transfer
                .signer()?
                .value(PacketCompleteRestoreTransferPhase::Prepare, 4)?,
        )
        .map_err(|_| RuntimeError::InvalidReceipt)?;
        let prepare: PacketCompleteRestorePrepareRequest = Deserialize::deserialize(
            transfer
                .signer()?
                .value(PacketCompleteRestoreTransferPhase::Prepare, 0)?,
        )
        .map_err(|_| RuntimeError::InvalidReceipt)?;
        let request = PacketCompleteRestoreCommitRequest {
            schema: PACKET_COMPLETE_RESTORE_COMMIT_EXTENSION.into(),
            prepare,
            capture_terminal: inputs.capture_terminal.clone(),
            prepare_request_id: inputs.prepare_id.clone(),
            prepare_request_sequence: prior.original().sequence,
            prepare_request_digest: Bytes::new(request_digest.to_vec()),
            prepare_response_sequence: prior.response().sequence,
            prepare_response_digest: Bytes::new(response_digest.to_vec()),
            transfer_token: receipt.transfer_token,
        };
        request
            .validate_data()
            .map_err(|_| RuntimeError::InvalidReceipt)?;
        let baseline = requests::baseline(inputs.prepare_id, &request.prepare.restoration)?;
        // The same Source's once state precedes Commit normalization/assignment.
        transfer.retain_value(
            PacketCompleteRestoreTransferPhase::Commit,
            0,
            serde_json::to_value(&request).map_err(|_| RuntimeError::InvalidReceipt)?,
            MAXIMUM_COMPLETE_RESTORE_TRANSFER_REQUEST_BYTES,
        )?;
        let mapping_value = serde_json::to_value(inputs.mapping.normalization_view())
            .map_err(|_| RuntimeError::InvalidReceipt)?;
        let mapping =
            canonical::canonical_json(&mapping_value).map_err(|_| RuntimeError::InvalidReceipt)?;
        if mapping.len() > admitted.maximum_mapping_bytes_data() {
            return Err(RuntimeError::ResourceLimit);
        }
        let mut prepared = controller
            .prepare_original_complete_restore_commit(
                emitter,
                inputs.commit_id.clone(),
                baseline,
                request,
                inputs.mapping,
            )
            .map_err(|_| RuntimeError::InvalidReceipt)?;
        prepared
            .authenticate_original_emitter(emitter)
            .map_err(|_| RuntimeError::ForeignAuthority)?;
        prepared
            .authenticate_archived_mapping(inputs.mapping)
            .map_err(|_| RuntimeError::ForeignAuthority)?;
        let envelope = prepared
            .original()
            .map_err(|_| RuntimeError::InvalidReceipt)?;
        if envelope.request_id.0.as_ref() != Some(inputs.commit_id)
            || envelope
                .extensions
                .get(PACKET_COMPLETE_RESTORE_COMMIT_EXTENSION)
                != Some(
                    transfer
                        .signer()?
                        .value(PacketCompleteRestoreTransferPhase::Commit, 0)?,
                )
        {
            return Err(RuntimeError::InvalidReceipt);
        }
        let assigned = complete_restore_transfer_assigned_request_digest(
            envelope,
            PacketCompleteRestoreTransferPhase::Commit,
            maximum,
        )
        .map_err(|_| RuntimeError::InvalidReceipt)?;
        let request: PacketCompleteRestoreCommitRequest = Deserialize::deserialize(
            transfer
                .signer()?
                .value(PacketCompleteRestoreTransferPhase::Commit, 0)?,
        )
        .map_err(|_| RuntimeError::InvalidReceipt)?;
        let bindings = request
            .prepare
            .restoration
            .context_bindings(&mapping)
            .map_err(|_| RuntimeError::InvalidReceipt)?;
        let hello = prepared
            .original_canonical_ack_hello_frame_digests(hello)
            .map_err(|_| RuntimeError::ForeignAuthority)?;
        let restoration = PacketCompleteRestoreContext {
            schema: PACKET_COMPLETE_RESTORE_CONTEXT_SCHEMA.into(),
            algorithm: PACKET_COMPLETE_RESTORE_ALGORITHM.into(),
            source_birth: digest(&original.banks[0]),
            kernel_binding: digest(&original.banks[1]),
            policy_binding: digest(&original.banks[2]),
            host_registration: digest(
                birth
                    .original_initial_lifecycle_inputs_data()?
                    .host_registration,
            ),
            native_registration: digest(&original.banks[3]),
            hello_request: Bytes::new(hello.request_frame_digest.to_vec()),
            hello_response: Bytes::new(hello.response_frame_digest.to_vec()),
            assigned_restore: Bytes::new(assigned.to_vec()),
            archive_binding: bindings.archive_binding,
            target_binding: bindings.target_binding,
            mapping_binding: bindings.mapping_binding,
            request_binding: bindings.request_binding,
        };
        let context = PacketCompleteRestoreCommitContext {
            schema: "source-owned.packet-complete-restore-commit-context/12".into(),
            algorithm: PACKET_COMPLETE_RESTORE_ALGORITHM.into(),
            restoration,
            commit_request: digest(transfer.bank(PacketCompleteRestoreTransferPhase::Commit, 0)?),
            prepare_request: request.prepare_request_digest,
            prepare_response: request.prepare_response_digest,
            transfer_token: request.transfer_token,
            input_roster: request
                .prepare
                .input_roster_digest_data()
                .map_err(|_| RuntimeError::InvalidReceipt)?,
        };
        // Decode the independently retained original rather than deriving a
        // new Prepare at Commit or rerunning the consumed Query frontier.
        let request: PacketCompleteRestoreCommitRequest = Deserialize::deserialize(
            transfer
                .signer()?
                .value(PacketCompleteRestoreTransferPhase::Commit, 0)?,
        )
        .map_err(|_| RuntimeError::InvalidReceipt)?;
        context
            .authenticate_request_data(&request, &mapping)
            .map_err(|_| RuntimeError::InvalidReceipt)?;
        transfer.retain_value(
            PacketCompleteRestoreTransferPhase::Commit,
            1,
            serde_json::to_value(&context).map_err(|_| RuntimeError::InvalidReceipt)?,
            MAXIMUM_COMPLETE_RESTORE_TRANSFER_CONTEXT_BYTES,
        )?;
        let proof = complete_restore_commit_proof_data(key, &context)
            .map_err(|_| RuntimeError::InvalidReceipt)?;
        transfer.retain_value(
            PacketCompleteRestoreTransferPhase::Commit,
            2,
            serde_json::to_value(&proof).map_err(|_| RuntimeError::InvalidReceipt)?,
            MAXIMUM_COMPLETE_RESTORE_TRANSFER_PROOF_BYTES,
        )?;
        native.ensure_original_fresh_current(&mut scratch)?;
        claim.authenticate_current()?;
        prepared
            .seal(emitter, proof)
            .map_err(|_| RuntimeError::InvalidReceipt)?;
        transfer
            .signer_mut()?
            .mark_sealed(PacketCompleteRestoreTransferPhase::Commit)?;
        transfer.retain_value(
            PacketCompleteRestoreTransferPhase::Commit,
            3,
            serde_json::to_value(
                prepared
                    .original()
                    .map_err(|_| RuntimeError::InvalidReceipt)?,
            )
            .map_err(|_| RuntimeError::InvalidReceipt)?,
            maximum,
        )?;
        transfer
            .signer_mut()?
            .mark_publishing(PacketCompleteRestoreTransferPhase::Commit)?;
        prepared
            .publish_selected_into(emitter, completed)
            .map_err(|_| RuntimeError::InvalidReceipt)?;
        drop(prepared);
        let pair = controller
            .original_completed_complete_restore_transfer(
                emitter,
                PacketCompleteRestoreTransferPhase::Commit,
            )
            .map_err(|_| RuntimeError::InvalidReceipt)?;
        transfer.retain_value(
            PacketCompleteRestoreTransferPhase::Commit,
            4,
            pair.response()
                .extensions
                .get(PACKET_COMPLETE_RESTORE_COMMIT_RECEIPT_EXTENSION)
                .ok_or(RuntimeError::InvalidReceipt)?
                .clone(),
            MAXIMUM_COMPLETE_RESTORE_TRANSFER_RECEIPT_BYTES,
        )?;
        receipts::authenticate_commit_pair(
            transfer,
            pair.original(),
            pair.response(),
            inputs.capture_terminal,
            &mapping,
            key,
            maximum,
        )?;
        self.authenticate_transfer_inputs_data(&inputs)?;
        call.complete(&mut scratch, || claim.authenticate_current())?;
        transfer
            .signer_mut()?
            .finish_verified(PacketCompleteRestoreTransferPhase::Commit)?;
        Ok(OriginalSourceRestoreVerifiedPhase::new(
            self,
            controller,
            SourceVerifiedPhase::Commit,
        ))
    }
}
