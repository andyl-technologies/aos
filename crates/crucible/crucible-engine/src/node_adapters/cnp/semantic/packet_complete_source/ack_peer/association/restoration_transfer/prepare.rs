//! Constructs, signs and checks one actual selected Prepare under its claim.
//!
//! The Source comparison owner is installed before allocation. SDK assignment
//! retains its own original and literal slot before sealing, and publication
//! retains the raw response before decoding. An error cannot reset either slot.

use super::*;
use crucible_node_transport::client::OriginalFreshRestorePrepareInputs;
use crucible_node_transport::reference_packet::service::fresh_restore_allocation::verify_fresh_restore_allocation_proof_data;

impl PacketCompleteSemanticSource {
    pub(crate) fn call_original_restore_transfer_prepare_into<'a>(
        &'a self,
        controller: &'a mut CnpController,
        query: &OriginalFreshRestoreQuery,
        binding_quote: &OriginalFreshRestorePrepareBindingStorageData,
        claim: OriginalRestorationTransactionClaim<'_>,
        admitted: &OriginalSourceRestoreSignerConstructionData,
        completed: &mut Option<ResponseBody>,
    ) -> Result<OriginalSourceRestoreVerifiedPhase<'a>, RuntimeError> {
        self.storage_origin_with_error::<RuntimeError>()?;
        if !matches!(claim.phase(), OriginalRestorationTransactionPhase::Prepare)
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
        emitter
            .authenticate_original(controller)
            .map_err(|_| RuntimeError::ForeignAuthority)?;
        original
            .restore_input_emitter
            .as_ref()
            .ok_or(RuntimeError::OwnerUnavailable)?
            .authenticate_original(controller)
            .map_err(|_| RuntimeError::ForeignAuthority)?;
        claim.authenticate_original_prepare_query_data(controller, emitter, query)?;
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

        // Both the Source once flag and the real native read fence precede
        // request construction, index serialization and SDK assignment.
        let mut scratch = native.original_fresh_current_scratch()?;
        let call = native.begin_original_fresh_query_call_data(&mut scratch)?;
        transfer.begin_original_prepare(nonce, inputs.prepare_id, inputs.commit_id)?;
        query
            .authenticate_original_source_context_data(
                controller,
                emitter,
                &self.installation().owner,
            )
            .map_err(|_| RuntimeError::InvalidReceipt)?;
        let report = query.report_data().ok_or(RuntimeError::InvalidReceipt)?;
        verify_fresh_restore_allocation_proof_data(key, &report.data, &report.proof)
            .map_err(|_| RuntimeError::InvalidReceipt)?;
        let mapping_value = serde_json::to_value(inputs.mapping.normalization_view())
            .map_err(|_| RuntimeError::InvalidReceipt)?;
        let mapping =
            canonical::canonical_json(&mapping_value).map_err(|_| RuntimeError::InvalidReceipt)?;
        if mapping.len() > admitted.maximum_mapping_bytes_data() {
            return Err(RuntimeError::ResourceLimit);
        }
        let mapping_reference = canonical::content_ref(&mapping, "application/json")
            .map_err(|_| RuntimeError::InvalidReceipt)?;
        let request = self.derive_transfer_prepare_request(
            &inputs,
            &report.data.scope.owner_binding,
            mapping_reference,
            &nonce,
            transfer.signer()?.generation(),
        )?;
        request
            .validate_data()
            .map_err(|_| RuntimeError::InvalidReceipt)?;
        let baseline = requests::baseline(inputs.prepare_id, &request.restoration)?;
        transfer.retain_value(
            PacketCompleteRestoreTransferPhase::Prepare,
            0,
            serde_json::to_value(&request).map_err(|_| RuntimeError::InvalidReceipt)?,
            MAXIMUM_COMPLETE_RESTORE_TRANSFER_REQUEST_BYTES,
        )?;
        let mut prepared = controller
            .prepare_original_complete_restore_prepare_with_fresh_query(
                emitter,
                query,
                binding_quote,
                OriginalFreshRestorePrepareInputs {
                    request_id: inputs.prepare_id.clone(),
                    baseline,
                    request,
                },
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
        if envelope
            .extensions
            .get(PACKET_COMPLETE_RESTORE_PREPARE_EXTENSION)
            != Some(
                transfer
                    .signer()?
                    .value(PacketCompleteRestoreTransferPhase::Prepare, 0)?,
            )
            || envelope.request_id.0.as_ref() != Some(inputs.prepare_id)
        {
            return Err(RuntimeError::InvalidReceipt);
        }
        let maximum = admitted.maximum_frame_bytes_data();
        let assigned = complete_restore_fresh_prepare_assigned_request_digest(envelope, maximum)
            .map_err(|_| RuntimeError::InvalidReceipt)?;
        let request: PacketCompleteRestorePrepareRequest = Deserialize::deserialize(
            transfer
                .signer()?
                .value(PacketCompleteRestoreTransferPhase::Prepare, 0)?,
        )
        .map_err(|_| RuntimeError::InvalidReceipt)?;
        let hello_digests = prepared
            .original_canonical_ack_hello_frame_digests(hello)
            .map_err(|_| RuntimeError::ForeignAuthority)?;
        let context = PacketCompleteRestorePrepareContext {
            schema: "source-owned.packet-complete-restore-prepare-context/12".into(),
            algorithm: PACKET_COMPLETE_RESTORE_ALGORITHM.into(),
            source_birth: digest(&original.banks[0]),
            kernel_binding: digest(&original.banks[1]),
            policy_binding: digest(&original.banks[2]),
            host_registration: digest(
                birth
                    .as_ref()
                    .ok_or(RuntimeError::OwnerUnavailable)?
                    .original_initial_lifecycle_inputs_data()?
                    .host_registration,
            ),
            native_registration: digest(&original.banks[3]),
            hello_request: Bytes::new(hello_digests.request_frame_digest.to_vec()),
            hello_response: Bytes::new(hello_digests.response_frame_digest.to_vec()),
            assigned_prepare: Bytes::new(assigned.to_vec()),
            prepare_request: digest(transfer.bank(PacketCompleteRestoreTransferPhase::Prepare, 0)?),
            input_roster: request
                .input_roster_digest_data()
                .map_err(|_| RuntimeError::InvalidReceipt)?,
        };
        context
            .authenticate_request_data(&request)
            .map_err(|_| RuntimeError::InvalidReceipt)?;
        transfer.retain_value(
            PacketCompleteRestoreTransferPhase::Prepare,
            1,
            serde_json::to_value(&context).map_err(|_| RuntimeError::InvalidReceipt)?,
            MAXIMUM_COMPLETE_RESTORE_TRANSFER_CONTEXT_BYTES,
        )?;
        let proof = complete_restore_prepare_proof_data(key, &context)
            .map_err(|_| RuntimeError::InvalidReceipt)?;
        transfer.retain_value(
            PacketCompleteRestoreTransferPhase::Prepare,
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
            .mark_sealed(PacketCompleteRestoreTransferPhase::Prepare)?;
        transfer.retain_value(
            PacketCompleteRestoreTransferPhase::Prepare,
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
            .mark_publishing(PacketCompleteRestoreTransferPhase::Prepare)?;
        prepared
            .publish_selected_into(emitter, completed)
            .map_err(|_| RuntimeError::InvalidReceipt)?;
        // Release the temporary mutable SDK loan before borrowing its actual
        // independently retained completed request and response.
        drop(prepared);
        let pair = controller
            .original_completed_complete_restore_transfer(
                emitter,
                PacketCompleteRestoreTransferPhase::Prepare,
            )
            .map_err(|_| RuntimeError::InvalidReceipt)?;
        transfer.retain_value(
            PacketCompleteRestoreTransferPhase::Prepare,
            4,
            pair.response()
                .extensions
                .get(PACKET_COMPLETE_RESTORE_PREPARE_RECEIPT_EXTENSION)
                .ok_or(RuntimeError::InvalidReceipt)?
                .clone(),
            MAXIMUM_COMPLETE_RESTORE_TRANSFER_RECEIPT_BYTES,
        )?;
        receipts::authenticate_prepare_pair(
            transfer,
            pair.original(),
            pair.response(),
            key,
            maximum,
        )?;
        self.authenticate_transfer_inputs_data(&inputs)?;
        call.complete(&mut scratch, || claim.authenticate_current())?;
        transfer
            .signer_mut()?
            .finish_verified(PacketCompleteRestoreTransferPhase::Prepare)?;
        Ok(OriginalSourceRestoreVerifiedPhase::new(
            self,
            controller,
            SourceVerifiedPhase::Prepare,
        ))
    }
}

impl OriginalAckPeerAssociation {
    pub(in super::super) fn authenticate_transfer_ready_data(&self) -> Result<(), RuntimeError> {
        if !self.ready
            || self.failed
            || !self.completed_mechanism.get()
            || self.native.is_none()
            || self.emitter.is_none()
            || self.restore_input_emitter.is_none()
            || self.hello.is_none()
            || self.restore_transfer_banks.is_none()
        {
            return Err(RuntimeError::OwnerUnavailable);
        }
        self.restore
            .as_ref()
            .ok_or(RuntimeError::OwnerUnavailable)?
            .authenticate_unpopulated_capture_metadata_with_error::<RuntimeError>()
    }
}
