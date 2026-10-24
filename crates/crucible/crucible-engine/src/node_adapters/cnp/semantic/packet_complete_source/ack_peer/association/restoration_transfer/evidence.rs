//! Lends actual verified Source phase custody without a final-context conversion.
//!
//! The only constructor is called after the integrated signer/upload path has
//! verified its real SDK originals and keyed receipts under the same native read
//! fence. Reauthentication reads that history and never renews Query or a claim.

use super::*;
use crucible_node_transport::client::OriginalCompleteRestoreInputUpload;
use serde_json::Value;

#[derive(Clone, Copy, PartialEq, Eq)]
pub(crate) enum SourceVerifiedPhase {
    Prepare,
    Inputs,
    Commit,
}

#[must_use = "the real installed target advances only after authenticating this loan"]
pub(crate) struct OriginalSourceRestoreVerifiedPhase<'a> {
    source: &'a PacketCompleteSemanticSource,
    controller: &'a CnpController,
    phase: SourceVerifiedPhase,
}

impl<'a> OriginalSourceRestoreVerifiedPhase<'a> {
    pub(super) fn new(
        source: &'a PacketCompleteSemanticSource,
        controller: &'a CnpController,
        phase: SourceVerifiedPhase,
    ) -> Self {
        Self {
            source,
            controller,
            phase,
        }
    }

    pub(crate) fn phase_data(&self) -> SourceVerifiedPhase {
        self.phase
    }

    pub(crate) fn authenticate_current(
        &self,
        inputs: &OriginalRestorationSigningInputs<'_>,
        admitted: &OriginalSourceRestoreSignerConstructionData,
        uploaded: Option<&OriginalCompleteRestoreInputUpload>,
        final_currency: impl FnOnce() -> Result<(), RuntimeError>,
    ) -> Result<SourceVerifiedPhase, RuntimeError> {
        self.source.authenticate_verified_transfer_phase_data(
            self.controller,
            inputs,
            admitted,
            uploaded,
            self.phase,
            final_currency,
        )?;
        Ok(self.phase)
    }
}

impl PacketCompleteSemanticSource {
    fn authenticate_verified_transfer_phase_data(
        &self,
        controller: &CnpController,
        inputs: &OriginalRestorationSigningInputs<'_>,
        admitted: &OriginalSourceRestoreSignerConstructionData,
        uploaded: Option<&OriginalCompleteRestoreInputUpload>,
        phase: SourceVerifiedPhase,
        final_currency: impl FnOnce() -> Result<(), RuntimeError>,
    ) -> Result<(), RuntimeError> {
        self.storage_origin_with_error::<RuntimeError>()?;
        self.authenticate_transfer_inputs_data(inputs)?;
        admitted.authenticate_original_effect_data(self, controller, inputs)?;
        let association = self
            .ack_peer_association
            .try_borrow()
            .map_err(|_| RuntimeError::OwnerBusy)?;
        let original = association.as_ref().ok_or(RuntimeError::OwnerUnavailable)?;
        original.authenticate_transfer_ready_data()?;
        let transfer = original
            .restore_transfer_banks
            .as_ref()
            .ok_or(RuntimeError::OwnerUnavailable)?;
        transfer
            .signer()?
            .authenticate_ids(inputs.prepare_id, inputs.commit_id)?;
        transfer.signer()?.authenticate_verified(phase)?;
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
        controller
            .authenticate_archived_protocol_transfer_mapping(inputs.mapping)
            .map_err(|_| RuntimeError::ForeignAuthority)?;
        let prepare = controller
            .original_completed_complete_restore_transfer(
                emitter,
                PacketCompleteRestoreTransferPhase::Prepare,
            )
            .map_err(|_| RuntimeError::InvalidReceipt)?;
        receipts::authenticate_prepare_pair(
            transfer,
            prepare.original(),
            prepare.response(),
            key,
            admitted.maximum_frame_bytes_data(),
        )?;
        match phase {
            SourceVerifiedPhase::Prepare => {}
            SourceVerifiedPhase::Inputs => uploaded
                .ok_or(RuntimeError::OwnerUnavailable)?
                .authenticate_completed_original(controller, input_emitter)
                .map_err(|_| RuntimeError::InvalidReceipt)?,
            SourceVerifiedPhase::Commit => {
                uploaded
                    .ok_or(RuntimeError::OwnerUnavailable)?
                    .authenticate_completed_original_after_commit(controller, input_emitter)
                    .map_err(|_| RuntimeError::InvalidReceipt)?;
                let mapping_value = serde_json::to_value(inputs.mapping.normalization_view())
                    .map_err(|_| RuntimeError::InvalidReceipt)?;
                let mapping = canonical::canonical_json(&mapping_value)
                    .map_err(|_| RuntimeError::InvalidReceipt)?;
                if mapping.len() > admitted.maximum_mapping_bytes_data() {
                    return Err(RuntimeError::ResourceLimit);
                }
                let commit = controller
                    .original_completed_complete_restore_transfer(
                        emitter,
                        PacketCompleteRestoreTransferPhase::Commit,
                    )
                    .map_err(|_| RuntimeError::InvalidReceipt)?;
                receipts::authenticate_commit_pair(
                    transfer,
                    commit.original(),
                    commit.response(),
                    inputs.capture_terminal,
                    &mapping,
                    key,
                    admitted.maximum_frame_bytes_data(),
                )?;
            }
        }
        call.complete(&mut scratch, || {
            self.authenticate_transfer_inputs_data(inputs)?;
            final_currency()
        })
    }

    pub(crate) fn original_verified_restore_transfer_commit_data<'a>(
        &'a self,
        controller: &'a CnpController,
        uploaded: &OriginalCompleteRestoreInputUpload,
        admitted: &OriginalSourceRestoreSignerConstructionData,
        inspection: &OriginalRestorationTransactionInspection<'_>,
    ) -> Result<OriginalSourceRestoreVerifiedPhase<'a>, RuntimeError> {
        self.storage_origin_with_error::<RuntimeError>()?;
        inspection.authenticate_current()?;
        let inputs = inspection.original_inputs_data()?;
        self.authenticate_verified_transfer_phase_data(
            controller,
            &inputs,
            admitted,
            Some(uploaded),
            SourceVerifiedPhase::Commit,
            || inspection.authenticate_current(),
        )?;
        // The inspector callback was inside the SourceRead completion; actual
        // kernel/registrar/executable checks ran again after that callback.
        Ok(OriginalSourceRestoreVerifiedPhase::new(
            self,
            controller,
            SourceVerifiedPhase::Commit,
        ))
    }
}

impl OriginalSourceRestoreVerifiedPhase<'_> {
    pub(crate) fn authenticate_held_continuation_data(
        &self,
        inputs: &OriginalRestorationSigningInputs<'_>,
        admitted: &OriginalSourceRestoreSignerConstructionData,
        uploaded: &OriginalCompleteRestoreInputUpload,
        validate_held: impl FnOnce(
            &crucible_node_transport::reference_packet::service::complete_restore::PacketNativeRestoredCommitHold,
            &ContentRef,
        ) -> Result<(), RuntimeError>,
        final_currency: impl FnOnce() -> Result<(), RuntimeError>,
    ) -> Result<(), RuntimeError> {
        self.source.storage_origin_with_error::<RuntimeError>()?;
        if self.phase != SourceVerifiedPhase::Commit {
            return Err(RuntimeError::UnsupportedFacet);
        }

        self.source.authenticate_verified_transfer_phase_data(
            self.controller,
            inputs,
            admitted,
            Some(uploaded),
            SourceVerifiedPhase::Commit,
            || {
                // These are compatible immutable loans beneath the already
                // armed SourceRead. No Query is renewed and no effect claim is
                // reconstructed from the historical Commit or its receipt.
                let association = self.source
                    .ack_peer_association
                    .try_borrow()
                    .map_err(|_| RuntimeError::OwnerBusy)?;
                let original = association
                    .as_ref()
                    .ok_or(RuntimeError::OwnerUnavailable)?;
                let emitter = original.emitter
                    .as_ref()
                    .ok_or(RuntimeError::OwnerUnavailable)?;
                let transfer = original.restore_transfer_banks
                    .as_ref()
                    .ok_or(RuntimeError::OwnerUnavailable)?;
                transfer.signer()?
                    .authenticate_verified(SourceVerifiedPhase::Commit)?;

                let pair = self.controller.original_completed_complete_restore_transfer(
                    emitter,
                    PacketCompleteRestoreTransferPhase::Commit
                )
                    .map_err(|_| RuntimeError::InvalidReceipt)?;
                let reference: ContentRef = Deserialize::deserialize(
                    pair.response()
                        .body
                        .get("result")
                        .and_then(Value::as_object)
                        .and_then(|result| result.get("closed_gate_receipt"))
                        .ok_or(RuntimeError::InvalidReceipt)?
                )
                    .map_err(|_| RuntimeError::InvalidReceipt)?;
                let bytes = self.controller.content(&reference)
                    .map_err(|_| RuntimeError::InvalidReceipt)?;
                let maximum =
                    crucible_node_transport::reference_packet::service::complete_restore::
                        maximum_complete_restore_held_evidence_bytes()
                    .map_err(|_| RuntimeError::ResourceLimit)?;
                if bytes.len() > maximum {
                    return Err(RuntimeError::ResourceLimit);
                }

                let value = canonical::parse_json(bytes, maximum)
                    .map_err(|_| RuntimeError::InvalidReceipt)?;
                let encoded = canonical::canonical_json(&value)
                    .map_err(|_| RuntimeError::InvalidReceipt)?;
                if encoded.as_slice() != bytes {
                    return Err(RuntimeError::InvalidReceipt);
                }
                drop(encoded);

                let held: crucible_node_transport::reference_packet::service::complete_restore::PacketNativeRestoredCommitHold =
                    serde_json::from_value(value)
                    .map_err(|_| RuntimeError::InvalidReceipt)?;
                held.validate_data()
                    .map_err(|_| RuntimeError::InvalidReceipt)?;
                let prepare: PacketCompleteRestorePrepareRequest = Deserialize::deserialize(
                    transfer.signer()?.value(PacketCompleteRestoreTransferPhase::Prepare, 0)?
                )
                    .map_err(|_| RuntimeError::InvalidReceipt)?;
                let expected = &prepare.restoration;
                let owner = inputs.ticket.owner()?;

                if held.native_pid.get() != u64::from(self.controller.peer_pid())
                    || held.target_world != inputs.activation.world_binding_hash
                    || held.target_owner != owner.owner
                    || held.target_owner_binding != expected.target_owner_binding
                    || held.target_activation != inputs.activation.activation_id
                    || held.target_generation != inputs.activation.generation
                    || held.captured_owner_state != owner.state
                    || held.captured_control != inputs.journal.native_control
                    || held.captured_journal != *inputs.journal_reference
                    || held.mapping != expected.mapping
                    || held.context_digest.as_slice() != blake3::hash(
                        transfer.bank(PacketCompleteRestoreTransferPhase::Commit, 1)?
                    ).as_bytes()
                {
                    return Err(RuntimeError::InvalidReceipt);
                }
                held.restore_commit.verify(
                    transfer.bank(PacketCompleteRestoreTransferPhase::Commit, 3)?
                )
                    .map_err(|_| RuntimeError::InvalidReceipt)?;

                // The concrete Core validator compares cursor/inventory and
                // complete operation/input/ACK histories with the same four
                // retained cold owners. This Source loan cannot issue context.
                validate_held(&held, &reference)?;
                final_currency()
            }
        )
    }
}
