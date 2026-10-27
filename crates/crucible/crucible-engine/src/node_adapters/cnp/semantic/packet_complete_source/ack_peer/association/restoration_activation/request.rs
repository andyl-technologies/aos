//! Derives the unsigned phase request from genuine same-Window and SDK originals.
//!
//! Construction runs after independent Source credit and under the original
//! native read fence. Its immutable Controller loans end before assignment or
//! publication; no decoded label, historical proof or callback result issues a
//! claim or replaces the actual completed Commit and held continuation.

use super::*;
use crucible_node_transport::reference_packet::service::complete_restore::transfer::PacketCompleteRestoreTransferPhase;

impl PacketCompleteSemanticSource {
    pub(super) fn original_restoration_activation_request_data(
        &self,
        controller: &CnpController,
        inputs: &OriginalInstalledRestorationActivationSigningInputs<'_>,
    ) -> Result<PacketRestorationActivationRequest, RuntimeError> {
        self.storage_origin_with_error::<RuntimeError>()?;
        if !std::ptr::eq(inputs.transfer.source.as_ref(), self)
            || inputs.scope.target != *inputs.transfer.activation
            || inputs.scope.proof != *inputs.scope_proof
        {
            return Err(RuntimeError::ForeignAuthority);
        }
        inputs
            .scope_proof
            .verify(inputs.scope_proof_body)
            .map_err(|_| RuntimeError::InvalidReceipt)?;
        let verified = self.original_verified_restore_transfer_commit_data(
            controller,
            inputs.uploaded,
            inputs.signer,
            &inputs.inspection,
        )?;
        let mut request = None;
        verified.authenticate_held_continuation_data(
            &inputs.transfer,
            inputs.signer,
            inputs.uploaded,
            |held, held_reference| {
                // Core compares the actual original native cursor/inventory and
                // complete four-owner artifact, not a saved success marker.
                inputs.authenticate_original_activation_hold_data(held, held_reference)?;
                let target = controller
                    .original_installed_restoration_activation_target_binding_data()
                    .map_err(|_| RuntimeError::ForeignAuthority)?;
                let installed = self.installation();
                if target.owner_binding != &installed.owner
                    || target.node != &installed.binding.compatibility.node_id
                    || target.owner != &installed.owner.owner.id
                    || target.admission != &installed.admission
                    || target.transaction != &installed.transaction
                    || target.gate != &installed.gate
                    || target.world != &installed.world_binding_hash
                    || target.world != &inputs.scope.target.world_binding_hash
                    || held.native_pid.get() != u64::from(controller.peer_pid())
                {
                    return Err(RuntimeError::ForeignAuthority);
                }
                let captured_owner = inputs.transfer.ticket.owner()?;
                let mapped = inputs
                    .scope
                    .owners
                    .iter()
                    .find(|one| one.source.owner == captured_owner.owner)
                    .ok_or(RuntimeError::ForeignAuthority)?;
                if mapped.target.owner != *target.owner
                    || mapped.target.incarnation != *target.incarnation
                    || mapped.target.generation != installed.binding.authority.owner_generation
                    || !inputs.scope.target.owners.contains(&mapped.target)
                {
                    return Err(RuntimeError::ForeignAuthority);
                }
                let binding_hash = target
                    .owner_binding
                    .identity()
                    .map_err(|_| RuntimeError::InvalidReceipt)?;
                if binding_hash != held.target_owner_binding {
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
                let pair = controller
                    .original_completed_complete_restore_transfer(
                        emitter,
                        PacketCompleteRestoreTransferPhase::Commit,
                    )
                    .map_err(|_| RuntimeError::InvalidReceipt)?;
                // Hash the unique canonical incoming original under its actual
                // immutable bank loan. No response DOM or byte copy is made.
                let history = controller
                    .original_native5_frame_history()
                    .map_err(|_| RuntimeError::InvalidReceipt)?;
                let response = history
                    .original_canonical_reference_data(pair.response())
                    .map_err(|_| RuntimeError::InvalidReceipt)?;
                let scope = PacketRestorationActivationScope {
                    source_birth: canonical::content_ref(&original.banks[0], "application/json")
                        .map_err(|_| RuntimeError::InvalidReceipt)?,
                    source_runtime: inputs.scope.source_record.clone(),
                    scope_proof: inputs.scope_proof.clone(),
                    target: PacketRestorationActivationTarget {
                        native_pid: held.native_pid,
                        session: target.session.clone(),
                        incarnation: target.incarnation.clone(),
                        node: target.node.clone(),
                        owner: target.owner.clone(),
                        owner_generation: mapped.target.generation,
                        binding_hash,
                        world: target.world.clone(),
                        activation: inputs.scope.target.activation_id.clone(),
                        generation: inputs.scope.target.generation,
                        prepared_token: target.prepared_token.clone(),
                        gate: target.gate.clone(),
                        admission: target.admission.clone(),
                        transaction: target.transaction.clone(),
                    },
                    restoration: PacketRestorationActivationOriginals {
                        captured_owner_state: held.captured_owner_state.clone(),
                        captured_control: held.captured_control.clone(),
                        captured_journal: held.captured_journal.clone(),
                        mapping: held.mapping.clone(),
                        commit_request: canonical::content_ref(
                            transfer.bank(PacketCompleteRestoreTransferPhase::Commit, 3)?,
                            "application/json",
                        )
                        .map_err(|_| RuntimeError::InvalidReceipt)?,
                        commit_response: response,
                        context_digest: held.context_digest.clone(),
                    },
                };
                request = Some(PacketRestorationActivationRequest {
                    schema: PACKET_RESTORATION_ACTIVATION_FEATURE.into(),
                    phase: provider_phase(inputs.phase),
                    scope,
                    native_allocation: inputs
                        .activation_data
                        .native_allocation_data(provider_phase(inputs.phase)),
                });
                Ok(())
            },
            || inputs.inspection.authenticate_current(),
        )?;
        request.ok_or(RuntimeError::OwnerUnavailable)
    }
}
