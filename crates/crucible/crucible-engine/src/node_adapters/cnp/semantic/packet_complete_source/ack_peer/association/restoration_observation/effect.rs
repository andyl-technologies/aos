//! Keeps one real observation claim and owning Source read across publication.

use super::super::restoration_activation;
use super::*;
use crucible_node_transport::reference_packet::service::complete_restore::activation::{
    PacketRestorationActivationArtifact, PacketRestorationActivationPhase,
    authenticate_restoration_activation_held_correspondence_data,
    restoration_activation_scope_digest_data,
};

impl PacketCompleteSemanticSource {
    /// Spends the actual once claim before assigning and signing its Observe.
    ///
    /// No caller supplies a body, scope, quota or digest. SDK/caller terminals
    /// and Source partials stay retained on every error. The returned evidence
    /// keeps the owned Core claim until the real node fence consumes its ledger.
    ///
    /// # Errors
    /// Refuses foreign/stale claims, changed World/Commit originals, exhausted
    /// independent credit, malformed current evidence or a failed final fence.
    pub(crate) fn call_original_installed_restoration_observation_into<'a>(
        &'a self,
        controller: &'a mut CnpController,
        claim: OriginalInstalledRestorationObservationClaim,
        admitted: &OriginalSourceRestorationObservationConstructionData,
        completed: &mut Option<ResponseBody>,
    ) -> Result<OriginalSourceRestorationObservationVerifiedPhase<'a>, RuntimeError> {
        self.storage_origin_with_error::<RuntimeError>()?;
        claim.authenticate_current(self)?;
        admitted.authenticate_original(self, controller)?;
        if completed.is_some() {
            return Err(RuntimeError::OutstandingObligations);
        }
        let mut prepared = None;
        claim.with_original_observation_signing_inputs_data(self, |inputs| {
            admitted.authenticate_same_construction_data(inputs.source_construction)?;
            // Both immutable Controller loans and the old Source read end
            // before this method takes its exclusive assignment/send loan.
            let old = self.original_verified_restoration_activation_data(
                controller,
                inputs.activation,
                &admitted.activation,
            )?;
            drop(old);
            let association = self
                .ack_peer_association
                .try_borrow()
                .map_err(|_| RuntimeError::OwnerBusy)?;
            let original = association.as_ref().ok_or(RuntimeError::OwnerUnavailable)?;
            let emitter = original
                .emitter
                .as_ref()
                .ok_or(RuntimeError::OwnerUnavailable)?;
            let activation = original
                .restoration_activation
                .as_ref()
                .ok_or(RuntimeError::OwnerUnavailable)?;
            let artifact: PacketRestorationActivationArtifact = serde::Deserialize::deserialize(
                activation.value(PacketRestorationActivationPhase::WorldActivate, 1)?,
            )
            .map_err(|_| RuntimeError::InvalidReceipt)?;
            let pair = controller
                .original_completed_installed_restoration_activation(
                    emitter,
                    PacketRestorationActivationPhase::WorldActivate,
                )
                .map_err(|_| RuntimeError::InvalidReceipt)?;
            let original_value =
                serde_json::to_value(pair.original()).map_err(|_| RuntimeError::InvalidReceipt)?;
            let original_bytes = canonical::canonical_json(&original_value)
                .map_err(|_| RuntimeError::InvalidReceipt)?;
            let world_original = canonical::content_ref(&original_bytes, "application/json")
                .map_err(|_| RuntimeError::InvalidReceipt)?;
            let world_terminal = controller
                .original_native5_frame_history()
                .map_err(|_| RuntimeError::InvalidReceipt)?
                .original_canonical_reference_data(pair.response())
                .map_err(|_| RuntimeError::InvalidReceipt)?;
            let request = PacketRestorationObservationRequest {
                schema: PACKET_RESTORATION_OBSERVE_FEATURE.into(),
                scope: artifact.request.scope,
                world_original,
                world_terminal,
                maximum_items: 1.into(),
                native_allocation: inputs.observation_data.native_allocation_data(),
            };
            admitted.authenticate_request_data(&request, inputs.request_id)?;
            prepared = Some((request, inputs.request_id.clone(), *inputs.observation_data));
            Ok(())
        })?;
        let (request, id, provider) = prepared.ok_or(RuntimeError::OwnerUnavailable)?;
        let binding = restoration_activation_scope_digest_data(&request.scope)
            .map_err(|_| RuntimeError::InvalidReceipt)?;
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
        emitter
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
        claim.with_original_observation_signing_inputs_data(self, |inputs| {
            restoration_activation::with_verified_world_under_read_data(
                self,
                controller,
                original,
                inputs.activation,
                &admitted.activation,
                key,
                || {
                    call.ensure_original_fresh_current_before_effect_data(&mut scratch)?;
                    claim.authenticate_current(self)
                },
                |scope, _, _| {
                    if request.scope != *scope {
                        return Err(RuntimeError::ForeignAuthority);
                    }
                    Ok(())
                },
            )
        })?;
        OriginalSourceRestorationObservationAttempt::reserve_into(
            self,
            controller,
            binding,
            admitted.frame,
            &mut original.restoration_observation,
        )?;
        let attempt = original
            .restoration_observation
            .as_mut()
            .ok_or(RuntimeError::OwnerUnavailable)?;
        attempt.authenticate_original(self, controller, binding)?;
        attempt.retain_value(
            0,
            serde_json::to_value(&request).map_err(|_| RuntimeError::InvalidReceipt)?,
            MAXIMUM_RESTORATION_OBSERVE_ARTIFACT_BYTES,
        )?;
        let mut marker = controller
            .prepare_original_installed_restoration_observation(emitter, id, request, &provider)
            .map_err(|_| RuntimeError::InvalidReceipt)?;
        let assigned = restoration_observe_assigned_request_digest(
            marker
                .original()
                .map_err(|_| RuntimeError::InvalidReceipt)?,
            admitted.frame,
        )
        .map_err(|_| RuntimeError::InvalidReceipt)?;
        let context = PacketRestorationObservationContext {
            request: serde::Deserialize::deserialize(attempt.value(0)?)
                .map_err(|_| RuntimeError::InvalidReceipt)?,
            assigned_request: Bytes::new(assigned.to_vec()),
        };
        let proof = restoration_observe_proof_data(key, &context)
            .map_err(|_| RuntimeError::InvalidReceipt)?;
        let artifact = PacketRestorationObservationArtifact {
            request: context.request,
            proof,
        };
        attempt.retain_value(
            1,
            serde_json::to_value(&artifact).map_err(|_| RuntimeError::InvalidReceipt)?,
            MAXIMUM_RESTORATION_OBSERVE_ARTIFACT_BYTES,
        )?;
        marker
            .seal(emitter, artifact)
            .map_err(|_| RuntimeError::InvalidReceipt)?;
        attempt.retain_value(
            2,
            serde_json::to_value(
                marker
                    .original()
                    .map_err(|_| RuntimeError::InvalidReceipt)?,
            )
            .map_err(|_| RuntimeError::InvalidReceipt)?,
            admitted.frame,
        )?;
        call.ensure_original_fresh_current_before_effect_data(&mut scratch)?;
        claim.authenticate_current(self)?;
        marker
            .publish_into(emitter, completed)
            .map_err(|_| RuntimeError::InvalidReceipt)?;
        drop(marker);
        let pair = controller
            .original_completed_installed_restoration_observation(emitter)
            .map_err(|_| RuntimeError::InvalidReceipt)?;
        let request: PacketRestorationObservationRequest =
            serde::Deserialize::deserialize(attempt.value(0)?)
                .map_err(|_| RuntimeError::InvalidReceipt)?;
        let measurement =
            authenticate_terminal(pair.response_body_data(), &request, pair.original())?.clone();
        if !pair.response().extensions.is_empty() {
            return Err(RuntimeError::InvalidReceipt);
        }
        attempt.retain_value(
            3,
            serde_json::to_value(pair.response()).map_err(|_| RuntimeError::InvalidReceipt)?,
            admitted.frame,
        )?;
        evidence::authenticate_saved_pair(self, attempt, controller, emitter, key, admitted)?;
        retain_native_evidence(attempt, controller, emitter, &measurement)?;
        // Re-run World and saved archive predicates beneath this SAME armed
        // read, then construct the real scheduling DATA from its verified model.
        claim.with_original_observation_signing_inputs_data(self, |inputs| {
            restoration_activation::with_verified_world_under_read_data(
                self,
                controller,
                original,
                inputs.activation,
                &admitted.activation,
                key,
                || {
                    call.ensure_original_fresh_current_before_effect_data(&mut scratch)?;
                    claim.authenticate_current(self)
                },
                |scope, reference, held| {
                    if request.scope != *scope {
                        return Err(RuntimeError::ForeignAuthority);
                    }
                    let attempt = original
                        .restoration_observation
                        .as_ref()
                        .ok_or(RuntimeError::OwnerUnavailable)?;
                    let record = attempt.record()?;
                    let bytes = controller
                        .content(&record.native_receipt.native_record)
                        .map_err(|_| RuntimeError::InvalidReceipt)?;
                    let observed = controller
                        .authenticate_original_installed_restoration_observation_evidence_data(
                            emitter, record, bytes,
                        )
                        .map_err(|_| RuntimeError::InvalidReceipt)?;
                    authenticate_restoration_activation_held_correspondence_data(
                        record, &observed, held,
                    )
                    .map_err(|_| RuntimeError::InvalidReceipt)?;
                    // The preceding complete-model correspondence recomputes
                    // the same native inventory hash and authenticates this
                    // historical value. Bind the actual typed terminal to it.
                    let completed = controller
                        .original_completed_installed_restoration_observation(emitter)
                        .map_err(|_| RuntimeError::InvalidReceipt)?;
                    authenticate_terminal_inventory_data(
                        completed.response_body_data(),
                        &held.inventory_hash,
                    )?;
                    inputs.authenticate_original_observation_hold_data(held, reference)
                },
            )?;
            let world = inputs
                .activation
                .world
                .ok_or(RuntimeError::ForeignAuthority)?;
            let attempt = original
                .restoration_observation
                .as_ref()
                .ok_or(RuntimeError::OwnerUnavailable)?;
            let observation =
                scheduling::construct(self, world, &measurement, attempt.underlying()?)?;
            attempt.retain_scheduling(observation)?;
            scheduling::authenticate_bound(attempt.scheduling()?, admitted.scheduling)
        })?;
        call.complete(&mut scratch, || claim.authenticate_current(self))?;
        original
            .restoration_observation
            .as_mut()
            .ok_or(RuntimeError::OwnerUnavailable)?
            .finish_verified()?;
        drop(association);
        OriginalSourceRestorationObservationVerifiedPhase::new(self, controller, Some(claim))
    }
}

fn retain_native_evidence(
    attempt: &mut OriginalSourceRestorationObservationAttempt,
    controller: &CnpController,
    emitter: &OriginalCanonicalBlobAckEmitter,
    reference: &ContentRef,
) -> Result<(), RuntimeError> {
    let raw = controller
        .content(reference)
        .map_err(|_| RuntimeError::InvalidReceipt)?;
    reference
        .verify(raw)
        .map_err(|_| RuntimeError::InvalidReceipt)?;
    let value = canonical::parse_json(raw, 65_536).map_err(|_| RuntimeError::InvalidReceipt)?;
    let encoded = canonical::canonical_json(&value).map_err(|_| RuntimeError::InvalidReceipt)?;
    if encoded.as_slice() != raw {
        return Err(RuntimeError::InvalidReceipt);
    }
    let record = serde_json::from_value(value).map_err(|_| RuntimeError::InvalidReceipt)?;
    attempt.retain_record(record)?;
    let record = attempt.record()?;
    let bytes = controller
        .content(&record.native_receipt.native_record)
        .map_err(|_| RuntimeError::InvalidReceipt)?;
    let underlying = controller
        .authenticate_original_installed_restoration_observation_evidence_data(
            emitter, record, bytes,
        )
        .map_err(|_| RuntimeError::InvalidReceipt)?;
    attempt.retain_underlying(underlying)
}

pub(super) fn authenticate_terminal<'a>(
    response: &'a ResponseBody,
    request: &PacketRestorationObservationRequest,
    original: &crucible_node_transport::envelope::Envelope,
) -> Result<&'a ContentRef, RuntimeError> {
    use crucible_node_transport::bodies::{MethodResult, OperationState, ResponseShape};
    if !matches!(
        &response.shape,
        ResponseShape::Completed {
            operation_state: OperationState::Completed,
            extensions,
            ..
        } if extensions.is_empty()
    ) {
        return Err(RuntimeError::InvalidReceipt);
    }
    let Some(MethodResult::Observe(result)) = response.result.as_ref() else {
        return Err(RuntimeError::InvalidReceipt);
    };
    let [batch] = result.observations.as_slice() else {
        return Err(RuntimeError::InvalidReceipt);
    };
    let target = &request.scope.target;
    if !result.complete
        || result.next_sequence.get() != 1
        || batch.schema_version != 1
        || batch.execution_owner_id != target.owner
        || batch.owner_binding_hash != target.binding_hash
        || batch.world_binding_hash != target.world
        || batch.activation_id != target.activation
        || batch.world_generation != target.generation
        || batch.owner_generation != target.owner_generation
        || Some(&batch.operation_id) != original.request_id.0.as_ref()
        || batch.grant_id.is_some()
        || batch.first_sequence.get() != 0
        || batch.last_sequence.get() != 0
        || !batch.events.is_empty()
        || batch.visibility != crucible_node_format::Visibility::Staged
        || !batch.extensions.is_empty()
    {
        return Err(RuntimeError::ForeignAuthority);
    }
    Ok(&batch.measurement_ref)
}

/// Binds the actual terminal to an independently verified complete inventory.
///
/// The expected hash comes only from the genuine historical Hold after the
/// current underlying model has been hashed and compared to that same Hold.
/// This DATA predicate alone neither verifies a model nor issues authority.
///
/// # Errors
/// Refuses an absent/wrong typed method or a different complete inventory hash.
pub(super) fn authenticate_terminal_inventory_data(
    response: &ResponseBody,
    expected: &crucible_node_format::HashRef,
) -> Result<(), RuntimeError> {
    use crucible_node_transport::bodies::MethodResult;
    let Some(MethodResult::Observe(result)) = response.result.as_ref() else {
        return Err(RuntimeError::InvalidReceipt);
    };
    if &result.inventory_hash != expected {
        return Err(RuntimeError::InvalidReceipt);
    }
    Ok(())
}

#[cfg(test)]
#[path = "effect_tests.rs"]
mod tests;
