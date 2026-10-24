//! Signs one real assigned phase and preserves its original partial custody.
//!
//! The opaque Core claim is consumed before Source construction. The committed
//! immutable Controller evidence is authenticated in an inner callback and ends
//! before the exclusive assignment loan. The same original SourceRead remains
//! armed across sealing, send, native evidence and the terminal member fence.

use super::*;

impl PacketCompleteSemanticSource {
    /// Spends a genuine same-Window phase before signing its assigned original.
    ///
    /// SDK/caller originals and Source partials remain owned on every error.
    /// Successful transport alone never completes Core's private phase ledger.
    ///
    /// # Errors
    /// Refuses foreign or stale claims, changed complete originals, exhausted
    /// independent credit, invalid native evidence or failed terminal fences.
    pub(crate) fn call_original_installed_restoration_activation_into<'a>(
        &'a self,
        controller: &'a mut CnpController,
        claim: OriginalInstalledRestorationActivationClaim,
        command: PacketRestorationActivationCommand,
        admitted: &OriginalSourceRestorationActivationConstructionData,
        completed: &mut Option<ResponseBody>,
    ) -> Result<OriginalSourceRestorationActivationVerifiedPhase<'a>, RuntimeError> {
        self.storage_origin_with_error::<RuntimeError>()?;
        claim.authenticate_current(self)?;
        if completed.is_some() {
            return Err(RuntimeError::OutstandingObligations);
        }
        admitted.authenticate_original(self, controller)?;
        let phase = provider_phase(claim.phase_data());
        let mut prepared_inputs = None;
        claim.with_original_activation_signing_inputs_data(self, |inputs| {
            if inputs.phase != claim.phase_data() {
                return Err(RuntimeError::ForeignAuthority);
            }
            admitted.authenticate_same_construction_data(inputs.source_construction)?;
            let request = self.original_restoration_activation_request_data(controller, inputs)?;
            admitted.authenticate_request_data(&request)?;
            command
                .authenticate_request_data(&request)
                .map_err(|_| RuntimeError::ForeignAuthority)?;
            let world_bodies = match (&command, inputs.world, inputs.phase) {
                (
                    PacketRestorationActivationCommand::Arm(_),
                    None,
                    OriginalInstalledRestorationActivationPhase::Arm,
                ) => None,
                (
                    PacketRestorationActivationCommand::WorldActivate(body),
                    Some(world),
                    OriginalInstalledRestorationActivationPhase::WorldActivate,
                ) => Some(world_content::WorldUploadBodies::from_original_world(
                    self,
                    world,
                    body,
                    inputs.activation_data.upload_maximum_content_bytes_data(
                        PacketRestorationActivationUploadRole::Coordinator,
                    ),
                    admitted.maximum_activation_manifest_encoded_bytes_data(),
                )?),
                _ => return Err(RuntimeError::ForeignAuthority),
            };
            prepared_inputs = Some((
                request,
                inputs.request_id.clone(),
                *inputs.activation_data,
                world_bodies,
            ));
            Ok(())
        })?;
        let (request, request_id, provider_data, world_bodies) =
            prepared_inputs.ok_or(RuntimeError::OwnerUnavailable)?;
        let binding = blake3::Hash::from_bytes(
            restoration_activation_scope_digest_data(&request.scope)
                .map_err(|_| RuntimeError::InvalidReceipt)?,
        );

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
        claim.authenticate_current(self)?;
        if original.restoration_activation.is_none() {
            OriginalSourceRestorationActivationAttempt::reserve_into(
                self,
                controller,
                binding,
                admitted.maximum_frame_bytes_data(),
                &mut original.restoration_activation,
            )?;
        }
        let attempt = original
            .restoration_activation
            .as_mut()
            .ok_or(RuntimeError::OwnerUnavailable)?;
        attempt.authenticate_original(self, controller, binding)?;
        attempt.begin(phase)?;
        if let Some(bodies) = world_bodies {
            attempt.retain_world_bodies(bodies)?;
            upload::publish_world_uploads(
                controller,
                emitter,
                key,
                attempt,
                &request.scope,
                admitted,
                &provider_data,
                || {
                    call.ensure_original_fresh_current_before_effect_data(&mut scratch)?;
                    claim.authenticate_current(self)
                },
            )?;
            claim.with_original_activation_signing_inputs_data(self, |inputs| {
                authenticate_world_command(
                    self,
                    controller,
                    &command,
                    inputs,
                    admitted.maximum_activation_manifest_encoded_bytes_data(),
                )
            })?;
        }
        attempt.retain_value(
            phase,
            0,
            serde_json::to_value(&request).map_err(|_| RuntimeError::InvalidReceipt)?,
            MAXIMUM_RESTORATION_ACTIVATION_ARTIFACT_BYTES,
        )?;

        let mut marker = controller
            .prepare_original_installed_restoration_activation(
                emitter,
                request_id,
                command,
                request,
                &provider_data,
            )
            .map_err(|_| RuntimeError::InvalidReceipt)?;
        let assigned = restoration_activation_assigned_request_digest(
            marker
                .original()
                .map_err(|_| RuntimeError::InvalidReceipt)?,
            phase,
            admitted.maximum_frame_bytes_data(),
        )
        .map_err(|_| RuntimeError::InvalidReceipt)?;
        let context = PacketRestorationActivationContext {
            request: serde::Deserialize::deserialize(attempt.value(phase, 0)?)
                .map_err(|_| RuntimeError::InvalidReceipt)?,
            assigned_request: Bytes::new(assigned.to_vec()),
        };
        let proof = restoration_activation_proof_data(key, &context)
            .map_err(|_| RuntimeError::InvalidReceipt)?;
        let artifact = PacketRestorationActivationArtifact {
            request: context.request,
            proof,
        };
        attempt.retain_value(
            phase,
            1,
            serde_json::to_value(&artifact).map_err(|_| RuntimeError::InvalidReceipt)?,
            MAXIMUM_RESTORATION_ACTIVATION_ARTIFACT_BYTES,
        )?;
        marker
            .seal(emitter, artifact)
            .map_err(|_| RuntimeError::InvalidReceipt)?;
        attempt.retain_value(
            phase,
            2,
            serde_json::to_value(
                marker
                    .original()
                    .map_err(|_| RuntimeError::InvalidReceipt)?,
            )
            .map_err(|_| RuntimeError::InvalidReceipt)?,
            admitted.maximum_frame_bytes_data(),
        )?;
        call.ensure_original_fresh_current_before_effect_data(&mut scratch)?;
        claim.authenticate_current(self)?;
        marker
            .publish_into(emitter, completed)
            .map_err(|_| RuntimeError::InvalidReceipt)?;
        drop(marker);
        let pair = controller
            .original_completed_installed_restoration_activation(emitter, phase)
            .map_err(|_| RuntimeError::InvalidReceipt)?;
        // SDK and caller already own every actual terminal, including errors.
        // Source creates its additional normalized owner only after the closed
        // actual single-owner result is checked; failure cannot complete phase.
        let unsigned: PacketRestorationActivationRequest =
            serde::Deserialize::deserialize(attempt.value(phase, 0)?)
                .map_err(|_| RuntimeError::InvalidReceipt)?;
        authenticate_terminal_owner(
            completed.as_ref().ok_or(RuntimeError::OwnerUnavailable)?,
            phase,
            &unsigned.scope.target,
        )?;
        drop(unsigned);
        if !pair.response().extensions.is_empty() {
            return Err(RuntimeError::InvalidReceipt);
        }
        attempt.retain_value(
            phase,
            3,
            serde_json::to_value(pair.response()).map_err(|_| RuntimeError::InvalidReceipt)?,
            admitted.maximum_frame_bytes_data(),
        )?;
        authenticate_saved_pair(attempt, controller, emitter, phase, key, admitted)?;
        retain_native_evidence(attempt, controller, emitter, phase)?;
        call.complete(&mut scratch, || claim.authenticate_current(self))?;
        attempt.finish_verified(phase)?;
        drop(association);
        Ok(OriginalSourceRestorationActivationVerifiedPhase::new(
            self,
            controller,
            claim.phase_data(),
        ))
    }
}

fn retain_native_evidence(
    attempt: &mut OriginalSourceRestorationActivationAttempt,
    controller: &CnpController,
    emitter: &OriginalCanonicalBlobAckEmitter,
    phase: PacketRestorationActivationPhase,
) -> Result<(), RuntimeError> {
    let pair = controller
        .original_completed_installed_restoration_activation(emitter, phase)
        .map_err(|_| RuntimeError::InvalidReceipt)?;
    let reference: ContentRef = serde::Deserialize::deserialize(
        pair.response()
            .body
            .get("result")
            .and_then(serde_json::Value::as_object)
            .and_then(|result| result.get("activation_receipt"))
            .ok_or(RuntimeError::InvalidReceipt)?,
    )
    .map_err(|_| RuntimeError::InvalidReceipt)?;
    let raw = controller
        .content(&reference)
        .map_err(|_| RuntimeError::InvalidReceipt)?;
    reference
        .verify(raw)
        .map_err(|_| RuntimeError::InvalidReceipt)?;
    let value = canonical::parse_json(raw, 65_536).map_err(|_| RuntimeError::InvalidReceipt)?;
    let canonical = canonical::canonical_json(&value).map_err(|_| RuntimeError::InvalidReceipt)?;
    if canonical.as_slice() != raw {
        return Err(RuntimeError::InvalidReceipt);
    }
    let record = serde_json::from_value(value).map_err(|_| RuntimeError::InvalidReceipt)?;
    attempt.retain_native_record(phase, record)?;
    let record = attempt.native_record(phase)?;
    let underlying = controller
        .content(&record.native_receipt.native_record)
        .map_err(|_| RuntimeError::InvalidReceipt)?;
    let underlying = controller
        .authenticate_original_installed_restoration_activation_evidence_data(
            emitter, phase, record, underlying,
        )
        .map_err(|_| RuntimeError::InvalidReceipt)?;
    attempt.retain_underlying(phase, underlying)
}

pub(super) fn authenticate_terminal_owner(
    completed: &ResponseBody,
    phase: PacketRestorationActivationPhase,
    target: &PacketRestorationActivationTarget,
) -> Result<(), RuntimeError> {
    use crucible_node_transport::bodies::{MethodResult, OperationState, ResponseShape};
    match &completed.shape {
        ResponseShape::Completed {
            operation_state: OperationState::Completed,
            extensions,
            ..
        } if extensions.is_empty() => {}
        _ => return Err(RuntimeError::InvalidReceipt),
    }
    let (gate, owners) = match (phase, completed.result.as_ref()) {
        (PacketRestorationActivationPhase::Arm, Some(MethodResult::Activate(result)))
            if result.staged =>
        {
            (&result.gate_id, &result.staged_owner_ids)
        }
        (
            PacketRestorationActivationPhase::WorldActivate,
            Some(MethodResult::WorldActivate(result)),
        ) => (&result.gate_id, &result.armed_owner_ids),
        _ => return Err(RuntimeError::InvalidReceipt),
    };
    authenticate_terminal_identity(gate, owners, &target.gate, &target.owner)
}

fn authenticate_terminal_identity(
    gate: &Id,
    owners: &[Id],
    expected_gate: &Id,
    expected_owner: &Id,
) -> Result<(), RuntimeError> {
    if gate != expected_gate || owners != std::slice::from_ref(expected_owner) {
        return Err(RuntimeError::ForeignAuthority);
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn actual_terminal_projection_rejects_foreign_gate_owner_and_extra_owner() {
        let gate = Id::new("actual-gate").unwrap();
        let foreign_gate = Id::new("other-gate").unwrap();
        let owner = Id::new("actual-owner").unwrap();
        let foreign_owner = Id::new("other-owner").unwrap();
        let exact = [owner.clone()];

        authenticate_terminal_identity(&gate, &exact, &gate, &owner).unwrap();
        assert!(authenticate_terminal_identity(&foreign_gate, &exact, &gate, &owner).is_err());
        assert!(
            authenticate_terminal_identity(&gate, &[foreign_owner.clone()], &gate, &owner).is_err()
        );
        assert!(
            authenticate_terminal_identity(&gate, &[owner.clone(), foreign_owner], &gate, &owner)
                .is_err()
        );
        assert!(authenticate_terminal_identity(&gate, &[], &gate, &owner).is_err());

        // Actual DATA entrypoint: these records have no Source, claim, key,
        // Window, controller or native owner. They only exercise the checks
        // performed before Source creates its own terminal Value/bank owner.
        use crucible_node_transport::bodies::{
            ActivateResult, MethodResult, OperationState, ResponseShape, WorldActivateResult,
        };
        let target = PacketRestorationActivationTarget {
            native_pid: 42.into(),
            session: Id::new("session").unwrap(),
            incarnation: Id::new("incarnation").unwrap(),
            node: Id::new("node").unwrap(),
            owner: owner.clone(),
            owner_generation: 1.into(),
            binding_hash: canonical::hash("cnp.owner-binding.v1", b"binding").unwrap(),
            world: canonical::hash("cnp.world-binding.v1", b"world").unwrap(),
            activation: Id::new("activation").unwrap(),
            generation: 1.into(),
            prepared_token: Id::new("prepared").unwrap(),
            gate: gate.clone(),
            admission: Id::new("admission").unwrap(),
            transaction: Id::new("transaction").unwrap(),
        };
        let arm_result = ActivateResult {
            staged: true,
            gate_id: gate.clone(),
            staged_owner_ids: vec![owner.clone()],
            activation_receipt: canonical::content_ref(b"receipt", "application/json").unwrap(),
        };
        let raw_result = serde_json::to_value(&arm_result)
            .unwrap()
            .as_object()
            .unwrap()
            .clone();
        let mut response = ResponseBody {
            shape: ResponseShape::Completed {
                operation_state: OperationState::Completed,
                result: raw_result.clone(),
                extensions: Default::default(),
            },
            result: Some(MethodResult::Activate(arm_result.clone())),
        };
        authenticate_terminal_owner(&response, PacketRestorationActivationPhase::Arm, &target)
            .unwrap();
        assert!(
            authenticate_terminal_owner(
                &response,
                PacketRestorationActivationPhase::WorldActivate,
                &target
            )
            .is_err()
        );

        response.result = None;
        assert!(
            authenticate_terminal_owner(&response, PacketRestorationActivationPhase::Arm, &target)
                .is_err()
        );
        let mut unstaged = arm_result.clone();
        unstaged.staged = false;
        response.result = Some(MethodResult::Activate(unstaged));
        assert!(
            authenticate_terminal_owner(&response, PacketRestorationActivationPhase::Arm, &target)
                .is_err()
        );

        response.result = Some(MethodResult::Activate(arm_result));
        response.shape = ResponseShape::Accepted {
            operation_state: OperationState::Running,
            result: raw_result.clone(),
            extensions: Default::default(),
        };
        assert!(
            authenticate_terminal_owner(&response, PacketRestorationActivationPhase::Arm, &target)
                .is_err()
        );
        response.shape = ResponseShape::Completed {
            operation_state: OperationState::Running,
            result: raw_result.clone(),
            extensions: Default::default(),
        };
        assert!(
            authenticate_terminal_owner(&response, PacketRestorationActivationPhase::Arm, &target)
                .is_err()
        );
        let mut extensions = crucible_node_format::Extensions::new();
        extensions.insert("unexpected".into(), serde_json::Value::Bool(true));
        response.shape = ResponseShape::Completed {
            operation_state: OperationState::Completed,
            result: raw_result,
            extensions,
        };
        assert!(
            authenticate_terminal_owner(&response, PacketRestorationActivationPhase::Arm, &target)
                .is_err()
        );

        response.shape = ResponseShape::Error {
            operation_state: OperationState::NotStarted,
            error: crucible_node_transport::bodies::ErrorRecord {
                code: "RESOURCE_EXHAUSTED".into(),
                message: "bounded DATA refusal".into(),
                effect: crucible_node_transport::bodies::EffectCertainty::NotStarted,
                retryable: false,
                details: Default::default(),
            },
            extensions: Default::default(),
        };
        response.result = None;
        assert!(
            authenticate_terminal_owner(&response, PacketRestorationActivationPhase::Arm, &target)
                .is_err()
        );

        let world_result = WorldActivateResult {
            gate_id: gate,
            armed_owner_ids: vec![owner],
            activation_receipt: canonical::content_ref(b"world receipt", "application/json")
                .unwrap(),
        };
        let raw_world = serde_json::to_value(&world_result)
            .unwrap()
            .as_object()
            .unwrap()
            .clone();
        response.shape = ResponseShape::Completed {
            operation_state: OperationState::Completed,
            result: raw_world,
            extensions: Default::default(),
        };
        response.result = Some(MethodResult::WorldActivate(world_result));
        authenticate_terminal_owner(
            &response,
            PacketRestorationActivationPhase::WorldActivate,
            &target,
        )
        .unwrap();
        assert!(
            authenticate_terminal_owner(&response, PacketRestorationActivationPhase::Arm, &target)
                .is_err()
        );
    }
}
