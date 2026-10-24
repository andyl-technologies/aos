//! Reauthenticates actual signed phase originals before Core records completion.
//!
//! A phase label, decoded native record or completed response is not evidence.
//! This opaque loan is created only after the Source keeps its actual signer
//! attempt, assigned pair and underlying native owner. Read-only inspection
//! opens no Query, creates no claim and never renews a spent phase.

use super::*;

/// Borrows one actual Source-verified activation phase without issuing readiness.
///
/// There is no public constructor, Clone, decoder or conversion to a phase
/// claim. Core must authenticate this same loan under the retained Window and
/// terminal member before updating its private ledger.
#[must_use = "authenticate the actual same-Window phase before recording completion"]
pub struct OriginalSourceRestorationActivationVerifiedPhase<'a> {
    source: &'a PacketCompleteSemanticSource,
    controller: &'a CnpController,
    phase: OriginalInstalledRestorationActivationPhase,
}

impl<'a> OriginalSourceRestorationActivationVerifiedPhase<'a> {
    pub(super) fn new(
        source: &'a PacketCompleteSemanticSource,
        controller: &'a CnpController,
        phase: OriginalInstalledRestorationActivationPhase,
    ) -> Self {
        Self {
            source,
            controller,
            phase,
        }
    }

    /// Reauthenticates actual phase/MAC/native owners under the final fence.
    ///
    /// # Errors
    /// Refuses foreign, stale, incomplete or altered same-Window evidence.
    pub(crate) fn authenticate_current(
        &self,
        inputs: &OriginalInstalledRestorationActivationSigningInputs<'_>,
        admitted: &OriginalSourceRestorationActivationConstructionData,
        final_currency: impl FnOnce() -> Result<(), RuntimeError>,
    ) -> Result<OriginalInstalledRestorationActivationPhase, RuntimeError> {
        self.source
            .authenticate_original_restoration_activation_evidence_data(
                self.controller,
                inputs,
                admitted,
                self.phase,
                |_, _| Ok(()),
                final_currency,
            )?;
        Ok(self.phase)
    }

    /// Rechecks the actual current phase before lending its historical Commit.
    ///
    /// The old Hold remains held-true history. Current physical state is proved
    /// independently by the completed activation pair and native record first.
    /// Both callbacks run beneath the same new SourceRead and kernel fence.
    ///
    /// # Errors
    /// Refuses stale current evidence, changed historical correspondence or
    /// either actual continuation/member callback's refusal.
    pub(crate) fn authenticate_continuation_data(
        &self,
        inputs: &OriginalInstalledRestorationActivationSigningInputs<'_>,
        admitted: &OriginalSourceRestorationActivationConstructionData,
        validate_held: impl FnOnce(
            &PacketNativeRestoredCommitHold,
            &ContentRef,
        ) -> Result<(), RuntimeError>,
        final_currency: impl FnOnce() -> Result<(), RuntimeError>,
    ) -> Result<OriginalInstalledRestorationActivationPhase, RuntimeError> {
        self.source
            .authenticate_original_restoration_activation_evidence_data(
                self.controller,
                inputs,
                admitted,
                self.phase,
                validate_held,
                final_currency,
            )?;
        Ok(self.phase)
    }
}

impl PacketCompleteSemanticSource {
    /// Borrows an already verified actual phase without renewing any claim.
    ///
    /// # Errors
    /// Refuses absent, foreign, stale or changed same-Controller phase evidence.
    pub(crate) fn original_verified_restoration_activation_data<'a>(
        &'a self,
        controller: &'a CnpController,
        inputs: &OriginalInstalledRestorationActivationSigningInputs<'_>,
        admitted: &OriginalSourceRestorationActivationConstructionData,
    ) -> Result<OriginalSourceRestorationActivationVerifiedPhase<'a>, RuntimeError> {
        self.authenticate_original_restoration_activation_evidence_data(
            controller,
            inputs,
            admitted,
            inputs.phase,
            |_, _| Ok(()),
            || inputs.inspection.authenticate_current(),
        )?;
        Ok(OriginalSourceRestorationActivationVerifiedPhase::new(
            self,
            controller,
            inputs.phase,
        ))
    }

    fn authenticate_original_restoration_activation_evidence_data(
        &self,
        controller: &CnpController,
        inputs: &OriginalInstalledRestorationActivationSigningInputs<'_>,
        admitted: &OriginalSourceRestorationActivationConstructionData,
        expected: OriginalInstalledRestorationActivationPhase,
        validate_held: impl FnOnce(
            &PacketNativeRestoredCommitHold,
            &ContentRef,
        ) -> Result<(), RuntimeError>,
        final_currency: impl FnOnce() -> Result<(), RuntimeError>,
    ) -> Result<(), RuntimeError> {
        self.storage_origin_with_error::<RuntimeError>()?;
        if expected != inputs.phase || !std::ptr::eq(inputs.transfer.source.as_ref(), self) {
            return Err(RuntimeError::ForeignAuthority);
        }
        admitted.authenticate_same_construction_data(inputs.source_construction)?;
        admitted.authenticate_original(self, controller)?;
        // Commit remains authenticated immutable history after physical release.
        // Do not reuse the old current-held=true continuation check here.
        let committed = self.original_verified_restore_transfer_commit_data(
            controller,
            inputs.uploaded,
            inputs.signer,
            &inputs.inspection,
        )?;
        drop(committed);
        inputs
            .scope_proof
            .verify(inputs.scope_proof_body)
            .map_err(|_| RuntimeError::InvalidReceipt)?;

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
        let native = original
            .native
            .as_ref()
            .ok_or(RuntimeError::OwnerUnavailable)?;
        let attempt = original
            .restoration_activation
            .as_ref()
            .ok_or(RuntimeError::OwnerUnavailable)?;
        let phase = provider_phase(expected);
        attempt.authenticate_verified(phase)?;
        let artifact: PacketRestorationActivationArtifact =
            serde::Deserialize::deserialize(attempt.value(phase, 1)?)
                .map_err(|_| RuntimeError::InvalidReceipt)?;
        let scope = &artifact.request.scope;
        attempt.authenticate_original(
            self,
            controller,
            blake3::Hash::from_bytes(
                restoration_activation_scope_digest_data(scope)
                    .map_err(|_| RuntimeError::InvalidReceipt)?,
            ),
        )?;
        scope
            .source_birth
            .verify(&original.banks[0])
            .map_err(|_| RuntimeError::InvalidReceipt)?;
        if scope.source_runtime != inputs.scope.source_record
            || scope.scope_proof != *inputs.scope_proof
            || scope.target.world != inputs.scope.target.world_binding_hash
            || scope.target.activation != inputs.scope.target.activation_id
            || scope.target.generation != inputs.scope.target.generation
            || scope.restoration.captured_owner_state != inputs.transfer.ticket.owner()?.state
            || scope.restoration.captured_control != inputs.transfer.journal.native_control
            || scope.restoration.captured_journal != *inputs.transfer.journal_reference
        {
            return Err(RuntimeError::ForeignAuthority);
        }
        let pair = controller
            .original_completed_installed_restoration_activation(emitter, phase)
            .map_err(|_| RuntimeError::InvalidReceipt)?;
        if pair.original().request_id.0.as_ref() != Some(inputs.request_id) {
            return Err(RuntimeError::ForeignAuthority);
        }
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
        authenticate_saved_pair(attempt, controller, emitter, phase, key, admitted)?;
        if expected == OriginalInstalledRestorationActivationPhase::WorldActivate {
            let world = inputs.world.ok_or(RuntimeError::ForeignAuthority)?;
            let body: crucible_node_transport::bodies::WorldActivateRequest =
                serde_json::from_value(serde_json::Value::Object(pair.original().body.clone()))
                    .map_err(|_| RuntimeError::InvalidReceipt)?;
            authenticate_world_manifest(
                self,
                controller,
                &body,
                world,
                admitted.maximum_activation_manifest_encoded_bytes_data(),
            )?;
        } else if inputs.world.is_some() {
            return Err(RuntimeError::ForeignAuthority);
        }
        let record = attempt.native_record(phase)?;
        let underlying = controller
            .content(&record.native_receipt.native_record)
            .map_err(|_| RuntimeError::InvalidReceipt)?;
        // Keep this newly revalidated DATA owner alive beside the permanently
        // retained original through the final callback and native kernel fence.
        let observed = controller
            .authenticate_original_installed_restoration_activation_evidence_data(
                emitter, phase, record, underlying,
            )
            .map_err(|_| RuntimeError::InvalidReceipt)?;
        // This is a real historical Controller content owner, not the current
        // physical held bit. Complete current-model correspondence is checked
        // before Core may inspect saved predicates or its node/ACK copy.
        let (held_reference, held) = historical_commit_hold(controller, emitter, original, scope)?;
        authenticate_restoration_activation_held_correspondence_data(record, &observed, &held)
            .map_err(|_| RuntimeError::InvalidReceipt)?;
        validate_held(&held, &held_reference)?;
        call.complete(&mut scratch, final_currency)?;
        drop(observed);
        Ok(())
    }
}

pub(super) fn authenticate_saved_pair(
    attempt: &OriginalSourceRestorationActivationAttempt,
    controller: &CnpController,
    emitter: &OriginalCanonicalBlobAckEmitter,
    phase: PacketRestorationActivationPhase,
    key: &[u8; 32],
    admitted: &OriginalSourceRestorationActivationConstructionData,
) -> Result<(), RuntimeError> {
    let pair = controller
        .original_completed_installed_restoration_activation(emitter, phase)
        .map_err(|_| RuntimeError::InvalidReceipt)?;
    if pair.phase_data() != phase
        || pair
            .original()
            .extensions
            .get(PACKET_RESTORATION_ACTIVATION_FEATURE)
            != Some(attempt.value(phase, 1)?)
        || serde_json::to_value(pair.original()).map_err(|_| RuntimeError::InvalidReceipt)?
            != *attempt.value(phase, 2)?
        || serde_json::to_value(pair.response()).map_err(|_| RuntimeError::InvalidReceipt)?
            != *attempt.value(phase, 3)?
    {
        return Err(RuntimeError::InvalidReceipt);
    }
    let artifact: PacketRestorationActivationArtifact =
        serde::Deserialize::deserialize(attempt.value(phase, 1)?)
            .map_err(|_| RuntimeError::InvalidReceipt)?;
    let unsigned: PacketRestorationActivationRequest =
        serde::Deserialize::deserialize(attempt.value(phase, 0)?)
            .map_err(|_| RuntimeError::InvalidReceipt)?;
    if artifact.request != unsigned || unsigned.phase != phase {
        return Err(RuntimeError::InvalidReceipt);
    }
    admitted.authenticate_request_data(&unsigned)?;
    let assigned = restoration_activation_assigned_request_digest(
        pair.original(),
        phase,
        admitted.maximum_frame_bytes_data(),
    )
    .map_err(|_| RuntimeError::InvalidReceipt)?;
    let context = PacketRestorationActivationContext {
        request: unsigned,
        assigned_request: Bytes::new(assigned.to_vec()),
    };
    verify_restoration_activation_proof_data(key, &context, &artifact.proof)
        .map_err(|_| RuntimeError::InvalidReceipt)
}

fn historical_commit_hold(
    controller: &CnpController,
    emitter: &OriginalCanonicalBlobAckEmitter,
    original: &OriginalAckPeerAssociation,
    scope: &PacketRestorationActivationScope,
) -> Result<(ContentRef, PacketNativeRestoredCommitHold), RuntimeError> {
    use crucible_node_transport::reference_packet::service::complete_restore::{
        maximum_complete_restore_held_evidence_bytes, transfer::PacketCompleteRestoreTransferPhase,
    };
    let pair = controller
        .original_completed_complete_restore_transfer(
            emitter,
            PacketCompleteRestoreTransferPhase::Commit,
        )
        .map_err(|_| RuntimeError::InvalidReceipt)?;
    let reference: ContentRef = serde::Deserialize::deserialize(
        pair.response()
            .body
            .get("result")
            .and_then(serde_json::Value::as_object)
            .and_then(|result| result.get("closed_gate_receipt"))
            .ok_or(RuntimeError::InvalidReceipt)?,
    )
    .map_err(|_| RuntimeError::InvalidReceipt)?;
    let bytes = controller
        .content(&reference)
        .map_err(|_| RuntimeError::InvalidReceipt)?;
    let maximum =
        maximum_complete_restore_held_evidence_bytes().map_err(|_| RuntimeError::ResourceLimit)?;
    if bytes.len() > maximum {
        return Err(RuntimeError::ResourceLimit);
    }
    reference
        .verify(bytes)
        .map_err(|_| RuntimeError::InvalidReceipt)?;
    let value = canonical::parse_json(bytes, maximum).map_err(|_| RuntimeError::InvalidReceipt)?;
    let encoded = canonical::canonical_json(&value).map_err(|_| RuntimeError::InvalidReceipt)?;
    if encoded.as_slice() != bytes {
        return Err(RuntimeError::InvalidReceipt);
    }
    drop(encoded);
    let held: PacketNativeRestoredCommitHold =
        serde_json::from_value(value).map_err(|_| RuntimeError::InvalidReceipt)?;
    held.validate_data()
        .map_err(|_| RuntimeError::InvalidReceipt)?;
    let originals = &scope.restoration;
    if held.native_pid != scope.target.native_pid
        || held.target_world != scope.target.world
        || held.target_owner != scope.target.owner
        || held.target_owner_binding != scope.target.binding_hash
        || held.target_activation != scope.target.activation
        || held.target_generation != scope.target.generation
        || held.captured_owner_state != originals.captured_owner_state
        || held.captured_control != originals.captured_control
        || held.captured_journal != originals.captured_journal
        || held.mapping != originals.mapping
        || held.restore_commit != originals.commit_request
        || held.context_digest != originals.context_digest
    {
        return Err(RuntimeError::ForeignAuthority);
    }
    let transfer = original
        .restore_transfer_banks
        .as_ref()
        .ok_or(RuntimeError::OwnerUnavailable)?;
    held.restore_commit
        .verify(transfer.bank(PacketCompleteRestoreTransferPhase::Commit, 3)?)
        .map_err(|_| RuntimeError::InvalidReceipt)?;
    Ok((reference, held))
}

/// Repeats actual World evidence beneath an already owning observation read.
///
/// The observation caller supplies its real armed-call recheck and retains the
/// association loan. This helper opens no Source association or idle ReadCall;
/// it cannot release, replace or reconstruct that owning token. It only lends
/// actual saved DATA after MAC/model/history checks, never a phase capability.
pub(in super::super) fn with_verified_world_under_read_data(
    source: &PacketCompleteSemanticSource,
    controller: &CnpController,
    original: &OriginalAckPeerAssociation,
    inputs: &OriginalInstalledRestorationActivationSigningInputs<'_>,
    admitted: &OriginalSourceRestorationActivationConstructionData,
    key: &[u8; 32],
    mut recheck: impl FnMut() -> Result<(), RuntimeError>,
    inspect: impl FnOnce(
        &PacketRestorationActivationScope,
        &ContentRef,
        &PacketNativeRestoredCommitHold,
    ) -> Result<(), RuntimeError>,
) -> Result<(), RuntimeError> {
    if inputs.phase != OriginalInstalledRestorationActivationPhase::WorldActivate
        || !std::ptr::eq(inputs.transfer.source.as_ref(), source)
    {
        return Err(RuntimeError::ForeignAuthority);
    }
    admitted.authenticate_original(source, controller)?;
    admitted.authenticate_same_construction_data(inputs.source_construction)?;
    original.authenticate_transfer_ready_data()?;
    inputs
        .scope_proof
        .verify(inputs.scope_proof_body)
        .map_err(|_| RuntimeError::InvalidReceipt)?;
    let emitter = original
        .emitter
        .as_ref()
        .ok_or(RuntimeError::OwnerUnavailable)?;
    let attempt = original
        .restoration_activation
        .as_ref()
        .ok_or(RuntimeError::OwnerUnavailable)?;
    let phase = PacketRestorationActivationPhase::WorldActivate;
    attempt.authenticate_verified(phase)?;
    let artifact: PacketRestorationActivationArtifact =
        serde::Deserialize::deserialize(attempt.value(phase, 1)?)
            .map_err(|_| RuntimeError::InvalidReceipt)?;
    let scope = &artifact.request.scope;
    attempt.authenticate_original(
        source,
        controller,
        blake3::Hash::from_bytes(
            restoration_activation_scope_digest_data(scope)
                .map_err(|_| RuntimeError::InvalidReceipt)?,
        ),
    )?;
    scope
        .source_birth
        .verify(&original.banks[0])
        .map_err(|_| RuntimeError::InvalidReceipt)?;
    if scope.source_runtime != inputs.scope.source_record
        || scope.scope_proof != *inputs.scope_proof
        || scope.target.world != inputs.scope.target.world_binding_hash
        || scope.target.activation != inputs.scope.target.activation_id
        || scope.target.generation != inputs.scope.target.generation
        || scope.restoration.captured_owner_state != inputs.transfer.ticket.owner()?.state
        || scope.restoration.captured_control != inputs.transfer.journal.native_control
        || scope.restoration.captured_journal != *inputs.transfer.journal_reference
    {
        return Err(RuntimeError::ForeignAuthority);
    }
    let pair = controller
        .original_completed_installed_restoration_activation(emitter, phase)
        .map_err(|_| RuntimeError::InvalidReceipt)?;
    if pair.original().request_id.0.as_ref() != Some(inputs.request_id) {
        return Err(RuntimeError::ForeignAuthority);
    }
    recheck()?;
    authenticate_saved_pair(attempt, controller, emitter, phase, key, admitted)?;
    let body: crucible_node_transport::bodies::WorldActivateRequest =
        serde_json::from_value(serde_json::Value::Object(pair.original().body.clone()))
            .map_err(|_| RuntimeError::InvalidReceipt)?;
    authenticate_world_manifest(
        source,
        controller,
        &body,
        inputs.world.ok_or(RuntimeError::ForeignAuthority)?,
        admitted.maximum_activation_manifest_encoded_bytes_data(),
    )?;
    let record = attempt.native_record(phase)?;
    let bytes = controller
        .content(&record.native_receipt.native_record)
        .map_err(|_| RuntimeError::InvalidReceipt)?;
    let observed = controller
        .authenticate_original_installed_restoration_activation_evidence_data(
            emitter, phase, record, bytes,
        )
        .map_err(|_| RuntimeError::InvalidReceipt)?;
    let (reference, held) = historical_commit_hold(controller, emitter, original, scope)?;
    authenticate_restoration_activation_held_correspondence_data(record, &observed, &held)
        .map_err(|_| RuntimeError::InvalidReceipt)?;
    recheck()?;
    inspect(scope, &reference, &held)?;
    recheck()
}
