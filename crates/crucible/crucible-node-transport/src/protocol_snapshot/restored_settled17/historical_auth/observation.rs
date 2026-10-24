//! Joins the complete held restoration, Arm, World and first Observe histories.

use super::super::current_stages::CurrentActivation17;
use super::shared::*;
use super::*;
use crate::bodies::{RequestBody, decode_request};
use crate::envelope::Method;
use crate::reference_packet::service::ack_emitter::NativeAckBoot;
use crate::reference_packet::service::complete_restore::activation::*;
use crate::reference_packet::service::complete_restore::restoration_observe::*;
use crucible_node_format::{Validate, Visibility};

/// Checks one actual Arm or World pair against its complete retained MAC context.
///
/// Recorded milestone bits do not establish publication here. Actual SDK output
/// correspondence and shared-root identities remain separate parent predicates.
///
/// # Errors
/// Refuses missing partials, changed phase/scope/body/routing, assigned digest,
/// original artifact, complete correlated terminal or native proof.
pub(crate) fn authenticate_historical_activation_data(
    key: &[u8; 32],
    stage: &CurrentActivation17,
    scope: &PacketRestorationActivationScope,
    maximum_frame: usize,
) -> Result<(), ProviderError> {
    let artifact = stage.artifact.as_ref().ok_or_else(invalid)?;
    let context = stage.context.as_ref().ok_or_else(invalid)?;
    let pair = activation_pair(stage)?;
    completed_pair(pair, stage.phase.method(), maximum_frame)?;
    artifact.validate_data()?;
    if context.request != artifact.request
        || artifact.request.scope != *scope
        || artifact.request.phase != stage.phase
        || !pair.terminal.extensions.is_empty()
        || pair.original.extensions.len() != 1
    {
        return Err(invalid());
    }
    extension(
        pair.original,
        PACKET_RESTORATION_ACTIVATION_FEATURE,
        artifact,
        MAXIMUM_RESTORATION_ACTIVATION_ARTIFACT_BYTES,
    )?;
    let command = match decode_request(pair.original.method, &pair.original.body)? {
        RequestBody::Activate(body) => PacketRestorationActivationCommand::Arm(body),
        RequestBody::WorldActivate(body) => PacketRestorationActivationCommand::WorldActivate(body),
        _ => return Err(invalid()),
    };
    command.authenticate_request_data(&artifact.request)?;
    let target = &scope.target;
    if pair.original.session_id.0.as_ref() != Some(&target.session)
        || pair.original.incarnation_id.0.as_ref() != Some(&target.incarnation)
        || pair.original.node_id.0.as_ref() != Some(&target.node)
        || pair.original.execution_owner_id.0.as_ref() != Some(&target.owner)
        || pair.original.capture_owner_id.0.is_some()
        || pair.original.operation_id.0.is_some()
    {
        return Err(invalid());
    }
    digest_matches(
        &context.assigned_request,
        &restoration_activation_assigned_request_digest(pair.original, stage.phase, maximum_frame)?,
    )?;
    verify_restoration_activation_proof_data(key, context, &artifact.proof)?;
    if stage.phase == PacketRestorationActivationPhase::WorldActivate {
        let manifest = stage.manifest.as_ref().ok_or_else(invalid)?;
        manifest.validate()?;
        let RequestBody::WorldActivate(body) =
            decode_request(pair.original.method, &pair.original.body)?
        else {
            return Err(invalid());
        };
        verify_reference(&body.activation_manifest, manifest, maximum_frame)?;
        if manifest.transaction_id != target.transaction
            || manifest.activation_id != target.activation
            || manifest.world_generation != target.generation
            || manifest.gate_id != target.gate
            || manifest.world_binding_hash != target.world
        {
            return Err(invalid());
        }
    }
    Ok(())
}

/// Checks full first-Observe native and Source history without renewing currentness.
///
/// The caller independently joins this graph to the actual SDK four outputs and
/// raw Controller content dictionary. This function recomputes both referenced
/// proof bodies from their concrete DTOs and verifies their full ContentRefs.
/// A later current model may have advanced; the immutable held inventory is the
/// historical baseline for this first observation, never a substituted cursor.
///
/// # Errors
/// Refuses any earlier keyed history failure, incomplete actual pair, altered
/// World/Commit/Hold or Source scope, native artifact/body/context/assigned digest,
/// typed terminal/measurement, full native record, inventory or cached original.
pub(crate) fn authenticate_historical_restored_observation_data(
    key: &[u8; 32],
    source: &HistoricalRestoredObservation17Data<'_>,
    restoration: &HistoricalRestoration17<'_>,
    stages: HistoricalRestorationStages17<'_>,
    limits: HistoricalAuthLimits17,
) -> Result<(), ProviderError> {
    let maximum_frame = limits.maximum_frame_bytes;
    authenticate_historical_commit_data(
        key,
        &restoration.ack,
        &restoration.prepare,
        &restoration.commit,
        restoration.canonical_mapping,
        maximum_frame,
    )?;
    let arm = stages.arm;
    let world = stages.world;
    let stage = stages.first_observation;
    let artifact = stage.artifact.as_ref().ok_or_else(invalid)?;
    let context = stage.context.as_ref().ok_or_else(invalid)?;
    let scope = &artifact.request.scope;
    if arm.phase != PacketRestorationActivationPhase::Arm
        || world.phase != PacketRestorationActivationPhase::WorldActivate
        || context.request != artifact.request
        || stage.original.as_ref() != Some(source.original)
        || stage.terminal.as_ref() != Some(source.terminal)
        || restoration_activation_scope_digest_data(scope)? != *source.binding
    {
        return Err(invalid());
    }
    authenticate_scope(restoration, scope, maximum_frame)?;
    authenticate_historical_activation_data(key, arm, scope, maximum_frame)?;
    authenticate_historical_activation_data(key, world, scope, maximum_frame)?;
    let arm_pair = activation_pair(arm)?;
    let world_pair = activation_pair(world)?;
    let pair = HistoricalCompletedPair17 {
        original: source.original,
        terminal: source.terminal,
    };
    follows(restoration.commit.pair, arm_pair)?;
    follows(arm_pair, world_pair)?;
    follows(world_pair, pair)?;

    artifact.validate_data()?;
    extension(
        source.original,
        PACKET_RESTORATION_OBSERVE_FEATURE,
        artifact,
        MAXIMUM_RESTORATION_OBSERVE_ARTIFACT_BYTES,
    )?;
    let RequestBody::Observe(body) = decode_request(Method::Observe, &source.original.body)? else {
        return Err(invalid());
    };
    artifact.request.authenticate_body_data(&body)?;
    same_value(
        stage.body.as_ref().ok_or_else(invalid)?,
        &body,
        maximum_frame,
    )?;
    digest_matches(
        &context.assigned_request,
        &restoration_observe_assigned_request_digest(source.original, maximum_frame)?,
    )?;
    verify_restoration_observe_proof_data(key, context, &artifact.proof)?;
    verify_reference(
        &artifact.request.world_original,
        world_pair.original,
        maximum_frame,
    )?;
    verify_reference(
        &artifact.request.world_terminal,
        world_pair.terminal,
        maximum_frame,
    )?;

    let response = completed_pair(pair, Method::Observe, maximum_frame)?;
    if response != *source.response || !source.terminal.extensions.is_empty() {
        return Err(invalid());
    }
    let result = observe_result(&response)?;
    let measurement = observation_measurement(result, scope, source.original)?;
    let held = restoration.commit.held;
    if result.inventory_hash != held.inventory_hash {
        return Err(invalid());
    }
    source.record.validate_data()?;
    if source.record.physical_gate_held
        || source.record.restore_response != scope.restoration.commit_response
    {
        return Err(invalid());
    }
    let record_bytes = verify_reference(measurement, source.record, limits.maximum_evidence_bytes)?;
    let underlying_bytes =
        restored_underlying_bytes(source.underlying, limits.maximum_evidence_bytes)?;
    source
        .record
        .native_receipt
        .native_record
        .verify(&underlying_bytes)?;
    let native_pid = u32::try_from(restoration.ack.native_pid.get()).map_err(|_| invalid())?;
    let verified = source.record.native_receipt.verify_original_record_data(
        restoration.ack.selection,
        native_pid,
        source.original,
        &underlying_bytes,
    )?;
    if restored_underlying_bytes(&verified, limits.maximum_evidence_bytes)? != underlying_bytes {
        return Err(invalid());
    }
    authenticate_restoration_activation_held_correspondence_data(
        source.record,
        source.underlying,
        held,
    )?;

    let control = restoration.control;
    control.authenticate_local_groups_data()?;
    if control.historical_creator_data() != native_pid {
        return Err(invalid());
    }
    same_value(
        control.selection_data(),
        restoration.ack.selection,
        maximum_frame,
    )?;
    let hold = control.hold_data().ok_or_else(invalid)?;
    if hold.original_cursor_data() != held.local_cursor
        || hold.inventory_hash_data() != &held.inventory_hash
    {
        return Err(invalid());
    }
    for pair in [arm_pair, world_pair, pair] {
        cached_pair(control, pair)?;
    }
    if control.content_data().get(measurement).map(Vec::as_slice) != Some(record_bytes.as_slice())
        || control
            .content_data()
            .get(&source.record.native_receipt.native_record)
            .map(Vec::as_slice)
            != Some(underlying_bytes.as_slice())
    {
        return Err(invalid());
    }
    Ok(())
}

fn authenticate_scope(
    history: &HistoricalRestoration17<'_>,
    scope: &PacketRestorationActivationScope,
    maximum_frame: usize,
) -> Result<(), ProviderError> {
    let request = history.commit.request;
    let target = &request.prepare.restoration;
    let held = history.commit.held;
    let [binding] = history.ack.selection.realization.bindings.as_slice() else {
        return Err(invalid());
    };
    let expected = &history.ack.selection;
    let limits = NativeAckBoot::historical_ack_context_limits17_data();
    verify_reference(
        &scope.source_birth,
        history.ack.bindings.birth_association,
        limits[0],
    )?;
    if scope.source_runtime != target.source_runtime
        || scope.target.native_pid != history.ack.native_pid
        || scope.target.owner != target.target_owner
        || scope.target.owner_generation != target.target_owner_generation
        || scope.target.binding_hash != target.target_owner_binding
        || scope.target.world != target.target_world
        || scope.target.activation != target.target_activation
        || scope.target.generation != target.target_generation
        || scope.target.node != binding.compatibility.node_id
        || scope.target.session != history.ack.bindings.authority.session
        || scope.target.incarnation != history.ack.bindings.authority.incarnation
        || scope.target.prepared_token != expected.prepared_token
        || scope.target.admission != expected.admission
        || scope.target.transaction != expected.transaction
        || scope.target.gate != expected.gate
        || scope.restoration.captured_owner_state != target.owner_state
        || scope.restoration.captured_control != request.prepare.native_control
        || scope.restoration.captured_journal != target.journal
        || scope.restoration.mapping != target.mapping
        || scope.restoration.commit_request != held.restore_commit
        || scope.restoration.context_digest != held.context_digest
    {
        return Err(invalid());
    }
    verify_reference(
        &scope.restoration.commit_request,
        history.commit.pair.original,
        maximum_frame,
    )?;
    verify_reference(
        &scope.restoration.commit_response,
        history.commit.pair.terminal,
        maximum_frame,
    )?;
    Ok(())
}

fn activation_pair(
    stage: &CurrentActivation17,
) -> Result<HistoricalCompletedPair17<'_>, ProviderError> {
    Ok(HistoricalCompletedPair17 {
        original: stage.original.as_ref().ok_or_else(invalid)?,
        terminal: stage.terminal.as_ref().ok_or_else(invalid)?,
    })
}

fn observation_measurement<'a>(
    result: &'a crate::bodies::ObserveResult,
    scope: &PacketRestorationActivationScope,
    original: &Envelope,
) -> Result<&'a crucible_node_format::ContentRef, ProviderError> {
    result.validate()?;
    let [batch] = result.observations.as_slice() else {
        return Err(invalid());
    };
    let target = &scope.target;
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
        || batch.visibility != Visibility::Staged
        || !batch.extensions.is_empty()
    {
        return Err(invalid());
    }
    Ok(&batch.measurement_ref)
}
