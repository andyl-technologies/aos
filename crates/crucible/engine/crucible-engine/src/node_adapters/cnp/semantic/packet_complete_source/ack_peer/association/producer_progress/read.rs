//! Keeps one owning Source read across exactly one already-spent phase.

use super::*;
use crucible_node_transport::reference_packet::service::complete_restore::PacketNativeRestoredCommitHold;

pub(super) fn run_phase_data<'a>(
    source: &'a PacketCompleteSemanticSource,
    controller: &'a mut CnpController,
    inputs: &OriginalInstalledRestorationObservationSigningInputs<'_>,
    claim: &OriginalRestoredProducerExecutionClaim<'_>,
    original_admission: &OperationAdmission,
    effect: impl FnOnce(
        &mut ProducerProgressAttempt,
        &mut CnpController,
        &OriginalAckPeerAssociation,
        &mut dyn FnMut() -> Result<(), RuntimeError>,
    ) -> Result<(), RuntimeError>,
    validate: impl FnOnce(
        &mut ProducerProgressAttempt,
        &CnpController,
        &OriginalAckPeerAssociation,
        (
            &PacketNativeRestoredRecord,
            &PacketNativeRecord,
            &ContentRef,
        ),
        &PacketNativeRestoredCommitHold,
    ) -> Result<(), RuntimeError>,
) -> Result<OriginalSourceRestoredProducerPhaseCompletion<'a>, RuntimeError> {
    claim.authenticate_current_data(source, controller)?;
    let (launch, raw5) = claim.launch_data();
    source.authenticate_original_restored_producer_launch_data(launch, raw5)?;
    claim.authenticate_inputs_data(inputs)?;
    let association = source
        .ack_peer_association
        .try_borrow()
        .map_err(|_| RuntimeError::OwnerBusy)?;
    let original = association.as_ref().ok_or(RuntimeError::OwnerUnavailable)?;
    original.authenticate_transfer_ready_data()?;
    let native = original
        .native
        .as_ref()
        .ok_or(RuntimeError::OwnerUnavailable)?;
    let birth = source
        .ack_peer_birth
        .try_borrow()
        .map_err(|_| RuntimeError::OwnerBusy)?;
    let key = birth
        .as_ref()
        .ok_or(RuntimeError::OwnerUnavailable)?
        .original_fresh_query_key_data()?;
    let mut scratch = native.original_fresh_current_scratch()?;
    let call = native.begin_original_fresh_query_call_data(&mut scratch)?;
    let guard = AttemptGuard::new(&original.producer_progress);
    let mut history = original
        .producer_progress
        .try_borrow_mut()
        .map_err(|_| RuntimeError::OwnerBusy)?;
    history.origin_data()?;
    if history.failed {
        return Err(RuntimeError::OutstandingObligations);
    }
    let phase = claim.phase_data();
    if phase == ProducerExecutionPhase::Begin {
        history.require_verified_prefix_data()?;
        if history
            .attempts
            .last()
            .is_some_and(|attempt| attempt.slot >= claim.slot_data())
        {
            return Err(RuntimeError::ForeignAuthority);
        }
        let previous = history.attempts.last().map_or(Ok([0; 32]), |attempt| {
            attempt.signature.ok_or(RuntimeError::InvalidReceipt)
        })?;
        history.failed = true;
        if history.attempts.len() >= source.installation().maximum_operations {
            return Err(RuntimeError::ResourceLimit);
        }
        let requested_slots = history
            .attempts
            .len()
            .checked_add(1)
            .ok_or(RuntimeError::ResourceLimit)?;
        history
            .attempts
            .try_reserve_exact(1)
            .map_err(|_| RuntimeError::ResourceLimit)?;
        if history.attempts.capacity() > requested_slots {
            return Err(RuntimeError::ResourceLimit);
        }
        history.attempts.push(ProducerProgressAttempt::new_data(
            *claim.row_data(),
            claim.slot_data(),
            previous,
        ));
    } else {
        let attempt = history
            .attempts
            .last()
            .ok_or(RuntimeError::OwnerUnavailable)?;
        let stage_ok = match phase {
            ProducerExecutionPhase::Poll => attempt.stage.get() == Stage::Begun,
            ProducerExecutionPhase::Publication => {
                matches!(attempt.stage.get(), Stage::Completed | Stage::Durable)
            }
            ProducerExecutionPhase::Retirement => attempt.stage.get() == Stage::Durable,
            ProducerExecutionPhase::Observation => attempt.stage.get() == Stage::Retired,
            ProducerExecutionPhase::Begin => false,
        };
        if !stage_ok || attempt.signature != Some(proof::signature_data(attempt, key)?) {
            return Err(RuntimeError::InvalidReceipt);
        }
        attempt.authenticate_admission_data(original_admission)?;
        history.failed = true;
    }
    let (attempt, earlier) = history
        .attempts
        .split_last_mut()
        .ok_or(RuntimeError::OwnerUnavailable)?;
    if attempt.slot != claim.slot_data() {
        return Err(RuntimeError::ForeignAuthority);
    }
    construction::authenticate_source_row_data(claim.row_data(), &attempt.row)?;
    let checkpoint = match earlier.last() {
        Some(prior) => (
            prior
                .checkpoint_record
                .as_ref()
                .ok_or(RuntimeError::OwnerUnavailable)?,
            prior.checkpoint_producer_data()?,
            prior
                .checkpoint_measurement
                .as_ref()
                .ok_or(RuntimeError::OwnerUnavailable)?,
        ),
        None => original
            .restoration_observation
            .as_ref()
            .ok_or(RuntimeError::OwnerUnavailable)?
            .original_producer_checkpoint_data()?,
    };
    super::super::restoration_activation::with_verified_world_under_read_data(
        source,
        controller,
        original,
        inputs.activation,
        inputs.activation.source_construction,
        key,
        || {
            call.ensure_original_fresh_current_before_effect_data(&mut scratch)?;
            claim.authenticate_current_data(source, claim.row_data().controller)
        },
        |_, reference, held| {
            inputs.authenticate_original_observation_hold_data(held, reference)?;
            if matches!(
                phase,
                ProducerExecutionPhase::Publication | ProducerExecutionPhase::Retirement
            ) {
                proof::authenticate_completed_data(
                    attempt,
                    controller,
                    original,
                    checkpoint,
                    claim.launch_data().0,
                    held,
                )?;
            }
            Ok(())
        },
    )?;
    effect(attempt, controller, original, &mut || {
        call.ensure_original_fresh_current_before_effect_data(&mut scratch)?;
        claim.authenticate_current_data(source, claim.row_data().controller)
    })?;
    super::super::restoration_activation::with_verified_world_under_read_data(
        source,
        controller,
        original,
        inputs.activation,
        inputs.activation.source_construction,
        key,
        || {
            call.ensure_original_fresh_current_before_effect_data(&mut scratch)?;
            claim.authenticate_current_data(source, claim.row_data().controller)
        },
        |_, reference, held| {
            inputs.authenticate_original_observation_hold_data(held, reference)?;
            validate(attempt, controller, original, checkpoint, held)
        },
    )?;
    let signature = proof::signature_data(attempt, key)?;
    attempt.signature = Some(signature);
    call.complete(&mut scratch, || {
        claim.authenticate_terminal_member_data(source, controller)
    })?;
    attempt.stage.set(match phase {
        ProducerExecutionPhase::Begin => Stage::Begun,
        ProducerExecutionPhase::Poll => Stage::Completed,
        ProducerExecutionPhase::Publication => {
            if attempt
                .durable_root
                .try_borrow()
                .map_err(|_| RuntimeError::OwnerBusy)?
                .is_some()
            {
                Stage::Durable
            } else {
                Stage::Completed
            }
        }
        ProducerExecutionPhase::Retirement => Stage::Retired,
        ProducerExecutionPhase::Observation => Stage::Verified,
    });
    history.failed = false;
    guard.complete_data();
    drop(history);
    drop(guard);
    drop(birth);
    drop(association);
    Ok(OriginalSourceRestoredProducerPhaseCompletion::new_data(
        source,
        controller,
        claim.slot_data(),
        phase,
        signature,
    ))
}
