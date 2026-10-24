//! Publishes only an independently admitted current Observe under one SourceRead.

use super::*;

impl PacketCompleteSemanticSource {
    pub(crate) fn call_original_current_observation_into(
        &self,
        controller: &mut CnpController,
        inputs: &OriginalInstalledRestorationObservationSigningInputs<'_>,
        claim: &OriginalRestoredSchedulingObservationClaim<'_>,
        retained: &mut Option<NativeSchedulingObservation>,
        returned: &mut Option<NativeSchedulingObservation>,
    ) -> Result<(), RuntimeError> {
        let row = claim.row_data();
        row.authenticate_owner_data(self, controller)?;
        claim.authenticate_current_data(self, controller)?;
        if retained.is_some() || returned.is_some() {
            return Err(RuntimeError::DuplicateOperation);
        }
        let (launch, raw5) = claim.launch_data();
        let expected = self.original_current_observation_construction_data(
            controller,
            row.read_owner,
            launch,
            raw5,
            row.ordinal,
            &row.first,
            row.maximum,
        )?;
        authenticate_same_row_data(row, &expected)?;
        let ancestry =
            self.original_verified_restoration_observation_data(controller, inputs, &row.first)?;
        drop(ancestry);

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
        let _attempt = AttemptGuard(&original.current_observations);
        let mut history = original
            .current_observations
            .try_borrow_mut()
            .map_err(|_| RuntimeError::OwnerBusy)?;
        // Poison before reserve/clone/assignment. Even an allocation failure
        // cannot renew this Source through another genuine Window or caller.
        history.poison_next_data(row.ordinal)?;
        let previous = match history.attempts.last() {
            None => [0; 32],
            Some(attempt) => {
                if attempt.stage != Stage::Verified
                    || attempt.signature != Some(validation::signature_data(attempt, key)?)
                {
                    return Err(RuntimeError::InvalidReceipt);
                }
                attempt
                    .sdk
                    .as_ref()
                    .ok_or(RuntimeError::OwnerUnavailable)?
                    .authenticate_current_pair_data(controller, emitter)
                    .map_err(|_| RuntimeError::InvalidReceipt)?;
                attempt.signature.ok_or(RuntimeError::InvalidReceipt)?
            }
        };
        history
            .attempts
            .try_reserve_exact(1)
            .map_err(|_| RuntimeError::ResourceLimit)?;
        history.attempts.push(CurrentObservationAttempt {
            row: *row,
            id: None,
            body: None,
            sdk: None,
            measurement: None,
            record: None,
            underlying: None,
            scheduling: None,
            previous,
            signature: None,
            stage: Stage::Started,
        });
        let attempt = history
            .attempts
            .last_mut()
            .ok_or(RuntimeError::OwnerUnavailable)?;
        attempt.body = Some(
            controller
                .original_restored_suffix_observation_body_data(emitter)
                .map_err(|_| RuntimeError::InvalidReceipt)?
                .clone(),
        );
        attempt.id = Some(request_id_data(row.ordinal)?);
        call.ensure_original_fresh_current_before_effect_data(&mut scratch)?;
        claim.authenticate_current_data(self, controller)?;
        if self.original_restored_suffix_observation_startup_data()? != row.startup {
            return Err(RuntimeError::ForeignAuthority);
        }
        {
            let mut marker = controller
                .prepare_original_restored_suffix_into(
                    emitter,
                    attempt
                        .id
                        .as_ref()
                        .ok_or(RuntimeError::OwnerUnavailable)?
                        .clone(),
                    None,
                    OriginalRestoredSuffixBody::Observe(
                        attempt
                            .body
                            .as_ref()
                            .ok_or(RuntimeError::OwnerUnavailable)?,
                    ),
                    crucible_node_format::Extensions::new(),
                    &mut attempt.sdk,
                )
                .map_err(|_| RuntimeError::InvalidReceipt)?;
            marker
                .original_data()
                .map_err(|_| RuntimeError::InvalidReceipt)?;
            call.ensure_original_fresh_current_before_effect_data(&mut scratch)?;
            claim.authenticate_current_data(self, row.controller)?;
            marker
                .publish_data(emitter)
                .map_err(|_| RuntimeError::InvalidReceipt)?;
        }
        attempt.stage = Stage::Published;
        restoration_activation::with_verified_world_under_read_data(
            self,
            controller,
            original,
            inputs.activation,
            &row.first.activation,
            key,
            || {
                call.ensure_original_fresh_current_before_effect_data(&mut scratch)?;
                claim.authenticate_current_data(self, controller)
            },
            |scope, reference, held| {
                validation::retain_proof_data(attempt, controller, emitter, scope)?;
                validation::authenticate_proof_data(attempt, controller, emitter, scope, held)?;
                inputs.authenticate_original_observation_hold_data(held, reference)
            },
        )?;
        let world = inputs
            .activation
            .world
            .ok_or(RuntimeError::ForeignAuthority)?;
        if !world.same_authority(claim.world_data()) {
            return Err(RuntimeError::ForeignAuthority);
        }
        attempt.scheduling = Some(scheduling::construct(
            self,
            world,
            attempt
                .measurement
                .as_ref()
                .ok_or(RuntimeError::OwnerUnavailable)?,
            attempt
                .underlying
                .as_ref()
                .ok_or(RuntimeError::OwnerUnavailable)?,
        )?);
        let actual = attempt
            .scheduling
            .as_ref()
            .ok_or(RuntimeError::OwnerUnavailable)?;
        scheduling::authenticate_bound(
            actual,
            row.first.scheduling_observation_requested_bytes_data(),
        )?;
        *retained = Some(actual.clone());
        *returned = Some(actual.clone());
        let signature = validation::signature_data(attempt, key)?;
        attempt.signature = Some(signature);
        call.complete(&mut scratch, || {
            claim.authenticate_terminal_member_data(self, controller)
        })?;
        attempt.stage = Stage::Verified;
        history.failed = false;
        drop(history);
        drop(_attempt);
        drop(birth);
        drop(association);
        let completion = validation::OriginalSourceRestoredObservationCompletion::new_data(
            self,
            controller,
            row.ordinal,
            signature,
        );
        claim.retain_source_completion_data(&completion)
    }
}

fn authenticate_same_row_data(
    admitted: &OriginalRestoredSchedulingObservationConstructionData,
    actual: &OriginalRestoredSchedulingObservationConstructionData,
) -> Result<(), RuntimeError> {
    admitted
        .provider
        .authenticate_same_quote_data(&actual.provider)
        .map_err(|_| RuntimeError::ForeignAuthority)?;
    admitted
        .first
        .authenticate_same_construction_data(&actual.first)?;
    if admitted.process != actual.process
        || admitted.thread != actual.thread
        || admitted.source != actual.source
        || admitted.controller != actual.controller
        || admitted.read_owner != actual.read_owner
        || admitted.ordinal != actual.ordinal
        || admitted.startup != actual.startup
        || admitted.retained
            != actual
                .retained
                .checked_add(admitted.runtime_retained)
                .ok_or(RuntimeError::ResourceLimit)?
        || admitted.transient
            != actual
                .transient
                .checked_add(admitted.runtime_transient)
                .ok_or(RuntimeError::ResourceLimit)?
        || admitted.scratch
            != actual
                .scratch
                .checked_add(admitted.runtime_scratch)
                .ok_or(RuntimeError::ResourceLimit)?
        || admitted.requested
            != sum(
                [admitted.retained, admitted.transient, admitted.scratch],
                admitted.maximum,
            )?
        || admitted.maximum != actual.maximum
    {
        return Err(RuntimeError::ForeignAuthority);
    }
    Ok(())
}

fn request_id_data(ordinal: u64) -> Result<Id, RuntimeError> {
    use std::fmt::Write;
    let mut value = String::new();
    value
        .try_reserve_exact(REQUEST_PREFIX.len() + 20)
        .map_err(|_| RuntimeError::ResourceLimit)?;
    value.push_str(REQUEST_PREFIX);
    write!(&mut value, "{ordinal}").map_err(|_| RuntimeError::InvalidReceipt)?;
    Id::new(value).map_err(|_| RuntimeError::InvalidReceipt)
}

pub(super) fn counter_scratch_data() -> usize {
    size_of::<ObserveRequest>()
        + size_of::<OriginalRestoredSuffixBody<'static>>()
        + size_of::<Option<ObserveRequest>>()
        + size_of::<Id>()
        + size_of::<String>()
        + size_of::<Result<Id, RuntimeError>>()
        + size_of::<Result<Id, crucible_node_format::ContractError>>()
        + size_of::<Result<(), std::fmt::Error>>()
        + size_of::<std::fmt::Arguments<'static>>()
        + size_of::<[u8; 20]>()
        + size_of::<OriginalSourceRestoredObservationCompletion<'static>>()
        + size_of::<&OriginalInstalledRestorationObservationSigningInputs<'static>>()
        + size_of::<&OriginalRestoredSchedulingObservationConstructionData>() * 2
        + size_of::<&OriginalRestoredSchedulingObservationClaim<'static>>()
        + size_of::<&mut Option<NativeSchedulingObservation>>() * 2
        + size_of::<&NativeSchedulingObservation>()
        + size_of::<Result<NativeSchedulingObservation, RuntimeError>>()
        + size_of::<Option<&NativeSchedulingObservation>>()
        + size_of::<Result<&NativeSchedulingObservation, RuntimeError>>()
        + size_of::<Result<(), RuntimeError>>()
}
