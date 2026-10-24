//! Spends real Core phases while retaining every assigned SDK and proof owner.

use super::*;
use crate::node_contract::OriginalRuntimeOperationDispatch;
use crucible_node_transport::envelope::Nullable;
use crucible_node_transport::reference_packet::service::complete_restore::PacketNativeRestoredCommitHold;

impl PacketCompleteSemanticSource {
    /// Publishes the genuine admitted no-input Begin under its owning read.
    ///
    /// # Errors
    /// Refuses another exact phase, admission, quote, native proof or final fence; all initialized attempts remain retained.
    pub(crate) fn call_original_restored_producer_begin_data(
        &self,
        controller: &mut CnpController,
        inputs: &OriginalInstalledRestorationObservationSigningInputs<'_>,
        claim: &OriginalRestoredProducerExecutionClaim<'_>,
        dispatch: &OriginalRuntimeOperationDispatch<'_>,
    ) -> Result<(), RuntimeError> {
        let original = dispatch.admission_data();
        dispatch.authenticate_original_data(
            original,
            claim.world_data(),
            original.token().route(),
        )?;
        if claim.phase_data() != ProducerExecutionPhase::Begin {
            return Err(RuntimeError::ForeignAuthority);
        }
        claim.with_original_grant_data(|grant| {
            if grant.operation() != original.token().operation()
                || grant.node() != &original.token().route().node
                || &grant.request() != original.request()
                || !grant.activation().same_authority(original.activation())
            {
                return Err(RuntimeError::ForeignAuthority);
            }
            Ok(())
        })?;
        let (launch, raw5) = claim.launch_data();
        let expected = claim.with_original_grant_data(|grant| {
            self.original_restored_producer_execution_construction_data(
                controller,
                claim.row_data().read_owner,
                launch,
                raw5,
                grant,
                inputs,
                inputs.source_construction,
                claim.row_data().maximum,
            )
        })?;
        construction::authenticate_source_row_data(claim.row_data(), &expected)?;
        let completion = read::run_phase_data(
            self,
            controller,
            inputs,
            claim,
            original,
            |attempt, controller, association, recheck| {
                attempt.admission = Some(original.clone());
                let slots = attempt.row.provider.maximum_originals_data();
                attempt
                    .uploads
                    .try_reserve_exact(slots)
                    .map_err(|_| RuntimeError::ResourceLimit)?;
                attempt
                    .upload_bodies
                    .try_reserve_exact(slots)
                    .map_err(|_| RuntimeError::ResourceLimit)?;
                attempt
                    .request_ids
                    .try_reserve_exact(slots)
                    .map_err(|_| RuntimeError::ResourceLimit)?;
                if attempt.uploads.capacity() > slots
                    || attempt.upload_bodies.capacity() > slots
                    || attempt.request_ids.capacity() > slots
                {
                    return Err(RuntimeError::ResourceLimit);
                }
                let installation = self.installation();
                attempt.authorization = Some(crate::node_adapters::cnp::semantic::packet_grant::packet_complete_grant_authorization(
                    installation, original, U64::new(0), &original.activation().record().owners,
                ).map_err(|_| RuntimeError::InvalidReceipt)?);
                sdk::upload_data(attempt, controller, association, true, recheck)?;
                let interval =
                    construction::operation_data(original.token().operation(), original.request())?;
                let world = original.activation().record();
                attempt.arguments = Some(ExactRunArguments {
                    grant_id: original.token().operation().clone(),
                    participant_ids: installation.owner.owner.participant_ids.clone(),
                    realization_id: installation.realize.realization_id.clone(),
                    activation_id: world.activation_id.clone(),
                    world_generation: world.generation,
                    owner_generation: installation.binding.authority.owner_generation,
                    input_epoch: installation.binding.authority.input_epoch.clone(),
                    mode: crucible_node_format::OperatingMode::Exact,
                    ordering_profile: "superdense-v1".into(),
                    start: interval.start,
                    limit: interval.limit,
                    boundary_policy: BoundaryPolicy::OrdinaryStop,
                    input_authorization: attempt
                        .authorization
                        .as_ref()
                        .ok_or(RuntimeError::OwnerUnavailable)?
                        .reference
                        .clone(),
                    input_watermark: U64::new(0),
                });
                let value = serde_json::to_value(
                    attempt
                        .arguments
                        .as_ref()
                        .ok_or(RuntimeError::OwnerUnavailable)?,
                )
                .map_err(|_| RuntimeError::InvalidReceipt)?;
                let serde_json::Value::Object(arguments) = value else {
                    return Err(RuntimeError::InvalidReceipt);
                };
                attempt.begin_body = Some(BeginRequest {
                    kind: interval.kind,
                    binding_hash: installation
                        .owner
                        .identity()
                        .map_err(|_| RuntimeError::InvalidReceipt)?,
                    owner_generation: installation.binding.authority.owner_generation,
                    activation_id: Nullable(Some(world.activation_id.clone())),
                    world_generation: world.generation,
                    arguments,
                    extensions: Extensions::new(),
                });
                let id = sdk::request_id_data(attempt.slot, "begin", 0)?;
                recheck()?;
                let emitter = association
                    .emitter
                    .as_ref()
                    .ok_or(RuntimeError::OwnerUnavailable)?;
                let mut marker = controller
                    .prepare_original_restored_suffix_into(
                        emitter,
                        id,
                        Some(original.token().operation().clone()),
                        OriginalRestoredSuffixBody::Begin(
                            attempt
                                .begin_body
                                .as_ref()
                                .ok_or(RuntimeError::OwnerUnavailable)?,
                        ),
                        Extensions::new(),
                        &mut attempt.begin,
                    )
                    .map_err(|_| RuntimeError::InvalidReceipt)?;
                marker
                    .original_data()
                    .map_err(|_| RuntimeError::InvalidReceipt)?;
                recheck()?;
                marker
                    .publish_data(emitter)
                    .map_err(|_| RuntimeError::InvalidReceipt)?;
                drop(marker);
                proof::retain_native_data(attempt, controller, emitter, false)
            },
            |attempt, _, _, checkpoint, held| {
                let record = attempt
                    .completed_record
                    .as_ref()
                    .ok_or(RuntimeError::OwnerUnavailable)?;
                let producer = attempt.producer_data()?;
                // Begin has its own actual native proof, but Poll is still a
                // separate required phase before common Outcome publication.
                if producer
                    .grant
                    .as_ref()
                    .is_none_or(|grant| grant.operation != *original.token().operation())
                    || producer.inventory.reached < checkpoint.1.inventory.reached
                    || record.native_receipt.owner != held.target_owner
                    || record.native_receipt.world != held.target_world
                {
                    return Err(RuntimeError::InvalidReceipt);
                }
                Ok(())
            },
        )?;
        claim.retain_source_phase_completion_data(&completion)
    }

    /// Retains the actual Poll and both independently funded common Outcomes.
    ///
    /// # Errors
    /// Refuses occupied outputs, a non-Poll claim, changed original/native evidence or any failed final fence.
    pub(crate) fn call_original_restored_producer_poll_into(
        &self,
        controller: &mut CnpController,
        inputs: &OriginalInstalledRestorationObservationSigningInputs<'_>,
        claim: &OriginalRestoredProducerExecutionClaim<'_>,
        original: &OperationAdmission,
        retained: &mut Option<OperationOutcome>,
        returned: &mut Option<OperationOutcome>,
    ) -> Result<(), RuntimeError> {
        if claim.phase_data() != ProducerExecutionPhase::Poll {
            return Err(RuntimeError::ForeignAuthority);
        }
        if retained.is_some() || returned.is_some() {
            return Err(RuntimeError::DuplicateOperation);
        }
        let completion = read::run_phase_data(
            self,
            controller,
            inputs,
            claim,
            original,
            |attempt, controller, association, recheck| {
                attempt.poll_body = Some(PollRequest {
                    after_observation_sequence: U64::new(0),
                    extensions: Extensions::new(),
                });
                let id = sdk::request_id_data(attempt.slot, "poll", 0)?;
                let emitter = association
                    .emitter
                    .as_ref()
                    .ok_or(RuntimeError::OwnerUnavailable)?;
                recheck()?;
                let mut marker = controller
                    .prepare_original_restored_suffix_into(
                        emitter,
                        id,
                        Some(original.token().operation().clone()),
                        OriginalRestoredSuffixBody::Poll(
                            attempt
                                .poll_body
                                .as_ref()
                                .ok_or(RuntimeError::OwnerUnavailable)?,
                        ),
                        Extensions::new(),
                        &mut attempt.poll,
                    )
                    .map_err(|_| RuntimeError::InvalidReceipt)?;
                marker
                    .original_data()
                    .map_err(|_| RuntimeError::InvalidReceipt)?;
                recheck()?;
                marker
                    .publish_data(emitter)
                    .map_err(|_| RuntimeError::InvalidReceipt)
            },
            |attempt, controller, association, checkpoint, held| {
                proof::authenticate_completed_data(
                    attempt,
                    controller,
                    association,
                    checkpoint,
                    claim.launch_data().0,
                    held,
                )?;
                attempt.outcome = Some(
                    self.original_restored_producer_mapped_outcome_data(
                        original,
                        attempt
                            .completed_record
                            .as_ref()
                            .ok_or(RuntimeError::OwnerUnavailable)?,
                        attempt.producer_data()?,
                        attempt
                            .completed_measurement
                            .as_ref()
                            .ok_or(RuntimeError::OwnerUnavailable)?,
                    )?,
                );
                publication::retain_report_data(attempt)?;
                let actual = attempt
                    .outcome
                    .as_ref()
                    .ok_or(RuntimeError::OwnerUnavailable)?;
                *retained = Some(actual.clone());
                *returned = Some(actual.clone());
                Ok(())
            },
        )?;
        claim.retain_source_phase_completion_data(&completion)
    }

    /// Retires the actual consumed originals after the concrete durable ACK.
    ///
    /// # Errors
    /// Refuses a non-Retirement claim, absent actual durable root, changed consumption, partial reply or stale read.
    pub(crate) fn call_original_restored_producer_retire_data(
        &self,
        controller: &mut CnpController,
        inputs: &OriginalInstalledRestorationObservationSigningInputs<'_>,
        claim: &OriginalRestoredProducerExecutionClaim<'_>,
        original: &OperationAdmission,
    ) -> Result<(), RuntimeError> {
        if claim.phase_data() != ProducerExecutionPhase::Retirement {
            return Err(RuntimeError::ForeignAuthority);
        }
        let completion = read::run_phase_data(
            self,
            controller,
            inputs,
            claim,
            original,
            |attempt, controller, association, recheck| {
                if attempt
                    .durable_root
                    .try_borrow()
                    .map_err(|_| RuntimeError::OwnerBusy)?
                    .is_none()
                {
                    return Err(RuntimeError::OutstandingObligations);
                }
                let outcome = attempt
                    .outcome
                    .as_ref()
                    .ok_or(RuntimeError::OwnerUnavailable)?;
                // The genuine Runtime Retirement phase is issued only after its
                // actual Scheduler accepts the same durable common ACK.
                attempt.consumption_value = Some(
                    serde_json::json!({"schema":"source-owned.packet-consumption.v1", "operation": outcome.operation, "outputs": outcome.retained_outputs}),
                );
                let bytes = canonical::canonical_json(
                    attempt
                        .consumption_value
                        .as_ref()
                        .ok_or(RuntimeError::OwnerUnavailable)?,
                )
                .map_err(|_| RuntimeError::InvalidReceipt)?;
                if bytes.len() > 8192 {
                    return Err(RuntimeError::ResourceLimit);
                }
                attempt.consumption = Some(crate::node_scheduling::InputPayload {
                    reference: canonical::content_ref(&bytes, "application/json")
                        .map_err(|_| RuntimeError::InvalidReceipt)?,
                    bytes,
                });
                sdk::upload_data(attempt, controller, association, false, recheck)?;
                let (begin, _, _) = attempt
                    .begin
                    .as_ref()
                    .ok_or(RuntimeError::OwnerUnavailable)?
                    .completed_pair_data()
                    .map_err(|_| RuntimeError::InvalidReceipt)?;
                attempt.retire_body = Some(RetireRequest {
                    request_ids: vec![
                        begin
                            .request_id
                            .0
                            .as_ref()
                            .ok_or(RuntimeError::OwnerUnavailable)?
                            .clone(),
                    ],
                    operation_ids: vec![original.token().operation().clone()],
                    disposition: RetirementDisposition::Consumed,
                    custody_receipt: Nullable(Some(
                        attempt
                            .consumption
                            .as_ref()
                            .ok_or(RuntimeError::OwnerUnavailable)?
                            .reference
                            .clone(),
                    )),
                    extensions: Extensions::new(),
                });
                let id = sdk::request_id_data(attempt.slot, "retire", 0)?;
                let emitter = association
                    .emitter
                    .as_ref()
                    .ok_or(RuntimeError::OwnerUnavailable)?;
                recheck()?;
                let mut marker = controller
                    .prepare_original_restored_suffix_into(
                        emitter,
                        id,
                        None,
                        OriginalRestoredSuffixBody::Retire(
                            attempt
                                .retire_body
                                .as_ref()
                                .ok_or(RuntimeError::OwnerUnavailable)?,
                        ),
                        Extensions::new(),
                        &mut attempt.retire,
                    )
                    .map_err(|_| RuntimeError::InvalidReceipt)?;
                marker
                    .original_data()
                    .map_err(|_| RuntimeError::InvalidReceipt)?;
                recheck()?;
                marker
                    .publish_data(emitter)
                    .map_err(|_| RuntimeError::InvalidReceipt)
            },
            |attempt, _, _, _, _| {
                let (_, _, typed) = attempt
                    .retire
                    .as_ref()
                    .ok_or(RuntimeError::OwnerUnavailable)?
                    .completed_pair_data()
                    .map_err(|_| RuntimeError::InvalidReceipt)?;
                let request = attempt
                    .retire_body
                    .as_ref()
                    .ok_or(RuntimeError::OwnerUnavailable)?;
                let Some(MethodResult::Retire(result)) = &typed.result else {
                    return Err(RuntimeError::InvalidReceipt);
                };
                if !matches!(&typed.shape, ResponseShape::Completed { extensions, .. } if extensions.is_empty())
                    || result.retired_request_ids != request.request_ids
                    || result.retired_operation_ids != request.operation_ids
                {
                    return Err(RuntimeError::InvalidReceipt);
                }
                Ok(())
            },
        )?;
        claim.retain_source_phase_completion_data(&completion)
    }

    /// Retains the fresh grant-free post-Retire checkpoint and both node copies.
    ///
    /// # Errors
    /// Refuses a non-Observation claim, occupied outputs, changed retirement/progress evidence or any stale frontier.
    pub(crate) fn call_original_restored_producer_observe_into(
        &self,
        controller: &mut CnpController,
        inputs: &OriginalInstalledRestorationObservationSigningInputs<'_>,
        claim: &OriginalRestoredProducerExecutionClaim<'_>,
        original: &OperationAdmission,
        retained: &mut Option<crate::node_scheduling::NativeSchedulingObservation>,
        returned: &mut Option<crate::node_scheduling::NativeSchedulingObservation>,
    ) -> Result<(), RuntimeError> {
        if claim.phase_data() != ProducerExecutionPhase::Observation {
            return Err(RuntimeError::ForeignAuthority);
        }
        if retained.is_some() || returned.is_some() {
            return Err(RuntimeError::DuplicateOperation);
        }
        let completion = read::run_phase_data(
            self,
            controller,
            inputs,
            claim,
            original,
            |attempt, controller, association, recheck| {
                let emitter = association
                    .emitter
                    .as_ref()
                    .ok_or(RuntimeError::OwnerUnavailable)?;
                attempt.observe_body = Some(
                    controller
                        .original_restored_suffix_observation_body_data(emitter)
                        .map_err(|_| RuntimeError::InvalidReceipt)?
                        .clone(),
                );
                let id = sdk::request_id_data(attempt.slot, "observe", 0)?;
                recheck()?;
                let mut marker = controller
                    .prepare_original_restored_suffix_into(
                        emitter,
                        id,
                        None,
                        OriginalRestoredSuffixBody::Observe(
                            attempt
                                .observe_body
                                .as_ref()
                                .ok_or(RuntimeError::OwnerUnavailable)?,
                        ),
                        Extensions::new(),
                        &mut attempt.observe,
                    )
                    .map_err(|_| RuntimeError::InvalidReceipt)?;
                marker
                    .original_data()
                    .map_err(|_| RuntimeError::InvalidReceipt)?;
                recheck()?;
                marker
                    .publish_data(emitter)
                    .map_err(|_| RuntimeError::InvalidReceipt)?;
                drop(marker);
                proof::retain_native_data(attempt, controller, emitter, true)
            },
            |attempt, controller, association, checkpoint, held| {
                proof::authenticate_completed_data(
                    attempt,
                    controller,
                    association,
                    checkpoint,
                    claim.launch_data().0,
                    held,
                )?;
                let completed =
                    proof::completed_data(attempt, checkpoint, claim.launch_data().0, held)?;
                let root = attempt
                    .durable_root
                    .try_borrow()
                    .map_err(|_| RuntimeError::OwnerBusy)?;
                let consumption = attempt
                    .consumption
                    .as_ref()
                    .ok_or(RuntimeError::OwnerUnavailable)?;
                authenticate_restored_producer_retired_data(&PacketRestoredProducerRetiredData {
                    completed: &completed,
                    consumption: &consumption.reference,
                    canonical_consumption: &consumption.bytes,
                    durable_root: root.as_ref().ok_or(RuntimeError::OwnerUnavailable)?,
                    retire: attempt
                        .retire
                        .as_ref()
                        .ok_or(RuntimeError::OwnerUnavailable)?,
                    observe: attempt
                        .observe
                        .as_ref()
                        .ok_or(RuntimeError::OwnerUnavailable)?,
                    restored: attempt
                        .checkpoint_record
                        .as_ref()
                        .ok_or(RuntimeError::OwnerUnavailable)?,
                    producer: attempt.checkpoint_producer_data()?,
                    measurement: attempt
                        .checkpoint_measurement
                        .as_ref()
                        .ok_or(RuntimeError::OwnerUnavailable)?,
                })
                .map_err(|_| RuntimeError::InvalidReceipt)?;
                attempt
                    .observe
                    .as_ref()
                    .ok_or(RuntimeError::OwnerUnavailable)?
                    .authenticate_current_pair_data(
                        controller,
                        association
                            .emitter
                            .as_ref()
                            .ok_or(RuntimeError::OwnerUnavailable)?,
                    )
                    .map_err(|_| RuntimeError::InvalidReceipt)?;
                drop(root);
                attempt.scheduling = Some(
                    self.original_restored_producer_checkpoint_scheduling_data(
                        claim.world_data(),
                        attempt
                            .checkpoint_record
                            .as_ref()
                            .ok_or(RuntimeError::OwnerUnavailable)?,
                        attempt.checkpoint_producer_data()?,
                        attempt
                            .checkpoint_measurement
                            .as_ref()
                            .ok_or(RuntimeError::OwnerUnavailable)?,
                    )?,
                );
                let actual = attempt
                    .scheduling
                    .as_ref()
                    .ok_or(RuntimeError::OwnerUnavailable)?;
                *retained = Some(actual.clone());
                *returned = Some(actual.clone());
                Ok(())
            },
        )?;
        claim.retain_source_phase_completion_data(&completion)
    }
}

pub(super) fn counter_scratch_data() -> usize {
    size_of::<OriginalSourceRestoredProducerPhaseCompletion<'static>>()
        + size_of::<&OriginalRestoredProducerExecutionClaim<'static>>()
        + size_of::<&OriginalInstalledRestorationObservationSigningInputs<'static>>()
        + size_of::<&OriginalRuntimeOperationDispatch<'static>>()
        + size_of::<&OperationAdmission>()
        + size_of::<(
            &mut ProducerProgressAttempt,
            &mut CnpController,
            &OriginalAckPeerAssociation,
        )>()
        + size_of::<(
            &mut ProducerProgressAttempt,
            &CnpController,
            &OriginalAckPeerAssociation,
            (
                &PacketNativeRestoredRecord,
                &PacketNativeRecord,
                &ContentRef,
            ),
            &PacketNativeRestoredCommitHold,
        )>()
        + size_of::<(&mut ProducerProgressAttempt, &mut [ProducerProgressAttempt])>()
        + size_of::<Option<(&mut ProducerProgressAttempt, &mut [ProducerProgressAttempt])>>()
        + size_of::<
            Result<(&mut ProducerProgressAttempt, &mut [ProducerProgressAttempt]), RuntimeError>,
        >()
        + size_of::<&mut dyn FnMut() -> Result<(), RuntimeError>>()
        + size_of::<Option<ExactRunArguments>>()
        + size_of::<Result<serde_json::Value, serde_json::Error>>()
        + size_of::<Result<Id, RuntimeError>>()
        + size_of::<Result<Id, crucible_node_format::ContractError>>()
        + size_of::<String>()
        + size_of::<[u8; 20]>() * 2
        + size_of::<std::fmt::Arguments<'static>>()
        + size_of::<Result<(), std::fmt::Error>>()
        + size_of::<Result<(), std::collections::TryReserveError>>()
        + size_of::<Result<usize, std::num::TryFromIntError>>()
        + size_of::<Option<u64>>()
        + size_of::<Result<usize, RuntimeError>>()
        + size_of::<Result<(), RuntimeError>>()
        + size_of::<Result<OperationOutcome, RuntimeError>>()
        + size_of::<Option<OperationOutcome>>() * 2
        + size_of::<Result<crate::node_scheduling::NativeSchedulingObservation, RuntimeError>>()
        + size_of::<Option<crate::node_scheduling::NativeSchedulingObservation>>() * 2
        + size_of::<std::ops::Range<usize>>()
        + size_of::<std::slice::Chunks<'static, u8>>()
        + size_of::<std::iter::Enumerate<std::slice::Chunks<'static, u8>>>()
        + size_of::<UploadBody>()
        + size_of::<BlobBeginRequest>()
        + size_of::<BlobChunkRequest>()
        + size_of::<BlobFinishRequest>()
        + OriginalRestoredSuffixHostAttempt::counter_scratch_data()
}
