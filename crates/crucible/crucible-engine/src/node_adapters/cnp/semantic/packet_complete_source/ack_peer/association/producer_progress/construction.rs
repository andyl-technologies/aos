//! Quotes the whole new SDK, native, Source and result lifetime independently.

use super::*;
use crate::node_scheduling::ExecutionAdmission;
use crucible_node_transport::reference_packet::service::native_startup::{
    PacketRestoredProducerArgumentsData, PacketRestoredProducerLifecycleInputs,
    original_restored_producer_lifecycle_counter_scratch_data,
    original_restored_producer_lifecycle_storage_data,
};

impl PacketCompleteSemanticSource {
    /// Quotes independent new construction from the actual grant and checkpoint.
    ///
    /// No prior future row or retained owner is refunded. The Core caller funds
    /// a separate read/quote window before invoking this borrowed producer.
    ///
    /// # Errors
    /// Refuses another owner, input, program, incomplete history, stale current
    /// checkpoint, unsupported grant or any unchanged construction ceiling.
    pub(crate) fn original_restored_producer_execution_construction_data(
        &self,
        controller: &CnpController,
        read_owner: *const (),
        launch: &PacketNative5SourceLaunch,
        raw5: &[u8],
        grant: &ExecutionAdmission,
        inputs: &OriginalInstalledRestorationObservationSigningInputs<'_>,
        first: &OriginalSourceRestorationObservationConstructionData,
        maximum: usize,
    ) -> Result<OriginalRestoredProducerExecutionConstructionData, RuntimeError> {
        self.storage_origin_with_error::<RuntimeError>()?;
        self.authenticate_original_restored_producer_launch_data(launch, raw5)?;
        if read_owner.is_null()
            || grant.input_batch().is_some()
            || !inputs
                .activation
                .world
                .is_some_and(|world| world.same_authority(grant.activation()))
            || grant.node() != &self.installation().descriptor.id
        {
            return Err(RuntimeError::ForeignAuthority);
        }
        let operation = operation_data(grant.operation(), &grant.request())?;
        let startup = self.original_restored_suffix_observation_startup_data()?;
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
        emitter
            .authenticate_original(controller)
            .map_err(|_| RuntimeError::ForeignAuthority)?;
        let history = original
            .producer_progress
            .try_borrow()
            .map_err(|_| RuntimeError::OwnerBusy)?;
        history.require_verified_prefix_data()?;
        if history.attempts.len() >= self.installation().maximum_operations {
            return Err(RuntimeError::ResourceLimit);
        }
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
        proof::authenticate_checkpoint_data(&history, original, controller, emitter, key)?;
        let (checkpoint, producer, measurement) = history.checkpoint_data(original)?;
        authenticate_supported_stop_data(&producer.inventory.pending, operation.limit)?;
        let raw_checkpoint = controller
            .content(measurement)
            .map_err(|_| RuntimeError::InvalidReceipt)?;
        measurement
            .verify(raw_checkpoint)
            .map_err(|_| RuntimeError::InvalidReceipt)?;
        let raw_producer = controller
            .content(&checkpoint.native_receipt.native_record)
            .map_err(|_| RuntimeError::InvalidReceipt)?;
        checkpoint
            .native_receipt
            .native_record
            .verify(raw_producer)
            .map_err(|_| RuntimeError::InvalidReceipt)?;
        let mut quoted = None;
        super::super::restoration_activation::with_verified_world_under_read_data(
            self,
            controller,
            original,
            inputs.activation,
            inputs.activation.source_construction,
            key,
            || call.ensure_original_fresh_current_before_effect_data(&mut scratch),
            |_, reference, held| {
                inputs.authenticate_original_observation_hold_data(held, reference)?;
                quoted = Some(
                    original_restored_producer_lifecycle_storage_data(
                        &PacketRestoredProducerLifecycleInputs {
                            startup: &startup,
                            launch,
                            canonical_launch5: raw5,
                            checkpoint,
                            canonical_checkpoint: raw_checkpoint,
                            producer,
                            canonical_producer: raw_producer,
                            operation,
                            arguments: PacketRestoredProducerArgumentsData {
                                held,
                                maximum_authorization_bytes: self
                                    .installation()
                                    .maximum_authorization_bytes
                                    .min(8192),
                            },
                        },
                        maximum,
                    )
                    .map_err(|_| RuntimeError::ResourceLimit)?,
                );
                Ok(())
            },
        )?;
        call.complete(&mut scratch, || {
            inputs.activation.inspection.authenticate_current()
        })?;
        let provider = quoted.ok_or(RuntimeError::OwnerUnavailable)?;
        let outcome = self.original_restored_producer_outcome_construction_data(
            grant.activation().record(),
            maximum,
        )?;
        let previous_slots = history
            .attempts
            .len()
            .checked_add(1)
            .ok_or(RuntimeError::ResourceLimit)?;
        let source_bank = previous_slots
            .checked_mul(size_of::<ProducerProgressAttempt>())
            .ok_or(RuntimeError::ResourceLimit)?;
        let originals = provider.maximum_originals_data();
        let ingress = provider.native_ingress_data();
        let action = provider.native_action_data();
        let native =
            |value: U64| usize::try_from(value.get()).map_err(|_| RuntimeError::ResourceLimit);
        let ingress_retained = native(ingress.retained_requested_bytes)?
            .checked_mul(originals)
            .ok_or(RuntimeError::ResourceLimit)?;
        let ingress_transient = native(ingress.maximum_simultaneous_transient_bytes)?
            .checked_mul(originals)
            .ok_or(RuntimeError::ResourceLimit)?;
        let ingress_scratch = native(ingress.declared_counter_scratch_bytes)?
            .checked_mul(originals)
            .ok_or(RuntimeError::ResourceLimit)?;
        let action_retained = native(action.retained_requested_bytes)?
            .checked_mul(originals)
            .ok_or(RuntimeError::ResourceLimit)?;
        let (source_bodies, source_body_scratch, upload_bytes) =
            projection::source_bodies_data(self, grant, maximum)?;
        // Every independently retained B host, Source and native row remains
        // simultaneous. No old owner, publication or failed partial is refunded.
        let retained = sum(
            [
                provider.host_retained_requested_bytes_data(),
                provider.source_evidence_retained_requested_bytes_data(),
                ingress_retained,
                action_retained,
                source_bank,
                source_bodies,
                upload_bytes,
                // Eleven independent owners: Source mapped Outcome, Node retained
                // Poll Outcome, Node returned/caller Outcome, Runtime retained
                // Outcome; SchedulingReceipt; returned and retained SchedulingCommit
                // output banks; ACK temporary Outcome; final checkpoint Source,
                // Node retained and Node returned/validated scheduling observations.
                // The full defining Outcome projection dominates each named subtree.
                outcome
                    .requested_bytes_data()
                    .checked_mul(11)
                    .ok_or(RuntimeError::ResourceLimit)?,
                proof::reference_storage_data(maximum)?
                    .checked_mul(9)
                    .ok_or(RuntimeError::ResourceLimit)?,
                originals
                    .checked_mul(
                        size_of::<UploadBody>()
                            + size_of::<Option<OriginalRestoredSuffixHostAttempt>>()
                            + size_of::<Id>()
                            + 256,
                    )
                    .ok_or(RuntimeError::ResourceLimit)?,
                size_of::<ProducerProgressAttempt>(),
            ],
            maximum,
        )?;
        let transient = sum(
            [
                source_bank,
                first
                    .requested_peak_bytes_data()
                    .checked_mul(2)
                    .ok_or(RuntimeError::ResourceLimit)?,
                outcome.requested_bytes_data(),
                provider.host_maximum_simultaneous_transient_bytes_data(),
                provider.source_evidence_maximum_simultaneous_transient_bytes_data(),
                ingress_transient,
                native(action.maximum_simultaneous_transient_bytes)?,
                source_bodies,
                // Deferred-publication validation performs two fresh native receipt
                // walks under another read, independently from Poll and first Observe.
                provider
                    .source_evidence_maximum_simultaneous_transient_bytes_data()
                    .checked_mul(2)
                    .ok_or(RuntimeError::ResourceLimit)?,
            ],
            maximum,
        )?;
        let scratch = sum(
            [
                Self::original_restored_producer_execution_counter_scratch_data(),
                provider.host_counter_scratch_bytes_data(),
                provider.source_evidence_counter_scratch_bytes_data(),
                first.counter_scratch_bytes_data(),
                outcome.counter_scratch_bytes_data(),
                ingress_scratch,
                native(action.declared_counter_scratch_bytes)?,
                source_body_scratch,
            ],
            maximum,
        )?;
        sum([retained, transient, scratch], maximum)?;
        Ok(OriginalRestoredProducerExecutionConstructionData {
            process: std::process::id(),
            thread: std::thread::current().id(),
            source: self,
            controller,
            read_owner,
            provider,
            retained,
            transient,
            scratch,
            maximum,
            runtime_work: (0, 0, 0),
            complete_scratch: scratch,
        })
    }

    /// Names the defining counters, direct views and complete error Results.
    pub(crate) fn original_restored_producer_execution_counter_scratch_data() -> usize {
        use crucible_node_transport::ProviderError;
        use std::cell::{BorrowError, BorrowMutError};
        original_restored_producer_lifecycle_counter_scratch_data()
            + Self::original_restoration_observation_source_construction_counter_scratch_data()
            + Self::original_restored_producer_outcome_counter_scratch_data()
            + NodeRuntime::capture_opaque_owner_observer_scratch_data()
            + size_of::<ProducerProgressHistory>() + size_of::<ProducerProgressAttempt>()
            + size_of::<&ProducerProgressHistory>() + size_of::<&mut ProducerProgressHistory>()
            + size_of::<&ProducerProgressAttempt>() + size_of::<&mut ProducerProgressAttempt>()
            + size_of::<Vec<ProducerProgressAttempt>>() + size_of::<Vec<Option<OriginalRestoredSuffixHostAttempt>>>()
            + size_of::<[Option<serde_json::Value>; 4]>() + size_of::<[Vec<u8>; 4]>()
            + size_of::<&UploadBody>() + size_of::<&mut UploadBody>()
            + size_of::<Cell<Stage>>() + size_of::<&Cell<Stage>>() + size_of::<Stage>()
            + size_of::<&[crucible_node_transport::reference_packet::PacketEvent]>()
            + size_of::<ProducerExecutionPhase>() + size_of::<&ProducerExecutionPhase>()
            + size_of::<Option<ProducerProgressAttempt>>() + size_of::<UploadBody>()
            + size_of::<Option<UploadBody>>() + size_of::<Vec<UploadBody>>()
            + size_of::<RefCell<ProducerProgressHistory>>()
            + size_of::<Ref<'static, ProducerProgressHistory>>()
            + size_of::<RefMut<'static, ProducerProgressHistory>>()
            + size_of::<Result<Ref<'static, ProducerProgressHistory>, BorrowError>>()
            + size_of::<Result<RefMut<'static, ProducerProgressHistory>, BorrowMutError>>()
            + size_of::<Result<Ref<'static, ProducerProgressHistory>, RuntimeError>>()
            + size_of::<Result<RefMut<'static, ProducerProgressHistory>, RuntimeError>>()
            + size_of::<Ref<'static, Option<ContentRef>>>()
            + size_of::<RefMut<'static, Option<ContentRef>>>()
            + size_of::<Result<Ref<'static, Option<ContentRef>>, BorrowError>>()
            + size_of::<Result<RefMut<'static, Option<ContentRef>>, BorrowMutError>>()
            + size_of::<Result<Ref<'static, Option<ContentRef>>, RuntimeError>>()
            + size_of::<Result<RefMut<'static, Option<ContentRef>>, RuntimeError>>()
            + size_of::<std::slice::Iter<'static, ProducerProgressAttempt>>()
            + size_of::<Option<&ProducerProgressAttempt>>() + size_of::<Option<&mut ProducerProgressAttempt>>()
            + size_of::<Result<&ProducerProgressAttempt, RuntimeError>>()
            + size_of::<Result<&mut ProducerProgressAttempt, RuntimeError>>()
            + size_of::<OriginalRestoredProducerExecutionConstructionData>()
            + size_of::<Result<OriginalRestoredProducerExecutionConstructionData, RuntimeError>>()
            + size_of::<PacketRestoredProducerLifecycleInputs<'static>>()
            + size_of::<PacketRestoredProducerArgumentsData<'static>>()
            + size_of::<PacketRestoredProducerOperationData<'static>>()
            + size_of::<Result<PacketRestoredProducerOperationData<'static>, RuntimeError>>()
            + size_of::<Option<crucible_node_transport::reference_packet::service::native_startup::PacketRestoredProducerLifecycleStorageData>>()
            + size_of::<Result<crucible_node_transport::reference_packet::service::native_startup::PacketRestoredProducerLifecycleStorageData, ProviderError>>()
            + size_of::<AttemptGuard<'static>>()
            + deferred::counter_scratch_data()
            + Self::original_restored_producer_launch_counter_scratch_data()
            + owner::counter_scratch_data()
            + projection::counter_scratch_data()
            + proof::counter_scratch_data() + effect::counter_scratch_data() + publication::counter_scratch_data()
            + size_of::<[usize; 11]>() + size_of::<std::array::IntoIter<usize, 11>>()
            + size_of::<[usize; 9]>() + size_of::<std::array::IntoIter<usize, 9>>()
            + size_of::<[usize; 8]>() + size_of::<std::array::IntoIter<usize, 8>>()
            + size_of::<[usize; 4]>() + size_of::<std::array::IntoIter<usize, 4>>()
            + size_of::<[usize; 3]>() + size_of::<std::array::IntoIter<usize, 3>>()
    }
}

pub(super) fn operation_data<'a>(
    operation: &'a Id,
    request: &crate::node_contract::OperationRequest,
) -> Result<PacketRestoredProducerOperationData<'a>, RuntimeError> {
    use crate::node_contract::{ExactBoundaryPolicy, OperationRequest};
    let (kind, start, limit) = match request {
        OperationRequest::ExactRun {
            start,
            limit,
            boundary_policy: ExactBoundaryPolicy::HorizonPark,
        } => (BeginKind::ExactRun, *start, *limit),
        OperationRequest::BoundarySettle { start, limit } if start.time_ps == limit.time_ps => {
            (BeginKind::BoundarySettle, *start, *limit)
        }
        _ => return Err(RuntimeError::UnsupportedFacet),
    };
    Ok(PacketRestoredProducerOperationData {
        operation,
        kind,
        start,
        limit,
    })
}

pub(super) fn authenticate_source_row_data(
    admitted: &OriginalRestoredProducerExecutionConstructionData,
    actual: &OriginalRestoredProducerExecutionConstructionData,
) -> Result<(), RuntimeError> {
    admitted
        .provider
        .authenticate_same_quote_data(&actual.provider)
        .map_err(|_| RuntimeError::ForeignAuthority)?;
    if admitted.process != actual.process
        || admitted.thread != actual.thread
        || admitted.source != actual.source
        || admitted.controller != actual.controller
        || admitted.read_owner != actual.read_owner
        || admitted.retained != actual.retained
        || admitted.transient != actual.transient
        || admitted.scratch != actual.scratch
        || admitted.maximum != actual.maximum
    {
        return Err(RuntimeError::ForeignAuthority);
    }
    admitted.requested_bytes_data()?;
    Ok(())
}

pub(super) fn sum<const N: usize>(
    terms: [usize; N],
    maximum: usize,
) -> Result<usize, RuntimeError> {
    crate::node_adapters::cnp::semantic::packet_complete_source::retained_values::sum_with_error::<
        RuntimeError,
        N,
    >(terms, maximum)
}

/// Refuses native private Attention that has no truthful common stop category.
///
/// PacketProgram::preview skips precisely completion < limit, then reports the
/// first remaining evaluation below that limit. A private straddling callback
/// is not a public Output, Lifecycle or Idle stop. This check uses authenticated
/// current pending DATA, before any original SDK action is assigned.
fn authenticate_supported_stop_data(
    pending: &[crucible_node_transport::reference_packet::PacketEvent],
    limit: Position,
) -> Result<(), RuntimeError> {
    if let Some(first) = pending.iter().find(|event| event.completion >= limit)
        && first.evaluation < limit
        && first.payload.is_none()
    {
        return Err(RuntimeError::UnsupportedFacet);
    }
    Ok(())
}

#[cfg(test)]
#[allow(
    clippy::unwrap_used,
    reason = "actual pure program preview control constructs no Source or action authority"
)]
mod stop_tests {
    use super::*;
    use crucible_node_format::Phase;
    use crucible_node_transport::reference_packet::{PacketEvent, PacketProgram};
    use std::os::unix::net::UnixDatagram;

    fn position(time: u64, phase: Phase) -> Position {
        Position::new(U64::new(time), U64::new(0), phase)
    }

    #[test]
    fn actual_private_straddling_preview_refuses_before_any_sdk_action() {
        let (effects, observer) = UnixDatagram::pair().unwrap();
        let mut program = PacketProgram::new(
            vec![
                PacketEvent {
                    id: Id::new("private").unwrap(),
                    evaluation: position(2, Phase::Reaction),
                    completion: position(4, Phase::Reaction),
                    payload: None,
                },
                PacketEvent {
                    id: Id::new("packet").unwrap(),
                    evaluation: position(6, Phase::Reaction),
                    completion: position(8, Phase::Publication),
                    payload: Some(Bytes::new(vec![7, 11])),
                },
            ],
            effects,
        )
        .unwrap();
        program.open_gate().unwrap();
        let before = program.inventory();
        let operation = Id::new("preview-data-only").unwrap();
        let private_limit = position(3, Phase::BoundaryControl);
        let private = program
            .preview(&operation, before.reached, private_limit)
            .unwrap();
        assert_eq!(private.inventory.reached, position(2, Phase::Reaction));
        assert!(private.inventory.reached < private_limit);
        assert!(matches!(
            authenticate_supported_stop_data(&before.pending, private_limit),
            Err(RuntimeError::UnsupportedFacet)
        ));

        let full_private_limit = position(5, Phase::BoundaryControl);
        assert_eq!(
            program
                .preview(&operation, before.reached, full_private_limit)
                .unwrap()
                .inventory
                .reached,
            full_private_limit
        );
        authenticate_supported_stop_data(&before.pending, full_private_limit).unwrap();
        let payload_limit = position(7, Phase::BoundaryControl);
        assert_eq!(
            program
                .preview(&operation, before.reached, payload_limit)
                .unwrap()
                .inventory
                .reached,
            position(6, Phase::Reaction)
        );
        authenticate_supported_stop_data(&before.pending, payload_limit).unwrap();
        assert_eq!(program.inventory(), before);
        observer.set_nonblocking(true).unwrap();
        assert!(
            matches!(observer.recv(&mut [0; 1]), Err(error) if error.kind() == std::io::ErrorKind::WouldBlock)
        );
    }
}
