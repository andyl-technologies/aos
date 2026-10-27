//! Rechecks a genuine pending callback crossing two retained Producer operations.
//!
//! This read-only path consumes neither a new action claim nor a first-Observe
//! allowance. The actual current Poll frontier, keyed private history and both
//! original receipts must agree before the Runtime may accept deferred ordering.

use super::*;
use crate::node_scheduling::NativePublication;

impl PacketCompleteSemanticSource {
    /// Verifies the exact pending evaluation carried across two real grants.
    ///
    /// This read-only predicate creates no action, publication or Capture right.
    ///
    /// # Errors
    /// Refuses changed original tokens/Worlds, nonadjacent history, a stale Poll
    /// frontier, invalid full native proof or differing publication fields.
    pub(crate) fn authenticate_original_restored_producer_deferred_data(
        &self,
        controller: &CnpController,
        current_admission: &OperationAdmission,
        current_outcome: &OperationOutcome,
        publication: &NativePublication,
        prior_admission: &OperationAdmission,
        prior_outcome: &OperationOutcome,
    ) -> Result<(), RuntimeError> {
        self.storage_origin_with_error::<RuntimeError>()?;
        if !current_admission
            .activation()
            .same_authority(prior_admission.activation())
            || current_admission.token().operation() == prior_admission.token().operation()
        {
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
        emitter
            .authenticate_original(controller)
            .map_err(|_| RuntimeError::ForeignAuthority)?;
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
        let history = original
            .producer_progress
            .try_borrow()
            .map_err(|_| RuntimeError::OwnerBusy)?;
        history.origin_data()?;
        if history.failed {
            return Err(RuntimeError::OutstandingObligations);
        }
        let (current, earlier) = history
            .attempts
            .split_last()
            .ok_or(RuntimeError::OwnerUnavailable)?;
        if !matches!(current.stage.get(), Stage::Completed | Stage::Durable)
            || current.outcome.as_ref() != Some(current_outcome)
            || current.signature != Some(proof::signature_data(current, key)?)
        {
            return Err(RuntimeError::InvalidReceipt);
        }
        current.row.authenticate_owner_data(self, controller)?;
        current.authenticate_admission_data(current_admission)?;
        current
            .poll
            .as_ref()
            .ok_or(RuntimeError::OwnerUnavailable)?
            .authenticate_current_pair_data(controller, emitter)
            .map_err(|_| RuntimeError::InvalidReceipt)?;
        let prior = earlier.last().ok_or(RuntimeError::OwnerUnavailable)?;
        if prior.stage.get() != Stage::Verified
            || prior.outcome.as_ref() != Some(prior_outcome)
            || prior.signature != Some(proof::signature_data(prior, key)?)
            || prior.signature != Some(current.previous)
        {
            return Err(RuntimeError::InvalidReceipt);
        }
        prior.row.authenticate_owner_data(self, controller)?;
        prior.authenticate_admission_data(prior_admission)?;
        let actual = current_outcome
            .scheduling
            .as_ref()
            .ok_or(RuntimeError::InvalidReceipt)?;
        if !actual
            .publications
            .iter()
            .any(|candidate| candidate == publication)
        {
            return Err(RuntimeError::InvalidReceipt);
        }
        let current_operation = construction::operation_data(
            current_admission.token().operation(),
            current_admission.request(),
        )?;
        let prior_operation = construction::operation_data(
            prior_admission.token().operation(),
            prior_admission.request(),
        )?;
        let old = &prior.checkpoint_producer_data()?.inventory;
        let evaluation = publication.evaluation.ok_or(RuntimeError::InvalidReceipt)?;
        let Some(event) = old
            .pending
            .iter()
            .find(|event| event.id == publication.publication_id)
        else {
            return Err(RuntimeError::InvalidReceipt);
        };
        if old.reached != current_operation.start
            || evaluation < prior_operation.start
            || evaluation >= current_operation.start
            || event.evaluation != evaluation
            || event.completion != publication.publication
            || !publication.causal_parents.is_empty()
            || event
                .payload
                .as_ref()
                .is_none_or(|payload| payload.as_slice() != publication.payload_bytes.as_slice())
        {
            return Err(RuntimeError::InvalidReceipt);
        }
        publication
            .payload
            .verify(&publication.payload_bytes)
            .map_err(|_| RuntimeError::InvalidReceipt)?;
        for attempt in [prior, current] {
            let (request, response, _) = attempt
                .begin
                .as_ref()
                .ok_or(RuntimeError::OwnerUnavailable)?
                .completed_pair_data()
                .map_err(|_| RuntimeError::InvalidReceipt)?;
            let record = attempt
                .completed_record
                .as_ref()
                .ok_or(RuntimeError::OwnerUnavailable)?;
            let reference = attempt
                .completed_measurement
                .as_ref()
                .ok_or(RuntimeError::OwnerUnavailable)?;
            reference
                .verify(
                    controller
                        .content(reference)
                        .map_err(|_| RuntimeError::InvalidReceipt)?,
                )
                .map_err(|_| RuntimeError::InvalidReceipt)?;
            let bytes = controller
                .content(&record.native_receipt.native_record)
                .map_err(|_| RuntimeError::InvalidReceipt)?;
            record
                .native_receipt
                .native_record
                .verify(bytes)
                .map_err(|_| RuntimeError::InvalidReceipt)?;
            let observed = controller
                .authenticate_original_restored_suffix_receipt_data(
                    emitter, request, response, request, record, bytes,
                )
                .map_err(|_| RuntimeError::InvalidReceipt)?;
            if !matches!(observed, PacketNative5UnderlyingRecord::Producer(record) if record.as_ref() == attempt.producer_data()?)
            {
                return Err(RuntimeError::InvalidReceipt);
            }
        }
        call.complete(&mut scratch, || {
            current
                .poll
                .as_ref()
                .ok_or(RuntimeError::OwnerUnavailable)?
                .authenticate_current_pair_data(controller, emitter)
                .map_err(|_| RuntimeError::InvalidReceipt)?;
            emitter
                .authenticate_original(controller)
                .map_err(|_| RuntimeError::ForeignAuthority)
        })
    }
}

pub(super) fn counter_scratch_data() -> usize {
    size_of::<(&ProducerProgressAttempt, &[ProducerProgressAttempt])>()
        + size_of::<Option<(&ProducerProgressAttempt, &[ProducerProgressAttempt])>>()
        + size_of::<Result<(&ProducerProgressAttempt, &[ProducerProgressAttempt]), RuntimeError>>()
        + size_of::<[&ProducerProgressAttempt; 2]>()
        + size_of::<std::array::IntoIter<&ProducerProgressAttempt, 2>>()
        + size_of::<&NativePublication>()
        + size_of::<&OperationAdmission>() * 2
        + size_of::<&OperationOutcome>() * 2
        + size_of::<Option<Position>>()
        + size_of::<Result<Position, RuntimeError>>()
        + size_of::<Option<&crucible_node_transport::reference_packet::PacketEvent>>()
        + size_of::<Result<&crucible_node_transport::reference_packet::PacketEvent, RuntimeError>>()
        + size_of::<std::slice::Iter<'static, crucible_node_transport::reference_packet::PacketEvent>>(
        )
        + size_of::<std::slice::Iter<'static, NativePublication>>()
        + size_of::<Option<&crate::node_scheduling::NativeSchedulingObservation>>()
        + size_of::<Result<&crate::node_scheduling::NativeSchedulingObservation, RuntimeError>>()
}
