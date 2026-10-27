//! Plans the existing auxiliary Operation/Batch readiness successors.
//!
//! The native Source/C17 caller pays complete schema/model geometry first and
//! retains the same original Source and Root borrowers around each append.
//! This recipe shares the canonical lifecycle model, auxiliary join, reducer
//! envelopes and protected-domain planner. It supplies no writer or authority.

mod committed;
use super::*;
use aos_sandbox_protocol::domain_ledger::lifecycle_model::LifecycleModelError;
use aos_sandbox_protocol::domain_ledger::records::{
    ProtectedDomainEnvelopeV1, decode_reducer_payload_with_validator,
};
use super::super::{
    LifecycleEffectDomainV1, LifecyclePhase6EffectPlanV1, LifecyclePhaseV1,
    LifecycleStepV1, decode_lifecycle_auxiliary_record_from_protected_envelope_v1,
};

type Envelope = ProtectedDomainEnvelopeV1<Schema>;

/// Selects the three finite precommit model transitions, never an effect result.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum DeleteSourceReadinessPhaseV3 {
    Binding,
    Prepared,
    Ready,
    ControllerCommitted,
}

/// Retains one paid exact successor until actual native append/readback.
pub(crate) struct SourceDeleteReadinessPlanV3 {
    phase: DeleteSourceReadinessPhaseV3,
    transaction: JournalTransaction,
    source_before: u64,
    controller_before: u64,
    controller_commit: Option<[u8; 64]>,
    batch_digest: ObjectDigest,
    clock_bound: crate::normal_root::DeleteSourceClockBoundDataV3,
    root_plan: ObjectDigest,
    source_pending: [u8; 64],
    operation: LifecycleOperationV1,
}

impl SourceDeleteReadinessPlanV3 {
    /// Builds only the selected successor of the actual complete Source rows.
    pub(crate) fn prepare_v3(
        view: HistoricalLedgerReadViewV1<'_>,
        source_before: u64,
        controller_before: u64,
        pending: &SourceDeletePendingPlanV1<'_>,
        phase: DeleteSourceReadinessPhaseV3,
        binding: &crate::normal_root::DeleteSourceBindingDataV3,
    ) -> Result<Self, super::super::protected_journal::LifecycleProtectedJournalErrorV1> {
        Self::prepare_inner_v3(view, source_before, controller_before, pending, phase, binding, None)
    }

    pub(crate) fn prepare_controller_committed_data_v3(
        view: HistoricalLedgerReadViewV1<'_>,
        source_before: u64,
        controller_before: u64,
        pending: &SourceDeletePendingPlanV1<'_>,
        binding: &crate::normal_root::DeleteSourceBindingDataV3,
        native: [u8; 64],
    ) -> Result<Self, super::super::protected_journal::LifecycleProtectedJournalErrorV1> {
        Self::prepare_inner_v3(view, source_before, controller_before, pending,
            DeleteSourceReadinessPhaseV3::ControllerCommitted, binding, Some(native))
    }

    #[allow(clippy::too_many_arguments)]
    fn prepare_inner_v3(
        view: HistoricalLedgerReadViewV1<'_>,
        source_before: u64,
        controller_before: u64,
        pending: &SourceDeletePendingPlanV1<'_>,
        phase: DeleteSourceReadinessPhaseV3,
        binding: &crate::normal_root::DeleteSourceBindingDataV3,
        controller_commit: Option<[u8; 64]>,
    ) -> Result<Self, super::super::protected_journal::LifecycleProtectedJournalErrorV1> {
        let invalid = || super::super::protected_journal::LifecycleProtectedJournalErrorV1::NonCanonicalRecord;
        let (_, expected_operation, batch_digest) = pending.coordinates();
        match (phase, controller_commit) {
            (DeleteSourceReadinessPhaseV3::ControllerCommitted, Some(native)) => {
                let batch = aos_sandbox_protocol::domain_ledger::delete_batch::DeleteBatchViewV1::decode(pending.batch_bytes()?)
                    .map_err(|_| invalid())?;
                let commit = u64::from_be_bytes(native[48..56].try_into().map_err(|_| invalid())?);
                if native[..16] != batch.transaction() || commit.checked_add(1) != Some(controller_before) {
                    return Err(invalid());
                }
            }
            (DeleteSourceReadinessPhaseV3::ControllerCommitted, None) => return Err(invalid()),
            (_, None) if pending.controller_sequence_data_v1() == controller_before => {}
            _ => return Err(invalid()),
        }
        let saved = pending.batch_bytes()?;
        let held = aos_sandbox_ledger_replay::source_policy_hold::current_state(view.materialized_state_v1())
            .map_err(JournalError::from)?;
        if held.delete_pending != Some(batch_digest) {
            return Err(invalid());
        }
        binding.require_pending_data_v3(pending)?;
        let verifier = super::super::protected_owner::recover_saved_lifecycle_verifier_v1(view)
            .map_err(|_| invalid())?;
        let projection = replay_projection_records::<Schema>(view.all_records(), &verifier)?;
        let mut operation_member = None;
        let mut batch_member = None;
        for envelope in projection.records().iter().filter(|envelope| envelope.key().kind() == Kind::Auxiliary) {
            let decoded = decode_reducer_payload_with_validator::<Schema>(
                envelope.key(), envelope.payload(), &verifier)?;
            let auxiliary = decode_lifecycle_auxiliary_record_from_protected_envelope_v1(
                decoded.body(), verifier.replay()).map_err(|_| invalid())?;
            if auxiliary.project() != pending.project || auxiliary.operation() != expected_operation {
                continue;
            }
            match auxiliary.payload() {
                LifecycleAuxiliaryPayloadV1::Operation(value) if value.has_delete_batch_layout() => {
                    select_latest_member(&mut operation_member, envelope, auxiliary)?;
                }
                LifecycleAuxiliaryPayloadV1::DeleteBatch(value) if value.state() == 1
                    && value.batch().as_bytes() == saved => {
                    select_latest_member(&mut batch_member, envelope, auxiliary)?;
                }
                _ => return Err(invalid()),
            }
        }
        let (operation_envelope, previous_operation) = operation_member.ok_or_else(invalid)?;
        let (batch_envelope, previous_batch) = batch_member.ok_or_else(invalid)?;
        if previous_operation.atomic_join() != previous_batch.atomic_join()
            || previous_operation.operation_revision() != previous_batch.operation_revision()
            || previous_operation.operation_record() != previous_batch.operation_record()
        {
            return Err(invalid());
        }
        let LifecycleAuxiliaryPayloadV1::Operation(previous) = previous_operation.payload() else {
            return Err(invalid());
        };
        let (operation, batch_payload) = if let Some(native) = controller_commit {
            let LifecycleAuxiliaryPayloadV1::DeleteBatch(planned) = previous_batch.payload() else { return Err(invalid()); };
            let committed = planned.controller_committed_data_v3(&native).map_err(|_| invalid())?;
            let operation = committed::successor_v3(previous, previous_operation.operation_record(),
                committed.clone(), binding.clock_bound_data_v3().after).map_err(|_| invalid())?;
            (operation, LifecycleAuxiliaryPayloadV1::DeleteBatch(committed))
        } else {
            (successor_operation(previous, previous_operation.operation_record(), phase, binding)
                .map_err(|_| invalid())?, previous_batch.payload().clone())
        };
        let encoded = super::super::format::encode_retained_operation_record(&operation)
            .map_err(|_| invalid())?;
        let operation_digest = super::super::format::record_digest(&encoded).map_err(|_| invalid())?;
        let transaction_id = transaction_id(&operation, phase, binding);
        let join = ResourceId::from_bytes(transaction_id);
        let operation_auxiliary = LifecycleAuxiliaryRecordV1::proposal(
            pending.project, expected_operation, operation.record_revision(), operation_digest,
            previous_operation.lineage(), previous_operation.revision().checked_next().map_err(|_| invalid())?,
            Some(previous_operation.complete_digest()), LifecycleAuxiliaryPayloadV1::Operation(operation.clone()),
            join, previous_operation.replay_floor(), verifier.replay()).map_err(|_| invalid())?;
        let batch_auxiliary = LifecycleAuxiliaryRecordV1::proposal(
            pending.project, expected_operation, operation.record_revision(), operation_digest,
            previous_batch.lineage(), previous_batch.revision().checked_next().map_err(|_| invalid())?,
            Some(previous_batch.complete_digest()), batch_payload,
            join, previous_batch.replay_floor(), verifier.replay()).map_err(|_| invalid())?;
        let members = bind_lifecycle_atomic_join_v1(vec![operation_auxiliary, batch_auxiliary])
            .map_err(|_| invalid())?;
        let envelopes = members.iter().map(|member| {
            let before = if member.lineage() == previous_operation.lineage() {
                operation_envelope
            } else {
                batch_envelope
            };
            lifecycle_reducer_envelope_v1(before.key().clone(),
                before.revision().checked_add(1).ok_or_else(invalid)?, Some(before.digest()),
                LifecycleReducerRecordV1::Auxiliary(member), &verifier).map_err(|_| invalid())
        }).collect::<Result<Vec<_>, _>>()?;
        let planned = aos_sandbox_broker::domain_transaction_custody::plan_members_v1::<Schema>(
            view, source_before, projection.root(), transaction_id, envelopes, &verifier)?;
        Ok(Self { phase, transaction: planned.transaction().clone(), source_before,
            controller_before, controller_commit, batch_digest, clock_bound: binding.clock_bound_data_v3(), root_plan: binding.root_plan_data_v3(),
            source_pending: *binding.source_pending_data_v3(), operation })
    }

    pub(crate) fn controller_commit_data_v3(&self) -> Option<&[u8; 64]> { self.controller_commit.as_ref() }

    pub(crate) fn phase_v3(&self) -> DeleteSourceReadinessPhaseV3 { self.phase }

    pub(crate) fn require_binding_data_v3(
        &self,
        binding: &crate::normal_root::DeleteSourceBindingDataV3,
    ) -> Result<(), JournalError> {
        if self.root_plan != binding.root_plan_data_v3()
            || self.source_pending != *binding.source_pending_data_v3()
            || (self.operation.project(), self.operation.operation_id(), self.batch_digest)
                != binding.coordinates_data_v3()
        {
            return Err(JournalError::StaleAuthoritySnapshot);
        }
        Ok(())
    }

    pub(crate) fn require_saved_rows_v3(
        &self,
        state: &std::collections::BTreeMap<(RecordNamespace, Vec<u8>), Vec<u8>>,
    ) -> Result<(), JournalError> {
        let held = aos_sandbox_ledger_replay::source_policy_hold::current_state(state)?;
        if held.delete_pending != Some(self.batch_digest)
            || self.transaction.records().iter().any(|record|
                state.get(&(record.namespace(), record.key().to_vec())).map(Vec::as_slice) != record.value())
        {
            return Err(JournalError::StaleAuthoritySnapshot);
        }
        Ok(())
    }

    pub(crate) fn clock_bound_data_v3(&self) -> crate::normal_root::DeleteSourceClockBoundDataV3 {
        self.clock_bound
    }

    pub(crate) fn source_before_data_v3(&self) -> u64 { self.source_before }

    pub(crate) fn transaction_v3(&self) -> &JournalTransaction {
        &self.transaction
    }

    pub(crate) fn operation_v3(&self) -> &LifecycleOperationV1 {
        &self.operation
    }

    /// Restricts the hold exception to this actual planned transaction.
    pub(crate) fn require_transition_v3(
        &self,
        state: &std::collections::BTreeMap<(RecordNamespace, Vec<u8>), Vec<u8>>,
        transaction: &JournalTransaction,
    ) -> Result<(), JournalError> {
        let held = aos_sandbox_ledger_replay::source_policy_hold::current_state(state)?;
        if held.delete_pending != Some(self.batch_digest) || transaction != &self.transaction {
            return Err(JournalError::ProtectedBoundary);
        }
        Ok(())
    }

    pub(crate) fn require_before_v3(&self, source: u64, controller: u64) -> Result<(), JournalError> {
        if (source, controller) != (self.source_before, self.controller_before) {
            return Err(JournalError::StaleAuthoritySnapshot);
        }
        Ok(())
    }
}

pub(super) fn select_latest_member<'rows>(
    selected: &mut Option<(&'rows Envelope, LifecycleAuxiliaryRecordV1)>,
    envelope: &'rows Envelope,
    incoming: LifecycleAuxiliaryRecordV1,
) -> Result<(), super::super::protected_journal::LifecycleProtectedJournalErrorV1> {
    let invalid = || super::super::protected_journal::LifecycleProtectedJournalErrorV1::NonCanonicalRecord;
    if let Some((_, previous)) = selected {
        if incoming.revision() == previous.revision() { return Err(invalid()); }
        if incoming.revision() < previous.revision() { return Ok(()); }
    }
    *selected = Some((envelope, incoming));
    Ok(())
}

fn successor_operation(
    previous: &LifecycleOperationV1,
    previous_digest: super::super::LifecycleRecordDigestV1,
    phase: DeleteSourceReadinessPhaseV3,
    binding: &crate::normal_root::DeleteSourceBindingDataV3,
) -> Result<LifecycleOperationV1, LifecycleModelError> {
    let effect = LifecyclePhase6EffectPlanV1::new(LifecycleEffectDomainV1::Controller,
        1, binding.sandbox_data_v3(), binding.public_request_data_v3(), binding.root_plan_data_v3())
        .map_err(|_| LifecycleModelError::InvalidTransition)?;
    successor_for_effect(previous, previous_digest, phase, effect)
}

fn successor_for_effect(
    previous: &LifecycleOperationV1,
    previous_digest: super::super::LifecycleRecordDigestV1,
    phase: DeleteSourceReadinessPhaseV3,
    effect: LifecyclePhase6EffectPlanV1,
) -> Result<LifecycleOperationV1, LifecycleModelError> {
    use super::super::{LifecycleIntentV1, LifecycleStepClassV1, LifecycleStepDomainV1};
    let invalid = || LifecycleModelError::InvalidTransition;
    let (expected, successor) = match phase {
        DeleteSourceReadinessPhaseV3::Binding => (LifecyclePhaseV1::Accepted, LifecyclePhaseV1::Accepted),
        DeleteSourceReadinessPhaseV3::Prepared => (LifecyclePhaseV1::Accepted, LifecyclePhaseV1::Prepared),
        DeleteSourceReadinessPhaseV3::Ready => (LifecyclePhaseV1::Prepared, LifecyclePhaseV1::ReadyToCommit),
        DeleteSourceReadinessPhaseV3::ControllerCommitted => return Err(invalid()),
    };
    let LifecycleIntentV1::DeleteSandbox { sandbox, .. } = previous.intent() else { return Err(invalid()); };
    let [current] = previous.steps() else { return Err(invalid()); };
    if previous.phase() != expected || previous.method_semantic_commit().is_some()
        || effect.domain() != LifecycleEffectDomainV1::Controller || effect.ordinal() != 1
        || effect.target() != *sandbox.as_bytes() || current.index() != 0
        || current.class() != LifecycleStepClassV1::PostCommitForward
        || current.domain() != LifecycleStepDomainV1::Controller
    {
        return Err(invalid());
    }
    // Reuse the same canonical binder for both first binding and every later
    // comparison, preserving the original logical public-request commitment.
    let anchor = LifecycleStepV1::unbound(current.index(), current.class(), current.domain(), current.request(), None)?;
    let bound = super::super::phase6::lifecycle_phase6_bind_controller_anchor_v1(
        previous.operation_id(), &anchor, effect).map_err(|_| invalid())?;
    match phase {
        DeleteSourceReadinessPhaseV3::Binding if !current.is_unbound() => return Err(invalid()),
        DeleteSourceReadinessPhaseV3::Prepared | DeleteSourceReadinessPhaseV3::Ready if current != &bound => {
            return Err(invalid());
        }
        _ => {}
    }
    previous.successor(previous_digest, successor, previous.forward_progress(),
        previous.compensation_progress(), vec![bound], None, None, None, None, None)?
        .select_delete_batch_layout()
}

fn transaction_id(
    operation: &LifecycleOperationV1,
    phase: DeleteSourceReadinessPhaseV3,
    binding: &crate::normal_root::DeleteSourceBindingDataV3,
) -> [u8; 16] {
    let mut hash = Sha256::new();
    hash.update(b"aos.sandbox.delete.source-readiness-transaction.v3\0");
    hash.update(operation.project().as_bytes());
    hash.update(operation.operation_id().as_bytes());
    hash.update(operation.record_revision().get().to_be_bytes());
    hash.update([match phase { DeleteSourceReadinessPhaseV3::Binding => 1,
        DeleteSourceReadinessPhaseV3::Prepared => 2, DeleteSourceReadinessPhaseV3::Ready => 3,
        DeleteSourceReadinessPhaseV3::ControllerCommitted => 4 }]);
    hash.update(binding.root_plan_data_v3().as_bytes());
    let digest = hash.finalize();
    let mut id = [0; 16];
    id.copy_from_slice(&digest[..16]);
    // This domain-separated identity is selected exactly by the retained
    // recipe; failure of a sentinel check is a refusal, never an entropy retry.
    id
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::lifecycle::*;
    use aos_sandbox_model::{DesiredGeneration, PrincipalId, SandboxId};

    pub(super) fn accepted() -> LifecycleOperationV1 {
        let sandbox = SandboxId::from_bytes([7; 16]);
        let resource = aos_sandbox_protocol::domain_ledger::lifecycle_model::LifecycleResourceV1::Sandbox(sandbox);
        let state = LifecycleResourceStateDigestV1::commit(b"actual selected predecessor DATA");
        let fence = DesiredStateFenceV1::new(resource, DesiredGeneration::new(1), Revision::new(1), state).unwrap();
        LifecycleOperationV1::new(OperationId::from_bytes([5; 16]), PrincipalId::from_bytes([3; 16]),
            ProjectId::from_bytes([4; 16]), LifecycleIdempotencyDigestV1::commit(b"key"),
            LifecycleIntentV1::DeleteSandbox { sandbox, fence }, LifecycleTimeV1::new(1).unwrap(),
            Revision::new(1), vec![
                ResourceExpectationV1::present(resource, Revision::new(1), state).unwrap(),
                ResourceExpectationV1::present(aos_sandbox_protocol::domain_ledger::lifecycle_model::LifecycleResourceV1::Project(ProjectId::from_bytes([4; 16])),
                    Revision::new(9), LifecycleResourceStateDigestV1::commit(b"read-only authority dependency")).unwrap(),
            ],
            vec![LifecycleStepV1::unbound(0, LifecycleStepClassV1::PostCommitForward,
                LifecycleStepDomainV1::Controller, LifecycleStepRequestDigestV1::commit(b"original public Delete"), None).unwrap()],
            LifecyclePhaseV1::Accepted, 0, 0, None, None, None, None, None, None).unwrap()
            .select_delete_batch_layout().unwrap()
    }

    fn digest(operation: &LifecycleOperationV1) -> LifecycleRecordDigestV1 {
        let bytes = crate::lifecycle::format::encode_retained_operation_record(operation).unwrap();
        crate::lifecycle::format::record_digest(&bytes).unwrap()
    }

    fn effect(request: u8, plan: u8, ordinal: u32) -> LifecyclePhase6EffectPlanV1 {
        LifecyclePhase6EffectPlanV1::new(LifecycleEffectDomainV1::Controller, ordinal, [7; 16],
            ObjectDigest::from_bytes([request; 32]), ObjectDigest::from_bytes([plan; 32])).unwrap()
    }

    #[test]
    fn readiness_uses_canonical_edges_and_rejects_changed_root_request_and_ordinal() {
        let original = accepted();
        let selected = effect(20, 21, 1);
        let bound = successor_for_effect(&original, digest(&original), DeleteSourceReadinessPhaseV3::Binding, selected).unwrap();
        let prepared = successor_for_effect(&bound, digest(&bound), DeleteSourceReadinessPhaseV3::Prepared, selected).unwrap();
        let ready = successor_for_effect(&prepared, digest(&prepared), DeleteSourceReadinessPhaseV3::Ready, selected).unwrap();

        for successor in [&bound, &prepared, &ready] {
            assert!(successor.has_delete_batch_layout());
            let bytes = crate::lifecycle::format::encode_retained_operation_record(successor).unwrap();
            assert_eq!(&bytes[..8], b"AOSLIF04");
        }
        assert_eq!(ready.phase(), LifecyclePhaseV1::ReadyToCommit);
        assert_eq!(ready.steps()[0].request(), original.steps()[0].request());
        assert_eq!(ready.steps()[0].state(), LifecycleStepStateV1::Planned);
        assert!(ready.steps()[0].forward_attempts().is_empty());
        assert!(ready.method_semantic_commit().is_none());
        assert!(successor_for_effect(&original, digest(&original), DeleteSourceReadinessPhaseV3::Ready, selected).is_err());
        assert!(successor_for_effect(&bound, digest(&bound), DeleteSourceReadinessPhaseV3::Binding, selected).is_err());
        for changed in [effect(22, 21, 1), effect(20, 23, 1), effect(20, 21, 2)] {
            assert!(successor_for_effect(&bound, digest(&bound), DeleteSourceReadinessPhaseV3::Prepared, changed).is_err());
        }
        assert!(successor_for_effect(&original, digest(&original), DeleteSourceReadinessPhaseV3::Binding, effect(20, 21, 2)).is_err());
    }
}
