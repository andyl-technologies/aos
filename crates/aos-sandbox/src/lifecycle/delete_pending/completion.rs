//! Advances only the original accepted Delete cleanup anchor to terminal state.
//!
//! Batch2, its Controller proof and semantic access sets remain immutable.
//! The genuine same-Pending completion borrower separately supplies actual
//! physical/native/currentness authority; these recipes are passive DATA.

use super::progress::select_latest_member;
use super::*;
use crate::lifecycle::{
    LifecycleAttemptStateV1, LifecycleEffectAttemptV1, LifecycleEffectDirectionV1,
    LifecycleInventoryDigestV1, LifecyclePhaseV1, LifecycleSemanticCommitFactV1,
    LifecycleStepAdmissionDigestV1, LifecycleStepClassV1, LifecycleStepDomainV1,
    LifecycleStepResultDigestV1, LifecycleStepStateV1, LifecycleStepV1, LifecycleTerminalResultV1,
    LifecycleTimeV1,
};
use aos_sandbox_core::RawPairedClockSample;
use aos_sandbox_protocol::domain_ledger::lifecycle_model::LifecycleModelError;
use aos_sandbox_protocol::domain_ledger::{
    delete_root::completion::DeleteRootPhysicalCompletionDataV4,
    records::{ProtectedDomainEnvelopeV1, decode_reducer_payload_with_validator},
};

type ModelError = super::super::protected_journal::LifecycleProtectedJournalErrorV1;

/// Names the two actual Source successors of accepted physical cleanup debt.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum DeleteSourceCompletionPhaseV4 {
    Reserve,
    Terminal,
}

impl DeleteSourceCompletionPhaseV4 {
    pub(crate) const fn index_v4(self) -> usize {
        match self {
            Self::Reserve => 0,
            Self::Terminal => 1,
        }
    }
}

/// Keeps one exact paid Operation-only transaction until native readback.
pub(crate) struct SourceDeleteCompletionPlanV4 {
    phase: DeleteSourceCompletionPhaseV4,
    transaction: JournalTransaction,
    source_before: u64,
    controller_before: u64,
    batch: ObjectDigest,
    physical: [u8; 32],
    clock: crate::normal_root::DeleteSourceClockBoundDataV3,
    operation: LifecycleOperationV1,
}

impl SourceDeleteCompletionPlanV4 {
    /// Plans a narrow successor; the native caller owns all actual grants.
    pub(crate) fn prepare_v4(
        view: HistoricalLedgerReadViewV1<'_>,
        source_before: u64,
        controller_before: u64,
        pending: &SourceDeletePendingPlanV1<'_>,
        phase: DeleteSourceCompletionPhaseV4,
        physical: DeleteRootPhysicalCompletionDataV4,
        accepted_controller: &[u8; 64],
        clock: crate::normal_root::DeleteSourceClockBoundDataV3,
    ) -> Result<Self, ModelError> {
        let invalid = || ModelError::NonCanonicalRecord;
        let saved = pending.batch_bytes()?;
        let (_, parent, batch) = pending.coordinates();
        let held = aos_sandbox_ledger_replay::source_policy_hold::current_state(
            view.materialized_state_v1(),
        )
        .map_err(JournalError::from)?;
        if held.delete_pending != Some(batch) {
            return Err(invalid());
        }
        let physical = physical.commitment_v4().map_err(|_| invalid())?;
        let verifier = super::super::protected_owner::recover_saved_lifecycle_verifier_v1(view)
            .map_err(|_| invalid())?;
        let projection = replay_projection_records::<Schema>(view.all_records(), &verifier)?;
        let mut operation_member: Option<(
            &ProtectedDomainEnvelopeV1<Schema>,
            LifecycleAuxiliaryRecordV1,
        )> = None;
        let mut batch_member = None;
        for envelope in projection
            .records()
            .iter()
            .filter(|row| row.key().kind() == Kind::Auxiliary)
        {
            let decoded = decode_reducer_payload_with_validator::<Schema>(
                envelope.key(),
                envelope.payload(),
                &verifier,
            )?;
            let auxiliary =
                super::super::decode_lifecycle_auxiliary_record_from_protected_envelope_v1(
                    decoded.body(),
                    verifier.replay(),
                )
                .map_err(|_| invalid())?;
            if auxiliary.project() != pending.project || auxiliary.operation() != parent {
                continue;
            }
            match auxiliary.payload() {
                LifecycleAuxiliaryPayloadV1::Operation(operation)
                    if operation.has_delete_batch_layout() =>
                {
                    select_latest_member(&mut operation_member, envelope, auxiliary)?
                }
                LifecycleAuxiliaryPayloadV1::DeleteBatch(value)
                    if value.state() == 2
                        && value.batch().as_bytes() == saved
                        && value.native_proof() == accepted_controller =>
                {
                    select_latest_member(&mut batch_member, envelope, auxiliary)?
                }
                _ => return Err(invalid()),
            }
        }
        let (envelope, previous) = operation_member.ok_or_else(invalid)?;
        let (_, batch_record) = batch_member.ok_or_else(invalid)?;
        let LifecycleAuxiliaryPayloadV1::Operation(old) = previous.payload() else {
            return Err(invalid());
        };
        let LifecycleAuxiliaryPayloadV1::DeleteBatch(immutable) = batch_record.payload() else {
            return Err(invalid());
        };
        if !matches!(old.method_semantic_commit().map(|commit| commit.facts()),
            Some(LifecycleSemanticCommitFactV1::DeleteBatch { batch, .. }) if batch == immutable)
        {
            return Err(invalid());
        }
        let operation = successor_v4(
            old,
            previous.operation_record(),
            phase,
            physical,
            clock.after,
        )
        .map_err(|_| invalid())?;
        let encoded = super::super::format::encode_retained_operation_record(&operation)
            .map_err(|_| invalid())?;
        let digest = super::super::format::record_digest(&encoded).map_err(|_| invalid())?;
        let hash = Sha256::new()
            .chain_update(b"aos.sandbox.delete.source-completion-transaction.v4\0")
            .chain_update(parent.as_bytes())
            .chain_update(operation.record_revision().get().to_be_bytes())
            .chain_update([phase.index_v4() as u8])
            .chain_update(physical)
            .finalize();
        let mut transaction_id = [0; 16];
        transaction_id.copy_from_slice(&hash[..16]);
        let member = LifecycleAuxiliaryRecordV1::proposal(
            pending.project,
            parent,
            operation.record_revision(),
            digest,
            previous.lineage(),
            previous.revision().checked_next().map_err(|_| invalid())?,
            Some(previous.complete_digest()),
            LifecycleAuxiliaryPayloadV1::Operation(operation.clone()),
            ResourceId::from_bytes(transaction_id),
            previous.replay_floor(),
            verifier.replay(),
        )
        .map_err(|_| invalid())?;
        let joined = bind_lifecycle_atomic_join_v1(vec![member]).map_err(|_| invalid())?;
        let member = joined.into_iter().next().ok_or_else(invalid)?;
        let successor = lifecycle_reducer_envelope_v1(
            envelope.key().clone(),
            envelope.revision().checked_add(1).ok_or_else(invalid)?,
            Some(envelope.digest()),
            LifecycleReducerRecordV1::Auxiliary(&member),
            &verifier,
        )
        .map_err(|_| invalid())?;
        let planned = aos_sandbox_broker::domain_transaction_custody::plan_members_v1::<Schema>(
            view,
            source_before,
            projection.root(),
            transaction_id,
            vec![successor],
            &verifier,
        )?;
        let mut records = planned.transaction().records().to_vec();
        if phase == DeleteSourceCompletionPhaseV4::Terminal {
            records.push(JournalRecord::delete(
                RecordNamespace::SourceDomainPolicyHold,
                aos_sandbox_ledger_replay::source_policy_hold::DELETE_PENDING_KEY.to_vec(),
            ));
        }
        let transaction = JournalTransaction::new(transaction_id, records)?;
        Ok(Self {
            phase,
            transaction,
            source_before,
            controller_before,
            batch,
            physical,
            clock,
            operation,
        })
    }

    pub(crate) fn phase_v4(&self) -> DeleteSourceCompletionPhaseV4 {
        self.phase
    }
    pub(crate) fn transaction_v4(&self) -> &JournalTransaction {
        &self.transaction
    }
    pub(crate) fn clock_bound_v4(&self) -> crate::normal_root::DeleteSourceClockBoundDataV3 {
        self.clock
    }
    pub(crate) fn operation_v4(&self) -> &LifecycleOperationV1 {
        &self.operation
    }
    pub(crate) fn physical_v4(&self) -> [u8; 32] {
        self.physical
    }

    pub(crate) fn require_controller_v4(&self, controller: u64) -> Result<(), JournalError> {
        if controller != self.controller_before {
            return Err(JournalError::StaleAuthoritySnapshot);
        }
        Ok(())
    }

    pub(crate) fn require_before_v4(
        &self,
        source: u64,
        controller: u64,
    ) -> Result<(), JournalError> {
        if (source, controller) != (self.source_before, self.controller_before) {
            return Err(JournalError::StaleAuthoritySnapshot);
        }
        Ok(())
    }

    // The sole semantic appender accepts this exception only while borrowing
    // the actual private completion plan from the genuine Pending finalizer.
    pub(crate) fn require_transition_v4(
        &self,
        state: &std::collections::BTreeMap<(RecordNamespace, Vec<u8>), Vec<u8>>,
        transaction: &JournalTransaction,
    ) -> Result<(), JournalError> {
        let held = aos_sandbox_ledger_replay::source_policy_hold::current_state(state)?;
        if held.delete_pending != Some(self.batch) || transaction != &self.transaction {
            return Err(JournalError::ProtectedBoundary);
        }
        Ok(())
    }

    pub(crate) fn require_saved_v4(
        &self,
        state: &std::collections::BTreeMap<(RecordNamespace, Vec<u8>), Vec<u8>>,
    ) -> Result<(), JournalError> {
        let held = aos_sandbox_ledger_replay::source_policy_hold::current_state(state)?;
        let expected =
            (self.phase != DeleteSourceCompletionPhaseV4::Terminal).then_some(self.batch);
        if held.delete_pending != expected
            || self.transaction.records().iter().any(|record| {
                state
                    .get(&(record.namespace(), record.key().to_vec()))
                    .map(Vec::as_slice)
                    != record.value()
            })
        {
            return Err(JournalError::StaleAuthoritySnapshot);
        }
        Ok(())
    }
}

pub(super) fn successor_v4(
    previous: &LifecycleOperationV1,
    predecessor: super::super::LifecycleRecordDigestV1,
    phase: DeleteSourceCompletionPhaseV4,
    physical: [u8; 32],
    now: RawPairedClockSample,
) -> Result<LifecycleOperationV1, LifecycleModelError> {
    let invalid = || LifecycleModelError::InvalidTransition;
    let [step] = previous.steps() else {
        return Err(invalid());
    };
    if step.index() != 0
        || step.class() != LifecycleStepClassV1::PostCommitForward
        || step.domain() != LifecycleStepDomainV1::Controller
        || step.is_unbound()
        || previous.compensation_progress() != 0
        || previous.forward_progress() != 0
    {
        return Err(invalid());
    }
    let time = u64::try_from(now.wall_seconds())
        .ok()
        .and_then(|seconds| seconds.checked_mul(1_000_000_000))
        .ok_or_else(invalid)
        .and_then(LifecycleTimeV1::new)?;
    let admission = LifecycleStepAdmissionDigestV1::commit(&physical);
    let (attempt, state, result, inventory, target, progress, terminal, finished) = match phase {
        DeleteSourceCompletionPhaseV4::Reserve => {
            if previous.phase() != LifecyclePhaseV1::Committed
                || step.state() != LifecycleStepStateV1::Planned
                || !step.forward_attempts().is_empty()
            {
                return Err(invalid());
            }
            let attempt = LifecycleEffectAttemptV1::new(
                1,
                LifecycleEffectDirectionV1::Forward,
                step.request(),
                step.request_body(),
                step.plan(),
                admission,
                time,
                LifecycleAttemptStateV1::Reserved,
                None,
                None,
                None,
                None,
                None,
            )?;
            (
                attempt,
                LifecycleStepStateV1::Applying,
                None,
                None,
                LifecyclePhaseV1::Completing,
                0,
                None,
                None,
            )
        }
        DeleteSourceCompletionPhaseV4::Terminal => {
            let [reserved] = step.forward_attempts() else {
                return Err(invalid());
            };
            if previous.phase() != LifecyclePhaseV1::Completing
                || step.state() != LifecycleStepStateV1::Applying
                || reserved.state() != LifecycleAttemptStateV1::Reserved
                || reserved.admission() != admission
            {
                return Err(invalid());
            }
            let result = LifecycleStepResultDigestV1::commit(&physical);
            let inventory = LifecycleInventoryDigestV1::commit(&physical);
            let attempt = LifecycleEffectAttemptV1::new(
                1,
                LifecycleEffectDirectionV1::Forward,
                step.request(),
                step.request_body(),
                step.plan(),
                admission,
                reserved.started_at(),
                LifecycleAttemptStateV1::Succeeded,
                Some(result),
                None,
                Some(inventory),
                None,
                Some(time),
            )?;
            (
                attempt,
                LifecycleStepStateV1::Applied,
                Some(result),
                Some(inventory),
                LifecyclePhaseV1::Terminal,
                1,
                Some(LifecycleTerminalResultV1::Succeeded),
                Some(time),
            )
        }
    };
    let step = LifecycleStepV1::new(
        step.index(),
        step.class(),
        step.domain(),
        step.request(),
        step.request_body(),
        step.plan(),
        None,
        None,
        None,
        state,
        vec![attempt],
        Vec::new(),
        result,
        None,
        inventory,
        None,
        None,
    )?;
    previous
        .successor(
            predecessor,
            target,
            progress,
            0,
            vec![step],
            previous.method_semantic_commit().cloned(),
            None,
            None,
            terminal,
            finished,
        )?
        .select_delete_batch_layout()
}

/// Compares the terminal full model with the independently accepted anchor.
pub(crate) fn require_terminal_operation_data_v4(
    accepted: &LifecycleOperationV1,
    current: &LifecycleOperationV1,
    physical: [u8; 32],
) -> Result<(), LifecycleModelError> {
    let invalid = || LifecycleModelError::InvalidTransition;
    let [old] = accepted.steps() else {
        return Err(invalid());
    };
    let [step] = current.steps() else {
        return Err(invalid());
    };
    let [attempt] = step.forward_attempts() else {
        return Err(invalid());
    };
    let result = LifecycleStepResultDigestV1::commit(&physical);
    let inventory = LifecycleInventoryDigestV1::commit(&physical);
    if physical == [0; 32]
        || accepted.phase() != LifecyclePhaseV1::Committed
        || current.phase() != LifecyclePhaseV1::Terminal
        || current.terminal_result() != Some(LifecycleTerminalResultV1::Succeeded)
        || current.forward_progress() != 1
        || current.compensation_progress() != 0
        || current.method_semantic_commit() != accepted.method_semantic_commit()
        || old.index() != step.index()
        || old.class() != step.class()
        || old.domain() != step.domain()
        || old.request() != step.request()
        || old.request_body() != step.request_body()
        || old.plan() != step.plan()
        || step.class() != LifecycleStepClassV1::PostCommitForward
        || step.domain() != LifecycleStepDomainV1::Controller
        || step.index() != 0
        || step.is_unbound()
        || !step.compensation_attempts().is_empty()
        || step.state() != LifecycleStepStateV1::Applied
        || attempt.state() != LifecycleAttemptStateV1::Succeeded
        || attempt.number() != 1
        || attempt.direction() != LifecycleEffectDirectionV1::Forward
        || attempt.request() != step.request()
        || attempt.body() != step.request_body()
        || attempt.plan() != step.plan()
        || attempt.admission() != LifecycleStepAdmissionDigestV1::commit(&physical)
        || attempt.result() != Some(result)
        || attempt.inventory() != Some(inventory)
        || step.result() != Some(result)
        || step.inventory() != Some(inventory)
    {
        return Err(invalid());
    }
    Ok(())
}
