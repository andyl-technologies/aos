//! Checks the same unchanged old Stop, A7 ancestry and independent A8 settlement.
//!
//! These are passive replay predicates. The genuine Source22 append loan and
//! completed Host3/Root48 native originals remain mandatory at the writer.

use super::*;
use crate::journal::JournalError;
use aos_sandbox_protocol::domain_ledger::stop_completion::LifecycleStopCompletionDataV1;

/// Selects exactly the unchanged Stop and one independent settlement member.
pub(in crate::lifecycle) fn bind_stop_completion_join_v1(
    mut records: Vec<LifecycleAuxiliaryRecordV1>,
) -> Result<Vec<LifecycleAuxiliaryRecordV1>, LifecycleModelError> {
    if records.len() != 2 || records.iter().any(|record| record.join_digest.is_some()) {
        return Err(LifecycleModelError::InvalidTransition);
    }
    records.sort_unstable_by_key(LifecycleAuxiliaryRecordV1::kind);
    require_pair_v1(&records, 0x101)?;
    for record in &mut records {
        record.format = LifecycleAuxiliaryEnvelopeFormatV1::StopCompletion;
    }
    bind_lifecycle_atomic_join_v1(records)
}

pub(super) fn require_pair_v1(
    records: &[LifecycleAuxiliaryRecordV1],
    members: u16,
) -> Result<(), LifecycleModelError> {
    if (members, records.len()) != (0x101, 2) {
        return Err(LifecycleModelError::InvalidTransition);
    }
    let LifecycleAuxiliaryPayloadV1::Operation(operation) = records[0].payload() else {
        return Err(LifecycleModelError::InvalidTransition);
    };
    let LifecycleAuxiliaryPayloadV1::StopCompletion(binding) = records[1].payload() else {
        return Err(LifecycleModelError::InvalidTransition);
    };
    require_stop_completion_current_v1(binding, operation)
}

pub(in crate::lifecycle) fn require_stop_completion_current_v1(
    binding: &LifecycleStopCompletionDataV1,
    operation: &super::super::LifecycleOperationV1,
) -> Result<(), LifecycleModelError> {
    use super::super::{LifecycleIntentV1, LifecyclePhaseV1};
    if binding.operation() != operation.operation_id()
        || !matches!(operation.intent(), LifecycleIntentV1::Stop { .. })
        || !matches!(operation.phase(), LifecyclePhaseV1::Completing | LifecyclePhaseV1::Residual)
        || operation.terminal_result().is_some()
    {
        return Err(LifecycleModelError::InvalidTransition);
    }
    let LifecycleIntentV1::Stop { fence, .. } = operation.intent() else {
        return Err(LifecycleModelError::InvalidTransition);
    };
    let historical = binding.evidence_v1().historical_scope_v1().fence_v4();
    if historical.sandbox_id() != fence.sandbox().as_bytes()
        || historical.incarnation_id() != fence.incarnation().as_bytes()
        || historical.assignment_epoch() != fence.assignment_epoch().get()
    {
        return Err(LifecycleModelError::InvalidTransition);
    }
    let encoded = encode_operation_record_v1(operation)?;
    let record = super::super::format::record_digest(&encoded)?;
    if record.digest() != binding.binding_v1().operation_record {
        return Err(LifecycleModelError::InvalidTransition);
    }
    Ok(())
}

pub(super) fn require_history_v1(
    history: &LifecycleAuxiliaryHistoryV1,
    record: &LifecycleAuxiliaryRecordV1,
    binding: &LifecycleStopCompletionDataV1,
) -> Result<(), LifecycleModelError> {
    let invalid = || LifecycleModelError::InvalidTransition;
    let operation = history.operations.operation(record.operation).ok_or_else(invalid)?;
    require_stop_completion_current_v1(binding, operation)?;
    if history.records.values().any(|previous|
        previous.operation == record.operation
            && previous.kind() == LifecycleAuxiliaryKindV1::StopCompletion)
    {
        return Err(invalid());
    }

    // The exact immutable A7 member must already exist in this same replay.
    // The binding's current Source root is checked by the native append owner;
    // no auxiliary checksum is mistaken for that independently current cut.
    let dispatch = history.records.values().find(|previous|
        previous.operation == record.operation
            && previous.kind() == LifecycleAuxiliaryKindV1::StopDispatch
            && previous.complete_digest() == binding.binding_v1().dispatch_record)
        .ok_or_else(invalid)?;
    let LifecycleAuxiliaryPayloadV1::StopDispatch(data) = dispatch.payload() else {
        return Err(invalid());
    };
    binding.require_dispatch_data_v1(data)?;
    let snapshot = history.records.values().find(|previous|
        previous.operation == record.operation
            && previous.atomic_join == dispatch.atomic_join
            && previous.kind() == LifecycleAuxiliaryKindV1::Operation)
        .ok_or_else(invalid)?;
    let LifecycleAuxiliaryPayloadV1::Operation(dispatched) = snapshot.payload() else {
        return Err(invalid());
    };
    require_stop_dispatch_ancestor_data_v1(dispatched, snapshot.operation_record,
        operation, record.operation_record).map_err(|_| invalid())
}

// A7 remains the exact pre-dispatch Completing snapshot. The sole accepted
// later pending shape is its direct, canonical residual successor; neither
// an equal operation ID nor a matching immutable intent proves this edge.
pub(in crate::lifecycle) fn require_stop_dispatch_ancestor_data_v1(
    dispatched: &LifecycleOperationV1,
    dispatched_record: LifecycleRecordDigestV1,
    current: &LifecycleOperationV1,
    current_record: LifecycleRecordDigestV1,
) -> Result<(), JournalError> {
    use crate::lifecycle::{LifecycleAttemptStateV1, LifecyclePhaseV1, LifecycleStepStateV1};

    if dispatched == current && dispatched_record == current_record {
        return Ok(());
    }
    if dispatched.phase() != LifecyclePhaseV1::Completing
        || current.phase() != LifecyclePhaseV1::Residual
        || current.predecessor_digest() != Some(dispatched_record)
        || dispatched.steps().len() != 1
        || current.steps().len() != 1
        || dispatched.forward_progress() != 0
        || current.forward_progress() != 0
        || current.compensation_progress() != 0
        || current.steps()[0].state() != LifecycleStepStateV1::Residual
        || current.steps()[0].forward_attempts().last()
            .is_none_or(|attempt| attempt.state() != LifecycleAttemptStateV1::Failed)
    {
        return Err(JournalError::ProtectedBoundary);
    }
    crate::lifecycle::require_same_lifecycle_admission_v1(dispatched, current)
        .map_err(|_| JournalError::ProtectedBoundary)?;
    let mut steps = Vec::new();
    steps.try_reserve_exact(current.steps().len())
        .map_err(|_| JournalError::JournalTooLarge)?;
    steps.extend_from_slice(current.steps());
    let successor = dispatched.successor(
        dispatched_record, current.phase(), current.forward_progress(),
        current.compensation_progress(), steps,
        current.method_semantic_commit().cloned(), current.failure(), current.retry(),
        current.terminal_result(), current.finished_at(),
    ).map_err(|_| JournalError::ProtectedBoundary)?;
    if &successor != current {
        return Err(JournalError::ProtectedBoundary);
    }
    Ok(())
}
