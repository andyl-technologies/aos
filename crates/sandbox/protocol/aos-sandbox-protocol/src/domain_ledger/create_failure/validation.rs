//! Rejoins actual terminal rows and immutable prepare floors without grants.

use super::*;

/// Validates either terminal receipt against the same historical rows.
///
/// # Errors
/// Preserves ordered historical protection, decoding and relation failures.
pub fn validate_failed_create_operation(
    journal: &CreateFailureHistoricalDataV2<'_>,
    operation_id: OperationId,
    operation: OperationRecord,
) -> Result<(), CreateFailureDataErrorV2> {
    if operation.effect_count() != 1 {
        if operation.state() == OperationState::FailedBeforeCommit {
            return Err(invalid_settlement());
        }

        // A special receipt on any step of a multi-effect operation must not
        // evade cold replay merely because the operation cannot settle Create.
        for step in 0..operation.effect_count() {
            let bytes = journal
                .get(RecordNamespace::Effect, &effect_key(operation_id, step))
                .ok_or_else(invalid_settlement)?;
            let effect = decode_effect(bytes)
                .map_err(CreateFailureDataErrorV2::from)?
                .into_parts();
            if let EffectState::Applied { receipt, .. } = effect.1 {
                if has_special_receipt_data_v2(receipt.as_bytes()).map_err(|()| invalid_settlement())?
                {
                    return Err(invalid_settlement());
                }
            }
        }
        return Ok(());
    }
    let bytes = journal
        .get(RecordNamespace::Effect, &effect_key(operation_id, 0))
        .ok_or_else(invalid_settlement)?;
    let effect = decode_effect(bytes).map_err(CreateFailureDataErrorV2::from)?;
    let (receipt, effect_attempt) = match effect.state() {
        EffectState::Applied { attempt, receipt } => {
            match CreateFailureReceiptDataV2::decode(receipt.as_bytes()).map_err(|()| invalid_settlement())? {
                Some(CreateFailureReceiptDataV2::ClosedBeforeArgument(receipt)) => {
                    return validate_failed_operation_v2(journal, operation_id, operation, &effect, *attempt, receipt);
                }
                Some(CreateFailureReceiptDataV2::AfterArgument(receipt)) => (Some(receipt), *attempt),
                None => (None, *attempt),
            }
        }
        _ => (None, 0),
    };
    if operation.state() != OperationState::FailedBeforeCommit {
        return if receipt.is_some() {
            Err(invalid_settlement())
        } else {
            Ok(())
        };
    }

    journal.ensure_protected_authority()?;
    let receipt = receipt.ok_or_else(invalid_settlement)?;
    let floor = load_floor(journal, operation_id)?.ok_or_else(invalid_settlement)?;
    let marker = receipt.marker.fields();
    if operation.ownership_gated()
        || operation.runtime_intent_digest().is_some()
        || operation.public_operation().map(|public| public.method())
            != Some(PublicOperationMethodV1::CreateExecution)
        || effect.plan().public_mutation_method() != Some(PublicOperationMethodV1::CreateExecution)
        || marker.create_operation_id != operation_id.into_bytes()
        || receipt.successor_operation != operation_digest(operation)
        || receipt.effect_attempt != effect_attempt
        || floor.marker != receipt.marker
        || floor.archive_head != receipt.archive_head
        || floor.signed_outcome != receipt.signed_outcome
        || floor.current_host_cut != receipt.current_host_cut
        || floor.wall_seconds != receipt.wall_seconds
    {
        return Err(invalid_settlement());
    }

    let projection = PublicProjectionStoreV1::new(journal)
        .get(PublicProjectionKindV1::Execution, marker.execution_id)
        .map_err(|_| invalid_settlement())?
        .ok_or_else(invalid_settlement)?;
    let PublicProjectionResourceV1::Execution(execution) = projection.resource() else {
        return Err(invalid_settlement());
    };
    let admission = recovered_public_operation_admission_v1(journal, operation_id)?
        .ok_or_else(invalid_settlement)?;
    if admission.authorization().project() != projection.project()
        || admission.authorization().resource_kind() != ResourceKind::Execution
    {
        return Err(invalid_settlement());
    }
    validate_accepted_create_identity(&effect, operation_id, execution)?;
    let expected_sequence = receipt
        .predecessor_sequence
        .checked_add(1)
        .ok_or_else(invalid_settlement)?;
    if projection.operation() != operation_id
        || projection.revision() != receipt.successor_revision
        || execution.phase.as_known() != Some(ExecutionPhase::EXECUTION_PHASE_FAILED)
        || execution.observation_sequence != expected_sequence
        || execution.resource_version.as_slice() != receipt.resource_version()
        || execution.access.as_option().is_some()
        || execution.result.as_option().is_some()
        || execution
            .last_successful_reconciliation_time
            .as_option()
            .is_none_or(|time| time.seconds != receipt.wall_seconds || time.nanoseconds != 0)
    {
        return Err(invalid_settlement());
    }
    Ok(())
}

/// Validates the closed terminal operation, receipt and prepare relation.
///
/// # Errors
/// Preserves ordered historical protection, decoding and relation failures.
pub fn validate_failed_operation_v2(
    journal: &CreateFailureHistoricalDataV2<'_>, operation_id: OperationId, operation: OperationRecord,
    effect: &crate::domain_ledger::effect_history::EffectLedgerRecord,
    effect_attempt: u32, receipt: ClosedCreateFailureReceiptV2,
) -> Result<(), CreateFailureDataErrorV2> {
    journal.ensure_protected_authority()?;
    super::planning::require_accepted_request_digest_data_v2(journal, receipt.identity.marker)?;
    let floor = load_floor_v2(journal, operation_id)?;
    let source = receipt.identity.marker.fields().source.fields();
    if operation.state() != OperationState::FailedBeforeCommit || operation.effect_count() != 1
        || operation.ownership_gated() || operation.runtime_intent_digest().is_some()
        || operation.public_operation().map(|public| public.method()) != Some(PublicOperationMethodV1::CreateExecution)
        || effect.plan().public_mutation_method() != Some(PublicOperationMethodV1::CreateExecution)
        || effect.dispatch().is_some() || source.create_operation != operation_id.into_bytes()
        || receipt.successor_operation != operation_digest(operation)
        || receipt.effect_attempt != effect_attempt || floor.identity != receipt.identity
        || floor.wall_seconds != receipt.wall_seconds
    { return Err(invalid_settlement()); }

    let projection = PublicProjectionStoreV1::new(journal)
        .get(PublicProjectionKindV1::Execution, source.execution)
        .map_err(|_| invalid_settlement())?.ok_or_else(invalid_settlement)?;
    let PublicProjectionResourceV1::Execution(execution) = projection.resource() else {
        return Err(invalid_settlement());
    };
    let admission = recovered_public_operation_admission_v1(journal, operation_id)?
        .ok_or_else(invalid_settlement)?;
    validate_accepted_create_identity(effect, operation_id, execution)?;
    if admission.authorization().project() != projection.project()
        || admission.authorization().resource_kind() != ResourceKind::Execution
        || projection.operation() != operation_id || projection.revision() != receipt.successor_revision
        || execution.sandbox_id.as_slice() != source.sandbox
        || execution.sandbox_incarnation_id.as_slice() != source.incarnation
        || execution.execution_id.as_slice() != source.execution
        || execution.phase.as_known() != Some(ExecutionPhase::EXECUTION_PHASE_FAILED)
        || execution.observation_sequence != receipt.predecessor_sequence.checked_add(1).ok_or_else(invalid_settlement)?
        || execution.resource_version.as_slice() != receipt.resource_version()
        || execution.access.as_option().is_some() || execution.result.as_option().is_some()
        || execution.last_successful_reconciliation_time.as_option()
            .is_none_or(|time| time.seconds != receipt.wall_seconds || time.nanoseconds != 0)
    { return Err(invalid_settlement()); }
    if actual_record_digests_v2(journal, floor)? != floor.successor {
        return Err(invalid_settlement());
    }
    Ok(())
}

/// Validates a closed prepare against its exact original or successor rows.
///
/// # Errors
/// Preserves ordered historical protection, decoding and relation failures.
pub fn validate_floor_v2(journal: &CreateFailureHistoricalDataV2<'_>, key: &[u8], bytes: &[u8]) -> Result<(), CreateFailureDataErrorV2> {
    journal.ensure_protected_authority()?;
    let floor = ClosedCreateFailurePrepareDataV2::decode_canonical(key, bytes).map_err(|_| invalid_settlement())?;
    super::planning::require_accepted_request_digest_data_v2(journal, floor.identity.marker)?;
    let operation_bytes = journal.get(RecordNamespace::Operation, key).ok_or_else(invalid_settlement)?;
    let operation = decode_operation(operation_bytes)?;
    let effect_bytes = journal.get(RecordNamespace::Effect, &effect_key(floor.operation, 0))
        .ok_or_else(invalid_settlement)?;
    let effect = decode_effect(effect_bytes).map_err(CreateFailureDataErrorV2::from)?;
    let actual = actual_record_digests_v2(journal, floor)?;
    match operation.state() {
        OperationState::FailedBeforeCommit if actual == floor.successor => {
            let EffectState::Applied { attempt, receipt } = effect.state() else {
                return Err(invalid_settlement());
            };
            let Some(CreateFailureReceiptDataV2::ClosedBeforeArgument(receipt)) =
                CreateFailureReceiptDataV2::decode(receipt.as_bytes()).map_err(|_| invalid_settlement())?
            else { return Err(invalid_settlement()); };
            validate_failed_operation_v2(journal, floor.operation, operation, &effect, *attempt, receipt)
        }
        OperationState::Applying if actual == floor.predecessor => {
            let source = floor.identity.marker.fields().source.fields();
            let projection = PublicProjectionStoreV1::new(journal)
                .get(PublicProjectionKindV1::Execution, source.execution)
                .map_err(|_| invalid_settlement())?.ok_or_else(invalid_settlement)?;
            let PublicProjectionResourceV1::Execution(execution) = projection.resource() else {
                return Err(invalid_settlement());
            };
            let admission = recovered_public_operation_admission_v1(journal, floor.operation)?
                .ok_or_else(invalid_settlement)?;
            if operation.effect_count() != 1 || operation.ownership_gated()
                || operation.runtime_intent_digest().is_some()
                || operation.public_operation().map(|public| public.method()) != Some(PublicOperationMethodV1::CreateExecution)
                || effect.plan().public_mutation_method() != Some(PublicOperationMethodV1::CreateExecution)
                || effect.dispatch().is_some() || !matches!(effect.state(), EffectState::Applying { .. })
                || projection.operation() != floor.operation || execution.execution_id.as_slice() != source.execution
                || execution.sandbox_id.as_slice() != source.sandbox
                || execution.sandbox_incarnation_id.as_slice() != source.incarnation
                || execution.phase.as_known() != Some(ExecutionPhase::EXECUTION_PHASE_REQUESTED)
                || execution.result.as_option().is_some()
                || admission.authorization().project() != projection.project()
                || admission.authorization().resource_kind() != ResourceKind::Execution
            { return Err(invalid_settlement()); }
            validate_accepted_create_identity(&effect, floor.operation, execution)
        }
        _ => Err(invalid_settlement()),
    }
}

fn load_floor_v2(journal: &CreateFailureHistoricalDataV2<'_>, operation: OperationId) -> Result<ClosedCreateFailurePrepareDataV2, CreateFailureDataErrorV2> {
    let bytes = journal.get(RecordNamespace::ControllerCreateFailurePrepare, operation.as_bytes())
        .ok_or_else(invalid_settlement)?;
    ClosedCreateFailurePrepareDataV2::decode_canonical(operation.as_bytes(), bytes).map_err(|_| invalid_settlement())
}

fn actual_record_digests_v2(
    journal: &CreateFailureHistoricalDataV2<'_>,
    floor: ClosedCreateFailurePrepareDataV2,
) -> Result<[ObjectDigest; 3], CreateFailureDataErrorV2> {
    let records = actual_records_data_v2(journal, floor)?;
    Ok([
        record_digest(&records[0])?,
        record_digest(&records[1])?,
        record_digest(&records[2])?,
    ])
}

pub(super) fn actual_records_data_v2(
    journal: &CreateFailureHistoricalDataV2<'_>,
    floor: ClosedCreateFailurePrepareDataV2,
) -> Result<[JournalRecord; 3], CreateFailureDataErrorV2> {
    let effect_key = effect_key(floor.operation, 0);
    let desired_key = desired_execution_key(
        journal,
        floor.identity.marker.fields().source.fields().execution,
    )?;
    let effect = journal
        .get(RecordNamespace::Effect, &effect_key)
        .ok_or_else(invalid_settlement)?;
    let operation = journal
        .get(RecordNamespace::Operation, floor.operation.as_bytes())
        .ok_or_else(invalid_settlement)?;
    let desired = journal
        .get(RecordNamespace::DesiredState, &desired_key)
        .ok_or_else(invalid_settlement)?;
    Ok([
        JournalRecord::put(
            RecordNamespace::Effect,
            effect_key.to_vec(),
            effect.to_vec(),
        ),
        JournalRecord::put(
            RecordNamespace::Operation,
            floor.operation.into_bytes().to_vec(),
            operation.to_vec(),
        ),
        JournalRecord::put(RecordNamespace::DesiredState, desired_key, desired.to_vec()),
    ])
}
