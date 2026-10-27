//! Shares the sole canonical readonly body for borrowed Controller Journal work.
//!
//! Ordinary entry points delegate immediately; scoped Host entry retains the
//! genuine Start native owner through this same validation and commit engine.

use super::*;



pub(in crate::reconciler) fn load_operation(
        journal: &Journal,
        operation_id: OperationId,
    ) -> Result<OperationRecord, ReconcilerError> {
    aos_sandbox_protocol::historical_operation_read_data_v2! {
        read = journal.get(RecordNamespace::Operation, operation_id.as_bytes()),
        missing = ReconcilerError::OperationNotFound,
        project = ReconcilerError::from
    }
}

pub(in crate::reconciler) fn load_operation_rows_v2(
    rows: aos_sandbox_protocol::domain_ledger::readonly::HistoricalLedgerRowsDataV2<'_>, operation_id: OperationId,
) -> Result<OperationRecord, ReconcilerError> {
    aos_sandbox_protocol::historical_operation_read_data_v2! {
        read = rows.get_data_v2(RecordNamespace::Operation, operation_id.as_bytes()),
        missing = ReconcilerError::OperationNotFound,
        project = ReconcilerError::from
    }
}

pub(in crate::reconciler) fn pending_operation_count(journal: &Journal) -> Result<usize, ReconcilerError> {
    let mut pending = 0_usize;
    let adopted_children = observe_reservation::adopted_operations(&journal)?;
    for (key, value) in journal.records(RecordNamespace::Operation) {
        let operation_id = decode_operation_key(key)?;
        if adopted_children.contains(&operation_id) {
            continue;
        }
        let operation = decode_operation(value)?;
        if !operation.state().is_terminal() {
            pending = pending
                .checked_add(1)
                .ok_or(ReconcilerError::CorruptLedger(
                    "pending operation count overflow",
                ))?;
        }
    }
    Ok(pending)
}

pub(in crate::reconciler) fn validate_canceled_operation(
        journal: &Journal,
        operation_id: OperationId,
        operation: OperationRecord,
    ) -> Result<(), ReconcilerError> {
    if operation.state() != OperationState::CanceledBeforeCommit {
        return Ok(());
    }
    if operation.effect_count() != 1
        || operation.ownership_gated()
        || operation.public_operation().is_none()
    {
        return Err(ReconcilerError::CorruptLedger(
            "invalid canceled-before-commit operation",
        ));
    }

    let bytes = journal
        .get(RecordNamespace::Effect, &effect_key(operation_id, 0))
        .ok_or(ReconcilerError::CorruptLedger(
            "canceled operation is missing its effect",
        ))?;
    let effect = decode_effect(bytes)
        .map_err(ReconcilerError::from)?
        .into_parts();
    let EffectState::Applied { receipt, .. } = effect.1 else {
        return Err(ReconcilerError::CorruptLedger(
            "canceled operation effect is not applied",
        ));
    };
    if effect.0.public_mutation_method().is_none()
        || receipt
            .canceled_before_commit_evidence()
            .map_err(|()| {
                ReconcilerError::CorruptLedger("invalid canceled-before-commit effect receipt")
            })?
            .is_none()
    {
        return Err(ReconcilerError::CorruptLedger(
            "canceled operation lacks cancellation evidence",
        ));
    }
    Ok(())
}

pub(in crate::reconciler) fn validate_gated_effects_for_activation(
        journal: &Journal,
        operation_id: OperationId,
        effect_count: u32,
    ) -> Result<(), ReconcilerError> {
    for step in 0..effect_count {
        let bytes = journal
            .get(RecordNamespace::Effect, &effect_key(operation_id, step))
            .ok_or(ReconcilerError::CorruptLedger(
                "ownership-gated operation is missing an effect",
            ))?;
        if !matches!(
            decode_effect(bytes).map_err(ReconcilerError::from)?.state(),
            EffectState::Planned
        ) {
            return Err(ReconcilerError::CorruptLedger(
                "ownership-gated effect advanced before activation",
            ));
        }
    }
    for (key, _) in journal.records(RecordNamespace::Effect) {
        if key.len() >= OPERATION_KEY_BYTES
            && &key[..OPERATION_KEY_BYTES] == operation_id.as_bytes()
        {
            let step_bytes: [u8; 4] = key
                .get(OPERATION_KEY_BYTES..)
                .ok_or(ReconcilerError::CorruptLedger(
                    "invalid ownership-gated effect key",
                ))?
                .try_into()
                .map_err(|_| {
                    ReconcilerError::CorruptLedger("invalid ownership-gated effect key")
                })?;
            if u32::from_be_bytes(step_bytes) >= effect_count {
                return Err(ReconcilerError::CorruptLedger(
                    "ownership-gated operation has an extra effect",
                ));
            }
        }
    }
    Ok(())
}

pub(in crate::reconciler) fn validate_public_operation_authorizations(journal: &Journal) -> Result<(), ReconcilerError> {
    for (key, value) in journal
        .records(RecordNamespace::PublicOperationAuthorization)
    {
        let operation_id = decode_operation_key(key)?;
        let operation = load_operation(journal, operation_id).map_err(|error| {
            if matches!(error, ReconcilerError::OperationNotFound) {
                ReconcilerError::CorruptLedger("orphan public operation authorization binding")
            } else {
                error
            }
        })?;
        if operation.public_operation().is_none() {
            return Err(ReconcilerError::CorruptLedger(
                "authorization binding refers to a non-public operation",
            ));
        }
        PublicOperationAuthorizationV1::decode(value)?;
    }
    Ok(())
}
