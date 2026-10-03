//! Exact kind5 Attempt-selected local profile1 admission and cold rejoin.
//!
//! Current Abandoned T selects its successor S and actual predecessor S. The
//! full graph and fixed physical writer supply currentness; no old Head inverse
//! or caller-nominated reference map is reconstructed here.

use aos_sandbox_protocol::mount_source_acquisition_state::{
    DeadProviderExecutionProjectionV2, ProviderIntentV2, RecordRefV2, prepare_dead_replacement_v2,
};

use super::*;

pub(super) fn installed(
    state: &State,
    table: &MountSourceAcquisitionStateV2,
    primary: [u8; 32],
) -> Result<LocalPostimageBindings, JournalError> {
    let attempt = table.provider_attempts.get(&primary).ok_or_else(invalid)?;
    let ProviderAttemptStateV2::AbandonedIndeterminate {
        dead_execution,
        successor_session_id,
        recovery_root_attempt_id,
        outcome_may_exist: true,
        resolution: None,
    } = &attempt.state
    else {
        return Err(invalid());
    };
    let session = table
        .provider_sessions
        .get(successor_session_id)
        .ok_or_else(invalid)?;
    let predecessor = table
        .provider_sessions
        .get(&dead_execution.old_session_id)
        .filter(|value| value.record_digest == dead_execution.old_session_record_digest)
        .ok_or_else(invalid)?;
    let head = table
        .provider_heads
        .get(&(
            attempt.scope.holder_authority_id,
            attempt.scope.provider_authority_id,
        ))
        .ok_or_else(invalid)?;
    let barrier = head.recovery_barrier.as_ref().ok_or_else(invalid)?;
    let root = table
        .provider_attempts
        .get(recovery_root_attempt_id)
        .ok_or_else(invalid)?;
    let current_ref = RecordRefV2 {
        id: attempt.attempt_id,
        revision: attempt.revision,
        record_digest: attempt.record_digest,
    };
    if attempt.revision != 2
        || attempt.session_id != predecessor.session_id
        || attempt.session_record_digest != predecessor.record_digest
        || session.predecessor_session_id != Some(predecessor.session_id)
        || session.scope != attempt.scope
        || head.scope != attempt.scope
        || head.current_session_id != session.session_id
        || head.current_session_record_digest != session.record_digest
        || head.pending_attempt.is_some()
        || head.next_request_sequence != 1
        || head.next_response_sequence != 1
        || barrier.required_session_id != session.session_id
        || barrier.root_attempt.id != root.attempt_id
        || barrier.root_attempt.revision != root.revision
        || barrier.root_attempt.record_digest != root.record_digest
    {
        return Err(invalid());
    }

    let first = primary == root.attempt_id;
    if first {
        if barrier.replacement_count != 1 || barrier.recovery_inventory_tail.is_some() {
            return Err(invalid());
        }
    } else if attempt.owner != ProviderQueryOwnerV2::Inventory
        || attempt.method != ProviderMethodV2::Inventory
        || barrier.replacement_count < 2
        || barrier.recovery_inventory_tail != Some(current_ref)
        || !matches!(&attempt.intent, ProviderIntentV2::Inventory { value }
            if value.recovery_root_attempt_id == Some(root.attempt_id))
    {
        return Err(invalid());
    }

    let mut owner = Map::new();
    map_record(
        &mut owner,
        StoredRecordV2::ProviderQueryAttempt {
            value: attempt.clone(),
        },
    )?;
    map_record(
        &mut owner,
        StoredRecordV2::ProviderSession {
            value: session.clone(),
        },
    )?;
    let changed_row = if first {
        match attempt.owner {
            ProviderQueryOwnerV2::Acquire { acquisition_id }
            | ProviderQueryOwnerV2::Release { acquisition_id } => {
                let row = table
                    .acquisitions
                    .get(&acquisition_id)
                    .ok_or_else(invalid)?;
                if row.scope != attempt.scope
                    || !matches!(row.recovery, AcquisitionRecoveryV2::InventoryRequired { root_attempt }
                        if root_attempt == barrier.root_attempt)
                {
                    return Err(invalid());
                }
                map_record(
                    &mut owner,
                    StoredRecordV2::Acquisition { value: row.clone() },
                )?;
                Some(row)
            }
            ProviderQueryOwnerV2::Inventory => None,
        }
    } else {
        None
    };
    map_record(
        &mut owner,
        StoredRecordV2::ProviderHead {
            value: head.clone(),
        },
    )?;

    let mut references = Map::new();
    map_record(
        &mut references,
        StoredRecordV2::ProviderSession {
            value: predecessor.clone(),
        },
    )?;
    if !first {
        map_record(
            &mut references,
            StoredRecordV2::ProviderQueryAttempt {
                value: root.clone(),
            },
        )?;
    }
    let acquisition = match root.owner {
        ProviderQueryOwnerV2::Acquire { acquisition_id }
        | ProviderQueryOwnerV2::Release { acquisition_id } => Some(acquisition_key(acquisition_id)),
        ProviderQueryOwnerV2::Inventory => None,
    };
    let hseq = table
        .holder_sequences
        .get(&attempt.scope.holder_authority_id)
        .map_or(0, |value| value.revision);
    let transaction = transaction_id(
        MutationTagV2::DeadReplacement,
        attempt.scope.holder_authority_id,
        attempt.scope.provider_authority_id,
        hseq,
        head.revision,
        changed_row.map(|row| row.acquisition_id),
        changed_row.map(|row| row.revision),
        Some(attempt.attempt_id),
        Some(attempt.revision),
        Some(session.session_id),
    );
    Ok(LocalPostimageBindings {
        kind: Kind::DeadReplacement,
        primary,
        selector: 3,
        owner,
        reads: read_map(state, head)?,
        references,
        acquisition,
        transaction,
        session: session.clone(),
    })
}

pub(super) fn prepare(
    state: &State,
    successor: SourceProviderSessionV2,
    death: DeadProviderExecutionProjectionV2,
) -> Result<(JournalTransaction, OrdinaryCapacityRecordV4), JournalError> {
    let (checked, fences) = checked_owner(state)?;
    require_funded_local_owner(state, &checked)?;
    let table = checked.legacy();
    let before = table
        .provider_heads
        .get(&(
            successor.scope.holder_authority_id,
            successor.scope.provider_authority_id,
        ))
        .ok_or_else(invalid)?;
    let before_reads = read_map(state, before)?;
    let records = prepare_dead_replacement_v2(table, successor, death).map_err(|_| invalid())?;
    let Some(StoredRecordV2::ProviderQueryAttempt { value: primary }) = records.first() else {
        return Err(invalid());
    };
    let primary_id = primary.attempt_id;
    let mut after = state.clone();
    for record in &records {
        let (key, value) = stored(record.clone())?;
        after.insert((RecordNamespace::MountSourceAcquisition, key), value);
    }
    let after_graph = graph(&after)?;
    let bindings = installed(&after, after_graph.legacy(), primary_id)?;
    admitted_local_operation(state, records, bindings, before_reads, &fences)
}

pub(super) fn validate_admission(
    state: &State,
    transaction: &JournalTransaction,
) -> Result<(), JournalError> {
    let first = transaction.records().first().ok_or_else(invalid)?;
    let record =
        aos_sandbox_protocol::mount_source_acquisition_state::decode_mount_source_state_record_v2(
            first.key(),
            first.value().ok_or_else(invalid)?,
        )
        .map_err(|_| invalid())?;
    let StoredRecordV2::ProviderQueryAttempt { value: attempt } = record else {
        return Err(invalid());
    };
    let ProviderAttemptStateV2::AbandonedIndeterminate { dead_execution, .. } = attempt.state
    else {
        return Err(invalid());
    };
    let second = transaction.records().get(1).ok_or_else(invalid)?;
    let record =
        aos_sandbox_protocol::mount_source_acquisition_state::decode_mount_source_state_record_v2(
            second.key(),
            second.value().ok_or_else(invalid)?,
        )
        .map_err(|_| invalid())?;
    let StoredRecordV2::ProviderSession { value: successor } = record else {
        return Err(invalid());
    };
    if prepare(state, successor, dead_execution)?.0 != *transaction {
        return Err(invalid());
    }
    Ok(())
}
