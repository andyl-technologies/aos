//! Pure canonical DATA preparation for one dead-provider replacement.
//!
//! The named owner mutation preserves its exact T/S/[A]/H order and tag6
//! identity inputs. It proves neither protected execution death nor live
//! Session custody; those remain the actual Security and Mount prerequisites.

use std::collections::BTreeMap;

use super::format::{seal_record, state_error};
use super::{
    AcquisitionRecoveryV2, DeadProviderExecutionProjectionV2, MountSourceAcquisitionStateV2,
    ProviderAttemptStateV2, ProviderIntentV2, ProviderMethodV2, ProviderQueryOwnerV2, RecordRefV2,
    RecoveryBarrierV2, Result, SourceProviderHeadV2, SourceProviderSessionV2, StoredRecordV2,
    validate_recovered_table,
};

/// Derives the exact canonical dead-replacement owner proposal as DATA.
///
/// It selects the current pending Head/Attempt from the successor's scope and
/// validates the complete tentative graph. Supplied death bytes are structural
/// DATA, not protected execution evidence or a current Session/writer grant.
/// The caller must separately consume the actual Security death-bound plan.
///
/// # Errors
///
/// Rejects an invalid graph, changed pending predecessor, reused or regressive
/// successor, invalid death/lineage joins, or an unrelated repeated Inventory.
#[doc(hidden)]
pub fn prepare_dead_replacement_v2(
    table: &MountSourceAcquisitionStateV2,
    successor: SourceProviderSessionV2,
    durable_death: DeadProviderExecutionProjectionV2,
) -> Result<Vec<StoredRecordV2>> {
    validate_recovered_table(table)?;
    let holder_authority_id = successor.scope.holder_authority_id;
    let provider_authority_id = successor.scope.provider_authority_id;
    let identity = (holder_authority_id, provider_authority_id);
    let current_head = table
        .provider_heads
        .get(&identity)
        .cloned()
        .ok_or_else(|| state_error("dead provider replacement head is absent"))?;
    let current_attempt_ref = current_head
        .pending_attempt
        .ok_or_else(|| state_error("dead provider replacement has no Reserved attempt"))?;
    let current_attempt = table
        .provider_attempts
        .get(&current_attempt_ref.id)
        .filter(|attempt| {
            attempt.revision == current_attempt_ref.revision
                && attempt.record_digest == current_attempt_ref.record_digest
                && attempt.session_id == current_head.current_session_id
                && matches!(&attempt.state, ProviderAttemptStateV2::Reserved)
        })
        .cloned()
        .ok_or_else(|| state_error("dead provider replacement attempt is not current"))?;
    let predecessor = table
        .provider_sessions
        .get(&current_head.current_session_id)
        .filter(|session| session.record_digest == current_head.current_session_record_digest)
        .cloned()
        .ok_or_else(|| state_error("dead provider predecessor session is absent"))?;
    validate_provider_session_successor_v2(&predecessor, &successor, &table.provider_sessions)?;
    if successor.barrier_idle_replacement.is_some() {
        return Err(state_error(
            "dead replacement has a barrier-idle Session witness",
        ));
    }

    let existing_barrier = current_head.recovery_barrier.as_ref();
    let root_attempt_id = existing_barrier.map_or(current_attempt.attempt_id, |barrier| {
        barrier.root_attempt.id
    });
    if existing_barrier.is_some()
        && !matches!(
            &current_attempt.intent,
            ProviderIntentV2::Inventory { value }
                if value.recovery_root_attempt_id == Some(root_attempt_id)
        )
    {
        return Err(state_error(
            "repeated provider death is not the required recovery Inventory",
        ));
    }
    let mut next_attempt = current_attempt.clone();
    next_attempt.revision = 2;
    next_attempt.state = ProviderAttemptStateV2::AbandonedIndeterminate {
        dead_execution: durable_death,
        successor_session_id: successor.session_id,
        recovery_root_attempt_id: root_attempt_id,
        outcome_may_exist: true,
        resolution: None,
    };
    next_attempt.record_digest = [0; 32];
    let next_attempt = sealed_attempt(next_attempt)?;
    let next_attempt_ref = record_ref(&StoredRecordV2::ProviderQueryAttempt {
        value: next_attempt.clone(),
    })?;
    let root_ref = existing_barrier.map_or(next_attempt_ref, |barrier| barrier.root_attempt);

    let next_row = match current_attempt.owner {
        ProviderQueryOwnerV2::Acquire { acquisition_id }
        | ProviderQueryOwnerV2::Release { acquisition_id }
            if existing_barrier.is_none() =>
        {
            let current_row = table
                .acquisitions
                .get(&acquisition_id)
                .cloned()
                .ok_or_else(|| state_error("dead provider attempt owner row is absent"))?;
            let mut row = current_row.clone();
            row.revision = next_revision(current_row.revision)?;
            match current_attempt.method {
                ProviderMethodV2::Acquire => {
                    let lineage = &mut row.acquire_lineage;
                    if lineage.tail != current_attempt_ref
                        || lineage.root.id != current_attempt.lineage_root_attempt_id
                        || (lineage.root.id == current_attempt_ref.id
                            && lineage.root != current_attempt_ref)
                    {
                        return Err(state_error(
                            "dead Acquire does not replace its exact lineage predecessor",
                        ));
                    }

                    // The sole stored revision changes; an original root
                    // must follow it without rewriting a different root.
                    if lineage.root == current_attempt_ref {
                        lineage.root = next_attempt_ref;
                    }
                    lineage.tail = next_attempt_ref;
                }
                ProviderMethodV2::Release => {
                    row.release_lineage
                        .as_mut()
                        .ok_or_else(|| state_error("dead Release lineage is absent"))?
                        .tail = next_attempt_ref;
                }
                ProviderMethodV2::Inventory => {
                    return Err(state_error("Inventory attempt has an acquisition owner"));
                }
            }
            row.recovery = AcquisitionRecoveryV2::InventoryRequired {
                root_attempt: root_ref,
            };
            row.record_digest = [0; 32];
            Some(sealed_row(row)?)
        }
        ProviderQueryOwnerV2::Inventory => None,
        _ => {
            return Err(state_error(
                "recovery barrier cannot replace another acquisition attempt",
            ));
        }
    };

    let mut next_head = current_head.clone();
    next_head.revision = next_revision(current_head.revision)?;
    next_head.holder_authority_generation = successor.root_mount_authority_generation;
    next_head.holder_authority_digest = successor.root_mount_authority_digest;
    next_head.provider_authority_generation = successor.provider_authority_generation;
    next_head.provider_authority_digest = successor.provider_authority_digest;
    next_head.current_session_id = successor.session_id;
    next_head.current_session_record_digest = successor.record_digest;
    next_head.next_request_sequence = 1;
    next_head.next_response_sequence = 1;
    next_head.pending_attempt = None;
    next_head.last_reconciliation = None;
    next_head.recovery_barrier = Some(RecoveryBarrierV2 {
        root_attempt: root_ref,
        baseline_inventory_ordinal: existing_barrier
            .map_or(current_head.inventory_observation_ordinal, |barrier| {
                barrier.baseline_inventory_ordinal
            }),
        required_session_id: successor.session_id,
        recovery_inventory_tail: existing_barrier.map(|_| next_attempt_ref),
        replacement_count: existing_barrier.map_or(Ok(1), |barrier| {
            barrier
                .replacement_count
                .checked_add(1)
                .ok_or_else(|| state_error("provider replacement count is exhausted"))
        })?,
    });
    next_head.record_digest = [0; 32];
    let next_head = sealed_head(next_head)?;
    let mut records = vec![
        StoredRecordV2::ProviderQueryAttempt {
            value: next_attempt,
        },
        StoredRecordV2::ProviderSession { value: successor },
    ];
    if let Some(row) = next_row {
        records.push(StoredRecordV2::Acquisition { value: row });
    }
    records.push(StoredRecordV2::ProviderHead {
        value: next_head.clone(),
    });

    let mut after = table.clone();
    for record in &records {
        match record {
            StoredRecordV2::ProviderQueryAttempt { value } => {
                after
                    .provider_attempts
                    .insert(value.attempt_id, value.clone());
            }
            StoredRecordV2::ProviderSession { value } => {
                after
                    .provider_sessions
                    .insert(value.session_id, value.clone());
            }
            StoredRecordV2::Acquisition { value } => {
                after
                    .acquisitions
                    .insert(value.acquisition_id, value.clone());
            }
            StoredRecordV2::ProviderHead { value } => {
                after.provider_heads.insert(identity, value.clone());
            }
            StoredRecordV2::HolderSequence { .. } => {
                return Err(state_error("dead replacement changed holder sequence"));
            }
        }
    }
    validate_recovered_table(&after)?;
    Ok(records)
}

fn sealed_attempt(
    value: super::SourceProviderQueryAttemptV2,
) -> Result<super::SourceProviderQueryAttemptV2> {
    match seal_record(StoredRecordV2::ProviderQueryAttempt { value })? {
        StoredRecordV2::ProviderQueryAttempt { value } => Ok(value),
        _ => Err(state_error("sealed provider attempt changed record kind")),
    }
}

fn sealed_row(value: super::SourceAcquisitionRowV2) -> Result<super::SourceAcquisitionRowV2> {
    match seal_record(StoredRecordV2::Acquisition { value })? {
        StoredRecordV2::Acquisition { value } => Ok(value),
        _ => Err(state_error("sealed acquisition changed record kind")),
    }
}

fn sealed_head(value: SourceProviderHeadV2) -> Result<SourceProviderHeadV2> {
    match seal_record(StoredRecordV2::ProviderHead { value })? {
        StoredRecordV2::ProviderHead { value } => Ok(value),
        _ => Err(state_error("sealed provider head changed record kind")),
    }
}

fn record_ref(record: &StoredRecordV2) -> Result<RecordRefV2> {
    let StoredRecordV2::ProviderQueryAttempt { value } = record else {
        return Err(state_error(
            "dead replacement reference changed record kind",
        ));
    };
    Ok(RecordRefV2 {
        id: value.attempt_id,
        revision: value.revision,
        record_digest: value.record_digest,
    })
}

fn next_revision(current: u64) -> Result<u64> {
    current
        .checked_add(1)
        .ok_or_else(|| state_error("AOSMSA02 record revision is exhausted"))
}

fn monotonic(
    old_generation: u64,
    old_digest: [u8; 32],
    new_generation: u64,
    new_digest: [u8; 32],
) -> bool {
    new_generation > old_generation
        || (new_generation == old_generation && new_digest == old_digest)
}

/// Validates the existing monotonic successor Session DATA constraints.
///
/// This does not validate current live custody, execution death or a writer.
///
/// # Errors
///
/// Rejects reused identities, changed scope or regressive/equivocating authority,
/// route, trust or revocation history.
#[doc(hidden)]
pub fn validate_provider_session_successor_v2(
    predecessor: &SourceProviderSessionV2,
    successor: &SourceProviderSessionV2,
    sessions: &BTreeMap<[u8; 32], SourceProviderSessionV2>,
) -> Result<()> {
    if successor.scope != predecessor.scope
        || successor.session_id == predecessor.session_id
        || sessions.contains_key(&successor.session_id)
        || !monotonic(
            predecessor.root_mount_authority_generation,
            predecessor.root_mount_authority_digest,
            successor.root_mount_authority_generation,
            successor.root_mount_authority_digest,
        )
        || !monotonic(
            predecessor.provider_authority_generation,
            predecessor.provider_authority_digest,
            successor.provider_authority_generation,
            successor.provider_authority_digest,
        )
        || !monotonic(
            predecessor.route_generation,
            predecessor.route_digest,
            successor.route_generation,
            successor.route_digest,
        )
        || !monotonic(
            predecessor.trust_generation,
            predecessor.trust_digest,
            successor.trust_generation,
            successor.trust_digest,
        )
        || !monotonic(
            predecessor.revocation_generation,
            predecessor.revocation_digest,
            successor.revocation_generation,
            successor.revocation_digest,
        )
    {
        return Err(state_error(
            "provider successor session rolls back or equivocates protected history",
        ));
    }
    Ok(())
}
