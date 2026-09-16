//! Immutable attempt-lineage and direction-sequence graph validation.

use super::*;

pub(super) fn validate_lineages(table: &SourceAcquisitionTableV2) -> Result<()> {
    let mut successors = BTreeMap::new();
    for attempt in table.provider_attempts.values() {
        if let Some(predecessor) = attempt.previous_attempt_id {
            if successors.insert(predecessor, attempt.attempt_id).is_some() {
                return Err(state_error("provider query attempt lineage forks"));
            }
        }
    }
    if table.provider_attempts.values().any(|attempt| {
        is_complete(attempt)
            && successors
                .get(&attempt.attempt_id)
                .and_then(|successor| table.provider_attempts.get(successor))
                .is_some_and(|successor| {
                    attempt.method != ProviderMethodV2::Inventory
                        || successor.method != ProviderMethodV2::Inventory
                })
    }) {
        return Err(state_error(
            "Complete provider disposition has a later lineage attempt",
        ));
    }

    let mut authoritative_roots = BTreeSet::new();
    for row in table.acquisitions.values() {
        validate_lineage(
            table,
            &successors,
            &row.acquire_lineage,
            ProviderQueryOwnerV2::Acquire {
                acquisition_id: row.acquisition_id,
            },
            ProviderMethodV2::Acquire,
            row.acquire_intent_digest,
        )?;
        validate_lineage_terminal_join(
            table,
            row.acquire_lineage.root.id,
            row.acquire_lineage.tail.id,
            row.acquire_terminal_attempt,
        )?;
        authoritative_roots.insert(row.acquire_lineage.root.id);
        if let Some(lineage) = &row.release_lineage {
            let digest = row
                .release_intent_digest
                .ok_or_else(|| state_error("Release lineage lacks intent digest"))?;
            validate_lineage(
                table,
                &successors,
                lineage,
                ProviderQueryOwnerV2::Release {
                    acquisition_id: row.acquisition_id,
                },
                ProviderMethodV2::Release,
                digest,
            )?;
            validate_lineage_terminal_join(
                table,
                lineage.root.id,
                lineage.tail.id,
                row.release_terminal_attempt,
            )?;
            authoritative_roots.insert(lineage.root.id);
        }
        if let Some(ReleaseProofV2::ProviderInventory { attempt, .. }) = &row.release_proof {
            let inventory = exact_attempt(table, *attempt)?;
            authoritative_roots.insert(inventory.lineage_root_attempt_id);
        }
    }
    for head in table.provider_heads.values() {
        for reference in [
            head.last_inventory_attempt,
            head.inventory_floor.as_ref().map(|floor| floor.attempt),
            head.recovery_barrier
                .as_ref()
                .and_then(|barrier| barrier.recovery_inventory_tail),
        ]
        .into_iter()
        .flatten()
        {
            let tail = exact_attempt(table, reference)?;
            validate_attempt_chain(
                table,
                tail,
                ProviderQueryOwnerV2::Inventory,
                ProviderMethodV2::Inventory,
                tail.immutable_intent_digest,
            )?;
            authoritative_roots.insert(tail.lineage_root_attempt_id);
        }
        for reference in [
            head.last_inventory_attempt,
            head.recovery_barrier
                .as_ref()
                .and_then(|barrier| barrier.recovery_inventory_tail),
        ]
        .into_iter()
        .flatten()
        {
            if successors.contains_key(&reference.id) {
                return Err(state_error(
                    "provider head Inventory tail has an unreferenced successor",
                ));
            }
        }
        if let Some(barrier) = &head.recovery_barrier {
            let root = exact_attempt(table, barrier.root_attempt)?;
            validate_attempt_chain(
                table,
                root,
                root.owner,
                root.method,
                root.immutable_intent_digest,
            )?;
            authoritative_roots.insert(barrier.root_attempt.id);
        }
        if let Some(reference) = head.pending_attempt {
            let pending = exact_attempt(table, reference)?;
            if pending.owner == ProviderQueryOwnerV2::Inventory {
                validate_attempt_chain(
                    table,
                    pending,
                    pending.owner,
                    pending.method,
                    pending.immutable_intent_digest,
                )?;
                authoritative_roots.insert(pending.lineage_root_attempt_id);
            }
        }
    }
    for attempt in table.provider_attempts.values() {
        if let ProviderAttemptStateV2::AbandonedIndeterminate {
            resolution: Some(resolution),
            ..
        } = &attempt.state
        {
            let inventory = exact_attempt(table, recovery_inventory_reference(resolution))?;
            authoritative_roots.insert(inventory.lineage_root_attempt_id);
        }
        if let Some(OwnerPredecessorWitnessV2::ProviderHead { value }) = &attempt.owner_predecessor
        {
            for reference in [
                value.last_inventory_attempt,
                value.inventory_floor.as_ref().map(|floor| floor.attempt),
                value
                    .recovery_barrier
                    .as_ref()
                    .map(|barrier| barrier.root_attempt),
                value
                    .recovery_barrier
                    .as_ref()
                    .and_then(|barrier| barrier.recovery_inventory_tail),
            ]
            .into_iter()
            .flatten()
            {
                let retained = exact_attempt(table, reference)?;
                authoritative_roots.insert(retained.lineage_root_attempt_id);
            }
        }
    }

    for attempt in table.provider_attempts.values() {
        if !authoritative_roots.contains(&attempt.lineage_root_attempt_id) {
            return Err(state_error(
                "provider attempt is unreachable from every durable owner",
            ));
        }
        let root = table
            .provider_attempts
            .get(&attempt.lineage_root_attempt_id)
            .ok_or_else(|| state_error("provider attempt lineage root is missing"))?;
        if root.previous_attempt_id.is_some()
            || root.attempt_number != 1
            || root.lineage_root_attempt_id != root.attempt_id
        {
            return Err(state_error("provider attempt lineage root is invalid"));
        }
        validate_attempt_chain(
            table,
            attempt,
            root.owner,
            root.method,
            root.immutable_intent_digest,
        )?;
    }
    Ok(())
}

pub(super) fn validate_lineage_terminal_join(
    table: &SourceAcquisitionTableV2,
    root_id: [u8; 32],
    tail_id: [u8; 32],
    retained_terminal: Option<RecordRefV2>,
) -> Result<()> {
    let complete = table
        .provider_attempts
        .values()
        .filter(|attempt| attempt.lineage_root_attempt_id == root_id && is_complete(attempt))
        .collect::<Vec<_>>();
    match (complete.as_slice(), retained_terminal) {
        ([], None) => Ok(()),
        ([attempt], Some(reference))
            if attempt.attempt_id == tail_id
                && reference.id == attempt.attempt_id
                && reference.revision == attempt.revision
                && reference.record_digest == attempt.record_digest =>
        {
            Ok(())
        }
        _ => Err(state_error(
            "provider query lineage Complete outcome is not its retained terminal",
        )),
    }
}

pub(super) fn validate_lineage(
    table: &SourceAcquisitionTableV2,
    successors: &BTreeMap<[u8; 32], [u8; 32]>,
    lineage: &QueryLineageV2,
    owner: ProviderQueryOwnerV2,
    method: ProviderMethodV2,
    intent_digest: [u8; 32],
) -> Result<()> {
    let root = exact_attempt(table, lineage.root)?;
    let tail = exact_attempt(table, lineage.tail)?;
    if root.previous_attempt_id.is_some()
        || root.attempt_number != 1
        || root.lineage_root_attempt_id != root.attempt_id
        || tail.lineage_root_attempt_id != root.attempt_id
        || successors.contains_key(&tail.attempt_id)
        || lineage.next_attempt_number
            != tail
                .attempt_number
                .checked_add(1)
                .ok_or_else(|| state_error("provider attempt number overflow"))?
    {
        return Err(state_error("provider query lineage endpoints are invalid"));
    }
    validate_attempt_chain(table, tail, owner, method, intent_digest)
}

pub(super) fn validate_attempt_chain(
    table: &SourceAcquisitionTableV2,
    tail: &SourceProviderQueryAttemptV2,
    owner: ProviderQueryOwnerV2,
    method: ProviderMethodV2,
    intent_digest: [u8; 32],
) -> Result<()> {
    let mut current = tail;
    let mut expected_number = tail.attempt_number;
    let mut count = 0usize;
    loop {
        count += 1;
        let immutable_lineage_matches = method == ProviderMethodV2::Inventory
            || (current.immutable_intent_digest == intent_digest && current.intent == tail.intent);
        if count > MAXIMUM_LINEAGE_ATTEMPTS
            || current.owner != owner
            || current.method != method
            || !immutable_lineage_matches
            || current.scope != tail.scope
            || current.attempt_number != expected_number
            || current.lineage_root_attempt_id != tail.lineage_root_attempt_id
        {
            return Err(state_error(
                "provider query lineage is inconsistent or over limit",
            ));
        }
        match current.previous_attempt_id {
            Some(previous) => {
                expected_number = expected_number
                    .checked_sub(1)
                    .ok_or_else(|| state_error("provider attempt number underflow"))?;
                let next = table
                    .provider_attempts
                    .get(&previous)
                    .ok_or_else(|| state_error("provider attempt predecessor is missing"))?;
                if (method == ProviderMethodV2::Inventory
                    && !inventory_lineage_step_is_valid(next, current)?)
                    || next.owner_predecessor_revision >= current.owner_predecessor_revision
                    || !attempt_happens_after(table, next, current)?
                {
                    return Err(state_error(
                        "provider attempt lineage time or owner witness is not monotonic",
                    ));
                }
                current = next;
            }
            None => {
                if expected_number != 1 || current.attempt_id != tail.lineage_root_attempt_id {
                    return Err(state_error("provider query lineage root is invalid"));
                }
                return Ok(());
            }
        }
    }
}

pub(super) fn inventory_lineage_step_is_valid(
    predecessor: &SourceProviderQueryAttemptV2,
    successor: &SourceProviderQueryAttemptV2,
) -> Result<bool> {
    let (
        ProviderIntentV2::Inventory {
            value: predecessor_intent,
        },
        ProviderIntentV2::Inventory {
            value: successor_intent,
        },
    ) = (&predecessor.intent, &successor.intent)
    else {
        return Ok(false);
    };
    if predecessor_intent.scope != successor_intent.scope
        || predecessor_intent.recovery_root_attempt_id != successor_intent.recovery_root_attempt_id
    {
        return Ok(false);
    }
    if is_complete(predecessor) {
        let (generation, digest, catalog_generation, catalog_digest) =
            inventory_attempt_floor(predecessor)?;
        Ok(successor_intent.known_inventory_generation == generation
            && successor_intent.known_inventory_digest == digest
            && successor_intent.known_catalog_generation == catalog_generation
            && successor_intent.known_catalog_digest == catalog_digest
            && predecessor_intent.known_observation_ordinal.checked_add(1)
                == Some(successor_intent.known_observation_ordinal))
    } else {
        Ok(predecessor_intent.scope == successor_intent.scope
            && predecessor_intent.known_inventory_generation
                == successor_intent.known_inventory_generation
            && predecessor_intent.known_inventory_digest == successor_intent.known_inventory_digest
            && predecessor_intent.known_catalog_generation
                == successor_intent.known_catalog_generation
            && predecessor_intent.known_catalog_digest == successor_intent.known_catalog_digest
            && predecessor_intent.known_observation_ordinal
                == successor_intent.known_observation_ordinal
            && predecessor_intent.recovery_root_attempt_id
                == successor_intent.recovery_root_attempt_id)
    }
}

pub(super) fn recovery_inventory_reference(resolution: &RecoveryResolutionV2) -> RecordRefV2 {
    match resolution {
        RecoveryResolutionV2::RetryAcquireSameIntent { proof }
        | RecoveryResolutionV2::RetryReleaseSameIntent { proof }
        | RecoveryResolutionV2::ProviderTerminalObserved { proof }
        | RecoveryResolutionV2::InventoryReconciled { proof }
        | RecoveryResolutionV2::Conflict { proof, .. } => proof.inventory_attempt,
    }
}

pub(super) fn validate_sequence_and_reservation_graph(
    table: &SourceAcquisitionTableV2,
) -> Result<()> {
    let mut reserved = BTreeSet::new();
    let mut sequences = BTreeMap::<[u8; 32], Vec<u64>>::new();
    let mut abandoned_sequences = BTreeMap::<[u8; 32], Vec<u64>>::new();
    for attempt in table.provider_attempts.values() {
        if attempt.request_sequence == u64::MAX {
            return Err(state_error("provider attempt sequence is exhausted"));
        }
        sequences
            .entry(attempt.session_id)
            .or_default()
            .push(attempt.request_sequence);
        if matches!(&attempt.state, ProviderAttemptStateV2::Reserved) {
            reserved.insert(attempt.attempt_id);
        }
        if matches!(
            &attempt.state,
            ProviderAttemptStateV2::AbandonedIndeterminate { .. }
                | ProviderAttemptStateV2::SupersededIndeterminate { .. }
        ) {
            abandoned_sequences
                .entry(attempt.session_id)
                .or_default()
                .push(attempt.request_sequence);
        }
    }
    for (session_id, values) in &mut sequences {
        values.sort_unstable();
        for (index, sequence) in values.iter().enumerate() {
            let expected = u64::try_from(index)
                .ok()
                .and_then(|value| value.checked_add(1))
                .ok_or_else(|| state_error("provider session sequence count overflow"))?;
            if *sequence != expected {
                return Err(state_error(
                    "provider session sequences are not a contiguous prefix",
                ));
            }
        }
        if !table.provider_sessions.contains_key(session_id) {
            return Err(state_error("provider sequence session is missing"));
        }
        let last_sequence = u64::try_from(values.len())
            .map_err(|_| state_error("provider session sequence count exceeds u64"))?;
        if abandoned_sequences
            .get(session_id)
            .is_some_and(|abandoned| abandoned.len() != 1 || abandoned[0] != last_sequence)
        {
            return Err(state_error(
                "provider indeterminate attempt is not the final request in its session",
            ));
        }
    }
    for head in table.provider_heads.values() {
        if head.next_request_sequence == u64::MAX || head.next_response_sequence == u64::MAX {
            return Err(state_error("provider head sequence is exhausted"));
        }
        let attempt_count = sequences.get(&head.current_session_id).map_or(0, Vec::len);
        let next_after_prefix = u64::try_from(attempt_count)
            .ok()
            .and_then(|value| value.checked_add(1))
            .ok_or_else(|| state_error("provider session sequence count overflow"))?;
        if let Some(reference) = head.pending_attempt {
            if !reserved.remove(&reference.id) {
                return Err(state_error("provider head pending edge is duplicated"));
            }
            if head.next_request_sequence != next_after_prefix
                || head.next_response_sequence.checked_add(1) != Some(next_after_prefix)
                || reference.id
                    != table
                        .provider_attempts
                        .values()
                        .find(|attempt| {
                            attempt.session_id == head.current_session_id
                                && attempt.request_sequence == head.next_response_sequence
                        })
                        .map_or([0; 32], |attempt| attempt.attempt_id)
            {
                return Err(state_error(
                    "pending provider attempt does not advance its exact session prefix",
                ));
            }
        } else if head.next_request_sequence != next_after_prefix
            || head.next_response_sequence != next_after_prefix
        {
            return Err(state_error(
                "idle provider head does not follow its exact session prefix",
            ));
        }
    }
    if !reserved.is_empty() {
        return Err(state_error(
            "reserved provider attempt has no exact head owner",
        ));
    }
    Ok(())
}
