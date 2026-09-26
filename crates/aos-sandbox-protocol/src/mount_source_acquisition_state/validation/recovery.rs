//! Provider-death barrier and recovery-resolution graph validation.

use super::*;

pub(super) fn validate_recovery_graph(table: &SourceAcquisitionTableV2) -> Result<()> {
    let mut unresolved_roots = BTreeSet::new();
    let mut covered_abandoned_attempts = BTreeSet::new();
    for head in table.provider_heads.values() {
        let Some(barrier) = &head.recovery_barrier else {
            continue;
        };
        let root = exact_attempt(table, barrier.root_attempt)?;
        let ProviderAttemptStateV2::AbandonedIndeterminate {
            recovery_root_attempt_id,
            resolution: None,
            ..
        } = &root.state
        else {
            return Err(state_error(
                "SourceProvider recovery root is not unresolved and abandoned",
            ));
        };
        let replacement_attempts = recovery_session_chain(
            table,
            root,
            head.current_session_id,
            barrier.replacement_count,
        )?;
        if replacement_attempts
            .into_iter()
            .any(|id| !covered_abandoned_attempts.insert(id))
            || barrier.required_session_id != head.current_session_id
            || barrier.replacement_count == 0
            || barrier.baseline_inventory_ordinal != head.inventory_observation_ordinal
            || root.scope != head.scope
            || *recovery_root_attempt_id != root.attempt_id
            || !unresolved_roots.insert(root.attempt_id)
            || session_successor_distance(table, root.session_id, head.current_session_id)?
                != barrier.replacement_count
        {
            return Err(state_error(
                "SourceProvider recovery barrier is inconsistent",
            ));
        }
        if let Some(tail) = barrier.recovery_inventory_tail {
            let inventory = exact_attempt(table, tail)?;
            let ProviderIntentV2::Inventory { value: intent } = &inventory.intent else {
                return Err(state_error(
                    "SourceProvider recovery tail lacks Inventory intent",
                ));
            };
            if inventory.method != ProviderMethodV2::Inventory
                || inventory.scope != head.scope
                || intent.scope != head.scope
                || intent.recovery_root_attempt_id != Some(root.attempt_id)
                || intent.known_observation_ordinal != barrier.baseline_inventory_ordinal
                || !inventory_intent_matches_floor(intent, head.inventory_floor.as_ref())
                || (matches!(&inventory.state, ProviderAttemptStateV2::Reserved)
                    && inventory.session_id != head.current_session_id)
            {
                return Err(state_error(
                    "SourceProvider recovery Inventory tail is inconsistent",
                ));
            }
        }
    }
    for row in table.acquisitions.values() {
        match &row.recovery {
            AcquisitionRecoveryV2::InventoryRequired { root_attempt } => {
                let root = exact_attempt(table, *root_attempt)?;
                let head = table
                    .provider_heads
                    .get(&(
                        row.scope.holder_authority_id,
                        row.scope.provider_authority_id,
                    ))
                    .ok_or_else(|| state_error("recovery row provider head is missing"))?;
                if head
                    .recovery_barrier
                    .as_ref()
                    .map(|barrier| barrier.root_attempt)
                    != Some(*root_attempt)
                    || root.scope != row.scope
                    || !matches!(
                        root.owner,
                        ProviderQueryOwnerV2::Acquire { acquisition_id }
                            | ProviderQueryOwnerV2::Release { acquisition_id }
                            if acquisition_id == row.acquisition_id
                    )
                {
                    return Err(state_error(
                        "acquisition recovery edge does not match provider head",
                    ));
                }
            }
            AcquisitionRecoveryV2::RetryPermitted { root_attempt } => {
                let root = exact_attempt(table, *root_attempt)?;
                let head = table
                    .provider_heads
                    .get(&(
                        row.scope.holder_authority_id,
                        row.scope.provider_authority_id,
                    ))
                    .ok_or_else(|| state_error("retry-permitted row provider head is missing"))?;
                let resolution = match &root.state {
                    ProviderAttemptStateV2::AbandonedIndeterminate {
                        resolution: Some(resolution),
                        ..
                    } => resolution,
                    _ => {
                        return Err(state_error(
                            "retry-permitted row lacks a resolved abandoned root",
                        ));
                    }
                };
                let proof = recovery_resolution_proof(resolution);
                let method_matches = matches!(
                    (root.method, resolution),
                    (
                        ProviderMethodV2::Acquire,
                        RecoveryResolutionV2::RetryAcquireSameIntent { .. }
                    ) | (
                        ProviderMethodV2::Release,
                        RecoveryResolutionV2::RetryReleaseSameIntent { .. }
                    )
                );
                let lineage_tail = match root.method {
                    ProviderMethodV2::Acquire => Some(row.acquire_lineage.tail),
                    ProviderMethodV2::Release => {
                        row.release_lineage.as_ref().map(|lineage| lineage.tail)
                    }
                    ProviderMethodV2::Inventory => None,
                };
                let phase_matches = match root.method {
                    ProviderMethodV2::Acquire => {
                        row.phase == SourceAcquisitionPhaseV2::PendingQuery
                            && row.release_proof.is_none()
                    }
                    ProviderMethodV2::Release => {
                        row.phase == SourceAcquisitionPhaseV2::Releasing
                            && row.release_proof.is_none()
                            && row.negative_custody_digest.is_none()
                    }
                    ProviderMethodV2::Inventory => false,
                };
                if !method_matches
                    || root.scope != row.scope
                    || !matches!(
                        root.owner,
                        ProviderQueryOwnerV2::Acquire { acquisition_id }
                            | ProviderQueryOwnerV2::Release { acquisition_id }
                            if acquisition_id == row.acquisition_id
                    )
                    || lineage_tail != Some(*root_attempt)
                    || !phase_matches
                    || head.pending_attempt.is_some()
                    || head.recovery_barrier.is_some()
                    || head.inventory_floor.as_ref().map(|floor| floor.attempt)
                        != Some(proof.inventory_attempt)
                    || head.last_reconciliation.as_ref() != Some(&proof.reconciliation)
                {
                    return Err(state_error(
                        "retry-permitted acquisition does not retain exact recovery proof",
                    ));
                }
            }
            AcquisitionRecoveryV2::Conflict {
                inventory_attempt,
                reconciliation_digest,
                conflict_digest,
            } => {
                let inventory = exact_attempt(table, *inventory_attempt)?;
                let head = table
                    .provider_heads
                    .get(&(
                        row.scope.holder_authority_id,
                        row.scope.provider_authority_id,
                    ))
                    .ok_or_else(|| state_error("conflict row provider head is missing"))?;
                let reconciliation = head
                    .last_reconciliation
                    .as_ref()
                    .ok_or_else(|| state_error("conflict row lacks reconciliation"))?;
                let ProviderAttemptStateV2::DispositionConsumed { signed_result, .. } =
                    &inventory.state
                else {
                    return Err(state_error("conflict Inventory is not consumed"));
                };
                let signed_inventory =
                    SignedSourceProviderInventoryV1::from_canonical_bytes(signed_result)
                        .map_err(|_| state_error("conflict Inventory is invalid"))?;
                let entry = signed_inventory.subject().entries().iter().find(|entry| {
                    entry.acquisition_id().as_bytes() == &row.provider_acquisition.acquisition_id
                });
                if inventory.scope != row.scope
                    || inventory.method != ProviderMethodV2::Inventory
                    || !is_complete(inventory)
                    || head.inventory_floor.as_ref().map(|floor| floor.attempt)
                        != Some(*inventory_attempt)
                    || *reconciliation_digest == [0; 32]
                    || *conflict_digest == [0; 32]
                    || reconciliation.conflict_count == 0
                    || reconciliation.conflict_digest != *conflict_digest
                    || reconciliation_commitment(reconciliation) != *reconciliation_digest
                    || reconciliation_conflict(row, entry).is_none()
                    || !table.provider_attempts.values().any(|attempt| {
                        matches!(
                            (&attempt.owner, &attempt.state),
                            (
                                ProviderQueryOwnerV2::Acquire { acquisition_id }
                                    | ProviderQueryOwnerV2::Release { acquisition_id },
                                ProviderAttemptStateV2::AbandonedIndeterminate {
                                    resolution: Some(RecoveryResolutionV2::Conflict {
                                        proof,
                                        conflict_digest: resolution_conflict,
                                    }),
                                    ..
                                }
                            ) if acquisition_id == &row.acquisition_id
                                && proof.inventory_attempt == *inventory_attempt
                                && proof.reconciliation_digest == *reconciliation_digest
                                && resolution_conflict == conflict_digest
                        )
                    })
                {
                    return Err(state_error(
                        "acquisition recovery conflict lacks exact Inventory evidence",
                    ));
                }
            }
            AcquisitionRecoveryV2::Ready => {}
        }
    }
    for attempt in table.provider_attempts.values() {
        let ProviderAttemptStateV2::AbandonedIndeterminate {
            recovery_root_attempt_id,
            resolution,
            ..
        } = &attempt.state
        else {
            continue;
        };
        let root = table
            .provider_attempts
            .get(recovery_root_attempt_id)
            .ok_or_else(|| state_error("abandoned attempt recovery root is missing"))?;
        if root.scope != attempt.scope
            || !matches!(
                &root.state,
                ProviderAttemptStateV2::AbandonedIndeterminate { .. }
            )
            || (attempt.attempt_id != root.attempt_id
                && attempt.method != ProviderMethodV2::Inventory)
        {
            return Err(state_error(
                "abandoned provider attempt does not join its recovery root",
            ));
        }
        let unresolved = matches!(
            &root.state,
            ProviderAttemptStateV2::AbandonedIndeterminate {
                resolution: None,
                ..
            }
        );
        let barrier_exists = table.provider_heads.values().any(|head| {
            head.recovery_barrier
                .as_ref()
                .is_some_and(|barrier| barrier.root_attempt.id == *recovery_root_attempt_id)
        });
        if unresolved != barrier_exists {
            return Err(state_error(
                "abandoned provider attempt and recovery barrier disagree",
            ));
        }
        if attempt.attempt_id == root.attempt_id {
            if let Some(resolution) = resolution {
                let inventory = exact_attempt(table, recovery_inventory_reference(resolution))?;
                let replacement_count =
                    session_successor_distance(table, root.session_id, inventory.session_id)?;
                let replacement_attempts =
                    recovery_session_chain(table, root, inventory.session_id, replacement_count)?;
                if replacement_attempts
                    .into_iter()
                    .any(|id| !covered_abandoned_attempts.insert(id))
                {
                    return Err(state_error(
                        "abandoned provider attempt belongs to multiple recovery chains",
                    ));
                }
            }
            match root.owner {
                ProviderQueryOwnerV2::Acquire { acquisition_id }
                | ProviderQueryOwnerV2::Release { acquisition_id } => {
                    let row = table
                        .acquisitions
                        .get(&acquisition_id)
                        .ok_or_else(|| state_error("recovery root owner row is missing"))?;
                    if unresolved
                        != matches!(
                            &row.recovery,
                            AcquisitionRecoveryV2::InventoryRequired { root_attempt }
                                if root_attempt.id == root.attempt_id
                        )
                    {
                        return Err(state_error(
                            "recovery root and acquisition recovery state disagree",
                        ));
                    }
                }
                ProviderQueryOwnerV2::Inventory => {}
            }
        }
    }
    let all_abandoned = table
        .provider_attempts
        .values()
        .filter(|attempt| {
            matches!(
                &attempt.state,
                ProviderAttemptStateV2::AbandonedIndeterminate { .. }
            )
        })
        .map(|attempt| attempt.attempt_id)
        .collect::<BTreeSet<_>>();
    if covered_abandoned_attempts != all_abandoned {
        return Err(state_error(
            "abandoned provider attempt is outside its exact replacement chain",
        ));
    }
    Ok(())
}

pub(super) fn validate_resolution_causality(table: &SourceAcquisitionTableV2) -> Result<()> {
    let successors = table
        .provider_attempts
        .values()
        .filter_map(|attempt| {
            attempt
                .previous_attempt_id
                .map(|previous| (previous, attempt))
        })
        .collect::<BTreeMap<_, _>>();

    for root in table.provider_attempts.values() {
        let ProviderAttemptStateV2::AbandonedIndeterminate {
            resolution: Some(resolution),
            ..
        } = &root.state
        else {
            continue;
        };
        let proof = recovery_resolution_proof(resolution);
        let inventory = exact_attempt(table, proof.inventory_attempt)?;
        let successor = successors.get(&root.attempt_id).copied();

        match resolution {
            RecoveryResolutionV2::RetryAcquireSameIntent { .. }
            | RecoveryResolutionV2::RetryReleaseSameIntent { .. } => {
                let acquisition_id = match root.owner {
                    ProviderQueryOwnerV2::Acquire { acquisition_id }
                    | ProviderQueryOwnerV2::Release { acquisition_id } => acquisition_id,
                    ProviderQueryOwnerV2::Inventory => {
                        return Err(state_error(
                            "provider retry resolution has no acquisition owner",
                        ));
                    }
                };
                let row = table
                    .acquisitions
                    .get(&acquisition_id)
                    .ok_or_else(|| state_error("provider retry owner row is missing"))?;
                match successor {
                    None => {
                        if !matches!(
                            &row.recovery,
                            AcquisitionRecoveryV2::RetryPermitted { root_attempt }
                                if root_attempt.id == root.attempt_id
                                    && root_attempt.revision == root.revision
                                    && root_attempt.record_digest == root.record_digest
                        ) {
                            return Err(state_error(
                                "resolved provider retry lacks its durable permit",
                            ));
                        }
                    }
                    Some(retry) => {
                        if retry.method != root.method
                            || retry.owner != root.owner
                            || retry.immutable_intent_digest != root.immutable_intent_digest
                            || retry.attempt_number
                                != root.attempt_number.checked_add(1).ok_or_else(|| {
                                    state_error("provider retry attempt number overflow")
                                })?
                            || !attempt_happens_after(table, inventory, retry)?
                            || matches!(
                                &row.recovery,
                                AcquisitionRecoveryV2::RetryPermitted { .. }
                                    | AcquisitionRecoveryV2::Conflict { .. }
                            )
                            || (row.release_proof.is_some()
                                && root.method == ProviderMethodV2::Release)
                        {
                            return Err(state_error(
                                "provider retry does not follow its recovery Inventory",
                            ));
                        }
                    }
                }
            }
            RecoveryResolutionV2::ProviderTerminalObserved { .. } => {
                if successor.is_some() || root.method != ProviderMethodV2::Release {
                    return Err(state_error(
                        "terminal provider recovery has a retry successor",
                    ));
                }
                let ProviderQueryOwnerV2::Release { acquisition_id } = root.owner else {
                    return Err(state_error(
                        "terminal provider recovery has no Release owner",
                    ));
                };
                let row = table
                    .acquisitions
                    .get(&acquisition_id)
                    .ok_or_else(|| state_error("terminal provider recovery row is missing"))?;
                let proof_matches = matches!(
                    row.release_proof.as_ref(),
                    Some(ReleaseProofV2::ProviderInventory {
                        attempt,
                        acquisition_predecessor,
                        inventory_digest,
                        inventory_observation_ordinal,
                        projection_epoch,
                    }) if *attempt == proof.inventory_attempt
                        && inventory
                            .inventory_correlations
                            .as_ref()
                            .and_then(|correlations| correlations.entries.iter().find(|entry| {
                                entry.mount_acquisition_id == row.acquisition_id
                            }))
                            .is_some_and(|entry| {
                                entry.acquisition_record == *acquisition_predecessor
                                    && entry.provider_acquisition == row.provider_acquisition
                                    && row.evidence.as_ref().is_some_and(|evidence| {
                                        entry.lease_id == Some(evidence.lease_id)
                                            && entry.signed_lease_digest
                                                == Some(evidence.signed_lease_digest)
                                    })
                                    && entry.expectation
                                        == InventoryCorrelationExpectationV2::ReapingReleasedOrAbsent
                            })
                        && *inventory_digest == proof.inventory_digest
                        && *inventory_observation_ordinal == proof.inventory_observation_ordinal
                        && *projection_epoch == proof.projection_epoch
                );
                if !proof_matches
                    || !matches!(
                        row.phase,
                        SourceAcquisitionPhaseV2::Releasing | SourceAcquisitionPhaseV2::Released
                    )
                    || (row.phase == SourceAcquisitionPhaseV2::Releasing
                        && row.negative_custody_digest.is_some())
                    || (row.phase == SourceAcquisitionPhaseV2::Released
                        && row.negative_custody_digest.is_none())
                    || !matches!(&row.recovery, AcquisitionRecoveryV2::Ready)
                {
                    return Err(state_error(
                        "terminal provider recovery is not retained by its row",
                    ));
                }
            }
            RecoveryResolutionV2::Conflict {
                conflict_digest, ..
            } => {
                if successor.is_some() {
                    return Err(state_error(
                        "conflicting provider recovery has a retry successor",
                    ));
                }
                let acquisition_id = match root.owner {
                    ProviderQueryOwnerV2::Acquire { acquisition_id }
                    | ProviderQueryOwnerV2::Release { acquisition_id } => acquisition_id,
                    ProviderQueryOwnerV2::Inventory => continue,
                };
                let row = table
                    .acquisitions
                    .get(&acquisition_id)
                    .ok_or_else(|| state_error("provider conflict owner row is missing"))?;
                if !matches!(
                    &row.recovery,
                    AcquisitionRecoveryV2::Conflict {
                        inventory_attempt,
                        reconciliation_digest,
                        conflict_digest: row_conflict,
                    } if *inventory_attempt == proof.inventory_attempt
                        && *reconciliation_digest == proof.reconciliation_digest
                        && *row_conflict == *conflict_digest
                ) {
                    return Err(state_error(
                        "provider conflict resolution is not retained by its row",
                    ));
                }
            }
            RecoveryResolutionV2::InventoryReconciled { .. } => {
                if successor.is_some() || root.method != ProviderMethodV2::Inventory {
                    return Err(state_error(
                        "reconciled Inventory recovery has a retry successor",
                    ));
                }
            }
        }
    }
    Ok(())
}

pub(super) fn recovery_resolution_proof(
    resolution: &RecoveryResolutionV2,
) -> &RecoveryInventoryProofV2 {
    match resolution {
        RecoveryResolutionV2::RetryAcquireSameIntent { proof }
        | RecoveryResolutionV2::RetryReleaseSameIntent { proof }
        | RecoveryResolutionV2::ProviderTerminalObserved { proof }
        | RecoveryResolutionV2::InventoryReconciled { proof }
        | RecoveryResolutionV2::Conflict { proof, .. } => proof,
    }
}

pub(super) fn recovery_session_chain(
    table: &SourceAcquisitionTableV2,
    root: &SourceProviderQueryAttemptV2,
    terminal_session_id: [u8; 32],
    expected_replacement_count: u64,
) -> Result<Vec<[u8; 32]>> {
    if expected_replacement_count == 0 {
        return Err(state_error(
            "provider recovery has no successor-session transition",
        ));
    }
    let mut replacements = Vec::new();
    for current in session_predecessor_path(table, root.session_id, terminal_session_id)? {
        let session = table
            .provider_sessions
            .get(&current)
            .ok_or_else(|| state_error("provider recovery successor session is missing"))?;
        let predecessor = session
            .predecessor_session_id
            .ok_or_else(|| state_error("provider recovery successor lacks predecessor"))?;
        let mut matches = table.provider_attempts.values().filter(|attempt| {
            if attempt.session_id != predecessor {
                return false;
            }
            matches!(
                &attempt.state,
                ProviderAttemptStateV2::AbandonedIndeterminate {
                    successor_session_id,
                    recovery_root_attempt_id,
                    ..
                } if *successor_session_id == current
                    && *recovery_root_attempt_id == root.attempt_id
            )
        });
        let replacement = matches
            .next()
            .ok_or_else(|| state_error("provider recovery session edge lacks death evidence"))?;
        if matches.next().is_some()
            || (predecessor == root.session_id && replacement.attempt_id != root.attempt_id)
            || (predecessor != root.session_id
                && (!matches!(replacement.owner, ProviderQueryOwnerV2::Inventory)
                    || !matches!(
                        &replacement.intent,
                        ProviderIntentV2::Inventory { value }
                            if value.recovery_root_attempt_id == Some(root.attempt_id)
                    )))
        {
            return Err(state_error(
                "provider recovery session edge has an invalid attempt witness",
            ));
        }
        replacements.push(replacement.attempt_id);
    }
    let count = u64::try_from(replacements.len())
        .map_err(|_| state_error("provider recovery replacement count exceeds u64"))?;
    if count != expected_replacement_count {
        return Err(state_error(
            "provider recovery replacement count does not reproduce",
        ));
    }
    Ok(replacements)
}

pub(super) fn inventory_intent_matches_floor(
    intent: &InventoryIntentV2,
    floor: Option<&InventoryFloorV2>,
) -> bool {
    match floor {
        Some(floor) => {
            intent.known_inventory_generation == Some(floor.inventory_generation)
                && intent.known_inventory_digest == Some(floor.inventory_digest)
                && intent.known_catalog_generation == Some(floor.catalog_generation)
                && intent.known_catalog_digest == Some(floor.catalog_digest)
        }
        None => {
            intent.known_inventory_generation.is_none()
                && intent.known_inventory_digest.is_none()
                && intent.known_catalog_generation.is_none()
                && intent.known_catalog_digest.is_none()
        }
    }
}

pub(super) fn session_successor_distance(
    table: &SourceAcquisitionTableV2,
    ancestor: [u8; 32],
    descendant: [u8; 32],
) -> Result<u64> {
    u64::try_from(session_predecessor_path(table, ancestor, descendant)?.len())
        .map_err(|_| state_error("provider recovery replacement count exceeds u64"))
}

fn session_predecessor_path(
    table: &SourceAcquisitionTableV2,
    ancestor: [u8; 32],
    descendant: [u8; 32],
) -> Result<Vec<[u8; 32]>> {
    let mut current = descendant;
    let mut path = Vec::new();
    let mut visited = BTreeSet::new();
    while current != ancestor {
        if !visited.insert(current) {
            return Err(state_error("provider recovery session chain is cyclic"));
        }
        if path.len() >= MAXIMUM_SOURCE_PROVIDER_SESSIONS {
            return Err(state_error(
                "provider recovery session chain exceeds the session bound",
            ));
        }
        let session = table
            .provider_sessions
            .get(&current)
            .ok_or_else(|| state_error("provider recovery session chain is missing"))?;
        path.push(current);
        current = session
            .predecessor_session_id
            .ok_or_else(|| state_error("provider recovery session is not a successor"))?;
    }
    Ok(path)
}

pub(super) fn attempt_happens_after(
    table: &SourceAcquisitionTableV2,
    earlier: &SourceProviderQueryAttemptV2,
    later: &SourceProviderQueryAttemptV2,
) -> Result<bool> {
    if earlier.session_id == later.session_id {
        return Ok(earlier.request_sequence < later.request_sequence);
    }
    Ok(session_successor_distance(table, earlier.session_id, later.session_id).is_ok())
}

pub(super) fn inventory_observation_ordinal(
    table: &SourceAcquisitionTableV2,
    scope: ProviderScopeV2,
    target: &SourceProviderQueryAttemptV2,
) -> Result<u64> {
    if target.scope != scope || target.method != ProviderMethodV2::Inventory || !is_complete(target)
    {
        return Err(state_error(
            "Inventory observation ordinal target is not Complete",
        ));
    }
    let mut ordinal = 0_u64;
    for attempt in table.provider_attempts.values().filter(|attempt| {
        attempt.scope == scope
            && attempt.method == ProviderMethodV2::Inventory
            && is_complete(attempt)
    }) {
        if attempt.attempt_id == target.attempt_id || attempt_happens_after(table, attempt, target)?
        {
            ordinal = ordinal
                .checked_add(1)
                .ok_or_else(|| state_error("Inventory observation ordinal overflow"))?;
        } else if !attempt_happens_after(table, target, attempt)? {
            return Err(state_error(
                "Complete Inventory observations are not chronologically ordered",
            ));
        }
    }
    Ok(ordinal)
}
