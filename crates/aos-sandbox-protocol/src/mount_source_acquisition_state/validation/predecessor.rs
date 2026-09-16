//! Attempt identity and compact owner-predecessor witness validation.

use super::*;

pub(super) fn validate_attempt(
    attempt: &SourceProviderQueryAttemptV2,
    table: &SourceAcquisitionTableV2,
) -> Result<()> {
    let session = exact_session(table, attempt.session_id, attempt.session_record_digest)?;
    let head = table
        .provider_heads
        .get(&(
            attempt.scope.holder_authority_id,
            attempt.scope.provider_authority_id,
        ))
        .ok_or_else(|| state_error("provider attempt owner head is missing"))?;
    if !valid_scope(attempt.scope)
        || attempt.scope != attempt.intent.scope()
        || attempt.scope != session.scope
        || attempt.attempt_id == [0; 32]
        || attempt.attempt_number == 0
        || attempt.request_sequence == 0
        || attempt.request_id == [0; 16]
        || attempt.immutable_intent_digest == [0; 32]
        || attempt.immutable_intent_digest != intent_digest(&attempt.intent)?
        || attempt.attempt_id != attempt_id(attempt)
        || attempt.request_id != request_id(attempt.attempt_id)
        || attempt.signer_set_commitment != session.signer_set_commitment
        || attempt.trust_digest != session.trust_digest
        || attempt.revocation_digest != session.revocation_digest
        || attempt.route_digest != session.route_digest
        || attempt.process_execution_digest != session.provider_execution.process_execution_digest
        || attempt.signed_request_digest == [0; 32]
        || head.scope != attempt.scope
        || attempt.record_digest == [0; 32]
        || !method_owner_intent_match(attempt)
    {
        return Err(state_error(
            "SourceProvider attempt has an invalid identity or snapshot",
        ));
    }
    validate_attempt_normalization(attempt, session, table)?;
    validate_owner_predecessor(attempt, head, table)?;
    validate_intent(&attempt.intent)?;
    validate_attempt_revision(attempt)?;
    validate_provider_request(attempt, session, table)?;
    validate_attempt_checkpoint(attempt, session)?;
    validate_consumed_result(attempt, session)?;
    validate_indeterminate_attempt(attempt, table)
}

pub(super) fn validate_attempt_normalization(
    attempt: &SourceProviderQueryAttemptV2,
    session: &SourceProviderSessionV2,
    table: &SourceAcquisitionTableV2,
) -> Result<()> {
    match (
        &attempt.intent,
        &attempt.normalized_acquire_intent,
        &attempt.acquire_verification_floor,
        &attempt.inventory_correlations,
    ) {
        (ProviderIntentV2::Acquire { .. }, Some(normalized), Some(verification_floor), None) => {
            let provider_acquisition = attempt
                .provider_acquisition
                .ok_or_else(|| state_error("Acquire attempt lacks its provider identity"))?;
            let value = NormalizedAcquisitionIntentV2::from_canonical_bytes(&normalized.bytes)
                .map_err(|_| state_error("attempt AOSNPI01 version-2 normalization is invalid"))?;
            if normalized.bytes.is_empty()
                || value.digest().as_bytes() != &normalized.digest
                || value.acquisition_id().as_bytes() != &provider_acquisition.acquisition_id
                || value.acquisition_sequence() != provider_acquisition.acquisition_sequence
                || normalized.maximum_lease_expiry_seconds <= session.authenticated_at_seconds
                || normalized.maximum_lease_expiry_seconds > session.current_valid_until_seconds
            {
                return Err(state_error(
                    "attempt Acquire normalization has an invalid bound or digest",
                ));
            }
            let (catalog, selection) =
                crate::mount_source_acquisition_state::protocol_acquire_verification_floor_v2(
                    verification_floor,
                )?;
            if catalog.provider_authority_id() != attempt.scope.provider_authority_id
                || catalog.resource_namespace_digest().as_bytes()
                    != &attempt.scope.resource_namespace_digest
                || selection.as_ref().is_some_and(|floor| {
                    floor.acquisition_id().as_bytes() != &provider_acquisition.acquisition_id
                        || floor.provider_authority_id() != attempt.scope.provider_authority_id
                        || floor.route_id() != attempt.scope.route_id
                        || floor.resource().resource_namespace_digest().as_bytes()
                            != &attempt.scope.resource_namespace_digest
                })
            {
                return Err(state_error(
                    "attempt Acquire verification floor changes its provider scope",
                ));
            }
        }
        (ProviderIntentV2::Acquire { .. }, _, _, _) => {
            return Err(state_error(
                "Acquire attempt lacks normalization or its pre-I/O verification floor",
            ));
        }
        (ProviderIntentV2::Inventory { value }, None, None, Some(correlations)) => {
            validate_inventory_correlation_set_v2(correlations)?;
            if value.correlation_digest == [0; 32]
                || value.correlation_digest != correlations.digest
            {
                return Err(state_error(
                    "Inventory intent does not bind its exact correlations",
                ));
            }
            for correlation in &correlations.entries {
                let row = table
                    .acquisitions
                    .get(&correlation.mount_acquisition_id)
                    .ok_or_else(|| state_error("Inventory correlation owner is missing"))?;
                let exact_at_reservation =
                    matches!(attempt.state, ProviderAttemptStateV2::Reserved);
                if row.scope != attempt.scope
                    || correlation.provider_acquisition != row.provider_acquisition
                    || row.evidence.as_ref().map(|evidence| evidence.lease_id)
                        != correlation.lease_id
                    || row
                        .evidence
                        .as_ref()
                        .map(|evidence| evidence.signed_lease_digest)
                        != correlation.signed_lease_digest
                    || correlation.acquisition_record.id != row.acquisition_id
                    || correlation.acquisition_record.revision > row.revision
                    || (exact_at_reservation
                        && (correlation.acquisition_record.revision != row.revision
                            || correlation.acquisition_record.record_digest != row.record_digest
                            || inventory_correlation_for_row_v2(row).as_ref() != Some(correlation)))
                {
                    return Err(state_error(
                        "Inventory correlation differs from its reservation owner",
                    ));
                }
            }
            if matches!(attempt.state, ProviderAttemptStateV2::Reserved) {
                let exact_entries = table
                    .acquisitions
                    .values()
                    .filter(|row| row.scope == attempt.scope)
                    .filter_map(inventory_correlation_for_row_v2)
                    .collect::<Vec<_>>();
                let exact_set = inventory_correlation_set_v2(exact_entries)?;
                if &exact_set != correlations {
                    return Err(state_error(
                        "Inventory reservation omits or adds an acquisition correlation",
                    ));
                }
            }
        }
        (ProviderIntentV2::Inventory { .. }, _, _, _) => {
            return Err(state_error(
                "Inventory attempt lacks its exact pre-I/O correlations",
            ));
        }
        (_, Some(_), _, _) | (_, _, Some(_), _) | (_, _, _, Some(_)) => {
            return Err(state_error(
                "attempt retains method-incompatible verification state",
            ));
        }
        (_, None, None, None) => {}
    }
    Ok(())
}

pub(super) fn validate_owner_predecessor(
    attempt: &SourceProviderQueryAttemptV2,
    head: &SourceProviderHeadV2,
    table: &SourceAcquisitionTableV2,
) -> Result<()> {
    let initial_acquire = attempt.method == ProviderMethodV2::Acquire
        && attempt.attempt_number == 1
        && attempt.previous_attempt_id.is_none();
    let zero_witness =
        attempt.owner_predecessor_revision == 0 && attempt.owner_predecessor_digest == [0; 32];
    let partial_zero =
        (attempt.owner_predecessor_revision == 0) != (attempt.owner_predecessor_digest == [0; 32]);
    if partial_zero
        || initial_acquire != zero_witness
        || initial_acquire != attempt.owner_predecessor.is_none()
    {
        return Err(state_error(
            "provider attempt has an invalid owner-predecessor witness",
        ));
    }

    if let Some(predecessor) = &attempt.owner_predecessor {
        validate_owner_predecessor_witness(attempt, predecessor, table)?;
    }

    match attempt.owner {
        ProviderQueryOwnerV2::Acquire { acquisition_id }
        | ProviderQueryOwnerV2::Release { acquisition_id } => {
            let row = table
                .acquisitions
                .get(&acquisition_id)
                .ok_or_else(|| state_error("provider attempt owner row is missing"))?;
            if attempt.owner_predecessor_revision >= row.revision && !initial_acquire {
                return Err(state_error(
                    "provider attempt owner witness is not older than its row",
                ));
            }
            if matches!(&attempt.state, ProviderAttemptStateV2::Reserved)
                && attempt.owner_predecessor_revision.checked_add(1) != Some(row.revision)
            {
                return Err(state_error(
                    "reserved provider attempt does not advance its owner row once",
                ));
            }
        }
        ProviderQueryOwnerV2::Inventory => {
            if attempt.owner_predecessor_revision >= head.revision {
                return Err(state_error(
                    "provider Inventory owner witness is not older than its head",
                ));
            }
            if matches!(&attempt.state, ProviderAttemptStateV2::Reserved)
                && attempt.owner_predecessor_revision.checked_add(1) != Some(head.revision)
            {
                return Err(state_error(
                    "reserved provider Inventory does not advance its head once",
                ));
            }
        }
    }
    Ok(())
}

pub(super) fn validate_owner_predecessor_witness(
    attempt: &SourceProviderQueryAttemptV2,
    predecessor: &OwnerPredecessorWitnessV2,
    table: &SourceAcquisitionTableV2,
) -> Result<()> {
    match (attempt.owner, predecessor) {
        (
            ProviderQueryOwnerV2::Acquire { acquisition_id }
            | ProviderQueryOwnerV2::Release { acquisition_id },
            OwnerPredecessorWitnessV2::Acquisition { value },
        ) => {
            let current = table
                .acquisitions
                .get(&acquisition_id)
                .ok_or_else(|| state_error("provider attempt owner row is missing"))?;
            if value.record.id != acquisition_id
                || value.acquisition_id != acquisition_id
                || value.scope != attempt.scope
                || value.record.revision != attempt.owner_predecessor_revision
                || value.record.record_digest != attempt.owner_predecessor_digest
                || !same_acquisition_identity(attempt, value, current)
            {
                return Err(state_error(
                    "provider attempt acquisition predecessor does not reproduce",
                ));
            }
            validate_predecessor_evidence(value)?;
            validate_predecessor_phase(value)?;
            validate_predecessor_terminal_evidence(value, table)?;
            exact_attempt(table, value.acquire_lineage.root)?;
            exact_attempt(table, value.acquire_lineage.tail)?;
            if let Some(lineage) = &value.release_lineage {
                exact_attempt(table, lineage.root)?;
                exact_attempt(table, lineage.tail)?;
            }
            validate_acquisition_predecessor_lineage(attempt, value, current, table)
        }
        (ProviderQueryOwnerV2::Inventory, OwnerPredecessorWitnessV2::ProviderHead { value }) => {
            let session = exact_session(table, attempt.session_id, attempt.session_record_digest)?;
            validate_provider_head_predecessor_witness(value, attempt, table)?;
            let ProviderIntentV2::Inventory { value: intent } = &attempt.intent else {
                return Err(state_error(
                    "provider Inventory predecessor has the wrong intent",
                ));
            };
            if value.record.id != provider_head_record_id(value.scope)
                || value.scope != attempt.scope
                || value.record.revision != attempt.owner_predecessor_revision
                || value.record.record_digest != attempt.owner_predecessor_digest
                || value.current_session_id != attempt.session_id
                || value.current_session_record_digest != attempt.session_record_digest
                || value.holder_authority_generation != session.root_mount_authority_generation
                || value.holder_authority_digest != session.root_mount_authority_digest
                || value.provider_authority_generation != session.provider_authority_generation
                || value.provider_authority_digest != session.provider_authority_digest
                || value.pending_attempt.is_some()
                || value.next_request_sequence != attempt.request_sequence
                || value.next_response_sequence != attempt.request_sequence
                || value.inventory_observation_ordinal != intent.known_observation_ordinal
                || !inventory_intent_matches_floor(intent, value.inventory_floor.as_ref())
                || (matches!(&attempt.state, ProviderAttemptStateV2::Reserved)
                    && !reserved_head_follows_predecessor(value, attempt, table))
            {
                return Err(state_error(
                    "provider Inventory head predecessor does not reproduce",
                ));
            }
            if let Some(floor) = &value.inventory_floor {
                let prior = exact_attempt(table, floor.attempt)?;
                if !attempt_happens_after(table, prior, attempt)? {
                    return Err(state_error(
                        "Inventory predecessor floor is not historically prior",
                    ));
                }
            }
            if let Some(reference) = value.last_inventory_attempt {
                let prior = exact_attempt(table, reference)?;
                if !attempt_happens_after(table, prior, attempt)? {
                    return Err(state_error(
                        "Inventory predecessor tail is not historically prior",
                    ));
                }
            }
            if let Some(barrier) = &value.recovery_barrier {
                let root = exact_attempt(table, barrier.root_attempt)?;
                if !attempt_happens_after(table, root, attempt)? {
                    return Err(state_error(
                        "Inventory predecessor recovery root is not historically prior",
                    ));
                }
                if let Some(tail) = barrier.recovery_inventory_tail {
                    let prior = exact_attempt(table, tail)?;
                    if !attempt_happens_after(table, prior, attempt)? {
                        return Err(state_error(
                            "Inventory predecessor recovery tail is not historically prior",
                        ));
                    }
                }
            }
            Ok(())
        }
        _ => Err(state_error(
            "provider attempt has the wrong owner-predecessor record kind",
        )),
    }
}

pub(super) fn provider_head_record_id(scope: ProviderScopeV2) -> [u8; 32] {
    let mut id = [0_u8; 32];
    id[..16].copy_from_slice(&scope.holder_authority_id);
    id[16..].copy_from_slice(&scope.provider_authority_id);
    id
}

pub(super) fn validate_provider_head_predecessor_witness(
    value: &ProviderHeadPredecessorWitnessV2,
    reserved_attempt: &SourceProviderQueryAttemptV2,
    table: &SourceAcquisitionTableV2,
) -> Result<()> {
    let session = exact_session(
        table,
        value.current_session_id,
        value.current_session_record_digest,
    )?;
    if value.record.id != provider_head_record_id(value.scope)
        || value.record.revision == 0
        || value.record.record_digest == [0; 32]
        || !valid_scope(value.scope)
        || session.scope != value.scope
        || value.holder_authority_generation != session.root_mount_authority_generation
        || value.holder_authority_digest != session.root_mount_authority_digest
        || value.provider_authority_generation != session.provider_authority_generation
        || value.provider_authority_digest != session.provider_authority_digest
        || value.next_request_sequence == 0
        || value.next_request_sequence != value.next_response_sequence
        || value.pending_attempt.is_some()
        || value.current_projection_digest == [0; 32]
        || value.inventory_floor.is_some() != (value.inventory_observation_ordinal != 0)
    {
        return Err(state_error(
            "provider-head predecessor witness has invalid shape",
        ));
    }
    if value
        .last_reconciliation
        .as_ref()
        .is_some_and(|reconciliation| {
            value.inventory_floor.is_none()
                || reconciliation.projection_epoch != value.current_projection_epoch
                || reconciliation.projection_digest != value.current_projection_digest
                || reconciliation.residual_digest == [0; 32]
                || reconciliation.conflict_digest == [0; 32]
                || reconciliation_commitment(reconciliation) == [0; 32]
        })
    {
        return Err(state_error(
            "provider-head predecessor reconciliation is invalid",
        ));
    }
    validate_predecessor_inventory_history(value, reserved_attempt, table)?;
    validate_predecessor_recovery_barrier(value, reserved_attempt, table)
}

pub(super) fn validate_predecessor_inventory_history(
    value: &ProviderHeadPredecessorWitnessV2,
    reserved_attempt: &SourceProviderQueryAttemptV2,
    table: &SourceAcquisitionTableV2,
) -> Result<()> {
    let mut retained = Vec::new();
    for attempt in table.provider_attempts.values().filter(|attempt| {
        attempt.scope == value.scope
            && attempt.method == ProviderMethodV2::Inventory
            && (attempt_is_terminal(&attempt.state)
                || matches!(
                    attempt.state,
                    ProviderAttemptStateV2::SupersededIndeterminate { .. }
                ))
    }) {
        if attempt_happens_after(table, attempt, reserved_attempt)? {
            retained.push(attempt);
        }
    }
    if value.last_inventory_attempt.is_some() != !retained.is_empty() {
        return Err(state_error(
            "provider-head predecessor Inventory tail has invalid presence",
        ));
    }
    let complete_count = retained
        .iter()
        .filter(|attempt| is_complete(attempt))
        .count();
    if u64::try_from(complete_count)
        .map_err(|_| state_error("predecessor Inventory count exceeds u64"))?
        != value.inventory_observation_ordinal
    {
        return Err(state_error(
            "provider-head predecessor Inventory ordinal does not reproduce",
        ));
    }
    if let Some(reference) = value.last_inventory_attempt {
        let last = resolve_historical_attempt(table, reference)?;
        if last.scope != value.scope
            || last.method != ProviderMethodV2::Inventory
            || !(attempt_is_terminal(&last.state)
                || matches!(
                    last.state,
                    ProviderAttemptStateV2::SupersededIndeterminate { .. }
                ))
            || !attempt_happens_after(table, &last, reserved_attempt)?
        {
            return Err(state_error(
                "provider-head predecessor Inventory tail is invalid",
            ));
        }
        for earlier in &retained {
            if earlier.attempt_id != last.attempt_id
                && !attempt_happens_after(table, earlier, &last)?
            {
                return Err(state_error(
                    "provider-head predecessor Inventory tail is not latest",
                ));
            }
        }
    }
    let Some(floor) = &value.inventory_floor else {
        return Ok(());
    };
    let attempt = exact_attempt(table, floor.attempt)?;
    let session = exact_session(table, attempt.session_id, attempt.session_record_digest)?;
    let ProviderAttemptStateV2::DispositionConsumed {
        status: ProviderStatusV2::Complete,
        signed_result,
        signed_result_digest,
        ..
    } = &attempt.state
    else {
        return Err(state_error(
            "provider-head predecessor floor is not Complete Inventory",
        ));
    };
    let inventory = SignedSourceProviderInventoryV1::from_canonical_bytes(signed_result)
        .map_err(|_| state_error("provider-head predecessor Inventory is invalid"))?;
    if attempt.scope != value.scope
        || attempt.method != ProviderMethodV2::Inventory
        || !attempt_happens_after(table, attempt, reserved_attempt)?
        || floor.provider_authority_generation != session.provider_authority_generation
        || floor.provider_authority_digest != session.provider_authority_digest
        || floor.provider_outcome_signer_digest != session.signers[3].public_key_fingerprint
        || floor.inventory_generation != inventory.subject().inventory_generation()
        || floor.inventory_digest != *digest_inventory(inventory.subject()).as_bytes()
        || floor.catalog_generation != inventory.subject().catalog_generation()
        || floor.catalog_digest != *inventory.subject().catalog_digest().as_bytes()
        || floor.signed_result_digest != *signed_result_digest
    {
        return Err(state_error(
            "provider-head predecessor Inventory floor does not reproduce",
        ));
    }
    for later_complete in terminal
        .into_iter()
        .filter(|candidate| is_complete(candidate))
    {
        if later_complete.attempt_id != attempt.attempt_id
            && !attempt_happens_after(table, later_complete, attempt)?
        {
            return Err(state_error(
                "provider-head predecessor Inventory floor is not latest Complete",
            ));
        }
    }
    Ok(())
}

pub(super) fn validate_predecessor_recovery_barrier(
    value: &ProviderHeadPredecessorWitnessV2,
    reserved_attempt: &SourceProviderQueryAttemptV2,
    table: &SourceAcquisitionTableV2,
) -> Result<()> {
    let ProviderIntentV2::Inventory {
        value: reserved_intent,
    } = &reserved_attempt.intent
    else {
        return Err(state_error(
            "provider-head predecessor owner is not Inventory",
        ));
    };
    let barrier = match (
        value.recovery_barrier.as_ref(),
        reserved_intent.recovery_root_attempt_id,
    ) {
        (None, None) => {
            return validate_ordinary_inventory_predecessor(value, reserved_attempt, table);
        }
        (Some(barrier), Some(root_id)) if barrier.root_attempt.id == root_id => barrier,
        _ => {
            return Err(state_error(
                "provider-head predecessor recovery barrier and intent differ",
            ));
        }
    };
    let root = resolve_historical_attempt(table, barrier.root_attempt)?;
    let ProviderAttemptStateV2::AbandonedIndeterminate {
        recovery_root_attempt_id,
        resolution: None,
        ..
    } = &root.state
    else {
        return Err(state_error(
            "provider-head predecessor recovery root is not unresolved",
        ));
    };
    if root.scope != value.scope
        || *recovery_root_attempt_id != root.attempt_id
        || barrier.required_session_id != value.current_session_id
        || barrier.replacement_count == 0
        || barrier.baseline_inventory_ordinal != value.inventory_observation_ordinal
        || !attempt_happens_after(table, &root, reserved_attempt)?
    {
        return Err(state_error(
            "provider-head predecessor recovery barrier is inconsistent",
        ));
    }
    recovery_session_chain(
        table,
        &root,
        value.current_session_id,
        barrier.replacement_count,
    )?;
    if reserved_intent.recovery_root_attempt_id != Some(root.attempt_id)
        || reserved_intent.known_observation_ordinal != barrier.baseline_inventory_ordinal
        || !inventory_intent_matches_floor(reserved_intent, value.inventory_floor.as_ref())
    {
        return Err(state_error(
            "provider-head predecessor recovery reservation does not join its root",
        ));
    }
    let tail = barrier
        .recovery_inventory_tail
        .map(|reference| exact_attempt(table, reference))
        .transpose()?;
    if let Some(tail) = tail {
        let ProviderIntentV2::Inventory { value: tail_intent } = &tail.intent else {
            return Err(state_error(
                "provider-head predecessor recovery tail is not Inventory",
            ));
        };
        if tail.scope != value.scope
            || tail.method != ProviderMethodV2::Inventory
            || tail_intent.recovery_root_attempt_id != Some(root.attempt_id)
            || tail_intent.known_observation_ordinal != barrier.baseline_inventory_ordinal
            || !inventory_intent_matches_floor(tail_intent, value.inventory_floor.as_ref())
            || !attempt_happens_after(table, tail, reserved_attempt)?
        {
            return Err(state_error(
                "provider-head predecessor recovery Inventory tail is inconsistent",
            ));
        }
    }
    let owner_follows_tail = match tail {
        None => {
            reserved_attempt.previous_attempt_id.is_none()
                && reserved_attempt.attempt_number == 1
                && reserved_attempt.lineage_root_attempt_id == reserved_attempt.attempt_id
        }
        Some(tail) => {
            reserved_attempt.previous_attempt_id == Some(tail.attempt_id)
                && tail.attempt_number.checked_add(1) == Some(reserved_attempt.attempt_number)
                && reserved_attempt.lineage_root_attempt_id == tail.lineage_root_attempt_id
        }
    };
    if !owner_follows_tail {
        return Err(state_error(
            "provider-head predecessor recovery owner does not advance its tail",
        ));
    }
    let mut recovery_attempts = Vec::new();
    for attempt in table.provider_attempts.values() {
        let belongs_to_root = matches!(
            &attempt.intent,
            ProviderIntentV2::Inventory { value: intent }
                if intent.recovery_root_attempt_id == Some(root.attempt_id)
        );
        if attempt.attempt_id != reserved_attempt.attempt_id
            && belongs_to_root
            && attempt_happens_after(table, attempt, reserved_attempt)?
        {
            recovery_attempts.push(attempt);
        }
    }
    if tail.is_none() && !recovery_attempts.is_empty() {
        return Err(state_error(
            "provider-head predecessor recovery Inventory lacks a tail",
        ));
    }
    if let Some(tail) = tail {
        for recovery_attempt in recovery_attempts {
            if recovery_attempt.scope != value.scope
                || recovery_attempt.method != ProviderMethodV2::Inventory
                || recovery_attempt.lineage_root_attempt_id != tail.lineage_root_attempt_id
                || (recovery_attempt.attempt_id != tail.attempt_id
                    && !attempt_happens_after(table, recovery_attempt, tail)?)
            {
                return Err(state_error(
                    "provider-head predecessor recovery Inventory join is inconsistent",
                ));
            }
        }
    }
    Ok(())
}

pub(super) fn validate_ordinary_inventory_predecessor(
    value: &ProviderHeadPredecessorWitnessV2,
    reserved_attempt: &SourceProviderQueryAttemptV2,
    table: &SourceAcquisitionTableV2,
) -> Result<()> {
    let tail = value
        .last_inventory_attempt
        .map(|reference| exact_attempt(table, reference))
        .transpose()?;
    match (tail, reserved_attempt.previous_attempt_id) {
        (None, None)
            if reserved_attempt.attempt_number == 1
                && reserved_attempt.lineage_root_attempt_id == reserved_attempt.attempt_id =>
        {
            Ok(())
        }
        (Some(tail), Some(previous))
            if previous == tail.attempt_id
                && tail.attempt_number.checked_add(1) == Some(reserved_attempt.attempt_number)
                && tail.lineage_root_attempt_id == reserved_attempt.lineage_root_attempt_id =>
        {
            Ok(())
        }
        (Some(tail), None)
            if tail.attempt_number == MAXIMUM_LINEAGE_ATTEMPTS as u64
                && attempt_is_terminal(&tail.state)
                && reserved_attempt.attempt_number == 1
                && reserved_attempt.lineage_root_attempt_id == reserved_attempt.attempt_id =>
        {
            Ok(())
        }
        _ => Err(state_error(
            "ordinary Inventory reservation does not extend or compact its exact tail",
        )),
    }
}

pub(super) fn reserved_head_follows_predecessor(
    predecessor: &ProviderHeadPredecessorWitnessV2,
    attempt: &SourceProviderQueryAttemptV2,
    table: &SourceAcquisitionTableV2,
) -> bool {
    let Some(current) = table.provider_heads.get(&(
        predecessor.scope.holder_authority_id,
        predecessor.scope.provider_authority_id,
    )) else {
        return false;
    };
    let attempt_reference = RecordRefV2 {
        id: attempt.attempt_id,
        revision: attempt.revision,
        record_digest: attempt.record_digest,
    };
    predecessor.record.revision.checked_add(1) == Some(current.revision)
        && current.scope == predecessor.scope
        && current.holder_authority_generation == predecessor.holder_authority_generation
        && current.holder_authority_digest == predecessor.holder_authority_digest
        && current.provider_authority_generation == predecessor.provider_authority_generation
        && current.provider_authority_digest == predecessor.provider_authority_digest
        && current.current_session_id == predecessor.current_session_id
        && current.current_session_record_digest == predecessor.current_session_record_digest
        && predecessor.next_request_sequence.checked_add(1) == Some(current.next_request_sequence)
        && current.next_response_sequence == predecessor.next_response_sequence
        && current.pending_attempt == Some(attempt_reference)
        && current.inventory_observation_ordinal == predecessor.inventory_observation_ordinal
        && current.inventory_floor == predecessor.inventory_floor
        && current.last_inventory_attempt == predecessor.last_inventory_attempt
        && current.current_projection_epoch == predecessor.current_projection_epoch
        && current.current_projection_digest == predecessor.current_projection_digest
        && current.last_reconciliation == predecessor.last_reconciliation
        && current.recovery_barrier == predecessor.recovery_barrier
}

pub(super) fn validate_predecessor_evidence(value: &AcquisitionPredecessorWitnessV2) -> Result<()> {
    if value.record.revision == 0
        || value.record.record_digest == [0; 32]
        || value.descriptor_custody_digest == Some([0; 32])
        || value.positive_custody_digest == Some([0; 32])
        || value.negative_custody_digest == Some([0; 32])
        || value.manager_custody_loss.is_some_and(|loss| {
            loss.capture_id == [0; 32]
                || loss.capture_record_digest == [0; 32]
                || loss.death_commitment == [0; 32]
                || loss.evidence_digest != manager_custody_loss_evidence_digest_v2(&loss)
        })
        || value.fault_digest == Some([0; 32])
        || value.retained_fault_digest == Some([0; 32])
        || value.consumption.as_ref().is_some_and(|evidence| {
            !consumption_evidence_is_valid(evidence)
                || !consumption_matches_template(
                    evidence,
                    None,
                    value.prospective_mount_template_digest,
                )
        })
    {
        return Err(state_error(
            "provider attempt predecessor has invalid scalar evidence",
        ));
    }
    if !provider_acquisition_is_valid(value.provider_acquisition, value.scope)
        || value.evidence.as_ref().is_some_and(|evidence| {
            evidence.provider_acquisition != value.provider_acquisition
                || evidence.acquire_attempt.id == [0; 32]
                || evidence.session_id == [0; 32]
                || evidence.provider_outcome_signer_digest == [0; 32]
                || evidence.provider_resource_id == [0; 32]
                || evidence.provider_resource_generation == 0
                || evidence.provider_resource_digest == [0; 32]
                || evidence.provider_catalog_generation == 0
                || evidence.provider_catalog_digest == [0; 32]
                || evidence.provider_selection_generation == 0
                || evidence.provider_selection_digest == [0; 32]
                || !(1..=4).contains(&evidence.provider_proof_class)
                || evidence.provider_proof_digest == [0; 32]
                || evidence.lease_id == [0; 16]
                || evidence.signed_lease_digest == [0; 32]
                || evidence.lease_issued_seconds < 0
                || evidence.lease_expires_seconds <= evidence.lease_issued_seconds
                || evidence.source_realization_handle == [0; 32]
                || evidence.source_physical_proof_digest == [0; 32]
                || evidence.source_kernel_boot_id == [0; 16]
                || evidence.source_device == 0
                || evidence.source_inode == 0
                || evidence.source_unique_mount_id == 0
                || evidence.descriptor_commitment == [0; 32]
        })
    {
        return Err(state_error(
            "provider attempt predecessor acquisition evidence is invalid",
        ));
    }
    if let Some(custody) = value.manager_custody {
        let subject_count = custody
            .cleanup_subject_count
            .checked_add(custody.terminal_subject_count);
        if custody.admission_predecessor.id != value.acquisition_id
            || custody.admission_predecessor.revision == 0
            || custody.admission_predecessor.revision >= value.record.revision
            || custody.admission_predecessor.record_digest == [0; 32]
            || custody.owner_attempt.id == [0; 32]
            || custody.owner_attempt.revision == 0
            || custody.owner_attempt.record_digest == [0; 32]
            || custody.owner_session_id == [0; 32]
            || custody.owner_session_record_digest == [0; 32]
            || custody.manager_kernel_boot_id == [0; 16]
            || custody.manager_execution_commitment == [0; 32]
            || custody.capture_sequence == 0
            || custody.capture_id == [0; 32]
            || custody.capture_record_digest == [0; 32]
            || custody.descriptor_count == 0
            || custody.activation_count > custody.descriptor_count
            || custody.expected_descriptor_count > custody.descriptor_count
            || subject_count != Some(custody.source_subject_count)
            || custody.source_entry_commitment == [0; 32]
            || custody.presence_commitment == [0; 32]
            || custody.evidence_digest != manager_custody_evidence_digest_v2(&custody)
        {
            return Err(state_error(
                "provider attempt predecessor manager custody is malformed",
            ));
        }
    }
    if value.release_inventory_fence.as_ref().is_some_and(|fence| {
        fence.inventory_observation_floor == 0
            || fence.projection_epoch == 0
            || fence.projection_digest == [0; 32]
            || fence.projection_entry_count == 0
            || usize::try_from(fence.projection_entry_count).ok()
                > Some(MAXIMUM_SOURCE_ACQUISITIONS)
    }) {
        return Err(state_error(
            "provider attempt predecessor Release fence is invalid",
        ));
    }
    Ok(())
}

pub(super) fn validate_predecessor_phase(value: &AcquisitionPredecessorWitnessV2) -> Result<()> {
    let has_evidence = value.evidence.is_some();
    let has_manager_custody = value.manager_custody.is_some();
    let has_manager_custody_loss = value.manager_custody_loss.is_some();
    let has_descriptor = value.descriptor_custody_digest.is_some();
    let has_positive = value.positive_custody_digest.is_some();
    let has_consumption = value.consumption.is_some();
    let release_fields = [
        value.release.is_some(),
        value.release_authority.is_some(),
        value.release_from_phase.is_some(),
        value.release_intent_digest.is_some(),
        value.release_lineage.is_some(),
        value.release_inventory_fence.is_some(),
    ];
    if release_fields.iter().any(|field| *field) && release_fields.iter().any(|field| !*field) {
        return Err(state_error(
            "provider attempt predecessor has partial Release intent",
        ));
    }
    let acquisition_shape = |phase| match phase {
        SourceAcquisitionPhaseV2::PendingQuery => {
            !has_manager_custody && !has_descriptor && !has_positive && !has_consumption
        }
        SourceAcquisitionPhaseV2::DescriptorCustodied => {
            has_evidence
                && has_manager_custody
                && has_descriptor
                && !has_positive
                && !has_consumption
        }
        SourceAcquisitionPhaseV2::Active => {
            has_evidence
                && has_manager_custody
                && has_descriptor
                && has_positive
                && !has_consumption
        }
        SourceAcquisitionPhaseV2::Consumed => {
            has_evidence && has_manager_custody && has_descriptor && has_positive && has_consumption
        }
        SourceAcquisitionPhaseV2::Releasing
        | SourceAcquisitionPhaseV2::Released
        | SourceAcquisitionPhaseV2::Faulted => false,
    };
    let release_shape = value.release_from_phase.is_some_and(acquisition_shape)
        && (value.release_from_phase != Some(SourceAcquisitionPhaseV2::PendingQuery)
            || has_manager_custody_loss);
    let phase_shape = |phase| match phase {
        SourceAcquisitionPhaseV2::PendingQuery
        | SourceAcquisitionPhaseV2::DescriptorCustodied
        | SourceAcquisitionPhaseV2::Active
        | SourceAcquisitionPhaseV2::Consumed => {
            acquisition_shape(phase)
                && value.release_lineage.is_none()
                && value.release_proof.is_none()
                && value.negative_custody_digest.is_none()
                && !has_manager_custody_loss
        }
        SourceAcquisitionPhaseV2::Releasing => {
            release_shape
                && value.release_proof.is_none()
                && value.negative_custody_digest.is_none()
        }
        SourceAcquisitionPhaseV2::Released => {
            release_shape
                && value.release_proof.is_some()
                && value.negative_custody_digest.is_some()
        }
        SourceAcquisitionPhaseV2::Faulted => false,
    };
    let shape = match value.phase {
        SourceAcquisitionPhaseV2::Faulted => value.faulted_from.is_some_and(phase_shape),
        phase => phase_shape(phase),
    };
    let fault_pair = value.faulted_from.is_some() == value.fault_digest.is_some();
    let retained_pair =
        value.retained_faulted_from.is_some() == value.retained_fault_digest.is_some();
    if !shape
        || !fault_pair
        || !retained_pair
        || (value.phase != SourceAcquisitionPhaseV2::Faulted && value.faulted_from.is_some())
        || matches!(
            value.faulted_from,
            Some(SourceAcquisitionPhaseV2::Faulted | SourceAcquisitionPhaseV2::Released)
        )
        || matches!(
            value.retained_faulted_from,
            Some(SourceAcquisitionPhaseV2::Faulted | SourceAcquisitionPhaseV2::Released)
        )
        || (value.retained_faulted_from.is_some()
            && !matches!(
                value.phase,
                SourceAcquisitionPhaseV2::Releasing | SourceAcquisitionPhaseV2::Released
            ))
        || value
            .retained_faulted_from
            .is_some_and(|origin| !predecessor_retained_origin_evidence_is_present(value, origin))
    {
        return Err(state_error(
            "provider attempt predecessor lifecycle shape is invalid",
        ));
    }
    Ok(())
}

pub(super) fn predecessor_retained_origin_evidence_is_present(
    value: &AcquisitionPredecessorWitnessV2,
    origin: SourceAcquisitionPhaseV2,
) -> bool {
    match origin {
        SourceAcquisitionPhaseV2::PendingQuery => true,
        SourceAcquisitionPhaseV2::DescriptorCustodied => {
            value.evidence.is_some()
                && value.manager_custody.is_some()
                && value.descriptor_custody_digest.is_some()
        }
        SourceAcquisitionPhaseV2::Active => {
            value.evidence.is_some()
                && value.manager_custody.is_some()
                && value.descriptor_custody_digest.is_some()
                && value.positive_custody_digest.is_some()
        }
        SourceAcquisitionPhaseV2::Consumed => {
            value.evidence.is_some()
                && value.manager_custody.is_some()
                && value.descriptor_custody_digest.is_some()
                && value.positive_custody_digest.is_some()
                && value.consumption.is_some()
        }
        SourceAcquisitionPhaseV2::Releasing => value.release_lineage.is_some(),
        SourceAcquisitionPhaseV2::Released | SourceAcquisitionPhaseV2::Faulted => false,
    }
}

pub(super) fn validate_predecessor_terminal_evidence(
    value: &AcquisitionPredecessorWitnessV2,
    table: &SourceAcquisitionTableV2,
) -> Result<()> {
    if let Some(custody) = value.manager_custody {
        let attempt = exact_attempt(table, custody.owner_attempt)?;
        let session = exact_session(
            table,
            custody.owner_session_id,
            custody.owner_session_record_digest,
        )?;
        if value.acquire_terminal_attempt != Some(custody.owner_attempt)
            || attempt.method != ProviderMethodV2::Acquire
            || attempt.owner
                != (ProviderQueryOwnerV2::Acquire {
                    acquisition_id: value.acquisition_id,
                })
            || !is_complete(attempt)
            || attempt.session_id != session.session_id
            || attempt.session_record_digest != session.record_digest
            || attempt.scope != value.scope
        {
            return Err(state_error(
                "provider attempt predecessor manager custody has no exact owner",
            ));
        }
    }
    if value.acquire_terminal_attempt.is_some() != value.evidence.is_some() {
        return Err(state_error(
            "acquisition predecessor Acquire terminal evidence has partial presence",
        ));
    }
    if let Some(reference) = value.acquire_terminal_attempt {
        let attempt = exact_attempt(table, reference)?;
        if reference != value.acquire_lineage.tail
            || attempt.method != ProviderMethodV2::Acquire
            || attempt.owner
                != (ProviderQueryOwnerV2::Acquire {
                    acquisition_id: value.acquisition_id,
                })
            || !is_complete(attempt)
            || value.evidence.as_ref().is_none_or(|evidence| {
                evidence.acquire_attempt != reference || evidence.session_id != attempt.session_id
            })
        {
            return Err(state_error(
                "acquisition predecessor Acquire evidence has the wrong terminal attempt",
            ));
        }
    }

    match &value.release_proof {
        Some(ReleaseProofV2::ProviderReceipt { attempt, .. }) => {
            let lineage = value
                .release_lineage
                .as_ref()
                .ok_or_else(|| state_error("acquisition predecessor Release lineage is missing"))?;
            let terminal = exact_attempt(table, *attempt)?;
            if value.release_terminal_attempt != Some(*attempt)
                || lineage.tail != *attempt
                || terminal.method != ProviderMethodV2::Release
                || terminal.owner
                    != (ProviderQueryOwnerV2::Release {
                        acquisition_id: value.acquisition_id,
                    })
                || !is_complete(terminal)
            {
                return Err(state_error(
                    "acquisition predecessor Release receipt has the wrong terminal attempt",
                ));
            }
        }
        Some(ReleaseProofV2::ProviderInventory { .. }) | None => {
            if value.release_terminal_attempt.is_some() {
                return Err(state_error(
                    "retryable acquisition predecessor retains a terminal Release attempt",
                ));
            }
        }
    }
    Ok(())
}

pub(super) fn same_acquisition_identity(
    attempt: &SourceProviderQueryAttemptV2,
    snapshot: &AcquisitionPredecessorWitnessV2,
    current: &SourceAcquisitionRowV2,
) -> bool {
    let provider_identity_matches = snapshot.provider_acquisition == current.provider_acquisition
        || (attempt.method == ProviderMethodV2::Acquire
            && attempt.provider_acquisition == Some(current.provider_acquisition)
            && snapshot.provider_acquisition.holder_authority_id
                == current.provider_acquisition.holder_authority_id
            && snapshot.provider_acquisition.acquisition_sequence
                == current.provider_acquisition.acquisition_sequence
            && snapshot.provider_acquisition.holder_authority_generation
                < current.provider_acquisition.holder_authority_generation);
    snapshot.acquisition_id == current.acquisition_id
        && provider_identity_matches
        && snapshot.scope == current.scope
        && snapshot.acquire == current.acquire
        && snapshot.acquire.request_digest
            == *mount_source_acquisition_request_digest_v1(&current.mount_acquire_request)
                .as_bytes()
        && snapshot.acquire_intent_digest == current.acquire_intent_digest
        && snapshot.acquire_lineage.root == current.acquire_lineage.root
        && snapshot.assignment == current.assignment
        && snapshot.prospective_mount_template_digest == current.prospective_mount_template_digest
        && snapshot.source_binding_digest == current.source_binding_digest
        && snapshot.mount_plan_digest == current.mount_plan_digest
        && snapshot.ownership_lease_digest == current.ownership_lease_digest
}

pub(super) fn validate_acquisition_predecessor_lineage(
    attempt: &SourceProviderQueryAttemptV2,
    snapshot: &AcquisitionPredecessorWitnessV2,
    current: &SourceAcquisitionRowV2,
    table: &SourceAcquisitionTableV2,
) -> Result<()> {
    if attempt.method == ProviderMethodV2::Release && attempt.attempt_number == 1 {
        if attempt.previous_attempt_id.is_some()
            || attempt.provider_acquisition != Some(snapshot.provider_acquisition)
            || snapshot.release.is_some()
            || snapshot.release_lineage.is_some()
            || snapshot.release_intent_digest.is_some()
            || !matches!(&snapshot.recovery, AcquisitionRecoveryV2::Ready)
            || current.release_from_phase != Some(effective_predecessor_phase(snapshot))
            || snapshot.acquire_lineage != current.acquire_lineage
            || snapshot.acquire_terminal_attempt != current.acquire_terminal_attempt
            || snapshot.evidence != current.evidence
            || snapshot.manager_custody != current.manager_custody
            || snapshot.descriptor_custody_digest != current.descriptor_custody_digest
            || snapshot.positive_custody_digest != current.positive_custody_digest
            || snapshot.consumption != current.consumption
            || !initial_release_loss_handoff_is_exact(snapshot, current)
            || !initial_release_fault_handoff_is_exact(snapshot, current)
        {
            return Err(state_error(
                "initial Release predecessor already contains Release state",
            ));
        }
        return Ok(());
    }
    let previous = attempt
        .previous_attempt_id
        .ok_or_else(|| state_error("noninitial acquisition attempt lacks predecessor"))?;
    let predecessor_tail = match attempt.method {
        ProviderMethodV2::Acquire => snapshot.acquire_lineage.tail,
        ProviderMethodV2::Release => {
            snapshot
                .release_lineage
                .as_ref()
                .ok_or_else(|| state_error("Release retry predecessor lacks lineage"))?
                .tail
        }
        ProviderMethodV2::Inventory => {
            return Err(state_error(
                "Inventory attempt uses an acquisition predecessor",
            ));
        }
    };
    let recovery_allows_retry = matches!(&snapshot.recovery, AcquisitionRecoveryV2::Ready)
        || matches!(
            &snapshot.recovery,
            AcquisitionRecoveryV2::RetryPermitted { root_attempt }
                if *root_attempt == predecessor_tail && predecessor_tail.id == previous
        );
    if !recovery_allows_retry {
        return Err(state_error(
            "provider retry predecessor is not ready for another query",
        ));
    }
    let predecessor_attempt = table
        .provider_attempts
        .get(&previous)
        .ok_or_else(|| state_error("provider retry predecessor attempt is missing"))?;
    let predecessor_provider_acquisition = predecessor_attempt
        .provider_acquisition
        .ok_or_else(|| state_error("provider retry predecessor identity is missing"))?;
    let current_provider_acquisition = attempt
        .provider_acquisition
        .ok_or_else(|| state_error("provider retry identity is missing"))?;
    let identity_advances = predecessor_provider_acquisition == current_provider_acquisition
        || (attempt.method == ProviderMethodV2::Acquire
            && current_provider_acquisition.holder_authority_id
                == predecessor_provider_acquisition.holder_authority_id
            && current_provider_acquisition.holder_authority_generation
                > predecessor_provider_acquisition.holder_authority_generation);
    if snapshot.provider_acquisition != predecessor_provider_acquisition || !identity_advances {
        return Err(state_error(
            "provider retry changes its acquisition identity without a new authority scope",
        ));
    }
    let (snapshot_lineage, current_lineage) = match attempt.method {
        ProviderMethodV2::Acquire => (&snapshot.acquire_lineage, &current.acquire_lineage),
        ProviderMethodV2::Release => {
            let snapshot_lineage = snapshot
                .release_lineage
                .as_ref()
                .ok_or_else(|| state_error("Release retry predecessor lacks lineage"))?;
            let current_lineage = current
                .release_lineage
                .as_ref()
                .ok_or_else(|| state_error("Release retry owner lacks lineage"))?;
            if snapshot.release != current.release
                || snapshot.release_authority != current.release_authority
                || snapshot.release_from_phase != current.release_from_phase
                || snapshot.release_intent_digest != current.release_intent_digest
                || !release_inventory_fence_witness_matches(
                    snapshot.release_inventory_fence.as_ref(),
                    current.release_inventory_fence.as_ref(),
                )
                || snapshot.evidence != current.evidence
                || snapshot.manager_custody != current.manager_custody
                || snapshot.manager_custody_loss != current.manager_custody_loss
                || snapshot.acquire_lineage != current.acquire_lineage
                || snapshot.acquire_terminal_attempt != current.acquire_terminal_attempt
                || snapshot.descriptor_custody_digest != current.descriptor_custody_digest
                || snapshot.positive_custody_digest != current.positive_custody_digest
                || snapshot.consumption != current.consumption
                || !release_retry_fault_handoff_is_exact(snapshot, current)
            {
                return Err(state_error(
                    "Release retry predecessor changes immutable Release intent",
                ));
            }
            (snapshot_lineage, current_lineage)
        }
        ProviderMethodV2::Inventory => {
            return Err(state_error(
                "Inventory attempt uses an acquisition predecessor",
            ));
        }
    };
    if snapshot_lineage.tail.id != previous
        || snapshot_lineage.next_attempt_number != attempt.attempt_number
        || snapshot_lineage.root != current_lineage.root
    {
        return Err(state_error(
            "provider retry does not advance its exact owner lineage",
        ));
    }
    Ok(())
}

fn initial_release_loss_handoff_is_exact(
    predecessor: &AcquisitionPredecessorWitnessV2,
    current: &SourceAcquisitionRowV2,
) -> bool {
    if predecessor.manager_custody_loss.is_some() {
        return false;
    }
    let Some(loss) = current.manager_custody_loss else {
        return true;
    };
    loss.subject.acquisition_id == predecessor.acquisition_id
        && loss.subject.acquisition_revision == predecessor.record.revision
        && loss.subject.acquisition_record_digest == predecessor.record.record_digest
        && current.release_from_phase == Some(effective_predecessor_phase(predecessor))
}

pub(super) fn initial_release_fault_handoff_is_exact(
    predecessor: &AcquisitionPredecessorWitnessV2,
    current: &SourceAcquisitionRowV2,
) -> bool {
    if predecessor.phase == SourceAcquisitionPhaseV2::Faulted {
        current.faulted_from.is_none()
            && current.fault_digest.is_none()
            && current.retained_faulted_from == predecessor.faulted_from
            && current.retained_fault_digest == predecessor.fault_digest
    } else {
        current.retained_faulted_from == predecessor.retained_faulted_from
            && current.retained_fault_digest == predecessor.retained_fault_digest
    }
}

pub(super) fn release_retry_fault_handoff_is_exact(
    predecessor: &AcquisitionPredecessorWitnessV2,
    current: &SourceAcquisitionRowV2,
) -> bool {
    if predecessor.phase == SourceAcquisitionPhaseV2::Faulted
        && predecessor.faulted_from == Some(SourceAcquisitionPhaseV2::Releasing)
    {
        current.faulted_from.is_none()
            && current.fault_digest.is_none()
            && current.retained_faulted_from == predecessor.faulted_from
            && current.retained_fault_digest == predecessor.fault_digest
    } else {
        current.retained_faulted_from == predecessor.retained_faulted_from
            && current.retained_fault_digest == predecessor.retained_fault_digest
    }
}

pub(super) fn release_inventory_fence_witness_matches(
    witness: Option<&ReleaseInventoryFenceWitnessV2>,
    current: Option<&ReleaseInventoryFenceV2>,
) -> bool {
    match (witness, current) {
        (Some(witness), Some(current)) => {
            witness.inventory_observation_floor == current.inventory_observation_floor
                && witness.projection_epoch == current.projection_epoch
                && witness.projection_digest == current.projection_digest
                && usize::try_from(witness.projection_entry_count).ok()
                    == Some(current.projection_entries.len())
        }
        (None, None) => true,
        (Some(_), None) | (None, Some(_)) => false,
    }
}

pub(super) fn effective_acquisition_phase(
    row: &SourceAcquisitionRowV2,
) -> SourceAcquisitionPhaseV2 {
    if row.phase == SourceAcquisitionPhaseV2::Faulted {
        row.faulted_from
            .unwrap_or(SourceAcquisitionPhaseV2::Faulted)
    } else {
        row.phase
    }
}

pub(super) fn effective_predecessor_phase(
    value: &AcquisitionPredecessorWitnessV2,
) -> SourceAcquisitionPhaseV2 {
    if value.phase == SourceAcquisitionPhaseV2::Faulted {
        value
            .faulted_from
            .unwrap_or(SourceAcquisitionPhaseV2::Faulted)
    } else {
        value.phase
    }
}
