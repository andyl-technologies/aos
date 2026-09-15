//! Provider-head, Inventory-floor, and inventory-entry validation.

use super::*;

pub(super) fn validate_head(
    head: &SourceProviderHeadV2,
    table: &SourceAcquisitionTableV2,
) -> Result<()> {
    let session = exact_session(
        table,
        head.current_session_id,
        head.current_session_record_digest,
    )?;
    if head.revision == 0
        || head.record_digest == [0; 32]
        || !valid_scope(head.scope)
        || session.scope != head.scope
        || head.holder_authority_generation != session.root_mount_authority_generation
        || head.holder_authority_digest != session.root_mount_authority_digest
        || head.provider_authority_generation != session.provider_authority_generation
        || head.provider_authority_digest != session.provider_authority_digest
        || head.next_request_sequence == 0
        || head.next_response_sequence == 0
    {
        return Err(state_error(
            "SourceProvider head is inconsistent with current session",
        ));
    }
    match head.pending_attempt {
        None if head.next_request_sequence != head.next_response_sequence => {
            return Err(state_error(
                "idle SourceProvider head sequence coordinates differ",
            ));
        }
        Some(reference) => {
            let attempt = exact_attempt(table, reference)?;
            if !matches!(&attempt.state, ProviderAttemptStateV2::Reserved)
                || attempt.session_id != head.current_session_id
                || attempt.scope != head.scope
                || attempt.request_sequence != head.next_response_sequence
                || head.next_request_sequence.checked_sub(1) != Some(head.next_response_sequence)
            {
                return Err(state_error(
                    "pending SourceProvider head edge is inconsistent",
                ));
            }
        }
        None => {}
    }
    validate_inventory_floor(head, table)?;
    let projection = project_scope(
        head.scope,
        head.current_projection_epoch,
        &table.acquisitions,
    )?;
    if projection.digest != head.current_projection_digest
        || usize::try_from(projection.count).ok()
            != Some(
                table
                    .acquisitions
                    .values()
                    .filter(|row| row.scope == head.scope)
                    .count(),
            )
    {
        return Err(state_error(
            "SourceProvider head projection digest is stale",
        ));
    }
    if let Some(reconciliation) = &head.last_reconciliation {
        if head.inventory_floor.is_none()
            || reconciliation.projection_epoch != head.current_projection_epoch
            || reconciliation.projection_digest != head.current_projection_digest
            || reconciliation.residual_digest == [0; 32]
            || reconciliation.conflict_digest == [0; 32]
        {
            return Err(state_error(
                "SourceProvider reconciliation checkpoint is invalid",
            ));
        }
        if reconciliation
            != &reproduce_reconciliation(head, &table.provider_attempts, &table.acquisitions)?
        {
            return Err(state_error(
                "SourceProvider reconciliation diagnostics do not reproduce",
            ));
        }
    }
    Ok(())
}

pub(super) fn validate_inventory_floor(
    head: &SourceProviderHeadV2,
    table: &SourceAcquisitionTableV2,
) -> Result<()> {
    if head.inventory_floor.is_some() != (head.inventory_observation_ordinal != 0) {
        return Err(state_error(
            "SourceProvider Inventory floor has incomplete presence",
        ));
    }
    let terminal_inventory_attempts = table
        .provider_attempts
        .values()
        .filter(|attempt| {
            attempt.scope == head.scope
                && attempt.method == ProviderMethodV2::Inventory
                && attempt_is_terminal(&attempt.state)
        })
        .collect::<Vec<_>>();
    let complete_inventory_count = terminal_inventory_attempts
        .iter()
        .filter(|attempt| is_complete(attempt))
        .count();
    if u64::try_from(complete_inventory_count)
        .map_err(|_| state_error("Complete provider Inventory count exceeds u64"))?
        != head.inventory_observation_ordinal
    {
        return Err(state_error(
            "provider Inventory ordinal does not equal its Complete history",
        ));
    }
    if head.last_inventory_attempt.is_some() != !terminal_inventory_attempts.is_empty() {
        return Err(state_error(
            "last provider Inventory attempt has incomplete presence",
        ));
    }
    if let Some(reference) = head.last_inventory_attempt {
        let last = exact_attempt(table, reference)?;
        if last.method != ProviderMethodV2::Inventory
            || last.scope != head.scope
            || !attempt_is_terminal(&last.state)
        {
            return Err(state_error(
                "last provider Inventory attempt is not a terminal Inventory",
            ));
        }
        for earlier in terminal_inventory_attempts {
            if earlier.attempt_id != last.attempt_id
                && !attempt_happens_after(table, earlier, last)?
            {
                return Err(state_error(
                    "last provider Inventory attempt is not chronologically last",
                ));
            }
        }
    }
    let Some(floor) = &head.inventory_floor else {
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
            "SourceProvider Inventory floor does not reference Complete Inventory",
        ));
    };
    let signed_inventory = SignedSourceProviderInventoryV1::from_canonical_bytes(signed_result)
        .map_err(|_| state_error("retained signed provider Inventory is invalid"))?;
    let inventory = signed_inventory.subject();
    let signed_request =
        SignedSourceProviderRequestV1::from_canonical_bytes(&attempt.signed_request)
            .map_err(|_| state_error("retained Inventory request is invalid"))?;
    let request = decode_inventory_request(signed_request.subject())
        .map_err(|_| state_error("retained Inventory request body is invalid"))?;
    verify_inventory(&signed_inventory, &session.signers[3].public_key)
        .map_err(|_| state_error("retained provider Inventory signature is invalid"))?;
    let ProviderIntentV2::Inventory { value: intent } = &attempt.intent else {
        return Err(state_error("Inventory floor attempt has the wrong intent"));
    };
    if inventory_observation_ordinal(table, head.scope, attempt)?
        != head.inventory_observation_ordinal
    {
        return Err(state_error(
            "SourceProvider Inventory floor is not the latest Complete observation",
        ));
    }
    if attempt.method != ProviderMethodV2::Inventory
        || attempt.scope != head.scope
        || floor.provider_authority_generation == 0
        || floor.provider_authority_digest == [0; 32]
        || floor.provider_outcome_signer_digest == [0; 32]
        || floor.inventory_generation == 0
        || floor.inventory_digest == [0; 32]
        || floor.catalog_generation == 0
        || floor.catalog_digest == [0; 32]
        || floor.signed_result_digest == [0; 32]
    {
        return Err(state_error(
            "SourceProvider Inventory floor does not reference Complete Inventory",
        ));
    }
    if !signer_matches(&session.signers[3], signed_inventory.signer())
        || inventory.request_id() != attempt.request_id
        || inventory.request_digest() != digest_inventory_request(&request)
        || inventory.holder_authority_id() != head.scope.holder_authority_id
        || inventory.holder_generation() != session.root_mount_authority_generation
        || inventory.holder_authority_digest().as_bytes() != &session.root_mount_authority_digest
        || inventory.provider().authority_id() != head.scope.provider_authority_id
        || inventory.provider().authority_generation() != floor.provider_authority_generation
        || inventory.provider().authority_digest().as_bytes() != &floor.provider_authority_digest
        || inventory.provider_process_instance() != session.provider_process_instance
        || session.authenticated_at_seconds >= request.deadline_seconds()
        || inventory.inventory_generation() != floor.inventory_generation
        || digest_inventory(inventory).as_bytes() != &floor.inventory_digest
        || inventory.catalog_generation() != floor.catalog_generation
        || inventory.catalog_digest().as_bytes() != &floor.catalog_digest
        || session.signers[3].public_key_fingerprint != floor.provider_outcome_signer_digest
        || signed_result_digest != &floor.signed_result_digest
        || intent.scope != head.scope
        || intent.known_inventory_generation.is_some() != intent.known_inventory_digest.is_some()
        || intent.known_catalog_generation.is_some() != intent.known_catalog_digest.is_some()
        || intent.known_inventory_generation.is_some_and(|generation| {
            inventory.inventory_generation() < generation
                || (inventory.inventory_generation() == generation
                    && intent.known_inventory_digest
                        != Some(*digest_inventory(inventory).as_bytes()))
        })
        || intent.known_catalog_generation.is_some_and(|generation| {
            inventory.catalog_generation() < generation
                || (inventory.catalog_generation() == generation
                    && intent.known_catalog_digest != Some(*inventory.catalog_digest().as_bytes()))
        })
    {
        return Err(state_error(
            "SourceProvider Inventory floor disagrees with its signed result",
        ));
    }
    validate_inventory_entries(
        inventory,
        head.scope,
        session.negotiated_capabilities.proof_class_capabilities,
    )?;
    Ok(())
}

pub(super) fn validate_inventory_entries(
    inventory: &aos_sandbox_source_provider_protocol::SourceProviderInventoryV1,
    scope: ProviderScopeV2,
    proof_capabilities: u8,
) -> Result<()> {
    let mut acquisition_ids = BTreeSet::new();
    for entry in inventory.entries() {
        let resource = entry.resource();
        let proof_bit = 1_u8
            .checked_shl(u32::from(entry.proof_class().saturating_sub(1)))
            .unwrap_or(0);
        if !acquisition_ids.insert(*entry.acquisition_id().as_bytes())
            || resource.resource_namespace_digest().as_bytes() != &scope.resource_namespace_digest
            || resource.catalog_generation() > inventory.catalog_generation()
            || (resource.catalog_generation() == inventory.catalog_generation()
                && resource.catalog_digest() != inventory.catalog_digest())
            || entry.proof_class() == 0
            || entry.proof_class() > 4
            || proof_bit & proof_capabilities == 0
            || entry.resource_commitment()
                != provider_resource_commitment_v1(resource, entry.proof_digest())
        {
            return Err(state_error(
                "retained provider Inventory entry violates its floor",
            ));
        }
    }
    Ok(())
}
