//! Signed request, outcome, intent, and provider-death artifact validation.

use super::*;

pub(super) fn validate_consumed_result(
    attempt: &SourceProviderQueryAttemptV2,
    session: &SourceProviderSessionV2,
) -> Result<()> {
    let ProviderAttemptStateV2::DispositionConsumed {
        status: ProviderStatusV2::Complete,
        signed_result,
        ..
    } = &attempt.state
    else {
        return Ok(());
    };
    match attempt.method {
        ProviderMethodV2::Acquire => {
            let receipt = SignedSourceProviderReceiptV1::from_canonical_bytes(signed_result)
                .map_err(|_| state_error("retained provider Acquire receipt is invalid"))?;
            if !signer_matches(&session.signers[3], receipt.signer()) {
                return Err(state_error(
                    "retained provider Acquire receipt signer differs from session",
                ));
            }
            verify_provider_receipt(&receipt, &session.signers[3].public_key)
                .map_err(|_| state_error("retained provider Acquire receipt is unauthenticated"))
        }
        ProviderMethodV2::Release => {
            let receipt = SignedSourceReleaseReceiptV1::from_canonical_bytes(signed_result)
                .map_err(|_| state_error("retained provider Release receipt is invalid"))?;
            if !signer_matches(&session.signers[3], receipt.signer()) {
                return Err(state_error(
                    "retained provider Release receipt signer differs from session",
                ));
            }
            verify_release_receipt(&receipt, &session.signers[3].public_key)
                .map_err(|_| state_error("retained provider Release receipt is unauthenticated"))
        }
        ProviderMethodV2::Inventory => {
            let inventory = SignedSourceProviderInventoryV1::from_canonical_bytes(signed_result)
                .map_err(|_| state_error("retained provider Inventory is invalid"))?;
            if !signer_matches(&session.signers[3], inventory.signer()) {
                return Err(state_error(
                    "retained provider Inventory signer differs from session",
                ));
            }
            verify_inventory(&inventory, &session.signers[3].public_key)
                .map_err(|_| state_error("retained provider Inventory is unauthenticated"))?;
            validate_complete_inventory_attempt(attempt, session, &inventory)
        }
    }
}

pub(super) fn validate_complete_inventory_attempt(
    attempt: &SourceProviderQueryAttemptV2,
    session: &SourceProviderSessionV2,
    signed_inventory: &SignedSourceProviderInventoryV1,
) -> Result<()> {
    let ProviderIntentV2::Inventory { value: intent } = &attempt.intent else {
        return Err(state_error("Complete Inventory has a non-Inventory intent"));
    };
    let signed_request =
        SignedSourceProviderRequestV1::from_canonical_bytes(&attempt.signed_request)
            .map_err(|_| state_error("retained Inventory request is invalid"))?;
    let request = decode_inventory_request(signed_request.subject())
        .map_err(|_| state_error("retained Inventory request body is invalid"))?;
    let inventory = signed_inventory.subject();
    if inventory.request_id() != attempt.request_id
        || inventory.request_digest() != digest_inventory_request(&request)
        || inventory.holder_authority_id() != intent.scope.holder_authority_id
        || inventory.holder_generation() != session.root_mount_authority_generation
        || inventory.holder_authority_digest().as_bytes() != &session.root_mount_authority_digest
        || inventory.provider().authority_id() != intent.scope.provider_authority_id
        || inventory.provider().authority_generation() != session.provider_authority_generation
        || inventory.provider().authority_digest().as_bytes() != &session.provider_authority_digest
        || inventory.provider_process_instance() != session.provider_process_instance
        || session.authenticated_at_seconds >= request.deadline_seconds()
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
            "Complete provider Inventory graph contradicts its intent",
        ));
    }
    validate_inventory_entries(
        inventory,
        intent.scope,
        session.negotiated_capabilities.proof_class_capabilities,
    )?;
    validate_inventory_correlations(attempt, inventory)
}

fn validate_inventory_correlations(
    attempt: &SourceProviderQueryAttemptV2,
    inventory: &aos_sandbox_source_provider_protocol::SourceProviderInventoryV1,
) -> Result<()> {
    let correlations = attempt
        .inventory_correlations
        .as_ref()
        .ok_or_else(|| state_error("Inventory attempt lacks correlations"))?;
    for correlation in &correlations.entries {
        let matching = inventory.entries().iter().find(|entry| {
            entry.acquisition_id().as_bytes() == &correlation.provider_acquisition.acquisition_id
        });
        if matching.is_some_and(|entry| {
            correlation
                .lease_id
                .is_some_and(|lease_id| entry.lease_id() != lease_id)
                || correlation
                    .signed_lease_digest
                    .is_some_and(|digest| entry.lease_digest().as_bytes() != &digest)
        }) {
            return Err(state_error(
                "provider Inventory aliases a correlated acquisition with another lease",
            ));
        }
        let matches = match (correlation.expectation, matching) {
            (InventoryCorrelationExpectationV2::AbsentOrMatchingActive, None) => true,
            (InventoryCorrelationExpectationV2::AbsentOrMatchingActive, Some(entry)) => {
                entry.state() == InventoryLeaseStateV1::Active
            }
            (InventoryCorrelationExpectationV2::PresentActiveOrReaping, Some(entry)) => matches!(
                entry.state(),
                InventoryLeaseStateV1::Active | InventoryLeaseStateV1::Reaping
            ),
            (InventoryCorrelationExpectationV2::ReapingReleasedOrAbsent, Some(entry)) => matches!(
                entry.state(),
                InventoryLeaseStateV1::Reaping | InventoryLeaseStateV1::Released
            ),
            (InventoryCorrelationExpectationV2::ReleasedOrAbsent, Some(entry)) => {
                entry.state() == InventoryLeaseStateV1::Released
            }
            (
                InventoryCorrelationExpectationV2::ReapingReleasedOrAbsent
                | InventoryCorrelationExpectationV2::ReleasedOrAbsent,
                None,
            ) => true,
            _ => false,
        };
        if !matches {
            return Err(state_error(
                "provider Inventory contradicts its reserved correlation preimage",
            ));
        }
    }
    Ok(())
}

pub(super) fn validate_intent(intent: &ProviderIntentV2) -> Result<()> {
    match intent {
        ProviderIntentV2::Acquire { value } => {
            if !valid_scope(value.scope)
                || value.acquisition_id == [0; 32]
                || value.mount_request.is_empty()
                || value.mount_request_digest == [0; 32]
                || value.assignment.sandbox_id == [0; 16]
                || value.assignment.incarnation_id == [0; 16]
                || value.assignment.assignment_epoch == 0
                || value.assignment.desired_generation == 0
                || value.assignment.assignment_digest == [0; 32]
                || value.assignment.namespace_generation == 0
                || value.mount_plan_digest == [0; 32]
                || value.ownership_lease_digest == [0; 32]
                || value.prospective_mount_template.is_empty()
                || value.prospective_mount_template_digest == [0; 32]
                || value.source_binding.is_empty()
                || value.source_binding_digest == [0; 32]
                || value.requested_lease_seconds == 0
                || (!value.recursive && value.requested_maximum_submounts != 0)
            {
                return Err(state_error("immutable provider Acquire intent is invalid"));
            }
        }
        ProviderIntentV2::Release { value } => {
            if !valid_scope(value.scope)
                || value.acquisition_id == [0; 32]
                || !provider_acquisition_is_valid(value.provider_acquisition, value.scope)
                || value.mount_request.is_empty()
                || value.mount_operation.operation_id == [0; 16]
                || value.mount_operation.request_digest == [0; 32]
                || value.authority.sandbox_id == [0; 16]
                || value.authority.incarnation_id == [0; 16]
                || value.authority.assignment_epoch == 0
                || value.authority.desired_generation == 0
                || value.authority.assignment_digest == [0; 32]
                || value.authority.expected_revision == 0
                || value.authority.expected_record_digest == [0; 32]
                || value.lease_id == [0; 16]
                || value.signed_lease_digest == [0; 32]
                || value.provider_resource_id == [0; 32]
                || value.provider_resource_digest == [0; 32]
                || value.provider_proof_digest == [0; 32]
                || value.descriptor_commitment == [0; 32]
            {
                return Err(state_error("immutable provider Release intent is invalid"));
            }
        }
        ProviderIntentV2::Inventory { value } => {
            if !valid_scope(value.scope)
                || value.known_inventory_generation.is_some()
                    != value.known_inventory_digest.is_some()
                || value.known_catalog_generation.is_some() != value.known_catalog_digest.is_some()
                || value.known_inventory_generation == Some(0)
                || value.known_inventory_digest == Some([0; 32])
                || value.known_catalog_generation == Some(0)
                || value.known_catalog_digest == Some([0; 32])
                || value.recovery_root_attempt_id == Some([0; 32])
                || value.correlation_digest == [0; 32]
            {
                return Err(state_error(
                    "immutable provider Inventory intent is invalid",
                ));
            }
        }
    }
    Ok(())
}

pub(super) fn provider_acquisition_is_valid(
    value: ProviderAcquisitionIdentityV2,
    scope: ProviderScopeV2,
) -> bool {
    value.holder_authority_id == scope.holder_authority_id
        && value.holder_authority_generation != 0
        && value.holder_authority_digest != [0; 32]
        && value.acquisition_sequence != 0
        && value.acquisition_id != [0; 32]
        && source_acquisition_id_v2(
            value.holder_authority_id,
            value.holder_authority_generation,
            ObjectDigest::from_bytes(value.holder_authority_digest),
            value.acquisition_sequence,
        )
        .as_bytes()
            == &value.acquisition_id
}

pub(super) fn validate_attempt_revision(attempt: &SourceProviderQueryAttemptV2) -> Result<()> {
    let expected = match &attempt.state {
        ProviderAttemptStateV2::Reserved => 1,
        ProviderAttemptStateV2::DispositionConsumed { .. } => 2,
        ProviderAttemptStateV2::AbandonedIndeterminate { resolution, .. } => {
            if resolution.is_some() {
                if match &attempt.state {
                    ProviderAttemptStateV2::AbandonedIndeterminate {
                        recovery_root_attempt_id,
                        ..
                    } => *recovery_root_attempt_id != attempt.attempt_id,
                    _ => true,
                } {
                    return Err(state_error("only a recovery root may retain resolution"));
                }
                3
            } else {
                2
            }
        }
        ProviderAttemptStateV2::SupersededIndeterminate { .. } => 2,
    };
    if attempt.revision != expected {
        return Err(state_error(
            "SourceProvider attempt revision contradicts state",
        ));
    }
    Ok(())
}

pub(super) fn validate_provider_request(
    attempt: &SourceProviderQueryAttemptV2,
    session: &SourceProviderSessionV2,
    table: &SourceAcquisitionTableV2,
) -> Result<()> {
    let signed = SignedSourceProviderRequestV1::from_canonical_bytes(&attempt.signed_request)
        .map_err(|_| state_error("retained SourceProvider request is invalid"))?;
    let common_matches = |binding: &[u8; 32], sequence, request| {
        binding == &session.session_binding
            && sequence == attempt.request_sequence
            && request == attempt.request_id
    };
    match (&attempt.intent, attempt.method, attempt.owner) {
        (
            ProviderIntentV2::Acquire { value },
            ProviderMethodV2::Acquire,
            ProviderQueryOwnerV2::Acquire { acquisition_id },
        ) => {
            let provider_acquisition = attempt
                .provider_acquisition
                .ok_or_else(|| state_error("provider Acquire identity is missing"))?;
            let request = decode_acquire_request(signed.subject())
                .map_err(|_| state_error("retained provider Acquire body is invalid"))?;
            let normalized = NormalizedAcquisitionIntentV2::from_acquire_request(
                &request,
                session_provider_authority(session)?,
                session_holder_authority(session)?,
                session.node_id,
                session.kernel_boot_id,
                session.scope.route_id,
                session.route_generation,
                ObjectDigest::from_bytes(session.route_digest),
                ObjectDigest::from_bytes(session.scope.resource_namespace_digest),
                session.revocation_generation,
                ObjectDigest::from_bytes(session.revocation_digest),
            )
            .map_err(|_| state_error("provider Acquire intent cannot be normalized"))?;
            let retained_normalization = attempt
                .normalized_acquire_intent
                .as_ref()
                .ok_or_else(|| state_error("provider Acquire normalization is missing"))?;
            if acquisition_id != value.acquisition_id
                || !common_matches(
                    request.session_binding().as_bytes(),
                    request.sequence(),
                    request.request_id(),
                )
                || !provider_acquisition_is_valid(provider_acquisition, value.scope)
                || request.acquisition_id().as_bytes() != &provider_acquisition.acquisition_id
                || request.acquisition_sequence() != provider_acquisition.acquisition_sequence
                || request.holder_authority_id() != value.scope.holder_authority_id
                || request.holder_generation() != session.root_mount_authority_generation
                || request.holder_authority_digest().as_bytes()
                    != &session.root_mount_authority_digest
                || request.holder_authority_id() != provider_acquisition.holder_authority_id
                || request.holder_generation() != provider_acquisition.holder_authority_generation
                || request.holder_authority_digest().as_bytes()
                    != &provider_acquisition.holder_authority_digest
                || request.node_id() != session.node_id
                || request.boot_id() != session.kernel_boot_id
                || request.prospective_apply_template() != value.prospective_mount_template
                || request.prospective_apply_template_digest().as_bytes()
                    != &value.prospective_mount_template_digest
                || request.binding() != value.source_binding
                || request.binding_digest().as_bytes() != &value.source_binding_digest
                || request.requested_lease_seconds() != value.requested_lease_seconds
                || request.requested_maximum_submounts() != value.requested_maximum_submounts
                || request.recursive() != value.recursive
                || request.kernel_coupled() != value.kernel_coupled
                || session.authenticated_at_seconds >= request.deadline_seconds()
                || retained_normalization.maximum_lease_expiry_seconds
                    != request
                        .deadline_seconds()
                        .min(session.current_valid_until_seconds)
                || normalized.to_canonical_bytes() != retained_normalization.bytes
                || normalized.digest().as_bytes() != &retained_normalization.digest
                || request.source_use() != SourceUseV1::MountCreate
            {
                return Err(state_error(
                    "provider Acquire request contradicts immutable intent",
                ));
            }
        }
        (
            ProviderIntentV2::Release { value },
            ProviderMethodV2::Release,
            ProviderQueryOwnerV2::Release { acquisition_id },
        ) => {
            let provider_acquisition = attempt
                .provider_acquisition
                .ok_or_else(|| state_error("provider Release identity is missing"))?;
            let request = decode_release_request(signed.subject())
                .map_err(|_| state_error("retained provider Release body is invalid"))?;
            if acquisition_id != value.acquisition_id
                || provider_acquisition != value.provider_acquisition
                || !common_matches(
                    request.session_binding().as_bytes(),
                    request.sequence(),
                    request.request_id(),
                )
                || request.acquisition_id().as_bytes() != &provider_acquisition.acquisition_id
                || request.holder_authority_id() != value.scope.holder_authority_id
                || request.holder_generation() != session.root_mount_authority_generation
                || request.holder_authority_digest().as_bytes()
                    != &session.root_mount_authority_digest
                || request.lease_id() != value.lease_id
                || request.lease_digest().as_bytes() != &value.signed_lease_digest
                || session.authenticated_at_seconds >= request.deadline_seconds()
            {
                return Err(state_error(
                    "provider Release request contradicts immutable intent",
                ));
            }
        }
        (
            ProviderIntentV2::Inventory { value },
            ProviderMethodV2::Inventory,
            ProviderQueryOwnerV2::Inventory,
        ) => {
            let request = decode_inventory_request(signed.subject())
                .map_err(|_| state_error("retained provider Inventory body is invalid"))?;
            if !common_matches(
                request.session_binding().as_bytes(),
                request.sequence(),
                request.request_id(),
            ) || request.holder_authority_id() != value.scope.holder_authority_id
                || request.holder_generation() != session.root_mount_authority_generation
                || request.holder_authority_digest().as_bytes()
                    != &session.root_mount_authority_digest
                || request
                    .known_inventory_digest()
                    .map(|digest| *digest.as_bytes())
                    != value.known_inventory_digest
                || session.authenticated_at_seconds >= request.deadline_seconds()
            {
                return Err(state_error(
                    "provider Inventory request contradicts immutable intent",
                ));
            }
            validate_inventory_intent_history(attempt, value, table)?;
        }
        _ => {
            return Err(state_error(
                "SourceProvider method, owner, and intent disagree",
            ));
        }
    }
    Ok(())
}

pub(super) fn validate_inventory_intent_history(
    attempt: &SourceProviderQueryAttemptV2,
    intent: &InventoryIntentV2,
    table: &SourceAcquisitionTableV2,
) -> Result<()> {
    let mut prior = Vec::new();
    for candidate in table.provider_attempts.values().filter(|candidate| {
        candidate.scope == attempt.scope
            && candidate.method == ProviderMethodV2::Inventory
            && is_complete(candidate)
            && candidate.attempt_id != attempt.attempt_id
    }) {
        if attempt_happens_after(table, candidate, attempt)? {
            prior.push(candidate);
        } else if !attempt_happens_after(table, attempt, candidate)? {
            return Err(state_error(
                "Inventory intent history is not chronologically ordered",
            ));
        }
    }
    let expected_ordinal = u64::try_from(prior.len())
        .map_err(|_| state_error("Inventory intent history exceeds u64"))?;
    if intent.known_observation_ordinal != expected_ordinal {
        return Err(state_error(
            "Inventory intent observation floor does not reproduce",
        ));
    }
    let latest = prior.into_iter().try_fold(None, |latest, candidate| {
        let Some(current) = latest else {
            return Ok::<_, MountSourceAcquisitionStateError>(Some(candidate));
        };
        if attempt_happens_after(table, current, candidate)? {
            Ok(Some(candidate))
        } else if attempt_happens_after(table, candidate, current)? {
            Ok(Some(current))
        } else {
            Err(state_error(
                "Inventory intent predecessors are not chronologically ordered",
            ))
        }
    })?;
    let expected = latest.map(inventory_attempt_floor).transpose()?;
    let retained = (
        intent.known_inventory_generation,
        intent.known_inventory_digest,
        intent.known_catalog_generation,
        intent.known_catalog_digest,
    );
    if retained != expected.unwrap_or((None, None, None, None)) {
        return Err(state_error(
            "Inventory intent does not retain its exact prior stable floor",
        ));
    }
    Ok(())
}

type InventoryIntentFloorV2 = (Option<u64>, Option<[u8; 32]>, Option<u64>, Option<[u8; 32]>);

pub(super) fn inventory_attempt_floor(
    attempt: &SourceProviderQueryAttemptV2,
) -> Result<InventoryIntentFloorV2> {
    let ProviderAttemptStateV2::DispositionConsumed {
        status: ProviderStatusV2::Complete,
        signed_result,
        ..
    } = &attempt.state
    else {
        return Err(state_error("Inventory floor source is not Complete"));
    };
    let signed = SignedSourceProviderInventoryV1::from_canonical_bytes(signed_result)
        .map_err(|_| state_error("Inventory floor source is invalid"))?;
    let inventory = signed.subject();
    Ok((
        Some(inventory.inventory_generation()),
        Some(*digest_inventory(inventory).as_bytes()),
        Some(inventory.catalog_generation()),
        Some(*inventory.catalog_digest().as_bytes()),
    ))
}

pub(super) fn validate_indeterminate_attempt(
    attempt: &SourceProviderQueryAttemptV2,
    table: &SourceAcquisitionTableV2,
) -> Result<()> {
    if let ProviderAttemptStateV2::SupersededIndeterminate {
        successor_session_id,
        recovery_root_attempt_id,
        outcome_may_exist,
    } = &attempt.state
    {
        let old = exact_session(table, attempt.session_id, attempt.session_record_digest)?;
        let successor = table
            .provider_sessions
            .get(successor_session_id)
            .ok_or_else(|| state_error("superseded attempt successor session is missing"))?;
        if !*outcome_may_exist
            || *recovery_root_attempt_id != attempt.lineage_root_attempt_id
            || successor.predecessor_session_id != Some(old.session_id)
            || successor.scope != old.scope
            || successor.session_id == old.session_id
        {
            return Err(state_error(
                "superseded provider attempt graph is inconsistent",
            ));
        }
        return Ok(());
    }

    let ProviderAttemptStateV2::AbandonedIndeterminate {
        dead_execution,
        successor_session_id,
        recovery_root_attempt_id,
        outcome_may_exist,
        resolution,
    } = &attempt.state
    else {
        return Ok(());
    };
    let old = exact_session(table, attempt.session_id, attempt.session_record_digest)?;
    let successor = table
        .provider_sessions
        .get(successor_session_id)
        .ok_or_else(|| state_error("abandoned attempt successor session is missing"))?;
    let recovery_root = table
        .provider_attempts
        .get(recovery_root_attempt_id)
        .ok_or_else(|| state_error("abandoned attempt recovery root is missing"))?;
    let joins_root = if attempt.attempt_id == recovery_root.attempt_id {
        true
    } else {
        matches!(
            &attempt.intent,
            ProviderIntentV2::Inventory { value }
                if value.recovery_root_attempt_id == Some(recovery_root.attempt_id)
        )
    };
    if !*outcome_may_exist
        || dead_execution.old_session_id != old.session_id
        || dead_execution.old_session_record_digest != old.record_digest
        || dead_execution.node_id != old.node_id
        || dead_execution.old_kernel_boot_id != old.kernel_boot_id
        || dead_execution.provider_process_instance != old.provider_process_instance
        || dead_execution.process_execution_digest
            != old.provider_execution.process_execution_digest
        || dead_execution.death_evidence_digest != death_digest(dead_execution)?
        || successor.predecessor_session_id != Some(old.session_id)
        || successor.scope != old.scope
        || recovery_root.scope != attempt.scope
        || !matches!(
            recovery_root.state,
            ProviderAttemptStateV2::AbandonedIndeterminate { .. }
        )
        || !joins_root
    {
        return Err(state_error(
            "abandoned provider execution graph is inconsistent",
        ));
    }
    match dead_execution.proof_kind {
        DeadProviderExecutionProofKindV2::PidfdExited => {
            if dead_execution.observed_kernel_boot_id != old.kernel_boot_id {
                return Err(state_error(
                    "same-boot provider death proof changed boot identity",
                ));
            }
        }
        DeadProviderExecutionProofKindV2::BootReplaced => {
            if dead_execution.observed_kernel_boot_id == old.kernel_boot_id
                || dead_execution.observed_kernel_boot_id == [0; 16]
            {
                return Err(state_error(
                    "cross-boot provider death proof did not replace boot",
                ));
            }
        }
    }
    if resolution.as_ref().is_some_and(|resolution| {
        !matches!(
            (attempt.method, resolution),
            (
                ProviderMethodV2::Acquire,
                RecoveryResolutionV2::RetryAcquireSameIntent { .. }
                    | RecoveryResolutionV2::Conflict { .. }
            ) | (
                ProviderMethodV2::Release,
                RecoveryResolutionV2::RetryReleaseSameIntent { .. }
                    | RecoveryResolutionV2::ProviderTerminalObserved { .. }
                    | RecoveryResolutionV2::Conflict { .. }
            ) | (
                ProviderMethodV2::Inventory,
                RecoveryResolutionV2::InventoryReconciled { .. }
                    | RecoveryResolutionV2::Conflict { .. }
            )
        )
    }) {
        return Err(state_error(
            "provider recovery resolution contradicts abandoned method",
        ));
    }
    if let Some(resolution) = resolution {
        validate_recovery_resolution(attempt, resolution, table)?;
    }
    Ok(())
}

pub(super) fn validate_recovery_resolution(
    root: &SourceProviderQueryAttemptV2,
    resolution: &RecoveryResolutionV2,
    table: &SourceAcquisitionTableV2,
) -> Result<()> {
    let (proof, conflict_digest) = match resolution {
        RecoveryResolutionV2::RetryAcquireSameIntent { proof }
        | RecoveryResolutionV2::RetryReleaseSameIntent { proof }
        | RecoveryResolutionV2::ProviderTerminalObserved { proof }
        | RecoveryResolutionV2::InventoryReconciled { proof } => (proof, None),
        RecoveryResolutionV2::Conflict {
            proof,
            conflict_digest,
        } => (proof, Some(*conflict_digest)),
    };
    let inventory_attempt = exact_attempt(table, proof.inventory_attempt)?;
    let ProviderAttemptStateV2::DispositionConsumed {
        status: ProviderStatusV2::Complete,
        signed_result,
        ..
    } = &inventory_attempt.state
    else {
        return Err(state_error(
            "provider recovery resolution lacks Complete Inventory",
        ));
    };
    let ProviderIntentV2::Inventory { value: intent } = &inventory_attempt.intent else {
        return Err(state_error(
            "provider recovery resolution points to a non-Inventory intent",
        ));
    };
    let signed_inventory = SignedSourceProviderInventoryV1::from_canonical_bytes(signed_result)
        .map_err(|_| state_error("provider recovery resolution Inventory is invalid"))?;
    let head = table
        .provider_heads
        .get(&(
            root.scope.holder_authority_id,
            root.scope.provider_authority_id,
        ))
        .ok_or_else(|| state_error("provider recovery resolution head is missing"))?;
    if inventory_attempt.scope != root.scope
        || intent.scope != root.scope
        || intent.recovery_root_attempt_id != Some(root.attempt_id)
        || proof.inventory_digest == [0; 32]
        || proof.inventory_observation_ordinal == 0
        || proof.inventory_observation_ordinal <= intent.known_observation_ordinal
        || proof.inventory_observation_ordinal > head.inventory_observation_ordinal
        || proof.projection_epoch > head.current_projection_epoch
        || proof.projection_digest == [0; 32]
        || proof.reconciliation_digest == [0; 32]
        || proof.reconciliation.projection_epoch != proof.projection_epoch
        || proof.reconciliation.projection_digest != proof.projection_digest
        || reconciliation_commitment(&proof.reconciliation) != proof.reconciliation_digest
        || digest_inventory(signed_inventory.subject()).as_bytes() != &proof.inventory_digest
        || conflict_digest == Some([0; 32])
    {
        return Err(state_error(
            "provider recovery resolution does not join its root",
        ));
    }
    if proof.inventory_observation_ordinal == head.inventory_observation_ordinal
        && (head.inventory_floor.as_ref().is_none_or(|floor| {
            floor.attempt != proof.inventory_attempt
                || floor.inventory_digest != proof.inventory_digest
        }) || (head.current_projection_epoch == proof.projection_epoch
            && head.last_reconciliation.as_ref() != Some(&proof.reconciliation)))
    {
        return Err(state_error(
            "current recovery Inventory floor differs from retained resolution",
        ));
    }
    if inventory_observation_ordinal(table, root.scope, inventory_attempt)?
        != proof.inventory_observation_ordinal
    {
        return Err(state_error(
            "provider recovery Inventory ordinal does not reproduce",
        ));
    }

    let row = match root.owner {
        ProviderQueryOwnerV2::Acquire { acquisition_id }
        | ProviderQueryOwnerV2::Release { acquisition_id } => {
            table.acquisitions.get(&acquisition_id)
        }
        ProviderQueryOwnerV2::Inventory => None,
    };
    let correlation = row
        .map(|row| recovery_inventory_correlation(inventory_attempt, row))
        .transpose()?;
    let entry = row.and_then(|row| {
        signed_inventory.subject().entries().iter().find(|entry| {
            entry.acquisition_id().as_bytes() == &row.provider_acquisition.acquisition_id
        })
    });
    let evidence_matches = row.zip(entry).is_some_and(|(row, entry)| {
        row.evidence
            .as_ref()
            .is_some_and(|evidence| inventory_entry_matches_evidence(entry, evidence))
    });
    let acquire_retry = root.method == ProviderMethodV2::Acquire
        && correlation.is_some_and(|correlation| {
            correlation.expectation == InventoryCorrelationExpectationV2::AbsentOrMatchingActive
        })
        && (entry.is_none()
            || entry.is_some_and(|entry| {
                entry.state() == aos_sandbox_source_provider_protocol::InventoryLeaseStateV1::Active
                    && evidence_matches
            }));
    let release_retry = root.method == ProviderMethodV2::Release
        && correlation.is_some_and(|correlation| {
            correlation.expectation == InventoryCorrelationExpectationV2::ReapingReleasedOrAbsent
        })
        && entry.is_some_and(|entry| {
            matches!(
                entry.state(),
                aos_sandbox_source_provider_protocol::InventoryLeaseStateV1::Active
                    | aos_sandbox_source_provider_protocol::InventoryLeaseStateV1::Reaping
            ) && evidence_matches
        });
    let release_terminal = root.method == ProviderMethodV2::Release
        && correlation.is_some_and(|correlation| {
            correlation.expectation == InventoryCorrelationExpectationV2::ReapingReleasedOrAbsent
        })
        && (entry.is_none()
            || entry.is_some_and(|entry| {
                entry.state()
                    == aos_sandbox_source_provider_protocol::InventoryLeaseStateV1::Released
                    && evidence_matches
            }));
    let target_conflicts = match root.method {
        ProviderMethodV2::Acquire => !acquire_retry,
        ProviderMethodV2::Release => !release_retry && !release_terminal,
        ProviderMethodV2::Inventory => proof.reconciliation.conflict_count != 0,
    };
    let resolution_matches = match resolution {
        RecoveryResolutionV2::RetryAcquireSameIntent { .. } => acquire_retry,
        RecoveryResolutionV2::RetryReleaseSameIntent { .. } => release_retry,
        RecoveryResolutionV2::ProviderTerminalObserved { .. } => release_terminal,
        RecoveryResolutionV2::InventoryReconciled { .. } => {
            root.method == ProviderMethodV2::Inventory
        }
        RecoveryResolutionV2::Conflict {
            conflict_digest, ..
        } => {
            target_conflicts
                && proof.reconciliation.conflict_count != 0
                && proof.reconciliation.conflict_digest == *conflict_digest
        }
    };
    if !resolution_matches {
        return Err(state_error(
            "provider recovery resolution contradicts Inventory evidence",
        ));
    }
    Ok(())
}

fn recovery_inventory_correlation<'a>(
    inventory_attempt: &'a SourceProviderQueryAttemptV2,
    row: &SourceAcquisitionRowV2,
) -> Result<&'a InventoryCorrelationV2> {
    let correlation = inventory_attempt
        .inventory_correlations
        .as_ref()
        .and_then(|correlations| {
            correlations
                .entries
                .iter()
                .find(|entry| entry.mount_acquisition_id == row.acquisition_id)
        })
        .ok_or_else(|| state_error("recovery Inventory omitted its target correlation"))?;
    if correlation.provider_acquisition != row.provider_acquisition
        || correlation.acquisition_record.id != row.acquisition_id
        || correlation.acquisition_record.revision > row.revision
        || row.evidence.as_ref().map(|evidence| evidence.lease_id) != correlation.lease_id
        || row
            .evidence
            .as_ref()
            .map(|evidence| evidence.signed_lease_digest)
            != correlation.signed_lease_digest
    {
        return Err(state_error(
            "recovery Inventory target differs from its reserved correlation",
        ));
    }
    Ok(correlation)
}
