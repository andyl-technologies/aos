//! Durable backend-observation to Active completion ordering.

use super::*;

pub(crate) fn complete_acquire(
    ledger: &mut ProviderLedgerV1<'_>,
    permit: DurableAcquireEffectPermitV1,
    observed: ObservedBackendAcquisitionV1,
    custody: &mut CurrentProviderIngressSessionV1,
) -> Result<DurableProviderReplyV1, ProviderLedgerError> {
    ledger
        .journal
        .validate_source_provider_authority_snapshot(&permit.journal_snapshot)?;
    let acquisition_key_value = ledger
        .recovered
        .acquisitions
        .keys()
        .find(|key| key.acquisition_id == permit.plan.acquisition_id)
        .cloned()
        .ok_or(ProviderLedgerError::InvalidTransition(
            "unknown acquire permit",
        ))?;
    let mut acquisition = ledger
        .recovered
        .acquisitions
        .get(&acquisition_key_value)
        .cloned()
        .ok_or(ProviderLedgerError::Corrupt("missing applying acquisition"))?;
    if acquisition.state != ProviderAcquisitionStateV1::Applying
        || permit.reservation_digest.as_bytes() == &[0; 32]
        || !permit.plan.matches_effect_acquisition(&acquisition)
        || observed.backend_id != permit.plan.backend_id
        || observed.lineage_digest != permit.plan.lineage_digest()
        || observed.evidence.state() != BackendEvidenceStateV1::Acquired
    {
        return Err(ProviderLedgerError::BackendConflict);
    }
    let attempt_key_value =
        ledger
            .recovered
            .attempts
            .keys()
            .find(|key| {
                ledger.recovered.attempts.get(*key).is_some_and(|attempt| {
                    attempt.attempt_digest == permit.completion_attempt_digest
                })
            })
            .cloned()
            .ok_or(ProviderLedgerError::Corrupt("missing acquire attempt"))?;
    let mut attempt = ledger
        .recovered
        .attempts
        .get(&attempt_key_value)
        .cloned()
        .ok_or(ProviderLedgerError::Corrupt("missing acquire attempt"))?;
    if attempt.state != ProviderAttemptStateV1::Reserved
        || attempt.session_binding != permit.completion_session_binding
        || attempt.attempt_digest != permit.completion_attempt_digest
    {
        return Err(ProviderLedgerError::InvalidTransition(
            "acquire attempt not reserved",
        ));
    }
    validate_backend_selection(ledger, &acquisition, &attempt, &observed)?;
    observed.revalidate_physical()?;
    let session_identity = (
        acquisition.provider.authority_id(),
        acquisition.holder.authority_id(),
    );
    let mut session = ledger
        .recovered
        .sessions
        .get(&session_identity)
        .cloned()
        .ok_or(ProviderLedgerError::Corrupt("missing acquire session"))?;
    if session.pending_attempt_digest != Some(attempt.attempt_digest) {
        return Err(ProviderLedgerError::Corrupt("acquire pending link"));
    }

    let lease_generation = ledger
        .recovered
        .authority
        .last_lease_issue_generation
        .checked_add(1)
        .ok_or(ProviderLedgerError::InvalidTransition(
            "lease generation exhausted",
        ))?;
    let lease_id = derive_lease_id(
        acquisition.acquisition_id,
        lease_generation,
        observed.backend_id,
    )?;
    let requested_expiry = observed
        .observed_seconds
        .checked_add(acquisition.normalized_intent.requested_lease_seconds() as i64)
        .ok_or(ProviderLedgerError::InvalidTransition(
            "lease time overflow",
        ))?;
    let expires_seconds = requested_expiry
        .min(attempt.deadline_seconds)
        .min(attempt.current_valid_until_seconds);
    if expires_seconds <= observed.observed_seconds {
        return Err(ProviderLedgerError::BackendConflict);
    }
    let proof_digest = digest_provider_proof(&observed.proof);
    let resource_commitment = provider_resource_commitment_v1(&observed.resource, proof_digest);
    let lease = SourceExportLeaseV1::new(
        lease_id,
        attempt.request_id,
        attempt.typed_request_digest,
        acquisition.holder.authority_id(),
        acquisition.holder.authority_generation(),
        acquisition.holder.authority_digest(),
        acquisition.provider.clone(),
        observed.resource.clone(),
        observed.proof.clone(),
        acquisition.normalized_intent.binding_digest(),
        observed.observed_seconds,
        expires_seconds,
        acquisition.normalized_intent.holder_revocation_digest(),
    )?;
    observed.revalidate_physical()?;
    let descriptor_observation = observed.descriptor_observation.clone();
    let descriptor_commitment = source_root_descriptor_commitment_v1(&descriptor_observation);
    if acquisition.lease_history.len() >= crate::limits::MAXIMUM_LEASE_HISTORY_PER_ACQUISITION {
        return Err(ProviderLedgerError::LimitExceeded(
            "acquisition lease history",
        ));
    }
    session.revision =
        session
            .revision
            .checked_add(1)
            .ok_or(ProviderLedgerError::InvalidTransition(
                "session revision exhausted",
            ))?;
    session.pending_attempt_digest = None;
    session.last_completed_attempt_digest = Some(attempt.attempt_digest);
    session.next_response_sequence = session.next_response_sequence.checked_add(1).ok_or(
        ProviderLedgerError::InvalidTransition("response sequence exhausted"),
    )?;
    let mut authority = ledger.recovered.authority.clone();
    authority.revision =
        authority
            .revision
            .checked_add(1)
            .ok_or(ProviderLedgerError::InvalidTransition(
                "authority revision exhausted",
            ))?;
    authority.last_lease_issue_generation = lease_generation;
    authority.inventory_generation = authority.inventory_generation.checked_add(1).ok_or(
        ProviderLedgerError::InvalidTransition("inventory generation exhausted"),
    )?;
    let _derived_records = vec![
        (
            authority_key(authority.provider.authority_id()),
            Some(encode_authority(&authority)),
        ),
        (
            session_key(session_identity.0, session_identity.1),
            Some(encode_session(&session)),
        ),
    ];
    let committed_session_binding = session.session_binding;
    let source_root_identity = aos_sandbox_source_provider_ledger::SourceRootIdentityV1::new(
        observed.source_root.kernel_boot_id,
        observed.source_root.device,
        observed.source_root.inode,
        observed.source_root.unique_mount_id,
    )
    .map_err(crate::transaction::map_pure_ledger_error)?;
    let acquire_patch = aos_sandbox_source_provider_ledger::AcquireCompletionPatchV1::new(
        acquisition_key(&acquisition_key_value),
        attempt.attempt_digest,
        lease_generation,
        proof_digest,
        resource_commitment,
        Some(observed.evidence.encode()),
        Some(observed.reopen_identity.encode().to_vec()),
        source_root_identity,
    )
    .map_err(crate::transaction::map_pure_ledger_error)?;
    let tombstones = ledger
        .configuration
        .limits()
        .maximum_inventory_tombstones_per_holder();
    let plan = aos_sandbox_source_provider_ledger::AcquireCompletionPlanV1::new(
        attempt_key(&attempt_key_value),
        acquire_patch,
        tombstones,
    )
    .map_err(crate::transaction::map_pure_ledger_error)?;
    let receipt_facts = aos_sandbox_source_provider_security::AcquireReceiptFactsV1::new(
        acquisition.acquisition_id,
        observed.source_root.kernel_boot_id,
        observed.source_root.device,
        observed.source_root.inode,
        observed.source_root.unique_mount_id,
        proof_digest,
        descriptor_commitment,
    )?;
    let builder = custody
        .provider_outcome_facade(&ledger.journal, &permit.signing_authorization)?
        .prepare_acquire_completion(plan, lease, receipt_facts)?;
    let committed_outcome = crate::transaction::commit_sealed_completion(ledger, custody, builder)?;
    let committed_snapshot = ledger.journal.snapshot()?;
    observed.revalidate_physical()?;
    ledger
        .journal
        .validate_source_provider_authority_snapshot(&committed_snapshot)?;
    confirm_current_session_after_commit(custody, committed_session_binding)?;
    Ok(DurableProviderReplyV1 {
        response: Vec::new(),
        source_root: Some(observed.into_physical_root()),
        durability: crate::backend::DurableReplyAuthorityV1::Fresh(committed_outcome),
    })
}
