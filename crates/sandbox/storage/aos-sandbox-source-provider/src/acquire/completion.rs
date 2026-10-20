//! Durable backend-observation to Active completion ordering.

use super::*;

enum CompletedAcquire {
    Fresh(aos_sandbox_source_provider_security::CommittedProviderOutcomeV1),
    RetainedNative(ObjectDigest),
}

pub(crate) fn complete_acquire(
    ledger: &mut ProviderLedgerV1<'_>,
    permit: DurableAcquireEffectPermitV1,
    observed: ObservedBackendAcquisitionV1,
    custody: &mut CurrentProviderIngressSessionV1,
) -> Result<DurableProviderReplyV1, ProviderLedgerError> {
    // Native observations are retained by the native executor before lending
    // the current session. This generic completion never consumes that token.
    if observed.native.is_some() {
        return Err(ProviderLedgerError::Unavailable);
    }
    let committed = match complete_observed_acquire(ledger, permit, &observed, custody)? {
        CompletedAcquire::Fresh(committed) => committed,
        CompletedAcquire::RetainedNative(_) => return Err(ProviderLedgerError::Equivocation),
    };
    Ok(DurableProviderReplyV1 {
        response: Vec::new(),
        source_root: Some(observed.into_physical_root()),
        durability: crate::backend::DurableReplyAuthorityV1::Fresh(committed),
    })
}

pub(crate) fn complete_retained_native(
    ledger: &mut ProviderLedgerV1<'_>,
    permit: DurableAcquireEffectPermitV1,
    custody: &mut CurrentProviderIngressSessionV1,
) -> Result<DurableProviderReplyV1, ProviderLedgerError> {
    let observed = ledger.native_reply_custody.lend_observed()?;
    let result = (|| {
        let identity = observed
            .native
            .as_ref()
            .ok_or(ProviderLedgerError::Unavailable)?
            .reply_identity();
        ledger.native_reply_custody.require_reserved(identity)?;
        let session_binding = match complete_observed_acquire(ledger, permit, &observed, custody)? {
            CompletedAcquire::RetainedNative(binding) => binding,
            CompletedAcquire::Fresh(_) => return Err(ProviderLedgerError::Equivocation),
        };
        // Only the wire FD is duplicated, never the original live token.
        let source_root = observed.duplicate_physical_root()?;
        Ok(DurableProviderReplyV1 {
            response: Vec::new(),
            source_root: Some(source_root),
            durability: crate::backend::DurableReplyAuthorityV1::RetainedNative {
                identity,
                session_binding,
            },
        })
    })();
    ledger.native_reply_custody.restore_observed(observed);
    if result.is_err() {
        ledger.poison_runtime();
    }
    result
}

fn complete_observed_acquire(
    ledger: &mut ProviderLedgerV1<'_>,
    permit: DurableAcquireEffectPermitV1,
    observed: &ObservedBackendAcquisitionV1,
    custody: &mut CurrentProviderIngressSessionV1,
) -> Result<CompletedAcquire, ProviderLedgerError> {
    let native = match &observed.native {
        Some(native) => Some(native.completion_record(ledger, &permit)?),
        None => {
            crate::native_completion::require_original_native_custody_closed(
                ledger,
                permit.plan.acquisition_id,
            )?;
            None
        }
    };
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
    validate_backend_selection(ledger, &acquisition, &attempt, observed)?;
    observed.revalidate_physical()?;
    let session_identity = (
        acquisition.provider.authority_id(),
        acquisition.holder.authority_id(),
    );
    let session = ledger
        .recovered
        .sessions
        .get(&session_identity)
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
    require_completion_headroom(
        session.revision,
        session.next_response_sequence,
        ledger.recovered.authority.revision,
        ledger.recovered.authority.inventory_generation,
    )?;
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
    let mut plan = aos_sandbox_source_provider_ledger::AcquireCompletionPlanV1::new(
        attempt_key(&attempt_key_value),
        acquire_patch,
        tombstones,
    )
    .map_err(crate::transaction::map_pure_ledger_error)?;
    if let Some(native) = native {
        plan = plan
            .with_native_completion(native)
            .map_err(crate::transaction::map_pure_ledger_error)?;
    }
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
    observed.revalidate_physical()?;
    let completed = if observed.native.is_some() {
        // Keep the exact sealed outcome even if postcommit readback, peer or
        // physical validation fails. These checks cannot undo durable effects.
        let binding =
            crate::transaction::commit_retained_native_completion(ledger, custody, builder)?;
        CompletedAcquire::RetainedNative(binding)
    } else {
        let committed_outcome =
            crate::transaction::commit_sealed_completion(ledger, custody, builder)?;
        CompletedAcquire::Fresh(committed_outcome)
    };
    let committed_snapshot = ledger.journal.snapshot()?;
    observed.revalidate_physical()?;
    ledger
        .journal
        .validate_source_provider_authority_snapshot(&committed_snapshot)?;
    confirm_current_session_after_commit(custody, committed_session_binding)?;
    Ok(completed)
}

// These data checks precede signing. The authoritative reducers still derive
// and encode the final records; they must not be the first overflow checks
// because completion preparation signs before finalizing those records.
pub(crate) fn require_completion_headroom(
    session_revision: u64,
    response_sequence: u64,
    authority_revision: u64,
    inventory_generation: u64,
) -> Result<(), ProviderLedgerError> {
    session_revision
        .checked_add(1)
        .ok_or(ProviderLedgerError::InvalidTransition(
            "session revision exhausted",
        ))?;
    response_sequence
        .checked_add(1)
        .ok_or(ProviderLedgerError::InvalidTransition(
            "response sequence exhausted",
        ))?;
    authority_revision
        .checked_add(1)
        .ok_or(ProviderLedgerError::InvalidTransition(
            "authority revision exhausted",
        ))?;
    inventory_generation
        .checked_add(1)
        .ok_or(ProviderLedgerError::InvalidTransition(
            "inventory generation exhausted",
        ))?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::{ProviderLedgerError, require_completion_headroom};

    // These pure data tests exercise no ingress or signer. A genuine completion
    // fixture is still required to qualify live signing order.
    #[test]
    fn completion_headroom_preserves_each_overflow_error() {
        let cases = [
            ([u64::MAX, 0, 0, 0], "session revision exhausted"),
            ([0, u64::MAX, 0, 0], "response sequence exhausted"),
            ([0, 0, u64::MAX, 0], "authority revision exhausted"),
            ([0, 0, 0, u64::MAX], "inventory generation exhausted"),
        ];

        for ([session, response, authority, inventory], expected) in cases {
            let result = require_completion_headroom(session, response, authority, inventory);

            assert!(matches!(
                result,
                Err(ProviderLedgerError::InvalidTransition(message)) if message == expected
            ));
        }
    }

    #[test]
    fn completion_headroom_preserves_first_overflow_order() {
        let cases = [
            ([u64::MAX; 4], "session revision exhausted"),
            (
                [0, u64::MAX, u64::MAX, u64::MAX],
                "response sequence exhausted",
            ),
            ([0, 0, u64::MAX, u64::MAX], "authority revision exhausted"),
        ];

        for ([session, response, authority, inventory], expected) in cases {
            let result = require_completion_headroom(session, response, authority, inventory);

            assert!(matches!(
                result,
                Err(ProviderLedgerError::InvalidTransition(message)) if message == expected
            ));
        }
    }

    #[test]
    fn completion_headroom_accepts_inclusive_increment_boundary() {
        let last_available = u64::MAX - 1;

        let boundary = require_completion_headroom(
            last_available,
            last_available,
            last_available,
            last_available,
        );

        assert!(boundary.is_ok());
        assert!(require_completion_headroom(0, 0, 0, 0).is_ok());
    }
}
