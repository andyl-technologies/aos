//! Compares the original Mount cleanup graph under a retained Git denial.
//!
//! These canonical graph predicates interpret DATA only. Native Mount custody,
//! actual admission, payment and physical posts remain with their real owners.

use aos_sandbox_core::RecordNamespace;
use aos_sandbox_protocol::domain_ledger::transaction::JournalTransaction;
use aos_sandbox_broker::canonical_journal::CanonicalJournalMechanicalErrorV1 as JournalError;

/// Compares the complete original graph before admitting negative cleanup.
///
/// The existing opt-in denial cannot create an acquisition, mutate immutable
/// bindings or turn a historical record into a native or retry permission.
/// # Errors
/// Rejects altered, deleted, introduced or malformed ownership and attempt rows.
pub fn require_mount_original_source_cleanup_v1(
    state: &std::collections::BTreeMap<(RecordNamespace, Vec<u8>), Vec<u8>>,
    transaction: &JournalTransaction,
) -> Result<(), JournalError> {
    use aos_sandbox_protocol::mount_source_acquisition_state::{
        ProviderMethodV2, ProviderQueryOwnerV2, SourceAcquisitionPhaseV2,
        native_held_completion::{
            validate_native_root_cold_transition_v2, validate_native_root_graph_v2,
        },
    };

    let mut prospective: std::collections::BTreeMap<&[u8], &[u8]> = state.iter()
        .filter(|((namespace, _), _)| {
            *namespace == RecordNamespace::MountSourceAcquisition
        })
        .map(|((_, key), value)| (key.as_slice(), value.as_slice()))
        .collect();
    let before = validate_native_root_graph_v2(
        prospective.iter().map(|(key, value)| (*key, *value)),
    ).map_err(|_| JournalError::ProtectedBoundary)?;

    for record in transaction.records().iter().filter(|record| {
        record.namespace() == RecordNamespace::MountSourceAcquisition
    }) {
        let value = record.value().ok_or(JournalError::ProtectedBoundary)?;
        prospective.insert(record.key(), value);
    }
    let after = validate_native_root_graph_v2(
        prospective.iter().map(|(key, value)| (*key, *value)),
    ).map_err(|_| JournalError::ProtectedBoundary)?;
    let original = before.legacy();
    let next = after.legacy();

    if original.holder_sequences != next.holder_sequences
        || original.acquisitions.len() != next.acquisitions.len()
        || original.provider_heads.len() != next.provider_heads.len()
        || before.v1_sidecars() != after.v1_sidecars()
    {
        return Err(JournalError::ProtectedBoundary);
    }
    for (id, row) in &next.acquisitions {
        let old = original.acquisitions.get(id)
            .ok_or(JournalError::ProtectedBoundary)?;
        if !preserves_source_acquisition_v1(old, row)
            || (row.phase != old.phase && !matches!(row.phase,
                SourceAcquisitionPhaseV2::Releasing
                    | SourceAcquisitionPhaseV2::Released
                    | SourceAcquisitionPhaseV2::Faulted))
        {
            return Err(JournalError::ProtectedBoundary);
        }
    }
    for scope in next.provider_heads.keys() {
        if !original.provider_heads.contains_key(scope) {
            return Err(JournalError::ProtectedBoundary);
        }
    }
    for (id, session) in &next.provider_sessions {
        if let Some(old) = original.provider_sessions.get(id) {
            if old != session {
                return Err(JournalError::ProtectedBoundary);
            }
        } else if !original.provider_heads.contains_key(&(
            session.scope.holder_authority_id,
            session.scope.provider_authority_id,
        )) {
            return Err(JournalError::ProtectedBoundary);
        }
    }
    for (id, attempt) in &next.provider_attempts {
        if let Some(old) = original.provider_attempts.get(id) {
            if !preserves_source_attempt_v1(old, attempt) {
                return Err(JournalError::ProtectedBoundary);
            }
            continue;
        }
        match (attempt.method, attempt.owner) {
            (ProviderMethodV2::Release, ProviderQueryOwnerV2::Release { acquisition_id })
                if original.acquisitions.get(&acquisition_id)
                    .is_some_and(|row| row.scope == attempt.scope) => {}
            (ProviderMethodV2::Inventory, ProviderQueryOwnerV2::Inventory)
                if original.provider_heads.contains_key(&(
                    attempt.scope.holder_authority_id,
                    attempt.scope.provider_authority_id,
                )) => {}
            _ => return Err(JournalError::ProtectedBoundary),
        }
    }

    for (attempt, sidecar) in after.sidecars() {
        if before.sidecars().get(attempt) == Some(sidecar) {
            continue;
        }
        if !original.provider_attempts.contains_key(attempt)
            || before.sidecars().get(attempt).is_some_and(|old| {
                old.original_scope() != sidecar.original_scope()
            })
        {
            return Err(JournalError::ProtectedBoundary);
        }
        // The existing closed cold reducer rejects hot preparation, receive,
        // CAS and Accepted, while retaining genuine intermediate cleanup.
        validate_native_root_cold_transition_v2(
            &before, &after, *attempt, *transaction.id(),
        ).map_err(|_| JournalError::ProtectedBoundary)?;
    }
    Ok(())
}

fn preserves_source_acquisition_v1(
    old: &aos_sandbox_protocol::mount_source_acquisition_state::SourceAcquisitionRowV2,
    next: &aos_sandbox_protocol::mount_source_acquisition_state::SourceAcquisitionRowV2,
) -> bool {
    old.acquisition_id == next.acquisition_id
        && old.provider_acquisition == next.provider_acquisition
        && old.scope == next.scope
        && old.acquire == next.acquire
        && old.mount_acquire_request == next.mount_acquire_request
        && old.acquire_intent_digest == next.acquire_intent_digest
        && old.acquire_lineage == next.acquire_lineage
        && old.assignment == next.assignment
        && old.prospective_mount_template == next.prospective_mount_template
        && old.prospective_mount_template_digest == next.prospective_mount_template_digest
        && old.source_binding == next.source_binding
        && old.source_binding_digest == next.source_binding_digest
        && old.mount_plan_digest == next.mount_plan_digest
        && old.ownership_lease_digest == next.ownership_lease_digest
        && old.manager_custody == next.manager_custody
        && old.descriptor_custody_digest == next.descriptor_custody_digest
        && old.positive_custody_digest == next.positive_custody_digest
        && old.consumption == next.consumption
}

fn preserves_source_attempt_v1(
    old: &aos_sandbox_protocol::mount_source_acquisition_state::SourceProviderQueryAttemptV2,
    next: &aos_sandbox_protocol::mount_source_acquisition_state::SourceProviderQueryAttemptV2,
) -> bool {
    old.attempt_id == next.attempt_id
        && old.scope == next.scope
        && old.method == next.method
        && old.owner == next.owner
        && old.intent == next.intent
        && old.provider_acquisition == next.provider_acquisition
        && old.immutable_intent_digest == next.immutable_intent_digest
        && old.lineage_root_attempt_id == next.lineage_root_attempt_id
        && old.previous_attempt_id == next.previous_attempt_id
        && old.attempt_number == next.attempt_number
        && old.session_id == next.session_id
        && old.session_record_digest == next.session_record_digest
        && old.signer_set_commitment == next.signer_set_commitment
        && old.trust_digest == next.trust_digest
        && old.revocation_digest == next.revocation_digest
        && old.route_digest == next.route_digest
        && old.process_execution_digest == next.process_execution_digest
        && old.normalized_acquire_intent == next.normalized_acquire_intent
        && old.acquire_verification_floor == next.acquire_verification_floor
        && old.inventory_correlations == next.inventory_correlations
        && old.request_id == next.request_id
        && old.request_sequence == next.request_sequence
        && old.signed_request == next.signed_request
        && old.signed_request_digest == next.signed_request_digest
        && old.owner_predecessor_revision == next.owner_predecessor_revision
        && old.owner_predecessor_digest == next.owner_predecessor_digest
        && old.owner_predecessor == next.owner_predecessor
}
