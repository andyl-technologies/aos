//! Independently funded Release reservation beside an immutable Root archive.
//!
//! This checks complete canonical graphs and the existing BeginRelease owner
//! transaction. It provides DATA only: no descriptor, signing, physical release,
//! current Session, opened capacity, or protected writer can be reconstructed.

use std::collections::BTreeMap;

use super::{RootNativeHeldGraphV2, original_root_remaining_v5};
use crate::mount_source_acquisition_state::{
    AcquisitionRecoveryV2, MutationTagV2, ProviderAttemptStateV2, ProviderIntentV2,
    ProviderMethodV2, ProviderQueryOwnerV2, QueryLineageV2, RecordRefV2, Result,
    SourceAcquisitionPhaseV2, StoredRecordV2, encode_mount_source_state_record_v2,
    seal_record, transaction_id,
    format::state_error,
};

/// Describes exact canonical replacements without granting Release authority.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct OriginalReleaseTransitionV1 {
    /// The genuine retained original Root attempt.
    pub root_attempt: [u8; 32],
    /// The distinct fresh Release attempt.
    pub release_attempt: [u8; 32],
    /// The deterministic existing BeginRelease transaction identity.
    pub transaction_id: [u8; 16],
    /// Exactly the new attempt, acquisition and current Head replacements.
    pub puts: BTreeMap<Vec<u8>, Vec<u8>>,
}

/// Validates a fresh ordinary Release while preserving the entire native cut.
///
/// # Errors
///
/// Rejects an unterminated original, a changed archive or unrelated owner,
/// missing Complete evidence, another current Session, pending traffic,
/// nonfresh Release lineage, altered custody or a different transaction ID.
pub fn validate_original_release_transition_v1(
    before: &RootNativeHeldGraphV2,
    after: &RootNativeHeldGraphV2,
    root_attempt: [u8; 32],
    release_attempt: [u8; 32],
    supplied_transaction: [u8; 16],
) -> Result<OriginalReleaseTransitionV1> {
    super::original_v5::require_original_release_cut_v1(before, root_attempt)?;
    super::original_v5::require_original_release_cut_v1(after, root_attempt)?;
    if root_attempt == release_attempt || before.legacy.provider_attempts.contains_key(&release_attempt) {
        return Err(state_error("original Release attempt is not fresh"));
    }
    let original = before.legacy.provider_attempts.get(&root_attempt)
        .ok_or_else(|| state_error("original Release Root attempt absent"))?;
    let acquisition_id = original.owner.owner_id();
    let old = before.legacy.acquisitions.get(&acquisition_id)
        .ok_or_else(|| state_error("original Release acquisition absent"))?;
    let next = after.legacy.acquisitions.get(&acquisition_id)
        .ok_or_else(|| state_error("original Release successor acquisition absent"))?;
    let query = after.legacy.provider_attempts.get(&release_attempt)
        .ok_or_else(|| state_error("original Release successor attempt absent"))?;
    let identity = (old.scope.holder_authority_id, old.scope.provider_authority_id);
    let head = before.legacy.provider_heads.get(&identity)
        .ok_or_else(|| state_error("original Release current Head absent"))?;
    let session = before.legacy.provider_sessions.get(&head.current_session_id)
        .ok_or_else(|| state_error("original Release current Session absent"))?;
    let ProviderIntentV2::Release { value: intent } = &query.intent else {
        return Err(state_error("original Release intent kind"));
    };
    let reference = RecordRefV2 {
        id: query.attempt_id,
        revision: query.revision,
        record_digest: query.record_digest,
    };
    let predecessor_phase = if old.phase == SourceAcquisitionPhaseV2::Faulted {
        old.faulted_from.ok_or_else(|| state_error("original Release fault origin absent"))?
    } else {
        old.phase
    };
    if old.evidence.is_none() || old.release.is_some()
        || old.recovery != AcquisitionRecoveryV2::Ready
        || head.pending_attempt.is_some() || head.recovery_barrier.is_some()
        || head.next_request_sequence != head.next_response_sequence
        || !matches!(predecessor_phase, SourceAcquisitionPhaseV2::PendingQuery
            | SourceAcquisitionPhaseV2::DescriptorCustodied | SourceAcquisitionPhaseV2::Active
            | SourceAcquisitionPhaseV2::Consumed)
        || query.revision != 1 || query.attempt_number != 1
        || query.previous_attempt_id.is_some() || query.lineage_root_attempt_id != release_attempt
        || query.method != ProviderMethodV2::Release
        || query.owner != (ProviderQueryOwnerV2::Release { acquisition_id })
        || query.state != ProviderAttemptStateV2::Reserved
        || query.scope != old.scope || session.scope != old.scope
        || query.session_id != head.current_session_id
        || query.session_record_digest != head.current_session_record_digest
        || session.record_digest != head.current_session_record_digest
        || query.request_sequence != head.next_request_sequence
        || query.owner_predecessor_revision != old.revision
        || query.owner_predecessor_digest != old.record_digest
        || intent.acquisition_id != acquisition_id || intent.provider_acquisition != old.provider_acquisition
    {
        return Err(state_error("original Release current owner/sequence/CAS mismatch"));
    }

    let mut expected_row = old.clone();
    expected_row.revision = old.revision.checked_add(1)
        .ok_or_else(|| state_error("original Release acquisition revision exhausted"))?;
    expected_row.phase = SourceAcquisitionPhaseV2::Releasing;
    expected_row.release = Some(intent.mount_operation);
    expected_row.mount_release_request = Some(intent.mount_request.clone());
    expected_row.release_authority = Some(intent.authority);
    expected_row.release_from_phase = Some(predecessor_phase);
    expected_row.release_intent_digest = Some(query.immutable_intent_digest);
    expected_row.release_lineage = Some(QueryLineageV2 {
        root: reference, tail: reference, next_attempt_number: 2,
    });
    expected_row.release_inventory_fence = next.release_inventory_fence.clone();
    if old.phase == SourceAcquisitionPhaseV2::Faulted {
        expected_row.retained_faulted_from = old.faulted_from;
        expected_row.retained_fault_digest = old.fault_digest;
        expected_row.faulted_from = None;
        expected_row.fault_digest = None;
    }
    expected_row.record_digest = [0; 32];
    let StoredRecordV2::Acquisition { value: expected_row } = seal_record(
        StoredRecordV2::Acquisition { value: expected_row },
    )? else {
        return Err(state_error("original Release acquisition sealing kind"));
    };
    if &expected_row != next {
        return Err(state_error("original Release changed original custody/companions"));
    }
    let fence = next.release_inventory_fence.as_ref()
        .ok_or_else(|| state_error("original Release inventory fence absent"))?;
    if fence.inventory_observation_floor != head.inventory_observation_ordinal
        || fence.projection_epoch != head.current_projection_epoch.checked_add(1)
            .ok_or_else(|| state_error("original Release projection epoch exhausted"))?
    {
        return Err(state_error("original Release inventory fence predecessor"));
    }
    let next_head_revision = head.revision.checked_add(1)
        .ok_or_else(|| state_error("original Release Head revision exhausted"))?;
    let mut next_head = head.clone();
    next_head.revision = next_head_revision;
    next_head.next_request_sequence = head.next_request_sequence.checked_add(1)
        .ok_or_else(|| state_error("original Release request sequence exhausted"))?;
    next_head.pending_attempt = Some(reference);
    next_head.current_projection_epoch = fence.projection_epoch;
    next_head.current_projection_digest = fence.projection_digest;
    next_head.last_reconciliation = None;
    next_head.record_digest = [0; 32];
    let expected = BTreeMap::from([
        encode_mount_source_state_record_v2(&StoredRecordV2::ProviderQueryAttempt { value: query.clone() })?,
        encode_mount_source_state_record_v2(&StoredRecordV2::Acquisition { value: next.clone() })?,
        encode_mount_source_state_record_v2(&seal_record(StoredRecordV2::ProviderHead { value: next_head })?)?,
    ]);
    let transaction = transaction_id(MutationTagV2::BeginRelease, identity.0, identity.1,
        before.legacy.holder_sequences.get(&identity.0).map_or(0, |row| row.revision),
        next_head_revision, Some(acquisition_id), Some(next.revision),
        Some(release_attempt), Some(query.revision), None);
    if supplied_transaction == [0; 16] || supplied_transaction != transaction
        || before.canonical.keys().any(|key| !after.canonical.contains_key(key))
        || after.canonical.iter().filter(|(key, value)| before.canonical.get(*key) != Some(*value))
            .map(|(key, value)| (key.clone(), value.clone())).collect::<BTreeMap<_, _>>() != expected
        || original_root_remaining_v5(before, root_attempt)? != 0
    {
        return Err(state_error("original Release transaction or exact canonical replacements"));
    }
    Ok(OriginalReleaseTransitionV1 {
        root_attempt, release_attempt, transaction_id: transaction, puts: expected,
    })
}

/// Checks exact Pending Release consumption beside the same terminal original.
///
/// This compares canonical DATA only. The shared completed-Head arithmetic and
/// full graph validator remain the sole projection and signature validators.
///
/// # Errors
///
/// Rejects any archive/custody change, non-Pending result, changed immutable
/// request, wrong lineage, unrelated mutation or different transaction identity.
pub fn validate_original_release_status_transition_v1(
    before: &RootNativeHeldGraphV2,
    after: &RootNativeHeldGraphV2,
    root: [u8; 32],
    release: [u8; 32],
    supplied_transaction: [u8; 16],
) -> Result<OriginalReleaseTransitionV1> {
    use crate::mount_source_acquisition_state::{
        ProviderStatusV2, derive_provider_completed_head_v2,
    };

    super::original_v5::require_original_release_cut_v1(before, root)?;
    super::original_v5::require_original_release_cut_v1(after, root)?;
    let old = before.legacy.provider_attempts.get(&release)
        .ok_or_else(|| state_error("original Release status predecessor absent"))?;
    let next = after.legacy.provider_attempts.get(&release)
        .ok_or_else(|| state_error("original Release status successor absent"))?;
    let ProviderAttemptStateV2::DispositionConsumed {
        status: ProviderStatusV2::Pending, ..
    } = &next.state else {
        return Err(state_error("original Release status is not consumed Pending"));
    };
    if old.method != ProviderMethodV2::Release || old.state != ProviderAttemptStateV2::Reserved
        || old.revision != 1 || next.revision != 2
    {
        return Err(state_error("original Release status predecessor state"));
    }
    let mut expected_attempt = old.clone();
    expected_attempt.revision = 2;
    expected_attempt.state = next.state.clone();
    expected_attempt.record_digest = [0; 32];
    let StoredRecordV2::ProviderQueryAttempt { value: expected_attempt } = seal_record(
        StoredRecordV2::ProviderQueryAttempt { value: expected_attempt },
    )? else {
        return Err(state_error("original Release status attempt sealing kind"));
    };
    if &expected_attempt != next {
        return Err(state_error("original Release status changed immutable request"));
    }

    let acquisition = old.owner.owner_id();
    let row = before.legacy.acquisitions.get(&acquisition)
        .ok_or_else(|| state_error("original Release status acquisition absent"))?;
    let next_row = after.legacy.acquisitions.get(&acquisition)
        .ok_or_else(|| state_error("original Release status next acquisition absent"))?;
    let identity = (row.scope.holder_authority_id, row.scope.provider_authority_id);
    let head = before.legacy.provider_heads.get(&identity)
        .ok_or_else(|| state_error("original Release status Head absent"))?;
    let old_ref = RecordRefV2 { id: release, revision: old.revision, record_digest: old.record_digest };
    let next_ref = RecordRefV2 { id: release, revision: next.revision, record_digest: next.record_digest };
    if row.phase != SourceAcquisitionPhaseV2::Releasing
        || row.acquire_lineage.root.id != root
        || head.pending_attempt != Some(old_ref)
        || row.release_lineage.as_ref().is_none_or(|lineage| lineage.tail != old_ref)
    {
        return Err(state_error("original Release status current lineage"));
    }
    let mut expected_row = row.clone();
    expected_row.revision = row.revision.checked_add(1)
        .ok_or_else(|| state_error("original Release status acquisition revision exhausted"))?;
    let lineage = expected_row.release_lineage.as_mut()
        .ok_or_else(|| state_error("original Release status lineage absent"))?;
    lineage.tail = next_ref;
    if lineage.root == old_ref { lineage.root = next_ref; }
    expected_row.record_digest = [0; 32];
    let StoredRecordV2::Acquisition { value: expected_row } = seal_record(
        StoredRecordV2::Acquisition { value: expected_row },
    )? else {
        return Err(state_error("original Release status acquisition sealing kind"));
    };
    if &expected_row != next_row {
        return Err(state_error("original Release status changed physical custody"));
    }
    let expected_head = derive_provider_completed_head_v2(
        head, &before.legacy.acquisitions, &after.legacy.acquisitions,
    ).map_err(|_| state_error("original Release status Head successor"))?;
    let expected = BTreeMap::from([
        encode_mount_source_state_record_v2(&StoredRecordV2::ProviderQueryAttempt { value: next.clone() })?,
        encode_mount_source_state_record_v2(&StoredRecordV2::Acquisition { value: next_row.clone() })?,
        encode_mount_source_state_record_v2(&seal_record(StoredRecordV2::ProviderHead { value: expected_head.clone() })?)?,
    ]);
    let transaction = transaction_id(MutationTagV2::ConsumeOutcome, identity.0, identity.1,
        before.legacy.holder_sequences.get(&identity.0).map_or(0, |row| row.revision),
        expected_head.revision, Some(acquisition), Some(next_row.revision),
        Some(release), Some(next.revision), None);
    if supplied_transaction == [0; 16] || supplied_transaction != transaction
        || before.canonical.keys().any(|key| !after.canonical.contains_key(key))
        || after.canonical.iter().filter(|(key, value)| before.canonical.get(*key) != Some(*value))
            .map(|(key, value)| (key.clone(), value.clone())).collect::<BTreeMap<_, _>>() != expected
        || original_root_remaining_v5(before, root)? != 0
    {
        return Err(state_error("original Release status exact canonical replacements"));
    }
    Ok(OriginalReleaseTransitionV1 {
        root_attempt: root, release_attempt: release, transaction_id: transaction, puts: expected,
    })
}
