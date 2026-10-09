//! Exact original reservation mutations in the single native phase0 admission.
//!
//! This check shares the complete legacy graph validator with later transitions.
//! It returns concrete original identities for the separate namespace46 capacity
//! adapter; neither these identities nor canonical proposals grant admission.

use std::collections::BTreeMap;

use aos_sandbox_core::ObjectDigest;

use super::graph::original_rows;
use super::{RootNativeHeldGraphV1, RootNativeHeldSidecarV1, native_root_sidecar_key_v1};
use crate::mount_source_acquisition_state::{
    AcquisitionRecoveryV2, HolderSequenceV2, MountOperationV2, ProviderAttemptStateV2,
    QueryLineageV2, RecordRefV2, Result, SourceProviderHeadV2, StoredRecordV2, acquisition_key,
    format::state_error, holder_sequence_key, projection_entries, projection_from_entries,
    provider_attempt_key, provider_head_key, provider_session_key, record_digest,
};

/// Binds concrete phase0 reservation data to the separately framed capacity row.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct RootNativeAdmissionBindingV1 {
    /// Names the original Mount operation and its canonical request digest.
    pub mount_operation: MountOperationV2,
    /// Names the fresh immutable Mount Acquire attempt.
    pub mount_attempt: [u8; 32],
    /// Names the actual signed original provider request identity.
    pub provider_request_id: [u8; 16],
    /// Commits the complete original signed provider Acquire request.
    pub signed_request_digest: [u8; 32],
    /// Commits the sealed original Reserved attempt checkpoint.
    pub reserved_attempt_digest: [u8; 32],
    /// Commits the exact reserved provider head checkpoint.
    pub reserved_head_digest: [u8; 32],
    /// Commits the exact unsigned Root1 including its original fixed signer.
    pub prepared_root_digest: ObjectDigest,
    /// Names the actual canonical retained session row.
    pub session_id: [u8; 32],
    /// Names the holder-scoped provider acquisition, not a caller-chosen scope.
    pub provider_acquisition: [u8; 32],
    /// Names the native flight used by the sidecar and capacity reservation.
    pub flight: ObjectDigest,
}

pub(super) fn validate_admission(
    before: &RootNativeHeldGraphV1,
    after: &RootNativeHeldGraphV1,
    sidecar: &RootNativeHeldSidecarV1,
    puts: &BTreeMap<Vec<u8>, Vec<u8>>,
) -> Result<RootNativeAdmissionBindingV1> {
    let (attempt, session) = original_rows(after, sidecar)?;
    let acquisition_id = attempt.owner.owner_id();
    if before
        .legacy
        .provider_attempts
        .contains_key(&attempt.attempt_id)
        || before.legacy.acquisitions.contains_key(&acquisition_id)
        || attempt.revision != 1
        || attempt.attempt_number != 1
        || attempt.previous_attempt_id.is_some()
        || attempt.lineage_root_attempt_id != attempt.attempt_id
        || attempt.owner_predecessor.is_some()
        || attempt.owner_predecessor_revision != 0
        || attempt.owner_predecessor_digest != [0; 32]
        || !matches!(attempt.state, ProviderAttemptStateV2::Reserved)
    {
        return Err(state_error(
            "native Root admission requires genuinely fresh original reservation",
        ));
    }
    let row = after
        .legacy
        .acquisitions
        .get(&acquisition_id)
        .ok_or_else(|| state_error("native Root admission acquisition absent"))?;
    let reference = RecordRefV2 {
        id: attempt.attempt_id,
        revision: attempt.revision,
        record_digest: attempt.record_digest,
    };
    if row.revision != 1
        || row.acquire_lineage
            != (QueryLineageV2 {
                root: reference,
                tail: reference,
                next_attempt_number: 2,
            })
        || row.acquire_terminal_attempt.is_some()
        || row.evidence.is_some()
        || row.release.is_some()
        || row.mount_release_request.is_some()
        || row.release_authority.is_some()
        || row.release_from_phase.is_some()
        || row.release_intent_digest.is_some()
        || row.release_lineage.is_some()
        || row.release_terminal_attempt.is_some()
        || row.release_inventory_fence.is_some()
        || row.manager_custody.is_some()
        || row.manager_custody_loss.is_some()
        || row.descriptor_custody_digest.is_some()
        || row.positive_custody_digest.is_some()
        || row.consumption.is_some()
        || row.release_proof.is_some()
        || row.negative_custody_digest.is_some()
        || row.faulted_from.is_some()
        || row.fault_digest.is_some()
        || row.retained_faulted_from.is_some()
        || row.retained_fault_digest.is_some()
        || row.recovery != AcquisitionRecoveryV2::Ready
    {
        return Err(state_error(
            "native Root admission changed exact initial acquisition shape",
        ));
    }
    // The unchanged legacy graph independently checks the MountOperation,
    // canonical historical Mount request, intent and original signature joins.
    let provider_acquisition = attempt
        .provider_acquisition
        .ok_or_else(|| state_error("native Root admission provider acquisition absent"))?;
    let previous_holder = before
        .legacy
        .holder_sequences
        .get(&session.scope.holder_authority_id);
    let sequence = previous_holder.map_or(1, |holder| holder.next_acquisition_sequence);
    if sequence != provider_acquisition.acquisition_sequence {
        return Err(state_error(
            "native Root admission did not allocate actual holder sequence",
        ));
    }
    let mut expected_holder = HolderSequenceV2 {
        revision: previous_holder.map_or(Ok(1), |holder| {
            holder
                .revision
                .checked_add(1)
                .ok_or_else(|| state_error("native Root holder revision overflow"))
        })?,
        holder_authority_id: session.scope.holder_authority_id,
        last_allocated_acquisition_sequence: sequence,
        next_acquisition_sequence: sequence
            .checked_add(1)
            .ok_or_else(|| state_error("native Root holder sequence overflow"))?,
        record_digest: [0; 32],
    };
    expected_holder.record_digest = record_digest(&StoredRecordV2::HolderSequence {
        value: expected_holder.clone(),
    })?;
    if after
        .legacy
        .holder_sequences
        .get(&session.scope.holder_authority_id)
        != Some(&expected_holder)
    {
        return Err(state_error("native Root admission exact holder successor"));
    }

    let head_id = (
        session.scope.holder_authority_id,
        session.scope.provider_authority_id,
    );
    let previous_head = before.legacy.provider_heads.get(&head_id);
    let mut expected_head = if let Some(head) = previous_head {
        if head.pending_attempt.is_some()
            || head.recovery_barrier.is_some()
            || head.next_request_sequence != head.next_response_sequence
            || head.current_session_id != session.session_id
            || head.current_session_record_digest != session.record_digest
            || attempt.request_sequence != head.next_request_sequence
        {
            return Err(state_error("native Root admission exact current idle head"));
        }
        let mut next = head.clone();
        next.revision = head
            .revision
            .checked_add(1)
            .ok_or_else(|| state_error("native Root admission head revision overflow"))?;
        next.next_request_sequence = head
            .next_request_sequence
            .checked_add(1)
            .ok_or_else(|| state_error("native Root admission request sequence overflow"))?;
        next.pending_attempt = Some(reference);
        next.current_projection_epoch = head
            .current_projection_epoch
            .checked_add(1)
            .ok_or_else(|| state_error("native Root admission projection overflow"))?;
        next.current_projection_digest = projection_from_entries(
            head.scope,
            next.current_projection_epoch,
            &projection_entries(head.scope, &after.legacy.acquisitions),
        )?
        .digest;
        next.last_reconciliation = None;
        next
    } else {
        if attempt.request_sequence != 1
            || session.revision != 1
            || session.predecessor_session_id.is_some()
            || session.barrier_idle_replacement.is_some()
        {
            return Err(state_error(
                "native Root admission exact initial session/head",
            ));
        }
        let projection = projection_from_entries(
            session.scope,
            1,
            &projection_entries(session.scope, &after.legacy.acquisitions),
        )?;
        SourceProviderHeadV2 {
            revision: 1,
            scope: session.scope,
            holder_authority_generation: session.root_mount_authority_generation,
            holder_authority_digest: session.root_mount_authority_digest,
            provider_authority_generation: session.provider_authority_generation,
            provider_authority_digest: session.provider_authority_digest,
            current_session_id: session.session_id,
            current_session_record_digest: session.record_digest,
            next_request_sequence: 2,
            next_response_sequence: 1,
            pending_attempt: Some(reference),
            inventory_observation_ordinal: 0,
            inventory_floor: None,
            last_inventory_attempt: None,
            current_projection_epoch: projection.epoch,
            current_projection_digest: projection.digest,
            last_reconciliation: None,
            recovery_barrier: None,
            record_digest: [0; 32],
        }
    };
    expected_head.record_digest = record_digest(&StoredRecordV2::ProviderHead {
        value: expected_head.clone(),
    })?;
    if after.legacy.provider_heads.get(&head_id) != Some(&expected_head) {
        return Err(state_error(
            "native Root admission exact reserved head successor",
        ));
    }

    let mut keys = vec![
        native_root_sidecar_key_v1(attempt.attempt_id)?,
        provider_attempt_key(attempt.attempt_id),
        acquisition_key(acquisition_id),
        provider_head_key(head_id.0, head_id.1),
        holder_sequence_key(head_id.0),
    ];
    match before.legacy.provider_sessions.get(&session.session_id) {
        Some(previous) if previous == session => {}
        None if previous_head.is_none() => keys.push(provider_session_key(session.session_id)),
        _ => {
            return Err(state_error(
                "native Root admission rewrote original session",
            ));
        }
    }
    if puts.len() != keys.len() || keys.iter().any(|key| !puts.contains_key(key)) {
        return Err(state_error(
            "native Root admission exact atomic reservation and sidecar keys",
        ));
    }
    Ok(RootNativeAdmissionBindingV1 {
        mount_operation: row.acquire,
        mount_attempt: attempt.attempt_id,
        provider_request_id: attempt.request_id,
        signed_request_digest: attempt.signed_request_digest,
        reserved_attempt_digest: attempt.record_digest,
        reserved_head_digest: expected_head.record_digest,
        prepared_root_digest: sidecar
            .suffix
            .prepared()
            .ok_or_else(|| state_error("native Root admission preparation absent"))?
            .digest(),
        session_id: session.session_id,
        provider_acquisition: provider_acquisition.acquisition_id,
        flight: sidecar.original_scope.flight,
    })
}
