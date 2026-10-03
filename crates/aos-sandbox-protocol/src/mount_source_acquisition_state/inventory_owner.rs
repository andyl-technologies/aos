//! Unsealed provider Head successors shared by the existing Inventory owners.
//!
//! These arithmetic results are plain DATA. Callers retain their own sealing,
//! full graph validation, protected signing and atomic commit obligations.

use std::collections::BTreeMap;

use aos_sandbox_source_provider_protocol::{SignedSourceProviderInventoryV1, digest_inventory};

use super::{
    InventoryFloorV2, MountSourceAcquisitionStateError, ProviderAttemptStateV2, ProviderStatusV2,
    RecordRefV2, SourceAcquisitionRowV2, SourceProviderHeadV2, SourceProviderQueryAttemptV2,
    SourceProviderSessionV2, projection_entries, projection_from_entries, reproduce_reconciliation,
};

/// Preserves whether a successor failed local arithmetic or canonical validation.
#[doc(hidden)]
#[derive(Clone, Debug, Eq, PartialEq, thiserror::Error)]
pub enum InventoryOwnerDerivationErrorV2 {
    /// An existing owner invariant failed with its original static reason.
    #[error("{0}")]
    Invariant(&'static str),
    /// An existing canonical projection or reconciliation check failed.
    #[error(transparent)]
    Canonical(#[from] MountSourceAcquisitionStateError),
}

use InventoryOwnerDerivationErrorV2::Invariant;

/// Derives the unsealed response Head for an existing provider owner.
///
/// Acquisition and Release owners also use this exact projection arithmetic.
/// The result does not establish currentness or authorize a commit.
///
/// # Errors
///
/// Returns the original response, revision or projection overflow reason,
/// unreachable response reason, or canonical projection error.
#[doc(hidden)]
pub fn derive_provider_completed_head_v2(
    current: &SourceProviderHeadV2,
    current_rows: &BTreeMap<[u8; 32], SourceAcquisitionRowV2>,
    next_rows: &BTreeMap<[u8; 32], SourceAcquisitionRowV2>,
) -> std::result::Result<SourceProviderHeadV2, InventoryOwnerDerivationErrorV2> {
    let next_response_sequence = current
        .next_response_sequence
        .checked_add(1)
        .ok_or(Invariant("SourceProvider response sequence is exhausted"))?;
    if current.pending_attempt.is_none() || next_response_sequence != current.next_request_sequence
    {
        return Err(Invariant("SourceProvider response head is not reachable"));
    }

    let current_entries = projection_entries(current.scope, current_rows);
    let next_entries = projection_entries(current.scope, next_rows);
    let mut next = current.clone();
    next.revision = next_revision(current.revision)?;
    next.next_response_sequence = next_response_sequence;
    next.pending_attempt = None;
    if current_entries != next_entries {
        let epoch = current
            .current_projection_epoch
            .checked_add(1)
            .ok_or(Invariant("SourceProvider projection epoch is exhausted"))?;
        let projection = projection_from_entries(current.scope, epoch, &next_entries)?;
        next.current_projection_epoch = epoch;
        next.current_projection_digest = projection.digest;
        next.last_reconciliation = None;
    }
    next.record_digest = [0; 32];
    Ok(next)
}

/// Derives the unsealed Head after an Inventory Attempt has been sealed.
///
/// The supplied reference is DATA, not proof of request signing or reservation.
///
/// # Errors
///
/// Returns the original record revision or request sequence overflow reason.
#[doc(hidden)]
pub fn derive_inventory_reservation_head_v2(
    current: &SourceProviderHeadV2,
    pending: RecordRefV2,
) -> std::result::Result<SourceProviderHeadV2, InventoryOwnerDerivationErrorV2> {
    let mut next_head = current.clone();
    next_head.revision = next_revision(current.revision)?;
    next_head.next_request_sequence = current
        .next_request_sequence
        .checked_add(1)
        .ok_or(Invariant("provider request sequence is exhausted"))?;
    next_head.pending_attempt = Some(pending);
    next_head.record_digest = [0; 32];
    Ok(next_head)
}

/// Derives the unsealed two-owner Inventory disposition Head.
///
/// The existing owner diverts barrier Complete to its separate recovery owner
/// before calling this helper. This helper alone validates no owner proposal.
///
/// # Errors
///
/// Returns existing response/revision/ordinal overflow, consumed-state,
/// Inventory decoding or missing-session reasons, or canonical projection and
/// reconciliation errors with their original provenance.
#[doc(hidden)]
pub fn derive_inventory_disposition_head_v2(
    current: &SourceProviderHeadV2,
    consumed: &SourceProviderQueryAttemptV2,
    terminal: RecordRefV2,
    sessions: &BTreeMap<[u8; 32], SourceProviderSessionV2>,
    attempts: &BTreeMap<[u8; 32], SourceProviderQueryAttemptV2>,
    acquisitions: &BTreeMap<[u8; 32], SourceAcquisitionRowV2>,
) -> std::result::Result<SourceProviderHeadV2, InventoryOwnerDerivationErrorV2> {
    let mut next_head = derive_provider_completed_head_v2(current, acquisitions, acquisitions)?;
    next_head.last_inventory_attempt = Some(terminal);
    if let Some(barrier) = next_head.recovery_barrier.as_mut() {
        barrier.recovery_inventory_tail = Some(terminal);
    }
    if consumed_status(consumed)? == ProviderStatusV2::Complete {
        let ProviderAttemptStateV2::DispositionConsumed { signed_result, .. } = &consumed.state
        else {
            return Err(Invariant("Complete Inventory attempt is not consumed"));
        };
        let signed = SignedSourceProviderInventoryV1::from_canonical_bytes(signed_result)
            .map_err(|_| Invariant("Complete Inventory is invalid"))?;
        let inventory = signed.subject().clone();
        next_head.inventory_observation_ordinal = current
            .inventory_observation_ordinal
            .checked_add(1)
            .ok_or(Invariant(
                "provider Inventory observation ordinal is exhausted",
            ))?;
        next_head.inventory_floor = Some(InventoryFloorV2 {
            attempt: terminal,
            provider_authority_generation: inventory.provider().authority_generation(),
            provider_authority_digest: *inventory.provider().authority_digest().as_bytes(),
            provider_outcome_signer_digest: sessions
                .get(&consumed.session_id)
                .ok_or(Invariant("Inventory outcome session is absent"))?
                .signers[3]
                .public_key_fingerprint,
            inventory_generation: inventory.inventory_generation(),
            inventory_digest: *digest_inventory(&inventory).as_bytes(),
            catalog_generation: inventory.catalog_generation(),
            catalog_digest: *inventory.catalog_digest().as_bytes(),
            signed_result_digest: consumed_result_digest(consumed),
        });
        let mut attempts = attempts.clone();
        attempts.insert(consumed.attempt_id, consumed.clone());
        next_head.last_reconciliation =
            Some(reproduce_reconciliation(&next_head, &attempts, acquisitions)?);
    }
    next_head.record_digest = [0; 32];
    Ok(next_head)
}

fn next_revision(current: u64) -> std::result::Result<u64, InventoryOwnerDerivationErrorV2> {
    current
        .checked_add(1)
        .ok_or(Invariant("AOSMSA02 record revision is exhausted"))
}

fn consumed_status(
    attempt: &SourceProviderQueryAttemptV2,
) -> std::result::Result<ProviderStatusV2, InventoryOwnerDerivationErrorV2> {
    match &attempt.state {
        ProviderAttemptStateV2::DispositionConsumed { status, .. } => Ok(*status),
        ProviderAttemptStateV2::Reserved
        | ProviderAttemptStateV2::AbandonedIndeterminate { .. }
        | ProviderAttemptStateV2::SupersededIndeterminate { .. }
        | ProviderAttemptStateV2::NativeNoDispatchSettled { .. } => {
            Err(Invariant("provider attempt is not disposition-consumed"))
        }
    }
}

fn consumed_result_digest(attempt: &SourceProviderQueryAttemptV2) -> [u8; 32] {
    match &attempt.state {
        ProviderAttemptStateV2::DispositionConsumed {
            signed_result_digest,
            ..
        } => *signed_result_digest,
        ProviderAttemptStateV2::Reserved
        | ProviderAttemptStateV2::AbandonedIndeterminate { .. }
        | ProviderAttemptStateV2::SupersededIndeterminate { .. }
        | ProviderAttemptStateV2::NativeNoDispatchSettled { .. } => [0; 32],
    }
}

#[cfg(test)]
mod tests;
