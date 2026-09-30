//! Ordinary Inventory DATA proposals preserving an immutable original Pending cut.
//!
//! Both inputs are complete validated graphs. Exact canonical comparison keeps
//! every native archive and unrelated owner unchanged. A proposal supplies no
//! live session, received packet, ordinary funding or protected append permit.

use std::collections::BTreeMap;

use aos_sandbox_source_provider_protocol::native_held_completion::NativeHeldControlKindV1 as Kind;

use super::{RootNativeHeldGraphV2, has_original_pending_closed_cut_v5, original_root_remaining_v5};
use crate::mount_source_acquisition_state::{
    InventoryIntentV2, InventoryOwnerDerivationErrorV2, MutationTagV2, OwnerPredecessorWitnessV2,
    ProviderAttemptStateV2, ProviderIntentV2, ProviderMethodV2, ProviderQueryOwnerV2, ProviderStatusV2,
    RecordRefV2, Result, SourceProviderHeadV2, SourceProviderQueryAttemptV2, StoredRecordV2,
    derive_inventory_disposition_head_v2, derive_inventory_reservation_head_v2,
    encode_mount_source_state_record_v2, inventory_correlation_for_row_v2,
    inventory_correlation_set_v2, seal_record, transaction_id,
};
use crate::mount_source_acquisition_state::format::{MAXIMUM_LINEAGE_ATTEMPTS, state_error};

/// Identifies the exact ordinary Inventory edge found in the two checked graphs.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum OriginalInventoryTransitionKindV6 {
    /// A new revision-one Inventory Attempt becomes the current pending query.
    Reserved,
    /// A Pending, Rejected or Unavailable disposition clears the pending query.
    NonCompleteConsumed,
    /// A Complete disposition advances the Inventory floor and reconciliation.
    CompleteConsumed,
}

/// Holds an inspectable, nonauthorizing ordinary Inventory mutation proposal.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct OriginalInventoryTransitionV6 {
    /// The edge derived from the actual Attempt before and after states.
    pub kind: OriginalInventoryTransitionKindV6,
    /// The deterministic ordinary owner transaction identity, not a receipt.
    pub transaction_id: [u8; 16],
    /// The immutable original consumed-Pending Root Attempt.
    pub root_attempt: [u8; 32],
    /// The distinct ordinary Inventory Attempt changed by this proposal.
    pub query_attempt: [u8; 32],
    /// Exactly the canonical query Attempt and provider Head replacements.
    pub puts: BTreeMap<Vec<u8>, Vec<u8>>,
    /// Exact prior bytes at the replacement keys; a new Attempt has no prior bytes.
    pub before_images: BTreeMap<Vec<u8>, Option<Vec<u8>>>,
}

/// Checks an ordinary Inventory edge preserving the original phase-eleven cut.
///
/// This separately named DATA validator does not widen the original native
/// owner, discharge its remaining two transactions, or prove request dispatch,
/// response receipt, protected currentness or physical funding.
///
/// # Errors
///
/// Rejects another cut phase, a recovery barrier, unsupported query state,
/// mismatched current Session, correlations, predecessor or lineage, altered
/// immutable query fields, any unrelated canonical change or removal, or a
/// zero or different deterministic owner transaction identity.
pub fn validate_original_inventory_transition_v6(
    before: &RootNativeHeldGraphV2,
    after: &RootNativeHeldGraphV2,
    root_attempt: [u8; 32],
    query_attempt: [u8; 32],
    supplied_transaction: [u8; 16],
) -> Result<OriginalInventoryTransitionV6> {
    validate_original_cut(before, root_attempt)?;
    validate_original_cut(after, root_attempt)?;
    if root_attempt == query_attempt {
        return Err(state_error(
            "ordinary Inventory query collides with original Root",
        ));
    }

    let original = before
        .legacy
        .provider_attempts
        .get(&root_attempt)
        .ok_or_else(|| state_error("ordinary Inventory original Attempt absent"))?;
    let identity = (
        original.scope.holder_authority_id,
        original.scope.provider_authority_id,
    );
    let current = before
        .legacy
        .provider_heads
        .get(&identity)
        .ok_or_else(|| state_error("ordinary Inventory current Head absent"))?;
    let query = after
        .legacy
        .provider_attempts
        .get(&query_attempt)
        .ok_or_else(|| state_error("ordinary Inventory successor Attempt absent"))?;

    if current.scope != original.scope
        || query.scope != original.scope
        || current.recovery_barrier.is_some()
        || query.method != ProviderMethodV2::Inventory
        || query.owner != ProviderQueryOwnerV2::Inventory
        || !matches!(&query.intent, ProviderIntentV2::Inventory { value }
            if value.recovery_root_attempt_id.is_none())
    {
        return Err(state_error(
            "ordinary Inventory scope or owner differs from original",
        ));
    }

    let (kind, tag, next_head) = match before.legacy.provider_attempts.get(&query_attempt) {
        None => {
            validate_reservation(before, current, query)?;
            let head = derive_inventory_reservation_head_v2(current, reference(query))
                .map_err(derivation_error)?;
            (
                OriginalInventoryTransitionKindV6::Reserved,
                MutationTagV2::ReserveRetry,
                head,
            )
        }
        Some(reserved) => {
            let kind = validate_consumption(current, reserved, query)?;
            let head = derive_inventory_disposition_head_v2(
                current,
                query,
                reference(query),
                &before.legacy.provider_sessions,
                &before.legacy.provider_attempts,
                &before.legacy.acquisitions,
            )
            .map_err(derivation_error)?;
            (kind, MutationTagV2::CompleteInventory, head)
        }
    };

    let expected_transaction = transaction_id(
        tag,
        current.scope.holder_authority_id,
        current.scope.provider_authority_id,
        before
            .legacy
            .holder_sequences
            .get(&current.scope.holder_authority_id)
            .map_or(0, |sequence| sequence.revision),
        next_head.revision,
        None,
        None,
        Some(query.attempt_id),
        Some(query.revision),
        None,
    );
    if supplied_transaction == [0; 16] || supplied_transaction != expected_transaction {
        return Err(state_error(
            "ordinary Inventory transaction identity differs from owner",
        ));
    }

    let expected = BTreeMap::from([
        encode_mount_source_state_record_v2(&StoredRecordV2::ProviderQueryAttempt {
            value: query.clone(),
        })?,
        encode_mount_source_state_record_v2(&seal_record(StoredRecordV2::ProviderHead {
            value: next_head,
        })?)?,
    ]);
    let puts = exact_changes(before, after, &expected)?;
    let before_images = puts
        .keys()
        .map(|key| (key.clone(), before.canonical.get(key).cloned()))
        .collect();

    Ok(OriginalInventoryTransitionV6 {
        kind,
        transaction_id: expected_transaction,
        root_attempt,
        query_attempt,
        puts,
        before_images,
    })
}

fn validate_original_cut(graph: &RootNativeHeldGraphV2, root_attempt: [u8; 32]) -> Result<()> {
    let sidecar = graph
        .sidecars
        .get(&root_attempt)
        .ok_or_else(|| state_error("ordinary Inventory original sidecar absent"))?;

    // The reusable association predicate also accepts later terminal phases.
    // This owner intentionally preserves only the signed Closed phase11 cut.
    if sidecar.suffix().phase() != 11
        || sidecar.suffix().control(Kind::RootPrepared).is_none()
        || sidecar.suffix().control(Kind::RootClosed).is_none()
        || !has_original_pending_closed_cut_v5(graph, sidecar)?
        || original_root_remaining_v5(graph, root_attempt)? != 2
    {
        return Err(state_error(
            "ordinary Inventory requires original Pending Closed phase11",
        ));
    }
    Ok(())
}

fn validate_reservation(
    before: &RootNativeHeldGraphV2,
    current: &SourceProviderHeadV2,
    query: &SourceProviderQueryAttemptV2,
) -> Result<()> {
    let session = before
        .legacy
        .provider_sessions
        .get(&current.current_session_id)
        .ok_or_else(|| state_error("Inventory current session is absent"))?;

    if current.pending_attempt.is_some()
        || current.next_request_sequence != current.next_response_sequence
        || query.revision != 1
        || !matches!(query.state, ProviderAttemptStateV2::Reserved)
        || session.scope != current.scope
        || session.record_digest != current.current_session_record_digest
        || query.session_id != current.current_session_id
        || query.session_record_digest != current.current_session_record_digest
        || query.request_sequence != current.next_request_sequence
        || query.signer_set_commitment != session.signer_set_commitment
        || query.trust_digest != session.trust_digest
        || query.revocation_digest != session.revocation_digest
        || query.route_digest != session.route_digest
        || query.process_execution_digest != session.provider_execution.process_execution_digest
        || query.owner_predecessor_revision != current.revision
        || query.owner_predecessor_digest != current.record_digest
        || query.owner_predecessor.as_ref()
            != Some(&OwnerPredecessorWitnessV2::ProviderHead {
                value: super::recovery_v2::head_predecessor(current),
            })
        || query.provider_acquisition.is_some()
        || query.normalized_acquire_intent.is_some()
        || query.acquire_verification_floor.is_some()
    {
        return Err(state_error(
            "ordinary Inventory reservation changes current Head or Session",
        ));
    }

    let mut entries = before
        .legacy
        .acquisitions
        .values()
        .filter(|row| row.scope == current.scope)
        .filter_map(inventory_correlation_for_row_v2)
        .collect::<Vec<_>>();
    entries.sort_by_key(|entry| entry.provider_acquisition.acquisition_id);
    let correlations = inventory_correlation_set_v2(entries)?;
    let expected_intent = ProviderIntentV2::Inventory {
        value: InventoryIntentV2 {
            scope: current.scope,
            known_inventory_generation: current
                .inventory_floor
                .as_ref()
                .map(|floor| floor.inventory_generation),
            known_inventory_digest: current
                .inventory_floor
                .as_ref()
                .map(|floor| floor.inventory_digest),
            known_catalog_generation: current
                .inventory_floor
                .as_ref()
                .map(|floor| floor.catalog_generation),
            known_catalog_digest: current
                .inventory_floor
                .as_ref()
                .map(|floor| floor.catalog_digest),
            known_observation_ordinal: current.inventory_observation_ordinal,
            recovery_root_attempt_id: None,
            correlation_digest: correlations.digest,
        },
    };

    if query.inventory_correlations.as_ref() != Some(&correlations) || query.intent != expected_intent {
        return Err(state_error(
            "ordinary Inventory correlations or known floor differ from Head",
        ));
    }

    let predecessor = inventory_predecessor(before, current)?;
    let (root, previous, number) = lineage_coordinates(predecessor)?;
    let root = if root == [0; 32] {
        query.attempt_id
    } else {
        root
    };
    if query.lineage_root_attempt_id != root
        || query.previous_attempt_id != previous
        || query.attempt_number != number
    {
        return Err(state_error(
            "ordinary Inventory lineage differs from current predecessor",
        ));
    }
    Ok(())
}

fn inventory_predecessor<'a>(
    graph: &'a RootNativeHeldGraphV2,
    current: &SourceProviderHeadV2,
) -> Result<Option<&'a SourceProviderQueryAttemptV2>> {
    current
        .last_inventory_attempt
        .map(|reference| {
            graph
                .legacy
                .provider_attempts
                .get(&reference.id)
                .filter(|attempt| {
                    attempt.revision == reference.revision
                        && attempt.record_digest == reference.record_digest
                        && attempt.method == ProviderMethodV2::Inventory
                })
                .ok_or_else(|| state_error("Inventory predecessor attempt is absent"))
        })
        .transpose()
}

fn lineage_coordinates(
    predecessor: Option<&SourceProviderQueryAttemptV2>,
) -> Result<([u8; 32], Option<[u8; 32]>, u64)> {
    // This is the existing ordinary predicate, including its absence of a
    // status condition. Complete graph validation still checks lineage/history.
    let compact_completed_prefix = predecessor
        .is_some_and(|attempt| attempt.attempt_number == MAXIMUM_LINEAGE_ATTEMPTS as u64);
    if compact_completed_prefix {
        return Ok(([0; 32], None, 1));
    }
    match predecessor {
        Some(attempt) => Ok((
            attempt.lineage_root_attempt_id,
            Some(attempt.attempt_id),
            attempt
                .attempt_number
                .checked_add(1)
                .ok_or_else(|| state_error("Inventory attempt number is exhausted"))?,
        )),
        None => Ok(([0; 32], None, 1)),
    }
}

fn validate_consumption(
    current: &SourceProviderHeadV2,
    reserved: &SourceProviderQueryAttemptV2,
    consumed: &SourceProviderQueryAttemptV2,
) -> Result<OriginalInventoryTransitionKindV6> {
    if reserved.revision != 1
        || consumed.revision != 2
        || !matches!(reserved.state, ProviderAttemptStateV2::Reserved)
        || current.pending_attempt != Some(reference(reserved))
    {
        return Err(state_error("ordinary Inventory consumption lacks exact pending Q1"));
    }
    super::recovery_v2::preserve_attempt(reserved, consumed)?;
    let ProviderAttemptStateV2::DispositionConsumed {
        response_sequence,
        status,
        ..
    } = &consumed.state
    else {
        return Err(state_error("ordinary Inventory Q2 is not disposition-consumed"));
    };
    if *response_sequence != reserved.request_sequence {
        return Err(state_error("ordinary Inventory response sequence differs from Q1"));
    }

    match status {
        ProviderStatusV2::Complete => Ok(OriginalInventoryTransitionKindV6::CompleteConsumed),
        ProviderStatusV2::Pending | ProviderStatusV2::Rejected | ProviderStatusV2::Unavailable => {
            Ok(OriginalInventoryTransitionKindV6::NonCompleteConsumed)
        }
    }
}

fn exact_changes(
    before: &RootNativeHeldGraphV2,
    after: &RootNativeHeldGraphV2,
    expected: &BTreeMap<Vec<u8>, Vec<u8>>,
) -> Result<BTreeMap<Vec<u8>, Vec<u8>>> {
    if before
        .canonical
        .keys()
        .any(|key| !after.canonical.contains_key(key))
    {
        return Err(state_error("ordinary Inventory removed a retained canonical record"));
    }
    let puts: BTreeMap<_, _> = after
        .canonical
        .iter()
        .filter(|(key, value)| before.canonical.get(*key) != Some(*value))
        .map(|(key, value)| (key.clone(), value.clone()))
        .collect();
    if &puts != expected {
        return Err(state_error(
            "ordinary Inventory changed unrelated canonical records or Head",
        ));
    }
    Ok(puts)
}

fn reference(attempt: &SourceProviderQueryAttemptV2) -> RecordRefV2 {
    RecordRefV2 {
        id: attempt.attempt_id,
        revision: attempt.revision,
        record_digest: attempt.record_digest,
    }
}

fn derivation_error(
    error: InventoryOwnerDerivationErrorV2,
) -> super::super::MountSourceAcquisitionStateError {
    match error {
        InventoryOwnerDerivationErrorV2::Invariant(reason) => state_error(reason),
        InventoryOwnerDerivationErrorV2::Canonical(error) => error,
    }
}
