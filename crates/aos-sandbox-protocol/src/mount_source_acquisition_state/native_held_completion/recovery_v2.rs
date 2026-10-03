//! Closed native legacy recovery projections and genuine local terminal cleanup.
//!
//! These checks reuse fully validated original legacy records and exact reducer
//! successors. They never exempt a historical record from current graph checks.
//! Repeated ordinary operations require their own separately reviewed producer;
//! this finite native prefix cannot consume the old floor indefinitely.

use std::collections::BTreeMap;

use aos_sandbox_source_provider_protocol::native_held_completion::NativeHeldControlKindV1 as Kind;

use super::{
    RootNativeHeldGraphV2, RootNativeHeldSidecarV2, reducer_v2::RootNativeTransitionKindV2,
};
use crate::mount_source_acquisition_state::{
    AcquisitionRecoveryV2, ProviderAttemptStateV2, ProviderHeadPredecessorWitnessV2,
    ProviderIntentV2, ProviderMethodV2, ProviderStatusV2, RecordRefV2, RecoveryBarrierV2,
    RecoveryResolutionV2, Result, SourceAcquisitionPhaseV2, SourceProviderHeadV2,
    SourceProviderQueryAttemptV2, StoredRecordV2, acquisition_key, format::state_error,
    native_recovery_settlement_digest_v2, provider_attempt_key, provider_head_key,
    provider_session_key, record_digest,
};

pub(super) fn validate_native_recovery_step(
    before: &RootNativeHeldGraphV2,
    after: &RootNativeHeldGraphV2,
    sidecar: &RootNativeHeldSidecarV2,
    puts: &BTreeMap<Vec<u8>, Vec<u8>>,
) -> Result<RootNativeTransitionKindV2> {
    if sidecar.suffix().control(Kind::ProviderHeld).is_some()
        || sidecar.response_transaction() != [0; 16]
        || sidecar.settlement().is_some()
    {
        return Err(state_error(
            "native no-interest prefix already has native dispatch interest",
        ));
    }
    let (old, _) = super::graph_v2::original_rows(before, sidecar)?;
    let (next, _) = super::graph_v2::original_rows(after, sidecar)?;
    if matches!(old.state, ProviderAttemptStateV2::Reserved)
        && matches!(
            next.state,
            ProviderAttemptStateV2::AbandonedIndeterminate {
                resolution: None,
                ..
            }
        )
    {
        validate_replacement(before, after, old, next, puts)?;
        return Ok(RootNativeTransitionKindV2::NativeRecoveryReplacement);
    }
    if old == next {
        validate_inventory_reservation(before, after, old, puts)?;
        return Ok(RootNativeTransitionKindV2::NativeRecoveryInventoryReserved);
    }
    validate_inventory_resolution(before, after, old, next, puts)?;
    Ok(RootNativeTransitionKindV2::NativeRecoveryInventoryResolved)
}

fn validate_replacement(
    before: &RootNativeHeldGraphV2,
    after: &RootNativeHeldGraphV2,
    old: &SourceProviderQueryAttemptV2,
    next: &SourceProviderQueryAttemptV2,
    puts: &BTreeMap<Vec<u8>, Vec<u8>>,
) -> Result<()> {
    let old_ref = reference(old);
    let next_ref = reference(next);
    let current_head = head(before, old)?;
    let next_head = head(after, old)?;
    let ProviderAttemptStateV2::AbandonedIndeterminate {
        successor_session_id,
        recovery_root_attempt_id,
        outcome_may_exist,
        resolution,
        ..
    } = &next.state
    else {
        return Err(state_error(
            "native replacement is not exact unresolved abandonment",
        ));
    };
    let successor = after
        .legacy
        .provider_sessions
        .get(successor_session_id)
        .ok_or_else(|| state_error("native replacement successor absent"))?;
    if old.revision != 1
        || next.revision != 2
        || !*outcome_may_exist
        || resolution.is_some()
        || *recovery_root_attempt_id != old.attempt_id
        || successor.predecessor_session_id != Some(old.session_id)
        || before
            .legacy
            .provider_sessions
            .contains_key(successor_session_id)
        || current_head.pending_attempt != Some(old_ref)
        || current_head.recovery_barrier.is_some()
    {
        return Err(state_error(
            "native replacement changed exact original pending cut",
        ));
    }
    preserve_attempt(old, next)?;
    let old_row = before
        .legacy
        .acquisitions
        .get(&old.owner.owner_id())
        .ok_or_else(|| state_error("native replacement acquisition absent"))?;
    let next_row = after
        .legacy
        .acquisitions
        .get(&old_row.acquisition_id)
        .ok_or_else(|| state_error("native replacement successor acquisition absent"))?;
    let mut expected_row = old_row.clone();
    expected_row.revision = increment(old_row.revision)?;
    advance_original(&mut expected_row.acquire_lineage, old_ref, next_ref)?;
    expected_row.recovery = AcquisitionRecoveryV2::InventoryRequired {
        root_attempt: next_ref,
    };
    expected_row.record_digest = record_digest(&StoredRecordV2::Acquisition {
        value: expected_row.clone(),
    })?;
    if &expected_row != next_row {
        return Err(state_error(
            "native replacement acquisition is not exact reducer successor",
        ));
    }

    let mut expected_head = current_head.clone();
    expected_head.revision = increment(current_head.revision)?;
    expected_head.holder_authority_generation = successor.root_mount_authority_generation;
    expected_head.holder_authority_digest = successor.root_mount_authority_digest;
    expected_head.provider_authority_generation = successor.provider_authority_generation;
    expected_head.provider_authority_digest = successor.provider_authority_digest;
    expected_head.current_session_id = successor.session_id;
    expected_head.current_session_record_digest = successor.record_digest;
    expected_head.next_request_sequence = 1;
    expected_head.next_response_sequence = 1;
    expected_head.pending_attempt = None;
    expected_head.last_reconciliation = None;
    expected_head.recovery_barrier = Some(RecoveryBarrierV2 {
        root_attempt: next_ref,
        baseline_inventory_ordinal: current_head.inventory_observation_ordinal,
        required_session_id: successor.session_id,
        recovery_inventory_tail: None,
        replacement_count: 1,
    });
    expected_head.record_digest = record_digest(&StoredRecordV2::ProviderHead {
        value: expected_head.clone(),
    })?;
    if &expected_head != next_head {
        return Err(state_error(
            "native replacement Head is not exact reducer successor",
        ));
    }
    exact_keys(
        puts,
        &[
            provider_attempt_key(old.attempt_id),
            provider_session_key(successor.session_id),
            acquisition_key(old_row.acquisition_id),
            provider_head_key(
                old.scope.holder_authority_id,
                old.scope.provider_authority_id,
            ),
        ],
    )
}

fn validate_inventory_reservation(
    before: &RootNativeHeldGraphV2,
    after: &RootNativeHeldGraphV2,
    original: &SourceProviderQueryAttemptV2,
    puts: &BTreeMap<Vec<u8>, Vec<u8>>,
) -> Result<()> {
    let previous_head = head(before, original)?;
    let next_head = head(after, original)?;
    let barrier = previous_head
        .recovery_barrier
        .as_ref()
        .ok_or_else(|| state_error("native Inventory reservation has no original barrier"))?;
    if barrier.root_attempt != reference(original)
        || barrier.recovery_inventory_tail.is_some()
        || previous_head.pending_attempt.is_some()
        || previous_head.next_request_sequence != previous_head.next_response_sequence
    {
        return Err(state_error(
            "native Inventory reservation exceeds original finite prefix",
        ));
    }
    let pending = next_head
        .pending_attempt
        .ok_or_else(|| state_error("native Inventory successor is not Reserved"))?;
    let inventory = after
        .legacy
        .provider_attempts
        .get(&pending.id)
        .filter(|attempt| reference(attempt) == pending)
        .ok_or_else(|| state_error("native Inventory exact pending Attempt absent"))?;
    if before
        .legacy
        .provider_attempts
        .contains_key(&inventory.attempt_id)
        || inventory.method != ProviderMethodV2::Inventory
        || inventory.revision != 1
        || !matches!(inventory.state, ProviderAttemptStateV2::Reserved)
        || inventory.session_id != previous_head.current_session_id
        || inventory.request_sequence != previous_head.next_request_sequence
        || !matches!(&inventory.intent, ProviderIntentV2::Inventory { value } if value.recovery_root_attempt_id == Some(original.attempt_id))
        || inventory.owner_predecessor_revision != previous_head.revision
        || inventory.owner_predecessor_digest != previous_head.record_digest
        || inventory.owner_predecessor.as_ref()
            != Some(
                &crate::mount_source_acquisition_state::OwnerPredecessorWitnessV2::ProviderHead {
                    value: head_predecessor(previous_head),
                },
            )
    {
        return Err(state_error(
            "native Inventory reservation changed original before-image or request",
        ));
    }
    let mut expected = previous_head.clone();
    expected.revision = increment(previous_head.revision)?;
    expected.next_request_sequence = increment(previous_head.next_request_sequence)?;
    expected.pending_attempt = Some(pending);
    expected.record_digest = record_digest(&StoredRecordV2::ProviderHead {
        value: expected.clone(),
    })?;
    if &expected != next_head {
        return Err(state_error(
            "native Inventory reservation Head is not exact reducer successor",
        ));
    }
    exact_keys(
        puts,
        &[
            provider_attempt_key(inventory.attempt_id),
            provider_head_key(
                original.scope.holder_authority_id,
                original.scope.provider_authority_id,
            ),
        ],
    )
}

fn validate_inventory_resolution(
    before: &RootNativeHeldGraphV2,
    after: &RootNativeHeldGraphV2,
    original: &SourceProviderQueryAttemptV2,
    resolved: &SourceProviderQueryAttemptV2,
    puts: &BTreeMap<Vec<u8>, Vec<u8>>,
) -> Result<()> {
    if original.revision != 2
        || resolved.revision != 3
        || !matches!(
            original.state,
            ProviderAttemptStateV2::AbandonedIndeterminate {
                resolution: None,
                ..
            }
        )
    {
        return Err(state_error(
            "native Inventory outcome has no exact unresolved predecessor",
        ));
    }
    let ProviderAttemptStateV2::AbandonedIndeterminate {
        resolution: Some(RecoveryResolutionV2::RetryAcquireSameIntent { proof }),
        ..
    } = &resolved.state
    else {
        return Err(state_error(
            "native Inventory outcome is not genuine absent original Acquire",
        ));
    };
    let mut historical = resolved.clone();
    if let ProviderAttemptStateV2::AbandonedIndeterminate { resolution, .. } = &mut historical.state
    {
        *resolution = None;
    }
    historical.revision = original.revision;
    historical.record_digest = original.record_digest;
    if historical != *original {
        return Err(state_error(
            "native Inventory outcome changed original abandonment",
        ));
    }
    let old_inventory = before
        .legacy
        .provider_attempts
        .get(&proof.inventory_attempt.id)
        .ok_or_else(|| state_error("native Inventory outcome original reserved Attempt absent"))?;
    let inventory = after
        .legacy
        .provider_attempts
        .get(&proof.inventory_attempt.id)
        .filter(|attempt| reference(attempt) == proof.inventory_attempt)
        .ok_or_else(|| state_error("native Inventory outcome exact Complete Attempt absent"))?;
    if old_inventory.method != ProviderMethodV2::Inventory
        || old_inventory.revision != 1
        || !matches!(old_inventory.state, ProviderAttemptStateV2::Reserved)
        || inventory.revision != 2
        || !matches!(
            inventory.state,
            ProviderAttemptStateV2::DispositionConsumed {
                status: ProviderStatusV2::Complete,
                ..
            }
        )
    {
        return Err(state_error(
            "native Inventory outcome changed exact Inventory CAS",
        ));
    }
    preserve_attempt(old_inventory, inventory)?;
    crate::mount_source_acquisition_state::validate_native_no_dispatch_absent_resolution_v2(
        resolved,
        &after.legacy,
    )?;
    let old_row = before
        .legacy
        .acquisitions
        .get(&original.owner.owner_id())
        .ok_or_else(|| state_error("native Inventory outcome original Acquisition absent"))?;
    let row = after
        .legacy
        .acquisitions
        .get(&old_row.acquisition_id)
        .ok_or_else(|| state_error("native Inventory outcome successor Acquisition absent"))?;
    let mut expected_row = old_row.clone();
    expected_row.revision = increment(old_row.revision)?;
    advance_original(
        &mut expected_row.acquire_lineage,
        reference(original),
        reference(resolved),
    )?;
    expected_row.recovery = AcquisitionRecoveryV2::RetryPermitted {
        root_attempt: reference(resolved),
    };
    expected_row.record_digest = record_digest(&StoredRecordV2::Acquisition {
        value: expected_row.clone(),
    })?;
    if &expected_row != row {
        return Err(state_error(
            "native Inventory outcome Acquisition is not exact reducer successor",
        ));
    }

    let previous_head = head(before, original)?;
    let next_head = head(after, original)?;
    if previous_head.pending_attempt != Some(reference(old_inventory))
        || previous_head
            .recovery_barrier
            .as_ref()
            .is_none_or(|barrier| {
                barrier.root_attempt != reference(original)
                    || barrier.recovery_inventory_tail.is_some()
            })
    {
        return Err(state_error(
            "native Inventory outcome lost exact before barrier",
        ));
    }
    let mut expected_head = previous_head.clone();
    expected_head.revision = increment(previous_head.revision)?;
    expected_head.next_response_sequence = increment(previous_head.next_response_sequence)?;
    expected_head.pending_attempt = None;
    expected_head.inventory_observation_ordinal =
        increment(previous_head.inventory_observation_ordinal)?;
    expected_head.inventory_floor = next_head.inventory_floor.clone();
    expected_head.last_inventory_attempt = Some(reference(inventory));
    expected_head.recovery_barrier = None;
    expected_head.last_reconciliation = Some(
        crate::mount_source_acquisition_state::reproduce_reconciliation(
            next_head,
            &after.legacy.provider_attempts,
            &after.legacy.acquisitions,
        )?,
    );
    expected_head.record_digest = record_digest(&StoredRecordV2::ProviderHead {
        value: expected_head.clone(),
    })?;
    if &expected_head != next_head
        || next_head
            .inventory_floor
            .as_ref()
            .is_none_or(|floor| floor.attempt != reference(inventory))
    {
        return Err(state_error(
            "native Inventory outcome Head is not exact reducer successor",
        ));
    }
    exact_keys(
        puts,
        &[
            provider_attempt_key(original.attempt_id),
            provider_attempt_key(inventory.attempt_id),
            acquisition_key(old_row.acquisition_id),
            provider_head_key(
                original.scope.holder_authority_id,
                original.scope.provider_authority_id,
            ),
        ],
    )
}

pub(super) fn validate_no_interest_cleanup(
    before: &RootNativeHeldGraphV2,
    after: &RootNativeHeldGraphV2,
    old: &RootNativeHeldSidecarV2,
    next: &RootNativeHeldSidecarV2,
    transaction_id: [u8; 16],
    puts: &BTreeMap<Vec<u8>, Vec<u8>>,
) -> Result<()> {
    super::reducer::preserve_immutable(&old.claims, &next.claims)?;
    let marker = next
        .no_interest_terminal()
        .ok_or_else(|| state_error("native no-interest marker absent"))?;
    if !matches!(old.suffix().phase(), 10 | 11)
        || old.suffix().phase() != next.suffix().phase()
        || old.suffix().control(Kind::ProviderHeld).is_some()
        || old.settlement().is_some()
        || old.response_transaction() != [0; 16]
        || old.suffix().controls() != next.suffix().controls()
        || old
            .suffix()
            .prepared()
            .is_some_and(|control| control.kind() != Kind::RootClosed)
        || next.suffix().prepared().is_some()
        || marker.cleanup_transaction != transaction_id
    {
        return Err(state_error(
            "native no-interest cleanup altered native archives or TX",
        ));
    }
    let (original, _) = super::graph_v2::original_rows(before, old)?;
    let (settled, _) = super::graph_v2::original_rows(after, next)?;
    let ProviderAttemptStateV2::NativeNoDispatchSettled {
        prior_state,
        canonical_query,
        signed_settlement,
        settlement_session_id,
    } = &settled.state
    else {
        return Err(state_error(
            "native no-interest cleanup lacks authenticated dedicated terminal proof",
        ));
    };
    let previous_head = head(before, original)?;
    if prior_state.as_ref() != &original.state
        || settled.revision != increment(original.revision)?
        || *settlement_session_id != previous_head.current_session_id
        || settled.attempt_number != 1
        || settled.previous_attempt_id.is_some()
        || canonical_query.is_empty()
        || signed_settlement.is_empty()
        || previous_head.pending_attempt.is_some()
        || previous_head.next_request_sequence != previous_head.next_response_sequence
    {
        return Err(state_error(
            "native no-interest cleanup is not exact authenticated old attempt",
        ));
    }
    if original.revision == 3 {
        crate::mount_source_acquisition_state::validate_native_no_dispatch_absent_resolution_v2(
            original,
            &before.legacy,
        )?;
    } else if original.revision != 2
        || !matches!(
            original.state,
            ProviderAttemptStateV2::AbandonedIndeterminate {
                resolution: None,
                ..
            } | ProviderAttemptStateV2::SupersededIndeterminate { .. }
        )
    {
        return Err(state_error(
            "native no-interest cleanup unsupported prior revision/state",
        ));
    }
    preserve_attempt(original, settled)?;
    let old_row = before
        .legacy
        .acquisitions
        .get(&original.owner.owner_id())
        .ok_or_else(|| state_error("native no-interest cleanup original Acquisition absent"))?;
    let row = after
        .legacy
        .acquisitions
        .get(&old_row.acquisition_id)
        .ok_or_else(|| state_error("native no-interest cleanup successor Acquisition absent"))?;
    if old_row.phase != SourceAcquisitionPhaseV2::PendingQuery
        || old_row.evidence.is_some()
        || old_row.acquire_terminal_attempt.is_some()
        || old_row.acquire_lineage.root != reference(original)
        || old_row.acquire_lineage.tail != reference(original)
    {
        return Err(state_error(
            "native no-interest cleanup original no-evidence row changed",
        ));
    }
    let mut expected_row = old_row.clone();
    expected_row.revision = increment(old_row.revision)?;
    expected_row.phase = SourceAcquisitionPhaseV2::Faulted;
    expected_row.faulted_from = Some(SourceAcquisitionPhaseV2::PendingQuery);
    expected_row.fault_digest = Some(native_recovery_settlement_digest_v2(signed_settlement));
    expected_row.recovery = AcquisitionRecoveryV2::Ready;
    advance_original(
        &mut expected_row.acquire_lineage,
        reference(original),
        reference(settled),
    )?;
    expected_row.record_digest = record_digest(&StoredRecordV2::Acquisition {
        value: expected_row.clone(),
    })?;
    if &expected_row != row {
        return Err(state_error(
            "native no-interest cleanup Acquisition is not exact reducer successor",
        ));
    }
    let mut expected_head = previous_head.clone();
    expected_head.revision = increment(previous_head.revision)?;
    expected_head.recovery_barrier = None;
    expected_head.record_digest = record_digest(&StoredRecordV2::ProviderHead {
        value: expected_head.clone(),
    })?;
    if &expected_head != head(after, original)? {
        return Err(state_error(
            "native no-interest cleanup Head is not exact cleared-barrier successor",
        ));
    }
    exact_keys(
        puts,
        &[
            provider_attempt_key(original.attempt_id),
            acquisition_key(old_row.acquisition_id),
            provider_head_key(
                original.scope.holder_authority_id,
                original.scope.provider_authority_id,
            ),
            super::native_root_sidecar_key_v2(original.attempt_id)?,
        ],
    )
}

pub(super) fn preserve_attempt(
    old: &SourceProviderQueryAttemptV2,
    next: &SourceProviderQueryAttemptV2,
) -> Result<()> {
    let mut immutable = next.clone();
    immutable.revision = old.revision;
    immutable.record_digest = old.record_digest;
    immutable.state = old.state.clone();
    if immutable != *old {
        return Err(state_error(
            "native recovery changed immutable original attempt",
        ));
    }
    Ok(())
}

fn advance_original(
    lineage: &mut crate::mount_source_acquisition_state::QueryLineageV2,
    old: RecordRefV2,
    next: RecordRefV2,
) -> Result<()> {
    if old.id != next.id
        || lineage.root != old
        || lineage.tail != old
        || lineage.next_attempt_number != 2
    {
        return Err(state_error(
            "native recovery has a retry or mismatching original before-image",
        ));
    }
    lineage.root = next;
    lineage.tail = next;
    Ok(())
}

fn exact_keys(puts: &BTreeMap<Vec<u8>, Vec<u8>>, keys: &[Vec<u8>]) -> Result<()> {
    if puts.len() != keys.len() || keys.iter().any(|key| !puts.contains_key(key)) {
        return Err(state_error(
            "native recovery changed unrelated canonical records",
        ));
    }
    Ok(())
}

fn head<'a>(
    graph: &'a RootNativeHeldGraphV2,
    original: &SourceProviderQueryAttemptV2,
) -> Result<&'a SourceProviderHeadV2> {
    graph
        .legacy
        .provider_heads
        .get(&(
            original.scope.holder_authority_id,
            original.scope.provider_authority_id,
        ))
        .ok_or_else(|| state_error("native recovery current Head absent"))
}

fn increment(value: u64) -> Result<u64> {
    value
        .checked_add(1)
        .ok_or_else(|| state_error("native recovery revision/sequence exhausted"))
}

fn reference(attempt: &SourceProviderQueryAttemptV2) -> RecordRefV2 {
    RecordRefV2 {
        id: attempt.attempt_id,
        revision: attempt.revision,
        record_digest: attempt.record_digest,
    }
}

pub(super) fn head_predecessor(head: &SourceProviderHeadV2) -> ProviderHeadPredecessorWitnessV2 {
    let mut id = [0; 32];
    id[..16].copy_from_slice(&head.scope.holder_authority_id);
    id[16..].copy_from_slice(&head.scope.provider_authority_id);
    ProviderHeadPredecessorWitnessV2 {
        record: RecordRefV2 {
            id,
            revision: head.revision,
            record_digest: head.record_digest,
        },
        scope: head.scope,
        holder_authority_generation: head.holder_authority_generation,
        holder_authority_digest: head.holder_authority_digest,
        provider_authority_generation: head.provider_authority_generation,
        provider_authority_digest: head.provider_authority_digest,
        current_session_id: head.current_session_id,
        current_session_record_digest: head.current_session_record_digest,
        next_request_sequence: head.next_request_sequence,
        next_response_sequence: head.next_response_sequence,
        pending_attempt: head.pending_attempt,
        inventory_observation_ordinal: head.inventory_observation_ordinal,
        inventory_floor: head.inventory_floor.clone(),
        last_inventory_attempt: head.last_inventory_attempt,
        current_projection_epoch: head.current_projection_epoch,
        current_projection_digest: head.current_projection_digest,
        last_reconciliation: head.last_reconciliation.clone(),
        recovery_barrier: head.recovery_barrier.clone(),
    }
}
