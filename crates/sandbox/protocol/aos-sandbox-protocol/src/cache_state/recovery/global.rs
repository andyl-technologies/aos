//! Global recovery-state transition and terminal-effect reducers.

use super::*;

pub(super) fn handoff_is_terminal(handoff: &CacheReadHandoffStateV1) -> bool {
    handoff.receipt_evidence.is_some() || handoff.cancellation.is_some()
}

pub(super) fn lookup_is_terminal(lookup: &CacheLookupStateV1) -> bool {
    lookup.value.is_some() || lookup.cancellation.is_some()
}

pub(super) fn validate_global_transition(
    previous: &CacheGlobalRecoveryStateV1,
    next: &CacheGlobalRecoveryStateV1,
    payload: &CacheAtomicObjectPayloadV1,
    protected_checkpoint: ObjectDigest,
) -> Result<(), RecoveryError> {
    let record = &payload.record;
    if previous.node_quota.partition != next.node_quota.partition || previous.poison != next.poison
    {
        return Err(RecoveryError::PayloadMismatch);
    }
    let quotas_changed =
        previous.node_quota != next.node_quota || previous.project_quotas != next.project_quotas;
    let watermarks_changed = previous.watermarks != next.watermarks;
    let idempotency_changed = previous.idempotency != next.idempotency;
    let pin_floor_changed = previous.pin_floor != next.pin_floor;
    let idempotency_floor_changed = previous.idempotency_floor != next.idempotency_floor;
    let handoffs_changed = previous.handoffs != next.handoffs;
    let lookups_changed = previous.lookups != next.lookups;
    let no_unrelated = |allow_quotas: bool,
                        allow_watermarks: bool,
                        allow_idempotency: bool,
                        allow_pin_floor: bool,
                        allow_idempotency_floor: bool,
                        allow_handoffs: bool,
                        allow_lookups: bool| {
        (!quotas_changed || allow_quotas)
            && (!watermarks_changed || allow_watermarks)
            && (!idempotency_changed || allow_idempotency)
            && (!pin_floor_changed || allow_pin_floor)
            && (!idempotency_floor_changed || allow_idempotency_floor)
            && (!handoffs_changed || allow_handoffs)
            && (!lookups_changed || allow_lookups)
    };
    let valid = match record.kind {
        CacheRecordKindV1::Quota => {
            quotas_changed
                && no_unrelated(true, false, false, false, false, false, false)
                && valid_quota_transition(previous, next, record.state)
        }
        CacheRecordKindV1::Admission | CacheRecordKindV1::EvictionProgress => {
            no_unrelated(false, true, true, false, false, false, false)
                && valid_idempotency_transition(&previous.idempotency, &next.idempotency)
                && valid_watermark_transition(&previous.watermarks, &next.watermarks, payload)
        }
        CacheRecordKindV1::Pin | CacheRecordKindV1::Scrub | CacheRecordKindV1::EvictionPlan => {
            no_unrelated(false, false, true, false, false, false, false)
                && valid_idempotency_transition(&previous.idempotency, &next.idempotency)
        }
        CacheRecordKindV1::ReadHandoff => {
            handoffs_changed
                && no_unrelated(false, false, true, false, false, true, false)
                && valid_idempotency_transition(&previous.idempotency, &next.idempotency)
                && valid_handoff_transition(
                    &previous.handoffs,
                    &next.handoffs,
                    record.state,
                    payload,
                )
        }
        CacheRecordKindV1::LookupMemo => {
            lookups_changed
                && no_unrelated(false, false, false, false, false, false, true)
                && valid_lookup_transition(
                    &previous.lookups,
                    &next.lookups,
                    record.state,
                    record.subject,
                    record.authority,
                    record.evidence,
                )
        }
        CacheRecordKindV1::Poison => no_unrelated(false, false, false, false, false, false, false),
        CacheRecordKindV1::Compaction => match record.state {
            1 => {
                pin_floor_changed
                    && no_unrelated(false, false, false, true, false, false, false)
                    && permanent_pin_floor_advanced(previous.pin_floor, next.pin_floor)
                    && next
                        .pin_floor
                        .is_some_and(|floor| floor.checkpoint() == protected_checkpoint)
            }
            2 => {
                idempotency_floor_changed
                    && no_unrelated(false, false, true, false, true, false, false)
                    && permanent_idempotency_floor_advanced(
                        previous.idempotency_floor,
                        next.idempotency_floor,
                    )
                    && next
                        .idempotency_floor
                        .is_some_and(|floor| floor.checkpoint() == protected_checkpoint)
                    && valid_idempotency_compaction(previous, next)
                    && next.idempotency.iter().all(|binding| {
                        next.idempotency_floor.is_some_and(|floor| {
                            (
                                *binding.principal.as_bytes(),
                                binding.method as u16,
                                binding.key,
                            ) > floor.scope()
                        })
                    })
            }
            _ => false,
        },
        CacheRecordKindV1::Domain | CacheRecordKindV1::Reservation | CacheRecordKindV1::Catalog => {
            no_unrelated(false, false, false, false, false, false, false)
        }
    };
    if !valid {
        return Err(RecoveryError::PayloadMismatch);
    }
    Ok(())
}

fn permanent_pin_floor_advanced(
    previous: Option<PinCompactionFloorV1>,
    next: Option<PinCompactionFloorV1>,
) -> bool {
    match (previous, next) {
        (None, Some(_)) => true,
        (Some(previous), Some(next)) => next.pin() > previous.pin(),
        _ => false,
    }
}

fn permanent_idempotency_floor_advanced(
    previous: Option<CacheIdempotencyCompactionFloorV1>,
    next: Option<CacheIdempotencyCompactionFloorV1>,
) -> bool {
    match (previous, next) {
        (None, Some(_)) => true,
        (Some(previous), Some(next)) => next.scope() > previous.scope(),
        _ => false,
    }
}

fn valid_idempotency_transition(
    previous: &[CacheIdempotencyBindingV1],
    next: &[CacheIdempotencyBindingV1],
) -> bool {
    if previous == next {
        return true;
    }
    if previous.len() == next.len() {
        let mut changed = previous
            .iter()
            .zip(next)
            .filter(|(before, after)| before != after);
        let Some((before, after)) = changed.next() else {
            return false;
        };
        return changed.next().is_none()
            && before.principal == after.principal
            && before.method == after.method
            && before.key == after.key
            && before.request == after.request
            && before.operation == after.operation
            && !before.terminal
            && before.generation.checked_add(1) == Some(after.generation)
            && after.predecessor == before.digest;
    }
    if previous.len().checked_add(1) != Some(next.len()) {
        return false;
    }
    let mut previous_index = 0;
    let mut next_index = 0;
    let mut added = None;
    while next_index < next.len() {
        if previous_index < previous.len() && previous[previous_index] == next[next_index] {
            previous_index += 1;
            next_index += 1;
        } else if added.is_none() {
            added = Some(next[next_index]);
            next_index += 1;
        } else {
            return false;
        }
    }
    previous_index == previous.len()
        && added.is_some_and(|binding| {
            binding.generation == 1 && binding.predecessor.as_bytes() == &[0; 32]
        })
}

fn valid_watermark_transition(
    previous: &[WatermarkRequirementV1],
    next: &[WatermarkRequirementV1],
    payload: &CacheAtomicObjectPayloadV1,
) -> bool {
    if previous == next {
        return true;
    }

    if previous.len() == next.len() {
        let mut changed = previous
            .iter()
            .zip(next)
            .filter(|(before, after)| before != after);
        let Some((before, after)) = changed.next() else {
            return false;
        };
        return changed.next().is_none()
            && before.reservation == after.reservation
            && before.plan_digest == after.plan_digest
            && before.required_bytes == after.required_bytes
            && before
                .credited_bytes
                .checked_add(eviction_record_reclaimed_bytes(payload))
                == Some(after.credited_bytes)
            && after.credited_bytes <= after.required_bytes;
    }

    if let Some(added) = one_added_watermark(previous, next) {
        return payload.record.kind == CacheRecordKindV1::Admission
            && payload.record.state == AdmissionStageV1::Reserved as u8
            && added.reservation == payload.reservation.id
            && added.plan_digest == payload.plan.digest
            && added.credited_bytes == 0
            && added.required_bytes != 0;
    }

    let Some(removed) = one_added_watermark(next, previous) else {
        return false;
    };
    let abort_released = payload.record.kind == CacheRecordKindV1::Admission
        && payload.record.state == AdmissionStageV1::Aborted as u8
        && payload.reservation.state == ReservationStateV1::Released
        && removed.reservation == payload.reservation.id;
    let reclaimed = eviction_record_reclaimed_bytes(payload);
    abort_released
        || (payload.record.kind == CacheRecordKindV1::EvictionProgress
            && reclaimed != 0
            && removed
                .required_bytes
                .saturating_sub(removed.credited_bytes)
                <= reclaimed)
}

fn one_added_watermark<'a>(
    previous: &'a [WatermarkRequirementV1],
    next: &'a [WatermarkRequirementV1],
) -> Option<&'a WatermarkRequirementV1> {
    if previous.len().checked_add(1) != Some(next.len()) {
        return None;
    }
    let mut previous_index = 0;
    let mut added = None;
    for item in next {
        if previous_index < previous.len() && previous[previous_index] == *item {
            previous_index += 1;
        } else if added.is_none() {
            added = Some(item);
        } else {
            return None;
        }
    }
    (previous_index == previous.len())
        .then_some(added)
        .flatten()
}

fn eviction_record_reclaimed_bytes(payload: &CacheAtomicObjectPayloadV1) -> u64 {
    if payload.record.kind != CacheRecordKindV1::EvictionProgress
        || payload.record.state != EvictionCandidateStateV1::Reclaimed as u8
    {
        return 0;
    }
    usize::try_from(payload.record.amount)
        .ok()
        .and_then(|index| payload.eviction_progress.get(index))
        .map_or(0, |progress| progress.reclaimed_bytes)
}

fn valid_quota_transition(
    previous: &CacheGlobalRecoveryStateV1,
    next: &CacheGlobalRecoveryStateV1,
    state: u8,
) -> bool {
    match state {
        1 => {
            previous.node_quota != next.node_quota && previous.project_quotas == next.project_quotas
        }
        2 => {
            previous.node_quota == next.node_quota
                && one_sorted_change(&previous.project_quotas, &next.project_quotas)
        }
        _ => false,
    }
}

fn valid_handoff_transition(
    previous: &[CacheReadHandoffStateV1],
    next: &[CacheReadHandoffStateV1],
    state: u8,
    payload: &CacheAtomicObjectPayloadV1,
) -> bool {
    let valid_binding = |handoff: &CacheReadHandoffStateV1| {
        handoff.operation == payload.record.operation
            && handoff.descriptor == payload.plan.descriptor
            && handoff.digest == payload.record.evidence
            && payload.catalog.as_ref().is_some_and(|catalog| {
                catalog.digest == handoff.catalog
                    && catalog.backing == handoff.backing
                    && catalog.presence == CatalogPresenceV1::Committed
            })
            && payload.pins.iter().any(|pin| {
                pin.id == handoff.pin
                    && matches!(
                        pin.kind,
                        CachePinKindV1::KernelReference | CachePinKindV1::BackingRegistration
                    )
            })
    };
    if state == 1 {
        return one_added_handoff(previous, next).is_some_and(|handoff| {
            handoff.receipt_evidence.is_none()
                && handoff.cancellation.is_none()
                && valid_binding(handoff)
        });
    }
    if state == 3 {
        return one_removed_handoff(previous, next).is_some_and(|handoff| {
            (handoff.receipt_evidence.is_some() || handoff.cancellation.is_some())
                && handoff.operation == payload.record.operation
                && handoff.descriptor == payload.plan.descriptor
                && handoff.digest == payload.record.evidence
        });
    }
    if state == 4 && previous.len() == next.len() {
        let mut changed = previous
            .iter()
            .zip(next)
            .filter(|(before, after)| before != after);
        let Some((before, after)) = changed.next() else {
            return false;
        };
        return changed.next().is_none()
            && before.operation == after.operation
            && before.operation == payload.record.operation
            && before.authority == after.authority
            && before.catalog == after.catalog
            && before.pin == after.pin
            && before.descriptor == after.descriptor
            && before.backing == after.backing
            && before.preparation_evidence == after.preparation_evidence
            && before.valid_until == after.valid_until
            && before.receipt_evidence.is_none()
            && before.cancellation.is_none()
            && after.receipt_evidence.is_none()
            && after.cancellation.is_some_and(|cancellation| {
                cancellation.target == before.digest
                    && cancellation.authority == payload.record.authority
                    && cancellation.evidence == payload.record.evidence
            });
    }
    if state != 2 || previous.len() != next.len() {
        return false;
    }
    let mut changed = previous
        .iter()
        .zip(next)
        .filter(|(before, after)| before != after);
    let Some((before, after)) = changed.next() else {
        return false;
    };
    changed.next().is_none()
        && before.operation == after.operation
        && before.authority == after.authority
        && before.catalog == after.catalog
        && before.pin == after.pin
        && before.descriptor == after.descriptor
        && before.backing == after.backing
        && before.preparation_evidence == after.preparation_evidence
        && before.valid_until == after.valid_until
        && before.receipt_evidence.is_none()
        && after.receipt_evidence.is_some()
        && before.cancellation.is_none()
        && after.cancellation.is_none()
        && valid_binding(after)
}

fn one_removed_handoff<'a>(
    previous: &'a [CacheReadHandoffStateV1],
    next: &'a [CacheReadHandoffStateV1],
) -> Option<&'a CacheReadHandoffStateV1> {
    if next.len().checked_add(1) != Some(previous.len()) {
        return None;
    }
    let mut next_index = 0;
    let mut removed = None;
    for item in previous {
        if next_index < next.len() && *item == next[next_index] {
            next_index += 1;
        } else if removed.is_none() {
            removed = Some(item);
        } else {
            return None;
        }
    }
    (next_index == next.len()).then_some(removed).flatten()
}

fn one_added_handoff<'a>(
    previous: &'a [CacheReadHandoffStateV1],
    next: &'a [CacheReadHandoffStateV1],
) -> Option<&'a CacheReadHandoffStateV1> {
    if previous.len().checked_add(1) != Some(next.len()) {
        return None;
    }
    let mut previous_index = 0;
    let mut added = None;
    for item in next {
        if previous_index < previous.len() && previous[previous_index] == *item {
            previous_index += 1;
        } else if added.is_none() {
            added = Some(item);
        } else {
            return None;
        }
    }
    (previous_index == previous.len())
        .then_some(added)
        .flatten()
}

fn valid_lookup_transition(
    previous: &[CacheLookupStateV1],
    next: &[CacheLookupStateV1],
    state: u8,
    subject: ObjectDigest,
    authority: ObjectDigest,
    evidence: ObjectDigest,
) -> bool {
    if state == 4 {
        return one_removed_lookup(previous, next).is_some_and(|entry| {
            entry.key == subject && (entry.value.is_some() || entry.cancellation.is_some())
        });
    }
    if state == 5 && previous.len() == next.len() {
        let Some(before) = previous.iter().find(|entry| entry.key == subject) else {
            return false;
        };
        let Some(after) = next.iter().find(|entry| entry.key == subject) else {
            return false;
        };
        return one_sorted_change(previous, next)
            && before.value.is_none()
            && before.cancellation.is_none()
            && after.value.is_none()
            && after.waiters == 0
            && after.in_flight_bytes == 0
            && after.cancellation.is_some_and(|cancellation| {
                cancellation.target == before.key
                    && cancellation.authority == authority
                    && cancellation.evidence == evidence
            });
    }
    if !one_sorted_change(previous, next) {
        return false;
    }
    let expected = match state {
        1 => Some(1),
        2 => Some(2),
        3 => Some(0),
        _ => None,
    };
    let Some(expected) = expected else {
        return false;
    };
    let Some(after) = next.iter().find(|entry| entry.key == subject) else {
        return false;
    };
    let actual = match after.value {
        Some(LookupMemoValueV1::Positive { .. }) => 1,
        Some(LookupMemoValueV1::Negative { .. }) => 2,
        None => 0,
    };
    if actual != expected || previous.contains(after) {
        return false;
    }
    match previous.iter().find(|entry| entry.key == subject) {
        Some(before) if state == 1 || state == 2 => before.value.is_none(),
        Some(before) if state == 3 => {
            before.value.is_none()
                && before.cancellation.is_none()
                && before.in_flight_bytes == after.in_flight_bytes
                && before.waiters.checked_add(1) == Some(after.waiters)
        }
        None => one_added_lookup(previous, next) == Some(after),
        _ => false,
    }
}

fn one_added_lookup<'a>(
    previous: &'a [CacheLookupStateV1],
    next: &'a [CacheLookupStateV1],
) -> Option<&'a CacheLookupStateV1> {
    if previous.len().checked_add(1) != Some(next.len()) {
        return None;
    }
    let mut previous_index = 0;
    let mut added = None;
    for item in next {
        if previous_index < previous.len() && previous[previous_index] == *item {
            previous_index += 1;
        } else if added.is_none() {
            added = Some(item);
        } else {
            return None;
        }
    }
    (previous_index == previous.len())
        .then_some(added)
        .flatten()
}

fn one_removed_lookup<'a>(
    previous: &'a [CacheLookupStateV1],
    next: &'a [CacheLookupStateV1],
) -> Option<&'a CacheLookupStateV1> {
    if next.len().checked_add(1) != Some(previous.len()) {
        return None;
    }
    let mut next_index = 0;
    let mut removed = None;
    for item in previous {
        if next_index < next.len() && *item == next[next_index] {
            next_index += 1;
        } else if removed.is_none() {
            removed = Some(item);
        } else {
            return None;
        }
    }
    (next_index == next.len()).then_some(removed).flatten()
}

fn valid_idempotency_compaction(
    previous: &CacheGlobalRecoveryStateV1,
    next: &CacheGlobalRecoveryStateV1,
) -> bool {
    let Some(floor) = next.idempotency_floor else {
        return false;
    };
    let first_retained = previous.idempotency.partition_point(|binding| {
        (
            *binding.principal.as_bytes(),
            binding.method as u16,
            binding.key,
        ) <= floor.scope()
    });
    first_retained != 0
        && previous.idempotency[..first_retained]
            .iter()
            .all(|binding| binding.terminal)
        && previous.idempotency[first_retained..] == next.idempotency
}

fn one_sorted_change<T: PartialEq>(previous: &[T], next: &[T]) -> bool {
    if previous.len() == next.len() {
        return previous
            .iter()
            .zip(next)
            .filter(|(before, after)| before != after)
            .count()
            == 1;
    }
    let (shorter, longer) = if previous.len().checked_add(1) == Some(next.len()) {
        (previous, next)
    } else if next.len().checked_add(1) == Some(previous.len()) {
        (next, previous)
    } else {
        return false;
    };
    let mut short_index = 0;
    let mut long_index = 0;
    let mut skipped = false;
    while long_index < longer.len() {
        if short_index < shorter.len() && shorter[short_index] == longer[long_index] {
            short_index += 1;
            long_index += 1;
        } else if !skipped {
            skipped = true;
            long_index += 1;
        } else {
            return false;
        }
    }
    short_index == shorter.len() && skipped
}
