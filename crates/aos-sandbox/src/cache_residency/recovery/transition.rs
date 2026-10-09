//! Atomic per-subject transition and projection validation.

use super::*;

pub(super) fn validate_eviction_components(
    payload: &CacheAtomicObjectPayloadV1,
) -> Result<(), RecoveryError> {
    let Some(plan) = &payload.eviction_plan else {
        return if payload.eviction_progress.is_empty() {
            Ok(())
        } else {
            Err(RecoveryError::PayloadMismatch)
        };
    };
    let recovered = FrozenEvictionPlanV1::recover_historical(
        plan.operation,
        plan.partition,
        plan.catalog_generation,
        plan.authority_digest,
        plan.target_reservation,
        plan.target_reclaim_bytes,
        plan.candidates.clone(),
        plan.authority_scope.valid_until(),
    )
    .map_err(|_| RecoveryError::PayloadMismatch)?;
    if &recovered != plan
        || plan.partition != payload.plan.partition
        || payload.eviction_progress.len() != plan.candidates.len()
    {
        return Err(RecoveryError::PayloadMismatch);
    }
    let mut previous_candidate = None;
    let mut host_progress = None;
    for progress in &payload.eviction_progress {
        let recovered = EvictionProgressV1::recover_historical(
            plan,
            progress.candidate.clone(),
            progress.state,
            progress.current_catalog_digest,
            progress.evidence,
            progress.reclaimed_bytes,
        )
        .map_err(|_| RecoveryError::PayloadMismatch)?;
        if &recovered != progress
            || previous_candidate
                .as_ref()
                .is_some_and(|descriptor| descriptor >= &progress.candidate.descriptor)
        {
            return Err(RecoveryError::PayloadMismatch);
        }
        if progress.candidate.descriptor == payload.plan.descriptor {
            host_progress = Some(progress);
        }
        previous_candidate = Some(progress.candidate.descriptor.clone());
    }
    let Some(host_progress) = host_progress else {
        return Err(RecoveryError::PayloadMismatch);
    };
    let Some(catalog) = &payload.catalog else {
        return Err(RecoveryError::PayloadMismatch);
    };
    let expected_presence = match host_progress.state {
        EvictionCandidateStateV1::Selected
        | EvictionCandidateStateV1::RestoredBeforeEffect
        | EvictionCandidateStateV1::RestoredAfterRename => {
            host_progress.candidate.original_presence
        }
        EvictionCandidateStateV1::Deleting
        | EvictionCandidateStateV1::UnlinkAmbiguous
        | EvictionCandidateStateV1::RemovedAwaitingReclaim => CatalogPresenceV1::Deleting,
        EvictionCandidateStateV1::Reclaimed => CatalogPresenceV1::Evicted,
        EvictionCandidateStateV1::Quarantined => CatalogPresenceV1::Quarantined,
    };
    if catalog.digest != host_progress.current_catalog_digest
        || catalog.presence != expected_presence
    {
        return Err(RecoveryError::PayloadMismatch);
    }
    Ok(())
}

pub(super) fn validate_typed_continuity(
    previous: &CacheAtomicObjectPayloadV1,
    next: &CacheAtomicObjectPayloadV1,
    record_kind: CacheRecordKindV1,
) -> Result<(), RecoveryError> {
    if previous.plan != next.plan {
        return Err(RecoveryError::PayloadMismatch);
    }
    if previous.reservation.digest != next.reservation.digest
        && (next.reservation.predecessor != Some(previous.reservation.digest)
            || previous.reservation.generation.checked_add(1) != Some(next.reservation.generation)
            || !valid_reservation_transition(previous.reservation.state, next.reservation.state))
    {
        return Err(RecoveryError::PayloadMismatch);
    }
    match (&previous.catalog, &next.catalog) {
        (None, Some(current)) if current.generation == 1 => {}
        (None, Some(_)) => return Err(RecoveryError::PayloadMismatch),
        (Some(previous), Some(current)) if previous.digest != current.digest => {
            if current.predecessor != Some(previous.digest)
                || previous.generation.checked_add(1) != Some(current.generation)
                || !valid_catalog_transition(previous.presence, current.presence)
            {
                return Err(RecoveryError::PayloadMismatch);
            }
        }
        (Some(_), None) => return Err(RecoveryError::PayloadMismatch),
        _ => {}
    }
    if previous.progress.digest != next.progress.digest
        && (next.progress.predecessor != Some(previous.progress.digest)
            || previous.progress.generation.checked_add(1) != Some(next.progress.generation)
            || !valid_progress_transition(&previous.progress, &next.progress))
    {
        return Err(RecoveryError::PayloadMismatch);
    }
    let previous_pins = replay_pin_projection(&previous.pins, &previous.released_pins)?;
    let next_pins = replay_pin_projection(&next.pins, &next.released_pins)?;
    let reservation_changed = previous.reservation.digest != next.reservation.digest;
    let catalog_changed = previous.catalog != next.catalog;
    let pins_changed = previous_pins != next_pins;
    let progress_changed = previous.progress.digest != next.progress.digest;
    let eviction_plan_changed = previous.eviction_plan != next.eviction_plan;
    let eviction_progress_changed = previous.eviction_progress != next.eviction_progress;
    let eviction_changed = eviction_plan_changed || eviction_progress_changed;
    let scrub_changed = previous.scrub != next.scrub;
    let valid_change_set = match record_kind {
        CacheRecordKindV1::Admission => {
            !eviction_changed
                && !scrub_changed
                && valid_admission_atomic_transition(
                    previous,
                    next,
                    reservation_changed,
                    catalog_changed,
                    pins_changed,
                    progress_changed,
                )?
        }
        CacheRecordKindV1::Reservation => false,
        CacheRecordKindV1::Catalog => false,
        CacheRecordKindV1::Scrub => {
            !reservation_changed
                && !pins_changed
                && !progress_changed
                && !eviction_changed
                && scrub_changed
                && valid_scrub_transition(previous, next, catalog_changed)
        }
        CacheRecordKindV1::Pin => {
            !reservation_changed
                && !catalog_changed
                && pins_changed
                && !progress_changed
                && !eviction_changed
                && !scrub_changed
                && valid_pin_atomic_transition(
                    previous,
                    next,
                    next.record.state,
                    next.record.amount,
                )
        }
        CacheRecordKindV1::EvictionProgress => {
            !pins_changed
                && !progress_changed
                && !eviction_plan_changed
                && eviction_progress_changed
                && !scrub_changed
                && valid_eviction_progress_transition(previous, next)
        }
        CacheRecordKindV1::EvictionPlan => {
            !reservation_changed
                && !catalog_changed
                && !pins_changed
                && !progress_changed
                && eviction_plan_changed
                && previous.eviction_plan.is_none()
                && next.eviction_plan.is_some()
                && previous.eviction_progress.is_empty()
                && valid_eviction_plan_install(next)
                && !scrub_changed
        }
        CacheRecordKindV1::Domain
        | CacheRecordKindV1::Quota
        | CacheRecordKindV1::ReadHandoff
        | CacheRecordKindV1::LookupMemo
        | CacheRecordKindV1::Poison => {
            !reservation_changed
                && !catalog_changed
                && !pins_changed
                && !progress_changed
                && !eviction_changed
                && !scrub_changed
        }
        CacheRecordKindV1::Compaction => valid_compaction_object_transition(
            previous,
            next,
            reservation_changed,
            catalog_changed,
            progress_changed,
            eviction_changed,
            scrub_changed,
        ),
    };
    if !valid_change_set {
        return Err(RecoveryError::PayloadMismatch);
    }
    Ok(())
}

pub(super) fn valid_scrub_transition(
    previous: &CacheAtomicObjectPayloadV1,
    next: &CacheAtomicObjectPayloadV1,
    catalog_changed: bool,
) -> bool {
    if !next.scrub.as_ref().is_some_and(|scrub| {
        previous.catalog.as_ref() == Some(&scrub.prior_catalog)
            && next.catalog.as_ref() == Some(&scrub.resulting_catalog)
    }) {
        return false;
    }
    let presence = previous
        .catalog
        .as_ref()
        .zip(next.catalog.as_ref())
        .map(|(before, after)| (before.presence, after.presence));
    match next.record.state {
        1 => {
            !catalog_changed
                && next
                    .catalog
                    .as_ref()
                    .is_some_and(|entry| entry.presence == CatalogPresenceV1::Committed)
        }
        2 => {
            catalog_changed
                && matches!(
                    presence,
                    Some((CatalogPresenceV1::Committed, CatalogPresenceV1::Quarantined))
                )
        }
        3 => {
            catalog_changed
                && matches!(
                    presence,
                    Some((CatalogPresenceV1::Quarantined, CatalogPresenceV1::Committed))
                )
        }
        _ => false,
    }
}

pub(super) fn valid_compaction_object_transition(
    previous: &CacheAtomicObjectPayloadV1,
    next: &CacheAtomicObjectPayloadV1,
    reservation_changed: bool,
    catalog_changed: bool,
    progress_changed: bool,
    eviction_changed: bool,
    scrub_changed: bool,
) -> bool {
    if reservation_changed
        || catalog_changed
        || progress_changed
        || eviction_changed
        || scrub_changed
    {
        return false;
    }
    match next.record.state {
        1 => {
            previous.pins == next.pins
                && retained_suffix(&previous.released_pins, &next.released_pins)
                && next
                    .global_after
                    .as_ref()
                    .and_then(|global| global.pin_floor)
                    .is_some_and(|floor| {
                        let removed = previous
                            .released_pins
                            .len()
                            .saturating_sub(next.released_pins.len());
                        removed != 0
                            && previous.released_pins[..removed]
                                .iter()
                                .all(|released| released.pin.id <= floor.pin())
                            && next
                                .released_pins
                                .iter()
                                .all(|released| released.pin.id > floor.pin())
                    })
        }
        2 => previous.pins == next.pins && previous.released_pins == next.released_pins,
        _ => false,
    }
}

pub(super) fn retained_suffix<T: PartialEq>(previous: &[T], next: &[T]) -> bool {
    next.len() <= previous.len()
        && previous
            .get(previous.len().saturating_sub(next.len())..)
            .is_some_and(|suffix| suffix == next)
}

pub(super) fn valid_initial_subject(payload: &CacheAtomicObjectPayloadV1) -> bool {
    payload.record.kind == CacheRecordKindV1::Admission
        && payload.record.state == AdmissionStageV1::Reserved as u8
        && payload.record.generation == 1
        && payload.progress.stage == AdmissionStageV1::Reserved
        && payload.progress.generation == 1
        && payload.progress.predecessor.is_none()
        && payload.reservation.state == ReservationStateV1::Reserved
        && payload.reservation.generation == 1
        && payload.reservation.predecessor.is_none()
        && payload.catalog.is_none()
        && payload.pins.is_empty()
        && payload.released_pins.is_empty()
        && payload.eviction_plan.is_none()
        && payload.eviction_progress.is_empty()
        && payload.scrub.is_none()
}

pub(super) fn valid_eviction_plan_install(next: &CacheAtomicObjectPayloadV1) -> bool {
    let Some(plan) = &next.eviction_plan else {
        return false;
    };
    valid_eviction_plan_record_shape(next)
        && plan
            .candidates
            .iter()
            .any(|candidate| candidate.descriptor == next.plan.descriptor)
        && next.eviction_progress.len() == plan.candidates.len()
        && next.eviction_progress.iter().all(|progress| {
            progress.state == EvictionCandidateStateV1::Selected
                && progress.plan_digest == plan.digest
                && plan.contains_candidate(&progress.candidate)
        })
}

pub(super) fn valid_pin_atomic_transition(
    previous: &CacheAtomicObjectPayloadV1,
    next: &CacheAtomicObjectPayloadV1,
    state: u8,
    amount: u64,
) -> bool {
    if state == 1 && previous.released_pins == next.released_pins {
        return one_added_active_pin(&previous.pins, &next.pins).is_some_and(|id| {
            next.pins
                .iter()
                .find(|pin| pin.id == id)
                .is_some_and(|pin| amount == pin.kind as u64)
        });
    }
    if state == 3 && previous.released_pins == next.released_pins {
        return one_renewed_logical_pin(&previous.pins, &next.pins)
            .is_some_and(|_| amount == CachePinKindV1::LogicalLease as u64);
    }
    if state != 2 {
        return false;
    }
    let Some(removed) = one_removed_active_pin(&previous.pins, &next.pins) else {
        return false;
    };
    if one_added_released_pin(&previous.released_pins, &next.released_pins) != Some(removed) {
        return false;
    }
    let removed_pin = previous.pins.iter().find(|pin| pin.id == removed);
    let tombstone = next
        .released_pins
        .iter()
        .find(|released| released.pin.id == removed);
    removed_pin.is_some_and(|pin| {
        tombstone.is_some_and(|released| {
            &released.pin == pin
                && amount == (((pin.kind as u64) << 8) | (released.drain.outcome() as u64))
        })
    })
}

fn one_renewed_logical_pin(
    previous: &[CachePinV1],
    next: &[CachePinV1],
) -> Option<super::super::pin::CachePinId> {
    if previous.len() != next.len() {
        return None;
    }
    let mut renewed = None;
    for (before, after) in previous.iter().zip(next) {
        if before == after {
            continue;
        }
        if renewed.is_some() || !super::super::pin::valid_logical_renewal(before, after) {
            return None;
        }
        renewed = Some(after.id);
    }
    renewed
}

pub(super) fn one_added_active_pin(
    previous: &[CachePinV1],
    next: &[CachePinV1],
) -> Option<super::super::pin::CachePinId> {
    if previous.len().checked_add(1) != Some(next.len()) {
        return None;
    }
    let mut previous_index = 0;
    let mut next_index = 0;
    let mut added = None;
    while next_index < next.len() {
        if previous_index < previous.len() && previous[previous_index] == next[next_index] {
            previous_index += 1;
            next_index += 1;
        } else if added.is_none() {
            added = Some(next[next_index].id);
            next_index += 1;
        } else {
            return None;
        }
    }
    (previous_index == previous.len())
        .then_some(added)
        .flatten()
}

pub(super) fn one_removed_active_pin(
    previous: &[CachePinV1],
    next: &[CachePinV1],
) -> Option<super::super::pin::CachePinId> {
    if next.len().checked_add(1) != Some(previous.len()) {
        return None;
    }
    let mut previous_index = 0;
    let mut next_index = 0;
    let mut removed = None;
    while previous_index < previous.len() {
        if next_index < next.len() && previous[previous_index] == next[next_index] {
            previous_index += 1;
            next_index += 1;
        } else if removed.is_none() {
            removed = Some(previous[previous_index].id);
            previous_index += 1;
        } else {
            return None;
        }
    }
    (next_index == next.len()).then_some(removed).flatten()
}

pub(super) fn one_added_released_pin(
    previous: &[ReleasedCachePinV1],
    next: &[ReleasedCachePinV1],
) -> Option<super::super::pin::CachePinId> {
    if previous.len().checked_add(1) != Some(next.len()) {
        return None;
    }
    let mut previous_index = 0;
    let mut next_index = 0;
    let mut added = None;
    while next_index < next.len() {
        if previous_index < previous.len() && previous[previous_index] == next[next_index] {
            previous_index += 1;
            next_index += 1;
        } else if added.is_none() {
            added = Some(next[next_index].pin.id);
            next_index += 1;
        } else {
            return None;
        }
    }
    (previous_index == previous.len())
        .then_some(added)
        .flatten()
}

pub(super) fn valid_eviction_progress_transition(
    previous: &CacheAtomicObjectPayloadV1,
    next: &CacheAtomicObjectPayloadV1,
) -> bool {
    if previous.eviction_progress.len() != next.eviction_progress.len() {
        return false;
    }
    let mut changed = previous
        .eviction_progress
        .iter()
        .zip(&next.eviction_progress)
        .enumerate()
        .filter(|(_, (before, after))| before != after);
    let Some((changed_index, (before, after))) = changed.next() else {
        return false;
    };
    if changed.next().is_some()
        || before.plan_digest != after.plan_digest
        || before.candidate != after.candidate
        || before.candidate.descriptor != next.plan.descriptor
        || next.record.amount != changed_index as u64
        || next.record.state != after.state as u8
    {
        return false;
    }
    let catalog_transition = previous
        .catalog
        .as_ref()
        .zip(next.catalog.as_ref())
        .map(|(before_entry, after_entry)| (before_entry.presence, after_entry.presence));
    match (before.state, after.state) {
        (EvictionCandidateStateV1::Selected, EvictionCandidateStateV1::RestoredBeforeEffect) => {
            previous.catalog == next.catalog && previous.reservation == next.reservation
        }
        (EvictionCandidateStateV1::Selected, EvictionCandidateStateV1::Deleting) => {
            matches!(
                catalog_transition,
                Some((CatalogPresenceV1::Committed, CatalogPresenceV1::Deleting))
                    | Some((CatalogPresenceV1::Quarantined, CatalogPresenceV1::Deleting))
            ) && previous.reservation == next.reservation
                && !has_eviction_blocker(&previous.pins)
        }
        (EvictionCandidateStateV1::Deleting, EvictionCandidateStateV1::RestoredAfterRename) => {
            matches!(
                catalog_transition,
                Some((CatalogPresenceV1::Deleting, CatalogPresenceV1::Committed))
                    | Some((CatalogPresenceV1::Deleting, CatalogPresenceV1::Quarantined))
            ) && previous.reservation == next.reservation
        }
        (
            EvictionCandidateStateV1::Deleting,
            EvictionCandidateStateV1::UnlinkAmbiguous
            | EvictionCandidateStateV1::RemovedAwaitingReclaim,
        )
        | (
            EvictionCandidateStateV1::UnlinkAmbiguous,
            EvictionCandidateStateV1::Deleting | EvictionCandidateStateV1::RemovedAwaitingReclaim,
        ) => previous.catalog == next.catalog && previous.reservation == next.reservation,
        (
            EvictionCandidateStateV1::Deleting | EvictionCandidateStateV1::UnlinkAmbiguous,
            EvictionCandidateStateV1::Quarantined,
        ) => {
            matches!(
                catalog_transition,
                Some((CatalogPresenceV1::Deleting, CatalogPresenceV1::Quarantined))
            ) && previous.reservation == next.reservation
        }
        (EvictionCandidateStateV1::RemovedAwaitingReclaim, EvictionCandidateStateV1::Reclaimed) => {
            matches!(
                catalog_transition,
                Some((CatalogPresenceV1::Deleting, CatalogPresenceV1::Evicted))
            ) && previous.reservation.state == ReservationStateV1::Converted
                && next.reservation.state == ReservationStateV1::Evicted
                && !has_eviction_blocker(&previous.pins)
        }
        _ => false,
    }
}

pub(super) fn has_eviction_blocker(pins: &[CachePinV1]) -> bool {
    pins.iter()
        .any(|pin| pin.kind != CachePinKindV1::SourceRetention)
}

pub(super) fn valid_admission_atomic_transition(
    previous: &CacheAtomicObjectPayloadV1,
    next: &CacheAtomicObjectPayloadV1,
    reservation_changed: bool,
    catalog_changed: bool,
    pins_changed: bool,
    progress_changed: bool,
) -> Result<bool, RecoveryError> {
    if !progress_changed {
        return Ok(false);
    }
    match next.progress.stage {
        AdmissionStageV1::CatalogCommitted => {
            let initial_pins =
                initial_pin_set_digest(&next.pins).map_err(|_| RecoveryError::PayloadMismatch)?;
            Ok(reservation_changed
                && catalog_changed
                && next.reservation.state == ReservationStateV1::Converted
                && previous.catalog.is_none()
                && next
                    .catalog
                    .as_ref()
                    .is_some_and(|entry| entry.presence == CatalogPresenceV1::Committed)
                && previous.released_pins.is_empty()
                && next.released_pins.is_empty()
                && active_pins_are_retained(&previous.pins, &next.pins)
                && initial_pins == next.plan.initial_pins_digest)
        }
        AdmissionStageV1::Aborted => Ok(reservation_changed
            && !catalog_changed
            && !pins_changed
            && next.record.authority == next.progress.evidence
            && next.record.authority.as_bytes() != &[0; 32]
            && next.reservation.state == ReservationStateV1::Released
            && next.catalog.is_none()
            && next.pins.is_empty()
            && next.released_pins.is_empty()),
        AdmissionStageV1::Uncertain => Ok(reservation_changed
            && !catalog_changed
            && !pins_changed
            && next.reservation.state == ReservationStateV1::Uncertain
            && next.catalog.is_none()),
        _ => Ok(!reservation_changed && !catalog_changed && !pins_changed),
    }
}

pub(super) fn active_pins_are_retained(previous: &[CachePinV1], next: &[CachePinV1]) -> bool {
    let mut previous_index = 0;
    let mut next_index = 0;
    while previous_index < previous.len() && next_index < next.len() {
        if previous[previous_index] == next[next_index] {
            previous_index += 1;
            next_index += 1;
        } else if previous[previous_index].id > next[next_index].id {
            next_index += 1;
        } else {
            return false;
        }
    }
    previous_index == previous.len()
}

pub(super) fn valid_reservation_transition(
    from: ReservationStateV1,
    to: ReservationStateV1,
) -> bool {
    matches!(
        (from, to),
        (ReservationStateV1::Reserved, ReservationStateV1::Uncertain)
            | (ReservationStateV1::Reserved, ReservationStateV1::Converted)
            | (ReservationStateV1::Reserved, ReservationStateV1::Released)
            | (ReservationStateV1::Uncertain, ReservationStateV1::Converted)
            | (ReservationStateV1::Uncertain, ReservationStateV1::Released)
            | (ReservationStateV1::Converted, ReservationStateV1::Evicted)
    )
}

pub(super) fn valid_catalog_transition(from: CatalogPresenceV1, to: CatalogPresenceV1) -> bool {
    matches!(
        (from, to),
        (CatalogPresenceV1::Committed, CatalogPresenceV1::Deleting)
            | (CatalogPresenceV1::Committed, CatalogPresenceV1::Quarantined)
            | (CatalogPresenceV1::Deleting, CatalogPresenceV1::Committed)
            | (CatalogPresenceV1::Deleting, CatalogPresenceV1::Quarantined)
            | (CatalogPresenceV1::Deleting, CatalogPresenceV1::Evicted)
            | (CatalogPresenceV1::Quarantined, CatalogPresenceV1::Deleting)
            | (CatalogPresenceV1::Quarantined, CatalogPresenceV1::Committed)
    )
}

pub(super) fn valid_progress_transition(
    from: &AdmissionProgressV1,
    to: &AdmissionProgressV1,
) -> bool {
    let from_stage = from.stage as u8;
    let to_stage = to.stage as u8;
    (from_stage <= 8 && to_stage == from_stage + 1)
        || (from.stage == AdmissionStageV1::ParentSynced
            && to.stage == AdmissionStageV1::CatalogCommitted)
        || ((2..=9).contains(&from_stage) && to.stage == AdmissionStageV1::Uncertain)
        || (from.stage == AdmissionStageV1::Uncertain
            && (matches!(
                to.stage,
                AdmissionStageV1::Quarantined | AdmissionStageV1::Aborted
            ) || (to.stage != AdmissionStageV1::CatalogCommitted
                && to.stage != AdmissionStageV1::Uncertain
                && (to.stage as u8) >= (from.last_certain_stage as u8))))
        || (!matches!(
            from.stage,
            AdmissionStageV1::CatalogCommitted
                | AdmissionStageV1::Quarantined
                | AdmissionStageV1::Aborted
        ) && to.stage == AdmissionStageV1::Aborted)
}

pub(super) fn replay_pin_projection(
    pins: &[CachePinV1],
    released: &[ReleasedCachePinV1],
) -> Result<ObjectDigest, RecoveryError> {
    let active = initial_pin_set_digest(pins).map_err(|_| RecoveryError::PayloadMismatch)?;
    let mut previous = None;
    let mut hasher = sha2::Sha256::new();
    use sha2::Digest as _;
    hasher.update(b"aos.sandbox.cache.replay-pin-projection.v1\0");
    hasher.update(active.as_bytes());
    hasher.update((released.len() as u64).to_be_bytes());
    let mut active_index = 0;
    for tombstone in released {
        tombstone
            .pin
            .clone()
            .validate()
            .map_err(|_| RecoveryError::PayloadMismatch)?;
        tombstone
            .drain
            .validate_replay(&tombstone.pin)
            .map_err(|_| RecoveryError::PayloadMismatch)?;
        while active_index < pins.len() && pins[active_index].id < tombstone.pin.id {
            active_index += 1;
        }
        if previous.is_some_and(|id| id >= tombstone.pin.id)
            || pins
                .get(active_index)
                .is_some_and(|pin| pin.id == tombstone.pin.id)
        {
            return Err(RecoveryError::PayloadMismatch);
        }
        previous = Some(tombstone.pin.id);
        hasher.update(tombstone.pin.id.as_bytes());
        hasher.update(tombstone.drain.digest().as_bytes());
        hasher.update([tombstone.drain.outcome() as u8]);
    }
    Ok(ObjectDigest::from_bytes(hasher.finalize().into()))
}

pub(super) fn empty_catalog_projection() -> ObjectDigest {
    let mut hasher = sha2::Sha256::new();
    use sha2::Digest as _;
    hasher.update(b"aos.sandbox.cache.empty-catalog-projection.v1\0");
    ObjectDigest::from_bytes(hasher.finalize().into())
}
