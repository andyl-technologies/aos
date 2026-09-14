//! Replay-wide identity uniqueness, pin retention, and floor validation.

use super::*;

pub(super) fn pin_is_above_floor(pin: CachePinId, floor: Option<PinCompactionFloorV1>) -> bool {
    floor.is_none_or(|floor| pin > floor.pin())
}

#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub(super) struct GlobalIdentityIndex {
    reservations: BTreeMap<[u8; 16], ObjectDigest>,
    operations: BTreeMap<[u8; 16], ObjectDigest>,
    pins: BTreeMap<[u8; 16], ObjectDigest>,
    backings: BTreeMap<[u8; 32], ObjectDigest>,
}

impl GlobalIdentityIndex {
    pub(super) fn from_subjects(
        subjects: &BTreeMap<ObjectDigest, CacheAtomicObjectPayloadV1>,
    ) -> Result<Self, RecoveryError> {
        let mut index = Self::default();
        for (subject, payload) in subjects {
            index.observe(*subject, payload)?;
        }
        Ok(index)
    }

    pub(super) fn observe(
        &mut self,
        subject: ObjectDigest,
        payload: &CacheAtomicObjectPayloadV1,
    ) -> Result<(), RecoveryError> {
        insert_unique(
            &mut self.reservations,
            *payload.reservation.id.as_bytes(),
            subject,
        )?;
        insert_unique(
            &mut self.operations,
            *payload.plan.operation.as_bytes(),
            subject,
        )?;
        if let Some(catalog) = &payload.catalog {
            insert_unique(&mut self.backings, *catalog.backing.as_bytes(), subject)?;
        }
        for pin in &payload.pins {
            insert_unique(&mut self.pins, *pin.id.as_bytes(), subject)?;
        }
        for released in &payload.released_pins {
            insert_unique(&mut self.pins, *released.pin.id.as_bytes(), subject)?;
        }
        Ok(())
    }
}

#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub(super) struct RetainedPinTombstoneIndex {
    active: BTreeMap<CachePinId, ObjectDigest>,
    released: BTreeMap<CachePinId, ObjectDigest>,
}

impl RetainedPinTombstoneIndex {
    pub(super) fn from_subjects(
        subjects: &BTreeMap<ObjectDigest, CacheAtomicObjectPayloadV1>,
        maximum: usize,
    ) -> Result<Self, RecoveryError> {
        let mut index = Self::default();
        for (subject, payload) in subjects {
            for pin in &payload.pins {
                if index
                    .active
                    .len()
                    .checked_add(index.released.len())
                    .is_none_or(|count| count >= maximum)
                {
                    return Err(RecoveryError::Capacity);
                }
                if index.active.insert(pin.id, *subject).is_some() {
                    return Err(RecoveryError::IdentityConflict);
                }
            }
            for released in &payload.released_pins {
                if index
                    .active
                    .len()
                    .checked_add(index.released.len())
                    .is_none_or(|count| count >= maximum)
                {
                    return Err(RecoveryError::Capacity);
                }
                if index.released.insert(released.pin.id, *subject).is_some() {
                    return Err(RecoveryError::IdentityConflict);
                }
            }
        }
        Ok(index)
    }

    pub(super) fn replace(
        &mut self,
        previous: Option<&CacheAtomicObjectPayloadV1>,
        next: &CacheAtomicObjectPayloadV1,
        maximum: usize,
    ) -> Result<(), RecoveryError> {
        if let Some(previous) = previous {
            for pin in &previous.pins {
                self.active.remove(&pin.id);
            }
            for released in &previous.released_pins {
                self.released.remove(&released.pin.id);
            }
        }
        if self
            .active
            .len()
            .checked_add(self.released.len())
            .and_then(|count| count.checked_add(next.pins.len()))
            .and_then(|count| count.checked_add(next.released_pins.len()))
            .is_none_or(|count| count > maximum)
        {
            return Err(RecoveryError::Capacity);
        }
        for pin in &next.pins {
            if self.active.insert(pin.id, next.record.subject).is_some() {
                return Err(RecoveryError::IdentityConflict);
            }
        }
        for released in &next.released_pins {
            if self
                .released
                .insert(released.pin.id, next.record.subject)
                .is_some()
            {
                return Err(RecoveryError::IdentityConflict);
            }
        }
        Ok(())
    }

    pub(super) fn validate_floor(
        &self,
        floor: Option<PinCompactionFloorV1>,
    ) -> Result<(), RecoveryError> {
        if floor.is_some_and(|floor| {
            self.active
                .keys()
                .any(|pin| !pin_is_above_floor(*pin, Some(floor)))
                || self
                    .released
                    .keys()
                    .any(|pin| !pin_is_above_floor(*pin, Some(floor)))
        }) {
            return Err(RecoveryError::SubjectRollback);
        }
        Ok(())
    }
}

fn insert_unique<const N: usize>(
    index: &mut BTreeMap<[u8; N], ObjectDigest>,
    identity: [u8; N],
    subject: ObjectDigest,
) -> Result<(), RecoveryError> {
    if index
        .insert(identity, subject)
        .is_some_and(|owner| owner != subject)
    {
        return Err(RecoveryError::IdentityConflict);
    }
    Ok(())
}

#[allow(clippy::too_many_arguments)]
pub(super) fn replay_subject(
    checkpoint: ObjectDigest,
    floor: ObjectDigest,
    head_sequence: u64,
    head: ObjectDigest,
    record_count: usize,
    catalog: ObjectDigest,
    reservation: ObjectDigest,
    pins: ObjectDigest,
    progress: ObjectDigest,
    global: ObjectDigest,
) -> ObjectDigest {
    use sha2::{Digest as _, Sha256};
    let mut hasher = Sha256::new();
    hasher.update(b"aos.sandbox.cache.recovery-replay-subject.v1\0");
    hasher.update(checkpoint.as_bytes());
    hasher.update(floor.as_bytes());
    hasher.update(head_sequence.to_be_bytes());
    hasher.update(head.as_bytes());
    hasher.update((record_count as u64).to_be_bytes());
    hasher.update(catalog.as_bytes());
    hasher.update(reservation.as_bytes());
    hasher.update(pins.as_bytes());
    hasher.update(progress.as_bytes());
    hasher.update(global.as_bytes());
    ObjectDigest::from_bytes(hasher.finalize().into())
}

pub(super) fn replay_inventory_binding(inventory: &CacheRecoveryInventoryV1) -> ObjectDigest {
    use sha2::{Digest as _, Sha256};

    let mut hasher = Sha256::new();
    hasher.update(b"aos.sandbox.cache.verified-replay-inventory.v1\0");
    hasher.update(inventory.checkpoint.as_bytes());
    hasher.update(inventory.floor.as_bytes());
    hasher.update(inventory.head_sequence.to_be_bytes());
    hasher.update(inventory.head_digest.as_bytes());
    hasher.update(inventory.catalog_projection.as_bytes());
    hasher.update(inventory.reservation_projection.as_bytes());
    hasher.update(inventory.pin_projection.as_bytes());
    hasher.update(inventory.progress_projection.as_bytes());
    hasher.update((inventory.reconstructed.len() as u64).to_be_bytes());
    for payload in &inventory.reconstructed {
        hasher.update(payload.record.digest.as_bytes());
    }
    hasher.update((inventory.family_heads.len() as u64).to_be_bytes());
    for head in &inventory.family_heads {
        hasher.update(head.subject.as_bytes());
        hasher.update([head.kind as u8]);
        hasher.update(head.generation.to_be_bytes());
        hasher.update(head.record_digest.as_bytes());
    }
    hasher.update(inventory.global.digest.as_bytes());
    hasher.update(inventory.replay_authority.as_bytes());
    ObjectDigest::from_bytes(hasher.finalize().into())
}
