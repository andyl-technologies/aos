//! Canonical single-event construction for a protected logical pin release.

use super::*;

impl CacheRecoveryInventoryV1 {
    /// Builds the exact next Pin event for one retained logical obligation.
    ///
    /// The inventory and pin are historical facts, not commit authority. The
    /// caller must obtain a current PinDrain capability from independent
    /// protected evidence and commit the returned payload through the protected
    /// journal, which replays the predecessor and checks the full transition.
    ///
    /// # Errors
    ///
    /// Returns an error for a poisoned or mismatched inventory, a stale drain
    /// capability, exhausted history, invalid pin accounting, or a noncanonical
    /// successor payload.
    #[allow(clippy::too_many_arguments)]
    pub(crate) fn plan_logical_pin_release(
        &self,
        owner: &CacheAuthorityOwner<'_, '_>,
        capability: &VerifiedCacheCapabilityV1,
        pin: &CachePinV1,
        operation: OperationId,
        valid_until: u64,
        now: u64,
        limits: CacheRecoveryLimitsV1,
    ) -> Result<(CacheAtomicObjectPayloadV1, ReleasedCachePinV1), RecoveryError> {
        let limits = limits.validate()?;
        if self.authority_poisoned || pin.kind != CachePinKindV1::LogicalLease {
            return Err(RecoveryError::PayloadMismatch);
        }

        let subject = object_descriptor_commitment(&pin.object);
        let previous = self
            .reconstructed
            .iter()
            .find(|payload| {
                payload.record.subject == subject
                    && payload.plan.partition == pin.partition
                    && payload.plan.project == pin.project
                    && payload.plan.descriptor == pin.object
            })
            .ok_or(RecoveryError::PayloadMismatch)?;
        let pin_index = previous
            .pins
            .iter()
            .position(|candidate| candidate == pin)
            .ok_or(RecoveryError::PayloadMismatch)?;
        let family_head = self
            .family_heads
            .iter()
            .find(|head| head.subject == subject && head.kind == CacheRecordKindV1::Pin)
            .ok_or(RecoveryError::SubjectRollback)?;

        // A logical pin never installs a kernel-like reference of its own.
        // Independent kernel/backing pins remain in the complete pin set.
        let drain = PinDrainEvidenceV1::from_verified(
            owner,
            capability,
            pin,
            PinDrainOutcomeV1::NeverInstalled,
            valid_until,
            now,
        )?;
        let released = ReleasedCachePinV1 {
            pin: pin.clone(),
            drain,
        };
        let mut next = previous.clone();
        next.pins.remove(pin_index);
        let tombstone_index = match next
            .released_pins
            .binary_search_by_key(&pin.id, |candidate| candidate.pin.id)
        {
            Ok(_) => return Err(RecoveryError::IdentityConflict),
            Err(index) => index,
        };
        next.released_pins.insert(tombstone_index, released.clone());
        next.global_after = Some(self.global.clone());

        let mut subjects = BTreeMap::new();
        for payload in &self.reconstructed {
            if subjects
                .insert(payload.record.subject, payload.clone())
                .is_some()
            {
                return Err(RecoveryError::IdentityConflict);
            }
        }
        subjects.insert(subject, next.clone());
        let (catalog, reservation, pins, progress) = aggregate_projections(&subjects)?;
        RecoveredAccountingProjection::from_subjects(&self.global, &subjects, limits)?;

        let sequence = self
            .head_sequence
            .checked_add(1)
            .ok_or(RecoveryError::HistoryOverflow)?;
        let generation = family_head
            .generation
            .checked_add(1)
            .ok_or(RecoveryError::HistoryOverflow)?;
        let model = atomic_projection_digest(catalog, reservation, pins, progress);
        let payload_digest = canonical_payload_digest(&next, limits)?;
        let authority_record = capability.record_digest();
        next.record = CacheDurableRecordV1::new(
            CacheRecordKindV1::Pin,
            2,
            sequence,
            operation,
            subject,
            pin.partition.digest(),
            next.plan.digest,
            model,
            authority_record,
            authority_record,
            catalog,
            reservation,
            pins,
            progress,
            payload_digest,
            ((pin.kind as u64) << 8) | PinDrainOutcomeV1::NeverInstalled as u64,
            generation,
            family_head.record_digest,
            self.head_digest,
        )?;
        next.validate(limits)?;
        validate_typed_continuity(previous, &next, CacheRecordKindV1::Pin)?;

        Ok((next, released))
    }
}
