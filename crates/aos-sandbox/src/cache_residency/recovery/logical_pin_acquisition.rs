//! Canonical single-event construction for protected logical pin acquisition.

use super::*;

impl CacheRecoveryInventoryV1 {
    /// Builds the next Pin event for one new or renewable logical obligation.
    ///
    /// This constructor validates the complete retained ledger and the exact
    /// PinAcquire capability. It does not prove that the consumer's current
    /// View source contains the object; the authority issuer and public
    /// controller must establish that independently before this is called.
    ///
    /// # Errors
    ///
    /// Returns an error for poisoned or mismatched state, an occupied logical
    /// consumer, stale acquisition authority, or a noncanonical successor.
    #[allow(clippy::too_many_arguments)]
    pub(crate) fn plan_logical_pin_acquisition(
        &self,
        owner: &CacheAuthorityOwner<'_, '_>,
        capability: &VerifiedCacheCapabilityV1,
        pin: CachePinV1,
        operation: OperationId,
        now: u64,
        limits: CacheRecoveryLimitsV1,
    ) -> Result<CacheAtomicObjectPayloadV1, RecoveryError> {
        let limits = limits.validate()?;
        if self.authority_poisoned
            || pin.kind != CachePinKindV1::LogicalLease
            || pin.partition != self.global.node_quota.partition
        {
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
        let family_head = self
            .family_heads
            .iter()
            .find(|head| head.subject == subject && head.kind == CacheRecordKindV1::Pin);

        let mut active = Vec::new();
        let mut released = Vec::new();
        for payload in &self.reconstructed {
            active.extend(payload.pins.iter().cloned());
            released.extend(payload.released_pins.iter().cloned());
        }
        let mut ledger = CachePinLedgerV1::replay(
            limits.maximum_records,
            self.global.pin_floor,
            active,
            released,
        )?;
        let existing = ledger
            .logical_consumer_pin(
                pin.partition,
                &pin.object,
                pin.project,
                pin.view,
                pin.attachment,
            )
            .cloned();
        let state = if let Some(previous_pin) = &existing {
            if previous_pin == &pin {
                return Err(RecoveryError::PayloadMismatch);
            }
            ledger.renew_logical(owner, capability, pin.clone(), now)?;
            3
        } else {
            if pin.id != ledger.next_pin_id()? {
                return Err(RecoveryError::IdentityConflict);
            }
            ledger.acquire(owner, capability, pin.clone(), now)?;
            1
        };

        let mut next = previous.clone();
        let pin_index = match (
            next.pins
                .binary_search_by_key(&pin.id, |candidate| candidate.id),
            existing.as_ref(),
        ) {
            (Ok(index), Some(previous_pin)) if state == 3 && &next.pins[index] == previous_pin => {
                index
            }
            (Ok(_), _) => return Err(RecoveryError::IdentityConflict),
            (Err(index), None) if state == 1 => index,
            (Err(_), _) => return Err(RecoveryError::PayloadMismatch),
        };
        if state == 3 {
            next.pins[pin_index] = pin.clone();
        } else {
            next.pins.insert(pin_index, pin.clone());
        }
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
        let (generation, family_predecessor) = match family_head {
            Some(head) => (
                head.generation
                    .checked_add(1)
                    .ok_or(RecoveryError::HistoryOverflow)?,
                head.record_digest,
            ),
            None => (1, ObjectDigest::from_bytes([0; 32])),
        };
        let model = atomic_projection_digest(catalog, reservation, pins, progress);
        let payload_digest = canonical_payload_digest(&next, limits)?;
        let authority_record = capability.record_digest();
        next.record = CacheDurableRecordV1::new(
            CacheRecordKindV1::Pin,
            state,
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
            pin.kind as u64,
            generation,
            family_predecessor,
            self.head_digest,
        )?;
        next.validate(limits)?;
        validate_typed_continuity(previous, &next, CacheRecordKindV1::Pin)?;

        Ok(next)
    }
}
