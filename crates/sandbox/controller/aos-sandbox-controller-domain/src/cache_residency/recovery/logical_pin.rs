//! Complete protected logical-pin planning and canonical successors.
//!
//! Acquisition and renewal validate the complete retained ledger and current
//! PinAcquire evidence; release validates the exact retained pin and PinDrain
//! evidence. One closed successor recipe preserves their canonical history,
//! accounting and digest order. Returned payloads remain plans: protected commit
//! and independent physical settlement stay with the native Cache owners.

use super::*;
use crate::cache_residency::pin::{CachePinV1, CachePinLedgerV1,
    PinCompactionFloorV1, PinDrainEvidenceV1, ReleasedCachePinV1};
use aos_sandbox_protocol::cache_state::pin_ledger::ReleasedCachePinDataV1;

// Release retains its already-required family head; acquisition and renewal
// can begin the Pin family. This selector carries historical references only.
#[derive(Clone, Copy)]
enum LogicalPinEvent<'head> {
    Acquire(Option<&'head CacheSubjectFamilyHeadV1>),
    Renew(Option<&'head CacheSubjectFamilyHeadV1>),
    Release(&'head CacheSubjectFamilyHeadV1),
}

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
            active.extend(payload.pins.iter().cloned().map(CachePinV1::from_parsed_history_data_v1));
            released.extend(payload.released_pins.iter().map(|released| ReleasedCachePinV1 {
                pin: CachePinV1::from_parsed_history_data_v1(released.pin.clone()),
                drain: PinDrainEvidenceV1::from_parsed_history_data_v1(released.drain),
            }));
        }
        let mut ledger = CachePinLedgerV1::replay(
            limits.maximum_records,
            self.global.pin_floor.map(PinCompactionFloorV1::from_parsed_history_data_v1),
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
            (Ok(index), Some(previous_pin)) if state == 3 && &next.pins[index] == previous_pin.historical_data_v1() => {
                index
            }
            (Ok(_), _) => return Err(RecoveryError::IdentityConflict),
            (Err(index), None) if state == 1 => index,
            (Err(_), _) => return Err(RecoveryError::PayloadMismatch),
        };
        if state == 3 {
            next.pins[pin_index] = pin.historical_data_v1().clone();
        } else {
            next.pins.insert(pin_index, pin.historical_data_v1().clone());
        }
        next.global_after = Some(self.global.clone());

        let mut subjects = BTreeMap::new();
        self.finish_logical_pin_event(
            previous,
            &mut next,
            &mut subjects,
            operation,
            capability,
            if state == 3 {
                LogicalPinEvent::Renew(family_head)
            } else {
                LogicalPinEvent::Acquire(family_head)
            },
            limits,
        )?;

        Ok(next)
    }

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
            .position(|candidate| candidate == pin.historical_data_v1())
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
        next.released_pins.insert(tombstone_index, ReleasedCachePinDataV1 {
            pin: released.pin.historical_data_v1().clone(),
            drain: released.drain.historical_data_v1(),
        });
        next.global_after = Some(self.global.clone());

        let mut subjects = BTreeMap::new();
        self.finish_logical_pin_event(
            previous,
            &mut next,
            &mut subjects,
            operation,
            capability,
            LogicalPinEvent::Release(family_head),
            limits,
        )?;

        Ok((next, released))
    }

    // Both unchanged entry gates already prove the predecessor's subject and
    // partition match the pin and its kind is LogicalLease. These Copy facts
    // select the same record values; no current authority is inferred here.
    // Caller-owned subjects and next remain borrowed to preserve drop points.
    #[allow(clippy::too_many_arguments)]
    fn finish_logical_pin_event(
        &self,
        previous: &CacheAtomicObjectPayloadV1,
        next: &mut CacheAtomicObjectPayloadV1,
        subjects: &mut BTreeMap<ObjectDigest, CacheAtomicObjectPayloadV1>,
        operation: OperationId,
        capability: &VerifiedCacheCapabilityV1,
        event: LogicalPinEvent<'_>,
        limits: CacheRecoveryLimitsV1,
    ) -> Result<(), RecoveryError> {
        for payload in &self.reconstructed {
            if subjects
                .insert(payload.record.subject, payload.clone())
                .is_some()
            {
                return Err(RecoveryError::IdentityConflict);
            }
        }
        subjects.insert(previous.record.subject, next.clone());
        let (catalog, reservation, pins, progress) = aggregate_projections(&subjects)?;
        RecoveredAccountingProjection::from_subjects(&self.global, &subjects, limits)?;

        let sequence = self
            .head_sequence
            .checked_add(1)
            .ok_or(RecoveryError::HistoryOverflow)?;
        let family_head = match event {
            LogicalPinEvent::Acquire(head) | LogicalPinEvent::Renew(head) => head,
            LogicalPinEvent::Release(head) => Some(head),
        };
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
        let payload_digest = canonical_payload_digest(next, limits)?;
        let authority_record = capability.record_digest();
        next.record = CacheDurableRecordV1::new(
            CacheRecordKindV1::Pin,
            match event {
                LogicalPinEvent::Acquire(_) => 1,
                LogicalPinEvent::Renew(_) => 3,
                LogicalPinEvent::Release(_) => 2,
            },
            sequence,
            operation,
            previous.record.subject,
            previous.plan.partition.digest(),
            next.plan.digest,
            model,
            authority_record,
            authority_record,
            catalog,
            reservation,
            pins,
            progress,
            payload_digest,
            match event {
                LogicalPinEvent::Acquire(_) | LogicalPinEvent::Renew(_) => {
                    CachePinKindV1::LogicalLease as u64
                }
                LogicalPinEvent::Release(_) => {
                    ((CachePinKindV1::LogicalLease as u64) << 8)
                        | PinDrainOutcomeV1::NeverInstalled as u64
                }
            },
            generation,
            family_predecessor,
            self.head_digest,
        )?;
        next.validate(limits)?;
        validate_typed_continuity(previous, next, CacheRecordKindV1::Pin)?;

        Ok(())
    }
}
