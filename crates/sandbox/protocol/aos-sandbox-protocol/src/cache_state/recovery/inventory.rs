//! Staged complete historical replay through its authority-comparison frontier.

use super::*;

/// Holds the exact historical replay prefix at its authority comparison frontier.
///
/// This is DATA, not a Native inventory or capability. The Native coordinator
/// performs its original fresh capability check before finishing assembly.
pub struct CacheRecoveryAssemblyDataV1 {
    work: Vec<CacheRecoveryWorkV1>,
    accounting: RecoveredAccountingProjection,
    projections: ProjectionAccumulator,
    retained_pin_tombstones: RetainedPinTombstoneIndex,
    identities: GlobalIdentityIndex,
    family_heads: BTreeMap<(ObjectDigest, u8), (u64, ObjectDigest)>,
    latest: BTreeMap<ObjectDigest, CacheAtomicObjectPayloadV1>,
    global: CacheGlobalRecoveryStateV1,
    checkpoint_global: CacheGlobalRecoveryStateV1,
    authority_scope: CacheAuthorityScopeV1,
    typed_checkpoint_digest: ObjectDigest,
    floor: CacheHistoryFloorV1,
    head_sequence: u64,
    expected_predecessor: ObjectDigest,
    authority_poisoned: bool,
    catalog_projection: ObjectDigest,
    reservation_projection: ObjectDigest,
    pin_projection: ObjectDigest,
    progress_projection: ObjectDigest,
    authority_record: ObjectDigest,
}

impl CacheRecoveryAssemblyDataV1 {
    /// Returns the historical scope derived by the original complete replay.
    #[must_use]
    pub const fn authority_scope_data_v1(&self) -> CacheAuthorityScopeV1 {
        self.authority_scope
    }

    /// Finishes historical inventory assembly after the caller's comparison.
    ///
    /// This constructs DATA only and accepts no success token, boolean or callback.
    ///
    /// # Errors
    ///
    /// Returns [`RecoveryError`] for invalid final family codes.
    pub fn finish_data_v1(
        self,
        selection: &mut CacheRecoverySelectionV1,
    ) -> Result<CacheRecoveryInventoryDataV1, RecoveryError> {
        let Self {
            checkpoint_global: _checkpoint_global, global, latest, family_heads,
            identities: _identities, retained_pin_tombstones: _retained_pin_tombstones,
            projections: _projections, accounting, work,
            authority_scope: _, typed_checkpoint_digest, floor, head_sequence,
            expected_predecessor, authority_poisoned, catalog_projection,
            reservation_projection, pin_projection, progress_projection,
            authority_record,
        } = self;
        selection.retain(&accounting);
        let reconstructed = latest.into_values().collect::<Vec<_>>();
        let mut recovered_family_heads = Vec::with_capacity(family_heads.len());
        for ((subject, kind), (generation, record_digest)) in family_heads {
            recovered_family_heads.push(CacheSubjectFamilyHeadV1 {
                subject,
                kind: record_kind(kind)?,
                generation,
                record_digest,
            });
        }
        let mut inventory = CacheRecoveryInventoryDataV1 {
            checkpoint: typed_checkpoint_digest,
            floor: floor.digest,
            head_sequence,
            head_digest: expected_predecessor,
            work,
            authority_poisoned,
            catalog_projection,
            reservation_projection,
            pin_projection,
            progress_projection,
            reconstructed,
            family_heads: recovered_family_heads,
            global,
            replay_authority: authority_record,
            replay_binding: ObjectDigest::from_bytes([0; 32]),
        };
        inventory.replay_binding = replay_inventory_binding(&inventory);
        Ok(inventory)
    }
}

/// Replays every retained historical record to its exact comparison frontier.
///
/// # Errors
///
/// Returns [`RecoveryError`] for invalid anchors, record/family history,
/// typed transitions, identity/usage projections or bounded capacity.
#[allow(clippy::too_many_arguments)]
pub fn prepare_historical_recovery_data_v1(
    partition: PhysicalPartitionId,
    typed_checkpoint_bytes: &[u8],
    prior_typed_checkpoint_bytes: Option<&[u8]>,
    floor: CacheHistoryFloorV1,
    records: impl IntoIterator<Item = Vec<u8>>,
    limits: CacheRecoveryLimitsV1,
    authority_valid_until: u64,
    authority_record: ObjectDigest,
) -> Result<CacheRecoveryAssemblyDataV1, RecoveryError> {
        let limits = limits.validate()?;
        let typed_checkpoint = decode_typed_checkpoint(partition, typed_checkpoint_bytes, limits)?;
        match prior_typed_checkpoint_bytes {
            Some(bytes) => {
                let prior = decode_typed_checkpoint(partition, bytes, limits)?;
                validate_checkpoint_successor(&prior, &typed_checkpoint)?;
            }
            None if typed_checkpoint.checkpoint.predecessor.as_bytes() == &[0; 32] => {}
            None => return Err(RecoveryError::AnchorMismatch),
        }
        let typed_checkpoint_digest = typed_checkpoint.digest;
        let mut global = typed_checkpoint.global.clone();
        let checkpoint = typed_checkpoint.checkpoint;
        floor.validate()?;
        if checkpoint.catalog_entries > limits.maximum_subjects as u64
            || checkpoint.reservations > limits.maximum_subjects as u64
            || checkpoint.pins > limits.maximum_subjects as u64
            || checkpoint.lookup_entries > limits.maximum_subjects as u64
            || checkpoint.pending_effects > limits.maximum_work_items as u64
        {
            return Err(RecoveryError::Capacity);
        }
        if checkpoint.projection
            != atomic_projection_digest(
                checkpoint.catalog_projection,
                checkpoint.reservation_projection,
                checkpoint.pin_projection,
                checkpoint.progress_projection,
            )
        {
            return Err(RecoveryError::ProjectionMismatch);
        }
        if floor.checkpoint != checkpoint.digest
            || floor.retained_history_root != checkpoint.history_head
            || floor.first_retained_sequence
                != checkpoint
                    .sequence
                    .checked_add(1)
                    .ok_or(RecoveryError::HistoryOverflow)?
        {
            return Err(RecoveryError::AnchorMismatch);
        }

        let mut latest = BTreeMap::<ObjectDigest, CacheAtomicObjectPayloadV1>::new();
        for baseline in typed_checkpoint.baselines {
            if latest.insert(baseline.record.subject, baseline).is_some() {
                return Err(RecoveryError::PayloadMismatch);
            }
        }
        let mut family_heads = BTreeMap::<(ObjectDigest, u8), (u64, ObjectDigest)>::new();
        for head in typed_checkpoint.family_heads {
            if family_heads
                .insert(
                    (head.subject, head.kind as u8),
                    (head.generation, head.record_digest),
                )
                .is_some()
            {
                return Err(RecoveryError::PayloadMismatch);
            }
        }
        let mut identities = GlobalIdentityIndex::from_subjects(&latest)?;
        let mut retained_pin_tombstones =
            RetainedPinTombstoneIndex::from_subjects(&latest, limits.maximum_records)?;
        let mut projections = ProjectionAccumulator::from_subjects(&latest)?;
        let mut accounting =
            RecoveredAccountingProjection::from_subjects(&global, &latest, limits)?;
        let mut expected_sequence = floor.first_retained_sequence;
        let mut expected_predecessor = checkpoint.history_head;
        let mut record_count = 0usize;
        for bytes in records {
            record_count = record_count.checked_add(1).ok_or(RecoveryError::Capacity)?;
            if record_count > limits.maximum_records {
                return Err(RecoveryError::Capacity);
            }
            let input = decode_atomic_object_record(partition, &bytes, limits)?;
            let record = input.record;
            let next_global = input
                .global_after
                .as_ref()
                .ok_or(RecoveryError::PayloadMismatch)?;
            validate_global_transition(&global, next_global, &input, typed_checkpoint_digest)?;
            global = next_global.clone();
            if record.kind == CacheRecordKindV1::Poison && global.poison.is_none() {
                global.poison = Some(CachePoisonLatchV1 {
                    operation: record.operation,
                    record_digest: record.digest,
                });
                global.digest = global_state_digest(&global, limits)?;
            }
            if record.model
                != atomic_projection_digest(
                    record.catalog_projection,
                    record.reservation_projection,
                    record.pin_projection,
                    record.progress_projection,
                )
            {
                return Err(RecoveryError::ProjectionMismatch);
            }
            if record.sequence != expected_sequence || record.predecessor != expected_predecessor {
                return Err(RecoveryError::BrokenHistory);
            }
            let subject_key = record.subject;
            if let Some(previous) = latest.get(&subject_key) {
                validate_typed_continuity(previous, &input, record.kind)?;
            } else if latest.len() >= limits.maximum_subjects {
                return Err(RecoveryError::Capacity);
            } else if !valid_initial_subject(&input) {
                return Err(RecoveryError::PayloadMismatch);
            }
            let family_key = (subject_key, record.kind as u8);
            if let Some((generation, digest)) = family_heads.get(&family_key) {
                if generation.checked_add(1) != Some(record.generation)
                    || record.family_predecessor != *digest
                {
                    return Err(RecoveryError::SubjectRollback);
                }
            } else if record.generation != 1 || record.family_predecessor.as_bytes() != &[0; 32] {
                return Err(RecoveryError::SubjectRollback);
            }
            family_heads.insert(family_key, (record.generation, record.digest));
            identities.observe(subject_key, &input)?;
            retained_pin_tombstones.replace(
                latest.get(&subject_key),
                &input,
                limits.maximum_records,
            )?;
            retained_pin_tombstones.validate_floor(global.pin_floor)?;
            expected_sequence = expected_sequence
                .checked_add(1)
                .ok_or(RecoveryError::HistoryOverflow)?;
            expected_predecessor = record.digest;
            projections.replace(subject_key, latest.get(&subject_key), &input)?;
            accounting.replace(latest.get(&subject_key), &input, &global)?;
            latest.insert(subject_key, input);
            validate_watermark_gate(&global, projections.charged_bytes)?;
            let current_projections = projections.digests();
            if record.catalog_projection != current_projections.0
                || record.reservation_projection != current_projections.1
                || record.pin_projection != current_projections.2
                || record.progress_projection != current_projections.3
                || record.model
                    != atomic_projection_digest(
                        current_projections.0,
                        current_projections.1,
                        current_projections.2,
                        current_projections.3,
                    )
            {
                return Err(RecoveryError::ProjectionMismatch);
            }
        }

        let mut work = Vec::new();
        for input in latest.values() {
            let remaining = limits.maximum_work_items.saturating_sub(work.len());
            for item in classify_work(input, remaining)? {
                if work.len() >= limits.maximum_work_items {
                    return Err(RecoveryError::Capacity);
                }
                work.push(item);
            }
        }
        let has_logical_owner_obligations = latest.values().any(|payload| {
            payload
                .pins
                .iter()
                .any(|pin| pin.kind == CachePinKindV1::LogicalLease)
                || payload
                    .released_pins
                    .iter()
                    .any(|released| released.pin.kind == CachePinKindV1::LogicalLease)
        });
        if has_logical_owner_obligations {
            push_recovery_work(
                &mut work,
                limits.maximum_work_items,
                CacheRecoveryWorkV1::ReconcileLogicalOwnerPins {
                    partition,
                    history_head: expected_predecessor,
                },
            )?;
        }
        for handoff in &global.handoffs {
            let item = if handoff_is_terminal(handoff) {
                CacheRecoveryWorkV1::CompactCompletedHandoff {
                    operation: handoff.operation,
                    handoff_digest: handoff.digest,
                }
            } else {
                CacheRecoveryWorkV1::ObservePendingHandoff {
                    operation: handoff.operation,
                    handoff_digest: handoff.digest,
                }
            };
            push_recovery_work(&mut work, limits.maximum_work_items, item)?;
        }
        for lookup in &global.lookups {
            let item = if lookup_is_terminal(lookup) {
                CacheRecoveryWorkV1::CompactCompletedLookup { key: lookup.key }
            } else {
                CacheRecoveryWorkV1::ObservePendingLookup { key: lookup.key }
            };
            push_recovery_work(&mut work, limits.maximum_work_items, item)?;
        }
        if let Some(poison) = global.poison {
            if work.len() >= limits.maximum_work_items {
                return Err(RecoveryError::Capacity);
            }
            work.push(CacheRecoveryWorkV1::ResolvePoison {
                operation: poison.operation,
                record_digest: poison.record_digest,
            });
        }
        let authority_poisoned = global.poison.is_some();

        let (catalog_projection, reservation_projection, pin_projection, progress_projection) =
            projections.digests();
        let head_sequence = expected_sequence.saturating_sub(1);
        // Protected authority binds the immutable replay anchor. The journal
        // CAS/hash chain and inventory binding authenticate the evolving suffix.
        let authority_scope = replay_scope_from_validated_anchor(
            partition,
            typed_checkpoint_digest,
            floor,
            authority_valid_until,
        )?;

        Ok(CacheRecoveryAssemblyDataV1 {
            work, accounting, projections, retained_pin_tombstones, identities,
            family_heads, latest, global, checkpoint_global: typed_checkpoint.global,
            authority_scope, typed_checkpoint_digest, floor, head_sequence,
            expected_predecessor, authority_poisoned, catalog_projection,
            reservation_projection, pin_projection, progress_projection,
            authority_record,
        })
}

/// Returns the compiled inline assembly bytes for representation prepayment.
#[must_use]
pub const fn recovery_assembly_inline_bytes_v1() -> usize {
    std::mem::size_of::<CacheRecoveryAssemblyDataV1>()
}
