//! Monotone typed-checkpoint chain and permanent-floor validation.

use super::*;

pub(super) fn validate_checkpoint_successor(
    previous: &CacheTypedCheckpointV1,
    next: &CacheTypedCheckpointV1,
) -> Result<(), RecoveryError> {
    if next.checkpoint.predecessor != previous.digest
        || next.checkpoint.sequence <= previous.checkpoint.sequence
        || (previous.global.poison.is_some() && next.global.poison != previous.global.poison)
        || previous.global.pin_floor.is_some_and(|floor| {
            !next
                .global
                .pin_floor
                .is_some_and(|next_floor| next_floor.pin() >= floor.pin())
        })
        || previous.global.idempotency_floor.is_some_and(|floor| {
            !next
                .global
                .idempotency_floor
                .is_some_and(|next_floor| next_floor.scope() >= floor.scope())
        })
    {
        return Err(RecoveryError::AnchorMismatch);
    }
    if next.global.pin_floor != previous.global.pin_floor
        && !next
            .global
            .pin_floor
            .is_some_and(|floor| floor.checkpoint() == previous.digest)
    {
        return Err(RecoveryError::AnchorMismatch);
    }
    if next.global.idempotency_floor != previous.global.idempotency_floor
        && !next
            .global
            .idempotency_floor
            .is_some_and(|floor| floor.checkpoint() == previous.digest)
    {
        return Err(RecoveryError::AnchorMismatch);
    }
    let next_heads = next
        .family_heads
        .iter()
        .map(|head| ((head.subject, head.kind as u8), head))
        .collect::<BTreeMap<_, _>>();
    for previous_head in &previous.family_heads {
        let Some(next_head) = next_heads.get(&(previous_head.subject, previous_head.kind as u8))
        else {
            return Err(RecoveryError::SubjectRollback);
        };
        if next_head.generation < previous_head.generation
            || (next_head.generation == previous_head.generation
                && next_head.record_digest != previous_head.record_digest)
        {
            return Err(RecoveryError::SubjectRollback);
        }
    }
    Ok(())
}

/// Encodes a reconstructible typed checkpoint with per-family heads.
///
/// # Errors
///
/// Returns [`RecoveryError`] for inconsistent aggregate state or a byte bound.
pub fn encode_typed_checkpoint(
    checkpoint: &CacheTypedCheckpointV1,
    partition: PhysicalPartitionId,
    limits: CacheRecoveryLimitsV1,
) -> Result<Vec<u8>, RecoveryError> {
    let limits = limits.validate()?;
    validate_typed_checkpoint(checkpoint, partition, limits)?;
    let mut writer = CanonicalWriter::new(TYPED_CHECKPOINT_MAGIC, limits.maximum_payload_bytes)?;
    writer.length_prefixed(&encode_checkpoint(&checkpoint.checkpoint)?)?;
    writer.u32(checkpoint.baselines.len())?;
    for baseline in &checkpoint.baselines {
        writer.length_prefixed(&encode_atomic_object_record(baseline, limits)?)?;
    }
    writer.u32(checkpoint.family_heads.len())?;
    for head in &checkpoint.family_heads {
        writer.digest(head.subject)?;
        writer.u8(head.kind as u8)?;
        writer.u64(head.generation)?;
        writer.digest(head.record_digest)?;
    }
    writer.length_prefixed(&encode_global_recovery_state(
        &checkpoint.global,
        partition,
        limits,
    )?)?;
    writer.digest(checkpoint.digest)?;
    Ok(writer.finish())
}

/// Decodes and validates a reconstructible typed checkpoint.
///
/// # Errors
///
/// Returns [`RecoveryError`] for malformed bytes, duplicate heads, or a
/// checkpoint whose aggregate projections do not match its baselines.
pub fn decode_typed_checkpoint(
    partition: PhysicalPartitionId,
    bytes: &[u8],
    limits: CacheRecoveryLimitsV1,
) -> Result<CacheTypedCheckpointV1, RecoveryError> {
    let limits = limits.validate()?;
    let mut reader =
        CanonicalReader::new(TYPED_CHECKPOINT_MAGIC, bytes, limits.maximum_payload_bytes)?;
    let checkpoint = decode_checkpoint(reader.length_prefixed(CHECKPOINT_BYTES)?)?;
    let baseline_count = reader.count(limits.maximum_subjects)?;
    let mut baselines = Vec::with_capacity(baseline_count);
    for _ in 0..baseline_count {
        let record = reader.length_prefixed(limits.maximum_payload_bytes)?;
        baselines.push(decode_atomic_object_record(partition, record, limits)?);
    }
    let head_count = reader.count(limits.maximum_records)?;
    let mut family_heads = Vec::with_capacity(head_count);
    for _ in 0..head_count {
        family_heads.push(CacheSubjectFamilyHeadV1 {
            subject: reader.digest()?,
            kind: record_kind(reader.u8()?)?,
            generation: reader.u64()?,
            record_digest: reader.digest()?,
        });
    }
    let global = decode_global_recovery_state(
        partition,
        reader.length_prefixed(limits.maximum_payload_bytes)?,
        limits,
    )?;
    let digest = reader.digest()?;
    reader.complete()?;
    let typed = CacheTypedCheckpointV1 {
        checkpoint,
        baselines,
        family_heads,
        global,
        digest,
    };
    validate_typed_checkpoint(&typed, partition, limits)?;
    Ok(typed)
}

pub(super) fn encode_atomic_payload_components(
    payload: &CacheAtomicObjectPayloadV1,
    limits: CacheRecoveryLimitsV1,
) -> Result<Vec<u8>, RecoveryError> {
    let mut writer = CanonicalWriter::new(ATOMIC_PAYLOAD_MAGIC, limits.maximum_payload_bytes)?;
    writer.length_prefixed(&encode_admission_plan(
        &payload.plan,
        limits.maximum_payload_bytes,
    )?)?;
    writer.length_prefixed(&encode_reservation(
        &payload.reservation,
        limits.maximum_payload_bytes,
    )?)?;
    writer.u8(u8::from(payload.catalog.is_some()))?;
    if let Some(catalog) = &payload.catalog {
        writer.length_prefixed(&encode_catalog(catalog, limits.maximum_payload_bytes)?)?;
    }
    writer.u32(payload.pins.len())?;
    for pin in &payload.pins {
        writer.length_prefixed(&encode_pin(pin, limits.maximum_payload_bytes)?)?;
    }
    writer.u32(payload.released_pins.len())?;
    for released in &payload.released_pins {
        writer.length_prefixed(&encode_released_pin(
            released,
            limits.maximum_payload_bytes,
        )?)?;
    }
    writer.length_prefixed(&encode_admission_progress(
        &payload.progress,
        limits.maximum_payload_bytes,
    )?)?;
    writer.u8(u8::from(payload.eviction_plan.is_some()))?;
    if let Some(plan) = &payload.eviction_plan {
        writer.length_prefixed(&encode_eviction_plan(plan, limits.maximum_payload_bytes)?)?;
    }
    writer.u32(payload.eviction_progress.len())?;
    for progress in &payload.eviction_progress {
        writer.length_prefixed(&encode_eviction_progress(
            progress,
            limits.maximum_payload_bytes,
        )?)?;
    }
    writer.u8(u8::from(payload.scrub.is_some()))?;
    if let Some(scrub) = &payload.scrub {
        writer.length_prefixed(&encode_scrub_record(
            scrub,
            payload.plan.partition,
            limits.maximum_payload_bytes,
        )?)?;
    }
    writer.u8(u8::from(payload.global_after.is_some()))?;
    if let Some(global) = &payload.global_after {
        writer.length_prefixed(&encode_global_recovery_state(
            global,
            payload.plan.partition,
            limits,
        )?)?;
    }
    Ok(writer.finish())
}

pub(super) fn decode_atomic_payload_components(
    partition: PhysicalPartitionId,
    record: CacheDurableRecordV1,
    bytes: &[u8],
    limits: CacheRecoveryLimitsV1,
) -> Result<CacheAtomicObjectPayloadV1, RecoveryError> {
    let mut reader =
        CanonicalReader::new(ATOMIC_PAYLOAD_MAGIC, bytes, limits.maximum_payload_bytes)?;
    let plan = decode_admission_plan(
        partition,
        reader.length_prefixed(limits.maximum_payload_bytes)?,
        limits.maximum_payload_bytes,
    )?;
    let reservation = decode_reservation(
        partition,
        reader.length_prefixed(limits.maximum_payload_bytes)?,
        limits.maximum_payload_bytes,
    )?;
    let catalog = match reader.boolean()? {
        true => Some(decode_catalog(
            partition,
            reader.length_prefixed(limits.maximum_payload_bytes)?,
            limits.maximum_payload_bytes,
        )?),
        false => None,
    };
    let pin_count = reader.count(limits.maximum_subjects)?;
    let mut pins = Vec::with_capacity(pin_count);
    for _ in 0..pin_count {
        pins.push(decode_pin(
            partition,
            reader.length_prefixed(limits.maximum_payload_bytes)?,
            limits.maximum_payload_bytes,
        )?);
    }
    let released_count = reader.count(limits.maximum_subjects)?;
    let mut released_pins = Vec::with_capacity(released_count);
    for _ in 0..released_count {
        released_pins.push(decode_released_pin(
            partition,
            reader.length_prefixed(limits.maximum_payload_bytes)?,
            limits.maximum_payload_bytes,
        )?);
    }
    let progress = decode_admission_progress(
        reader.length_prefixed(limits.maximum_payload_bytes)?,
        limits.maximum_payload_bytes,
    )?;
    let eviction_plan = match reader.boolean()? {
        true => Some(decode_eviction_plan(
            partition,
            reader.length_prefixed(limits.maximum_payload_bytes)?,
            limits.maximum_payload_bytes,
            limits.maximum_subjects,
        )?),
        false => None,
    };
    let eviction_count = reader.count(MAXIMUM_EVICTION_CANDIDATES)?;
    let mut eviction_progress = Vec::with_capacity(eviction_count);
    for _ in 0..eviction_count {
        let plan = eviction_plan
            .as_ref()
            .ok_or(RecoveryError::PayloadMismatch)?;
        eviction_progress.push(decode_eviction_progress(
            plan,
            reader.length_prefixed(limits.maximum_payload_bytes)?,
            limits.maximum_payload_bytes,
        )?);
    }
    let scrub = match reader.boolean()? {
        true => Some(decode_scrub_record(
            partition,
            reader.length_prefixed(limits.maximum_payload_bytes)?,
            limits.maximum_payload_bytes,
        )?),
        false => None,
    };
    let global_after = match reader.boolean()? {
        true => Some(decode_global_recovery_state(
            partition,
            reader.length_prefixed(limits.maximum_payload_bytes)?,
            limits,
        )?),
        false => None,
    };
    reader.complete()?;
    Ok(CacheAtomicObjectPayloadV1 {
        record,
        plan,
        reservation,
        catalog,
        pins,
        released_pins,
        progress,
        eviction_plan,
        eviction_progress,
        scrub,
        global_after,
    })
}

pub(super) fn validate_typed_checkpoint(
    typed: &CacheTypedCheckpointV1,
    partition: PhysicalPartitionId,
    limits: CacheRecoveryLimitsV1,
) -> Result<(), RecoveryError> {
    typed.checkpoint.validate()?;
    if typed.baselines.len() > limits.maximum_subjects
        || typed.family_heads.len() > limits.maximum_records
    {
        return Err(RecoveryError::Capacity);
    }
    let mut baselines = BTreeMap::new();
    let mut previous_subject = None;
    for baseline in &typed.baselines {
        baseline.validate(limits)?;
        if baseline.plan.partition != partition
            || baseline.record.sequence > typed.checkpoint.sequence
            || previous_subject.is_some_and(|subject| subject >= baseline.record.subject)
            || baselines
                .insert(baseline.record.subject, baseline.clone())
                .is_some()
        {
            return Err(RecoveryError::PayloadMismatch);
        }
        previous_subject = Some(baseline.record.subject);
    }
    GlobalIdentityIndex::from_subjects(&baselines)?;
    RetainedPinTombstoneIndex::from_subjects(&baselines, limits.maximum_records)?
        .validate_floor(typed.global.pin_floor)?;
    let projections = aggregate_projections(&baselines)?;
    if typed.checkpoint.catalog_projection != projections.0
        || typed.checkpoint.reservation_projection != projections.1
        || typed.checkpoint.pin_projection != projections.2
        || typed.checkpoint.progress_projection != projections.3
        || typed.checkpoint.projection
            != atomic_projection_digest(projections.0, projections.1, projections.2, projections.3)
    {
        return Err(RecoveryError::ProjectionMismatch);
    }
    validate_global_recovery_state(&typed.global, partition, limits)?;
    RecoveredAccountingProjection::from_subjects(&typed.global, &baselines, limits)?;
    let (catalog_entries, reservations, pins, pending_effects, charged_bytes) =
        aggregate_counts(&baselines)?;
    let pending_effects = pending_effects
        .checked_add(global_pending_effects(&typed.global)?)
        .ok_or(RecoveryError::Capacity)?;
    let lookup_entries =
        u64::try_from(typed.global.lookups.len()).map_err(|_| RecoveryError::Capacity)?;
    if typed.checkpoint.catalog_entries != catalog_entries
        || typed.checkpoint.reservations != reservations
        || typed.checkpoint.pins != pins
        || typed.checkpoint.pending_effects != pending_effects
        || typed.checkpoint.charged_bytes != charged_bytes
        || typed.checkpoint.lookup_entries != lookup_entries
    {
        return Err(RecoveryError::ProjectionMismatch);
    }
    validate_watermark_gate(&typed.global, charged_bytes)?;
    let mut heads = BTreeMap::new();
    let mut previous_head = None;
    for head in &typed.family_heads {
        let head_key = (head.subject, head.kind as u8);
        if head.subject.as_bytes() == &[0; 32]
            || head.generation == 0
            || head.record_digest.as_bytes() == &[0; 32]
            || !baselines.contains_key(&head.subject)
            || previous_head.is_some_and(|previous| previous >= head_key)
            || heads.insert(head_key, *head).is_some()
        {
            return Err(RecoveryError::PayloadMismatch);
        }
        previous_head = Some(head_key);
    }
    for baseline in typed.baselines.iter() {
        let key = (baseline.record.subject, baseline.record.kind as u8);
        if !heads.get(&key).is_some_and(|head| {
            head.generation == baseline.record.generation
                && head.record_digest == baseline.record.digest
        }) {
            return Err(RecoveryError::PayloadMismatch);
        }
    }
    if typed.digest != typed_checkpoint_digest(typed, limits)? {
        return Err(RecoveryError::PayloadMismatch);
    }
    Ok(())
}

pub(super) fn typed_checkpoint_digest(
    typed: &CacheTypedCheckpointV1,
    limits: CacheRecoveryLimitsV1,
) -> Result<ObjectDigest, RecoveryError> {
    let mut hasher = sha2::Sha256::new();
    use sha2::Digest as _;
    hasher.update(b"aos.sandbox.cache.typed-checkpoint.v1\0");
    hasher.update(typed.checkpoint.digest.as_bytes());
    hasher.update((typed.baselines.len() as u64).to_be_bytes());
    for baseline in &typed.baselines {
        hasher.update(encode_atomic_object_record(baseline, limits)?);
    }
    hasher.update((typed.family_heads.len() as u64).to_be_bytes());
    for head in &typed.family_heads {
        hasher.update(head.subject.as_bytes());
        hasher.update([head.kind as u8]);
        hasher.update(head.generation.to_be_bytes());
        hasher.update(head.record_digest.as_bytes());
    }
    hasher.update(encode_global_recovery_state(
        &typed.global,
        typed.global.node_quota.partition,
        limits,
    )?);
    Ok(ObjectDigest::from_bytes(hasher.finalize().into()))
}
