//! Canonical codecs for typed recovery evidence components.

use super::*;

/// Encodes exact scrub observations and the resulting catalog generation.
///
/// # Errors
///
/// Returns [`RecoveryError`] for malformed evidence or a byte-bound breach.
pub fn encode_scrub_record(
    scrub: &CacheScrubRecordV1,
    partition: PhysicalPartitionId,
    maximum_bytes: usize,
) -> Result<Vec<u8>, RecoveryError> {
    scrub
        .evidence
        .validate()
        .map_err(|_| RecoveryError::PayloadMismatch)?;
    scrub
        .prior_catalog
        .clone()
        .validate()
        .map_err(|_| RecoveryError::PayloadMismatch)?;
    scrub
        .resulting_catalog
        .clone()
        .validate()
        .map_err(|_| RecoveryError::PayloadMismatch)?;
    if scrub.prior_catalog.partition != partition || scrub.resulting_catalog.partition != partition
    {
        return Err(RecoveryError::PayloadMismatch);
    }
    let mut writer = CanonicalWriter::new(b"AOSSCR01", maximum_bytes)?;
    writer.digest(partition.digest())?;
    writer.identity(scrub.evidence.operation.as_bytes())?;
    writer.digest(scrub.evidence.catalog_digest)?;
    write_backing_observation(&mut writer, scrub.evidence.before_validation)?;
    write_backing_observation(&mut writer, scrub.evidence.after_validation)?;
    writer.digest(scrub.evidence.content_digest)?;
    writer.digest(scrub.evidence.digest)?;
    writer.digest(scrub.evidence.authority_scope.subject())?;
    writer.identity(&scrub.evidence.authority_scope.operation())?;
    writer.digest(scrub.evidence.authority_scope.plan())?;
    writer.digest(scrub.evidence.authority_scope.root_custody())?;
    writer.u64(scrub.evidence.authority_scope.generation())?;
    writer.u64(scrub.evidence.authority_scope.valid_until())?;
    writer.digest(scrub.evidence.authority_record)?;
    writer.length_prefixed(&encode_catalog(&scrub.prior_catalog, maximum_bytes)?)?;
    writer.length_prefixed(&encode_catalog(&scrub.resulting_catalog, maximum_bytes)?)?;
    Ok(writer.finish())
}

/// Decodes exact scrub observations and both bound catalog generations.
///
/// # Errors
///
/// Returns [`RecoveryError`] for malformed or inconsistent canonical bytes.
pub fn decode_scrub_record(
    partition: PhysicalPartitionId,
    bytes: &[u8],
    maximum_bytes: usize,
) -> Result<CacheScrubRecordV1, RecoveryError> {
    let mut reader = CanonicalReader::new(b"AOSSCR01", bytes, maximum_bytes)?;
    reader.expect_digest(partition.digest())?;
    let operation = OperationId::from_bytes(reader.identity()?);
    let catalog_digest = reader.digest()?;
    let before_validation = read_backing_observation(&mut reader)?;
    let after_validation = read_backing_observation(&mut reader)?;
    let content_digest = reader.digest()?;
    let digest = reader.digest()?;
    let subject = reader.digest()?;
    let scope_operation = OperationId::from_bytes(reader.identity()?);
    let plan = reader.digest()?;
    let root_custody = reader.digest()?;
    let generation = reader.u64()?;
    let valid_until = reader.u64()?;
    let authority_record = reader.digest()?;
    let prior_catalog = decode_catalog(
        partition,
        reader.length_prefixed(maximum_bytes)?,
        maximum_bytes,
    )?;
    let resulting_catalog = decode_catalog(
        partition,
        reader.length_prefixed(maximum_bytes)?,
        maximum_bytes,
    )?;
    reader.complete()?;
    let authority_scope = CacheAuthorityScopeV1::new(
        partition,
        subject,
        Some(scope_operation),
        plan,
        root_custody,
        generation,
        valid_until,
    )?;
    let evidence = ScrubEvidenceV1 {
        operation,
        catalog_digest,
        before_validation,
        after_validation,
        content_digest,
        digest,
        authority_scope,
        authority_record,
    }
    .validate()
    .map_err(|_| RecoveryError::PayloadMismatch)?;
    Ok(CacheScrubRecordV1 {
        evidence,
        prior_catalog,
        resulting_catalog,
    })
}

fn write_backing_observation(
    writer: &mut CanonicalWriter,
    observation: BackingObservationV1,
) -> Result<(), RecoveryError> {
    writer.digest(observation.root_custody)?;
    writer.u64(observation.root_generation)?;
    writer.digest(observation.canonical_name)?;
    writer.bytes(observation.backing.as_bytes())?;
    writer.u64(observation.size)?;
    write_seal(writer, observation.seal)?;
    writer.u8(u8::from(observation.read_only))?;
    writer.u8(u8::from(observation.confined_resolution))
}

fn read_backing_observation(
    reader: &mut CanonicalReader<'_>,
) -> Result<BackingObservationV1, RecoveryError> {
    Ok(BackingObservationV1 {
        root_custody: reader.digest()?,
        root_generation: reader.u64()?,
        canonical_name: reader.digest()?,
        backing: BackingObjectIdentityV1::from_bytes(reader.array()?)
            .map_err(|_| RecoveryError::MalformedPayload)?,
        size: reader.u64()?,
        seal: read_seal(reader)?,
        read_only: reader.boolean()?,
        confined_resolution: reader.boolean()?,
    })
}

/// Encodes a complete admission plan into a canonical bounded component.
///
/// # Errors
///
/// Returns [`RecoveryError`] if the plan is invalid or exceeds the byte bound.
pub fn encode_admission_plan(
    plan: &ImmutableAdmissionPlanV1,
    maximum_bytes: usize,
) -> Result<Vec<u8>, RecoveryError> {
    plan.validate()
        .map_err(|_| RecoveryError::PayloadMismatch)?;
    let mut writer = CanonicalWriter::new(b"AOSPLN01", maximum_bytes)?;
    writer.identity(plan.operation.as_bytes())?;
    writer.identity(plan.reservation.as_bytes())?;
    writer.identity(plan.project.as_bytes())?;
    writer.digest(plan.partition.digest())?;
    write_descriptor(&mut writer, &plan.descriptor)?;
    writer.digest(plan.source.release_digest)?;
    writer.digest(plan.source.source_revision)?;
    write_descriptor(&mut writer, &plan.source.descriptor)?;
    writer.digest(plan.source.source_seal)?;
    writer.u64(plan.source.authority_generation)?;
    writer.u64(plan.source.valid_until)?;
    write_seal(&mut writer, plan.expected_seal)?;
    writer.u64(plan.reserved_bytes)?;
    writer.digest(plan.policy_revision)?;
    writer.u64(plan.root_generation)?;
    writer.digest(plan.root_custody)?;
    writer.digest(plan.initial_pins_digest)?;
    writer.digest(plan.request_digest)?;
    writer.digest(plan.digest)?;
    Ok(writer.finish())
}

/// Decodes and validates one canonical admission plan.
///
/// # Errors
///
/// Returns [`RecoveryError`] for malformed, over-bound, or inconsistent bytes.
pub fn decode_admission_plan(
    partition: PhysicalPartitionId,
    bytes: &[u8],
    maximum_bytes: usize,
) -> Result<ImmutableAdmissionPlanV1, RecoveryError> {
    let mut reader = CanonicalReader::new(b"AOSPLN01", bytes, maximum_bytes)?;
    let operation = OperationId::from_bytes(reader.identity()?);
    let reservation = super::super::accounting::CacheReservationId::from_bytes(reader.identity()?)
        .map_err(|_| RecoveryError::MalformedPayload)?;
    let project = ProjectId::from_bytes(reader.identity()?);
    reader.expect_digest(partition.digest())?;
    let descriptor = read_descriptor(&mut reader)?;
    let release_digest = reader.digest()?;
    let source_revision = reader.digest()?;
    let source_descriptor = read_descriptor(&mut reader)?;
    let source_seal = reader.digest()?;
    let authority_generation = reader.u64()?;
    let valid_until = reader.u64()?;
    let source = super::super::admission::SourceAuthorizationV1::recover_historical(
        release_digest,
        source_revision,
        source_descriptor,
        source_seal,
        authority_generation,
        valid_until,
    )
    .map_err(|_| RecoveryError::PayloadMismatch)?;
    let expected_seal = read_seal(&mut reader)?;
    let reserved_bytes = reader.u64()?;
    let policy_revision = reader.digest()?;
    let root_generation = reader.u64()?;
    let root_custody = reader.digest()?;
    let initial_pins_digest = reader.digest()?;
    let request_digest = reader.digest()?;
    let expected_digest = reader.digest()?;
    reader.complete()?;
    let plan = ImmutableAdmissionPlanV1::new(
        operation,
        reservation,
        project,
        partition,
        descriptor,
        source,
        expected_seal,
        reserved_bytes,
        policy_revision,
        root_generation,
        root_custody,
        initial_pins_digest,
        request_digest,
    )
    .map_err(|_| RecoveryError::PayloadMismatch)?;
    if plan.digest != expected_digest {
        return Err(RecoveryError::PayloadMismatch);
    }
    Ok(plan)
}

/// Encodes one exact reservation generation.
///
/// # Errors
///
/// Returns [`RecoveryError`] for invalid state or an exhausted byte bound.
pub fn encode_reservation(
    reservation: &CacheReservationV1,
    maximum_bytes: usize,
) -> Result<Vec<u8>, RecoveryError> {
    reservation
        .validate_record()
        .map_err(|_| RecoveryError::PayloadMismatch)?;
    let mut writer = CanonicalWriter::new(b"AOSRSV01", maximum_bytes)?;
    writer.identity(reservation.id.as_bytes())?;
    writer.identity(reservation.operation.as_bytes())?;
    writer.identity(reservation.project.as_bytes())?;
    writer.digest(reservation.partition.digest())?;
    write_descriptor(&mut writer, &reservation.descriptor)?;
    writer.u64(reservation.reserved_bytes)?;
    writer.digest(reservation.plan_digest)?;
    writer.u64(reservation.resident_bytes)?;
    writer.u8(reservation.state as u8)?;
    writer.u64(reservation.generation)?;
    writer.optional_digest(reservation.predecessor)?;
    writer.digest(reservation.digest)?;
    Ok(writer.finish())
}

/// Decodes one exact reservation generation.
///
/// # Errors
///
/// Returns [`RecoveryError`] for malformed or inconsistent bytes.
pub fn decode_reservation(
    partition: PhysicalPartitionId,
    bytes: &[u8],
    maximum_bytes: usize,
) -> Result<CacheReservationV1, RecoveryError> {
    let mut reader = CanonicalReader::new(b"AOSRSV01", bytes, maximum_bytes)?;
    let reservation = CacheReservationV1 {
        id: super::super::accounting::CacheReservationId::from_bytes(reader.identity()?)
            .map_err(|_| RecoveryError::MalformedPayload)?,
        operation: OperationId::from_bytes(reader.identity()?),
        project: ProjectId::from_bytes(reader.identity()?),
        partition,
        descriptor: {
            reader.expect_digest(partition.digest())?;
            read_descriptor(&mut reader)?
        },
        reserved_bytes: reader.u64()?,
        plan_digest: reader.digest()?,
        resident_bytes: reader.u64()?,
        state: reservation_state(reader.u8()?)?,
        generation: reader.u64()?,
        predecessor: reader.optional_digest()?,
        digest: reader.digest()?,
    };
    reader.complete()?;
    reservation
        .validate_record()
        .map_err(|_| RecoveryError::PayloadMismatch)?;
    Ok(reservation)
}

/// Encodes one exact catalog generation.
///
/// # Errors
///
/// Returns [`RecoveryError`] for invalid state or an exhausted byte bound.
pub fn encode_catalog(
    catalog: &CatalogEntryV1,
    maximum_bytes: usize,
) -> Result<Vec<u8>, RecoveryError> {
    catalog
        .clone()
        .validate()
        .map_err(|_| RecoveryError::PayloadMismatch)?;
    let mut writer = CanonicalWriter::new(b"AOSCAT01", maximum_bytes)?;
    writer.digest(catalog.partition.digest())?;
    write_descriptor(&mut writer, &catalog.descriptor)?;
    write_seal(&mut writer, catalog.seal)?;
    writer.bytes(catalog.backing.as_bytes())?;
    writer.u64(catalog.allocated_bytes)?;
    writer.digest(catalog.root_custody)?;
    writer.u64(catalog.root_generation)?;
    writer.digest(catalog.canonical_name)?;
    writer.identity(catalog.publication.as_bytes())?;
    writer.identity(catalog.reservation.as_bytes())?;
    writer.u8(catalog.presence as u8)?;
    writer.u64(catalog.generation)?;
    writer.optional_digest(catalog.predecessor)?;
    writer.digest(catalog.digest)?;
    Ok(writer.finish())
}

/// Decodes one exact catalog generation.
///
/// # Errors
///
/// Returns [`RecoveryError`] for malformed or inconsistent bytes.
pub fn decode_catalog(
    partition: PhysicalPartitionId,
    bytes: &[u8],
    maximum_bytes: usize,
) -> Result<CatalogEntryV1, RecoveryError> {
    let mut reader = CanonicalReader::new(b"AOSCAT01", bytes, maximum_bytes)?;
    reader.expect_digest(partition.digest())?;
    let entry = CatalogEntryV1 {
        partition,
        descriptor: read_descriptor(&mut reader)?,
        seal: read_seal(&mut reader)?,
        backing: super::super::catalog::BackingObjectIdentityV1::from_bytes(reader.array()?)
            .map_err(|_| RecoveryError::MalformedPayload)?,
        allocated_bytes: reader.u64()?,
        root_custody: reader.digest()?,
        root_generation: reader.u64()?,
        canonical_name: reader.digest()?,
        publication: OperationId::from_bytes(reader.identity()?),
        reservation: super::super::accounting::CacheReservationId::from_bytes(reader.identity()?)
            .map_err(|_| RecoveryError::MalformedPayload)?,
        presence: catalog_presence(reader.u8()?)?,
        generation: reader.u64()?,
        predecessor: reader.optional_digest()?,
        digest: reader.digest()?,
    };
    reader.complete()?;
    entry.validate().map_err(|_| RecoveryError::PayloadMismatch)
}

/// Encodes one exact historical pin.
///
/// # Errors
///
/// Returns [`RecoveryError`] for invalid state or an exhausted byte bound.
pub fn encode_pin(pin: &CachePinV1, maximum_bytes: usize) -> Result<Vec<u8>, RecoveryError> {
    pin.clone()
        .validate()
        .map_err(|_| RecoveryError::PayloadMismatch)?;
    let mut writer = CanonicalWriter::new(b"AOSPIN01", maximum_bytes)?;
    writer.identity(pin.id.as_bytes())?;
    writer.digest(pin.partition.digest())?;
    write_descriptor(&mut writer, &pin.object)?;
    writer.identity(pin.project.as_bytes())?;
    writer.identity(pin.view.as_bytes())?;
    writer.optional_identity(pin.attachment.map(|value| value.into_bytes()))?;
    writer.optional_identity(pin.sandbox.map(|value| value.into_bytes()))?;
    writer.optional_identity(pin.incarnation.map(|value| value.into_bytes()))?;
    writer.u8(pin.kind as u8)?;
    writer.u64(pin.assignment_epoch)?;
    writer.u64(pin.lease_valid_until)?;
    writer.digest(pin.evidence)?;
    Ok(writer.finish())
}

/// Decodes one exact historical pin without recreating current authority.
///
/// # Errors
///
/// Returns [`RecoveryError`] for malformed or inconsistent bytes.
pub fn decode_pin(
    partition: PhysicalPartitionId,
    bytes: &[u8],
    maximum_bytes: usize,
) -> Result<CachePinV1, RecoveryError> {
    let mut reader = CanonicalReader::new(b"AOSPIN01", bytes, maximum_bytes)?;
    let id =
        CachePinId::from_bytes(reader.identity()?).map_err(|_| RecoveryError::MalformedPayload)?;
    reader.expect_digest(partition.digest())?;
    let object = read_descriptor(&mut reader)?;
    let project = ProjectId::from_bytes(reader.identity()?);
    let view = ViewId::from_bytes(reader.identity()?);
    let attachment = reader.optional_identity()?.map(AttachmentId::from_bytes);
    let sandbox = reader.optional_identity()?.map(SandboxId::from_bytes);
    let incarnation = reader.optional_identity()?.map(IncarnationId::from_bytes);
    let kind = pin_kind(reader.u8()?)?;
    let assignment_epoch = reader.u64()?;
    let lease_valid_until = reader.u64()?;
    let evidence = reader.digest()?;
    reader.complete()?;
    CachePinV1::recover_historical(
        id,
        partition,
        object,
        project,
        view,
        attachment,
        sandbox,
        incarnation,
        kind,
        assignment_epoch,
        lease_valid_until,
        evidence,
    )
    .map_err(|_| RecoveryError::PayloadMismatch)
}

/// Encodes one released-pin tombstone and its exact drain outcome.
///
/// # Errors
///
/// Returns [`RecoveryError`] for invalid state or an exhausted byte bound.
pub fn encode_released_pin(
    released: &ReleasedCachePinV1,
    maximum_bytes: usize,
) -> Result<Vec<u8>, RecoveryError> {
    released
        .drain
        .validate_replay(&released.pin)
        .map_err(|_| RecoveryError::PayloadMismatch)?;
    let mut writer = CanonicalWriter::new(b"AOSRPN01", maximum_bytes)?;
    writer.length_prefixed(&encode_pin(&released.pin, maximum_bytes)?)?;
    writer.u8(released.drain.outcome() as u8)?;
    writer.u64(released.drain.valid_until())?;
    writer.digest(released.drain.digest())?;
    Ok(writer.finish())
}

/// Decodes one released-pin tombstone without recreating current authority.
///
/// # Errors
///
/// Returns [`RecoveryError`] for malformed or inconsistent bytes.
pub fn decode_released_pin(
    partition: PhysicalPartitionId,
    bytes: &[u8],
    maximum_bytes: usize,
) -> Result<ReleasedCachePinV1, RecoveryError> {
    let mut reader = CanonicalReader::new(b"AOSRPN01", bytes, maximum_bytes)?;
    let pin = decode_pin(
        partition,
        reader.length_prefixed(maximum_bytes)?,
        maximum_bytes,
    )?;
    let outcome = pin_drain_outcome(reader.u8()?)?;
    let valid_until = reader.u64()?;
    let digest = reader.digest()?;
    reader.complete()?;
    let drain = PinDrainEvidenceV1::recover_historical(&pin, outcome, digest, valid_until)
        .map_err(|_| RecoveryError::PayloadMismatch)?;
    Ok(ReleasedCachePinV1 { pin, drain })
}

/// Encodes one admission-progress generation.
///
/// # Errors
///
/// Returns [`RecoveryError`] for invalid state or an exhausted byte bound.
pub fn encode_admission_progress(
    progress: &AdmissionProgressV1,
    maximum_bytes: usize,
) -> Result<Vec<u8>, RecoveryError> {
    progress
        .validate()
        .map_err(|_| RecoveryError::PayloadMismatch)?;
    let mut writer = CanonicalWriter::new(b"AOSAPR01", maximum_bytes)?;
    writer.digest(progress.plan_digest)?;
    writer.u8(progress.stage as u8)?;
    writer.u8(progress.last_certain_stage as u8)?;
    writer.u64(progress.generation)?;
    writer.optional_digest(progress.predecessor)?;
    writer.digest(progress.evidence)?;
    writer.digest(progress.digest)?;
    Ok(writer.finish())
}

/// Decodes one admission-progress generation.
///
/// # Errors
///
/// Returns [`RecoveryError`] for malformed or inconsistent bytes.
pub fn decode_admission_progress(
    bytes: &[u8],
    maximum_bytes: usize,
) -> Result<AdmissionProgressV1, RecoveryError> {
    let mut reader = CanonicalReader::new(b"AOSAPR01", bytes, maximum_bytes)?;
    let progress = AdmissionProgressV1 {
        plan_digest: reader.digest()?,
        stage: admission_stage(reader.u8()?)?,
        last_certain_stage: admission_stage(reader.u8()?)?,
        generation: reader.u64()?,
        predecessor: reader.optional_digest()?,
        evidence: reader.digest()?,
        digest: reader.digest()?,
    };
    reader.complete()?;
    progress
        .validate()
        .map_err(|_| RecoveryError::PayloadMismatch)?;
    Ok(progress)
}

/// Encodes one frozen eviction plan and its complete candidate set.
///
/// # Errors
///
/// Returns [`RecoveryError`] for invalid state or an exhausted byte bound.
pub fn encode_eviction_plan(
    plan: &FrozenEvictionPlanV1,
    maximum_bytes: usize,
) -> Result<Vec<u8>, RecoveryError> {
    let mut writer = CanonicalWriter::new(b"AOSEVP01", maximum_bytes)?;
    writer.identity(plan.operation.as_bytes())?;
    writer.digest(plan.partition.digest())?;
    writer.u64(plan.catalog_generation)?;
    writer.digest(plan.authority_digest)?;
    writer.optional_identity(plan.target_reservation.map(|value| *value.as_bytes()))?;
    writer.u64(plan.target_reclaim_bytes)?;
    writer.u64(plan.authority_scope.valid_until())?;
    writer.u32(plan.candidates.len())?;
    for candidate in &plan.candidates {
        writer.length_prefixed(&encode_eviction_candidate(candidate, maximum_bytes)?)?;
    }
    writer.digest(plan.digest)?;
    Ok(writer.finish())
}

/// Decodes one frozen eviction plan and its complete candidate set.
///
/// # Errors
///
/// Returns [`RecoveryError`] for malformed, over-bound, or inconsistent bytes.
pub fn decode_eviction_plan(
    partition: PhysicalPartitionId,
    bytes: &[u8],
    maximum_bytes: usize,
    maximum_candidates: usize,
) -> Result<FrozenEvictionPlanV1, RecoveryError> {
    if maximum_candidates == 0 || maximum_candidates > MAXIMUM_EVICTION_CANDIDATES {
        return Err(RecoveryError::InvalidLimits);
    }
    let mut reader = CanonicalReader::new(b"AOSEVP01", bytes, maximum_bytes)?;
    let operation = OperationId::from_bytes(reader.identity()?);
    reader.expect_digest(partition.digest())?;
    let catalog_generation = reader.u64()?;
    let authority_digest = reader.digest()?;
    let target_reservation = reader
        .optional_identity()?
        .map(super::super::accounting::CacheReservationId::from_bytes)
        .transpose()
        .map_err(|_| RecoveryError::MalformedPayload)?;
    let target_reclaim_bytes = reader.u64()?;
    let valid_until = reader.u64()?;
    let count = reader.count(maximum_candidates)?;
    let mut candidates = Vec::with_capacity(count);
    for _ in 0..count {
        candidates.push(decode_eviction_candidate(
            reader.length_prefixed(maximum_bytes)?,
            maximum_bytes,
        )?);
    }
    let expected_digest = reader.digest()?;
    reader.complete()?;
    let plan = FrozenEvictionPlanV1::recover_historical(
        operation,
        partition,
        catalog_generation,
        authority_digest,
        target_reservation,
        target_reclaim_bytes,
        candidates,
        valid_until,
    )
    .map_err(|_| RecoveryError::PayloadMismatch)?;
    if plan.digest != expected_digest {
        return Err(RecoveryError::PayloadMismatch);
    }
    Ok(plan)
}

/// Encodes one exact eviction-candidate progress value.
///
/// # Errors
///
/// Returns [`RecoveryError`] for invalid state or an exhausted byte bound.
pub fn encode_eviction_progress(
    progress: &EvictionProgressV1,
    maximum_bytes: usize,
) -> Result<Vec<u8>, RecoveryError> {
    let mut writer = CanonicalWriter::new(b"AOSEVG01", maximum_bytes)?;
    writer.digest(progress.plan_digest)?;
    writer.length_prefixed(&encode_eviction_candidate(
        &progress.candidate,
        maximum_bytes,
    )?)?;
    writer.u8(progress.state as u8)?;
    writer.digest(progress.current_catalog_digest)?;
    writer.optional_digest(progress.evidence)?;
    writer.u64(progress.reclaimed_bytes)?;
    Ok(writer.finish())
}

/// Decodes one exact eviction-candidate progress value.
///
/// # Errors
///
/// Returns [`RecoveryError`] for malformed or inconsistent bytes.
pub fn decode_eviction_progress(
    plan: &FrozenEvictionPlanV1,
    bytes: &[u8],
    maximum_bytes: usize,
) -> Result<EvictionProgressV1, RecoveryError> {
    let mut reader = CanonicalReader::new(b"AOSEVG01", bytes, maximum_bytes)?;
    reader.expect_digest(plan.digest)?;
    let candidate =
        decode_eviction_candidate(reader.length_prefixed(maximum_bytes)?, maximum_bytes)?;
    let state = eviction_state(reader.u8()?)?;
    let current_catalog_digest = reader.digest()?;
    let evidence = reader.optional_digest()?;
    let reclaimed_bytes = reader.u64()?;
    reader.complete()?;
    EvictionProgressV1::recover_historical(
        plan,
        candidate,
        state,
        current_catalog_digest,
        evidence,
        reclaimed_bytes,
    )
    .map_err(|_| RecoveryError::PayloadMismatch)
}

/// Encodes one frozen eviction candidate.
///
/// # Errors
///
/// Returns [`RecoveryError`] for invalid state or an exhausted byte bound.
pub fn encode_eviction_candidate(
    candidate: &EvictionCandidateV1,
    maximum_bytes: usize,
) -> Result<Vec<u8>, RecoveryError> {
    validate_eviction_candidate(candidate).map_err(|_| RecoveryError::PayloadMismatch)?;
    let mut writer = CanonicalWriter::new(b"AOSEVC01", maximum_bytes)?;
    write_eviction_candidate(&mut writer, candidate)?;
    Ok(writer.finish())
}

/// Decodes one frozen eviction candidate.
///
/// # Errors
///
/// Returns [`RecoveryError`] for malformed or inconsistent bytes.
pub fn decode_eviction_candidate(
    bytes: &[u8],
    maximum_bytes: usize,
) -> Result<EvictionCandidateV1, RecoveryError> {
    let mut reader = CanonicalReader::new(b"AOSEVC01", bytes, maximum_bytes)?;
    let candidate = read_eviction_candidate(&mut reader)?;
    reader.complete()?;
    validate_eviction_candidate(&candidate).map_err(|_| RecoveryError::PayloadMismatch)?;
    Ok(candidate)
}

/// Encodes a complete typed object payload committed by a durable record.
///
/// # Errors
///
/// Returns [`RecoveryError`] for invalid component state or a byte-bound breach.
pub fn encode_atomic_object_payload(
    payload: &CacheAtomicObjectPayloadV1,
    limits: CacheRecoveryLimitsV1,
) -> Result<Vec<u8>, RecoveryError> {
    let limits = limits.validate()?;
    payload.validate(limits)?;
    encode_atomic_payload_components(payload, limits)
}

/// Decodes typed object components against their separately protected header.
///
/// # Errors
///
/// Returns [`RecoveryError`] for malformed, over-bound, or inconsistent bytes.
pub fn decode_atomic_object_payload(
    partition: PhysicalPartitionId,
    record: CacheDurableRecordV1,
    bytes: &[u8],
    limits: CacheRecoveryLimitsV1,
) -> Result<CacheAtomicObjectPayloadV1, RecoveryError> {
    let limits = limits.validate()?;
    let payload = decode_atomic_payload_components(partition, record, bytes, limits)?;
    payload.validate(limits)?;
    Ok(payload)
}

/// Encodes one durable header together with its canonical typed payload bytes.
///
/// # Errors
///
/// Returns [`RecoveryError`] if either component is invalid or over-bound.
pub fn encode_atomic_object_record(
    payload: &CacheAtomicObjectPayloadV1,
    limits: CacheRecoveryLimitsV1,
) -> Result<Vec<u8>, RecoveryError> {
    let limits = limits.validate()?;
    let payload_bytes = encode_atomic_object_payload(payload, limits)?;
    let record_bytes = encode_record(&payload.record)?;
    let mut writer = CanonicalWriter::new(ATOMIC_RECORD_MAGIC, limits.maximum_payload_bytes)?;
    writer.length_prefixed(&record_bytes)?;
    writer.length_prefixed(&payload_bytes)?;
    let digest = digest_bytes(
        b"aos.sandbox.cache.atomic-record-envelope.v1\0",
        writer.as_bytes(),
    );
    writer.digest(digest)?;
    Ok(writer.finish())
}

/// Decodes one durable header and reconstructs every typed object component.
///
/// # Errors
///
/// Returns [`RecoveryError`] for malformed, over-bound, or inconsistent bytes.
pub fn decode_atomic_object_record(
    partition: PhysicalPartitionId,
    bytes: &[u8],
    limits: CacheRecoveryLimitsV1,
) -> Result<CacheAtomicObjectPayloadV1, RecoveryError> {
    let limits = limits.validate()?;
    let mut reader =
        CanonicalReader::new(ATOMIC_RECORD_MAGIC, bytes, limits.maximum_payload_bytes)?;
    let record_bytes = reader.length_prefixed(DURABLE_RECORD_BYTES)?;
    let record = decode_record(record_bytes)?;
    let payload_bytes = reader.length_prefixed(limits.maximum_payload_bytes)?;
    let envelope_end = reader.position();
    let expected_digest = reader.digest()?;
    reader.complete()?;
    if expected_digest
        != digest_bytes(
            b"aos.sandbox.cache.atomic-record-envelope.v1\0",
            &bytes[..envelope_end],
        )
        || record.payload != payload_digest_bytes(payload_bytes)
    {
        return Err(RecoveryError::PayloadMismatch);
    }
    decode_atomic_object_payload(partition, record, payload_bytes, limits)
}

/// Encodes complete global recovery state in one canonical bounded envelope.
///
/// # Errors
///
/// Returns [`RecoveryError`] for malformed state or a byte-bound breach.
pub fn encode_global_recovery_state(
    state: &CacheGlobalRecoveryStateV1,
    partition: PhysicalPartitionId,
    limits: CacheRecoveryLimitsV1,
) -> Result<Vec<u8>, RecoveryError> {
    let limits = limits.validate()?;
    validate_global_recovery_state(state, partition, limits)?;
    let mut writer = CanonicalWriter::new(b"AOSGLB01", limits.maximum_payload_bytes)?;
    write_global_recovery_state(&mut writer, state, limits)?;
    writer.digest(state.digest)?;
    Ok(writer.finish())
}

/// Decodes complete global recovery state from canonical bounded bytes.
///
/// # Errors
///
/// Returns [`RecoveryError`] for malformed, duplicate, or over-bound state.
pub fn decode_global_recovery_state(
    partition: PhysicalPartitionId,
    bytes: &[u8],
    limits: CacheRecoveryLimitsV1,
) -> Result<CacheGlobalRecoveryStateV1, RecoveryError> {
    let limits = limits.validate()?;
    let mut reader = CanonicalReader::new(b"AOSGLB01", bytes, limits.maximum_payload_bytes)?;
    reader.expect_digest(partition.digest())?;
    let node_quota = read_node_quota(&mut reader, partition)?;
    let project_count = reader.count(limits.maximum_subjects)?;
    let mut project_quotas = Vec::with_capacity(project_count);
    for _ in 0..project_count {
        project_quotas.push(read_project_quota(&mut reader, partition)?);
    }
    let watermark_count = reader.count(limits.maximum_subjects)?;
    let mut watermarks = Vec::with_capacity(watermark_count);
    for _ in 0..watermark_count {
        watermarks.push(WatermarkRequirementV1 {
            reservation: super::super::accounting::CacheReservationId::from_bytes(
                reader.identity()?,
            )
            .map_err(|_| RecoveryError::MalformedPayload)?,
            plan_digest: reader.digest()?,
            required_bytes: reader.u64()?,
            credited_bytes: reader.u64()?,
        });
    }
    let idempotency_count = reader.count(limits.maximum_records)?;
    let mut idempotency = Vec::with_capacity(idempotency_count);
    for _ in 0..idempotency_count {
        idempotency.push(decode_idempotency(
            reader.length_prefixed(limits.maximum_payload_bytes)?,
        )?);
    }
    let pin_floor = match reader.boolean()? {
        true => Some(
            decode_pin_compaction_floor_persisted(partition, reader.take(PIN_FLOOR_BYTES)?)
                .map_err(|_| RecoveryError::PayloadMismatch)?,
        ),
        false => None,
    };
    let idempotency_floor = match reader.boolean()? {
        true => Some(
            decode_idempotency_floor_persisted(partition, reader.take(IDEMPOTENCY_FLOOR_BYTES)?)
                .map_err(|_| RecoveryError::PayloadMismatch)?,
        ),
        false => None,
    };
    let handoff_count = reader.count(limits.maximum_records)?;
    let mut handoffs = Vec::with_capacity(handoff_count);
    for _ in 0..handoff_count {
        handoffs.push(read_handoff_state(&mut reader)?);
    }
    let lookup_count = reader.count(limits.maximum_subjects)?;
    let mut lookups = Vec::with_capacity(lookup_count);
    for _ in 0..lookup_count {
        lookups.push(read_lookup_state(&mut reader)?);
    }
    let poison = match reader.boolean()? {
        true => Some(CachePoisonLatchV1 {
            operation: OperationId::from_bytes(reader.identity()?),
            record_digest: reader.digest()?,
        }),
        false => None,
    };
    let digest = reader.digest()?;
    reader.complete()?;
    let state = CacheGlobalRecoveryStateV1 {
        node_quota,
        project_quotas,
        watermarks,
        idempotency,
        pin_floor,
        idempotency_floor,
        handoffs,
        lookups,
        poison,
        digest,
    };
    validate_global_recovery_state(&state, partition, limits)?;
    Ok(state)
}

pub(super) fn write_global_recovery_state(
    writer: &mut CanonicalWriter,
    state: &CacheGlobalRecoveryStateV1,
    limits: CacheRecoveryLimitsV1,
) -> Result<(), RecoveryError> {
    if state.project_quotas.len() > limits.maximum_subjects
        || state.watermarks.len() > limits.maximum_subjects
        || state.idempotency.len() > limits.maximum_records
        || state.handoffs.len() > limits.maximum_records
        || state.lookups.len() > limits.maximum_subjects
    {
        return Err(RecoveryError::Capacity);
    }
    writer.digest(state.node_quota.partition.digest())?;
    write_node_quota(writer, state.node_quota)?;
    writer.u32(state.project_quotas.len())?;
    for quota in &state.project_quotas {
        write_project_quota(writer, *quota)?;
    }
    writer.u32(state.watermarks.len())?;
    for watermark in &state.watermarks {
        writer.identity(watermark.reservation.as_bytes())?;
        writer.digest(watermark.plan_digest)?;
        writer.u64(watermark.required_bytes)?;
        writer.u64(watermark.credited_bytes)?;
    }
    writer.u32(state.idempotency.len())?;
    for binding in &state.idempotency {
        writer.length_prefixed(&encode_idempotency(binding)?)?;
    }
    writer.u8(u8::from(state.pin_floor.is_some()))?;
    if let Some(floor) = state.pin_floor {
        writer.bytes(
            &encode_pin_compaction_floor(floor).map_err(|_| RecoveryError::PayloadMismatch)?,
        )?;
    }
    writer.u8(u8::from(state.idempotency_floor.is_some()))?;
    if let Some(floor) = state.idempotency_floor {
        writer.bytes(&encode_idempotency_floor(floor)?)?;
    }
    writer.u32(state.handoffs.len())?;
    for handoff in &state.handoffs {
        write_handoff_state(writer, handoff)?;
    }
    writer.u32(state.lookups.len())?;
    for lookup in &state.lookups {
        write_lookup_state(writer, *lookup)?;
    }
    writer.u8(u8::from(state.poison.is_some()))?;
    if let Some(poison) = state.poison {
        writer.identity(poison.operation.as_bytes())?;
        writer.digest(poison.record_digest)?;
    }
    Ok(())
}

pub(super) fn validate_global_recovery_state(
    state: &CacheGlobalRecoveryStateV1,
    partition: PhysicalPartitionId,
    limits: CacheRecoveryLimitsV1,
) -> Result<(), RecoveryError> {
    if state
        .node_quota
        .validate()
        .map_err(|_| RecoveryError::PayloadMismatch)?
        .partition
        != partition
    {
        return Err(RecoveryError::PayloadMismatch);
    }
    if state.project_quotas.len() > limits.maximum_subjects
        || state.watermarks.len() > limits.maximum_subjects
        || state.idempotency.len() > limits.maximum_records
        || state.handoffs.len() > limits.maximum_records
        || state.lookups.len() > limits.maximum_subjects
    {
        return Err(RecoveryError::Capacity);
    }
    let mut prior_project = None;
    for quota in &state.project_quotas {
        let quota = quota
            .validate()
            .map_err(|_| RecoveryError::PayloadMismatch)?;
        let project = *quota.project.as_bytes();
        if quota.partition != partition || prior_project.is_some_and(|prior| prior >= project) {
            return Err(RecoveryError::PayloadMismatch);
        }
        prior_project = Some(project);
    }
    let mut prior_watermark = None;
    for watermark in &state.watermarks {
        let reservation = *watermark.reservation.as_bytes();
        if watermark.plan_digest.as_bytes() == &[0; 32]
            || watermark.required_bytes == 0
            || watermark.credited_bytes >= watermark.required_bytes
            || prior_watermark.is_some_and(|prior| prior >= reservation)
        {
            return Err(RecoveryError::PayloadMismatch);
        }
        prior_watermark = Some(reservation);
    }
    let mut prior_idempotency = None;
    for binding in &state.idempotency {
        binding.validate()?;
        let key = (
            *binding.principal.as_bytes(),
            binding.method as u16,
            binding.key,
        );
        if prior_idempotency.is_some_and(|prior| prior >= key)
            || state
                .idempotency_floor
                .is_some_and(|floor| key <= floor.scope())
        {
            return Err(RecoveryError::PayloadMismatch);
        }
        prior_idempotency = Some(key);
    }
    let mut prior_handoff = None;
    for handoff in &state.handoffs {
        validate_handoff_state(handoff)?;
        let identity = *handoff.operation.as_bytes();
        if prior_handoff.is_some_and(|prior| prior >= identity) {
            return Err(RecoveryError::PayloadMismatch);
        }
        prior_handoff = Some(identity);
    }
    let mut prior_lookup = None;
    for lookup in &state.lookups {
        validate_lookup_state(*lookup)?;
        if prior_lookup.is_some_and(|prior| prior >= lookup.key) {
            return Err(RecoveryError::PayloadMismatch);
        }
        prior_lookup = Some(lookup.key);
    }
    if state.poison.is_some_and(|poison| {
        poison.operation.as_bytes() == &[0; 16] || poison.record_digest.as_bytes() == &[0; 32]
    }) || state.digest != global_state_digest(state, limits)?
    {
        return Err(RecoveryError::PayloadMismatch);
    }
    Ok(())
}

pub(super) fn global_pending_effects(
    state: &CacheGlobalRecoveryStateV1,
) -> Result<u64, RecoveryError> {
    let handoffs = state
        .handoffs
        .iter()
        .filter(|handoff| !handoff_is_terminal(handoff))
        .count();
    let lookups = state
        .lookups
        .iter()
        .filter(|lookup| !lookup_is_terminal(lookup))
        .count();
    u64::try_from(
        handoffs
            .checked_add(lookups)
            .ok_or(RecoveryError::Capacity)?,
    )
    .map_err(|_| RecoveryError::Capacity)
}

pub(super) fn global_state_digest(
    state: &CacheGlobalRecoveryStateV1,
    limits: CacheRecoveryLimitsV1,
) -> Result<ObjectDigest, RecoveryError> {
    let mut writer = CanonicalWriter::new(b"AOSGLD01", limits.maximum_payload_bytes)?;
    write_global_recovery_state(&mut writer, state, limits)?;
    Ok(digest_bytes(
        b"aos.sandbox.cache.global-recovery-state.v1\0",
        writer.as_bytes(),
    ))
}

pub(super) fn write_node_quota(
    writer: &mut CanonicalWriter,
    quota: NodeCacheQuotaV1,
) -> Result<(), RecoveryError> {
    for value in [
        quota.maximum_physical_bytes,
        quota.maximum_resident_objects,
        quota.maximum_logical_pins,
        quota.maximum_source_retentions,
        quota.maximum_kernel_references,
        quota.maximum_backing_registrations,
        quota.recovery_reserve_bytes,
        quota.high_water_bytes,
        quota.low_water_bytes,
    ] {
        writer.u64(value)?;
    }
    Ok(())
}

pub(super) fn read_node_quota(
    reader: &mut CanonicalReader<'_>,
    partition: PhysicalPartitionId,
) -> Result<NodeCacheQuotaV1, RecoveryError> {
    Ok(NodeCacheQuotaV1 {
        partition,
        maximum_physical_bytes: reader.u64()?,
        maximum_resident_objects: reader.u64()?,
        maximum_logical_pins: reader.u64()?,
        maximum_source_retentions: reader.u64()?,
        maximum_kernel_references: reader.u64()?,
        maximum_backing_registrations: reader.u64()?,
        recovery_reserve_bytes: reader.u64()?,
        high_water_bytes: reader.u64()?,
        low_water_bytes: reader.u64()?,
    })
}

pub(super) fn write_project_quota(
    writer: &mut CanonicalWriter,
    quota: ProjectCacheQuotaV1,
) -> Result<(), RecoveryError> {
    writer.identity(quota.project.as_bytes())?;
    writer.digest(quota.partition.digest())?;
    for value in [
        quota.maximum_charged_bytes,
        quota.maximum_logical_pins,
        quota.maximum_source_retentions,
        quota.maximum_kernel_references,
        quota.maximum_backing_registrations,
    ] {
        writer.u64(value)?;
    }
    Ok(())
}

pub(super) fn read_project_quota(
    reader: &mut CanonicalReader<'_>,
    partition: PhysicalPartitionId,
) -> Result<ProjectCacheQuotaV1, RecoveryError> {
    let project = ProjectId::from_bytes(reader.identity()?);
    reader.expect_digest(partition.digest())?;
    Ok(ProjectCacheQuotaV1 {
        project,
        partition,
        maximum_charged_bytes: reader.u64()?,
        maximum_logical_pins: reader.u64()?,
        maximum_source_retentions: reader.u64()?,
        maximum_kernel_references: reader.u64()?,
        maximum_backing_registrations: reader.u64()?,
    })
}

pub(super) fn write_handoff_state(
    writer: &mut CanonicalWriter,
    handoff: &CacheReadHandoffStateV1,
) -> Result<(), RecoveryError> {
    writer.identity(handoff.operation.as_bytes())?;
    writer.digest(handoff.authority)?;
    writer.digest(handoff.catalog)?;
    writer.identity(handoff.pin.as_bytes())?;
    write_descriptor(writer, &handoff.descriptor)?;
    writer.bytes(handoff.backing.as_bytes())?;
    writer.digest(handoff.preparation_evidence)?;
    writer.optional_digest(handoff.receipt_evidence)?;
    write_pending_cancellation(writer, handoff.cancellation)?;
    writer.u64(handoff.valid_until)?;
    writer.digest(handoff.digest)
}

pub(super) fn read_handoff_state(
    reader: &mut CanonicalReader<'_>,
) -> Result<CacheReadHandoffStateV1, RecoveryError> {
    Ok(CacheReadHandoffStateV1 {
        operation: OperationId::from_bytes(reader.identity()?),
        authority: reader.digest()?,
        catalog: reader.digest()?,
        pin: CachePinId::from_bytes(reader.identity()?)
            .map_err(|_| RecoveryError::MalformedPayload)?,
        descriptor: read_descriptor(reader)?,
        backing: BackingObjectIdentityV1::from_bytes(reader.array()?)
            .map_err(|_| RecoveryError::MalformedPayload)?,
        preparation_evidence: reader.digest()?,
        receipt_evidence: reader.optional_digest()?,
        cancellation: read_pending_cancellation(reader)?,
        valid_until: reader.u64()?,
        digest: reader.digest()?,
    })
}

pub(super) fn validate_handoff_state(
    handoff: &CacheReadHandoffStateV1,
) -> Result<(), RecoveryError> {
    if handoff.operation.as_bytes() == &[0; 16]
        || handoff.authority.as_bytes() == &[0; 32]
        || handoff.catalog.as_bytes() == &[0; 32]
        || super::super::domain::validate_object_descriptor(&handoff.descriptor).is_err()
        || handoff.preparation_evidence.as_bytes() == &[0; 32]
        || handoff.valid_until == 0
        || handoff.receipt_evidence.is_some() && handoff.cancellation.is_some()
        || handoff.cancellation.is_some_and(|cancellation| {
            validate_pending_cancellation(
                cancellation,
                handoff_pending_digest(handoff),
                Some(handoff.valid_until),
            )
            .is_err()
        })
        || handoff.digest != handoff_state_digest(handoff)
    {
        return Err(RecoveryError::PayloadMismatch);
    }
    Ok(())
}

pub(super) fn handoff_pending_digest(handoff: &CacheReadHandoffStateV1) -> ObjectDigest {
    let mut pending = handoff.clone();
    pending.receipt_evidence = None;
    pending.cancellation = None;
    handoff_state_digest(&pending)
}

pub(super) fn handoff_state_digest(handoff: &CacheReadHandoffStateV1) -> ObjectDigest {
    let mut hasher = sha2::Sha256::new();
    use sha2::Digest as _;
    hasher.update(b"aos.sandbox.cache.recovery-handoff.v1\0");
    hasher.update(handoff.operation.as_bytes());
    hasher.update(handoff.authority.as_bytes());
    hasher.update(handoff.catalog.as_bytes());
    hasher.update(handoff.pin.as_bytes());
    hasher.update(object_descriptor_commitment(&handoff.descriptor).as_bytes());
    hasher.update(handoff.backing.as_bytes());
    hasher.update(handoff.preparation_evidence.as_bytes());
    hasher.update(
        handoff
            .receipt_evidence
            .map_or([0; 32], |evidence| *evidence.as_bytes()),
    );
    hasher.update(
        handoff
            .cancellation
            .map_or([0; 32], |cancellation| *cancellation.digest.as_bytes()),
    );
    hasher.update(handoff.valid_until.to_be_bytes());
    ObjectDigest::from_bytes(hasher.finalize().into())
}

pub(super) fn write_lookup_state(
    writer: &mut CanonicalWriter,
    lookup: CacheLookupStateV1,
) -> Result<(), RecoveryError> {
    writer.digest(lookup.key)?;
    match lookup.value {
        None => writer.u8(0)?,
        Some(LookupMemoValueV1::Positive { catalog_digest }) => {
            writer.u8(1)?;
            writer.digest(catalog_digest)?;
        }
        Some(LookupMemoValueV1::Negative {
            valid_through_generation,
        }) => {
            writer.u8(2)?;
            writer.u64(valid_through_generation)?;
        }
    }
    writer.bytes(&lookup.waiters.to_be_bytes())?;
    writer.u64(lookup.in_flight_bytes)?;
    write_pending_cancellation(writer, lookup.cancellation)
}

pub(super) fn read_lookup_state(
    reader: &mut CanonicalReader<'_>,
) -> Result<CacheLookupStateV1, RecoveryError> {
    let key = reader.digest()?;
    let value = match reader.u8()? {
        0 => None,
        1 => Some(LookupMemoValueV1::Positive {
            catalog_digest: reader.digest()?,
        }),
        2 => Some(LookupMemoValueV1::Negative {
            valid_through_generation: reader.u64()?,
        }),
        _ => return Err(RecoveryError::MalformedPayload),
    };
    Ok(CacheLookupStateV1 {
        key,
        value,
        waiters: u32::from_be_bytes(reader.array()?),
        in_flight_bytes: reader.u64()?,
        cancellation: read_pending_cancellation(reader)?,
    })
}

pub(super) fn validate_lookup_state(lookup: CacheLookupStateV1) -> Result<(), RecoveryError> {
    let completed = lookup.value.is_some() || lookup.cancellation.is_some();
    let valid_value = match lookup.value {
        Some(LookupMemoValueV1::Positive { catalog_digest }) => {
            catalog_digest.as_bytes() != &[0; 32]
        }
        Some(LookupMemoValueV1::Negative {
            valid_through_generation,
        }) => valid_through_generation > 0,
        None => true,
    };
    if lookup.key.as_bytes() == &[0; 32]
        || !valid_value
        || lookup.value.is_some() && lookup.cancellation.is_some()
        || lookup.cancellation.is_some_and(|cancellation| {
            validate_pending_cancellation(cancellation, lookup.key, None).is_err()
        })
        || (completed && (lookup.waiters != 0 || lookup.in_flight_bytes != 0))
        || (!completed && lookup.in_flight_bytes == 0)
    {
        return Err(RecoveryError::PayloadMismatch);
    }
    Ok(())
}

pub(super) fn write_pending_cancellation(
    writer: &mut CanonicalWriter,
    cancellation: Option<PendingCancellationV1>,
) -> Result<(), RecoveryError> {
    writer.u8(u8::from(cancellation.is_some()))?;
    if let Some(cancellation) = cancellation {
        writer.digest(cancellation.target)?;
        writer.u8(cancellation.outcome as u8)?;
        writer.u64(cancellation.observed_at)?;
        writer.u64(cancellation.target_valid_until)?;
        writer.digest(cancellation.authority)?;
        writer.digest(cancellation.evidence)?;
        writer.digest(cancellation.digest)?;
    }
    Ok(())
}

pub(super) fn read_pending_cancellation(
    reader: &mut CanonicalReader<'_>,
) -> Result<Option<PendingCancellationV1>, RecoveryError> {
    if !reader.boolean()? {
        return Ok(None);
    }
    let target = reader.digest()?;
    let outcome = match reader.u8()? {
        1 => PendingCancellationOutcomeV1::NoEffectObserved,
        2 => PendingCancellationOutcomeV1::ExpiredNoEffectObserved,
        _ => return Err(RecoveryError::MalformedPayload),
    };
    let cancellation = PendingCancellationV1 {
        target,
        outcome,
        observed_at: reader.u64()?,
        target_valid_until: reader.u64()?,
        authority: reader.digest()?,
        evidence: reader.digest()?,
        digest: reader.digest()?,
    };
    validate_pending_cancellation(cancellation, target, None)?;
    Ok(Some(cancellation))
}
