//! Authentication and canonical translation of QEMU clock evidence records.

use super::*;

pub(in crate::fault_command) fn translate_clock_evidence(
    raw: &[u8],
    manifest_payload: &[u8],
    event: &QemuFaultEvent,
    observed_icount: u64,
    expectation: &ClockCommandExpectation,
) -> Result<Vec<u8>, FaultCommandBridgeError> {
    fn invalid<T>(_: T) -> FaultCommandBridgeError {
        FaultCommandBridgeError::ClockEvidence
    }
    if raw.starts_with(b"CRUCCIM1") {
        return translate_clock_impulse_event_evidence(
            raw,
            manifest_payload,
            event,
            observed_icount,
            expectation,
        );
    }
    let read_record = raw.starts_with(b"CRUCCRE1");
    if expectation.operation != NodeFaultOperationV1::Upsert
        || raw.len() != if read_record { 416 } else { 384 }
        || raw_u16(raw, 8).map_err(invalid)? != 1
    {
        return Err(FaultCommandBridgeError::ClockEvidence);
    }
    let source_kind = raw_u16(raw, 10).map_err(invalid)?;
    let (
        source_offset,
        binding_offset,
        before_offset,
        after_offset,
        generation,
        opportunity,
        observation,
    ) = match &raw[..8] {
        b"CRUCCRE1" => {
            if raw_u64(raw, 16).map_err(invalid)? != event.observed_icount
                || raw[404..].iter().any(|byte| *byte != 0)
            {
                return Err(FaultCommandBridgeError::ClockEvidence);
            }
            (
                128,
                160,
                192,
                224,
                raw_u64(raw, 96).map_err(invalid)?,
                raw_u64(raw, 24).map_err(invalid)?,
                FaultClockObservationV1::Read {
                    raw_value: raw_u64(raw, 32).map_err(invalid)?,
                    transformed_value: raw_u64(raw, 40).map_err(invalid)?,
                    raw_architectural_value: raw_u64(raw, 384).map_err(invalid)?,
                    transformed_architectural_value: raw_u64(raw, 392).map_err(invalid)?,
                    source_width_bits: raw_u16(raw, 400).map_err(invalid)?,
                    wrap_action: raw_u16(raw, 402).map_err(invalid)?,
                    anchor_raw: raw_u64(raw, 48).map_err(invalid)?,
                    anchor_value: raw_u64(raw, 56).map_err(invalid)?,
                    drift_ratio: [
                        raw_u64(raw, 64).map_err(invalid)?,
                        raw_u64(raw, 72).map_err(invalid)?,
                    ],
                    additive_nanos: raw_u64(raw, 80).map_err(invalid)? as i64,
                    frozen_value: raw_u64(raw, 88).map_err(invalid)?,
                    read_error: match raw_u32(raw, 12).map_err(invalid)? {
                        0 => false,
                        1 => true,
                        _ => return Err(FaultCommandBridgeError::ClockEvidence),
                    },
                    read_opportunity: raw_u64(raw, 264).map_err(invalid)?,
                    transform_kind: raw_u32(raw, 256).map_err(invalid)?,
                    contribution: raw_u64(raw, 272).map_err(invalid)? as i64,
                    monotonicity: raw_u32(raw, 104).map_err(invalid)?,
                    overdue_policy: raw_u32(raw, 108).map_err(invalid)?,
                    source_state: raw_u32(raw, 112).map_err(invalid)?,
                    freeze_release: raw_u32(raw, 116).map_err(invalid)?,
                    synchronization_remaining_nanos: raw_u64(raw, 120).map_err(invalid)? as i64,
                },
            )
        }
        b"CRUCCWE1"
            if raw[12..16].iter().all(|byte| *byte == 0)
                && raw[240..].iter().all(|byte| *byte == 0) =>
        {
            (
                104,
                136,
                168,
                200,
                raw_u64(raw, 96).map_err(invalid)?,
                raw_u64(raw, 232).map_err(invalid)?,
                FaultClockObservationV1::Wander {
                    scheduler_nanos: raw_u64(raw, 16).map_err(invalid)?,
                    raw_nanos: raw_u64(raw, 24).map_err(invalid)?,
                    offsets: [
                        raw_u64(raw, 32).map_err(invalid)? as i64,
                        raw_u64(raw, 40).map_err(invalid)? as i64,
                    ],
                    rates_ppb: [
                        raw_u64(raw, 48).map_err(invalid)? as i64,
                        raw_u64(raw, 56).map_err(invalid)? as i64,
                    ],
                    next_nanos: [
                        raw_u64(raw, 64).map_err(invalid)?,
                        raw_u64(raw, 72).map_err(invalid)?,
                    ],
                    sequences: [
                        raw_u64(raw, 80).map_err(invalid)?,
                        raw_u64(raw, 88).map_err(invalid)?,
                    ],
                },
            )
        }
        b"CRUCCSE1"
            if raw[20..24].iter().all(|byte| *byte == 0)
                && raw[312..].iter().all(|byte| *byte == 0) =>
        {
            (
                64,
                160,
                192,
                224,
                raw_u64(raw, 304).map_err(invalid)?,
                raw_u64(raw, 296).map_err(invalid)?,
                FaultClockObservationV1::SourceTransition {
                    scheduler_nanos: raw_u64(raw, 24).map_err(invalid)?,
                    raw_nanos: raw_u64(raw, 32).map_err(invalid)?,
                    states: [
                        raw_u32(raw, 12).map_err(invalid)?,
                        raw_u32(raw, 16).map_err(invalid)?,
                    ],
                    old_value: raw_u64(raw, 40).map_err(invalid)?,
                    new_anchor_value: raw_u64(raw, 48).map_err(invalid)?,
                    transition_generation: raw_u64(raw, 56).map_err(invalid)?,
                    old_fallback: raw[96..128].try_into().map_err(invalid)?,
                    new_fallback: raw[128..160].try_into().map_err(invalid)?,
                    synchronization_remaining_nanos: [
                        raw_u64(raw, 256).map_err(invalid)? as i64,
                        raw_u64(raw, 264).map_err(invalid)? as i64,
                    ],
                    synchronization_ratio: [
                        raw_u64(raw, 272).map_err(invalid)?,
                        raw_u64(raw, 280).map_err(invalid)?,
                    ],
                    synchronization_threshold_nanos: raw_u64(raw, 288).map_err(invalid)?,
                },
            )
        }
        b"CRUCCTE1"
            if raw[14..16].iter().all(|byte| *byte == 0)
                && raw[226..232].iter().all(|byte| *byte == 0)
                && raw[256..].iter().all(|byte| *byte == 0) =>
        {
            (
                88,
                120,
                152,
                184,
                raw_u64(raw, 80).map_err(invalid)?,
                raw_u64(raw, 216).map_err(invalid)?,
                FaultClockObservationV1::TimerTransition {
                    role: raw_u16(raw, 12).map_err(invalid)?,
                    index: raw_u32(raw, 16).map_err(invalid)?,
                    action: raw_u32(raw, 20).map_err(invalid)?,
                    sequence: raw_u64(raw, 24).map_err(invalid)?,
                    old_deadlines: [
                        raw_u64(raw, 32).map_err(invalid)?,
                        raw_u64(raw, 40).map_err(invalid)?,
                    ],
                    new_deadlines: [
                        raw_u64(raw, 56).map_err(invalid)?,
                        raw_u64(raw, 64).map_err(invalid)?,
                    ],
                    generations: [
                        raw_u64(raw, 48).map_err(invalid)?,
                        raw_u64(raw, 72).map_err(invalid)?,
                    ],
                    opportunity_phase: raw_u16(raw, 224).map_err(invalid)?,
                    jitter_contribution: raw_u64(raw, 232).map_err(invalid)? as i64,
                    timer_opportunity: raw_u64(raw, 240).map_err(invalid)?,
                    arm_sequence: raw_u64(raw, 248).map_err(invalid)?,
                },
            )
        }
        _ => return Err(FaultCommandBridgeError::ClockEvidence),
    };
    let source_id: [u8; 32] = raw[source_offset..source_offset + 32]
        .try_into()
        .map_err(invalid)?;
    let binding_hash: [u8; 32] = raw[binding_offset..binding_offset + 32]
        .try_into()
        .map_err(invalid)?;
    let before_hash: [u8; 32] = raw[before_offset..before_offset + 32]
        .try_into()
        .map_err(invalid)?;
    let after_hash: [u8; 32] = raw[after_offset..after_offset + 32]
        .try_into()
        .map_err(invalid)?;
    let manifest = FaultClockCapabilityManifestV1::decode(manifest_payload).map_err(invalid)?;
    let Some(row) = manifest.rows.iter().find(|row| {
        row.source_kind == source_kind
            && crucible_shmem::fault_object_id_hash_v1(&row.id) == source_id
    }) else {
        return Err(FaultCommandBridgeError::ClockEvidence);
    };
    if binding_hash != event.binding_hash
        || event.command_kind != expectation.command_kind
        || binding_hash != expectation.binding_hash
        || event.model_phase != expectation.model_phase
        || !expectation.source_ids.contains(&source_id)
        || before_hash != event.before_hash
        || after_hash != event.after_hash
        || !validate_clock_observation_parameters(
            &observation,
            expectation,
            source_id,
            generation,
            minimum_clock_transform_policies(expectation, row),
        )
        || !validate_clock_read_architecture(&observation, row)
    {
        return Err(FaultCommandBridgeError::ClockEvidence);
    }
    FaultClockEvidenceV1 {
        source_kind,
        model_phase: event.model_phase,
        observed_icount,
        source_id,
        binding_hash,
        before_hash,
        after_hash,
        manifest_sha256: sha2::Sha256::digest(manifest_payload).into(),
        transform_generation: generation,
        opportunity,
        observation,
    }
    .encode()
    .map_err(invalid)
}

fn translate_clock_impulse_event_evidence(
    raw: &[u8],
    manifest_payload: &[u8],
    event: &QemuFaultEvent,
    observed_icount: u64,
    expectation: &ClockCommandExpectation,
) -> Result<Vec<u8>, FaultCommandBridgeError> {
    fn invalid<T>(_: T) -> FaultCommandBridgeError {
        FaultCommandBridgeError::ClockEvidence
    }
    validate_raw_clock_impulse(raw)?;
    let source_kind = raw_u16(raw, 210).map_err(invalid)?;
    let source_id: [u8; 32] = raw[80..112].try_into().map_err(invalid)?;
    let binding_hash: [u8; 32] = raw[112..144].try_into().map_err(invalid)?;
    let before_hash: [u8; 32] = raw[144..176].try_into().map_err(invalid)?;
    let after_hash: [u8; 32] = raw[176..208].try_into().map_err(invalid)?;
    let model_phase = raw_u16(raw, 208).map_err(invalid)?;
    let generation = raw_u64(raw, 72).map_err(invalid)?;
    let manifest = FaultClockCapabilityManifestV1::decode(manifest_payload).map_err(invalid)?;
    let observation = decode_clock_impulse_observation(raw)?;
    let Some(row) = manifest.rows.iter().find(|row| {
        row.source_kind == source_kind
            && crucible_shmem::fault_object_id_hash_v1(&row.id) == source_id
    }) else {
        return Err(FaultCommandBridgeError::ClockEvidence);
    };
    if expectation.operation != NodeFaultOperationV1::Apply
        || expectation.command_kind != FaultCommandKind::ClockTransform as u16
        || event.command_kind != expectation.command_kind
        || raw_u64(raw, 16).map_err(invalid)? != event.observed_icount
        || event.model_phase != model_phase
        || event.model_phase != expectation.model_phase
        || event.binding_hash != binding_hash
        || expectation.binding_hash != binding_hash
        || event.before_hash != before_hash
        || event.after_hash != after_hash
        || !expectation.source_ids.contains(&source_id)
        || !validate_clock_observation_parameters(
            &observation,
            expectation,
            source_id,
            generation,
            minimum_clock_transform_policies(expectation, row),
        )
    {
        return Err(FaultCommandBridgeError::ClockEvidence);
    }
    FaultClockEvidenceV1 {
        source_kind,
        model_phase,
        observed_icount,
        source_id,
        binding_hash,
        before_hash,
        after_hash,
        manifest_sha256: sha2::Sha256::digest(manifest_payload).into(),
        transform_generation: generation,
        opportunity: 0,
        observation,
    }
    .encode()
    .map_err(invalid)
}

fn validate_raw_clock_impulse(raw: &[u8]) -> Result<(), FaultCommandBridgeError> {
    fn invalid<T>(_: T) -> FaultCommandBridgeError {
        FaultCommandBridgeError::ClockEvidence
    }
    if raw.len() != 384
        || &raw[..8] != b"CRUCCIM1"
        || raw_u16(raw, 8).map_err(invalid)? != 1
        || raw[12..16].iter().any(|byte| *byte != 0)
        || raw[284..].iter().any(|byte| *byte != 0)
    {
        return Err(FaultCommandBridgeError::ClockEvidence);
    }
    Ok(())
}

fn decode_clock_impulse_observation(
    raw: &[u8],
) -> Result<FaultClockObservationV1, FaultCommandBridgeError> {
    fn invalid<T>(_: T) -> FaultCommandBridgeError {
        FaultCommandBridgeError::ClockEvidence
    }
    Ok(FaultClockObservationV1::Impulse {
        transform_kind: raw_u16(raw, 10).map_err(invalid)? as u32,
        raw_nanos: raw_u64(raw, 24).map_err(invalid)?,
        old_value: raw_u64(raw, 32).map_err(invalid)?,
        signed_value: raw_u64(raw, 40).map_err(invalid)? as i64,
        ratio: [
            raw_u64(raw, 48).map_err(invalid)?,
            raw_u64(raw, 56).map_err(invalid)?,
        ],
        unsigned_value: raw_u64(raw, 64).map_err(invalid)?,
        new_anchor: [
            raw_u64(raw, 212).map_err(invalid)?,
            raw_u64(raw, 220).map_err(invalid)?,
        ],
        new_drift_ratio: [
            raw_u64(raw, 228).map_err(invalid)?,
            raw_u64(raw, 236).map_err(invalid)?,
        ],
        new_additive_nanos: raw_u64(raw, 244).map_err(invalid)? as i64,
        new_frozen_value: raw_u64(raw, 252).map_err(invalid)?,
        new_freeze_release: raw_u32(raw, 260).map_err(invalid)?,
        new_monotonicity: raw_u32(raw, 264).map_err(invalid)?,
        new_overdue_policy: raw_u32(raw, 268).map_err(invalid)?,
        new_source_state: raw_u32(raw, 272).map_err(invalid)?,
        old_additive_nanos: raw_u64(raw, 276).map_err(invalid)? as i64,
    })
}

pub(in crate::fault_command) fn translate_clock_impulse_evidence(
    raw: &[u8],
    manifest_payload: &[u8],
    result: &QemuFaultResult,
    logical_icount_offset: u64,
    expectation: &ClockCommandExpectation,
) -> Result<Vec<u8>, FaultCommandBridgeError> {
    fn invalid<T>(_: T) -> FaultCommandBridgeError {
        FaultCommandBridgeError::ClockEvidence
    }
    validate_raw_clock_impulse(raw)?;
    let source_kind = raw_u16(raw, 210).map_err(invalid)?;
    let source_id: [u8; 32] = raw[80..112].try_into().map_err(invalid)?;
    let binding_hash: [u8; 32] = raw[112..144].try_into().map_err(invalid)?;
    let before_hash: [u8; 32] = raw[144..176].try_into().map_err(invalid)?;
    let after_hash: [u8; 32] = raw[176..208].try_into().map_err(invalid)?;
    let generation = raw_u64(raw, 72).map_err(invalid)?;
    let manifest = FaultClockCapabilityManifestV1::decode(manifest_payload).map_err(invalid)?;
    let observation = decode_clock_impulse_observation(raw)?;
    let Some(row) = manifest.rows.iter().find(|row| {
        row.source_kind == source_kind
            && crucible_shmem::fault_object_id_hash_v1(&row.id) == source_id
    }) else {
        return Err(FaultCommandBridgeError::ClockEvidence);
    };
    if expectation.operation != NodeFaultOperationV1::Apply
        || before_hash != result.before_hash
        || after_hash != result.after_hash
        || result.command_kind != expectation.command_kind
        || binding_hash != expectation.binding_hash
        || raw_u64(raw, 16).map_err(invalid)? != result.observed_icount
        || result.applied_icount != result.observed_icount
        || raw_u16(raw, 208).map_err(invalid)? != expectation.model_phase
        || !expectation.source_ids.contains(&source_id)
        || !validate_clock_observation_parameters(
            &observation,
            expectation,
            source_id,
            generation,
            minimum_clock_transform_policies(expectation, row),
        )
    {
        return Err(FaultCommandBridgeError::ClockEvidence);
    }
    let observed_icount = raw_u64(raw, 16)
        .map_err(invalid)?
        .checked_add(logical_icount_offset)
        .ok_or(FaultCommandBridgeError::CoordinateOverflow)?;
    FaultClockEvidenceV1 {
        source_kind,
        model_phase: raw_u16(raw, 208).map_err(invalid)?,
        observed_icount,
        source_id,
        binding_hash,
        before_hash,
        after_hash,
        manifest_sha256: sha2::Sha256::digest(manifest_payload).into(),
        transform_generation: generation,
        opportunity: 0,
        observation,
    }
    .encode()
    .map_err(invalid)
}
