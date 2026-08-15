//! Guest-clock command and evidence validation.

use super::*;
pub(super) fn clock_json_u64(value: &serde_json::Value, name: &str) -> Option<u64> {
    value.as_object()?.get(name)?.as_u64()
}

pub(super) fn clock_json_i64_table(value: &serde_json::Value) -> Option<Vec<i64>> {
    value
        .as_array()?
        .iter()
        .map(serde_json::Value::as_i64)
        .collect()
}

pub(super) fn clock_timer_opportunity(
    source_id: [u8; 32],
    arm_sequence: u64,
    phase: u16,
    role: u16,
    index: u32,
    transform_generation: u64,
) -> u64 {
    let mut material = [0_u8; 64];
    material[..8].copy_from_slice(b"CRUCTMR1");
    material[8..40].copy_from_slice(&source_id);
    material[40..48].copy_from_slice(&arm_sequence.to_le_bytes());
    material[48..50].copy_from_slice(&phase.to_le_bytes());
    material[50..52].copy_from_slice(&role.to_le_bytes());
    material[52..56].copy_from_slice(&index.to_le_bytes());
    material[56..64].copy_from_slice(&transform_generation.to_le_bytes());
    let digest = sha2::Sha256::digest(material);
    let mut selected = [0_u8; 8];
    selected.copy_from_slice(&digest[..8]);
    match u64::from_le_bytes(selected) {
        0 => u64::MAX,
        opportunity => opportunity,
    }
}

pub(super) fn clock_timer_table_index(
    binding_hash: [u8; 32],
    source_id: [u8; 32],
    timer_opportunity: u64,
    count: usize,
) -> Option<usize> {
    if count == 0 {
        return None;
    }
    let mut material = [0_u8; 80];
    material[..8].copy_from_slice(b"CRUCKEY1");
    material[8..40].copy_from_slice(&binding_hash);
    material[40..72].copy_from_slice(&source_id);
    material[72..80].copy_from_slice(&timer_opportunity.to_le_bytes());
    let digest = sha2::Sha256::digest(material);
    let selected = u64::from_le_bytes(digest[..8].try_into().ok()?);
    usize::try_from(selected % u64::try_from(count).ok()?).ok()
}

pub(super) fn validate_clock_timer_observation(
    observation: &FaultClockObservationV1,
    source_id: [u8; 32],
    transform_generation: u64,
) -> Option<(u16, i64)> {
    let FaultClockObservationV1::TimerTransition {
        role,
        index,
        opportunity_phase,
        jitter_contribution,
        timer_opportunity,
        arm_sequence,
        ..
    } = observation
    else {
        return None;
    };
    if !matches!(*opportunity_phase, 29 | 30)
        || *timer_opportunity
            != clock_timer_opportunity(
                source_id,
                *arm_sequence,
                *opportunity_phase,
                *role,
                *index,
                transform_generation,
            )
    {
        return None;
    }
    Some((*opportunity_phase, *jitter_contribution))
}

pub(super) fn validate_clock_observation_parameters(
    observation: &FaultClockObservationV1,
    expectation: &ClockCommandExpectation,
    source_id: [u8; 32],
    transform_generation: u64,
) -> bool {
    match (&expectation.parameters, observation) {
        (ClockCommandParameters::Remove, _) => false,
        (
            ClockCommandParameters::Transform {
                kind,
                signed_value,
                ratio,
                unsigned_value,
                process: _,
                monotonicity,
                overdue_policy,
            },
            FaultClockObservationV1::Impulse {
                transform_kind,
                signed_value: observed_signed,
                ratio: observed_ratio,
                unsigned_value: observed_unsigned,
                new_monotonicity,
                new_overdue_policy,
                ..
            },
        ) => {
            transform_kind == kind
                && observed_signed == signed_value
                && observed_ratio == ratio
                && observed_unsigned == unsigned_value
                && new_monotonicity == monotonicity
                && new_overdue_policy == overdue_policy
        }
        (
            ClockCommandParameters::Transform {
                kind,
                unsigned_value,
                process,
                monotonicity,
                overdue_policy,
                ..
            },
            FaultClockObservationV1::Read {
                transform_kind,
                contribution,
                monotonicity: observed_monotonicity,
                overdue_policy: observed_overdue,
                freeze_release,
                ..
            },
        ) => {
            let contribution_valid = match *kind {
                1..=4 => *contribution == 0,
                5 => process
                    .as_ref()
                    .and_then(clock_json_i64_table)
                    .is_some_and(|values| {
                        values.contains(contribution)
                            && contribution.unsigned_abs() <= *unsigned_value
                    }),
                6 => process.as_ref().is_some_and(|value| {
                    clock_json_u64(value, "maximum_offset_nanos")
                        .is_some_and(|maximum| contribution.unsigned_abs() <= maximum)
                }),
                _ => false,
            };
            let freeze_valid = if *kind == 4 {
                process.as_ref().is_some_and(|value| {
                    matches!(
                        (value.as_str(), *freeze_release),
                        (Some("resume_from_frozen"), 1) | (Some("catch_up_jump"), 2)
                    )
                })
            } else {
                true
            };
            transform_kind == kind
                && observed_monotonicity == monotonicity
                && observed_overdue == overdue_policy
                && contribution_valid
                && freeze_valid
        }
        (
            ClockCommandParameters::Transform {
                kind: 6, process, ..
            },
            FaultClockObservationV1::Wander {
                offsets,
                rates_ppb,
                next_nanos,
                sequences,
                ..
            },
        ) => process.as_ref().is_some_and(|value| {
            let Some(step) = clock_json_u64(value, "step_nanos") else {
                return false;
            };
            let Some(maximum_offset) = clock_json_u64(value, "maximum_offset_nanos") else {
                return false;
            };
            let Some(maximum_rate) = clock_json_u64(value, "maximum_rate_ppb") else {
                return false;
            };
            let Some(increments) = value
                .as_object()
                .and_then(|object| object.get("increments_ppb"))
                .and_then(clock_json_i64_table)
            else {
                return false;
            };
            offsets
                .iter()
                .all(|offset| offset.unsigned_abs() <= maximum_offset)
                && rates_ppb
                    .iter()
                    .all(|rate| rate.unsigned_abs() <= maximum_rate)
                && rates_ppb[1]
                    .checked_sub(rates_ppb[0])
                    .is_some_and(|delta| increments.contains(&delta))
                && next_nanos[1].checked_sub(next_nanos[0]) == Some(step)
                && sequences[1].checked_sub(sequences[0]) == Some(1)
        }),
        (
            ClockCommandParameters::Transform {
                kind,
                unsigned_value,
                process,
                ..
            },
            FaultClockObservationV1::TimerTransition {
                timer_opportunity, ..
            },
        ) => validate_clock_timer_observation(observation, source_id, transform_generation)
            .is_some_and(|(phase, contribution)| {
                if phase != expectation.model_phase {
                    return false;
                }
                if *kind != 5 {
                    return contribution == 0;
                }
                process
                    .as_ref()
                    .and_then(clock_json_i64_table)
                    .and_then(|values| {
                        let index = clock_timer_table_index(
                            expectation.binding_hash,
                            source_id,
                            *timer_opportunity,
                            values.len(),
                        )?;
                        values.get(index).copied()
                    })
                    .is_some_and(|selected| {
                        selected == contribution && selected.unsigned_abs() <= *unsigned_value
                    })
            }),
        (
            ClockCommandParameters::SourceState {
                transition,
                synchronization,
            },
            FaultClockObservationV1::SourceTransition {
                states,
                new_fallback,
                synchronization_ratio,
                synchronization_threshold_nanos,
                ..
            },
        ) => {
            let Some(kind) = transition.get("kind").and_then(serde_json::Value::as_str) else {
                return false;
            };
            let expected_state = match kind {
                "healthy" => 1,
                "degraded" => 2,
                "failed" => match transition
                    .pointer("/parameters/behavior")
                    .and_then(serde_json::Value::as_str)
                {
                    Some("stop") => 3,
                    Some("read_error") => 4,
                    _ => return false,
                },
                "fallback" => 5,
                _ => return false,
            };
            let fallback_valid = if kind == "fallback" {
                transition
                    .pointer("/parameters/source")
                    .and_then(serde_json::Value::as_str)
                    .is_some_and(|source| {
                        crucible_shmem::fault_object_id_hash_v1(source) == *new_fallback
                    })
            } else {
                *new_fallback == [0; 32]
            };
            let synchronization_valid = match synchronization
                .get("kind")
                .and_then(serde_json::Value::as_str)
            {
                Some("step") => {
                    *synchronization_ratio == [0, 0] && *synchronization_threshold_nanos == 0
                }
                Some("slew") => {
                    let numerator = synchronization
                        .pointer("/parameters/rate/numerator")
                        .and_then(serde_json::Value::as_u64);
                    let denominator = synchronization
                        .pointer("/parameters/rate/denominator")
                        .and_then(serde_json::Value::as_u64);
                    let threshold = synchronization
                        .pointer("/parameters/threshold_nanos")
                        .and_then(serde_json::Value::as_u64);
                    numerator == Some(synchronization_ratio[0])
                        && denominator == Some(synchronization_ratio[1])
                        && threshold == Some(*synchronization_threshold_nanos)
                }
                _ => false,
            };
            states[1] == expected_state && fallback_valid && synchronization_valid
        }
        (
            ClockCommandParameters::SourceState { transition, .. },
            FaultClockObservationV1::Read {
                transform_kind,
                source_state,
                contribution,
                ..
            },
        ) => {
            let expected_state = match transition.get("kind").and_then(serde_json::Value::as_str) {
                Some("healthy") => 1,
                Some("degraded") => 2,
                Some("failed")
                    if transition
                        .pointer("/parameters/behavior")
                        .and_then(serde_json::Value::as_str)
                        == Some("stop") =>
                {
                    3
                }
                Some("failed") => 4,
                Some("fallback") => 5,
                _ => return false,
            };
            *transform_kind == 0 && *contribution == 0 && *source_state == expected_state
        }
        (
            ClockCommandParameters::SourceState { .. },
            FaultClockObservationV1::TimerTransition { .. },
        ) => validate_clock_timer_observation(observation, source_id, transform_generation)
            .is_some_and(|(_, contribution)| contribution == 0),
        _ => false,
    }
}

pub(super) fn validate_clock_read_architecture(
    observation: &FaultClockObservationV1,
    row: &FaultClockCapabilityRowV1,
) -> bool {
    let FaultClockObservationV1::Read {
        raw_value,
        transformed_value,
        raw_architectural_value,
        transformed_architectural_value,
        source_width_bits,
        wrap_action,
        read_error,
        ..
    } = observation
    else {
        return true;
    };
    if u32::from(*source_width_bits) != row.width_bits || *wrap_action > 1 {
        return false;
    }
    let normalized_raw = u128::from(*raw_architectural_value)
        .checked_mul(1_000_000_000)
        .and_then(|value| value.checked_mul(u128::from(row.frequency_denominator)))
        .map(|value| value / u128::from(row.frequency_numerator));
    if normalized_raw != Some(u128::from(*raw_value)) {
        return false;
    }
    if *read_error {
        return *transformed_architectural_value == *raw_architectural_value && *wrap_action == 0;
    }
    let Some(ticks) = u128::from(*transformed_value)
        .checked_mul(u128::from(row.frequency_numerator))
        .map(|value| value / (1_000_000_000_u128 * u128::from(row.frequency_denominator)))
    else {
        return false;
    };
    let mask = if row.width_bits == 64 {
        u128::from(u64::MAX)
    } else {
        (1_u128 << row.width_bits) - 1
    };
    let wrapped = ticks & !mask != 0;
    ticks & mask == u128::from(*transformed_architectural_value)
        && *wrap_action == u16::from(wrapped)
        && (!wrapped || row.flags & 1 != 0)
}

pub(super) fn translate_clock_evidence(
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
        || !validate_clock_observation_parameters(&observation, expectation, source_id, generation)
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

pub(super) fn translate_clock_impulse_event_evidence(
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
    let manifest = FaultClockCapabilityManifestV1::decode(manifest_payload).map_err(invalid)?;
    let observation = decode_clock_impulse_observation(raw)?;
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
        || !manifest.rows.iter().any(|row| {
            row.source_kind == source_kind
                && crucible_shmem::fault_object_id_hash_v1(&row.id) == source_id
        })
        || !validate_clock_observation_parameters(
            &observation,
            expectation,
            source_id,
            raw_u64(raw, 72).map_err(invalid)?,
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
        transform_generation: raw_u64(raw, 72).map_err(invalid)?,
        opportunity: 0,
        observation,
    }
    .encode()
    .map_err(invalid)
}

pub(super) fn validate_raw_clock_impulse(raw: &[u8]) -> Result<(), FaultCommandBridgeError> {
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

pub(super) fn decode_clock_impulse_observation(
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

pub(super) fn translate_clock_impulse_evidence(
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
    let manifest = FaultClockCapabilityManifestV1::decode(manifest_payload).map_err(invalid)?;
    let observation = decode_clock_impulse_observation(raw)?;
    if expectation.operation != NodeFaultOperationV1::Apply
        || before_hash != result.before_hash
        || after_hash != result.after_hash
        || result.command_kind != expectation.command_kind
        || binding_hash != expectation.binding_hash
        || raw_u64(raw, 16).map_err(invalid)? != result.observed_icount
        || result.applied_icount != result.observed_icount
        || raw_u16(raw, 208).map_err(invalid)? != expectation.model_phase
        || !expectation.source_ids.contains(&source_id)
        || !manifest.rows.iter().any(|row| {
            row.source_kind == source_kind
                && crucible_shmem::fault_object_id_hash_v1(&row.id) == source_id
        })
        || !validate_clock_observation_parameters(
            &observation,
            expectation,
            source_id,
            raw_u64(raw, 72).map_err(invalid)?,
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
        transform_generation: raw_u64(raw, 72).map_err(invalid)?,
        opportunity: 0,
        observation,
    }
    .encode()
    .map_err(invalid)
}

pub(super) fn raw_u16(bytes: &[u8], offset: usize) -> Result<u16, FaultCommandBridgeError> {
    bytes
        .get(offset..offset + 2)
        .and_then(|value| value.try_into().ok())
        .map(u16::from_le_bytes)
        .ok_or(FaultCommandBridgeError::RegisterEvidence)
}

pub(super) fn raw_u32(bytes: &[u8], offset: usize) -> Result<u32, FaultCommandBridgeError> {
    bytes
        .get(offset..offset + 4)
        .and_then(|value| value.try_into().ok())
        .map(u32::from_le_bytes)
        .ok_or(FaultCommandBridgeError::RegisterEvidence)
}

pub(super) fn raw_u64(bytes: &[u8], offset: usize) -> Result<u64, FaultCommandBridgeError> {
    bytes
        .get(offset..offset + 8)
        .and_then(|value| value.try_into().ok())
        .map(u64::from_le_bytes)
        .ok_or(FaultCommandBridgeError::RegisterEvidence)
}

pub(super) fn accelerator_field(
    expectation: &AcceleratorCommandExpectation,
    tag: u16,
) -> Result<&[u8], FaultCommandBridgeError> {
    expectation
        .fields
        .get(&tag)
        .map(Vec::as_slice)
        .ok_or(FaultCommandBridgeError::AcceleratorEvidence)
}

pub(super) fn accelerator_u32(
    expectation: &AcceleratorCommandExpectation,
    tag: u16,
) -> Result<u32, FaultCommandBridgeError> {
    accelerator_field(expectation, tag)?
        .try_into()
        .map(u32::from_le_bytes)
        .map_err(|_| FaultCommandBridgeError::AcceleratorEvidence)
}

pub(super) fn accelerator_u64(
    expectation: &AcceleratorCommandExpectation,
    tag: u16,
) -> Result<u64, FaultCommandBridgeError> {
    accelerator_field(expectation, tag)?
        .try_into()
        .map(u64::from_le_bytes)
        .map_err(|_| FaultCommandBridgeError::AcceleratorEvidence)
}

pub(super) fn accelerator_bool(
    expectation: &AcceleratorCommandExpectation,
    tag: u16,
) -> Result<bool, FaultCommandBridgeError> {
    match accelerator_field(expectation, tag)? {
        [0] => Ok(false),
        [1] => Ok(true),
        _ => Err(FaultCommandBridgeError::AcceleratorEvidence),
    }
}
