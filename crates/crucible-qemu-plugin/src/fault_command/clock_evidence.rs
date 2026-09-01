//! Guest-clock command and evidence validation.

use super::*;

#[path = "clock_evidence/translation.rs"]
mod translation;
pub(super) use translation::{translate_clock_evidence, translate_clock_impulse_evidence};

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
    minimum_transform_policies: Option<[u32; 2]>,
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
            let minimum = minimum_transform_policies.unwrap_or([*monotonicity, *overdue_policy]);
            transform_kind == kind
                && observed_signed == signed_value
                && observed_ratio == ratio
                && observed_unsigned == unsigned_value
                && clock_transform_policies_match(*new_monotonicity, *new_overdue_policy, minimum)
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
            let minimum = minimum_transform_policies.unwrap_or([*monotonicity, *overdue_policy]);
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
                && clock_transform_policies_match(
                    *observed_monotonicity,
                    *observed_overdue,
                    minimum,
                )
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

fn minimum_clock_transform_policies(
    expectation: &ClockCommandExpectation,
    row: &FaultClockCapabilityRowV1,
) -> Option<[u32; 2]> {
    let ClockCommandParameters::Transform {
        monotonicity,
        overdue_policy,
        ..
    } = &expectation.parameters
    else {
        return None;
    };
    Some([
        (*monotonicity).max(u32::from(row.monotonicity)),
        (*overdue_policy).max(1),
    ])
}

fn clock_transform_policies_match(
    observed_monotonicity: u32,
    observed_overdue_policy: u32,
    minimum: [u32; 2],
) -> bool {
    observed_monotonicity >= minimum[0]
        && observed_monotonicity <= 3
        && observed_overdue_policy >= minimum[1]
        && observed_overdue_policy <= 3
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
