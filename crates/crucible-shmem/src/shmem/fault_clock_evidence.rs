//! Canonical public evidence for guest-clock faults.
//!
//! The GPL-side bridge translates QEMU-private observations into this fixed
//! byte contract before publishing them through shared memory.

use crate::FaultAbiError;

/// Magic prefix for version-1 guest-clock evidence.
pub const FAULT_CLOCK_EVIDENCE_MAGIC_V1: [u8; 8] = *b"CRUCLKV1";
/// Fixed encoded length of version-1 guest-clock evidence.
pub const FAULT_CLOCK_EVIDENCE_V1_BYTES: usize = 384;

#[path = "fault_clock_evidence/observation.rs"]
mod observation;

pub use observation::FaultClockObservationV1;

/// Independently decodable guest-clock fault evidence.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct FaultClockEvidenceV1 {
    /// Realized source-kind tag from the admitted clock manifest.
    pub source_kind: u16,
    /// Model phase at which the observation occurred.
    pub model_phase: u16,
    /// Scheduler-logical retired-instruction coordinate.
    pub observed_icount: u64,
    /// Canonical source identity hash.
    pub source_id: [u8; 32],
    /// Fault-rule binding hash.
    pub binding_hash: [u8; 32],
    /// Source state hash before the observation.
    pub before_hash: [u8; 32],
    /// Source state hash after the observation.
    pub after_hash: [u8; 32],
    /// SHA-256 of the complete admitted clock manifest bytes.
    pub manifest_sha256: [u8; 32],
    /// Active transform generation.
    pub transform_generation: u64,
    /// Rule opportunity sequence.
    pub opportunity: u64,
    /// Typed observation.
    pub observation: FaultClockObservationV1,
}

impl FaultClockEvidenceV1 {
    /// Encodes canonical fixed-width guest-clock evidence.
    ///
    /// # Errors
    ///
    /// Returns [`FaultAbiError`] when a tag, identity, coordinate, or closed
    /// observation invariant is invalid.
    pub fn encode(&self) -> Result<Vec<u8>, FaultAbiError> {
        let zero = [0_u8; 32];
        if !(1..=9).contains(&self.source_kind)
            || !(28..=32).contains(&self.model_phase)
            || self.transform_generation == 0
            || self.source_id == zero
            || self.binding_hash == zero
            || self.before_hash == zero
            || self.after_hash == zero
            || self.manifest_sha256 == zero
            || (self.opportunity == 0
                && !matches!(&self.observation, FaultClockObservationV1::Impulse { .. }))
        {
            return Err(FaultAbiError::CapabilityInvariant);
        }
        let mut out = vec![0_u8; FAULT_CLOCK_EVIDENCE_V1_BYTES];
        out[..8].copy_from_slice(&FAULT_CLOCK_EVIDENCE_MAGIC_V1);
        out[8..10].copy_from_slice(&1_u16.to_le_bytes());
        out[12..14].copy_from_slice(&self.source_kind.to_le_bytes());
        out[14..16].copy_from_slice(&self.model_phase.to_le_bytes());
        out[24..32].copy_from_slice(&self.observed_icount.to_le_bytes());
        out[32..64].copy_from_slice(&self.source_id);
        out[64..96].copy_from_slice(&self.binding_hash);
        out[96..128].copy_from_slice(&self.before_hash);
        out[128..160].copy_from_slice(&self.after_hash);
        out[160..192].copy_from_slice(&self.manifest_sha256);
        out[192..200].copy_from_slice(&self.transform_generation.to_le_bytes());
        out[200..208].copy_from_slice(&self.opportunity.to_le_bytes());
        let record_kind = match &self.observation {
            FaultClockObservationV1::Read { .. } => 1_u16,
            FaultClockObservationV1::Wander { .. } => 2,
            FaultClockObservationV1::SourceTransition { .. } => 3,
            FaultClockObservationV1::TimerTransition { .. } => 4,
            FaultClockObservationV1::Impulse { .. } => 5,
        };
        out[10..12].copy_from_slice(&record_kind.to_le_bytes());
        let body = &mut out[224..];
        match &self.observation {
            FaultClockObservationV1::Read {
                raw_value,
                transformed_value,
                raw_architectural_value,
                transformed_architectural_value,
                source_width_bits,
                wrap_action,
                anchor_raw,
                anchor_value,
                drift_ratio,
                additive_nanos,
                frozen_value,
                read_error,
                read_opportunity,
                transform_kind,
                contribution,
                monotonicity,
                overdue_policy,
                source_state,
                freeze_release,
                synchronization_remaining_nanos,
            } => {
                if *read_opportunity == 0
                    || !(1..=6).contains(transform_kind)
                    || drift_ratio[0] == 0
                    || drift_ratio[1] == 0
                    || !(1..=3).contains(monotonicity)
                    || !(1..=3).contains(overdue_policy)
                    || !(1..=5).contains(source_state)
                    || *freeze_release > 2
                    || !(1..=64).contains(source_width_bits)
                    || *wrap_action > 1
                    || (*source_width_bits == 64 && *wrap_action != 0)
                {
                    return Err(FaultAbiError::CapabilityInvariant);
                }
                put_u64s(
                    body,
                    &[
                        *raw_value,
                        *transformed_value,
                        *anchor_raw,
                        *anchor_value,
                        drift_ratio[0],
                        drift_ratio[1],
                        *additive_nanos as u64,
                        *frozen_value,
                        *read_opportunity,
                        *contribution as u64,
                        *synchronization_remaining_nanos as u64,
                    ],
                );
                body[88..92].copy_from_slice(&transform_kind.to_le_bytes());
                body[92..96].copy_from_slice(&u32::from(*read_error).to_le_bytes());
                body[96..100].copy_from_slice(&monotonicity.to_le_bytes());
                body[100..104].copy_from_slice(&overdue_policy.to_le_bytes());
                body[104..108].copy_from_slice(&source_state.to_le_bytes());
                body[108..112].copy_from_slice(&freeze_release.to_le_bytes());
                body[112..120].copy_from_slice(&raw_architectural_value.to_le_bytes());
                body[120..128].copy_from_slice(&transformed_architectural_value.to_le_bytes());
                body[128..130].copy_from_slice(&source_width_bits.to_le_bytes());
                body[130..132].copy_from_slice(&wrap_action.to_le_bytes());
            }
            FaultClockObservationV1::Wander {
                scheduler_nanos,
                raw_nanos,
                offsets,
                rates_ppb,
                next_nanos,
                sequences,
            } => {
                if sequences[1] <= sequences[0]
                    || (next_nanos[1] != u64::MAX && next_nanos[1] <= next_nanos[0])
                {
                    return Err(FaultAbiError::CapabilityInvariant);
                }
                put_u64s(
                    body,
                    &[
                        *scheduler_nanos,
                        *raw_nanos,
                        offsets[0] as u64,
                        offsets[1] as u64,
                        rates_ppb[0] as u64,
                        rates_ppb[1] as u64,
                        next_nanos[0],
                        next_nanos[1],
                        sequences[0],
                        sequences[1],
                    ],
                );
            }
            FaultClockObservationV1::SourceTransition {
                scheduler_nanos,
                raw_nanos,
                states,
                old_value,
                new_anchor_value,
                transition_generation,
                old_fallback,
                new_fallback,
                synchronization_remaining_nanos,
                synchronization_ratio,
                synchronization_threshold_nanos,
            } => {
                let has_slew = synchronization_ratio[0] != 0
                    || synchronization_ratio[1] != 0
                    || *synchronization_threshold_nanos != 0;
                if !(1..=5).contains(&states[0])
                    || !(1..=5).contains(&states[1])
                    || *transition_generation == 0
                    || ((states[0] == 5) != (*old_fallback != zero))
                    || ((states[1] == 5) != (*new_fallback != zero))
                    || (has_slew
                        != (synchronization_ratio[0] != 0
                            && synchronization_ratio[1] != 0
                            && *synchronization_threshold_nanos != 0))
                    || (!has_slew && synchronization_remaining_nanos[1] != 0)
                {
                    return Err(FaultAbiError::CapabilityInvariant);
                }
                put_u64s(
                    body,
                    &[
                        *scheduler_nanos,
                        *raw_nanos,
                        *old_value,
                        *new_anchor_value,
                        *transition_generation,
                    ],
                );
                body[40..44].copy_from_slice(&states[0].to_le_bytes());
                body[44..48].copy_from_slice(&states[1].to_le_bytes());
                body[48..80].copy_from_slice(old_fallback);
                body[80..112].copy_from_slice(new_fallback);
                put_u64s(
                    &mut body[112..],
                    &[
                        synchronization_remaining_nanos[0] as u64,
                        synchronization_remaining_nanos[1] as u64,
                        synchronization_ratio[0],
                        synchronization_ratio[1],
                        *synchronization_threshold_nanos,
                    ],
                );
            }
            FaultClockObservationV1::TimerTransition {
                role,
                index,
                action,
                sequence,
                old_deadlines,
                new_deadlines,
                generations,
                opportunity_phase,
                jitter_contribution,
                timer_opportunity,
                arm_sequence,
            } => {
                let removed = matches!(*action, 2 | 4);
                if !(1..=5).contains(role)
                    || !(1..=4).contains(action)
                    || *sequence == 0
                    || !matches!(*opportunity_phase, 29 | 30)
                    || *timer_opportunity == 0
                    || *arm_sequence == 0
                    || (removed
                        != (new_deadlines[0] == 0
                            && new_deadlines[1] == u64::MAX
                            && generations[1] == 0))
                {
                    return Err(FaultAbiError::CapabilityInvariant);
                }
                body[..2].copy_from_slice(&role.to_le_bytes());
                body[4..8].copy_from_slice(&index.to_le_bytes());
                body[8..12].copy_from_slice(&action.to_le_bytes());
                put_u64s(
                    &mut body[16..],
                    &[
                        *sequence,
                        old_deadlines[0],
                        old_deadlines[1],
                        new_deadlines[0],
                        new_deadlines[1],
                        generations[0],
                        generations[1],
                    ],
                );
                body[72..74].copy_from_slice(&opportunity_phase.to_le_bytes());
                body[80..88].copy_from_slice(&(*jitter_contribution as u64).to_le_bytes());
                body[88..96].copy_from_slice(&timer_opportunity.to_le_bytes());
                body[96..104].copy_from_slice(&arm_sequence.to_le_bytes());
            }
            FaultClockObservationV1::Impulse {
                transform_kind,
                raw_nanos,
                old_value,
                signed_value,
                ratio,
                unsigned_value,
                new_anchor,
                new_drift_ratio,
                new_additive_nanos,
                new_frozen_value,
                new_freeze_release,
                new_monotonicity,
                new_overdue_policy,
                new_source_state,
            } => {
                if !(1..=3).contains(transform_kind)
                    || ratio[0] == 0
                    || ratio[1] == 0
                    || (matches!(*transform_kind, 1 | 3)
                        && (*signed_value == 0 || *ratio != [1, 1] || *unsigned_value != 0))
                    || (*transform_kind == 2
                        && (*signed_value != 0 || ratio[0] == ratio[1] || *unsigned_value != 0))
                    || new_drift_ratio[0] == 0
                    || new_drift_ratio[1] == 0
                    || *new_freeze_release > 2
                    || !(1..=3).contains(new_monotonicity)
                    || !(1..=3).contains(new_overdue_policy)
                    || !(1..=5).contains(new_source_state)
                {
                    return Err(FaultAbiError::CapabilityInvariant);
                }
                body[..4].copy_from_slice(&transform_kind.to_le_bytes());
                put_u64s(
                    &mut body[8..],
                    &[
                        *raw_nanos,
                        *old_value,
                        *signed_value as u64,
                        ratio[0],
                        ratio[1],
                        *unsigned_value,
                        new_anchor[0],
                        new_anchor[1],
                        new_drift_ratio[0],
                        new_drift_ratio[1],
                        *new_additive_nanos as u64,
                        *new_frozen_value,
                    ],
                );
                body[104..108].copy_from_slice(&new_freeze_release.to_le_bytes());
                body[108..112].copy_from_slice(&new_monotonicity.to_le_bytes());
                body[112..116].copy_from_slice(&new_overdue_policy.to_le_bytes());
                body[116..120].copy_from_slice(&new_source_state.to_le_bytes());
            }
        }
        Ok(out)
    }

    /// Decodes and validates canonical guest-clock evidence.
    ///
    /// # Errors
    ///
    /// Returns [`FaultAbiError`] for malformed, noncanonical, or invalid bytes.
    pub fn decode(bytes: &[u8]) -> Result<Self, FaultAbiError> {
        if bytes.len() != FAULT_CLOCK_EVIDENCE_V1_BYTES
            || bytes[..8] != FAULT_CLOCK_EVIDENCE_MAGIC_V1
            || u16_at(bytes, 8)? != 1
            || bytes[16..24].iter().any(|byte| *byte != 0)
            || bytes[208..224].iter().any(|byte| *byte != 0)
        {
            return Err(FaultAbiError::CapabilityInvariant);
        }
        let body = &bytes[224..];
        let observation = match u16_at(bytes, 10)? {
            1 => FaultClockObservationV1::Read {
                raw_value: u64_at(body, 0)?,
                transformed_value: u64_at(body, 8)?,
                raw_architectural_value: u64_at(body, 112)?,
                transformed_architectural_value: u64_at(body, 120)?,
                source_width_bits: u16_at(body, 128)?,
                wrap_action: u16_at(body, 130)?,
                anchor_raw: u64_at(body, 16)?,
                anchor_value: u64_at(body, 24)?,
                drift_ratio: [u64_at(body, 32)?, u64_at(body, 40)?],
                additive_nanos: u64_at(body, 48)? as i64,
                frozen_value: u64_at(body, 56)?,
                read_opportunity: u64_at(body, 64)?,
                contribution: u64_at(body, 72)? as i64,
                synchronization_remaining_nanos: u64_at(body, 80)? as i64,
                transform_kind: u32_at(body, 88)?,
                read_error: match u32_at(body, 92)? {
                    0 => false,
                    1 => true,
                    _ => return Err(FaultAbiError::CapabilityInvariant),
                },
                monotonicity: u32_at(body, 96)?,
                overdue_policy: u32_at(body, 100)?,
                source_state: u32_at(body, 104)?,
                freeze_release: u32_at(body, 108)?,
            },
            2 => FaultClockObservationV1::Wander {
                scheduler_nanos: u64_at(body, 0)?,
                raw_nanos: u64_at(body, 8)?,
                offsets: [u64_at(body, 16)? as i64, u64_at(body, 24)? as i64],
                rates_ppb: [u64_at(body, 32)? as i64, u64_at(body, 40)? as i64],
                next_nanos: [u64_at(body, 48)?, u64_at(body, 56)?],
                sequences: [u64_at(body, 64)?, u64_at(body, 72)?],
            },
            3 => FaultClockObservationV1::SourceTransition {
                scheduler_nanos: u64_at(body, 0)?,
                raw_nanos: u64_at(body, 8)?,
                old_value: u64_at(body, 16)?,
                new_anchor_value: u64_at(body, 24)?,
                transition_generation: u64_at(body, 32)?,
                states: [u32_at(body, 40)?, u32_at(body, 44)?],
                old_fallback: array32(body, 48)?,
                new_fallback: array32(body, 80)?,
                synchronization_remaining_nanos: [
                    u64_at(body, 112)? as i64,
                    u64_at(body, 120)? as i64,
                ],
                synchronization_ratio: [u64_at(body, 128)?, u64_at(body, 136)?],
                synchronization_threshold_nanos: u64_at(body, 144)?,
            },
            4 => FaultClockObservationV1::TimerTransition {
                role: u16_at(body, 0)?,
                index: u32_at(body, 4)?,
                action: u32_at(body, 8)?,
                sequence: u64_at(body, 16)?,
                old_deadlines: [u64_at(body, 24)?, u64_at(body, 32)?],
                new_deadlines: [u64_at(body, 40)?, u64_at(body, 48)?],
                generations: [u64_at(body, 56)?, u64_at(body, 64)?],
                opportunity_phase: u16_at(body, 72)?,
                jitter_contribution: u64_at(body, 80)? as i64,
                timer_opportunity: u64_at(body, 88)?,
                arm_sequence: u64_at(body, 96)?,
            },
            5 => FaultClockObservationV1::Impulse {
                transform_kind: u32_at(body, 0)?,
                raw_nanos: u64_at(body, 8)?,
                old_value: u64_at(body, 16)?,
                signed_value: u64_at(body, 24)? as i64,
                ratio: [u64_at(body, 32)?, u64_at(body, 40)?],
                unsigned_value: u64_at(body, 48)?,
                new_anchor: [u64_at(body, 56)?, u64_at(body, 64)?],
                new_drift_ratio: [u64_at(body, 72)?, u64_at(body, 80)?],
                new_additive_nanos: u64_at(body, 88)? as i64,
                new_frozen_value: u64_at(body, 96)?,
                new_freeze_release: u32_at(body, 104)?,
                new_monotonicity: u32_at(body, 108)?,
                new_overdue_policy: u32_at(body, 112)?,
                new_source_state: u32_at(body, 116)?,
            },
            _ => return Err(FaultAbiError::CapabilityInvariant),
        };
        let evidence = Self {
            source_kind: u16_at(bytes, 12)?,
            model_phase: u16_at(bytes, 14)?,
            observed_icount: u64_at(bytes, 24)?,
            source_id: array32(bytes, 32)?,
            binding_hash: array32(bytes, 64)?,
            before_hash: array32(bytes, 96)?,
            after_hash: array32(bytes, 128)?,
            manifest_sha256: array32(bytes, 160)?,
            transform_generation: u64_at(bytes, 192)?,
            opportunity: u64_at(bytes, 200)?,
            observation,
        };
        if evidence.encode()? != bytes {
            return Err(FaultAbiError::CapabilityInvariant);
        }
        Ok(evidence)
    }
}

fn put_u64s(output: &mut [u8], values: &[u64]) {
    for (index, value) in values.iter().enumerate() {
        let start = index * 8;
        output[start..start + 8].copy_from_slice(&value.to_le_bytes());
    }
}
fn u16_at(bytes: &[u8], offset: usize) -> Result<u16, FaultAbiError> {
    bytes
        .get(offset..offset + 2)
        .and_then(|raw| raw.try_into().ok())
        .map(u16::from_le_bytes)
        .ok_or(FaultAbiError::CapabilityInvariant)
}
fn u32_at(bytes: &[u8], offset: usize) -> Result<u32, FaultAbiError> {
    bytes
        .get(offset..offset + 4)
        .and_then(|raw| raw.try_into().ok())
        .map(u32::from_le_bytes)
        .ok_or(FaultAbiError::CapabilityInvariant)
}
fn u64_at(bytes: &[u8], offset: usize) -> Result<u64, FaultAbiError> {
    bytes
        .get(offset..offset + 8)
        .and_then(|raw| raw.try_into().ok())
        .map(u64::from_le_bytes)
        .ok_or(FaultAbiError::CapabilityInvariant)
}
fn array32(bytes: &[u8], offset: usize) -> Result<[u8; 32], FaultAbiError> {
    bytes
        .get(offset..offset + 32)
        .and_then(|raw| raw.try_into().ok())
        .ok_or(FaultAbiError::CapabilityInvariant)
}

#[cfg(test)]
#[path = "fault_clock_evidence_test.rs"]
mod tests;
