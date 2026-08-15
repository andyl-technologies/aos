//! Canonical public evidence for guest-clock faults.
//!
//! The GPL-side bridge translates QEMU-private observations into this fixed
//! byte contract before publishing them through shared memory.

use crate::FaultAbiError;

/// Magic prefix for version-1 guest-clock evidence.
pub const FAULT_CLOCK_EVIDENCE_MAGIC_V1: [u8; 8] = *b"CRUCLKV1";
/// Fixed encoded length of version-1 guest-clock evidence.
pub const FAULT_CLOCK_EVIDENCE_V1_BYTES: usize = 384;

/// Closed guest-clock observation kind.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum FaultClockObservationV1 {
    /// One guest-visible source read.
    Read {
        /// Raw value normalized to nanoseconds for affine evaluation.
        raw_value: u64,
        /// Transformed value normalized to nanoseconds before width handling.
        transformed_value: u64,
        /// Raw value in the architecture's register or counter domain.
        raw_architectural_value: u64,
        /// Final guest-visible register or counter value after width handling.
        transformed_architectural_value: u64,
        /// Architectural register or counter width.
        source_width_bits: u16,
        /// Closed wrap-action tag: zero for none and one for wrapped.
        wrap_action: u16,
        /// Raw coordinate at which the current affine transform was anchored.
        anchor_raw: u64,
        /// Guest-visible value at the current affine anchor.
        anchor_value: u64,
        /// Exact active drift numerator and denominator.
        drift_ratio: [u64; 2],
        /// Active signed offset and accumulated jump contribution.
        additive_nanos: i64,
        /// Held value when the source is frozen, otherwise zero.
        frozen_value: u64,
        /// Whether the source reported an architectural read error.
        read_error: bool,
        /// Stable read opportunity.
        read_opportunity: u64,
        /// Transform kind that contributed at this opportunity.
        transform_kind: u32,
        /// Signed jitter or wander contribution.
        contribution: i64,
        /// Closed backward-time policy tag.
        monotonicity: u32,
        /// Closed overdue-timer policy tag.
        overdue_policy: u32,
        /// Closed source-state tag.
        source_state: u32,
        /// Closed freeze-release tag, or zero while unfrozen.
        freeze_release: u32,
        /// Signed synchronization correction remaining after this read.
        synchronization_remaining_nanos: i64,
    },
    /// One deterministic wander-process transition.
    Wander {
        /// Scheduler virtual time at the transition.
        scheduler_nanos: u64,
        /// Raw source coordinate at the transition.
        raw_nanos: u64,
        /// Offset before and after the transition.
        offsets: [i64; 2],
        /// Rate before and after the transition, in parts per billion.
        rates_ppb: [i64; 2],
        /// Update coordinates before and after the transition.
        next_nanos: [u64; 2],
        /// Process sequence before and after the transition.
        sequences: [u64; 2],
    },
    /// One source failure, fallback, or synchronization transition.
    SourceTransition {
        /// Scheduler virtual time at the transition.
        scheduler_nanos: u64,
        /// Raw source coordinate at the transition.
        raw_nanos: u64,
        /// Old and new closed source-state tags.
        states: [u32; 2],
        /// Source value immediately before the transition.
        old_value: u64,
        /// New anchor value.
        new_anchor_value: u64,
        /// Source-transition generation.
        transition_generation: u64,
        /// Old fallback source identity hash.
        old_fallback: [u8; 32],
        /// New fallback source identity hash.
        new_fallback: [u8; 32],
        /// Synchronization correction remaining before and after transition.
        synchronization_remaining_nanos: [i64; 2],
        /// Exact synchronization slew numerator and denominator.
        synchronization_ratio: [u64; 2],
        /// Positive slew completion threshold, or zero for step correction.
        synchronization_threshold_nanos: u64,
    },
    /// One timer deadline or disposition transition.
    TimerTransition {
        /// Closed timer-role tag.
        role: u16,
        /// Device-local timer index.
        index: u32,
        /// Closed timer-action tag.
        action: u32,
        /// Timer-transition sequence.
        sequence: u64,
        /// Old guest and scheduler deadlines.
        old_deadlines: [u64; 2],
        /// New guest and scheduler deadlines.
        new_deadlines: [u64; 2],
        /// Old and new transform generations.
        generations: [u64; 2],
    },
    /// One durable one-shot offset, drift, or jump mutation.
    Impulse {
        /// Closed transform-kind tag.
        transform_kind: u32,
        /// Raw source coordinate.
        raw_nanos: u64,
        /// Guest-visible value before the impulse.
        old_value: u64,
        /// Signed offset or jump parameter.
        signed_value: i64,
        /// Exact drift-ratio numerator and denominator.
        ratio: [u64; 2],
        /// Reserved unsigned parameter, which is zero for every valid impulse.
        unsigned_value: u64,
        /// Raw and guest-visible affine anchors after the impulse.
        new_anchor: [u64; 2],
        /// Exact active drift ratio after the impulse.
        new_drift_ratio: [u64; 2],
        /// Active offset and accumulated jumps after the impulse.
        new_additive_nanos: i64,
        /// Held value after the impulse when already frozen, otherwise zero.
        new_frozen_value: u64,
        /// Closed freeze-release tag after the impulse.
        new_freeze_release: u32,
        /// Closed backward-time policy after the impulse.
        new_monotonicity: u32,
        /// Closed overdue-timer policy after the impulse.
        new_overdue_policy: u32,
        /// Closed source-state tag after the impulse.
        new_source_state: u32,
    },
}

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
            } => {
                let removed = matches!(*action, 2 | 4);
                if !(1..=5).contains(role)
                    || !(1..=4).contains(action)
                    || *sequence == 0
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
mod tests {
    use super::*;

    fn evidence(observation: FaultClockObservationV1) -> FaultClockEvidenceV1 {
        FaultClockEvidenceV1 {
            source_kind: 7,
            model_phase: 30,
            observed_icount: 42,
            source_id: [1; 32],
            binding_hash: [2; 32],
            before_hash: [3; 32],
            after_hash: [4; 32],
            manifest_sha256: [5; 32],
            transform_generation: 9,
            opportunity: 10,
            observation,
        }
    }

    #[test]
    fn every_clock_evidence_kind_round_trips_canonically() {
        let observations = [
            FaultClockObservationV1::Read {
                raw_value: 11,
                transformed_value: 12,
                raw_architectural_value: 21,
                transformed_architectural_value: 22,
                source_width_bits: 32,
                wrap_action: 0,
                anchor_raw: 9,
                anchor_value: 10,
                drift_ratio: [1001, 1000],
                additive_nanos: -2,
                frozen_value: 0,
                read_error: false,
                read_opportunity: 13,
                transform_kind: 5,
                contribution: -7,
                monotonicity: 2,
                overdue_policy: 1,
                source_state: 1,
                freeze_release: 0,
                synchronization_remaining_nanos: -3,
            },
            FaultClockObservationV1::Wander {
                scheduler_nanos: 20,
                raw_nanos: 21,
                offsets: [-2, 3],
                rates_ppb: [-4, 5],
                next_nanos: [22, 23],
                sequences: [6, 7],
            },
            FaultClockObservationV1::SourceTransition {
                scheduler_nanos: 30,
                raw_nanos: 31,
                states: [1, 5],
                old_value: 32,
                new_anchor_value: 33,
                transition_generation: 2,
                old_fallback: [0; 32],
                new_fallback: [6; 32],
                synchronization_remaining_nanos: [0, -4],
                synchronization_ratio: [1001, 1000],
                synchronization_threshold_nanos: 1,
            },
            FaultClockObservationV1::TimerTransition {
                role: 1,
                index: 3,
                action: 1,
                sequence: 7,
                old_deadlines: [11, 12],
                new_deadlines: [13, 14],
                generations: [8, 9],
            },
            FaultClockObservationV1::Impulse {
                transform_kind: 2,
                raw_nanos: 40,
                old_value: 41,
                signed_value: 0,
                ratio: [1001, 1000],
                unsigned_value: 0,
                new_anchor: [43, 44],
                new_drift_ratio: [1001, 1000],
                new_additive_nanos: -9,
                new_frozen_value: 0,
                new_freeze_release: 0,
                new_monotonicity: 2,
                new_overdue_policy: 1,
                new_source_state: 1,
            },
        ];
        for observation in observations {
            let mut value = evidence(observation);
            if matches!(&value.observation, FaultClockObservationV1::Impulse { .. }) {
                value.opportunity = 0;
            }
            let encoded = value
                .encode()
                .unwrap_or_else(|error| panic!("clock evidence should encode: {error}"));
            assert_eq!(
                FaultClockEvidenceV1::decode(&encoded)
                    .unwrap_or_else(|error| panic!("clock evidence should decode: {error}")),
                value
            );
        }
    }

    #[test]
    fn clock_evidence_rejects_noncanonical_and_unbound_records() {
        let value = evidence(FaultClockObservationV1::TimerTransition {
            role: 1,
            index: 3,
            action: 1,
            sequence: 7,
            old_deadlines: [11, 12],
            new_deadlines: [13, 14],
            generations: [8, 9],
        });
        let mut encoded = value
            .encode()
            .unwrap_or_else(|error| panic!("clock evidence should encode: {error}"));
        encoded[223] = 1;
        assert!(FaultClockEvidenceV1::decode(&encoded).is_err());

        let mut missing_identity = value;
        missing_identity.source_id = [0; 32];
        assert!(missing_identity.encode().is_err());
    }
}
