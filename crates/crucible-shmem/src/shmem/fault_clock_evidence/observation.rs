//! Closed clock-fault observation vocabulary.

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
        /// Actual timer opportunity phase: arm or fire.
        opportunity_phase: u16,
        /// Deterministic jitter contribution selected for this binding.
        jitter_contribution: i64,
        /// Stable timer opportunity used to select the jitter contribution.
        timer_opportunity: u64,
        /// Device-local arm sequence used to derive the timer opportunity.
        arm_sequence: u64,
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
        /// Active offset and accumulated jumps before the impulse.
        old_additive_nanos: i64,
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
