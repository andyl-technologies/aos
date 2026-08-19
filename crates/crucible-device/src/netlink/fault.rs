//! The network-link effective fault table and its deterministic transforms.
//!
//! A link's behavior is the fault-free delivery (base latency) composed with an
//! **effective fault table** ([IO-20]): the set of faults currently active on
//! the link, each a deterministic transform of a frame's delivery icount and/or
//! payload. This module owns [`LinkFaults`] (the table) and the pure transform
//! functions every fault applies at RESOLVE.
//!
//! # The fault application model
//!
//! Faults are applied in a fixed order so the result is a pure function of the
//! frame, the table, and the injected RNG draws. The order matters: bandwidth
//! serialization and latency are deterministic shifts computed first; the
//! probabilistic effects (jitter, reorder, loss, duplicate, corrupt) each consume
//! one or more draws in this fixed sequence.
//!
//! ```text
//! resolve(frame, t_emit_ns, draws):
//!   delivery_ns  = t_emit_ns + effective_latency_ns        // base, clamped to floor (IO-33)
//!   delivery_ns += serialization_delay_ns(len, bandwidth)  // bandwidth (integer ns, no float)
//!   delivery_ns += draw(jitter)  % (jitter_window_ns + 1)  // jitter   (seeded, shift later)
//!   delivery_ns += draw(reorder) % (reorder_window_ns + 1) // reorder  (seeded, shift later)
//!   if loss      and any draw(loss)  < loss_num/loss_den    : DROP (no delivery)
//!   if duplicate and draw(dup)       < dup_num/dup_den      : emit a 2nd copy at
//!                                                             delivery_ns + dup_gap_ns
//!   if corrupt   and draw(corrupt)   < corrupt_num/cor_den  : mutate payload
//! ```
//!
//! Every probabilistic decision is a pure function of an **injected draw value**
//! (a `u64`) supplied by the seeded per-device RNG ([`crate::fault::DeviceRng`]),
//! forked by name-hash from the scenario seed ([IO-21]). The link consumes its
//! draws in the fixed order documented above; the shared [`Probability`] and the
//! transform functions are owned by [`crate::fault`] and re-exported here so the
//! block, 9p, and network sub-nodes apply one taxonomy ([IO-25], [IO-26]).

pub use crate::fault::{Probability, corrupt_payload, jitter_shift_ns, reorder_shift_ns};

/// A deterministic payload mutation applied when the link corruption decision fires.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum LinkCorruptionStrategy {
    /// Flips up to `max_bits` seeded bit positions in the frame payload.
    BitFlip {
        /// Number of bit-position draws consumed for this strategy.
        max_bits: u32,
    },
    /// Mutates one seeded modeled field of the opaque frame.
    ///
    /// Network frames are opaque at this layer, so the modeled field is a
    /// payload byte selected by a deterministic corruption selector draw.
    FieldMutation,
    /// Removes up to `max_bytes` bytes from the end of the payload.
    Truncation {
        /// Maximum number of bytes removed from one delivered payload.
        max_bytes: u64,
    },
}

impl LinkCorruptionStrategy {
    /// Returns the number of seeded selector draws this strategy needs.
    ///
    /// Bit-flip selectors choose payload bit positions. Field mutation and
    /// truncation each consume one selector so the mutated byte and truncation
    /// length are schedule material rather than fixed constants.
    #[must_use]
    pub fn selector_draws(self) -> u32 {
        match self {
            Self::BitFlip { max_bits } => max_bits,
            Self::FieldMutation | Self::Truncation { .. } => 1,
        }
    }
}

/// The effective fault table for a directed network link.
///
/// Holds every fault parameter the link applies at RESOLVE. All fields are
/// integer nanoseconds or exact-fraction probabilities; no floating point
/// appears anywhere ([IO-24]). A default table is fault-free: zero windows, zero
/// bandwidth limit (unlimited), and never-firing probabilities, so the link
/// delivers at exactly the base latency.
///
/// The fields are deliberately a flat data contract: the link reads them, and a
/// snapshot stores them verbatim, so the active fault set is part of the device
/// half of `MaterializedState` ([IO-26], deferred wiring in CS-IO-5).
#[derive(Clone, Debug, PartialEq, Eq, Default)]
pub struct LinkFaults {
    /// Whether this directed link is partitioned and drops every frame.
    pub partitioned: bool,

    /// Extra fixed latency added to every frame, in virtual nanoseconds.
    ///
    /// A latency fault that *raises* the effective latency is honored as-is (it
    /// only widens lookahead, [IO-33]); a fault that would *lower* the link below
    /// its floor is clamped by [`super::link::NetLink`], never applied here.
    pub added_latency_ns: u64,

    /// The upper bound (inclusive) of the seeded jitter window, in ns.
    ///
    /// Jitter shifts a frame later by `draw % (jitter_window_ns + 1)` ([IO-20]).
    /// A window of zero is no jitter.
    pub jitter_window_ns: u64,

    /// The upper bound (inclusive) of the seeded reorder window, in ns.
    ///
    /// Reorder shifts a frame later by `draw % (reorder_window_ns + 1)`,
    /// potentially past a sibling frame ([IO-20]). The shift is checked against
    /// the consumer's frontier by [`super::link::NetLink`] ([IO-34]).
    pub reorder_window_ns: u64,

    /// Active serialization-rate caps in bits per virtual second.
    ///
    /// Each nonzero cap contributes its own integer serialization delay, and the
    /// delays are summed. This keeps model-level `bits_per_second` limits exact
    /// even when they are not divisible by eight.
    pub bandwidth_bits_per_sec: Vec<u64>,

    /// The probability a frame is dropped (lost) entirely.
    pub loss: Probability,

    /// Additional loss probabilities evaluated after [`Self::loss`].
    ///
    /// Overlapping loss faults use the any-fires rule. The bridge layer stores
    /// the highest active rate in [`Self::loss`] and the remaining rates here, in
    /// deterministic highest-first order.
    pub additional_loss: Vec<Probability>,

    /// The probability a frame is duplicated (a second copy is emitted).
    pub duplicate: Probability,

    /// The fixed gap, in ns, between an original and its duplicate's delivery.
    ///
    /// The duplicate is delivered at `delivery_ns + duplicate_gap_ns`, so the two
    /// copies never collide on the same icount and the order is deterministic.
    pub duplicate_gap_ns: u64,

    /// The probability a frame's payload is corrupted (bits flipped).
    pub corrupt: Probability,

    /// Concrete corruption strategies applied when [`Self::corrupt`] fires.
    pub corruption_strategies: Vec<LinkCorruptionStrategy>,
}

impl LinkFaults {
    /// Returns a fault-free table (the default): no shifts, no probabilistic effects.
    #[must_use]
    pub fn none() -> Self {
        Self::default()
    }

    /// Returns whether any fault raises the conservative minimum latency bound.
    ///
    /// This is the set of faults that change the scalar effective latency the
    /// scheduler uses as its conservative lookahead edge ([IO-33]). Added latency
    /// raises that lower bound for every frame. Jitter, reorder, and bandwidth can
    /// delay individual frames, but their minimum additional delay is zero, so they
    /// do not change this conservative bound. Loss, duplicate, and corrupt do not
    /// change it either.
    #[must_use]
    pub fn affects_latency(&self) -> bool {
        self.added_latency_ns != 0
    }

    /// Returns the total serialization delay from every active bandwidth cap.
    ///
    /// Every active exact bit-rate cap contributes independently. Overlapping
    /// bandwidth faults therefore add their delays rather than replacing each
    /// other.
    #[must_use]
    pub fn serialization_delay_ns(&self, len_bytes: u64) -> u64 {
        self.bandwidth_bits_per_sec
            .iter()
            .copied()
            .fold(0, |total, bits_per_sec| {
                total.saturating_add(serialization_delay_bits_per_sec(len_bytes, bits_per_sec))
            })
    }

    /// Returns whether the loss fault table fires for the supplied draws.
    ///
    /// The primary loss probability is evaluated first, followed by additional
    /// overlapping loss rates in their stored order. Missing additional draws are
    /// treated as deterministic non-firing draws so hand-written tests that omit
    /// them do not accidentally fire a loss fault.
    #[must_use]
    pub fn loss_fires(&self, loss_draw: u64, additional_loss_draws: &[u64]) -> bool {
        if self.loss.fires(loss_draw) {
            return true;
        }

        self.additional_loss
            .iter()
            .enumerate()
            .any(|(index, probability)| {
                let draw = additional_loss_draws
                    .get(index)
                    .copied()
                    .unwrap_or_else(|| non_firing_draw(*probability));
                probability.fires(draw)
            })
    }

    /// Returns the number of corruption selector draws required per frame.
    ///
    /// This is the sum of every concrete strategy's selector needs.
    #[must_use]
    pub fn corruption_selector_draws(&self) -> u32 {
        self.corruption_strategies
            .iter()
            .fold(0u32, |total, strategy| {
                total.saturating_add(strategy.selector_draws())
            })
    }
}

fn non_firing_draw(probability: Probability) -> u64 {
    if probability.denominator == 0 || probability.numerator >= probability.denominator {
        0
    } else {
        probability.numerator
    }
}

/// Computes serialization delay for a bit-per-second bandwidth cap.
#[must_use]
pub(super) fn serialization_delay_bits_per_sec(len_bytes: u64, bits_per_sec: u64) -> u64 {
    checked_serialization_delay_bits_per_sec(len_bytes, bits_per_sec).unwrap_or(u64::MAX)
}

pub(super) fn checked_serialization_delay_bits_per_sec(
    len_bytes: u64,
    bits_per_sec: u64,
) -> Option<u64> {
    if bits_per_sec == 0 {
        return None;
    }
    let nanos = u128::from(len_bytes)
        .checked_mul(8)?
        .checked_mul(1_000_000_000_u128)?;
    let denominator = u128::from(bits_per_sec);
    let nanos = nanos.checked_add(denominator.checked_sub(1)?)? / denominator;
    u64::try_from(nanos).ok()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn probability_fires_on_exact_fraction_without_float() {
        let p = Probability::new(3, 10); // 30%
        // draws 0,1,2 fire; 3..9 do not; wraps at 10.
        assert!(p.fires(0));
        assert!(p.fires(2));
        assert!(!p.fires(3));
        assert!(!p.fires(9));
        assert!(p.fires(10)); // 10 % 10 = 0 < 3
        assert!(!Probability::NEVER.fires(0));
        assert!(Probability::ALWAYS.fires(123));
    }

    #[test]
    fn probability_zero_denominator_never_fires() {
        let p = Probability::new(5, 0);
        assert!(!p.fires(0));
        assert!(!p.fires(u64::MAX));
    }

    #[test]
    fn jitter_and_reorder_shifts_stay_within_window() {
        for draw in [0u64, 1, 7, 99, u64::MAX] {
            assert!(jitter_shift_ns(draw, 16) <= 16);
            assert!(reorder_shift_ns(draw, 1000) <= 1000);
        }
        assert_eq!(jitter_shift_ns(123, 0), 0);
        assert_eq!(reorder_shift_ns(123, 0), 0);
        // Determinism: same draw => same shift.
        assert_eq!(jitter_shift_ns(42, 16), jitter_shift_ns(42, 16));
    }

    #[test]
    fn corrupt_flips_exactly_the_seeded_bits() {
        let mut payload = vec![0u8; 4]; // 32 bits, all zero
        // draws select bit positions 0, 9, 17.
        corrupt_payload(&mut payload, &[0, 9, 17], 3);
        // bit 0 -> byte 0 bit 0; bit 9 -> byte 1 bit 1; bit 17 -> byte 2 bit 1.
        assert_eq!(payload, vec![0b0000_0001, 0b0000_0010, 0b0000_0010, 0]);
        // Re-applying the same draws toggles back (XOR is its own inverse).
        corrupt_payload(&mut payload, &[0, 9, 17], 3);
        assert_eq!(payload, vec![0; 4]);
    }

    #[test]
    fn corrupt_is_a_noop_on_empty_or_zero_flips() {
        let mut empty: Vec<u8> = Vec::new();
        corrupt_payload(&mut empty, &[1, 2, 3], 3);
        assert!(empty.is_empty());
        let mut payload = vec![0xFFu8; 2];
        corrupt_payload(&mut payload, &[1, 2, 3], 0);
        assert_eq!(payload, vec![0xFF; 2]);
    }

    #[test]
    fn affects_latency_reports_only_minimum_bound_changes() {
        let mut f = LinkFaults::none();
        assert!(!f.affects_latency());
        f.partitioned = true;
        f.loss = Probability::ALWAYS;
        f.duplicate = Probability::ALWAYS;
        f.duplicate_gap_ns = 5;
        f.corrupt = Probability::ALWAYS;
        f.corruption_strategies = vec![LinkCorruptionStrategy::BitFlip { max_bits: 3 }];
        f.jitter_window_ns = 5;
        f.reorder_window_ns = 7;
        f.bandwidth_bits_per_sec.push(10_000);
        assert!(
            !f.affects_latency(),
            "faults whose minimum added delay is zero do not raise the conservative bound"
        );
        f.added_latency_ns = 1;
        assert!(f.affects_latency());
    }

    #[test]
    fn bandwidth_delays_sum_across_exact_bit_caps() {
        let mut faults = LinkFaults::none();
        faults.bandwidth_bits_per_sec = vec![
            8_000,  // 100 bytes => 100_000_000 ns
            16_000, // 100 bytes => 50_000_000 ns
        ];

        assert_eq!(faults.serialization_delay_ns(100), 150_000_000);
    }
}
