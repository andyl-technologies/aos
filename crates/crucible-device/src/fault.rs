//! Deterministic network-effect transforms and the seeded per-device RNG.
//!
//! Signal-driven network adapters use these integer-only primitives to resolve
//! frame effects without host time or floating-point behavior.
//!
//! - The pure, integer-only **transforms** ([`Probability`],
//!   [`serialization_delay_ns`], [`jitter_shift_ns`], [`reorder_shift_ns`],
//!   [`corrupt_payload`]) are functions of an injected draw value — no RNG,
//!   no floating point ([IO-24]). The network link
//!   ([`super::netlink::fault`]) re-exports these so disk, filesystem, and
//!   network share one implementation.
//! - The seeded **per-device RNG** ([`DeviceRng`]) supplies those draws in a
//!   fixed consumption order ([IO-21]). It is forked by name-hash from the
//!   scenario seed (the fork itself is computed in the `crucible` engine via the
//!   determinism-contract name-hash; this crate only carries the resulting
//!   stream seed and the SplitMix64 draw sequence), so adding or renaming an
//!   unrelated device never perturbs another device's draws.
//!

/// A Bernoulli probability expressed as an exact integer fraction.
///
/// The fault model uses no floating point ([IO-24]); a probability is the
/// rational `numerator / denominator`, and a draw `d` fires the decision when
/// `(d % denominator) < numerator`. A `numerator` of zero never fires; a
/// `numerator >= denominator` always fires.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Probability {
    /// The fraction numerator (favorable outcomes).
    pub numerator: u64,
    /// The fraction denominator (total outcomes); a zero denominator never fires.
    pub denominator: u64,
}

impl Probability {
    /// A probability that never fires (the absence of a probabilistic effect).
    pub const NEVER: Self = Self {
        numerator: 0,
        denominator: 1,
    };

    /// A probability that always fires.
    pub const ALWAYS: Self = Self {
        numerator: 1,
        denominator: 1,
    };

    /// Creates a probability from an exact integer fraction.
    ///
    /// A `denominator` of zero is treated as "never fires" so a malformed table
    /// cannot panic on the modulo.
    #[must_use]
    pub fn new(numerator: u64, denominator: u64) -> Self {
        Self {
            numerator,
            denominator,
        }
    }

    /// Returns whether the injected `draw` fires this probability.
    ///
    /// Pure function of `(self, draw)`: `(draw % denominator) < numerator`. A zero
    /// denominator never fires. No floating point is used ([IO-24]).
    #[must_use]
    pub fn fires(&self, draw: u64) -> bool {
        if self.denominator == 0 {
            return false;
        }
        (draw % self.denominator) < self.numerator
    }
}

impl Default for Probability {
    fn default() -> Self {
        Self::NEVER
    }
}

/// The deterministic serialization delay for a payload under a bandwidth limit.
///
/// Models `delay_ns = len_bytes * 1_000_000_000 / bandwidth_bytes_per_sec`,
/// computed entirely in integer arithmetic — **no floating point** ([IO-24]).
/// The multiplication is widened to `u128` so a large payload cannot overflow,
/// and the result saturates at `u64::MAX`. A `bandwidth_bytes_per_sec` of zero
/// means "unlimited" and yields no delay.
///
/// # Examples
///
/// ```no_run
/// use crucible_device::fault::serialization_delay_ns;
/// // 1500 bytes at 1 Gbps (125_000_000 B/s) = 12_000 ns.
/// assert_eq!(serialization_delay_ns(1500, 125_000_000), 12_000);
/// ```
#[must_use]
pub fn serialization_delay_ns(len_bytes: u64, bandwidth_bytes_per_sec: u64) -> u64 {
    if bandwidth_bytes_per_sec == 0 {
        return 0;
    }
    let nanos = u128::from(len_bytes) * 1_000_000_000_u128 / u128::from(bandwidth_bytes_per_sec);
    u64::try_from(nanos).unwrap_or(u64::MAX)
}

/// Computes serialization delay for a bit-per-second bandwidth cap.
///
/// This is the exact RFC-level form used by fault plans: `len_bytes * 8 * 1e9 /
/// bits_per_second`, widened and saturating so the result is host-independent.
#[must_use]
pub fn serialization_delay_bits_per_sec(len_bytes: u64, bits_per_second: u64) -> u64 {
    if bits_per_second == 0 {
        return 0;
    }
    let nanos = u128::from(len_bytes)
        .saturating_mul(8)
        .saturating_mul(1_000_000_000_u128)
        / u128::from(bits_per_second);
    u64::try_from(nanos).unwrap_or(u64::MAX)
}

/// The deterministic jitter shift drawn from an injected value.
///
/// Returns `draw % (window_ns + 1)`, a value in `0..=window_ns` ([IO-20]). A zero
/// window yields zero. Pure function of `(draw, window_ns)`.
///
/// The maximal `window_ns == u64::MAX` is the full-range identity: `window_ns + 1`
/// would overflow, so the function returns `draw` verbatim — which is already in
/// `0..=u64::MAX`, satisfying the `0..=window_ns` contract.
#[must_use]
pub fn jitter_shift_ns(draw: u64, window_ns: u64) -> u64 {
    match window_ns.checked_add(1) {
        Some(modulus) => draw % modulus,
        // window_ns == u64::MAX: the full range; the draw is already in 0..=window.
        None => draw,
    }
}

/// The deterministic reorder shift drawn from an injected value.
///
/// Returns `draw % (window_ns + 1)`, a value in `0..=window_ns` ([IO-20]). A zero
/// window yields zero. Pure function of `(draw, window_ns)`. Identical math to
/// [`jitter_shift_ns`] but kept distinct so the two faults consume independent
/// draws in a fixed order; the same `window_ns == u64::MAX` full-range identity
/// applies (the draw is returned verbatim, already in `0..=window_ns`).
#[must_use]
pub fn reorder_shift_ns(draw: u64, window_ns: u64) -> u64 {
    match window_ns.checked_add(1) {
        Some(modulus) => draw % modulus,
        // window_ns == u64::MAX: the full range; the draw is already in 0..=window.
        None => draw,
    }
}

/// Flips `bit_flips` bits in `payload` at positions derived from `draws`.
///
/// Each draw selects a bit position `draw % (payload_bits)`, and that bit is
/// toggled in place ([IO-20]). The same draws flip exactly the same bits, so the
/// corruption is reproducible. An empty payload or zero `bit_flips` leaves the
/// payload unchanged. Pure function of `(payload, draws, bit_flips)`.
///
/// `draws` MUST supply at least `bit_flips` values; only the first `bit_flips`
/// are consumed. If fewer are supplied, only that many bits are flipped (the
/// caller is responsible for supplying enough draws).
pub fn corrupt_payload(payload: &mut [u8], draws: &[u64], bit_flips: u32) {
    if payload.is_empty() {
        return;
    }
    let total_bits = (payload.len() as u64) * 8;
    let count = (bit_flips as usize).min(draws.len());
    for &draw in draws.iter().take(count) {
        let bit_index = draw % total_bits;
        let byte = (bit_index / 8) as usize;
        let bit = (bit_index % 8) as u8;
        payload[byte] ^= 1 << bit;
    }
}

/// A seeded per-device RNG: the source of every probabilistic device draw ([IO-21]).
///
/// `DeviceRng` is a thin newtype over the `crucible` engine's
/// [`crucible_sim::DecisionStream`], so the PRNG has a **single source of truth**
/// in L0: the SplitMix64 algorithm, the seed-fork formula, and the draw-cursor
/// convention are defined once and cannot drift between a device's recorded draws
/// and an engine replay. A device stream forked by name-hash from the scenario
/// seed ([DET-25]) therefore reproduces the same sequence an engine
/// [`crucible_sim::DecisionRng::fork_in_domain`] would. The RNG tracks a
/// monotonically increasing **draw cursor** ([`DeviceRng::position`]); that cursor
/// is the device's RNG state captured in a snapshot and restored on resume so the
/// next draw resolves identically after a pause as it would have without one
/// ([IO-23], [EXEC-13]).
///
/// Forking by name-hash (rather than by sequential draw from a root) is what
/// makes the stream order- and topology-stable: adding or renaming an unrelated
/// device never perturbs this device's sequence ([IO-21]).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct DeviceRng {
    stream: crucible_sim::DecisionStream,
}

impl DeviceRng {
    /// Forks a device RNG by name-hash from the engine's decision-RNG root seed.
    ///
    /// Delegates to [`crucible_sim::DecisionRng::fork_in_domain`], the single L0
    /// source of the SplitMix64 stream and the `seed XOR stable_hash(domain,
    /// name)` fork formula ([DET-25]). `root_seed` is the scenario's
    /// decision-RNG root (`Seed::decision_rng().root_seed()`); `domain` and
    /// `name` are the device stream's stable domain and the device name. Because
    /// the fork is by name-hash, an unrelated device never perturbs this device's
    /// sequence.
    #[must_use]
    pub fn fork(root_seed: u64, domain: &str, name: &str) -> Self {
        Self {
            stream: crucible_sim::DecisionRng::new(root_seed).fork_in_domain(domain, name),
        }
    }

    /// Restores a forked device RNG to a captured draw cursor ([IO-23]).
    ///
    /// Re-forks the stream from `(root_seed, domain, name)` and replays
    /// `position` draws, so a restored stream's next draw is byte-identical to
    /// the uninterrupted run's. Restoring to position zero is identical to
    /// [`DeviceRng::fork`].
    #[must_use]
    pub fn restore(root_seed: u64, domain: &str, name: &str, position: u64) -> Self {
        let mut rng = Self::fork(root_seed, domain, name);
        let mut remaining = position;
        while remaining > 0 {
            let _ = rng.next_u64();
            remaining -= 1;
        }
        rng
    }

    /// Returns the forked stream seed this RNG draws from.
    #[must_use]
    pub fn seed(&self) -> u64 {
        self.stream.seed()
    }

    /// Returns the number of values drawn so far (the snapshot cursor, [IO-23]).
    #[must_use]
    pub fn position(&self) -> u64 {
        self.stream.draws()
    }

    /// Draws the next deterministic `u64`, advancing the cursor by one.
    pub fn next_u64(&mut self) -> u64 {
        self.stream.next_u64()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A fixed engine decision-RNG root for the fault tests.
    const TEST_ROOT: u64 = 0x1234_5678_9abc_def0;
    /// A stand-in device stream domain for the fault tests.
    const TEST_DOMAIN: &str = "crucible.test.device-stream";

    /// Forks a device RNG for `name` from the fixed test root.
    fn test_rng(name: &str) -> DeviceRng {
        DeviceRng::fork(TEST_ROOT, TEST_DOMAIN, name)
    }

    #[test]
    fn probability_fires_on_exact_fraction_without_float() {
        let p = Probability::new(3, 10); // 30%
        assert!(p.fires(0));
        assert!(p.fires(2));
        assert!(!p.fires(3));
        assert!(!p.fires(9));
        assert!(p.fires(10)); // 10 % 10 = 0 < 3
        assert!(!Probability::NEVER.fires(0));
        assert!(Probability::ALWAYS.fires(123));
    }

    #[test]
    fn device_rng_is_deterministic_and_tracks_position() {
        let mut a = test_rng("disk");
        let mut b = test_rng("disk");
        assert_eq!(a.position(), 0);
        let first = a.next_u64();
        let second = a.next_u64();
        assert_eq!(a.position(), 2);
        assert_eq!(first, b.next_u64());
        assert_eq!(second, b.next_u64());
        assert_ne!(first, second);
    }

    #[test]
    fn device_rng_name_hash_fork_is_topology_stable() {
        // The engine forks `seed XOR stable_hash(domain, name)`; an unrelated
        // device must never perturb this device's draw sequence.
        let mut a1 = test_rng("disk");
        let mut a2 = test_rng("disk");
        let mut unrelated = test_rng("cache");
        let a1_first = a1.next_u64();
        let _ = unrelated.next_u64();
        let a2_first = a2.next_u64();
        assert_eq!(
            a1_first, a2_first,
            "device A draws unaffected by device B existence"
        );
    }

    #[test]
    fn device_rng_restore_resumes_identical_stream() {
        let mut live = test_rng("disk");
        let _ = live.next_u64();
        let _ = live.next_u64();
        let _ = live.next_u64();
        let position = live.position();
        let live_next = live.next_u64();

        let mut restored = DeviceRng::restore(TEST_ROOT, TEST_DOMAIN, "disk", position);
        assert_eq!(restored.position(), position);
        assert_eq!(
            restored.next_u64(),
            live_next,
            "restored stream resumes byte-identically ([IO-23])"
        );
    }
}
